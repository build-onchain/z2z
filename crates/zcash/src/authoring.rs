use std::fmt;

use orchard::{
    Address, Note,
    bundle::BundleVersion,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::SpendAuthorizingKey,
    note::{ExtractedNoteCommitment, NoteVersion, Rho},
    note_encryption::IronwoodDomain,
    primitives::redpallas,
};
use pczt::{
    Pczt,
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, prover::Prover, redactor::Redactor,
        signer::Signer, tx_extractor::TransactionExtractor,
        verifier::{OrchardError, Verifier},
    },
};
use rand_core::{CryptoRng, RngCore};
use zcash_note_encryption::{Domain, try_output_recovery_with_pkd_esk};
use zcash_primitives::transaction::{
    Authorization, TransactionData, TxVersion,
    builder::{BuildConfig, Builder, BundlePadding},
    fees::{FeeRule as _, zip317},
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID},
    memo::MemoBytes,
    value::Zatoshis,
};
use zeroize::Zeroizing;
use ziquid_protocol::{
    IRONWOOD_POOL, MAX_QUOTED_RECEIVERS, PreparationBinding, SOURCE_TESTNET,
    SOURCE_TRANSACTION_VERSION, SolverCapsule, StatementContext, ValidatedContext,
    input_commitment, note_consumption_tag, payment_commitment, preparation_consent_digest,
    preparation_packet_binding, solver_capsule_commitment,
};

use crate::{
    IronwoodTransaction, OwnedInput, PayoutWitness,
    witness::{SenderOutputWitness, effect_id},
};

/// Sanitized categories: never include PCZTs, notes, keys, paths or source locators.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthoringError {
    WrongNoteVersion,
    InvalidInputValue,
    InputNotOwned,
    AnchorMismatch,
    InvalidHeight,
    WrongBranch,
    MissingOutputs,
    RecoveryOutputNotOwned,
    UnbalancedOutputs,
    BuilderRejected,
    InvalidPczt,
    InvalidInputRelation,
    InvalidPreparationIntent,
    InvalidOutputIndex,
    InvalidOutputCiphertext,
    EffectsMismatch,
    WrongCircuitVersion,
    FinalizationFailed,
    ProvingFailed,
    SigningFailed,
    ExtractionFailed,
}

impl fmt::Display for AuthoringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Local Ironwood authoring failed: {self:?}")
    }
}

impl std::error::Error for AuthoringError {}

/// Genuine wallet-local source parameters, not another DEX context encoding.
/// The caller binds these values to its ValidatedContext before release/funding.
#[derive(Clone, Debug)]
pub struct SourceParameters {
    pub network: Network,
    pub target_height: BlockHeight,
    pub expiry_height: BlockHeight,
    pub consensus_branch: BranchId,
    pub fee_rule: zip317::FeeRule,
}

impl SourceParameters {
    pub(crate) fn validate(&self) -> Result<(), AuthoringError> {
        ziquid_proofs::native_relation::validate_source(&ziquid_proofs::native_relation::SourceFacts {
            network: self.network, target_height: self.target_height, expiry_height: self.expiry_height,
            consensus_branch: self.consensus_branch, fee_rule: &self.fee_rule,
        }).map_err(crate::witness::relation_error)?;
        Ok(())
    }
}

/// Every output, including change, is explicit: no automatic fee input or top-up.
#[derive(Clone)]
pub struct OutputPlan {
    recipient: Address,
    value: Zatoshis,
    memo: MemoBytes,
}

impl fmt::Debug for OutputPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutputPlan([redacted])")
    }
}

impl OutputPlan {
    pub fn new(recipient: Address, value: Zatoshis, memo: MemoBytes) -> Self {
        Self {
            recipient,
            value,
            memo,
        }
    }
    pub fn recipient(&self) -> Address {
        self.recipient
    }
    pub fn value(&self) -> Zatoshis {
        self.value
    }
    pub fn memo(&self) -> &MemoBytes {
        &self.memo
    }
}

/// Exact redacted effects, NOT a consensus transaction or ownership certificate.
/// No SpendAuth (including padding signatures), FVK, dummy key, witness,
/// alpha, output opening, binding key or source proof is carried to S.
pub struct UnsignedPayment {
    pczt_bytes: Vec<u8>,
    effect_id: [u8; 32],
}

impl fmt::Debug for UnsignedPayment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnsignedPayment([redacted])")
    }
}

impl UnsignedPayment {
    pub fn pczt_bytes(&self) -> &[u8] {
        &self.pczt_bytes
    }
    pub fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }
}

/// Final Q consensus bytes only: never a proving PCZT or U FVK to S.
/// Task3's independent application certificate is still required before funding;
/// valid source signatures do not certify that all outputs belong to U.
pub struct ExecutableSelfSpend {
    transaction_bytes: Vec<u8>,
    effect_id: [u8; 32],
    authorization_id: [u8; 32],
}

impl fmt::Debug for ExecutableSelfSpend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExecutableSelfSpend([redacted])")
    }
}

impl ExecutableSelfSpend {
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }
    pub fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }
    pub fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }
}
/// Owner-reviewed complete context and private semantic openings, never an opaque
/// digest signing request. All four blinds must be fresh, independent,
/// confidential CSPRNG values; equality/zero checks cannot establish entropy.
/// Receivers are the exact strictly sorted, canonical S-authorized destinations.
/// This type does not authenticate S's quote or funding authority.
pub struct PreparationIntent<'a> {
    pub context: &'a ValidatedContext,
    pub input_blind: &'a [u8; 32],
    pub payment_blind: &'a [u8; 32],
    pub receivers: &'a [[u8; 43]],
    pub preparation_blind: &'a [u8; 32],
    pub capsule_blind: &'a [u8; 32],
}

impl fmt::Debug for PreparationIntent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparationIntent([redacted])")
    }
}


/// Private wallet-local preparation. Persist sender/prover data before exporting.
pub struct PreparedPair {
    unsigned_payment: UnsignedPayment,
    payout_witness: PayoutWitness,
    recovery_pczt: Pczt,
    recovery_effect_id: [u8; 32],
    payment_fee: Zatoshis,
    recovery_fee: Zatoshis,
    source_network: Network,
    source_target_height: u32,
}

impl fmt::Debug for PreparedPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedPair([redacted])")
    }
}

impl PreparedPair {
    pub fn unsigned_payment(&self) -> &UnsignedPayment {
        &self.unsigned_payment
    }
    pub fn payout_witness(&self) -> &PayoutWitness {
        &self.payout_witness
    }
    pub fn payment_fee(&self) -> Zatoshis {
        self.payment_fee
    }
    pub fn recovery_fee(&self) -> Zatoshis {
        self.recovery_fee
    }
    /// Exact source height already validated during prepare; never inferred from
    /// the branch, expiry or lock time when constructing the private proof input.
    pub fn source_target_height(&self) -> u32 {
        self.source_target_height
    }

    /// Sign distinct private owner consent only after checking the actual P/Q
    /// relation and owner-reviewed context. Borrows ask locally without retaining
    /// it, overwriting Q's signatures, or authorizing/releasing P.
    /// Q must be the final result of this pair's checked finish_recovery path;
    /// its full effects and all source signatures are checked again here, without
    /// rebuilding or rerunning the already-verified Halo2 proof.
    /// Newly materialized private byte buffers are zeroized on return; caller
    /// inputs/returned signature and upstream typed crypto objects are not covered
    /// by that guarantee and remain the caller/upstream custody responsibility.
    /// The solver capsule is derived from this pair's exact P and final Q, never
    /// accepted as a caller-supplied digest; only its independent blind is borrowed.
    /// No source history, exclusive S ownership, S quote/funding approval,
    /// deployment trust, financial settlement or replay reservation is implied.
    pub fn authorize_preparation<R: RngCore + CryptoRng>(
        &self,
        input: &OwnedInput,
        q: &ExecutableSelfSpend,
        intent: PreparationIntent<'_>,
        ask: &SpendAuthorizingKey,
        rng: &mut R,
    ) -> Result<[u8; 64], AuthoringError> {
        let retained = self.payout_witness.owned_input();
        let note = input.note();
        if note.version() != retained.note().version()
            || note.recipient() != retained.note().recipient()
            || note.value() != retained.note().value()
            || note.rho() != retained.note().rho()
            || note.rseed().as_bytes() != retained.note().rseed().as_bytes()
            || input.full_viewing_key() != retained.full_viewing_key()
            || input.merkle_path().position() != retained.merkle_path().position()
            || input.merkle_path().auth_path() != retained.merkle_path().auth_path()
            || input.anchor() != retained.anchor()
            || input.full_viewing_key().scope_for_address(&note.recipient()).is_none()
            || input.merkle_path().root(note.commitment().into()) != input.anchor()
        {
            return Err(AuthoringError::InvalidInputRelation);
        }
        if q.effect_id() != self.recovery_effect_id {
            return Err(AuthoringError::EffectsMismatch);
        }
        let context = intent.context.context();
        if self.source_network != Network::TestNetwork
            || context.source_network != SOURCE_TESTNET
            || context.source_pool != IRONWOOD_POOL
            || context.transaction_version != SOURCE_TRANSACTION_VERSION
            || context.consensus_branch != u32::from(BranchId::Nu6_3)
            || !(4_134_000..4_465_026).contains(&self.source_target_height)
            || context.source_expiry < self.source_target_height
            || context.source_expiry >= 4_465_026
            || u64::from(self.payment_fee) > context.source_fee_cap
            || u64::from(self.recovery_fee) > context.source_fee_cap
            || intent.input_blind == intent.payment_blind
            || intent.capsule_blind.iter().all(|&byte| byte == 0)
            || intent.capsule_blind == intent.preparation_blind
            || intent.capsule_blind == intent.input_blind
            || intent.capsule_blind == intent.payment_blind
            || intent.receivers.is_empty()
            || intent.receivers.len() > MAX_QUOTED_RECEIVERS
            || intent.receivers.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AuthoringError::InvalidPreparationIntent);
        }
        for receiver in intent.receivers {
            let address = Address::from_raw_address_bytes(receiver)
                .into_option()
                .ok_or(AuthoringError::InvalidPreparationIntent)?;
            let canonical = Zeroizing::new(address.to_raw_address_bytes());
            if *canonical != *receiver
                || input.full_viewing_key().scope_for_address(&address).is_some()
            {
                return Err(AuthoringError::InvalidPreparationIntent);
            }
        }

        let anchor = Zeroizing::new(input.anchor().to_bytes());
        let private_p = Pczt::parse(self.payout_witness.private_pczt_bytes())
            .map_err(|_| AuthoringError::InvalidPczt)?;
        let redacted_p = Pczt::parse(self.unsigned_payment.pczt_bytes())
            .map_err(|_| AuthoringError::InvalidPczt)?;
        for pczt in [&private_p, &redacted_p, &self.recovery_pczt] {
            if *pczt.global().tx_version() != V6_TX_VERSION
                || *pczt.global().version_group_id() != V6_VERSION_GROUP_ID
                || *pczt.global().consensus_branch_id() != context.consensus_branch
                || *pczt.global().expiry_height() != context.source_expiry
                || pczt.ironwood().anchor().as_ref() != Some(&*anchor)
            {
                return Err(AuthoringError::InvalidPreparationIntent);
            }
        }
        // Verifier owns each parsed artifact once, then consumes its checked
        // result for the effects. Only retained immutable Q needs a clone.
        let verified_p = Verifier::new(private_p)
            .with_ironwood::<AuthoringError, _>(|bundle| {
                validate_preparation_bundle(
                    bundle, input, self.payment_fee, self.source_target_height,
                    context, Some(intent.receivers),
                ).map(|_| ()).map_err(OrchardError::Custom)
            })
            .map_err(preparation_role_error)?
            .finish();
        let p_effects = verified_p.into_effects().map_err(|_| AuthoringError::InvalidPczt)?;
        let exported_effects = redacted_p.into_effects().map_err(|_| AuthoringError::InvalidPczt)?;
        let mut randomized_ask = None;
        let verified_q = Verifier::new(self.recovery_pczt.clone())
            .with_ironwood::<AuthoringError, _>(|bundle| {
                let real_index = validate_preparation_bundle(
                    bundle, input, self.recovery_fee, self.source_target_height,
                    context, None,
                ).map_err(OrchardError::Custom)?;
                let spend = bundle.actions()[real_index].spend();
                let alpha = spend.alpha().as_ref()
                    .ok_or(OrchardError::Custom(AuthoringError::InvalidInputRelation))?;
                let key = ask.randomize(alpha);
                if redpallas::VerificationKey::from(&key) != *spend.rk() {
                    return Err(OrchardError::Custom(AuthoringError::SigningFailed));
                }
                randomized_ask = Some(key);
                Ok(())
            })
            .map_err(preparation_role_error)?
            .finish();
        let q_effects = verified_q.into_effects().map_err(|_| AuthoringError::InvalidPczt)?;
        let parsed_q = IronwoodTransaction::parse(q.transaction_bytes(), BranchId::Nu6_3)
            .map_err(|_| AuthoringError::InvalidPczt)?;
        compare_preparation_effects(&p_effects, &exported_effects)?;
        compare_preparation_headers(&p_effects, &q_effects)?;
        compare_preparation_effects(&q_effects, parsed_q.transaction())?;
        let payment_effect = effect_id(&p_effects);
        if payment_effect != self.unsigned_payment.effect_id()
            || effect_id(&q_effects) != self.recovery_effect_id
            || parsed_q.effect_id() != q.effect_id()
            || parsed_q.authorization_id() != q.authorization_id()
        {
            return Err(AuthoringError::EffectsMismatch);
        }
        let q_bundle = parsed_q.transaction().ironwood_bundle()
            .ok_or(AuthoringError::InvalidPczt)?;
        // Pure shielded v6's source signature digest is its upstream effect ID.
        for action in q_bundle.actions().iter() {
            action.rk().verify(&q.effect_id(), action.authorization())
                .map_err(|_| AuthoringError::SigningFailed)?;
        }
        q_bundle.binding_validating_key()
            .verify(&q.effect_id(), q_bundle.authorization().binding_signature())
            .map_err(|_| AuthoringError::SigningFailed)?;

        let fvk_bytes = Zeroizing::new(input.full_viewing_key().to_bytes());
        let nf = Zeroizing::new(input.nullifier().to_bytes());
        let recipient = Zeroizing::new(note.recipient().to_raw_address_bytes());
        let rho = Zeroizing::new(note.rho().to_bytes());
        let cmx = Zeroizing::new(ExtractedNoteCommitment::from(note.commitment()).to_bytes());
        let siblings = Zeroizing::new(input.merkle_path().auth_path().map(|node| node.to_bytes()));
        let actual_input = input_commitment(
            intent.input_blind, &context.source_network, &context.source_pool,
            &recipient, note.value().inner(), &rho, note.rseed().as_bytes(), &cmx, &nf,
        ).map_err(|_| AuthoringError::InvalidPreparationIntent)?;
        let actual_payment = payment_commitment(
            intent.payment_blind, &context.source_network, &context.source_pool,
            &payment_effect, intent.receivers, context.source_quoted_amount,
        ).map_err(|_| AuthoringError::InvalidPreparationIntent)?;
        let tag = note_consumption_tag(
            &context.source_network, &context.source_pool, context.evm_chain_id,
            &context.escrow,
            fvk_bytes[32..64].try_into().map_err(|_| AuthoringError::InvalidInputRelation)?,
            &nf,
        ).map_err(|_| AuthoringError::InvalidPreparationIntent)?;
        if actual_input != context.real_input_commitment
            || actual_payment != context.source_payment_commitment
            || tag != context.consumption_tag
        {
            return Err(AuthoringError::InvalidPreparationIntent);
        }
        let binding = Zeroizing::new(preparation_packet_binding(PreparationBinding {
            context: intent.context,
            preparation_blind: intent.preparation_blind,
            redacted_payment: self.unsigned_payment.pczt_bytes(),
            recovery_transaction: q.transaction_bytes(),
            note_recipient: &recipient,
            note_value: note.value().inner(),
            note_rho: &rho,
            note_rseed: note.rseed().as_bytes(),
            full_viewing_key: &fvk_bytes,
            merkle_position: input.merkle_path().position(),
            merkle_siblings: &siblings,
            anchor: &anchor,
            source_target_height: self.source_target_height,
        }).map_err(|_| AuthoringError::InvalidPreparationIntent)?);
        let capsule = Zeroizing::new(solver_capsule_commitment(SolverCapsule {
            context: intent.context,
            private_packet_binding: &binding,
            capsule_blind: intent.capsule_blind,
            redacted_payment: self.unsigned_payment.pczt_bytes(),
            recovery_transaction: q.transaction_bytes(),
        }).map_err(|_| AuthoringError::InvalidPreparationIntent)?);
        let message = Zeroizing::new(preparation_consent_digest(intent.context, &binding, &capsule)
            .map_err(|_| AuthoringError::InvalidPreparationIntent)?);
        let signature = Zeroizing::new(<[u8; 64]>::from(
            &randomized_ask.ok_or(AuthoringError::SigningFailed)?.sign(rng, message.as_ref()),
        ));
        Ok(*signature)
    }

    /// Private persistence/application-prover boundary, never part of the S packet.
    pub fn private_recovery_pczt_bytes(&self) -> Result<Vec<u8>, AuthoringError> {
        self.recovery_pczt
            .clone()
            .serialize()
            .map_err(|_| AuthoringError::InvalidPczt)
    }

    /// Locally prove, sign EVERY action and extract Q. Borrowed ask is not retained.
    /// The original private artifacts remain available for durable app/sender use.
    pub fn finish_recovery(
        &self,
        ask: &SpendAuthorizingKey,
        proving_key: &ProvingKey,
        verifying_key: &VerifyingKey,
    ) -> Result<ExecutableSelfSpend, AuthoringError> {
        if proving_key.circuit_version() != OrchardCircuitVersion::PostNu6_3
            || verifying_key.circuit_version() != OrchardCircuitVersion::PostNu6_3
        {
            return Err(AuthoringError::WrongCircuitVersion);
        }
        let finalized = IoFinalizer::new(self.recovery_pczt.clone())
            .finalize_io()
            .map_err(|_| AuthoringError::FinalizationFailed)?;
        // Upstream I/O finalization signs genuine padding dummies; sign all
        // remaining actions, not an assumed index zero or one-action bundle.
        let missing: Vec<usize> = finalized
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .filter_map(|(i, action)| action.spend().spend_auth_sig().is_none().then_some(i))
            .collect();
        let mut signer = Signer::new(finalized).map_err(|_| AuthoringError::SigningFailed)?;
        for index in missing {
            signer
                .sign_ironwood(index, ask)
                .map_err(|_| AuthoringError::SigningFailed)?;
        }
        let proved = Prover::new(signer.finish())
            .create_ironwood_proof(proving_key)
            .map_err(|_| AuthoringError::ProvingFailed)?
            .finish();
        let transaction = TransactionExtractor::new(proved)
            .with_orchard(verifying_key)
            .extract()
            .map_err(|_| AuthoringError::ExtractionFailed)?;
        if <[u8; 32]>::from(transaction.txid()) != self.recovery_effect_id {
            return Err(AuthoringError::EffectsMismatch);
        }
        let mut bytes = Vec::new();
        transaction
            .write(&mut bytes)
            .map_err(|_| AuthoringError::ExtractionFailed)?;
        let parsed = IronwoodTransaction::parse(&bytes, BranchId::Nu6_3)
            .map_err(|_| AuthoringError::ExtractionFailed)?;
        Ok(ExecutableSelfSpend {
            transaction_bytes: bytes,
            effect_id: parsed.effect_id(),
            authorization_id: parsed.authorization_id(),
        })
    }
}

/// Standard anchored, normally padded P/Q from exactly one positive U-owned V3
/// note. Checks Q ownership LOCALLY, not independently for S without an FVK.
/// No preparation certificate or verified financial fact is fabricated here.
pub fn prepare<R: RngCore + CryptoRng>(
    source: &SourceParameters,
    input: &OwnedInput,
    payment_outputs: &[OutputPlan],
    recovery_outputs: &[OutputPlan],
    rng: &mut R,
) -> Result<PreparedPair, AuthoringError> {
    source.validate()?;
    if payment_outputs.is_empty() || recovery_outputs.is_empty() {
        return Err(AuthoringError::MissingOutputs);
    }
    for output in recovery_outputs {
        if input
            .full_viewing_key()
            .scope_for_address(&output.recipient)
            .is_none()
        {
            return Err(AuthoringError::RecoveryOutputNotOwned);
        }
    }
    let payment = build_pczt(source, input, payment_outputs, rng)?;
    let recovery = build_pczt(source, input, recovery_outputs, rng)?;
    let payment_effect_id = effect_id(
        &payment
            .pczt
            .clone()
            .into_effects()
            .map_err(|_| AuthoringError::InvalidPczt)?,
    );
    let recovery_effect_id = effect_id(
        &recovery
            .pczt
            .clone()
            .into_effects()
            .map_err(|_| AuthoringError::InvalidPczt)?,
    );
    // Preserve all private input/dummy/output/encryption material FIRST.
    let payout_witness = PayoutWitness {
        input: input.clone(),
        private_pczt_bytes: payment
            .pczt
            .clone()
            .serialize()
            .map_err(|_| AuthoringError::InvalidPczt)?,
        effect_id: payment_effect_id,
        outputs: payment.outputs,
        requested_output_actions: payment.requested_output_actions,
    };
    let redacted = Redactor::new(payment.pczt)
        .redact_global_with(|mut global| global.clear_proprietary())
        .redact_ironwood_with(|mut bundle| {
            bundle.clear_bsk();
            bundle.clear_zkproof();
            bundle.redact_actions(|mut action| {
                action.clear_spend_auth_sig();
                action.clear_spend_recipient();
                action.clear_spend_value();
                action.clear_spend_rho();
                action.clear_spend_rseed();
                action.clear_spend_fvk();
                action.clear_spend_witness();
                action.clear_spend_alpha();
                action.clear_spend_zip32_derivation();
                action.clear_spend_dummy_sk();
                action.clear_spend_proprietary();
                action.clear_output_recipient();
                action.clear_output_value();
                action.clear_output_rseed();
                action.clear_output_ock();
                action.clear_output_zip32_derivation();
                action.clear_output_user_address();
                action.clear_output_proprietary();
                action.clear_rcv();
            });
        })
        .finish();
    // Never strip memo ciphertext or reconstruct encryption in the export.
    if effect_id(
        &redacted
            .clone()
            .into_effects()
            .map_err(|_| AuthoringError::InvalidPczt)?,
    ) != payment_effect_id
    {
        return Err(AuthoringError::EffectsMismatch);
    }
    Ok(PreparedPair {
        unsigned_payment: UnsignedPayment {
            pczt_bytes: redacted
                .serialize()
                .map_err(|_| AuthoringError::InvalidPczt)?,
            effect_id: payment_effect_id,
        },
        payout_witness,
        recovery_pczt: recovery.pczt,
        recovery_effect_id,
        payment_fee: payment.fee,
        recovery_fee: recovery.fee,
        source_network: source.network,
        source_target_height: u32::from(source.target_height),
    })
}

pub(crate) struct BuiltPczt {
    pub(crate) pczt: Pczt,
    pub(crate) fee: Zatoshis,
    pub(crate) outputs: Vec<SenderOutputWitness>,
    pub(crate) requested_output_actions: Vec<usize>,
}

pub(crate) fn build_pczt<R: RngCore + CryptoRng>(
    source: &SourceParameters,
    input: &OwnedInput,
    outputs: &[OutputPlan],
    rng: &mut R,
) -> Result<BuiltPczt, AuthoringError> {
    let mut builder = Builder::new(
        source.network,
        source.target_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(input.anchor()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    .with_expiry_height(source.expiry_height);
    builder
        .add_ironwood_spend::<zip317::FeeError>(
            input.full_viewing_key().clone(),
            *input.note(),
            input.merkle_path().clone(),
        )
        .map_err(|_| AuthoringError::BuilderRejected)?;
    for output in outputs {
        // No master OVK needed; sender note randomness retained below suffices.
        builder
            .add_ironwood_output::<zip317::FeeError>(
                None,
                output.recipient,
                output.value,
                output.memo.clone(),
            )
            .map_err(|_| AuthoringError::BuilderRejected)?;
    }
    let fee = builder
        .get_fee(&source.fee_rule)
        .map_err(|_| AuthoringError::BuilderRejected)?;
    let output_sum = outputs
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(u64::from(output.value)))
        .ok_or(AuthoringError::UnbalancedOutputs)?;
    if output_sum.checked_add(u64::from(fee)) != Some(input.note().value().inner()) {
        return Err(AuthoringError::UnbalancedOutputs);
    }
    let built = builder
        .build_for_pczt(rng, &source.fee_rule)
        .map_err(|_| AuthoringError::BuilderRejected)?;
    let requested_output_actions = (0..outputs.len())
        .map(|i| {
            built
                .ironwood_meta
                .output_action_index(i)
                .ok_or(AuthoringError::InvalidOutputIndex)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let pczt = Creator::build_from_parts(built.pczt_parts).ok_or(AuthoringError::InvalidPczt)?;
    let private = Zeroizing::new(pczt.clone().serialize().map_err(|_| AuthoringError::InvalidPczt)?);
    let restored = ziquid_proofs::native_relation::restore_funding(&private,
        &ziquid_proofs::native_relation::OwnedInputFacts {
            note: input.note(), full_viewing_key: input.full_viewing_key(),
            merkle_path: input.merkle_path(), anchor: input.anchor(),
        }, &requested_output_actions).map_err(crate::witness::relation_error)?;
    let sender_outputs = restored.outputs.into_iter().map(|output| SenderOutputWitness {
        action_index: output.action_index, note: output.note, memo: *output.memo,
    }).collect::<Vec<_>>();
    for (&index, plan) in requested_output_actions.iter().zip(outputs) {
        let output = &sender_outputs[index];
        if output.note.recipient() != plan.recipient || output.note.value().inner() != u64::from(plan.value)
            || &output.memo != plan.memo.as_array() { return Err(AuthoringError::InvalidOutputCiphertext); }
    }
    Ok(BuiltPczt {
        pczt,
        fee,
        outputs: sender_outputs,
        requested_output_actions,
    })
}

fn output_note(action: &orchard::pczt::Action) -> Result<Note, AuthoringError> {
    let output = action.output();
    let rho = Rho::from_bytes(&action.spend().nullifier().to_bytes())
        .into_option()
        .ok_or(AuthoringError::InvalidOutputCiphertext)?;
    Note::from_parts(
        *output
            .recipient()
            .as_ref()
            .ok_or(AuthoringError::InvalidOutputCiphertext)?,
        *output
            .value()
            .as_ref()
            .ok_or(AuthoringError::InvalidOutputCiphertext)?,
        rho,
        *output
            .rseed()
            .as_ref()
            .ok_or(AuthoringError::InvalidOutputCiphertext)?,
        NoteVersion::V3,
    )
    .into_option()
    .ok_or(AuthoringError::InvalidOutputCiphertext)
}

fn preparation_role_error(error: OrchardError<AuthoringError>) -> AuthoringError {
    match error {
        OrchardError::Custom(error) => error,
        _ => AuthoringError::InvalidPczt,
    }
}

fn compare_preparation_headers<A: Authorization, B: Authorization>(
    left: &TransactionData<A>,
    right: &TransactionData<B>,
) -> Result<(), AuthoringError> {
    if left.version() != TxVersion::V6
        || right.version() != left.version()
        || left.consensus_branch_id() != BranchId::Nu6_3
        || right.consensus_branch_id() != left.consensus_branch_id()
        || left.expiry_height() != right.expiry_height()
        || left.lock_time() != right.lock_time()
        || left.transparent_bundle().is_some()
        || right.transparent_bundle().is_some()
        || left.sprout_bundle().is_some()
        || right.sprout_bundle().is_some()
        || left.sapling_bundle().is_some()
        || right.sapling_bundle().is_some()
        || left.orchard_bundle().is_some()
        || right.orchard_bundle().is_some()
    {
        return Err(AuthoringError::EffectsMismatch);
    }
    Ok(())
}

fn compare_preparation_effects<A: Authorization, B: Authorization>(
    left: &TransactionData<A>,
    right: &TransactionData<B>,
) -> Result<(), AuthoringError> {
    compare_preparation_headers(left, right)?;
    let left = left.ironwood_bundle().ok_or(AuthoringError::InvalidPczt)?;
    let right = right.ironwood_bundle().ok_or(AuthoringError::InvalidPczt)?;
    if left.bundle_version() != right.bundle_version()
        || left.flag_byte() != right.flag_byte()
        || left.anchor() != right.anchor()
        || left.value_balance() != right.value_balance()
        || left.actions().len() != right.actions().len()
    {
        return Err(AuthoringError::EffectsMismatch);
    }
    // Compare upstream effects, not private pre-proof bytes or only txid: v6's
    // anchor is authorizing data, and final Q adds a proof/source signatures.
    for (left, right) in left.actions().iter().zip(right.actions().iter()) {
        let left_ciphertext = left.encrypted_note();
        let right_ciphertext = right.encrypted_note();
        if left.cv_net().to_bytes() != right.cv_net().to_bytes()
            || left.nullifier() != right.nullifier()
            || left.rk() != right.rk()
            || left.cmx() != right.cmx()
            || left_ciphertext.epk_bytes != right_ciphertext.epk_bytes
            || left_ciphertext.enc_ciphertext != right_ciphertext.enc_ciphertext
            || left_ciphertext.out_ciphertext != right_ciphertext.out_ciphertext
        {
            return Err(AuthoringError::EffectsMismatch);
        }
    }
    Ok(())
}

fn validate_preparation_bundle(
    bundle: &orchard::pczt::Bundle,
    input: &OwnedInput,
    retained_fee: Zatoshis,
    source_target_height: u32,
    context: &StatementContext,
    receivers: Option<&[[u8; 43]]>,
) -> Result<usize, AuthoringError> {
    if *bundle.bundle_version() != BundleVersion::ironwood_v3()
        || bundle.flag_byte() & 3 != 3
        || bundle.anchor() != &input.anchor()
        || bundle.zkproof().is_some()
        || bundle.bsk().is_some()
    {
        return Err(AuthoringError::InvalidPczt);
    }
    bundle.verify_cross_address_restriction()
        .map_err(|_| AuthoringError::InvalidInputRelation)?;
    let mut real_index = None;
    let mut output_total = 0u64;
    let mut payment_total = 0u64;
    let mut nullifiers = Zeroizing::new(Vec::with_capacity(bundle.actions().len()));
    for (index, action) in bundle.actions().iter().enumerate() {
        let spend = action.spend();
        if *spend.note_version() != NoteVersion::V3
            || spend.fvk().is_none()
            || spend.spend_auth_sig().is_some()
            || spend.rk().is_identity()
        {
            return Err(AuthoringError::InvalidInputRelation);
        }
        action.verify_cv_net().map_err(|_| AuthoringError::InvalidInputRelation)?;
        spend.verify_nullifier(Some(input.full_viewing_key()))
            .map_err(|_| AuthoringError::InvalidInputRelation)?;
        spend.verify_rk(Some(input.full_viewing_key()))
            .map_err(|_| AuthoringError::InvalidInputRelation)?;
        let value = spend.value().as_ref()
            .ok_or(AuthoringError::InvalidInputRelation)?.inner();
        Zatoshis::from_u64(value).map_err(|_| AuthoringError::InvalidInputRelation)?;
        nullifiers.push(spend.nullifier().to_bytes());
        if value != 0 {
            let note = input.note();
            let path = spend.witness().as_ref().ok_or(AuthoringError::InvalidInputRelation)?;
            if real_index.is_some()
                || value != note.value().inner()
                || spend.recipient().as_ref() != Some(&note.recipient())
                || spend.rho().as_ref() != Some(&note.rho())
                || spend.rseed().as_ref().map(|seed| seed.as_bytes()) != Some(note.rseed().as_bytes())
                || spend.fvk().as_ref() != Some(input.full_viewing_key())
                || spend.nullifier() != &input.nullifier()
                || path.position() != input.merkle_path().position()
                || path.auth_path() != input.merkle_path().auth_path()
                || path.root(note.commitment().into()) != input.anchor()
            {
                return Err(AuthoringError::InvalidInputRelation);
            }
            real_index = Some(index);
        }
        if *action.output().note_version() != NoteVersion::V3 {
            return Err(AuthoringError::InvalidOutputCiphertext);
        }
        action.output().verify_note_commitment(spend)
            .map_err(|_| AuthoringError::InvalidOutputCiphertext)?;
        let note = output_note(action)?;
        let (recovered, recipient, memo) = try_output_recovery_with_pkd_esk(
            &IronwoodDomain::for_pczt_action(action),
            IronwoodDomain::get_pk_d(&note),
            IronwoodDomain::derive_esk(&note).ok_or(AuthoringError::InvalidOutputCiphertext)?,
            action,
        ).ok_or(AuthoringError::InvalidOutputCiphertext)?;
        let _memo = Zeroizing::new(memo);
        if recovered != note
            || recipient != note.recipient()
            || recovered.value() != note.value()
            || recovered.rho() != note.rho()
            || recovered.rseed().as_bytes() != note.rseed().as_bytes()
            || recovered.version() != NoteVersion::V3
        {
            return Err(AuthoringError::InvalidOutputCiphertext);
        }
        // Recover EVERY output (padding included), independently of positive
        // spend positions or caller-requested output metadata.
        output_total = preparation_sum(output_total, note.value().inner())?;
        if let Some(receivers) = receivers {
            let raw_recipient = Zeroizing::new(recipient.to_raw_address_bytes());
            if receivers.binary_search(&*raw_recipient).is_ok() {
                payment_total = preparation_sum(payment_total, note.value().inner())?;
            }
        } else if note.value().inner() != 0
            && input.full_viewing_key().scope_for_address(&recipient).is_none()
        {
            return Err(AuthoringError::RecoveryOutputNotOwned);
        }
    }
    let real_index = real_index.ok_or(AuthoringError::InvalidInputRelation)?;
    nullifiers.sort_unstable();
    if nullifiers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AuthoringError::InvalidInputRelation);
    }
    if receivers.is_some() && payment_total != context.source_quoted_amount {
        return Err(AuthoringError::InvalidPreparationIntent);
    }
    let fee = input.note().value().inner().checked_sub(output_total)
        .ok_or(AuthoringError::UnbalancedOutputs)?;
    let declared = i64::try_from(*bundle.value_sum())
        .map_err(|_| AuthoringError::UnbalancedOutputs)?;
    if u64::try_from(declared).ok() != Some(fee) || fee != u64::from(retained_fee) {
        return Err(AuthoringError::UnbalancedOutputs);
    }
    let required = zip317::FeeRule::standard().fee_required(
        &Network::TestNetwork,
        BlockHeight::from(source_target_height),
        std::iter::empty(), std::iter::empty(), 0, 0, 0, bundle.actions().len(),
    ).map_err(|_| AuthoringError::InvalidPreparationIntent)?;
    if fee != u64::from(required) || fee > context.source_fee_cap {
        return Err(AuthoringError::InvalidPreparationIntent);
    }
    Ok(real_index)
}

fn preparation_sum(sum: u64, value: u64) -> Result<u64, AuthoringError> {
    let total = sum.checked_add(value).ok_or(AuthoringError::UnbalancedOutputs)?;
    Zatoshis::from_u64(total).map_err(|_| AuthoringError::UnbalancedOutputs)?;
    Ok(total)
}
