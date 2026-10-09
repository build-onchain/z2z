//! Source-local funding of the exact builder-generated route-1a joint note J.
//!
//! Prepare unsigned F, retain its generated J opening, preauthorize and durably
//! retain early R independently, then explicitly authorize completion of THIS F.
//! Finished R requires later J membership; requiring it before F is circular.
//! The C-only target-arming gate must not be applied to F.
//!
//! This module establishes neither durable R custody nor funding preflight,
//! source admission, unspent status, finality, financial proofs, or a usable
//! branch/fee/retirement window. Those remain caller prerequisites; a source
//! signature or local Halo2 proof is not financial authorization. Current funded
//! execution remains unqualified until those independent gates are satisfied.
//! Private F PCZT/input/FVK material belongs only to the funding wallet, NOT the
//! counterparty's fresh-J auxiliary packet. No complete J ask is needed or made.

use std::fmt;

use orchard::{
    Note,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, SpendAuthorizingKey},
};
use pczt::{
    Pczt,
    roles::{
        io_finalizer::IoFinalizer, prover::Prover, signer::Signer,
        tx_extractor::TransactionExtractor,
    },
};
use rand_core::{CryptoRng, RngCore};
use zcash_protocol::{consensus::Network, value::Zatoshis};
use zeroize::Zeroizing;

use crate::{
    AuthoringError, IronwoodTransaction, OutputPlan, OwnedInput, PayoutWitness,
    SourceParameters, ValidationError, authoring::build_pczt,
};
use ziquid_proofs::native_relation::{self, FundingFacts, NativeOutputFacts, OwnedInputFacts, SourceFacts};

/// Sanitized local failure categories, never private keys, notes or PCZT bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FundingError {
    Source(AuthoringError),
    TestnetRequired,
    GroupMismatch,
    InvalidJointOutput,
    JointOutputNotOwned,
    Consensus(ValidationError),
}

impl fmt::Display for FundingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local joint funding rejected: {self:?}")
    }
}

impl std::error::Error for FundingError {}

impl From<AuthoringError> for FundingError {
    fn from(error: AuthoringError) -> Self {
        Self::Source(error)
    }
}

/// Exact unsigned F and private sender custody, not a source/financial certificate.
/// The retained mapping distinguishes identical plans and explicit zero outputs.
/// Typed upstream notes/FVKs and the existing PayoutWitness do not promise erasure;
/// the caller owns encrypted persistence, permissions and private-material custody.
pub struct PreparedJointFunding {
    payout_witness: PayoutWitness,
    source: SourceParameters,
    fee: Zatoshis,
    joint_requested_index: usize,
    joint_fvk: FullViewingKey,
    group_ak: [u8; 32],
}

impl fmt::Debug for PreparedJointFunding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedJointFunding([redacted])")
    }
}

impl PreparedJointFunding {
    /// Actual generated opening, available before wallet SpendAuth or Halo2 proof.
    /// Disclosure requires the caller's per-swap fresh-J grant, never public logs.
    pub fn joint_note(&self) -> &Note {
        &self.payout_witness.outputs[self.joint_action_index()].note
    }

    pub fn joint_action_index(&self) -> usize {
        self.payout_witness.requested_output_actions()[self.joint_requested_index]
    }

    pub fn joint_requested_index(&self) -> usize {
        self.joint_requested_index
    }

    pub fn joint_memo(&self) -> &[u8; 512] {
        &self.payout_witness.outputs[self.joint_action_index()].memo
    }

    /// Caller-supplied fresh-J FVK, NOT the funding wallet's FVK.
    pub fn joint_full_viewing_key(&self) -> &FullViewingKey {
        &self.joint_fvk
    }

    pub fn group_ak(&self) -> [u8; 32] {
        self.group_ak
    }

    pub fn source_parameters(&self) -> &SourceParameters {
        &self.source
    }

    pub fn effect_id(&self) -> [u8; 32] {
        self.payout_witness.effect_id()
    }

    pub fn fee(&self) -> Zatoshis {
        self.fee
    }

    /// Explicit OWNER-LOCAL boundary: includes wallet FVK/note/path/dummy keys.
    /// Never disclose these bytes as if they contained only fresh-J material.
    pub fn private_pczt_bytes(&self) -> &[u8] {
        self.payout_witness.private_pczt_bytes()
    }

    /// Owner-local exact input, output mapping/openings and ciphertext recovery.
    pub fn payout_witness(&self) -> &PayoutWitness {
        &self.payout_witness
    }

    /// Complete only the retained F using a borrowed REAL FUNDING WALLET ask.
    /// Invoking this method is the caller's explicit local authorization boundary:
    /// first independently verify durable early-R/completion/protection custody,
    /// the exact outputs/change/memos/fee and qualified source/lifetime preflight.
    /// This API cannot attest those prerequisites or grant release/send authority.
    /// Failure returns no partially signed artifact; the unsigned F is unchanged.
    /// The installed PCZT roles use their own OsRng for proof/signing/finalization;
    /// independent full authorization verification is deterministic and borrows F.
    pub fn complete_borrowed_owner<R: RngCore + CryptoRng>(
        &self,
        ask: &SpendAuthorizingKey,
        proving_key: &ProvingKey,
        verifying_key: &VerifyingKey,
        _rng: &mut R,
    ) -> Result<IronwoodTransaction, FundingError> {
        if proving_key.circuit_version() != OrchardCircuitVersion::PostNu6_3
            || verifying_key.circuit_version() != OrchardCircuitVersion::PostNu6_3
        {
            return Err(AuthoringError::WrongCircuitVersion.into());
        }
        let private = Pczt::parse(self.private_pczt_bytes())
            .map_err(|_| AuthoringError::InvalidPczt)?;
        let finalized = IoFinalizer::new(private).finalize_io()
            .map_err(|_| AuthoringError::FinalizationFailed)?;
        // The constructor has exactly one positive wallet input. Finalization
        // signs genuine zero padding; locate the sole remaining owner action,
        // never assume its shuffled index and never sign padding with wallet ask.
        let owner_index = {
            let mut missing = finalized.ironwood().actions().iter().enumerate()
                .filter_map(|(index, action)| action.spend().spend_auth_sig().is_none().then_some(index));
            let index = missing.next().ok_or(AuthoringError::SigningFailed)?;
            if missing.next().is_some() {
                return Err(AuthoringError::SigningFailed.into());
            }
            index
        };
        let mut signer = Signer::new(finalized).map_err(|_| AuthoringError::SigningFailed)?;
        signer.sign_ironwood(owner_index, ask).map_err(|_| AuthoringError::SigningFailed)?;
        let signed = signer.finish();
        if signed.ironwood().actions().iter().any(|action| action.spend().spend_auth_sig().is_none()) {
            return Err(AuthoringError::SigningFailed.into());
        }
        let proved = Prover::new(signed).create_ironwood_proof(proving_key)
            .map_err(|_| AuthoringError::ProvingFailed)?.finish();
        let transaction = TransactionExtractor::new(proved).with_orchard(verifying_key)
            .extract().map_err(|_| AuthoringError::ExtractionFailed)?;
        if <[u8; 32]>::from(transaction.txid()) != self.effect_id() {
            return Err(AuthoringError::EffectsMismatch.into());
        }
        let mut bytes = Vec::new();
        transaction.write(&mut bytes).map_err(|_| AuthoringError::ExtractionFailed)?;
        let checked = IronwoodTransaction::parse(&bytes, self.source.consensus_branch)
            .map_err(FundingError::Consensus)?;
        if checked.effect_id() != self.effect_id() {
            return Err(AuthoringError::EffectsMismatch.into());
        }
        self.verify_transaction(&checked)?;
        Ok(checked)
    }

    /// Reopen retained private F, authenticate every action/output and bind the
    /// actual full transaction authorization and separate wallet anchor. This
    /// does not authenticate source history, quote agreement or permission to fund.
    pub fn verify_transaction(&self, transaction: &IronwoodTransaction) -> Result<(), FundingError> {
        let input = self.payout_witness.owned_input();
        let facts = FundingFacts {
            source: SourceFacts { network: self.source.network, target_height: self.source.target_height,
                expiry_height: self.source.expiry_height, consensus_branch: self.source.consensus_branch,
                fee_rule: &self.source.fee_rule },
            input: OwnedInputFacts { note: input.note(), full_viewing_key: input.full_viewing_key(),
                merkle_path: input.merkle_path(), anchor: input.anchor() },
            private_pczt: self.private_pczt_bytes(),
            requested_output_actions: self.payout_witness.requested_output_actions(),
            joint_requested_index: self.joint_requested_index, joint_full_viewing_key: &self.joint_fvk,
            group_ak: self.group_ak, fee: u64::from(self.fee),
        };
        native_relation::verify_funding(&facts,
            self.payout_witness.requested_output_actions().iter().map(|index| {
                let output = &self.payout_witness.outputs[*index];
                NativeOutputFacts { recipient: output.note.recipient(), value: output.note.value().inner(),
                    memo: Some(&output.memo) }
            }), Some(transaction.transaction())).map_err(|error| match error {
                native_relation::NativeRelationError::InvalidAuthorization => FundingError::Consensus(ValidationError::InvalidAuthorization),
                _ => FundingError::Source(crate::witness::relation_error(error)),
            })?;
        Ok(())
    }
}

/// Build one anchored positive V3 wallet spend and ALL caller-explicit outputs.
/// J is the selected requested output, not action zero, the first positive output
/// or a preselected rho/rseed. Standard/custom installed fee calculation must
/// balance exactly: no automatic change, fee subtraction, top-up or clamping.
/// Caller-selected J FVK/group binding establishes local ownership, not DKG
/// provenance, fresh-key qualification, source membership or permission to fund.
pub fn prepare_joint_funding<R: RngCore + CryptoRng>(
    source: &SourceParameters,
    input: &OwnedInput,
    outputs: &[OutputPlan],
    j_requested_index: usize,
    j_fvk: &FullViewingKey,
    group_ak: [u8; 32],
    rng: &mut R,
) -> Result<PreparedJointFunding, FundingError> {
    if source.network != Network::TestNetwork {
        return Err(FundingError::TestnetRequired);
    }
    source.validate()?;
    if outputs.is_empty() {
        return Err(AuthoringError::MissingOutputs.into());
    }
    let joint_plan = outputs.get(j_requested_index).ok_or(AuthoringError::InvalidOutputIndex)?;
    if u64::from(joint_plan.value()) == 0 {
        return Err(FundingError::InvalidJointOutput);
    }
    if j_fvk.scope_for_address(&joint_plan.recipient()).is_none() {
        return Err(FundingError::JointOutputNotOwned);
    }
    let fvk_bytes = Zeroizing::new(j_fvk.to_bytes());
    if fvk_bytes[..32] != group_ak {
        return Err(FundingError::GroupMismatch);
    }
    let built = build_pczt(source, input, outputs, rng)?;
    let fee = built.fee;
    let private_pczt = Zeroizing::new(built.pczt.serialize().map_err(|_| AuthoringError::InvalidPczt)?);
    let facts = FundingFacts {
        source: SourceFacts { network: source.network, target_height: source.target_height,
            expiry_height: source.expiry_height, consensus_branch: source.consensus_branch, fee_rule: &source.fee_rule },
        input: OwnedInputFacts { note: input.note(), full_viewing_key: input.full_viewing_key(),
            merkle_path: input.merkle_path(), anchor: input.anchor() },
        private_pczt: &private_pczt, requested_output_actions: &built.requested_output_actions,
        joint_requested_index: j_requested_index, joint_full_viewing_key: j_fvk, group_ak, fee: u64::from(fee),
    };
    let checked = native_relation::verify_funding(&facts, outputs.iter().map(|output| NativeOutputFacts {
        recipient: output.recipient(), value: u64::from(output.value()), memo: Some(output.memo().as_array()),
    }), None).map_err(crate::witness::relation_error)?;
    let payout_witness = PayoutWitness {
        input: input.clone(), private_pczt_bytes: private_pczt.to_vec(), effect_id: checked.effect_id,
        outputs: checked.outputs.into_iter().map(|output| crate::witness::SenderOutputWitness {
            action_index: output.action_index, note: output.note, memo: *output.memo,
        }).collect(),
        requested_output_actions: built.requested_output_actions,
    };
    Ok(PreparedJointFunding {
        payout_witness, source: source.clone(), fee,
        joint_requested_index: j_requested_index, joint_fvk: j_fvk.clone(), group_ak,
    })
}
