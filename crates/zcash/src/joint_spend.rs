//! Wallet-local route-1a transaction capability, not source admission or a swap.
//!
//! Terms must be independently held by each signer. Private PCZTs include viewing
//! material and note openings: keep them owner-local, never in public receipts or
//! logs. The caller controls C/R share release; this module grants no arming truth,
//! disclosure permission, alpha-generation qualification, or durable custody.

use std::fmt;

use orchard::{
    Anchor, Note, ValuePool,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::FullViewingKey,
    note::ExtractedNoteCommitment,
    tree::MerklePath,
};
use pczt::{
    Pczt,
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, prover::Prover,
        signer::{Signer, SpendAuthSignature}, tx_extractor::TransactionExtractor,
        updater::Updater, verifier::{OrchardError, Verifier},
    },
};
use rand_core::{CryptoRng, RngCore};
use zcash_primitives::transaction::{
    builder::{BundlePadding, DeferredPcztBuilder},
    fees::zip317,
};
use zcash_protocol::{
    consensus::BranchId,
    constants::MAX_BLOCK_BYTES,
    value::Zatoshis,
};
use zeroize::Zeroizing;

use crate::{
    AuthoringError, IronwoodTransaction, OutputPlan, SourceParameters, ValidationError,
    custody::{CustodyError, pczt::relation_error as custody_relation_error},
};
use ziquid_proofs::native_relation::{
    self, JointSpendFacts, NativeOutputFacts, NativeRelationError, SourceFacts,
};

const MAX_PCZT_BYTES: usize = native_relation::MAX_PCZT_BYTES;

/// Caller-local agreement for exactly one positive J input and one positive
/// payout. No ask, implicit change, automatic top-up, amount, expiry or fee.
/// Target height is local construction context, not a v6 consensus header field.
#[derive(Clone, Copy)]
pub struct JointSpendTerms<'a> {
    pub source: &'a SourceParameters,
    pub note: &'a Note,
    pub full_viewing_key: &'a FullViewingKey,
    pub group_ak: [u8; 32],
    pub payout: &'a OutputPlan,
    pub fee: Zatoshis,
}

impl fmt::Debug for JointSpendTerms<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JointSpendTerms([redacted])")
    }
}

/// Independent local expectations for a finished C/R handoff. The sighash must
/// come from prior semantic `review_joint_spend`, never the peer's transaction ID.
/// The anchor is separate because v6 effects do not bind it. Every output opening,
/// including zero padding, is sensitive fresh-session material, not public data.
#[derive(Clone, Copy)]
pub struct FinishedJointSpendExpectation<'a> {
    pub terms: JointSpendTerms<'a>,
    pub shielded_sighash: [u8; 32],
    pub anchor: Anchor,
    pub output_notes: &'a [Note],
}

impl fmt::Debug for FinishedJointSpendExpectation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FinishedJointSpendExpectation([redacted])")
    }
}

/// Sanitized categories only: upstream errors may contain private material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JointSpendError {
    Source(AuthoringError),
    Review(CustodyError),
    TestnetRequired,
    GroupMismatch,
    InvalidPayout,
    UnbalancedTerms,
    FeeMismatch,
    InvalidPczt,
    InvalidMembership,
    EffectsChanged,
    MissingAuthorization,
    InvalidSignature,
    FinalizationFailed,
    WrongCircuitVersion,
    ProvingFailed,
    ExtractionFailed,
    Consensus(ValidationError),
}

impl fmt::Display for JointSpendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local joint spend rejected: {self:?}")
    }
}

impl std::error::Error for JointSpendError {}

/// Complete private pre-parent PCZT; its anchor and real J witness are absent.
/// Access is explicit because these bytes are NOT a public transaction export.
pub struct DeferredJointSpend {
    private_pczt_bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for DeferredJointSpend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeferredJointSpend([redacted])")
    }
}

impl DeferredJointSpend {
    pub fn private_pczt_bytes(&self) -> &[u8] {
        &self.private_pczt_bytes
    }
}

/// Semantically reviewed exact PCZT, not a source-history or settlement fact.
/// The real action index is located by its checked J nullifier, never assumed.
pub struct ReviewedJointSpend {
    private_pczt_bytes: Zeroizing<Vec<u8>>,
    action_index: usize,
    alpha: [u8; 32],
    rk: [u8; 32],
    note_commitment: [u8; 32],
    effect_id: [u8; 32],
    shielded_sighash: [u8; 32],
}

impl fmt::Debug for ReviewedJointSpend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReviewedJointSpend([redacted])")
    }
}

impl ReviewedJointSpend {
    pub fn private_pczt_bytes(&self) -> &[u8] {
        &self.private_pczt_bytes
    }
    pub fn action_index(&self) -> usize {
        self.action_index
    }
    pub fn alpha(&self) -> [u8; 32] {
        self.alpha
    }
    pub fn randomized_key(&self) -> [u8; 32] {
        self.rk
    }
    pub fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }
    pub fn shielded_sighash(&self) -> [u8; 32] {
        self.shielded_sighash
    }

    /// Recover every validated private output in actual action order, including
    /// zero padding. Retain before consuming this artifact for completion. These
    /// openings require the per-swap fresh-J disclosure grant in bilateral use;
    /// do not log or publish them. Typed notes do not guarantee memory erasure.
    pub fn output_notes(&self) -> Result<Vec<Note>, JointSpendError> {
        let pczt = parse_canonical(&self.private_pczt_bytes)?;
        let mut notes = Vec::with_capacity(pczt.ironwood().actions().len());
        Verifier::new(pczt).with_ironwood(|bundle| {
            for action in bundle.actions() {
                let (note, _memo) = native_relation::recover_output(action).map_err(OrchardError::Custom)?;
                notes.push(note);
            }
            Ok(())
        }).map_err(|error| match error {
            OrchardError::Custom(error) => relation_error(error),
            _ => JointSpendError::InvalidPczt,
        })?;
        Ok(notes)
    }

    /// Apply an externally aggregated authorization only to these retained,
    /// independently checked effects/action. Upstream re-verifies its RedPallas
    /// signature under the maintained sighash. This does not release C shares.
    pub fn apply_external_signature(mut self, aggregate: [u8; 64]) -> Result<Self, JointSpendError> {
        let pczt = parse_canonical(&self.private_pczt_bytes)?;
        if pczt.ironwood().actions()[self.action_index].spend().spend_auth_sig().is_some() {
            return Err(JointSpendError::InvalidSignature);
        }
        let mut signer = Signer::new(pczt).map_err(|_| JointSpendError::InvalidPczt)?;
        if signer.shielded_sighash() != self.shielded_sighash {
            return Err(JointSpendError::EffectsChanged);
        }
        signer.apply_orchard_spend_auth_signature(&SpendAuthSignature::from_parts(
            ValuePool::Ironwood, self.action_index, aggregate,
        )).map_err(|_| JointSpendError::InvalidSignature)?;
        self.private_pczt_bytes = serialize_private(signer.finish())?;
        Ok(self)
    }

    /// Attach the caller's actual local membership relation AFTER authorization.
    /// This checks only the path-to-anchor relation, not whether a chain accepts
    /// the anchor or whether J is funded, unspent or final.
    pub fn attach_membership(
        mut self,
        merkle_path: MerklePath,
        anchor: Anchor,
    ) -> Result<Self, JointSpendError> {
        let commitment = ExtractedNoteCommitment::from_bytes(&self.note_commitment)
            .into_option().ok_or(JointSpendError::InvalidMembership)?;
        if merkle_path.root(commitment) != anchor {
            return Err(JointSpendError::InvalidMembership);
        }
        let pczt = parse_canonical(&self.private_pczt_bytes)?;
        require_authorizations(&pczt)?;
        let pczt = Updater::new(pczt)
            .set_ironwood_anchor(anchor).map_err(|_| JointSpendError::InvalidMembership)?
            .set_ironwood_spend_witnesses([(self.action_index, merkle_path)])
            .map_err(|_| JointSpendError::InvalidMembership)?
            .finish();
        let (pczt, actual_effect_id, actual_sighash) = effect_identity(pczt)?;
        if actual_effect_id != self.effect_id || actual_sighash != self.shielded_sighash {
            return Err(JointSpendError::EffectsChanged);
        }
        self.private_pczt_bytes = serialize_private(pczt)?;
        Ok(self)
    }

    /// Prove using supplied PostNu6_3 keys, extract a full consensus Transaction,
    /// canonically parse it and verify EVERY action, binding signature and proof.
    /// All signatures and an attached membership path are required before proving.
    pub fn extract_consensus<R: RngCore + CryptoRng>(
        self,
        proving_key: &ProvingKey,
        verifying_key: &VerifyingKey,
        rng: &mut R,
    ) -> Result<IronwoodTransaction, JointSpendError> {
        if proving_key.circuit_version() != OrchardCircuitVersion::PostNu6_3
            || verifying_key.circuit_version() != OrchardCircuitVersion::PostNu6_3
        {
            return Err(JointSpendError::WrongCircuitVersion);
        }
        let pczt = parse_canonical(&self.private_pczt_bytes)?;
        require_authorizations(&pczt)?;
        if pczt.ironwood().anchor().is_none()
            || pczt.ironwood().actions()[self.action_index].spend().witness().is_none()
        {
            return Err(JointSpendError::InvalidMembership);
        }
        let pczt = Prover::new(pczt).create_ironwood_proof(proving_key)
            .map_err(|_| JointSpendError::ProvingFailed)?.finish();
        let transaction = TransactionExtractor::new(pczt).with_orchard(verifying_key)
            .extract().map_err(|_| JointSpendError::ExtractionFailed)?;
        let mut bytes = Vec::new();
        transaction.write(&mut bytes).map_err(|_| JointSpendError::ExtractionFailed)?;
        let checked = IronwoodTransaction::parse(&bytes, BranchId::Nu6_3)
            .map_err(JointSpendError::Consensus)?;
        if checked.effect_id() != self.effect_id {
            return Err(JointSpendError::EffectsChanged);
        }
        checked.verify_authorization(verifying_key, rng).map_err(JointSpendError::Consensus)?;
        Ok(checked)
    }

    /// Complete the deferred capability with caller-supplied actual membership
    /// and circuit keys. Returned consensus bytes still assert no chain admission.
    pub fn complete<R: RngCore + CryptoRng>(
        self,
        merkle_path: MerklePath,
        anchor: Anchor,
        proving_key: &ProvingKey,
        verifying_key: &VerifyingKey,
        rng: &mut R,
    ) -> Result<IronwoodTransaction, JointSpendError> {
        self.attach_membership(merkle_path, anchor)?.extract_consensus(proving_key, verifying_key, rng)
    }
}

/// Construct a normally padded private v6 PCZT BEFORE the parent membership is
/// available. The maintained IO finalizer signs genuine zero-value padding and
/// clears its dummy spend keys; no complete J ask is ever accepted.
pub fn build_deferred_joint_spend<R: RngCore + CryptoRng>(
    terms: &JointSpendTerms<'_>,
    rng: &mut R,
) -> Result<DeferredJointSpend, JointSpendError> {
    validate_terms(terms)?;
    let mut builder = DeferredPcztBuilder::new::<zip317::FeeError>(
        terms.source.network, terms.source.target_height,
        BundlePadding::DEFAULT, BundlePadding::DEFAULT,
    ).map_err(|_| JointSpendError::Source(AuthoringError::BuilderRejected))?
        .with_expiry_height(terms.source.expiry_height);
    builder.add_ironwood_spend::<zip317::FeeError>(terms.full_viewing_key.clone(), *terms.note)
        .map_err(|_| JointSpendError::Source(AuthoringError::BuilderRejected))?;
    builder.add_ironwood_output::<zip317::FeeError>(
        None, terms.payout.recipient(), terms.payout.value(), terms.payout.memo().clone(),
    ).map_err(|_| JointSpendError::Source(AuthoringError::BuilderRejected))?;
    if builder.get_fee(&terms.source.fee_rule)
        .map_err(|_| JointSpendError::Source(AuthoringError::BuilderRejected))? != terms.fee
    {
        return Err(JointSpendError::FeeMismatch);
    }
    let built = builder.build_for_pczt(rng, &terms.source.fee_rule)
        .map_err(|_| JointSpendError::Source(AuthoringError::BuilderRejected))?;
    let real_index = built.ironwood_meta.spend_action_index(0)
        .ok_or(JointSpendError::InvalidPczt)?;
    let pczt = Creator::build_from_parts(built.pczt_parts).ok_or(JointSpendError::InvalidPczt)?;
    if pczt.ironwood().anchor().is_some()
        || pczt.ironwood().actions()[real_index].spend().witness().is_some()
    {
        return Err(JointSpendError::InvalidMembership);
    }
    let pczt = IoFinalizer::new(pczt).finalize_io()
        .map_err(|_| JointSpendError::FinalizationFailed)?;
    let private_pczt_bytes = serialize_private(pczt)?;
    // The same independent semantic verifier protects locally constructed output.
    let reviewed = review_owned_joint_spend(private_pczt_bytes, terms)?;
    if reviewed.action_index != real_index {
        return Err(JointSpendError::InvalidPczt);
    }
    Ok(DeferredJointSpend { private_pczt_bytes: reviewed.private_pczt_bytes })
}

/// Review received PRE-parent bytes against INDEPENDENT caller-local terms before
/// creating signing shares. The real J anchor and witness MUST both be absent;
/// received matching pairs are not owner-local membership enrollment. Genuine
/// padding witnesses remain required. A hash alone is never semantic approval.
/// Rejects proofs, unrelated pool data and retained dummy keys. Use the returned
/// artifact's `attach_membership` for the separate owner-local membership step.
pub fn review_joint_spend(
    bytes: &[u8],
    terms: &JointSpendTerms<'_>,
) -> Result<ReviewedJointSpend, JointSpendError> {
    if bytes.is_empty() || bytes.len() > MAX_PCZT_BYTES {
        return Err(JointSpendError::InvalidPczt);
    }
    review_owned_joint_spend(Zeroizing::new(bytes.to_vec()), terms)
}

/// Independently review finished consensus bytes without a private PCZT. Checks
/// the locally retained semantic sighash, separately selected anchor, unique J
/// nullifier, every V3 output opening/full ciphertext (including zero padding),
/// exact payout/memo/fee/expiry and every SpendAuth, binding signature and proof.
/// Unknown inputs are not inferred to be dummy from their nullifiers or balance:
/// the prior local semantic review is REQUIRED to bind their exact effects.
///
/// This read-only check does not establish J funding/unspent status, admissible
/// membership/history/anchor, current-height safety, inclusion/finality, winning
/// C/R, ETH arming, transfer, durable custody or completed recovery. It releases
/// no shares, advances no gate and grants no private-material disclosure rights.
pub fn review_finished_joint_spend<R: RngCore + CryptoRng>(
    bytes: &[u8],
    expected: &FinishedJointSpendExpectation<'_>,
    verifying_key: &VerifyingKey,
    _rng: &mut R,
) -> Result<IronwoodTransaction, JointSpendError> {
    if bytes.is_empty() || bytes.len() > MAX_BLOCK_BYTES {
        return Err(JointSpendError::Consensus(ValidationError::MalformedTransaction));
    }
    let facts = native_terms(&expected.terms);
    native_relation::validate_joint_terms(&facts).map_err(relation_error)?;
    let parsed = IronwoodTransaction::parse(bytes, BranchId::Nu6_3).map_err(JointSpendError::Consensus)?;
    native_relation::review_finished_semantics(parsed.transaction(), &facts,
        expected.shielded_sighash, expected.anchor, expected.output_notes).map_err(|error| match error {
            NativeRelationError::FeeMismatch => JointSpendError::FeeMismatch,
            _ => relation_error(error),
        })?;
    if verifying_key.circuit_version() != OrchardCircuitVersion::PostNu6_3 {
        return Err(JointSpendError::Consensus(ValidationError::WrongCircuitVersion));
    }
    native_relation::verify_transaction_authorization(parsed.transaction())
        .map_err(|_| JointSpendError::Consensus(ValidationError::InvalidAuthorization))?;
    Ok(parsed)
}

fn review_owned_joint_spend(
    private_pczt_bytes: Zeroizing<Vec<u8>>,
    terms: &JointSpendTerms<'_>,
) -> Result<ReviewedJointSpend, JointSpendError> {
    let checked = native_relation::review_joint_pczt(parse_canonical(&private_pczt_bytes)?, &native_terms(terms))
        .map_err(relation_error)?;
    Ok(ReviewedJointSpend {
        private_pczt_bytes, action_index: checked.action_index, alpha: checked.alpha, rk: checked.rk,
        note_commitment: checked.note_commitment, effect_id: checked.effect_id,
        shielded_sighash: checked.shielded_sighash,
    })
}

fn validate_terms(terms: &JointSpendTerms<'_>) -> Result<(), JointSpendError> {
    native_relation::validate_joint_terms(&native_terms(terms)).map_err(relation_error)
}

fn parse_canonical(bytes: &[u8]) -> Result<Pczt, JointSpendError> {
    native_relation::parse_canonical_pczt(bytes).map_err(relation_error)
}

fn serialize_private(pczt: Pczt) -> Result<Zeroizing<Vec<u8>>, JointSpendError> {
    pczt.serialize().map(Zeroizing::new).map_err(|_| JointSpendError::InvalidPczt)
}


fn effect_identity(pczt: Pczt) -> Result<(Pczt, [u8; 32], [u8; 32]), JointSpendError> {
    let (effect_id, sighash) = native_relation::pczt_effect_identity(&pczt).map_err(relation_error)?;
    Ok((pczt, effect_id, sighash))
}

fn require_authorizations(pczt: &Pczt) -> Result<(), JointSpendError> {
    if pczt.ironwood().actions().iter().any(|action| action.spend().spend_auth_sig().is_none()) {
        return Err(JointSpendError::MissingAuthorization);
    }
    Ok(())
}

pub(crate) fn native_terms<'a>(terms: &JointSpendTerms<'a>) -> JointSpendFacts<'a> {
    JointSpendFacts {
        source: SourceFacts {
            network: terms.source.network, target_height: terms.source.target_height,
            expiry_height: terms.source.expiry_height, consensus_branch: terms.source.consensus_branch,
            fee_rule: &terms.source.fee_rule,
        },
        note: terms.note, full_viewing_key: terms.full_viewing_key, group_ak: terms.group_ak,
        payout: NativeOutputFacts { recipient: terms.payout.recipient(), value: u64::from(terms.payout.value()),
            memo: Some(terms.payout.memo().as_array()) }, fee: u64::from(terms.fee),
    }
}
fn relation_error(error: NativeRelationError) -> JointSpendError {
    use NativeRelationError as E;
    match error {
        E::TestnetRequired => JointSpendError::TestnetRequired,
        E::GroupMismatch => JointSpendError::GroupMismatch,
        E::InvalidPayout => JointSpendError::InvalidPayout,
        E::UnbalancedTerms => JointSpendError::UnbalancedTerms,
        E::FeeMismatch => JointSpendError::Review(CustodyError::FeeMismatch),
        E::InvalidMembership | E::AnchorMismatch => JointSpendError::InvalidMembership,
        E::EffectsChanged => JointSpendError::EffectsChanged,
        E::InvalidSignature => JointSpendError::InvalidSignature,
        E::InvalidPczt | E::EffectExtraction | E::SighashEncoding => JointSpendError::InvalidPczt,
        E::InvalidHeight | E::WrongBranch | E::WrongNoteVersion | E::InvalidInputValue | E::InputNotOwned =>
            JointSpendError::Source(crate::witness::relation_error(error)),
        _ => JointSpendError::Review(custody_relation_error(error)),
    }
}
