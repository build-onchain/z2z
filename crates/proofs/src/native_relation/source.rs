//! Owner-local full-prefix composition. The caller supplies actual framed
//! history, not a trusted checkpoint, sealed host value or decoded zk journal.
//! Finite prefix evidence remains nonfinancial and never means canonical/final.
use std::{fmt, io::Read};
use orchard::{Anchor, note::ExtractedNoteCommitment};
use zcash_protocol::consensus::Network;
use ziquid_protocol::native::{Statement, stable_j_tag};
use super::{
    CheckedFunding, CheckedJointConsumer, FundingFacts, JointSpendFacts,
    NativeOutputFacts, NativeRelationError,
};
use crate::{
    genesis::ShieldedPool,
    header::HeaderTip,
    source_note::{SourceNoteError, SourceNoteOccurrence, SourceNoteSelection, replay_origin_joint_testnet},
};
use zeroize::Zeroizing;

/// Exact independent retained C/R terms and private pre-parent action metadata.
#[derive(Clone, Copy)]
pub struct ConsumerFacts<'a> {
    pub private_pczt: &'a [u8],
    pub terms: JointSpendFacts<'a>,
    pub anchor: Anchor,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixOutcome { UnspentInSuppliedPrefix, Completion, Recovery, Other }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceRelationError {
    Relation(NativeRelationError),
    History(SourceNoteError),
    Selection,
    Expectation,
    StatementShape,
    StatementMismatch,
    StableTagMismatch,
    RecoveryOwnership,
}
impl fmt::Display for SourceRelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native supplied-prefix relation rejected: {self:?}")
    }
}
impl std::error::Error for SourceRelationError {}
impl From<NativeRelationError> for SourceRelationError {
    fn from(error: NativeRelationError) -> Self { Self::Relation(error) }
}

/// Private checked accounting and exact occurrences. No verifier certificate,
/// entitlement or public financial journal can be constructed from this type.
pub struct CheckedNativePrefix {
    boundary: HeaderTip,
    origin_funding: SourceNoteOccurrence,
    funding_occurrence: SourceNoteOccurrence,
    consumption_occurrence: Option<SourceNoteOccurrence>,
    funding: CheckedFunding,
    consumer: Option<CheckedJointConsumer>,
    outcome: PrefixOutcome,
}
impl CheckedNativePrefix {
    pub fn boundary(&self) -> HeaderTip { self.boundary }
    pub fn origin_funding(&self) -> &SourceNoteOccurrence { &self.origin_funding }
    pub fn funding_occurrence(&self) -> &SourceNoteOccurrence { &self.funding_occurrence }
    pub fn consumption_occurrence(&self) -> Option<&SourceNoteOccurrence> { self.consumption_occurrence.as_ref() }
    pub fn funding(&self) -> &CheckedFunding { &self.funding }
    pub fn consumer(&self) -> Option<&CheckedJointConsumer> { self.consumer.as_ref() }
    pub fn outcome(&self) -> PrefixOutcome { self.outcome }
}
impl fmt::Debug for CheckedNativePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("CheckedNativePrefix([redacted])") }
}

/// Check only the specified source fields against actual private F/J/C/R data.
/// Reopens every F output and both pre-parent consumers using the shared rules;
/// the stable tag uses the generated J's authentic FVK nk and derived nullifier.
/// R must be recoverable by the originating wallet, not merely a claimed return.
///
/// This deliberately returns existing private funding accounting, NOT a checked
/// financial Statement. Canonical openings for source_terms_commitment,
/// joint_binding and group_grant_commitment, authenticated S source receiver /
/// quote-to-target beneficiary bindings and window/policy/program qualification
/// are unavailable here. Nonzero opaque fields are shape, never evidence. This
/// function creates no grant, authorization, journal, acceptance or entitlement.
pub fn check_statement_source_fields<'a>(
    statement: &Statement, funding: &FundingFacts<'_>,
    outputs: impl ExactSizeIterator<Item = NativeOutputFacts<'a>>,
    c: &ConsumerFacts<'_>, r: &ConsumerFacts<'_>,
) -> Result<CheckedFunding, SourceRelationError> {
    statement.validate().map_err(|_| SourceRelationError::StatementShape)?;
    for (index, (source, fee)) in [
        (&funding.source, funding.fee), (&c.terms.source, c.terms.fee), (&r.terms.source, r.terms.fee),
    ].into_iter().enumerate() {
        super::validate_source(source)?;
        if source.network != Network::TestNetwork
            || u32::from(source.consensus_branch) != statement.consensus_branch
            || u32::from(source.target_height) != statement.targets[index]
            || u32::from(source.expiry_height) != statement.expiries[index]
            || fee != statement.fees[index] || fee > statement.fee_caps[index]
        { return Err(SourceRelationError::StatementMismatch); }
    }
    // F and both children enforce the actual Ironwood V3 / transaction V6
    // profile, every note opening/ciphertext/memo, configured ZIP317 fee and
    // original private effects. No decoded scalar can substitute those checks.
    let checked = super::verify_funding(funding, outputs, None)?;
    check_consumer_expectations(funding, &checked, c, r)?;
    if checked.joint_note.value().inner() != statement.joint_value
        || c.terms.payout.value != statement.a || r.terms.payout.value != statement.r_return
    { return Err(SourceRelationError::StatementMismatch); }
    if funding.input.full_viewing_key.scope_for_address(&r.terms.payout.recipient).is_none() {
        return Err(SourceRelationError::RecoveryOwnership);
    }
    let fvk = Zeroizing::new(funding.joint_full_viewing_key.to_bytes());
    let nf = Zeroizing::new(checked.joint_note.nullifier(funding.joint_full_viewing_key).to_bytes());
    let nk = fvk[32..64].try_into().map_err(|_| SourceRelationError::Expectation)?;
    let tag = stable_j_tag(statement.target_chain_id, &statement.obligation, nk, &nf)
        .map_err(|_| SourceRelationError::StatementShape)?;
    if tag != statement.stable_jtag { return Err(SourceRelationError::StableTagMismatch); }
    Ok(checked)
}

fn check_consumer_expectations(
    funding: &FundingFacts<'_>, checked: &CheckedFunding, c: &ConsumerFacts<'_>, r: &ConsumerFacts<'_>,
) -> Result<(), SourceRelationError> {
    let expected_fvk = Zeroizing::new(funding.joint_full_viewing_key.to_bytes());
    for expected in [c, r] {
        if !super::same_note(expected.terms.note, &checked.joint_note)
            || *Zeroizing::new(expected.terms.full_viewing_key.to_bytes()) != *expected_fvk
            || expected.terms.group_ak != funding.group_ak { return Err(SourceRelationError::Expectation); }
    }
    let reviewed_c = super::review_joint_pczt(super::parse_canonical_pczt(c.private_pczt)?, &c.terms)?;
    let reviewed_r = super::review_joint_pczt(super::parse_canonical_pczt(r.private_pczt)?, &r.terms)?;
    if reviewed_c.effect_id == reviewed_r.effect_id { return Err(SourceRelationError::Expectation); }
    Ok(())
}

/// One actual complete-genesis replay tracks U and J, enforces U NF's consumer
/// is the EXACT J-funding F including both identities, then reopens complete F
/// and authentic same-J C/R metadata against the actual winner's bytes. Unknown
/// mixed/partial/excess consumers remain Other, never implied full refund.
/// Statement matching is limited to check_statement_source_fields above; opaque
/// commitments remain unopened and this prefix cannot create financial journals.
#[allow(clippy::too_many_arguments)]
pub fn verify_supplied_prefix<'a>(
    statement: &Statement,
    reader: &mut impl Read, max_blocks: u32, max_input_bytes: u64,
    origin: SourceNoteSelection, joint: SourceNoteSelection, funding: &FundingFacts<'_>,
    outputs: impl Clone + ExactSizeIterator<Item = NativeOutputFacts<'a>>,
    c: &ConsumerFacts<'_>, r: &ConsumerFacts<'_>,
) -> Result<CheckedNativePrefix, SourceRelationError> {
    let checked = check_statement_source_fields(statement, funding, outputs.clone(), c, r)?;
    let input = funding.input;
    if origin.pool != ShieldedPool::Ironwood
        || origin.commitment != ExtractedNoteCommitment::from(input.note.commitment()).to_bytes()
        || origin.nullifier != input.note.nullifier(input.full_viewing_key).to_bytes()
        || joint.pool != ShieldedPool::Ironwood
        || joint.commitment != ExtractedNoteCommitment::from(checked.joint_note.commitment()).to_bytes()
        || joint.nullifier != checked.joint_note.nullifier(funding.joint_full_viewing_key).to_bytes()
        || joint.funding.effect_id != checked.effect_id
        || usize::try_from(joint.funding.action_index).ok() != Some(checked.joint_action_index)
    { return Err(SourceRelationError::Selection); }
    drop(checked);
    let prefix = replay_origin_joint_testnet(reader, max_blocks, max_input_bytes, origin, joint)
        .map_err(SourceRelationError::History)?;
    if prefix.origin().merkle_path().position() != input.merkle_path.position() {
        return Err(SourceRelationError::Selection);
    }
    // Terminal replay paths/anchors are boundary witnesses, never substitutes
    // for F's earlier retained spend anchor or each consumer's actual anchor.
    let actual_f = super::parse_transaction(prefix.funding_transaction_bytes())?;
    let checked_f = super::verify_funding(funding, outputs, Some(&actual_f))?;
    let funding_occurrence = *prefix.joint().funding();
    let auth: [u8; 32] = actual_f.auth_commitment().as_bytes().try_into()
        .map_err(|_| SourceRelationError::Selection)?;
    if auth != funding_occurrence.auth_digest() || checked_f.effect_id != funding_occurrence.effect_id() {
        return Err(SourceRelationError::Selection);
    }
    let (outcome, consumer) = match prefix.consuming_transaction_bytes() {
        None => (PrefixOutcome::UnspentInSuppliedPrefix, None),
        Some(raw) => match super::parse_transaction(raw) {
            Err(_) => (PrefixOutcome::Other, None),
            Ok(transaction) => {
                if let Ok(consumer) = super::verify_joint_consumer(c.private_pczt, &c.terms, c.anchor, &transaction) {
                    (PrefixOutcome::Completion, Some(consumer))
                } else if let Ok(consumer) = super::verify_joint_consumer(r.private_pczt, &r.terms, r.anchor, &transaction) {
                    (PrefixOutcome::Recovery, Some(consumer))
                } else { (PrefixOutcome::Other, None) }
            }
        },
    };
    if let Some(consumer) = &consumer {
        let occurrence = prefix.joint().consumption().ok_or(SourceRelationError::Selection)?;
        if consumer.effect_id != occurrence.effect_id() || consumer.auth_digest != occurrence.auth_digest() {
            return Err(SourceRelationError::Selection);
        }
    }
    Ok(CheckedNativePrefix { boundary: prefix.boundary(), origin_funding: *prefix.origin().funding(),
        funding_occurrence, consumption_occurrence: prefix.joint().consumption().copied(),
        funding: checked_f, consumer, outcome })
}
