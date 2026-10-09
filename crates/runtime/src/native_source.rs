//! Read-only owner-local J reconciliation in one supplied full testnet prefix.
//!
//! J comes from the existing local funding builder, not an arbitrary commitment
//! or nullifier. Every body from authentic genesis and actual EOF must pass before
//! any outcome is returned. C/R refer only to the independently retained source
//! semantics of the actual consuming transaction, not net payment or refund.
//! This is not canonicality, freshness, finality, a SNARK, an accepted financial
//! fact, U funding-origin proof, ETH arming, transfer or permission to release C.
//! Keep all openings/FVKs and linkable replay evidence owner-local. Typed upstream
//! notes do not guarantee erasure; Debug here never prints private source data.

use std::{fmt, io::Read};

use orchard::{
    circuit::{OrchardCircuitVersion, VerifyingKey},
    note::ExtractedNoteCommitment,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;
use ziquid_proofs::{
    genesis::ShieldedPool,
    native_relation::{same_note, validate_group},
    source_note::{FiniteValidatedPrefixNote, SourceNoteError, SourceNoteSelection, replay_note_testnet},
};
use ziquid_zcash::{
    IronwoodTransaction,
    funding::PreparedJointFunding,
    joint_spend::{FinishedJointSpendExpectation, review_finished_joint_spend},
};

/// All four outcomes are nonterminal and scoped ONLY to the supplied prefix.
/// `Other` never implies a full refund, and C payout credit is not `C_net`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuppliedPrefixOutcome {
    SuppliedPrefixUnspent,
    SuppliedPrefixC,
    SuppliedPrefixR,
    SuppliedPrefixOther,
}

/// Completed immutable owner-local replay evidence. No public constructor,
/// deserializer, financial conversion or authority flag is provided.
pub struct SuppliedPrefixReconciliation {
    outcome: SuppliedPrefixOutcome,
    prefix: FiniteValidatedPrefixNote,
}

impl SuppliedPrefixReconciliation {
    pub fn supplied_prefix_outcome(&self) -> SuppliedPrefixOutcome { self.outcome }
    /// Explicit linkable access to the same completed replay, not public receipts.
    pub fn supplied_prefix(&self) -> &FiniteValidatedPrefixNote { &self.prefix }
}

impl fmt::Debug for SuppliedPrefixReconciliation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SuppliedPrefixReconciliation([redacted])")
    }
}

/// Fixed categories retain no note, transaction, locator or upstream I/O bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSourceError {
    Selection,
    Expectation,
    Funding,
    History(SourceNoteError),
}

impl fmt::Display for NativeSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selection => f.write_str("native source J selection rejected"),
            Self::Expectation => f.write_str("native source independent C/R linkage rejected"),
            Self::Funding => f.write_str("native source generated J funding linkage rejected"),
            Self::History(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for NativeSourceError {}

/// Derive canonical Ironwood V3 J cmx/NF from the genuine builder-retained
/// note/FVK/group and require the caller's explicit locator/query to agree.
/// Both C/R expectations must refer to that byte-identical same J and FVK/group;
/// their source, payout/full memo, fees, prior semantic sighash, separate anchor
/// and ALL output openings are independent caller inputs, never learned from T.
///
/// The same replay's funding bytes are sender-recovered with existing custody,
/// and its actual consuming bytes are passed to the existing finished reviewer.
/// Locators include independently held effect AND authorizing-data identities;
/// C/R classification does not demand an old authorizing digest, permitting new
/// valid authorizations of the independently held same effects and anchor.
/// Unknown or nonmatching consumers remain Other, never refund evidence.
///
/// Local generated-F linkage is not an S-independent origin proof, nor a proof
/// of U's debit, returned excess or net consideration. No such assertion is made.
#[allow(clippy::too_many_arguments)]
pub fn reconcile_source_testnet<R: RngCore + CryptoRng>(
    reader: &mut impl Read,
    max_blocks: u32,
    max_input_bytes: u64,
    selection: SourceNoteSelection,
    funding: &PreparedJointFunding,
    c: &FinishedJointSpendExpectation<'_>,
    r: &FinishedJointSpendExpectation<'_>,
    verifying_key: &VerifyingKey,
    rng: &mut R,
) -> Result<SuppliedPrefixReconciliation, NativeSourceError> {
    let selection = checked_selection(selection, funding, c, r, verifying_key)?;
    let prefix = replay_note_testnet(reader, max_blocks, max_input_bytes, selection)
        .map_err(NativeSourceError::History)?;
    check_funding_bytes(prefix.funding_transaction_bytes(), funding)?;
    let outcome = classify_consumption(prefix.consuming_transaction_bytes(), c, r, verifying_key, rng);
    Ok(SuppliedPrefixReconciliation { outcome, prefix })
}


fn checked_selection(
    selection: SourceNoteSelection,
    funding: &PreparedJointFunding,
    c: &FinishedJointSpendExpectation<'_>,
    r: &FinishedJointSpendExpectation<'_>,
    verifying_key: &VerifyingKey,
) -> Result<SourceNoteSelection, NativeSourceError> {
    let note = funding.joint_note();
    let fvk = funding.joint_full_viewing_key();
    let fvk_bytes = Zeroizing::new(fvk.to_bytes());
    validate_group(note, fvk, &funding.group_ak()).map_err(|_| NativeSourceError::Funding)?;
    let commitment = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
    let nullifier = note.nullifier(fvk).to_bytes();
    if selection.pool != ShieldedPool::Ironwood || selection.commitment != commitment
        || selection.nullifier != nullifier || selection.funding.effect_id != funding.effect_id()
        || usize::try_from(selection.funding.action_index).ok() != Some(funding.joint_action_index())
    {
        return Err(NativeSourceError::Selection);
    }
    if verifying_key.circuit_version() != OrchardCircuitVersion::PostNu6_3
        || c.shielded_sighash == r.shielded_sighash
    {
        return Err(NativeSourceError::Expectation);
    }
    for expected in [c, r] {
        if !same_note(expected.terms.note, note)
            || Zeroizing::new(expected.terms.full_viewing_key.to_bytes()).as_slice() != fvk_bytes.as_slice()
            || expected.terms.group_ak != funding.group_ak()
        {
            return Err(NativeSourceError::Expectation);
        }
    }
    Ok(SourceNoteSelection { pool: ShieldedPool::Ironwood, commitment, nullifier, funding: selection.funding })
}

fn check_funding_bytes(bytes: &[u8], funding: &PreparedJointFunding) -> Result<(), NativeSourceError> {
    // The full replay already verified these exact authorizing bytes and history.
    // Reuse canonical v6 parsing and exact generated-output ciphertext recovery.
    let transaction = IronwoodTransaction::parse(bytes, funding.source_parameters().consensus_branch)
        .map_err(|_| NativeSourceError::Funding)?;
    funding.verify_transaction(&transaction).map_err(|_| NativeSourceError::Funding)?;
    Ok(())
}

fn classify_consumption<R: RngCore + CryptoRng>(
    bytes: Option<&[u8]>,
    c: &FinishedJointSpendExpectation<'_>,
    r: &FinishedJointSpendExpectation<'_>,
    verifying_key: &VerifyingKey,
    rng: &mut R,
) -> SuppliedPrefixOutcome {
    let Some(bytes) = bytes else { return SuppliedPrefixOutcome::SuppliedPrefixUnspent; };
    if review_finished_joint_spend(bytes, c, verifying_key, rng).is_ok() {
        SuppliedPrefixOutcome::SuppliedPrefixC
    } else if review_finished_joint_spend(bytes, r, verifying_key, rng).is_ok() {
        SuppliedPrefixOutcome::SuppliedPrefixR
    } else {
        SuppliedPrefixOutcome::SuppliedPrefixOther
    }
}

#[cfg(test)]
#[path = "../tests/native_source/mod.rs"]
mod tests;
