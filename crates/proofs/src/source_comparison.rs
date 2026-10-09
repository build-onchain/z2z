//! Owner-local mechanical comparison of two supplied finite testnet prefixes.
//!
//! Each candidate is independently replayed from authentic genesis through every
//! complete ledger transition and actual EOF. Work ordering says nothing about
//! ancestry, omitted competitors, freshness, local-clock admission, canonicality,
//! finality, payment classification or financial authority. Equal work remains
//! ambiguous; neither hash nor input arrival order chooses a chain.

use std::{cmp::Ordering, fmt, io::Read};

use crate::{
    header::HeaderTip,
    source_replay::{JOURNAL_LEN, SourceReplayError, replay_framed_testnet_with},
};

/// Immutable private observations, published only after BOTH complete replays.
/// There is no public constructor, selected chain or financial-fact conversion.
pub struct ValidatedPrefixComparison {
    left_tip: HeaderTip,
    right_tip: HeaderTip,
    left_journal: [u8; JOURNAL_LEN],
    right_journal: [u8; JOURNAL_LEN],
}

impl ValidatedPrefixComparison {
    /// Actual ledger tip of the fully validated left candidate.
    pub fn left_tip(&self) -> HeaderTip {
        self.left_tip
    }

    /// Actual ledger tip of the fully validated right candidate.
    pub fn right_tip(&self) -> HeaderTip {
        self.right_tip
    }

    /// Exact unchanged v11 journal, including the complete left input digest.
    pub fn left_journal(&self) -> &[u8; JOURNAL_LEN] {
        &self.left_journal
    }

    /// Exact unchanged v11 journal, including the complete right input digest.
    pub fn right_journal(&self) -> &[u8; JOURNAL_LEN] {
        &self.right_journal
    }

    /// Left cumulative work relative to right, derived by the actual validators.
    /// `Equal` does not break a tie or authorize either candidate.
    pub fn work_ordering(&self) -> Ordering {
        self.left_tip.cumulative_work().cmp(&self.right_tip.cumulative_work())
    }

    /// Equal actual tips AND equal completed journals (including input digests).
    /// Header/height/work equality alone cannot stand in for full-body validation
    /// or identical supplied histories. This flag makes no ancestry claim.
    pub fn same_boundary(&self) -> bool {
        self.left_tip == self.right_tip && self.left_journal == self.right_journal
    }
}

impl fmt::Debug for ValidatedPrefixComparison {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ValidatedPrefixComparison").finish_non_exhaustive()
    }
}

/// Independently validates exactly two caller-supplied nonseekable inputs.
///
/// Each explicit block/byte budget retains the shared replay's reject-not-clamp
/// semantics. Limits count genesis, framing and complete bodies; actual EOF is
/// mandatory for each input. No caller-supplied work, tip, checkpoint or validity
/// assertion exists. A failure on either side returns no comparison or journal.
/// The left input is consumed first; its failure leaves the right unread.
///
/// Only one replay ledger and its reusable bounded body buffer are alive at a
/// time. Validator state still grows with admitted history; comparison retains
/// only two tips and two fixed journals, not headers, bodies or alternate state.
pub fn compare_framed_testnet_prefixes(
    left: &mut impl Read,
    right: &mut impl Read,
    left_max_blocks: u32,
    left_max_input_bytes: u64,
    right_max_blocks: u32,
    right_max_input_bytes: u64,
) -> Result<ValidatedPrefixComparison, SourceReplayError> {
    let (left_tip, left_journal) = replay_boundary(left, left_max_blocks, left_max_input_bytes)?;
    let (right_tip, right_journal) = replay_boundary(right, right_max_blocks, right_max_input_bytes)?;
    Ok(ValidatedPrefixComparison { left_tip, right_tip, left_journal, right_journal })
}

// The ledger is dropped here before the other candidate begins validation.
fn replay_boundary(
    reader: &mut impl Read,
    max_blocks: u32,
    max_input_bytes: u64,
) -> Result<(HeaderTip, [u8; JOURNAL_LEN]), SourceReplayError> {
    let (journal, ledger) = replay_framed_testnet_with::<SourceReplayError>(
        reader, max_blocks, max_input_bytes, |_, _, _| Ok(()),
    )?;
    Ok((ledger.tip(), journal))
}
