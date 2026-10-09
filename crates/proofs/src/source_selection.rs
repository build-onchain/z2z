//! Host-local transaction occurrence in a fully validated finite testnet prefix.
//!
//! This binds exact transaction bytes and both identities at one admitted block
//! position. It is not canonical-chain selection, freshness, finality, a SNARK,
//! J note/membership evidence, payment classification, or financial authority.
//! The unchanged boundary journal does not itself commit to this selection.

use std::{fmt, io::Read, ops::Range};

use corez::io::Write;
use zcash_encoding::CompactSize;
use zcash_primitives::{block::BlockHeader, transaction::Transaction};
use zcash_protocol::consensus::{BranchId, NetworkUpgrade, Parameters, TEST_NETWORK};

use crate::{
    header::HeaderTip,
    history::{CanonicalBytes, ParsedBlockBody},
    post_nu5_body::{PostNu5Block, PostNu5Transaction},
    source_replay::{JOURNAL_LEN, MAX_BLOCK_BYTES, ReplayPhase, SourceReplayError, replay_framed_testnet_with},
};

/// Independently held identities or the exact independently held canonical bytes.
/// Pre-v5 transactions use FF32 for the block authorization leaf: their effect
/// identity already commits to all authorization bytes.
#[derive(Clone, Copy)]
pub enum SelectedTransactionExpectation<'a> {
    Digests { effect_id: [u8; 32], auth_digest: [u8; 32] },
    CanonicalBytes(&'a [u8]),
}

impl SelectedTransactionExpectation<'_> {
    fn matches(self, transaction: &SelectedTransaction<'_>) -> bool {
        match self {
            Self::Digests { effect_id, auth_digest } =>
                transaction.effect_id == effect_id && transaction.auth_digest == auth_digest,
            Self::CanonicalBytes(bytes) => transaction.bytes == bytes,
        }
    }
}

/// One zero-based transaction position at an explicit genesis-derived height.
/// Locators and expectations remain host-local; no provider acceptance is trusted.
#[derive(Clone, Copy)]
pub struct SourceTransactionSelection<'a> {
    pub block_height: u32,
    pub transaction_index: u32,
    pub expected: SelectedTransactionExpectation<'a>,
}

/// Redacted failures contain no supplied identities, transaction bytes or I/O data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSelectionError {
    Replay(SourceReplayError),
    InvalidSelection,
    SelectionNotFound,
    SelectionMismatch,
}

impl From<SourceReplayError> for SourceSelectionError {
    fn from(error: SourceReplayError) -> Self {
        Self::Replay(error)
    }
}

impl fmt::Display for SourceSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replay(error) => fmt::Display::fmt(error, formatter),
            Self::InvalidSelection => formatter.write_str("source transaction selection rejected"),
            Self::SelectionNotFound => formatter.write_str("source transaction occurrence not found"),
            Self::SelectionMismatch => formatter.write_str("source transaction identities or bytes differ"),
        }
    }
}

impl std::error::Error for SourceSelectionError {}

/// Immutable owner-local occurrence, published only after every frame and EOF.
/// `block` is the selected occurrence; `boundary_journal` may end much later.
/// Work describes this supplied validated branch, not competing-branch absence.
/// There is deliberately no public constructor or conversion to a financial fact.
pub struct FiniteValidatedPrefixTransaction {
    block: HeaderTip,
    transaction_index: u32,
    transaction_bytes: Vec<u8>,
    effect_id: [u8; 32],
    auth_digest: [u8; 32],
    boundary_journal: [u8; JOURNAL_LEN],
}

impl FiniteValidatedPrefixTransaction {
    pub fn block(&self) -> HeaderTip {
        self.block
    }

    pub fn transaction_index(&self) -> u32 {
        self.transaction_index
    }

    /// Internal/wire identity order, not RPC display order.
    pub fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Actual v5/v6 auth digest, or FF32 for a pre-v5 complete effect identity.
    pub fn auth_digest(&self) -> [u8; 32] {
        self.auth_digest
    }

    pub fn transaction_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }

    /// Exact unchanged v11 aggregate journal of the completed replay boundary.
    pub fn boundary_journal(&self) -> &[u8; JOURNAL_LEN] {
        &self.boundary_journal
    }
}

impl fmt::Debug for FiniteValidatedPrefixTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FiniteValidatedPrefixTransaction").finish_non_exhaustive()
    }
}

struct SelectedTransaction<'a> {
    bytes: &'a [u8],
    effect_id: [u8; 32],
    auth_digest: [u8; 32],
}

/// Reuses the journal-only replay's genesis, full ledger, framing, budgets and EOF.
/// At most one selected transaction (at most the existing 2 MB body bound) is
/// retained alongside its one reusable block buffer and actual ledger state.
/// No public callback or partial result can escape a later block/reader failure.
pub fn replay_selected_testnet(
    reader: &mut impl Read,
    max_blocks: u32,
    max_input_bytes: u64,
    selection: SourceTransactionSelection<'_>,
) -> Result<FiniteValidatedPrefixTransaction, SourceSelectionError> {
    if matches!(selection.expected, SelectedTransactionExpectation::CanonicalBytes(bytes)
        if bytes.is_empty() || bytes.len() > MAX_BLOCK_BYTES)
    {
        return Err(SourceSelectionError::InvalidSelection);
    }
    let mut selected = None;
    let (boundary_journal, _) = replay_framed_testnet_with::<SourceSelectionError>(
        reader, max_blocks, max_input_bytes, |raw, ledger, phase| {
            let tip = ledger.tip();
            if matches!(phase, ReplayPhase::Admitted) && tip.height() == selection.block_height {
                // The common loop invokes this only AFTER complete block admission.
                let transaction = select_transaction(raw, tip.height(), selection.transaction_index)?;
                if !selection.expected.matches(&transaction) {
                    return Err(SourceSelectionError::SelectionMismatch);
                }
                selected = Some((tip, transaction.bytes.to_vec(), transaction.effect_id, transaction.auth_digest));
            }
            Ok(())
        },
    )?;
    let (block, transaction_bytes, effect_id, auth_digest) = selected.ok_or(SourceSelectionError::SelectionNotFound)?;
    Ok(FiniteValidatedPrefixTransaction {
        block, transaction_index: selection.transaction_index,
        transaction_bytes, effect_id, auth_digest, boundary_journal,
    })
}

// Structural extraction runs only for the selected body after full admission.
// The real era-specific complete-body parsers remain the sole body authorities.
fn select_transaction(raw: &[u8], height: u32, index: u32) -> Result<SelectedTransaction<'_>, SourceSelectionError> {
    let index = usize::try_from(index).map_err(|_| SourceSelectionError::SelectionNotFound)?;
    if height == 0 {
        // ParsedBlockBody intentionally rejects genesis. Reuse the maintained
        // fixed-base-case readers after the common loop authenticated it in full.
        if index != 0 {
            return Err(SourceSelectionError::SelectionNotFound);
        }
        let mut remaining = raw;
        BlockHeader::read(&mut remaining).map_err(|_| extraction_error())?;
        let _: usize = CompactSize::read_t(&mut remaining).map_err(|_| extraction_error())?;
        let bytes = remaining;
        let transaction = Transaction::read(&mut remaining, BranchId::Sprout)
            .map_err(|_| extraction_error())?;
        if !remaining.is_empty() {
            return Err(extraction_error());
        }
        return retain(bytes, transaction.txid().into(), [0xff; 32]);
    }
    if TEST_NETWORK.is_nu_active(NetworkUpgrade::Nu5, height.into()) {
        let body = PostNu5Block::parse(raw, height).map_err(|_| extraction_error())?;
        let transaction = body.transactions().get(index).ok_or(SourceSelectionError::SelectionNotFound)?;
        let effect_id = transaction.effect_id();
        let auth_digest = transaction.auth_digest().unwrap_or([0xff; 32]);
        let [Some(range), None] = post_nu5_transaction_ranges(raw, &body, [Some(index), None])?
            else { return Err(SourceSelectionError::SelectionNotFound); };
        return retain(&raw[range], effect_id, auth_digest);
    } else {
        let mut cursor = CanonicalBytes { remaining: raw };
        let body = ParsedBlockBody::parse(raw, &TEST_NETWORK).map_err(|_| extraction_error())?;
        let transaction = body.transaction(index).ok_or(SourceSelectionError::SelectionNotFound)?;
        let effect_id = transaction.effect_id();
        let auth_digest = transaction.auth_digest().unwrap_or([0xff; 32]);
        body.block().header().write(&mut cursor).map_err(|_| extraction_error())?;
        CompactSize::write(&mut cursor, body.transaction_count()).map_err(|_| extraction_error())?;
        for (position, transaction) in body.block().vtx().iter().enumerate() {
            let start = cursor.remaining;
            transaction.write(&mut cursor).map_err(|_| extraction_error())?;
            if position == index {
                return retain(&start[..start.len() - cursor.remaining.len()], effect_id, auth_digest);
            }
        }
    }
    Err(SourceSelectionError::SelectionNotFound)
}

// One canonical cursor walk over the existing complete parsed body, retaining
// original input spans rather than serialized replacements or new identities.
pub(crate) fn post_nu5_transaction_ranges<const N: usize>(
    raw: &[u8],
    body: &PostNu5Block<'_>,
    indices: [Option<usize>; N],
) -> Result<[Option<Range<usize>>; N], SourceSelectionError> {
    let mut ranges = std::array::from_fn(|_| None);
    if indices.iter().all(Option::is_none) { return Ok(ranges); }
    if raw.len() > MAX_BLOCK_BYTES { return Err(extraction_error()); }
    let mut cursor = CanonicalBytes { remaining: raw };
    body.header().write(&mut cursor).map_err(|_| extraction_error())?;
    CompactSize::write(&mut cursor, body.transactions().len()).map_err(|_| extraction_error())?;
    for (index, transaction) in body.transactions().iter().enumerate() {
        let start = raw.len() - cursor.remaining.len();
        match transaction {
            PostNu5Transaction::V4(transaction) | PostNu5Transaction::V6(transaction) => transaction.write(&mut cursor),
            PostNu5Transaction::V5(transaction) => cursor.write_all(transaction.original_bytes()),
        }.map_err(|_| extraction_error())?;
        let end = raw.len() - cursor.remaining.len();
        for (selected, range) in indices.iter().zip(&mut ranges) {
            if *selected == Some(index) {
                if start == end { return Err(extraction_error()); }
                *range = Some(start..end);
            }
        }
        if indices.iter().zip(&ranges).all(|(index, range)| index.is_none() || range.is_some()) {
            return Ok(ranges);
        }
    }
    Err(SourceSelectionError::SelectionNotFound)
}

fn retain(bytes: &[u8], effect_id: [u8; 32], auth_digest: [u8; 32]) -> Result<SelectedTransaction<'_>, SourceSelectionError> {
    if bytes.is_empty() || bytes.len() > MAX_BLOCK_BYTES {
        return Err(extraction_error());
    }
    Ok(SelectedTransaction { bytes, effect_id, auth_digest })
}

fn extraction_error() -> SourceSelectionError {
    SourceSelectionError::Replay(SourceReplayError::InvalidTransition)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Private parser-mechanics checks ONLY. None of these tests constructs a
    // successful replay, seeds a late ledger or publishes selected evidence.
    const LATE_BODY: &[u8] = include_bytes!("../tests/fixtures/testnet-nu5-block-1842467.bin");
    const ORIGINAL_V5: &[u8] = include_bytes!("../tests/fixtures/orchard-pure-testnet-1842467.bin");

    #[test]
    fn four_selected_occurrences_keep_one_exact_span_for_shared_funding() {
        // Structural span extraction only; this isolated body is not a checkpoint.
        let body = PostNu5Block::parse(LATE_BODY, 1_842_467).unwrap();
        let [Some(origin), Some(funding), Some(shared), None] = post_nu5_transaction_ranges(
            LATE_BODY, &body, [Some(0), Some(1), Some(1), None],
        ).unwrap() else { panic!("selected canonical spans missing"); };
        assert_eq!(funding, shared);
        assert_eq!(&LATE_BODY[funding], ORIGINAL_V5);
        assert_eq!(origin.end, LATE_BODY.len() - ORIGINAL_V5.len());
        assert!(matches!(
            post_nu5_transaction_ranges(LATE_BODY, &body, [Some(0), Some(1), Some(2), None]),
            Err(SourceSelectionError::SelectionNotFound),
        ));
    }

    #[test]
    fn original_v5_extraction_keeps_opaque_epk_and_every_authorization_suffix_byte() {
        let original = select_transaction(LATE_BODY, 1_842_467, 1).unwrap();
        assert_eq!(original.bytes, ORIGINAL_V5);
        // Independent maintained parser is an oracle on this original encoding.
        let oracle = Transaction::read(ORIGINAL_V5, BranchId::Nu5).unwrap();
        assert_eq!(original.effect_id, <[u8; 32]>::from(oracle.txid()));
        assert_eq!(original.auth_digest.as_slice(), oracle.auth_commitment().as_bytes());
        let mut changed = LATE_BODY.to_vec();
        let transaction_offset = LATE_BODY.len() - ORIGINAL_V5.len();
        changed[transaction_offset + 25 + 128..transaction_offset + 25 + 160].fill(0);
        let changed_effect = crate::raw_v5::RawV5::parse_exact(&changed[transaction_offset..]).unwrap().effect_id();
        changed[36..68].copy_from_slice(&two_effect_root(
            select_transaction(LATE_BODY, 1_842_467, 0).unwrap().effect_id,
            changed_effect,
        ));
        let opaque = select_transaction(&changed, 1_842_467, 1).unwrap();
        assert_eq!(opaque.bytes, &changed[transaction_offset..]);
        assert_eq!(&opaque.bytes[25 + 128..25 + 160], &[0; 32]);
        assert_eq!(opaque.auth_digest, original.auth_digest);
        assert_ne!(opaque.effect_id, original.effect_id);
        let (opaque_effect, opaque_auth) = (opaque.effect_id, opaque.auth_digest);
        // Raw V5 preserves a structural original proof suffix without normalizing
        // it into a maintained typed Orchard proof or claiming crypto validity.
        changed[transaction_offset + 8930] ^= 1;
        let suffix = select_transaction(&changed, 1_842_467, 1).unwrap();
        assert_eq!(suffix.bytes, &changed[transaction_offset..]);
        assert_eq!(suffix.effect_id, opaque_effect);
        assert_ne!(suffix.auth_digest, opaque_auth);
        assert!(!SelectedTransactionExpectation::Digests {
            effect_id: opaque_effect,
            auth_digest: opaque_auth,
        }.matches(&suffix));
    }

    fn two_effect_root(first: [u8; 32], second: [u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(first);
        digest.update(second);
        Sha256::digest(digest.finalize()).into()
    }

    fn v6_transparent(tag: u8, coinbase: bool) -> Vec<u8> {
        let height = 4_134_000u32;
        let mut bytes = 0x8000_0006u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0xd884_b698u32.to_le_bytes());
        bytes.extend_from_slice(&u32::from(BranchId::Nu6_3).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[tag; 32]);
        bytes.extend_from_slice(&(if coinbase { u32::MAX } else { 0u32 }).to_le_bytes());
        if coinbase {
            bytes.extend_from_slice(&[4, 3]);
            bytes.extend_from_slice(&height.to_le_bytes()[..3]);
        } else {
            bytes.extend_from_slice(&[1, 0x51]);
        }
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&[1, 0x51]);
        bytes.extend_from_slice(&[0; 4]);
        bytes
    }

    #[test]
    fn v6_same_effect_different_auth_cannot_match_a_selected_expectation() {
        // Existing history.rs structural vector, with deliberately invalid PoW.
        let coinbase = v6_transparent(0, true);
        let transaction = v6_transparent(1, false);
        let mut raw = LATE_BODY[..1487].to_vec();
        let first = Transaction::read(coinbase.as_slice(), BranchId::Nu6_3).unwrap();
        let second = Transaction::read(transaction.as_slice(), BranchId::Nu6_3).unwrap();
        raw[36..68].copy_from_slice(&two_effect_root(first.txid().into(), second.txid().into()));
        raw.push(2);
        raw.extend_from_slice(&coinbase);
        raw.extend_from_slice(&transaction);
        let selected = select_transaction(&raw, 4_134_000, 1).unwrap();
        assert_eq!(selected.bytes, transaction);
        let exact = SelectedTransactionExpectation::Digests {
            effect_id: selected.effect_id,
            auth_digest: selected.auth_digest,
        };
        assert!(exact.matches(&selected));
        assert!(SelectedTransactionExpectation::CanonicalBytes(&transaction).matches(&selected));
        let mut substituted = raw.clone();
        let mut with_trailing = transaction.clone();
        with_trailing.push(0);
        assert!(!SelectedTransactionExpectation::CanonicalBytes(&with_trailing).matches(&selected));
        substituted[1488 + coinbase.len() + 58] = 0x52;
        let changed = select_transaction(&substituted, 4_134_000, 1).unwrap();
        assert_eq!(changed.effect_id, selected.effect_id);
        assert_ne!(changed.auth_digest, selected.auth_digest);
        assert!(!exact.matches(&changed));
        assert!(!SelectedTransactionExpectation::CanonicalBytes(&transaction).matches(&changed));
        assert_ne!(select_transaction(&raw, 4_134_000, 0).unwrap().effect_id, selected.effect_id);
        assert!(matches!(select_transaction(&raw, 4_134_000, 2), Err(SourceSelectionError::SelectionNotFound)));
    }
}
