//! Bounded PUBLIC append-state-coherent replay from a caller-selected empty boundary.
//!
//! Each observation is acquired at an independently pinned hash. The provider is
//! trusted for the initial empty boundary, block answers and log completeness;
//! this is NOT consensus/finality, financial admission, backing or authenticated
//! global unspentness. In particular, omitting an unqueried NF-only transaction
//! can leave treeState unchanged and is invisible here. No C↔N owner mapping is
//! inferred. Empty blocks must be supplied; no arbitrary root/frontier import,
//! eviction, network, private opening, SQL or proving side effects exist here.

use std::{collections::{BTreeMap, BTreeSet}, error::Error, fmt};
use primitive_types::U256;
use ziquid_protocol::samechain::{MAX_CIPHERTEXT_BYTES, tree::{NoteInsertion, NoteTree, TREE_CAPACITY}};
use super::inspection::{
    AppendedNote, AuthorityObservation, ConsumedNullifier, InputState, InspectionScope,
    LogOccurrence, OccurrenceOrder,
};

pub const MAX_HISTORY_BLOCKS: usize = 2048;
pub const MAX_HISTORY_NOTES: usize = 4096;
pub const MAX_HISTORY_NULLIFIERS: usize = 8192;
pub const MAX_HISTORY_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryError {
    InvalidOrigin,
    WrongScope,
    WrongBlock,
    InitialBoundary,
    TreeMismatch,
    DuplicateCommitment,
    DuplicateNullifier,
    InvalidOccurrence,
    InputMismatch,
    LimitExceeded,
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidOrigin => "invalid public-history origin",
            Self::WrongScope => "public-history scope mismatch",
            Self::WrongBlock => "public-history block discontinuity",
            Self::InitialBoundary => "public-history origin is not the selected initial empty boundary",
            Self::TreeMismatch => "public-history append/tree mismatch",
            Self::DuplicateCommitment => "repeated public-history commitment",
            Self::DuplicateNullifier => "repeated observed public-history nullifier",
            Self::InvalidOccurrence => "inconsistent public-history occurrence",
            Self::InputMismatch => "public-history queried input mismatch",
            Self::LimitExceeded => "public-history retention limit exceeded",
        })
    }
}
impl Error for HistoryError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryBlock {
    pub number: U256,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
}

/// Ciphertext descriptor and its path to the historical insertion root, not ownership/admission.
#[derive(Debug, PartialEq, Eq)]
pub struct RetainedNote {
    pub block: HistoryBlock,
    pub note: AppendedNote,
    pub insertion: NoteInsertion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedNullifier {
    pub block: HistoryBlock,
    pub event: ConsumedNullifier,
}

/// Complete selected block coverage within fixed bounds, under provider assumptions.
/// Deliberately not Clone: ingestion stages only one fixed frontier and bounded block deltas.
#[derive(Debug)]
pub struct PublicHistory {
    origin: InspectionScope,
    origin_number: U256,
    tree: NoteTree,
    blocks: Vec<HistoryBlock>,
    block_hashes: BTreeSet<[u8; 32]>,
    notes: BTreeMap<[u8; 32], RetainedNote>,
    roots: BTreeMap<(u32, [u8; 32]), u64>,
    nullifiers: BTreeMap<[u8; 32], ObservedNullifier>,
    transactions: BTreeSet<[u8; 32]>,
    ciphertext_bytes: usize,
}

impl PublicHistory {
    /// Pins only the origin; the first acquired block must prove coherence with
    /// the initial empty tree0. Its absence of earlier spends is a TRUST assumption.
    pub fn new(origin: InspectionScope, origin_number: U256) -> Result<Self, HistoryError> {
        origin.validate().map_err(|_| HistoryError::InvalidOrigin)?;
        let deployment = origin.expected.digest().map_err(|_| HistoryError::InvalidOrigin)?;
        let tree = NoteTree::new(deployment, 0).map_err(|_| HistoryError::InvalidOrigin)?;
        Ok(Self {
            origin, origin_number, tree, blocks: Vec::new(), block_hashes: BTreeSet::new(),
            notes: BTreeMap::new(), roots: BTreeMap::new(), nullifiers: BTreeMap::new(),
            transactions: BTreeSet::new(), ciphertext_bytes: 0,
        })
    }

    /// Caller supplies an independent pin for EVERY block, including empty ones.
    /// All errors leave accepted state unchanged. Accepted ciphertexts are moved,
    /// never cloned with the growing retained history.
    pub fn ingest(&mut self, expected_hash: [u8; 32], observation: AuthorityObservation)
        -> Result<(), HistoryError>
    {
        let parts = observation.into_history_parts();
        let mut expected_scope = self.origin;
        expected_scope.block_hash = parts.scope.block_hash;
        if parts.scope != expected_scope { return Err(HistoryError::WrongScope); }
        if expected_hash == [0; 32] || parts.scope.block_hash != expected_hash
            || self.block_hashes.contains(&expected_hash)
        {
            return Err(HistoryError::WrongBlock);
        }
        let block = HistoryBlock {
            number: parts.block_number, hash: expected_hash, parent_hash: parts.parent_hash,
        };
        if let Some(prior) = self.latest_block() {
            let (next_number, overflow) = prior.number.overflowing_add(U256::one());
            if overflow || block.number != next_number || block.parent_hash != prior.hash {
                return Err(HistoryError::WrongBlock);
            }
        } else {
            if block.hash != self.origin.block_hash || block.number != self.origin_number {
                return Err(HistoryError::WrongBlock);
            }
            if parts.tree_id != 0 || parts.tree_count != 0 || parts.tree_root != self.tree.root()
                || !parts.appended_notes.is_empty() || !parts.consumed_nullifiers.is_empty()
            {
                return Err(HistoryError::InitialBoundary);
            }
        }

        let block_count = bounded_add(self.blocks.len(), 1, MAX_HISTORY_BLOCKS)?;
        bounded_add(self.notes.len(), parts.appended_notes.len(), MAX_HISTORY_NOTES)?;
        bounded_add(self.nullifiers.len(), parts.consumed_nullifiers.len(), MAX_HISTORY_NULLIFIERS)?;
        let mut ciphertext_bytes = self.ciphertext_bytes;
        for note in &parts.appended_notes {
            if note.ciphertext.is_empty() || note.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
                return Err(HistoryError::LimitExceeded);
            }
            ciphertext_bytes = bounded_add(ciphertext_bytes, note.ciphertext.len(), MAX_HISTORY_CIPHERTEXT_BYTES)?;
        }

        let transactions = merge_occurrences(&parts.appended_notes, &parts.consumed_nullifiers)?;
        if transactions.keys().any(|hash| self.transactions.contains(hash)) {
            return Err(HistoryError::InvalidOccurrence);
        }
        let mut tree = self.tree.clone(); // Fixed depth-32 frontier only, independent of history length.
        let mut insertions = Vec::with_capacity(parts.appended_notes.len());
        let mut commitments = BTreeSet::new();
        let mut roots = BTreeMap::new();
        let mut nullifiers = BTreeSet::new();
        for note in &parts.appended_notes {
            if self.notes.contains_key(&note.commitment) || !commitments.insert(note.commitment) {
                return Err(HistoryError::DuplicateCommitment);
            }
            if note.count != u64::from(note.index).checked_add(1).ok_or(HistoryError::TreeMismatch)? {
                return Err(HistoryError::TreeMismatch);
            }
            // Authority leaves a full tree current until the NEXT append. Empty
            // rollover roots are not recorded as admitted historical rootCounts.
            if tree.count() == TREE_CAPACITY { tree.rollover().map_err(|_| HistoryError::TreeMismatch)?; }
            let insertion = tree.append(note.commitment).map_err(|_| HistoryError::TreeMismatch)?;
            if (insertion.tree_id, insertion.index, insertion.count, insertion.root)
                != (note.tree_id, note.index, note.count, note.root)
            {
                return Err(HistoryError::TreeMismatch);
            }
            let key = (insertion.tree_id, insertion.root);
            if roots.contains_key(&key) || self.roots.contains_key(&key) {
                return Err(HistoryError::TreeMismatch);
            }
            roots.insert(key, insertion.count);
            insertions.push(insertion);
        }
        for event in &parts.consumed_nullifiers {
            if event.nullifier == [0; 32] || self.nullifiers.contains_key(&event.nullifier)
                || !nullifiers.insert(event.nullifier)
            {
                return Err(HistoryError::DuplicateNullifier);
            }
        }
        if (tree.tree_id(), tree.count(), tree.root()) != (parts.tree_id, parts.tree_count, parts.tree_root) {
            return Err(HistoryError::TreeMismatch);
        }
        // Getters describe END-of-block state, including every staged append/NF,
        // not the state at the queried packet's position in event order.
        for input in &parts.input_states {
            let count = roots.get(&(input.tree_id, input.root)).copied()
                .unwrap_or_else(|| self.root_count(input.tree_id, input.root));
            let spent = nullifiers.contains(&input.nullifier) || self.observed_spent(&input.nullifier);
            check_input(input, count, spent)?;
        }

        // No fallible coherence/limit operation follows this commit boundary.
        self.tree = tree;
        self.ciphertext_bytes = ciphertext_bytes;
        self.blocks.push(block);
        debug_assert_eq!(self.blocks.len(), block_count);
        self.block_hashes.insert(block.hash);
        self.transactions.extend(transactions.into_keys());
        self.roots.extend(roots);
        for (note, insertion) in parts.appended_notes.into_iter().zip(insertions) {
            self.notes.insert(note.commitment, RetainedNote { block, note, insertion });
        }
        for event in parts.consumed_nullifiers {
            self.nullifiers.insert(event.nullifier, ObservedNullifier { block, event });
        }
        Ok(())
    }

    /// Copy of the caller-selected public pins at the origin block, not authentication.
    pub fn origin_scope(&self) -> InspectionScope { self.origin }

    pub fn note(&self, commitment: &[u8; 32]) -> Option<&RetainedNote> { self.notes.get(commitment) }
    pub fn notes(&self) -> impl Iterator<Item = &RetainedNote> { self.notes.values() }
    pub fn root_count(&self, tree_id: u32, root: [u8; 32]) -> u64 {
        self.roots.get(&(tree_id, root)).copied().unwrap_or(0)
    }
    /// Absence means NOT OBSERVED under provider completeness, not proven unspent.
    pub fn observed_spent(&self, nullifier: &[u8; 32]) -> bool { self.nullifiers.contains_key(nullifier) }
    pub fn observed_nullifier(&self, nullifier: &[u8; 32]) -> Option<&ObservedNullifier> {
        self.nullifiers.get(nullifier)
    }
    pub fn nullifiers(&self) -> impl Iterator<Item = &ObservedNullifier> { self.nullifiers.values() }
    pub fn latest_block(&self) -> Option<HistoryBlock> { self.blocks.last().copied() }
    pub fn blocks(&self) -> &[HistoryBlock] { &self.blocks }
    pub fn tree_state(&self) -> (u32, u64, [u8; 32]) { (self.tree.tree_id(), self.tree.count(), self.tree.root()) }
    pub fn block_count(&self) -> usize { self.blocks.len() }
    pub fn note_count(&self) -> usize { self.notes.len() }
    pub fn nullifier_count(&self) -> usize { self.nullifiers.len() }
    pub fn ciphertext_bytes(&self) -> usize { self.ciphertext_bytes }
    pub fn source_scope(&self) -> &'static str { "TRUSTED_NODE_AT_SELECTED_BLOCK" }
    pub fn initial_boundary_trust(&self) -> &'static str { "TRUSTED_PROVIDER_INITIAL_EMPTY_BOUNDARY" }
    pub fn log_completeness_trust(&self) -> &'static str { "TRUSTED_PROVIDER_LOG_COMPLETENESS" }

    /// Compares node claims only; zero unknown root count or observed spent=true
    /// can be coherent while the associated packet is financially ineligible.
    pub fn check_input_state(&self, input: &InputState) -> Result<(), HistoryError> {
        check_input(input, self.root_count(input.tree_id, input.root), self.observed_spent(&input.nullifier))
    }
}

fn bounded_add(current: usize, added: usize, limit: usize) -> Result<usize, HistoryError> {
    current.checked_add(added).filter(|total| *total <= limit).ok_or(HistoryError::LimitExceeded)
}

fn check_input(input: &InputState, count: u64, spent: bool) -> Result<(), HistoryError> {
    if input.reported_root_count != count || input.reported_spent != spent {
        return Err(HistoryError::InputMismatch);
    }
    Ok(())
}

fn merge_occurrences(notes: &[AppendedNote], nullifiers: &[ConsumedNullifier])
    -> Result<BTreeMap<[u8; 32], u64>, HistoryError>
{
    let mut notes = notes.iter().map(|note| note.occurrence).peekable();
    let mut nullifiers = nullifiers.iter().map(|event| event.occurrence).peekable();
    let mut order = OccurrenceOrder::default();
    loop {
        let next = match (notes.peek(), nullifiers.peek()) {
            (Some(note), Some(nullifier)) => {
                if position(note) <= position(nullifier) { notes.next() } else { nullifiers.next() }
            }
            (Some(_), None) => notes.next(),
            (None, Some(_)) => nullifiers.next(),
            (None, None) => break,
        };
        if let Some(occurrence) = next {
            order.observe(occurrence).map_err(|_| HistoryError::InvalidOccurrence)?;
        }
    }
    Ok(order.into_transactions())
}

fn position(occurrence: &LogOccurrence) -> (u64, u64) {
    (occurrence.transaction_index, occurrence.log_index)
}
