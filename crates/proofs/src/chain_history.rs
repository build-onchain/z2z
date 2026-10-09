//! Bounded ZIP221 V1 Heartwood/Canopy, V2 NU5 through NU6.2, and V3 NU6.3 metadata accumulation.
//!
//! Leaves are metadata, not authenticated blocks or proof certificates. The
//! caller validates block contents and chooses the epoch start; this module
//! neither imports checkpoints nor resets itself when the source branch changes.
//! Upstream `zcash_history` owns node encoding, combining and hashing.

use std::fmt;

use primitive_types::U256;
use zcash_history::{V1, V2, V3, Version};

pub use zcash_history::NodeData as HistoryLeaf;
pub use zcash_history::NodeDataV2 as HistoryLeafV2;
pub use zcash_history::NodeDataV3 as HistoryLeafV3;

const HEARTWOOD_BRANCH: u32 = 0xf5b9_230b;
const CANOPY_BRANCH: u32 = 0xe9ff_75a6;
const NU5_BRANCH: u32 = 0xc2d6_d0b4;
const NU6_BRANCH: u32 = 0xc8e7_1055;
const NU61_BRANCH: u32 = 0x4dec_4df0;
const NU62_BRANCH: u32 = 0x5437_f330;
const NU63_BRANCH: u32 = 0x37a5_165b;
const MAX_PEAKS: usize = u32::BITS as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryError {
    UnsupportedBranch,
    BranchMismatch,
    MalformedLeaf,
    HeightOutOfRange,
    NonconsecutiveHeight,
    HeightOverflow,
    LeafCountOverflow,
    WorkOverflow,
    SaplingCountOverflow,
    OrchardCountOverflow,
    IronwoodCountOverflow,
}

impl fmt::Display for HistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedBranch => "not a supported V1 Heartwood/Canopy, V2 NU5 through NU6.2, or V3 NU6.3 consensus branch",
            Self::BranchMismatch => "history leaf branch differs from the owned epoch",
            Self::MalformedLeaf => "history leaf endpoints disagree",
            Self::HeightOutOfRange => "history leaf height exceeds u32",
            Self::NonconsecutiveHeight => "history leaf is not the exact next height",
            Self::HeightOverflow => "history height overflow",
            Self::LeafCountOverflow => "history leaf counter overflow",
            Self::WorkOverflow => "history total work overflow",
            Self::SaplingCountOverflow => "history Sapling transaction counter overflow",
            Self::OrchardCountOverflow => "history Orchard transaction counter overflow",
            Self::IronwoodCountOverflow => "history Ironwood transaction counter overflow",
        })
    }
}

impl std::error::Error for HistoryError {}

/// Complete peaks only, ordered left to right (largest to smallest).
/// No generated-node tree or historical leaves are retained.
#[derive(Clone, Debug)]
pub struct ChainHistoryV1 {
    consensus_branch_id: u32,
    peaks: [Option<HistoryLeaf>; MAX_PEAKS],
    peak_count: usize,
    leaf_count: u32,
    last_height: u32,
    total_work: U256,
    sapling_tx: u64,
    root: [u8; 32],
}

fn validate_leaf(leaf: &HistoryLeaf) -> Result<u32, HistoryError> {
    if !matches!(leaf.consensus_branch_id, HEARTWOOD_BRANCH | CANOPY_BRANCH) {
        return Err(HistoryError::UnsupportedBranch);
    }
    validate_leaf_endpoints(leaf)
}

fn validate_leaf_endpoints(leaf: &HistoryLeaf) -> Result<u32, HistoryError> {
    if leaf.start_height != leaf.end_height
        || leaf.start_time != leaf.end_time
        || leaf.start_target != leaf.end_target
        || leaf.start_sapling_root != leaf.end_sapling_root
    {
        return Err(HistoryError::MalformedLeaf);
    }
    u32::try_from(leaf.start_height).map_err(|_| HistoryError::HeightOutOfRange)
}

impl ChainHistoryV1 {
    /// Starts a new explicit Heartwood or Canopy epoch from one complete leaf.
    pub fn new(first: HistoryLeaf) -> Result<Self, HistoryError> {
        let height = validate_leaf(&first)?;
        let root = V1::hash(&first);
        let total_work = first.subtree_total_work;
        let sapling_tx = first.sapling_tx;
        let consensus_branch_id = first.consensus_branch_id;
        let mut peaks = std::array::from_fn(|_| None);
        peaks[0] = Some(first);
        Ok(Self {
            consensus_branch_id,
            peaks,
            peak_count: 1,
            leaf_count: 1,
            last_height: height,
            total_work,
            sapling_tx,
            root,
        })
    }

    /// Appends the exact next complete leaf. Every error leaves all state intact.
    pub fn append(&mut self, leaf: HistoryLeaf) -> Result<[u8; 32], HistoryError> {
        let height = validate_leaf(&leaf)?;
        if leaf.consensus_branch_id != self.consensus_branch_id {
            return Err(HistoryError::BranchMismatch);
        }
        let next_height = self.last_height.checked_add(1).ok_or(HistoryError::HeightOverflow)?;
        if height != next_height {
            return Err(HistoryError::NonconsecutiveHeight);
        }
        let leaf_count = self.leaf_count.checked_add(1).ok_or(HistoryError::LeafCountOverflow)?;
        let total_work = self.total_work.checked_add(leaf.subtree_total_work).ok_or(HistoryError::WorkOverflow)?;
        let sapling_tx = self.sapling_tx.checked_add(leaf.sapling_tx).ok_or(HistoryError::SaplingCountOverflow)?;

        // All upstream sums below are nonnegative sub-sums of these checked
        // totals. Stage only the carry and bagged root, never copy the MMR.
        let mut retained = self.peak_count;
        let mut carry = leaf;
        while retained > 0 {
            let left = self.peaks[retained - 1].as_ref().expect("occupied complete peak");
            if left.end_height - left.start_height != carry.end_height - carry.start_height {
                break;
            }
            carry = V1::combine(left, &carry);
            retained -= 1;
        }
        let root = V1::hash(&self.bag_with(Some((retained, &carry))));

        // No fallible operation follows the commit boundary. A u32 leaf count
        // has at most 32 complete peaks, so the carry always fits the array.
        for peak in &mut self.peaks[retained..self.peak_count] {
            *peak = None;
        }
        self.peaks[retained] = Some(carry);
        self.peak_count = retained + 1;
        self.leaf_count = leaf_count;
        self.last_height = height;
        self.total_work = total_work;
        self.sapling_tx = sapling_tx;
        self.root = root;
        Ok(root)
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    pub fn consensus_branch_id(&self) -> u32 {
        self.consensus_branch_id
    }

    pub fn last_height(&self) -> u32 {
        self.last_height
    }

    // Original ZIP221 bags peaks left to right, unlike right-to-left carry
    // merging. Replacement denotes the staged carry after the retained prefix.
    fn bag_with(&self, replacement: Option<(usize, &HistoryLeaf)>) -> HistoryLeaf {
        let retained = replacement.map_or(self.peak_count, |(retained, _)| retained);
        if retained == 0 {
            return replacement.expect("nonempty staged history").1.clone();
        }
        let mut root = self.peaks[0].as_ref().expect("occupied complete peak").clone();
        for peak in &self.peaks[1..retained] {
            root = V1::combine(&root, peak.as_ref().expect("occupied complete peak"));
        }
        if let Some((_, carry)) = replacement {
            root = V1::combine(&root, carry);
        }
        root
    }
}

/// Complete NU5/NU6/NU6.1/NU6.2 V2 peaks only, ordered left to right (largest to smallest).
/// No generated-node tree or historical leaves are retained. Epoch selection
/// and block authentication remain the caller's responsibility; heights are
/// metadata and are not restricted to a network activation interval.
#[derive(Clone, Debug)]
pub struct ChainHistoryV2 {
    consensus_branch_id: u32,
    peaks: [Option<HistoryLeafV2>; MAX_PEAKS],
    peak_count: usize,
    leaf_count: u32,
    last_height: u32,
    total_work: U256,
    sapling_tx: u64,
    orchard_tx: u64,
    root: [u8; 32],
}

fn validate_leaf_v2(leaf: &HistoryLeafV2) -> Result<u32, HistoryError> {
    if !matches!(leaf.v1.consensus_branch_id, NU5_BRANCH | NU6_BRANCH | NU61_BRANCH | NU62_BRANCH) {
        return Err(HistoryError::UnsupportedBranch);
    }
    if leaf.start_orchard_root != leaf.end_orchard_root {
        return Err(HistoryError::MalformedLeaf);
    }
    validate_leaf_endpoints(&leaf.v1)
}

impl ChainHistoryV2 {
    /// Starts a new explicit NU5 through NU6.2 epoch from one complete V2 leaf.
    pub fn new(first: HistoryLeafV2) -> Result<Self, HistoryError> {
        let height = validate_leaf_v2(&first)?;
        let root = V2::hash(&first);
        let total_work = first.v1.subtree_total_work;
        let sapling_tx = first.v1.sapling_tx;
        let orchard_tx = first.orchard_tx;
        let consensus_branch_id = first.v1.consensus_branch_id;
        let mut peaks = std::array::from_fn(|_| None);
        peaks[0] = Some(first);
        Ok(Self {
            consensus_branch_id,
            peaks,
            peak_count: 1,
            leaf_count: 1,
            last_height: height,
            total_work,
            sapling_tx,
            orchard_tx,
            root,
        })
    }

    /// Appends the exact next complete leaf. Every error leaves all state intact.
    pub fn append(&mut self, leaf: HistoryLeafV2) -> Result<[u8; 32], HistoryError> {
        let height = validate_leaf_v2(&leaf)?;
        if leaf.v1.consensus_branch_id != self.consensus_branch_id {
            return Err(HistoryError::BranchMismatch);
        }
        let next_height = self.last_height.checked_add(1).ok_or(HistoryError::HeightOverflow)?;
        if height != next_height {
            return Err(HistoryError::NonconsecutiveHeight);
        }
        let leaf_count = self.leaf_count.checked_add(1).ok_or(HistoryError::LeafCountOverflow)?;
        let total_work = self.total_work.checked_add(leaf.v1.subtree_total_work).ok_or(HistoryError::WorkOverflow)?;
        let sapling_tx = self.sapling_tx.checked_add(leaf.v1.sapling_tx).ok_or(HistoryError::SaplingCountOverflow)?;
        let orchard_tx = self.orchard_tx.checked_add(leaf.orchard_tx).ok_or(HistoryError::OrchardCountOverflow)?;

        // Every upstream unchecked sum is a nonnegative sub-sum of the checked
        // totals. Stage only the carry and bagged root, never copy the MMR.
        let mut retained = self.peak_count;
        let mut carry = leaf;
        while retained > 0 {
            let left = self.peaks[retained - 1].as_ref().expect("occupied complete peak");
            if left.v1.end_height - left.v1.start_height != carry.v1.end_height - carry.v1.start_height {
                break;
            }
            carry = V2::combine(left, &carry);
            retained -= 1;
        }
        let root = V2::hash(&self.bag_with(Some((retained, &carry))));

        // No fallible operation follows this boundary. The checked u32 leaf
        // count bounds the number of complete peaks to the 32-slot array.
        for peak in &mut self.peaks[retained..self.peak_count] {
            *peak = None;
        }
        self.peaks[retained] = Some(carry);
        self.peak_count = retained + 1;
        self.leaf_count = leaf_count;
        self.last_height = height;
        self.total_work = total_work;
        self.sapling_tx = sapling_tx;
        self.orchard_tx = orchard_tx;
        self.root = root;
        Ok(root)
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    pub fn consensus_branch_id(&self) -> u32 {
        self.consensus_branch_id
    }

    pub fn last_height(&self) -> u32 {
        self.last_height
    }

    // ZIP221 bags peaks left to right, not like right-to-left carry merging.
    fn bag_with(&self, replacement: Option<(usize, &HistoryLeafV2)>) -> HistoryLeafV2 {
        let retained = replacement.map_or(self.peak_count, |(retained, _)| retained);
        if retained == 0 {
            return replacement.expect("nonempty staged history").1.clone();
        }
        let mut root = self.peaks[0].as_ref().expect("occupied complete peak").clone();
        for peak in &self.peaks[1..retained] {
            root = V2::combine(&root, peak.as_ref().expect("occupied complete peak"));
        }
        if let Some((_, carry)) = replacement {
            root = V2::combine(&root, carry);
        }
        root
    }
}

/// Complete NU6.3 V3 peaks only, ordered left to right (largest to smallest).
/// No generated-node tree or historical leaves are retained. Epoch selection
/// and block authentication remain the caller's responsibility; heights are
/// metadata and are not restricted to a network activation interval.
#[derive(Clone, Debug)]
pub struct ChainHistoryV3 {
    consensus_branch_id: u32,
    peaks: [Option<HistoryLeafV3>; MAX_PEAKS],
    peak_count: usize,
    leaf_count: u32,
    last_height: u32,
    total_work: U256,
    sapling_tx: u64,
    orchard_tx: u64,
    ironwood_tx: u64,
    root: [u8; 32],
}

fn validate_leaf_v3(leaf: &HistoryLeafV3) -> Result<u32, HistoryError> {
    if leaf.v2.v1.consensus_branch_id != NU63_BRANCH {
        return Err(HistoryError::UnsupportedBranch);
    }
    if leaf.start_ironwood_root != leaf.end_ironwood_root
        || leaf.v2.start_orchard_root != leaf.v2.end_orchard_root
    {
        return Err(HistoryError::MalformedLeaf);
    }
    validate_leaf_endpoints(&leaf.v2.v1)
}

impl ChainHistoryV3 {
    /// Starts a new explicit NU6.3 epoch from one complete V3 leaf.
    pub fn new(first: HistoryLeafV3) -> Result<Self, HistoryError> {
        let height = validate_leaf_v3(&first)?;
        let root = V3::hash(&first);
        let total_work = first.v2.v1.subtree_total_work;
        let sapling_tx = first.v2.v1.sapling_tx;
        let orchard_tx = first.v2.orchard_tx;
        let ironwood_tx = first.ironwood_tx;
        let consensus_branch_id = first.v2.v1.consensus_branch_id;
        let mut peaks = std::array::from_fn(|_| None);
        peaks[0] = Some(first);
        Ok(Self {
            consensus_branch_id,
            peaks,
            peak_count: 1,
            leaf_count: 1,
            last_height: height,
            total_work,
            sapling_tx,
            orchard_tx,
            ironwood_tx,
            root,
        })
    }

    /// Appends the exact next complete leaf. Every error leaves all state intact.
    pub fn append(&mut self, leaf: HistoryLeafV3) -> Result<[u8; 32], HistoryError> {
        let height = validate_leaf_v3(&leaf)?;
        if leaf.v2.v1.consensus_branch_id != self.consensus_branch_id {
            return Err(HistoryError::BranchMismatch);
        }
        let next_height = self.last_height.checked_add(1).ok_or(HistoryError::HeightOverflow)?;
        if height != next_height {
            return Err(HistoryError::NonconsecutiveHeight);
        }
        let leaf_count = self.leaf_count.checked_add(1).ok_or(HistoryError::LeafCountOverflow)?;
        let total_work = self.total_work.checked_add(leaf.v2.v1.subtree_total_work).ok_or(HistoryError::WorkOverflow)?;
        let sapling_tx = self.sapling_tx.checked_add(leaf.v2.v1.sapling_tx).ok_or(HistoryError::SaplingCountOverflow)?;
        let orchard_tx = self.orchard_tx.checked_add(leaf.v2.orchard_tx).ok_or(HistoryError::OrchardCountOverflow)?;
        let ironwood_tx = self.ironwood_tx.checked_add(leaf.ironwood_tx).ok_or(HistoryError::IronwoodCountOverflow)?;

        // Every upstream unchecked sum is a nonnegative sub-sum of the checked
        // totals. Stage only the carry and bagged root, never copy the MMR.
        let mut retained = self.peak_count;
        let mut carry = leaf;
        while retained > 0 {
            let left = self.peaks[retained - 1].as_ref().expect("occupied complete peak");
            if left.v2.v1.end_height - left.v2.v1.start_height != carry.v2.v1.end_height - carry.v2.v1.start_height {
                break;
            }
            carry = V3::combine(left, &carry);
            retained -= 1;
        }
        let root = V3::hash(&self.bag_with(Some((retained, &carry))));

        // No fallible operation follows this boundary. The checked u32 leaf
        // count bounds the number of complete peaks to the 32-slot array.
        for peak in &mut self.peaks[retained..self.peak_count] {
            *peak = None;
        }
        self.peaks[retained] = Some(carry);
        self.peak_count = retained + 1;
        self.leaf_count = leaf_count;
        self.last_height = height;
        self.total_work = total_work;
        self.sapling_tx = sapling_tx;
        self.orchard_tx = orchard_tx;
        self.ironwood_tx = ironwood_tx;
        self.root = root;
        Ok(root)
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    pub fn consensus_branch_id(&self) -> u32 {
        self.consensus_branch_id
    }

    pub fn last_height(&self) -> u32 {
        self.last_height
    }

    // ZIP221 bags peaks left to right, not like right-to-left carry merging.
    fn bag_with(&self, replacement: Option<(usize, &HistoryLeafV3)>) -> HistoryLeafV3 {
        let retained = replacement.map_or(self.peak_count, |(retained, _)| retained);
        if retained == 0 {
            return replacement.expect("nonempty staged history").1.clone();
        }
        let mut root = self.peaks[0].as_ref().expect("occupied complete peak").clone();
        for peak in &self.peaks[1..retained] {
            root = V3::combine(&root, peak.as_ref().expect("occupied complete peak"));
        }
        if let Some((_, carry)) = replacement {
            root = V3::combine(&root, carry);
        }
        root
    }
}

#[cfg(test)]
#[path = "../tests/fixtures/history-v3-primary.rs"]
mod primary_vectors_v3;

#[cfg(test)]
mod v3_tests {
    use super::*;
    use primary_vectors_v3::{TestVector, TEST_VECTORS};

    fn vector_leaf(vector: &TestVector) -> HistoryLeafV3 {
        HistoryLeafV3 {
            v2: HistoryLeafV2 {
                v1: HistoryLeaf {
                    consensus_branch_id: vector.consensus_branch_id,
                    subtree_commitment: vector.leaf_block_hash,
                    start_time: vector.leaf_time,
                    end_time: vector.leaf_time,
                    start_target: vector.leaf_target_bits,
                    end_target: vector.leaf_target_bits,
                    start_sapling_root: vector.leaf_sapling_root,
                    end_sapling_root: vector.leaf_sapling_root,
                    subtree_total_work: U256::from_little_endian(&vector.leaf_work),
                    start_height: vector.leaf_height,
                    end_height: vector.leaf_height,
                    sapling_tx: vector.leaf_sapling_tx_count,
                },
                start_orchard_root: vector.leaf_orchard_root,
                end_orchard_root: vector.leaf_orchard_root,
                orchard_tx: vector.leaf_orchard_tx_count,
            },
            start_ironwood_root: vector.leaf_ironwood_root,
            end_ironwood_root: vector.leaf_ironwood_root,
            ironwood_tx: vector.leaf_ironwood_tx_count,
        }
    }

    fn serialized(node: &HistoryLeafV3) -> Vec<u8> {
        let mut bytes = Vec::new();
        V3::write(node, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn all_sixteen_primary_v3_leaves_peaks_roots_hashes_and_counters_match() {
        let mut history = None;
        let mut total_work = U256::zero();
        let mut sapling_tx = 0;
        let mut orchard_tx = 0;
        let mut ironwood_tx = 0;
        for vector in TEST_VECTORS {
            let leaf = vector_leaf(vector);
            assert_eq!(serialized(&leaf), vector.leaf_serialized);
            total_work += U256::from_little_endian(&vector.leaf_work);
            sapling_tx += vector.leaf_sapling_tx_count;
            orchard_tx += vector.leaf_orchard_tx_count;
            ironwood_tx += vector.leaf_ironwood_tx_count;
            let root = if let Some(history) = history.as_mut() {
                let history: &mut ChainHistoryV3 = history;
                history.append(leaf).unwrap()
            } else {
                let initial = ChainHistoryV3::new(leaf).unwrap();
                let root = initial.root();
                history = Some(initial);
                root
            };
            let history = history.as_ref().unwrap();
            assert_eq!(history.leaf_count(), vector.n_leaves);
            assert_eq!(history.consensus_branch_id(), vector.consensus_branch_id);
            assert_eq!(u64::from(history.last_height()), vector.leaf_height);
            assert_eq!(history.peak_count, vector.peaks.len());
            for (peak, expected) in history.peaks[..history.peak_count].iter().zip(vector.peaks) {
                assert_eq!(serialized(peak.as_ref().unwrap()), *expected);
            }
            assert!(history.peaks[history.peak_count..].iter().all(Option::is_none));
            let bagged = history.bag_with(None);
            assert_eq!(serialized(&bagged), vector.root_serialized);
            assert_eq!(V3::hash(&bagged), vector.hash_chain_history_root);
            assert_eq!(root, vector.hash_chain_history_root);
            assert_eq!(history.root(), vector.hash_chain_history_root);
            assert_eq!(history.total_work, total_work);
            assert_eq!(history.sapling_tx, sapling_tx);
            assert_eq!(history.orchard_tx, orchard_tx);
            assert_eq!(history.ironwood_tx, ironwood_tx);
            assert_eq!(bagged.v2.v1.subtree_total_work, total_work);
            assert_eq!(bagged.v2.v1.sapling_tx, sapling_tx);
            assert_eq!(bagged.v2.orchard_tx, orchard_tx);
            assert_eq!(bagged.ironwood_tx, ironwood_tx);
        }
        assert_eq!(history.unwrap().leaf_count(), 16);
    }

    #[test]
    fn saturated_v3_leaf_count_rejects_a_thirty_third_peak_atomically() {
        // Private construction reaches an impractical boundary without exposing
        // checkpoint import or retaining historical/generated nodes.
        let first = vector_leaf(&TEST_VECTORS[0]);
        let mut history = ChainHistoryV3::new(first.clone()).unwrap();
        let mut start = 0u64;
        for (index, slot) in history.peaks.iter_mut().enumerate() {
            let mut peak = first.clone();
            let size = 1u64 << (31 - index);
            peak.v2.v1.start_height = start;
            peak.v2.v1.end_height = start + size - 1;
            start += size;
            *slot = Some(peak);
        }
        history.peak_count = 32;
        history.leaf_count = u32::MAX;
        history.last_height = u32::MAX - 1;
        history.total_work = first.v2.v1.subtree_total_work * U256::from(32);
        history.sapling_tx = first.v2.v1.sapling_tx * 32;
        history.orchard_tx = first.v2.orchard_tx * 32;
        history.ironwood_tx = first.ironwood_tx * 32;
        history.root = V3::hash(&history.bag_with(None));
        let mut next = first;
        next.v2.v1.start_height = u64::from(u32::MAX);
        next.v2.v1.end_height = next.v2.v1.start_height;
        let before = format!("{history:?}");
        assert_eq!(history.append(next), Err(HistoryError::LeafCountOverflow));
        assert_eq!(format!("{history:?}"), before);
    }

    #[test]
    fn v3_owned_branch_guard_precedes_upstream_unchecked_combine() {
        let mut history = ChainHistoryV3::new(vector_leaf(&TEST_VECTORS[0])).unwrap();
        history.consensus_branch_id = NU62_BRANCH;
        let before = format!("{history:?}");
        assert_eq!(history.append(vector_leaf(&TEST_VECTORS[1])), Err(HistoryError::BranchMismatch));
        assert_eq!(format!("{history:?}"), before);
    }
}

#[cfg(test)]
#[path = "../tests/fixtures/history-v1-primary.rs"]
mod primary_vectors;

#[cfg(test)]
mod tests {
    use super::*;
    use primary_vectors::{TestVector, TEST_VECTORS};

    fn vector_leaf(vector: &TestVector) -> HistoryLeaf {
        HistoryLeaf {
            consensus_branch_id: vector.consensus_branch_id,
            subtree_commitment: vector.leaf_block_hash,
            start_time: vector.leaf_time,
            end_time: vector.leaf_time,
            start_target: vector.leaf_target_bits,
            end_target: vector.leaf_target_bits,
            start_sapling_root: vector.leaf_sapling_root,
            end_sapling_root: vector.leaf_sapling_root,
            subtree_total_work: U256::from_little_endian(&vector.leaf_work),
            start_height: vector.leaf_height,
            end_height: vector.leaf_height,
            sapling_tx: vector.leaf_sapling_tx_count,
        }
    }

    fn serialized(node: &HistoryLeaf) -> Vec<u8> {
        let mut bytes = Vec::new();
        V1::write(node, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn all_original_zip221_vectors_match_leaves_peaks_bagged_roots_and_hashes() {
        let mut history = None;
        for vector in TEST_VECTORS {
            let leaf = vector_leaf(vector);
            assert_eq!(serialized(&leaf), vector.leaf_serialized);
            let root = if let Some(history) = history.as_mut() {
                let history: &mut ChainHistoryV1 = history;
                history.append(leaf).unwrap()
            } else {
                let initial = ChainHistoryV1::new(leaf).unwrap();
                let root = initial.root();
                history = Some(initial);
                root
            };
            let history = history.as_ref().unwrap();
            assert_eq!(history.leaf_count(), vector.n_leaves);
            assert_eq!(history.peak_count, vector.peaks.len());
            for (peak, expected) in history.peaks[..history.peak_count].iter().zip(vector.peaks) {
                assert_eq!(serialized(peak.as_ref().unwrap()), *expected);
            }
            let bagged = history.bag_with(None);
            assert_eq!(serialized(&bagged), vector.root_serialized);
            assert_eq!(V1::hash(&bagged), vector.hash_chain_history_root);
            assert_eq!(root, vector.hash_chain_history_root);
            assert_eq!(history.root(), vector.hash_chain_history_root);
        }
        assert_eq!(history.unwrap().leaf_count(), 16);
    }

    #[test]
    fn invalid_leaf_metadata_is_rejected_before_initialization_or_append() {
        let first = vector_leaf(&TEST_VECTORS[0]);
        let next = vector_leaf(&TEST_VECTORS[1]);
        let mut malformed = Vec::new();
        let mut changed = next.clone();
        changed.consensus_branch_id = 0xc2d6_d0b4; // NU5 has V2 history, never V1.
        malformed.push((changed, HistoryError::UnsupportedBranch));
        let mut changed = next.clone();
        changed.end_height += 1;
        malformed.push((changed, HistoryError::MalformedLeaf));
        let mut changed = next.clone();
        changed.end_time ^= 1;
        malformed.push((changed, HistoryError::MalformedLeaf));
        let mut changed = next.clone();
        changed.end_target ^= 1;
        malformed.push((changed, HistoryError::MalformedLeaf));
        let mut changed = next.clone();
        changed.end_sapling_root[0] ^= 1;
        malformed.push((changed, HistoryError::MalformedLeaf));
        let mut changed = next.clone();
        changed.start_height = u64::from(u32::MAX) + 1;
        changed.end_height = changed.start_height;
        malformed.push((changed, HistoryError::HeightOutOfRange));
        let mut history = ChainHistoryV1::new(first).unwrap();
        let before = format!("{history:?}");
        for (leaf, error) in malformed {
            assert_eq!(ChainHistoryV1::new(leaf.clone()).unwrap_err(), error);
            assert_eq!(history.append(leaf).unwrap_err(), error);
            assert_eq!(format!("{history:?}"), before);
        }
        for height in [next.start_height - 1, next.start_height + 1, 0] {
            let mut changed = next.clone();
            changed.start_height = height;
            changed.end_height = height;
            assert_eq!(history.append(changed), Err(HistoryError::NonconsecutiveHeight));
            assert_eq!(format!("{history:?}"), before);
        }
        assert_eq!(history.append(next).unwrap(), TEST_VECTORS[1].hash_chain_history_root);
    }

    #[test]
    fn work_and_sapling_count_overflow_roll_back_merges_and_peak_bagging() {
        for prefix_length in [1, 2, 3] {
            for work_overflow in [true, false] {
                let mut leaves: Vec<_> = TEST_VECTORS[..=prefix_length].iter().map(vector_leaf).collect();
                if work_overflow {
                    leaves[0].subtree_total_work = U256::MAX;
                    for leaf in &mut leaves[1..prefix_length] {
                        leaf.subtree_total_work = U256::zero();
                    }
                    leaves[prefix_length].subtree_total_work = U256::from(1);
                } else {
                    leaves[0].sapling_tx = u64::MAX;
                    for leaf in &mut leaves[1..prefix_length] {
                        leaf.sapling_tx = 0;
                    }
                    leaves[prefix_length].sapling_tx = 1;
                }
                let mut history = ChainHistoryV1::new(leaves[0].clone()).unwrap();
                for leaf in &leaves[1..prefix_length] {
                    history.append(leaf.clone()).unwrap();
                }
                let before = format!("{history:?}");
                let expected = if work_overflow { HistoryError::WorkOverflow } else { HistoryError::SaplingCountOverflow };
                assert_eq!(history.append(leaves[prefix_length].clone()), Err(expected));
                assert_eq!(format!("{history:?}"), before);
                if work_overflow {
                    leaves[prefix_length].subtree_total_work = U256::zero();
                } else {
                    leaves[prefix_length].sapling_tx = 0;
                }
                history.append(leaves[prefix_length].clone()).unwrap();
                assert_eq!(history.leaf_count(), (prefix_length + 1) as u32);
            }
        }
    }

    #[test]
    fn maximum_height_cannot_wrap_and_zero_height_is_a_supported_metadata_boundary() {
        let mut first = vector_leaf(&TEST_VECTORS[0]);
        first.start_height = u64::from(u32::MAX) - 1;
        first.end_height = first.start_height;
        let mut next = first.clone();
        next.start_height += 1;
        next.end_height += 1;
        let mut history = ChainHistoryV1::new(first).unwrap();
        history.append(next.clone()).unwrap();
        let before = format!("{history:?}");
        next.start_height = 0;
        next.end_height = 0;
        assert_eq!(history.append(next.clone()), Err(HistoryError::HeightOverflow));
        assert_eq!(format!("{history:?}"), before);
        assert_eq!(ChainHistoryV1::new(next).unwrap().leaf_count(), 1);
    }

    #[test]
    fn saturated_leaf_counter_is_rejected_without_mutating_any_peak() {
        // Reach the otherwise impractical boundary using complete metadata peaks;
        // this is private test construction, not a public checkpoint import.
        let mut history = ChainHistoryV1::new(vector_leaf(&TEST_VECTORS[0])).unwrap();
        let mut start = 0u64;
        for (index, slot) in history.peaks.iter_mut().enumerate() {
            let mut peak = vector_leaf(&TEST_VECTORS[0]);
            let size = 1u64 << (31 - index);
            peak.start_height = start;
            peak.end_height = start + size - 1;
            start += size;
            *slot = Some(peak);
        }
        history.peak_count = 32;
        history.leaf_count = u32::MAX;
        history.last_height = u32::MAX - 1;
        history.total_work = U256::from_little_endian(&TEST_VECTORS[0].leaf_work) * U256::from(32);
        history.sapling_tx = 0;
        history.root = V1::hash(&history.bag_with(None));
        let mut next = vector_leaf(&TEST_VECTORS[0]);
        next.start_height = u64::from(u32::MAX);
        next.end_height = next.start_height;
        let before = format!("{history:?}");
        assert_eq!(history.append(next), Err(HistoryError::LeafCountOverflow));
        assert_eq!(format!("{history:?}"), before);
    }
}

#[cfg(test)]
mod canopy_tests {
    use super::*;

    fn leaf(height: u64) -> HistoryLeaf {
        HistoryLeaf {
            consensus_branch_id: CANOPY_BRANCH,
            subtree_commitment: [height as u8; 32],
            start_time: height as u32, end_time: height as u32,
            start_target: 0x2007_ffff, end_target: 0x2007_ffff,
            start_sapling_root: [3; 32], end_sapling_root: [3; 32],
            subtree_total_work: U256::from(32),
            start_height: height, end_height: height, sapling_tx: height % 3,
        }
    }

    #[test]
    fn canopy_v1_all_carries_and_left_to_right_peak_bags_match_the_upstream_tree() {
        use zcash_history::{Entry, Tree};
        let first = leaf(1_028_500);
        let mut history = ChainHistoryV1::new(first.clone()).unwrap();
        let mut original = Tree::<V1>::new(1, vec![(0, Entry::new_leaf(first))], vec![]);
        for height in 1_028_501..=1_028_516 {
            let next = leaf(height);
            original.append_leaf(next.clone()).unwrap();
            history.append(next).unwrap();
            assert_eq!(history.root(), V1::hash(original.root_node().unwrap().data()));
            assert_eq!(history.consensus_branch_id(), CANOPY_BRANCH);
            assert_eq!(history.last_height(), height as u32);
        }
        assert_eq!(history.leaf_count(), 17);
    }

    #[test]
    fn canopy_epoch_rejections_and_overflows_never_publish_a_partial_carry() {
        for prefix in [1, 2, 3, 7] {
            for work_overflow in [false, true] {
                let mut first = leaf(1_028_500);
                if work_overflow { first.subtree_total_work = U256::MAX; } else { first.sapling_tx = u64::MAX; }
                let mut history = ChainHistoryV1::new(first).unwrap();
                for height in 1_028_501..1_028_500 + prefix {
                    let mut next = leaf(height);
                    next.subtree_total_work = U256::zero();
                    next.sapling_tx = 0;
                    history.append(next).unwrap();
                }
                let before = format!("{history:?}");
                let mut next = leaf(1_028_500 + prefix);
                next.subtree_total_work = U256::from(1);
                next.sapling_tx = 1;
                assert_eq!(history.append(next.clone()), Err(if work_overflow { HistoryError::WorkOverflow } else { HistoryError::SaplingCountOverflow }));
                assert_eq!(format!("{history:?}"), before);
                next.subtree_total_work = U256::zero();
                next.sapling_tx = 0;
                history.append(next).unwrap();
                assert_eq!(history.leaf_count(), prefix as u32 + 1);
            }
        }
        let mut history = ChainHistoryV1::new(leaf(1_028_500)).unwrap();
        let before = format!("{history:?}");
        let mut heartwood = leaf(1_028_501);
        heartwood.consensus_branch_id = HEARTWOOD_BRANCH;
        assert_eq!(history.append(heartwood), Err(HistoryError::BranchMismatch));
        let mut nu5 = leaf(1_028_501);
        nu5.consensus_branch_id = 0xc2d6_d0b4;
        assert_eq!(history.append(nu5.clone()), Err(HistoryError::UnsupportedBranch));
        assert_eq!(ChainHistoryV1::new(nu5).unwrap_err(), HistoryError::UnsupportedBranch);
        assert_eq!(format!("{history:?}"), before);
        history.append(leaf(1_028_501)).unwrap();
    }
}

#[cfg(test)]
#[path = "../tests/fixtures/history-v2-primary.rs"]
mod primary_vectors_v2;

#[cfg(test)]
mod v2_tests {
    use super::*;
    use primary_vectors_v2::{TestVector, TEST_VECTORS};

    fn vector_leaf(vector: &TestVector) -> HistoryLeafV2 {
        HistoryLeafV2 {
            v1: HistoryLeaf {
                consensus_branch_id: vector.consensus_branch_id,
                subtree_commitment: vector.leaf_block_hash,
                start_time: vector.leaf_time,
                end_time: vector.leaf_time,
                start_target: vector.leaf_target_bits,
                end_target: vector.leaf_target_bits,
                start_sapling_root: vector.leaf_sapling_root,
                end_sapling_root: vector.leaf_sapling_root,
                subtree_total_work: U256::from_little_endian(&vector.leaf_work),
                start_height: vector.leaf_height,
                end_height: vector.leaf_height,
                sapling_tx: vector.leaf_sapling_tx_count,
            },
            start_orchard_root: vector.leaf_orchard_root,
            end_orchard_root: vector.leaf_orchard_root,
            orchard_tx: vector.leaf_orchard_tx_count,
        }
    }

    fn serialized(node: &HistoryLeafV2) -> Vec<u8> {
        let mut bytes = Vec::new();
        V2::write(node, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn all_original_v2_vectors_match_leaves_peaks_left_bagged_roots_and_hashes() {
        let mut history = None;
        for vector in TEST_VECTORS {
            let leaf = vector_leaf(vector);
            assert_eq!(serialized(&leaf), vector.leaf_serialized);
            let root = if let Some(history) = history.as_mut() {
                let history: &mut ChainHistoryV2 = history;
                history.append(leaf).unwrap()
            } else {
                let initial = ChainHistoryV2::new(leaf).unwrap();
                let root = initial.root();
                history = Some(initial);
                root
            };
            let history = history.as_ref().unwrap();
            assert_eq!(history.leaf_count(), vector.n_leaves);
            assert_eq!(history.consensus_branch_id(), vector.consensus_branch_id);
            assert_eq!(u64::from(history.last_height()), vector.leaf_height);
            assert_eq!(history.peak_count, vector.peaks.len());
            for (peak, expected) in history.peaks[..history.peak_count].iter().zip(vector.peaks) {
                assert_eq!(serialized(peak.as_ref().unwrap()), *expected);
            }
            assert!(history.peaks[history.peak_count..].iter().all(Option::is_none));
            let bagged = history.bag_with(None);
            assert_eq!(serialized(&bagged), vector.root_serialized);
            assert_eq!(V2::hash(&bagged), vector.hash_chain_history_root);
            assert_eq!(root, vector.hash_chain_history_root);
            assert_eq!(history.root(), vector.hash_chain_history_root);
        }
        assert_eq!(history.unwrap().leaf_count(), 16);
    }

    #[test]
    fn unsupported_branches_and_every_malformed_endpoint_leave_retry_rights_intact() {
        let next = vector_leaf(&TEST_VECTORS[1]);
        let mut rejected = Vec::new();
        for branch in [0, HEARTWOOD_BRANCH, CANOPY_BRANCH, 0xffff_ffff] {
            let mut changed = next.clone();
            changed.v1.consensus_branch_id = branch;
            rejected.push((changed, HistoryError::UnsupportedBranch));
        }
        let mut changed = next.clone();
        changed.v1.end_height += 1;
        rejected.push((changed, HistoryError::MalformedLeaf));
        let mut changed = next.clone();
        changed.v1.end_time ^= 1;
        rejected.push((changed, HistoryError::MalformedLeaf));
        let mut changed = next.clone();
        changed.v1.end_target ^= 1;
        rejected.push((changed, HistoryError::MalformedLeaf));
        let mut changed = next.clone();
        changed.v1.end_sapling_root[0] ^= 1;
        rejected.push((changed, HistoryError::MalformedLeaf));
        let mut changed = next.clone();
        changed.end_orchard_root[0] ^= 1;
        rejected.push((changed, HistoryError::MalformedLeaf));
        let mut changed = next.clone();
        changed.v1.start_height = u64::from(u32::MAX) + 1;
        changed.v1.end_height = changed.v1.start_height;
        rejected.push((changed, HistoryError::HeightOutOfRange));

        let mut history = ChainHistoryV2::new(vector_leaf(&TEST_VECTORS[0])).unwrap();
        let before = format!("{history:?}");
        for (leaf, error) in rejected {
            assert_eq!(ChainHistoryV2::new(leaf.clone()).unwrap_err(), error);
            assert_eq!(history.append(leaf), Err(error));
            assert_eq!(format!("{history:?}"), before);
        }
        for height in [0, next.v1.start_height - 1, next.v1.start_height + 1] {
            let mut changed = next.clone();
            changed.v1.start_height = height;
            changed.v1.end_height = height;
            assert_eq!(history.append(changed), Err(HistoryError::NonconsecutiveHeight));
            assert_eq!(format!("{history:?}"), before);
        }
        assert_eq!(history.append(next).unwrap(), TEST_VECTORS[1].hash_chain_history_root);
    }

    #[test]
    fn checked_work_sapling_and_orchard_totals_precede_all_carries_and_bags() {
        for prefix in [1, 2, 3, 7] {
            for dimension in 0..3 {
                let mut leaves: Vec<_> = TEST_VECTORS[..=prefix].iter().map(vector_leaf).collect();
                let expected = match dimension {
                    0 => {
                        leaves[0].v1.subtree_total_work = U256::MAX;
                        for leaf in &mut leaves[1..prefix] {
                            leaf.v1.subtree_total_work = U256::zero();
                        }
                        leaves[prefix].v1.subtree_total_work = U256::one();
                        HistoryError::WorkOverflow
                    }
                    1 => {
                        leaves[0].v1.sapling_tx = u64::MAX;
                        for leaf in &mut leaves[1..prefix] {
                            leaf.v1.sapling_tx = 0;
                        }
                        leaves[prefix].v1.sapling_tx = 1;
                        HistoryError::SaplingCountOverflow
                    }
                    _ => {
                        leaves[0].orchard_tx = u64::MAX;
                        for leaf in &mut leaves[1..prefix] {
                            leaf.orchard_tx = 0;
                        }
                        leaves[prefix].orchard_tx = 1;
                        HistoryError::OrchardCountOverflow
                    }
                };
                let mut history = ChainHistoryV2::new(leaves[0].clone()).unwrap();
                for leaf in &leaves[1..prefix] {
                    history.append(leaf.clone()).unwrap();
                }
                let before = format!("{history:?}");
                assert_eq!(history.append(leaves[prefix].clone()), Err(expected));
                assert_eq!(format!("{history:?}"), before);
                match dimension {
                    0 => leaves[prefix].v1.subtree_total_work = U256::zero(),
                    1 => leaves[prefix].v1.sapling_tx = 0,
                    _ => leaves[prefix].orchard_tx = 0,
                }
                history.append(leaves[prefix].clone()).unwrap();
                assert_eq!(history.leaf_count(), prefix as u32 + 1);
            }
        }
    }

    #[test]
    fn zero_height_and_maximum_height_preserve_metadata_only_boundaries() {
        let mut first = vector_leaf(&TEST_VECTORS[0]);
        first.v1.start_height = u64::from(u32::MAX) - 1;
        first.v1.end_height = first.v1.start_height;
        let mut next = first.clone();
        next.v1.start_height += 1;
        next.v1.end_height += 1;
        let mut history = ChainHistoryV2::new(first).unwrap();
        history.append(next.clone()).unwrap();
        let before = format!("{history:?}");
        next.v1.start_height = 0;
        next.v1.end_height = 0;
        assert_eq!(history.append(next.clone()), Err(HistoryError::HeightOverflow));
        assert_eq!(format!("{history:?}"), before);
        let mut zero = ChainHistoryV2::new(next.clone()).unwrap();
        assert_eq!(zero.last_height(), 0);
        next.v1.start_height = 1;
        next.v1.end_height = 1;
        zero.append(next).unwrap();
        assert_eq!(zero.leaf_count(), 2);
    }

    #[test]
    fn saturated_leaf_count_rejects_a_thirty_third_peak_before_mutation() {
        // Private construction reaches an impractical boundary without exposing
        // checkpoint import or retaining historical/generated nodes.
        let first = vector_leaf(&TEST_VECTORS[0]);
        let mut history = ChainHistoryV2::new(first.clone()).unwrap();
        let mut start = 0u64;
        for (index, slot) in history.peaks.iter_mut().enumerate() {
            let mut peak = first.clone();
            let size = 1u64 << (31 - index);
            peak.v1.start_height = start;
            peak.v1.end_height = start + size - 1;
            start += size;
            *slot = Some(peak);
        }
        history.peak_count = 32;
        history.leaf_count = u32::MAX;
        history.last_height = u32::MAX - 1;
        history.total_work = first.v1.subtree_total_work * U256::from(32);
        history.sapling_tx = first.v1.sapling_tx * 32;
        history.orchard_tx = first.orchard_tx * 32;
        history.root = V2::hash(&history.bag_with(None));
        let mut next = first;
        next.v1.start_height = u64::from(u32::MAX);
        next.v1.end_height = next.v1.start_height;
        let before = format!("{history:?}");
        assert_eq!(history.append(next), Err(HistoryError::LeafCountOverflow));
        assert_eq!(format!("{history:?}"), before);
    }

    #[test]
    fn branch_guard_precedes_upstream_combine_and_clone_staging_is_independent() {
        let mut history = ChainHistoryV2::new(vector_leaf(&TEST_VECTORS[0])).unwrap();
        for vector in &TEST_VECTORS[1..7] {
            history.append(vector_leaf(vector)).unwrap();
        }
        let before = format!("{history:?}");
        let next = vector_leaf(&TEST_VECTORS[7]);
        let mut staged = history.clone();
        staged.consensus_branch_id = CANOPY_BRANCH;
        let staged_before = format!("{staged:?}");
        assert_eq!(staged.append(next.clone()), Err(HistoryError::BranchMismatch));
        assert_eq!(format!("{staged:?}"), staged_before);
        assert_eq!(format!("{history:?}"), before);

        let mut staged = history.clone();
        staged.append(next.clone()).unwrap();
        assert_eq!(staged.root(), TEST_VECTORS[7].hash_chain_history_root);
        assert_eq!(format!("{history:?}"), before);
        let staged_before = format!("{staged:?}");
        let mut changed = next;
        changed.v1.subtree_commitment[0] ^= 1;
        history.append(changed).unwrap();
        assert_ne!(history.root(), staged.root());
        assert_eq!(format!("{staged:?}"), staged_before);
    }

    #[test]
    fn nu6_v2_is_explicit_height_independent_metadata_and_never_resets_on_append() {
        for height in [0, 2_976_000, 3_536_499, 3_536_500] {
            let mut first = vector_leaf(&TEST_VECTORS[0]);
            first.v1.consensus_branch_id = 0xc8e7_1055;
            first.v1.start_height = height;
            first.v1.end_height = height;
            let mut history = ChainHistoryV2::new(first.clone()).unwrap();
            assert_eq!(history.root(), V2::hash(&first));
            let mut next = first.clone();
            next.v1.start_height += 1;
            next.v1.end_height += 1;
            next.v1.subtree_commitment[0] ^= 1;
            let before = format!("{history:?}");
            let mut wrong = next.clone();
            wrong.v1.consensus_branch_id = 0xc2d6_d0b4;
            assert_eq!(history.append(wrong), Err(HistoryError::BranchMismatch));
            assert_eq!(format!("{history:?}"), before);
            assert_eq!(history.append(next.clone()).unwrap(), V2::hash(&V2::combine(&first, &next)));
            assert_eq!(history.consensus_branch_id(), 0xc8e7_1055);
            assert_eq!(history.leaf_count(), 2);
        }
    }
}
