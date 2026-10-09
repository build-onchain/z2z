//! Deterministic depth-32 commitment-tree arithmetic and insertion paths.
//!
//! These hashes authenticate no note opening, financial proof, backing, admitted
//! root, spentness, ciphertext/recovery metadata or chain event. The caller/target
//! must retain historical roots and complete output data; this accumulator does
//! not store them. Rollover is explicit and does not admit the new tree's root.

use super::{RELATION_VERSION, is_zero};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

pub type NoteHash = [u8; 32];
pub const TREE_DEPTH: usize = 32;
pub const TREE_CAPACITY: u64 = 1u64 << TREE_DEPTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeError {
    InvalidDeployment,
    InvalidCommitment,
    NotFull,
    Full,
    Exhausted,
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDeployment => "invalid note-tree deployment",
            Self::InvalidCommitment => "invalid note-tree commitment",
            Self::NotFull => "note tree is not full",
            Self::Full => "note tree is full",
            Self::Exhausted => "note-tree identifiers exhausted",
        })
    }
}

impl Error for TreeError {}

/// Context-bound real leaf; the index and tree identifier use big-endian bytes.
pub fn leaf_hash(
    deployment: &NoteHash, tree_id: u32, index: u32, commitment: &NoteHash,
) -> NoteHash {
    let mut hash = Sha256::new();
    hash.update(b"Z2Z_SAMECHAIN_MERKLE_LEAF\0");
    hash.update(RELATION_VERSION.to_be_bytes());
    hash.update(deployment);
    hash.update(tree_id.to_be_bytes());
    hash.update(index.to_be_bytes());
    hash.update(commitment);
    hash.finalize().into()
}

/// Ordered node hash, deliberately independent of deployment, tree and height.
pub fn node_hash(left: &NoteHash, right: &NoteHash) -> NoteHash {
    let mut hash = Sha256::new();
    hash.update(b"Z2Z_SAMECHAIN_MERKLE_NODE\0");
    hash.update(RELATION_VERSION.to_be_bytes());
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

/// Domain-separated empty leaf, not a real leaf with a zero commitment.
pub fn empty_leaf_hash() -> NoteHash {
    let mut hash = Sha256::new();
    hash.update(b"Z2Z_SAMECHAIN_MERKLE_EMPTY\0");
    hash.update(RELATION_VERSION.to_be_bytes());
    hash.finalize().into()
}

/// Reconstructs a mathematical root using leaf-to-root, LSB-first siblings.
/// It does not establish that the root is eligible at an asset authority.
pub fn root_from_path(
    deployment: &NoteHash, tree_id: u32, index: u32, commitment: &NoteHash,
    siblings: &[NoteHash; TREE_DEPTH],
) -> NoteHash {
    let mut current = leaf_hash(deployment, tree_id, index, commitment);
    for (height, sibling) in siblings.iter().enumerate() {
        current = if (index >> height) & 1 == 0 {
            node_hash(&current, sibling)
        } else {
            node_hash(sibling, &current)
        };
    }
    current
}

/// Public commitment-tree state, with mutation restricted to append/rollover.
/// Cached empty subtrees are computed only when this tree is constructed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteTree {
    deployment: NoteHash,
    tree_id: u32,
    count: u64,
    frontier: [NoteHash; TREE_DEPTH],
    root: NoteHash,
    empty: [NoteHash; TREE_DEPTH + 1],
}

/// Path to the historical root immediately after insertion, not proof admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteInsertion {
    pub tree_id: u32,
    pub index: u32,
    pub count: u64,
    pub root: NoteHash,
    pub siblings: [NoteHash; TREE_DEPTH],
}

impl NoteTree {
    pub fn new(deployment: NoteHash, tree_id: u32) -> Result<Self, TreeError> {
        if is_zero(&deployment) { return Err(TreeError::InvalidDeployment); }
        let mut empty = [[0; 32]; TREE_DEPTH + 1];
        empty[0] = empty_leaf_hash();
        for height in 1..=TREE_DEPTH {
            empty[height] = node_hash(&empty[height - 1], &empty[height - 1]);
        }
        Ok(Self {
            deployment, tree_id, count: 0, frontier: [[0; 32]; TREE_DEPTH],
            root: empty[TREE_DEPTH], empty,
        })
    }

    pub fn deployment(&self) -> NoteHash { self.deployment }
    pub fn tree_id(&self) -> u32 { self.tree_id }
    pub fn count(&self) -> u64 { self.count }
    pub fn root(&self) -> NoteHash { self.root }

    /// Appends without allocation or recomputing empty defaults. All fallible
    /// checks precede mutation, including the full tree's unrepresentable index.
    pub fn append(&mut self, commitment: NoteHash) -> Result<NoteInsertion, TreeError> {
        if is_zero(&commitment) { return Err(TreeError::InvalidCommitment); }
        if self.count >= TREE_CAPACITY { return Err(TreeError::Full); }
        let index = u32::try_from(self.count).map_err(|_| TreeError::Full)?;
        let mut current = leaf_hash(&self.deployment, self.tree_id, index, &commitment);
        let mut siblings = [[0; 32]; TREE_DEPTH];
        for (height, sibling) in siblings.iter_mut().enumerate() {
            if (index >> height) & 1 == 0 {
                *sibling = self.empty[height];
                self.frontier[height] = current;
                current = node_hash(&current, sibling);
            } else {
                *sibling = self.frontier[height];
                current = node_hash(sibling, &current);
            }
        }
        self.count += 1;
        self.root = current;
        Ok(NoteInsertion {
            tree_id: self.tree_id, index, count: self.count, root: current, siblings,
        })
    }

    /// Starts the next tree only after exactly 2^32 insertions. Historical paths
    /// and roots remain the caller's responsibility, including the final tree.
    pub fn rollover(&mut self) -> Result<(), TreeError> {
        if self.count != TREE_CAPACITY { return Err(TreeError::NotFull); }
        let tree_id = self.tree_id.checked_add(1).ok_or(TreeError::Exhausted)?;
        self.tree_id = tree_id;
        self.count = 0;
        self.frontier = [[0; 32]; TREE_DEPTH];
        self.root = self.empty[TREE_DEPTH];
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_node(left: &NoteHash, right: &NoteHash) -> NoteHash {
        Sha256::digest([
            b"Z2Z_SAMECHAIN_MERKLE_NODE\0".as_slice(), &[0, 1], left, right,
        ].concat()).into()
    }

    fn expected_leaf(deployment: &NoteHash, tree_id: u32, index: u32, note: &NoteHash) -> NoteHash {
        Sha256::digest([
            b"Z2Z_SAMECHAIN_MERKLE_LEAF\0".as_slice(), &[0, 1], deployment,
            &tree_id.to_be_bytes(), &index.to_be_bytes(), note,
        ].concat()).into()
    }

    fn expected_empty() -> [NoteHash; 33] {
        let mut empty = [[0; 32]; 33];
        empty[0] = Sha256::digest(b"Z2Z_SAMECHAIN_MERKLE_EMPTY\0\0\x01").into();
        for height in 1..=32 {
            empty[height] = expected_node(&empty[height - 1], &empty[height - 1]);
        }
        empty
    }

    // Collapsed perfect subtrees of synthetic leaf digests, not note openings or
    // publicly constructible/admitted state. No billions-of-leaves allocation.
    struct Block { start: u64, height: usize, root: NoteHash }

    fn sparse_root(blocks: &[Block], start: u64, height: usize, empty: &[NoteHash; 33]) -> NoteHash {
        if let Some(block) = blocks.iter().find(|block| block.start == start && block.height == height) {
            return block.root;
        }
        let end = start + (1u64 << height);
        if !blocks.iter().any(|block| block.start >= start && block.start < end) {
            return empty[height];
        }
        assert!(height > 0, "occupied leaf must have a supplied digest");
        let half = 1u64 << (height - 1);
        expected_node(
            &sparse_root(blocks, start, height - 1, empty),
            &sparse_root(blocks, start + half, height - 1, empty),
        )
    }

    fn seeded(count: u64, tree_id: u32) -> (NoteTree, Vec<Block>) {
        assert!(count < (1u64 << 32));
        let empty = expected_empty();
        let mut tree = NoteTree::new([7; 32], tree_id).unwrap();
        let mut blocks = Vec::new();
        let mut start = 0;
        for height in (0..32).rev() {
            if count & (1u64 << height) == 0 { continue; }
            let mut root: NoteHash = Sha256::digest([height as u8 + 1; 32]).into();
            for _ in 0..height { root = expected_node(&root, &root); }
            tree.frontier[height] = root;
            blocks.push(Block { start, height, root });
            start += 1u64 << height;
        }
        assert_eq!(start, count);
        tree.count = count;
        tree.root = sparse_root(&blocks, 0, 32, &empty);
        (tree, blocks)
    }

    fn append_and_compare(tree: &mut NoteTree, blocks: &mut Vec<Block>, note: NoteHash) -> NoteInsertion {
        let index = u32::try_from(tree.count()).unwrap();
        let empty = expected_empty();
        blocks.push(Block {
            start: u64::from(index), height: 0,
            root: expected_leaf(&tree.deployment(), tree.tree_id(), index, &note),
        });
        let expected_root = sparse_root(blocks, 0, 32, &empty);
        let expected_siblings = std::array::from_fn(|height| {
            let start = ((u64::from(index) >> height) ^ 1) << height;
            sparse_root(blocks, start, height, &empty)
        });
        let insertion = tree.append(note).unwrap();
        assert_eq!(insertion.index, index);
        assert_eq!(insertion.count, u64::from(index) + 1);
        assert_eq!(insertion.root, expected_root);
        assert_eq!(insertion.siblings, expected_siblings);
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.count(), u64::from(index) + 1);
        insertion
    }

    #[test]
    fn mixed_high_carry_preserves_every_sibling_and_following_frontier() {
        for count in [0x7fff_ffff, 0x89ab_ffff] {
            let (mut tree, mut blocks) = seeded(count, 9);
            for note in [[1; 32], [2; 32], [3; 32]] {
                append_and_compare(&mut tree, &mut blocks, note);
            }
        }
    }

    #[test]
    fn last_u32_index_reaches_u64_capacity_then_requires_explicit_rollover() {
        let (mut tree, mut blocks) = seeded(u64::from(u32::MAX), 9);
        let note = [8; 32];
        let insertion = append_and_compare(&mut tree, &mut blocks, note);
        assert_eq!(insertion.index, u32::MAX);
        assert_eq!(insertion.count, 1u64 << 32);
        let full = tree.clone();
        assert_eq!(tree.append([9; 32]), Err(TreeError::Full));
        assert_eq!(tree, full);
        assert_eq!(tree.append([0; 32]), Err(TreeError::InvalidCommitment));
        assert_eq!(tree, full);
        tree.rollover().unwrap();
        assert_eq!(tree.deployment(), full.deployment());
        assert_eq!(tree.tree_id(), 10);
        assert_eq!(tree.count(), 0);
        assert_eq!(tree.root(), expected_empty()[32]);
        assert_eq!(tree.empty, full.empty);
        let mut next_blocks = Vec::new();
        let next = append_and_compare(&mut tree, &mut next_blocks, note);
        assert_eq!(next.index, 0);
        assert_eq!(next.tree_id, 10);
        let mut previous_tree = NoteTree::new(full.deployment(), 9).unwrap();
        assert_ne!(next.root, previous_tree.append(note).unwrap().root);
        assert_eq!(root_from_path(
            &full.deployment(), insertion.tree_id, insertion.index, &note, &insertion.siblings,
        ), full.root());
    }

    #[test]
    fn final_identifier_accepts_last_leaf_but_never_wraps_or_changes_on_failure() {
        let (mut tree, mut blocks) = seeded(u64::from(u32::MAX), u32::MAX);
        let before = tree.clone();
        assert_eq!(tree.rollover(), Err(TreeError::NotFull));
        assert_eq!(tree, before);
        let insertion = append_and_compare(&mut tree, &mut blocks, [11; 32]);
        assert_eq!(insertion.tree_id, u32::MAX);
        assert_eq!(insertion.index, u32::MAX);
        assert_eq!(insertion.count, 1u64 << 32);
        let full = tree.clone();
        for _ in 0..2 {
            assert_eq!(tree.rollover(), Err(TreeError::Exhausted));
            assert_eq!(tree, full);
            assert_eq!(tree.append([12; 32]), Err(TreeError::Full));
            assert_eq!(tree, full);
        }
    }
}
