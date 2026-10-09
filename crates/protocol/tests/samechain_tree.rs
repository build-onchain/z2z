use sha2::{Digest, Sha256};
use ziquid_protocol::samechain::tree::{
    NoteHash, NoteTree, TreeError, empty_leaf_hash, leaf_hash, node_hash, root_from_path,
};

const DEPLOYMENT: NoteHash = [7; 32];
const TREE_ID: u32 = 0x0102_0304;

// Deliberately assemble literal version/domain bytes without production helpers.
fn expected_leaf(deployment: &NoteHash, tree_id: u32, index: u32, commitment: &NoteHash) -> NoteHash {
    Sha256::digest([
        b"Z2Z_SAMECHAIN_MERKLE_LEAF\0".as_slice(), &[0, 1], deployment,
        &tree_id.to_be_bytes(), &index.to_be_bytes(), commitment,
    ].concat()).into()
}

fn expected_node(left: &NoteHash, right: &NoteHash) -> NoteHash {
    Sha256::digest([
        b"Z2Z_SAMECHAIN_MERKLE_NODE\0".as_slice(), &[0, 1], left, right,
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

// Independent top-down sparse recomputation: no frontier or append algorithm.
fn subtree(
    deployment: &NoteHash, tree_id: u32, commitments: &[NoteHash],
    start: u64, height: usize, empty: &[NoteHash; 33],
) -> NoteHash {
    if start >= commitments.len() as u64 { return empty[height]; }
    if height == 0 {
        return expected_leaf(deployment, tree_id, start as u32, &commitments[start as usize]);
    }
    let half = 1u64 << (height - 1);
    expected_node(
        &subtree(deployment, tree_id, commitments, start, height - 1, empty),
        &subtree(deployment, tree_id, commitments, start + half, height - 1, empty),
    )
}

#[test]
fn sequential_appends_match_independent_sparse_roots_and_every_insertion_sibling() {
    let empty = expected_empty();
    let mut tree = NoteTree::new(DEPLOYMENT, TREE_ID).unwrap();
    assert_eq!(tree.root(), empty[32]);
    let mut commitments = Vec::new();
    let mut retained = Vec::new();
    for index in 0..17u32 {
        let commitment = [index as u8 + 1; 32];
        commitments.push(commitment);
        let insertion = tree.append(commitment).unwrap();
        let expected_root = subtree(&DEPLOYMENT, TREE_ID, &commitments, 0, 32, &empty);
        let expected_siblings = std::array::from_fn(|height| {
            let sibling_start = ((u64::from(index) >> height) ^ 1) << height;
            subtree(&DEPLOYMENT, TREE_ID, &commitments, sibling_start, height, &empty)
        });
        assert_eq!(insertion.tree_id, TREE_ID);
        assert_eq!(insertion.index, index);
        assert_eq!(insertion.count, u64::from(index) + 1);
        assert_eq!(insertion.root, expected_root);
        assert_eq!(insertion.siblings, expected_siblings);
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.count(), u64::from(index) + 1);
        assert_eq!(tree.deployment(), DEPLOYMENT);
        assert_eq!(tree.tree_id(), TREE_ID);
        retained.push((commitment, insertion));
    }
    // Later appends cannot change the already captured historical insertion path.
    for (commitment, insertion) in retained {
        assert_eq!(root_from_path(
            &DEPLOYMENT, insertion.tree_id, insertion.index, &commitment, &insertion.siblings,
        ), insertion.root);
    }
}

#[test]
fn literal_hash_framing_and_high_index_bits_match_independent_sha256() {
    let commitment = [9; 32];
    let index = 0x8040_0205;
    let expected = expected_leaf(&DEPLOYMENT, TREE_ID, index, &commitment);
    assert_eq!(leaf_hash(&DEPLOYMENT, TREE_ID, index, &commitment), expected);
    assert_eq!(empty_leaf_hash(), expected_empty()[0]);
    assert_ne!(empty_leaf_hash(), expected_leaf(&[0; 32], 0, 0, &[0; 32]));
    assert_eq!(node_hash(&[1; 32], &[2; 32]), expected_node(&[1; 32], &[2; 32]));
    assert_ne!(node_hash(&[1; 32], &[2; 32]), node_hash(&[2; 32], &[1; 32]));

    let siblings: [NoteHash; 32] = std::array::from_fn(|height| [height as u8 + 32; 32]);
    // Fold from the top down recursively, rather than using the production loop.
    fn expected_path(index: u32, leaf: NoteHash, siblings: &[NoteHash; 32], height: usize) -> NoteHash {
        if height == 0 { return leaf; }
        let child = expected_path(index, leaf, siblings, height - 1);
        if index & (1 << (height - 1)) == 0 {
            expected_node(&child, &siblings[height - 1])
        } else {
            expected_node(&siblings[height - 1], &child)
        }
    }
    let root = expected_path(index, expected, &siblings, 32);
    assert_eq!(root_from_path(&DEPLOYMENT, TREE_ID, index, &commitment, &siblings), root);
    for (deployment, tree_id, leaf_index, note) in [
        ([8; 32], TREE_ID, index, commitment),
        (DEPLOYMENT, TREE_ID + 1, index, commitment),
        (DEPLOYMENT, TREE_ID, index ^ (1 << 31), commitment),
        (DEPLOYMENT, TREE_ID, index ^ 1, commitment),
        (DEPLOYMENT, TREE_ID, index, [10; 32]),
    ] {
        assert_ne!(leaf_hash(&deployment, tree_id, leaf_index, &note), expected);
        assert_ne!(root_from_path(&deployment, tree_id, leaf_index, &note, &siblings), root);
    }
    let mut changed_siblings = siblings;
    changed_siblings[31][0] ^= 1;
    assert_ne!(root_from_path(&DEPLOYMENT, TREE_ID, index, &commitment, &changed_siblings), root);
}

#[test]
fn invalid_inputs_and_premature_rollover_leave_the_complete_tree_unchanged() {
    assert_eq!(NoteTree::new([0; 32], TREE_ID), Err(TreeError::InvalidDeployment));
    let mut tree = NoteTree::new(DEPLOYMENT, TREE_ID).unwrap();
    for count in 0..3 {
        let before = tree.clone();
        assert_eq!(tree.append([0; 32]), Err(TreeError::InvalidCommitment));
        assert_eq!(tree, before);
        assert_eq!(tree.rollover(), Err(TreeError::NotFull));
        assert_eq!(tree, before);
        assert_eq!(tree.count(), count);
        tree.append([count as u8 + 1; 32]).unwrap();
    }
}
