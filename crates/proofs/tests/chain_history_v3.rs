//! V3 metadata is not authenticated source history.
use primitive_types::U256;
use zcash_history::{V3, Version};
use ziquid_proofs::chain_history::{ChainHistoryV3, HistoryError, HistoryLeaf, HistoryLeafV2, HistoryLeafV3};

#[path = "fixtures/history-v3-primary.rs"]
mod primary_vectors;
use primary_vectors::{TestVector, TEST_VECTORS};

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

#[test]
fn sixteen_primary_roots_match_public_consecutive_append() {
    let mut history = ChainHistoryV3::new(vector_leaf(&TEST_VECTORS[0])).unwrap();
    for vector in TEST_VECTORS {
        if vector.n_leaves > 1 {
            assert_eq!(history.append(vector_leaf(vector)).unwrap(), vector.hash_chain_history_root);
        }
        assert_eq!(history.root(), vector.hash_chain_history_root);
        assert_eq!(history.leaf_count(), vector.n_leaves);
        assert_eq!(history.consensus_branch_id(), vector.consensus_branch_id);
        assert_eq!(u64::from(history.last_height()), vector.leaf_height);
        let mut bytes = Vec::new();
        V3::write(&vector_leaf(vector), &mut bytes).unwrap();
        assert_eq!(bytes, vector.leaf_serialized);
        // Full owned peak/root serialization is exercised by the private oracle.
        let oracle_root = V3::from_bytes(vector.consensus_branch_id, vector.root_serialized).unwrap();
        assert_eq!(history.root(), V3::hash(&oracle_root));
        let peak_leaf_count: u64 = vector.peaks.iter().map(|bytes| {
            let peak = V3::from_bytes(vector.consensus_branch_id, bytes).unwrap();
            peak.v2.v1.end_height - peak.v2.v1.start_height + 1
        }).sum();
        assert_eq!(peak_leaf_count, u64::from(history.leaf_count()));
    }
}

#[test]
fn v3_owned_epoch_hashes_actual_ironwood_fields_and_appends_consecutive_leaf() {
    let mut leaf = vector_leaf(&TEST_VECTORS[0]);
    leaf.v2.v1.start_height = 4_134_000;
    leaf.v2.v1.end_height = 4_134_000;
    let mut history = ChainHistoryV3::new(leaf.clone()).unwrap();
    assert_eq!(history.root(), V3::hash(&leaf));
    let mut next = leaf.clone();
    next.v2.v1.start_height += 1;
    next.v2.v1.end_height += 1;
    next.start_ironwood_root = [6; 32];
    next.end_ironwood_root = [6; 32];
    assert_eq!(history.append(next.clone()).unwrap(), V3::hash(&V3::combine(&leaf, &next)));
    assert_eq!(history.last_height(), 4_134_001);

    for dimension in 0..2 {
        let mut changed = vector_leaf(&TEST_VECTORS[1]);
        if dimension == 0 {
            changed.start_ironwood_root[0] ^= 1;
            changed.end_ironwood_root = changed.start_ironwood_root;
        } else {
            changed.ironwood_tx += 1;
        }
        let mut changed_history = ChainHistoryV3::new(vector_leaf(&TEST_VECTORS[0])).unwrap();
        assert_ne!(changed_history.append(changed).unwrap(), TEST_VECTORS[1].hash_chain_history_root);
    }
}

#[test]
fn every_version_endpoint_and_wrong_branch_reject_atomically_then_retry() {
    let next = vector_leaf(&TEST_VECTORS[1]);
    let mut rejected = Vec::new();
    for branch in [0, 0xf5b9_230b, 0xe9ff_75a6, 0xc2d6_d0b4, 0xc8e7_1055, 0x4dec_4df0, 0x5437_f330, 0xffff_ffff] {
        let mut changed = next.clone();
        changed.v2.v1.consensus_branch_id = branch;
        rejected.push((changed, HistoryError::UnsupportedBranch));
    }
    let mut changed = next.clone();
    changed.v2.v1.end_height += 1;
    rejected.push((changed, HistoryError::MalformedLeaf));
    let mut changed = next.clone();
    changed.v2.v1.end_time ^= 1;
    rejected.push((changed, HistoryError::MalformedLeaf));
    let mut changed = next.clone();
    changed.v2.v1.end_target ^= 1;
    rejected.push((changed, HistoryError::MalformedLeaf));
    let mut changed = next.clone();
    changed.v2.v1.end_sapling_root[0] ^= 1;
    rejected.push((changed, HistoryError::MalformedLeaf));
    let mut changed = next.clone();
    changed.v2.end_orchard_root[0] ^= 1;
    rejected.push((changed, HistoryError::MalformedLeaf));
    let mut changed = next.clone();
    changed.end_ironwood_root[0] ^= 1;
    rejected.push((changed, HistoryError::MalformedLeaf));
    let mut changed = next.clone();
    changed.v2.v1.start_height = u64::from(u32::MAX) + 1;
    changed.v2.v1.end_height = changed.v2.v1.start_height;
    rejected.push((changed, HistoryError::HeightOutOfRange));

    let mut history = ChainHistoryV3::new(vector_leaf(&TEST_VECTORS[0])).unwrap();
    let before = format!("{history:?}");
    for (leaf, error) in rejected {
        assert_eq!(ChainHistoryV3::new(leaf.clone()).unwrap_err(), error);
        assert_eq!(history.append(leaf), Err(error));
        assert_eq!(format!("{history:?}"), before);
    }
    for height in [0, next.v2.v1.start_height - 1, next.v2.v1.start_height + 1] {
        let mut changed = next.clone();
        changed.v2.v1.start_height = height;
        changed.v2.v1.end_height = height;
        assert_eq!(history.append(changed), Err(HistoryError::NonconsecutiveHeight));
        assert_eq!(format!("{history:?}"), before);
    }
    assert_eq!(history.append(next).unwrap(), TEST_VECTORS[1].hash_chain_history_root);
}

#[test]
fn checked_work_and_all_three_pool_counts_precede_carries_and_bags() {
    for prefix in [1, 2, 3, 7] {
        for dimension in 0..4 {
            let mut leaves: Vec<_> = TEST_VECTORS[..=prefix].iter().map(vector_leaf).collect();
            for (index, leaf) in leaves.iter_mut().enumerate() {
                let count = if index == 0 { u64::MAX } else { u64::from(index == prefix) };
                match dimension {
                    0 => leaf.v2.v1.subtree_total_work = if index == 0 { U256::MAX } else { U256::from(count) },
                    1 => leaf.v2.v1.sapling_tx = count,
                    2 => leaf.v2.orchard_tx = count,
                    _ => leaf.ironwood_tx = count,
                }
            }
            let error = match dimension {
                0 => HistoryError::WorkOverflow,
                1 => HistoryError::SaplingCountOverflow,
                2 => HistoryError::OrchardCountOverflow,
                _ => HistoryError::IronwoodCountOverflow,
            };
            let mut history = ChainHistoryV3::new(leaves[0].clone()).unwrap();
            for leaf in &leaves[1..prefix] {
                history.append(leaf.clone()).unwrap();
            }
            let before = format!("{history:?}");
            assert_eq!(history.append(leaves[prefix].clone()), Err(error));
            assert_eq!(format!("{history:?}"), before);
            match dimension {
                0 => leaves[prefix].v2.v1.subtree_total_work = U256::zero(),
                1 => leaves[prefix].v2.v1.sapling_tx = 0,
                2 => leaves[prefix].v2.orchard_tx = 0,
                _ => leaves[prefix].ironwood_tx = 0,
            }
            history.append(leaves[prefix].clone()).unwrap();
            assert_eq!(history.leaf_count(), prefix as u32 + 1);
        }
    }
}

#[test]
fn nu63_metadata_is_height_independent_and_height_overflow_is_atomic() {
    for height in [0, 3_500_000, 4_134_000, 4_465_026, u64::from(u32::MAX) - 1] {
        let mut first = vector_leaf(&TEST_VECTORS[0]);
        first.v2.v1.start_height = height;
        first.v2.v1.end_height = height;
        let mut history = ChainHistoryV3::new(first.clone()).unwrap();
        assert_eq!(history.root(), V3::hash(&first));
        let mut next = first.clone();
        next.v2.v1.start_height += 1;
        next.v2.v1.end_height += 1;
        history.append(next.clone()).unwrap();
        assert_eq!(history.consensus_branch_id(), 0x37a5_165b);
        assert_eq!(history.leaf_count(), 2);
        if height == u64::from(u32::MAX) - 1 {
            let before = format!("{history:?}");
            next.v2.v1.start_height = 0;
            next.v2.v1.end_height = 0;
            assert_eq!(history.append(next), Err(HistoryError::HeightOverflow));
            assert_eq!(format!("{history:?}"), before);
        }
    }
}

#[test]
fn clone_staging_is_independent_across_failed_append_retry_and_carry() {
    let mut history = ChainHistoryV3::new(vector_leaf(&TEST_VECTORS[0])).unwrap();
    for vector in &TEST_VECTORS[1..7] {
        history.append(vector_leaf(vector)).unwrap();
    }
    let before = format!("{history:?}");
    let mut staged = history.clone();
    let mut wrong = vector_leaf(&TEST_VECTORS[7]);
    wrong.v2.v1.consensus_branch_id = 0x5437_f330;
    assert_eq!(staged.append(wrong), Err(HistoryError::UnsupportedBranch));
    assert_eq!(format!("{staged:?}"), before);
    staged.append(vector_leaf(&TEST_VECTORS[7])).unwrap();
    assert_eq!(staged.root(), TEST_VECTORS[7].hash_chain_history_root);
    assert_eq!(format!("{history:?}"), before);
    let staged_before = format!("{staged:?}");
    let mut changed = vector_leaf(&TEST_VECTORS[7]);
    changed.v2.v1.subtree_commitment[0] ^= 1;
    history.append(changed).unwrap();
    assert_ne!(history.root(), staged.root());
    assert_eq!(format!("{staged:?}"), staged_before);
}
