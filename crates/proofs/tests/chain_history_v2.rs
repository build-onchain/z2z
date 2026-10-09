use primitive_types::U256;
use sha2::{Digest, Sha256};
use zcash_history::{V2, Version};
use ziquid_proofs::chain_history::{ChainHistoryV2, HistoryError, HistoryLeaf, HistoryLeafV2};

#[test]
fn nu5_history_binds_orchard_endpoints_and_preserves_failed_append() {
    let first = HistoryLeafV2 {
        v1: HistoryLeaf {
            consensus_branch_id: 0xc2d6_d0b4,
            subtree_commitment: [1; 32],
            start_time: 1,
            end_time: 1,
            start_target: 2,
            end_target: 2,
            start_sapling_root: [3; 32],
            end_sapling_root: [3; 32],
            subtree_total_work: U256::one(),
            start_height: 1_842_420,
            end_height: 1_842_420,
            sapling_tx: 1,
        },
        start_orchard_root: [4; 32],
        end_orchard_root: [4; 32],
        orchard_tx: 1,
    };
    let mut history = ChainHistoryV2::new(first.clone()).unwrap();
    assert_eq!(history.root(), V2::hash(&first));
    let mut second = first.clone();
    second.v1.start_height += 1;
    second.v1.end_height += 1;
    second.v1.subtree_commitment = [5; 32];
    let mut wrong = second.clone();
    wrong.end_orchard_root[0] ^= 1;
    let prior = format!("{history:?}");
    assert_eq!(history.append(wrong), Err(HistoryError::MalformedLeaf));
    assert_eq!(format!("{history:?}"), prior);
    assert_eq!(history.leaf_count(), 1);
    let expected = V2::hash(&V2::combine(&first, &second));
    assert_eq!(history.append(second).unwrap(), expected);
    assert_eq!(history.leaf_count(), 2);
    assert_eq!(history.consensus_branch_id(), 0xc2d6_d0b4);
    assert_eq!(history.last_height(), 1_842_421);
}

// Final roots and original block bytes: Zebra
// e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291, zebra-test/src/vectors/block.rs
// lines 293-294 and 1034-1042. Display-endian roots are reversed below.
// Block text Git blob da93d738c0ca2d0682d5627e14098ec6eaf211dd;
// decoded SHA256 1be0777aeea102d3ba65c1871b4f254e2b8fb0f7477658e0d3819323d8593a83.
/*
Copyright (c) 2019-2025 Zcash Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#[test]
fn genuine_nu5_fields_bind_an_isolated_synthetic_history_root_not_a_header_commitment() {
    let raw = include_bytes!("fixtures/testnet-nu5-block-1842467.bin");
    let block_hash: [u8; 32] = Sha256::digest(Sha256::digest(&raw[..1487])).into();
    let time = u32::from_le_bytes(raw[100..104].try_into().unwrap());
    let bits = u32::from_le_bytes(raw[104..108].try_into().unwrap());
    let exponent = bits >> 24;
    assert!((3..=32).contains(&exponent));
    assert_eq!(bits & 0x0080_0000, 0);
    let target = U256::from(bits & 0x007f_ffff) << (8 * (exponent - 3));
    let work = (!target / (target + U256::one())) + U256::one();
    let mut sapling_root = [
        0x13, 0xa3, 0x30, 0x99, 0xeb, 0x9b, 0x8d, 0xaf,
        0xc0, 0x31, 0x27, 0x19, 0x38, 0xf3, 0x5b, 0x62,
        0x7e, 0xb0, 0x81, 0x1f, 0x12, 0x48, 0x47, 0xab,
        0xbf, 0xb4, 0x3b, 0x58, 0x7c, 0x6e, 0x11, 0xae,
    ];
    sapling_root.reverse();
    let mut orchard_root = [
        0x58, 0x0a, 0xce, 0xb5, 0x86, 0xf3, 0x0a, 0x58,
        0x01, 0xa2, 0x34, 0x14, 0x46, 0x4a, 0xa8, 0x48,
        0x2a, 0xdd, 0x97, 0xb6, 0xd5, 0x5c, 0x06, 0x48,
        0x3b, 0x4f, 0xfb, 0x72, 0x5e, 0x0e, 0x79, 0x3b,
    ];
    orchard_root.reverse();
    let first = HistoryLeafV2 {
        v1: HistoryLeaf {
            consensus_branch_id: 0xc2d6_d0b4,
            subtree_commitment: block_hash,
            start_time: time,
            end_time: time,
            start_target: bits,
            end_target: bits,
            start_sapling_root: sapling_root,
            end_sapling_root: sapling_root,
            subtree_total_work: work,
            start_height: 1_842_467,
            end_height: 1_842_467,
            sapling_tx: 0,
        },
        start_orchard_root: orchard_root,
        end_orchard_root: orchard_root,
        // One transaction with two actions; history counts transactions.
        orchard_tx: 1,
    };
    let history = ChainHistoryV2::new(first.clone()).unwrap();
    assert_eq!(history.root(), V2::hash(&first));
    assert_eq!(history.leaf_count(), 1);
    assert_eq!(history.last_height(), 1_842_467);
    assert_eq!(history.consensus_branch_id(), 0xc2d6_d0b4);

    // This deliberately starts at an isolated block, not the NU5 epoch start.
    // Its root is synthetic, not authenticated against any connected successor.
    for field in 0..3 {
        let mut changed = first.clone();
        match field {
            0 => {
                changed.start_orchard_root[0] ^= 1;
                changed.end_orchard_root = changed.start_orchard_root;
            }
            1 => changed.orchard_tx = 2,
            _ => {
                changed.v1.start_sapling_root[0] ^= 1;
                changed.v1.end_sapling_root = changed.v1.start_sapling_root;
            }
        }
        assert_ne!(ChainHistoryV2::new(changed).unwrap().root(), history.root());
    }
}

#[test]
fn nu6_metadata_epoch_requires_explicit_reset_and_never_owns_network_height_admission() {
    let leaf = |branch, height| HistoryLeafV2 {
        v1: HistoryLeaf {
            consensus_branch_id: branch,
            subtree_commitment: [7; 32], start_time: 1, end_time: 1,
            start_target: 2, end_target: 2,
            start_sapling_root: [3; 32], end_sapling_root: [3; 32],
            subtree_total_work: U256::one(), start_height: height, end_height: height,
            sapling_tx: 1,
        },
        start_orchard_root: [4; 32], end_orchard_root: [4; 32], orchard_tx: 1,
    };
    let mut old = ChainHistoryV2::new(leaf(0xc2d6_d0b4, 2_975_999)).unwrap();
    let before = format!("{old:?}");
    let first = leaf(0xc8e7_1055, 2_976_000);
    assert_eq!(old.append(first.clone()), Err(HistoryError::BranchMismatch));
    assert_eq!(format!("{old:?}"), before);
    let mut current = ChainHistoryV2::new(first.clone()).unwrap();
    assert_eq!(current.root(), V2::hash(&first));
    assert_eq!(current.leaf_count(), 1);
    let next = leaf(0xc8e7_1055, 2_976_001);
    assert_eq!(current.append(next.clone()).unwrap(), V2::hash(&V2::combine(&first, &next)));
    assert_eq!(current.consensus_branch_id(), 0xc8e7_1055);
    let before = format!("{current:?}");
    assert_eq!(current.append(leaf(0x4dec_4df0, 2_976_002)), Err(HistoryError::BranchMismatch));
    assert_eq!(format!("{current:?}"), before);
    // Metadata knows no TEST_NETWORK activation/cutoff. The ledger, not this
    // accumulator, rejects NU6.3 or any branch at a wrong candidate height.
    for height in [0, 3_536_500] {
        assert_eq!(ChainHistoryV2::new(leaf(0xc8e7_1055, height)).unwrap().last_height(), height as u32);
    }
}

#[test]
fn nu61_v2_metadata_is_height_independent_with_explicit_epoch_reset_and_atomic_retry() {
    let leaf = |branch, height| HistoryLeafV2 {
        v1: HistoryLeaf {
            consensus_branch_id: branch, subtree_commitment: [8; 32],
            start_time: 1, end_time: 1, start_target: 2, end_target: 2,
            start_sapling_root: [3; 32], end_sapling_root: [3; 32],
            subtree_total_work: U256::one(), start_height: height, end_height: height,
            sapling_tx: 1,
        },
        start_orchard_root: [4; 32], end_orchard_root: [4; 32], orchard_tx: 0,
    };
    for height in [0, 3_536_500, 4_048_500, 4_052_000, u64::from(u32::MAX) - 1] {
        let first = leaf(0x4dec_4df0, height);
        let mut old = ChainHistoryV2::new(leaf(0xc8e7_1055, height)).unwrap();
        let before = format!("{old:?}");
        assert_eq!(old.append(leaf(0x4dec_4df0, height + 1)), Err(HistoryError::BranchMismatch));
        assert_eq!(format!("{old:?}"), before);
        let mut current = ChainHistoryV2::new(first.clone()).unwrap();
        assert_eq!(current.root(), V2::hash(&first));
        assert_eq!(current.leaf_count(), 1);
        let before = format!("{current:?}");
        for (candidate, error) in [
            (leaf(0xc8e7_1055, height + 1), HistoryError::BranchMismatch),
            (leaf(0x5437_f330, height + 1), HistoryError::BranchMismatch),
            (leaf(0x4dec_4df0, height), HistoryError::NonconsecutiveHeight),
        ] {
            assert_eq!(current.append(candidate), Err(error));
            assert_eq!(format!("{current:?}"), before);
        }
        let next = leaf(0x4dec_4df0, height + 1);
        assert_eq!(current.append(next.clone()).unwrap(), V2::hash(&V2::combine(&first, &next)));
        assert_eq!((current.consensus_branch_id(), current.leaf_count(), current.last_height()), (0x4dec_4df0, 2, (height + 1) as u32));
    }
}

#[test]
fn nu62_v2_metadata_is_height_independent_and_requires_explicit_epoch_reset() {
    let leaf = |branch, height| HistoryLeafV2 {
        v1: HistoryLeaf {
            consensus_branch_id: branch, subtree_commitment: [9; 32],
            start_time: 1, end_time: 1, start_target: 2, end_target: 2,
            start_sapling_root: [3; 32], end_sapling_root: [3; 32],
            subtree_total_work: U256::one(), start_height: height, end_height: height,
            sapling_tx: 1,
        },
        start_orchard_root: [4; 32], end_orchard_root: [4; 32], orchard_tx: 2,
    };
    for height in [0, 4_052_000, 4_134_000, u64::from(u32::MAX) - 1] {
        let mut old = ChainHistoryV2::new(leaf(0x4dec_4df0, height)).unwrap();
        let before = format!("{old:?}");
        assert_eq!(old.append(leaf(0x5437_f330, height + 1)), Err(HistoryError::BranchMismatch));
        assert_eq!(format!("{old:?}"), before);
        let first = leaf(0x5437_f330, height);
        let mut current = ChainHistoryV2::new(first.clone()).unwrap();
        assert_eq!(current.root(), V2::hash(&first));
        let before = format!("{current:?}");
        for (candidate, error) in [
            (leaf(0x4dec_4df0, height + 1), HistoryError::BranchMismatch),
            (leaf(0xffff_ffff, height + 1), HistoryError::UnsupportedBranch),
            (leaf(0x5437_f330, height), HistoryError::NonconsecutiveHeight),
        ] {
            assert_eq!(current.append(candidate), Err(error));
            assert_eq!(format!("{current:?}"), before);
        }
        let next = leaf(0x5437_f330, height + 1);
        assert_eq!(current.append(next.clone()).unwrap(), V2::hash(&V2::combine(&first, &next)));
        assert_eq!((current.consensus_branch_id(), current.leaf_count(), current.last_height()), (0x5437_f330, 2, (height + 1) as u32));
    }
}
