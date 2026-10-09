// Original unchanged numeric vectors and final-Sapling metadata from Zebra
// e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291 zebra-test/src/vectors/block.rs.
// MIT selected; isolated metadata does not supply a connected predecessor.
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

use primitive_types::U256;
use sha2::{Digest, Sha256};
use ziquid_proofs::chain_history::{ChainHistoryV1, HistoryError, HistoryLeaf};

#[test]
fn authentic_first_heartwood_leaf_matches_next_header_commitment() {
    let first = include_bytes!("fixtures/testnet-heartwood-block-903800.bin");
    let next = include_bytes!("fixtures/testnet-heartwood-block-903801.bin");
    let sapling_root = include_bytes!("fixtures/testnet-blossom-block-903799.bin")[68..100].try_into().unwrap();
    let block_hash: [u8; 32] = Sha256::digest(Sha256::digest(&first[..1487])).into();
    assert_eq!(&next[4..36], &block_hash);
    let history = ChainHistoryV1::new(HistoryLeaf {
        consensus_branch_id: 0xf5b9_230b,
        subtree_commitment: block_hash,
        start_time: u32::from_le_bytes(first[100..104].try_into().unwrap()),
        end_time: u32::from_le_bytes(first[100..104].try_into().unwrap()),
        start_target: u32::from_le_bytes(first[104..108].try_into().unwrap()),
        end_target: u32::from_le_bytes(first[104..108].try_into().unwrap()),
        start_sapling_root: sapling_root,
        end_sapling_root: sapling_root,
        subtree_total_work: U256::from(32),
        start_height: 903_800,
        end_height: 903_800,
        sapling_tx: 0,
    }).unwrap();
    assert_eq!(history.root().as_slice(), &next[68..100]);
    assert_eq!(history.leaf_count(), 1);
}

fn leaf(height: u64) -> HistoryLeaf {
    HistoryLeaf {
        consensus_branch_id: 0xf5b9_230b,
        subtree_commitment: [7; 32],
        start_time: 1,
        end_time: 1,
        start_target: 2,
        end_target: 2,
        start_sapling_root: [3; 32],
        end_sapling_root: [3; 32],
        subtree_total_work: U256::from(1),
        start_height: height,
        end_height: height,
        sapling_tx: 1,
    }
}

#[test]
fn rejected_append_preserves_state_and_next_append_right() {
    let mut history = ChainHistoryV1::new(leaf(903_800)).unwrap();
    let before = format!("{history:?}");
    let mut wrong_branch = leaf(903_801);
    wrong_branch.consensus_branch_id = 0xe9ff_75a6;
    let mut malformed = leaf(903_801);
    malformed.end_sapling_root[0] ^= 1;
    for rejected in [wrong_branch, leaf(903_800), leaf(903_802), malformed, leaf(u64::MAX)] {
        assert!(history.append(rejected).is_err());
        assert_eq!(format!("{history:?}"), before);
    }
    history.append(leaf(903_801)).unwrap();
    assert_eq!(history.leaf_count(), 2);
}

#[test]
fn branch_change_is_rejected_and_canopy_epoch_restart_is_explicit() {
    let mut first_canopy = leaf(1_028_500);
    first_canopy.consensus_branch_id = 0xe9ff_75a6;
    let mut history = ChainHistoryV1::new(leaf(1_028_499)).unwrap();
    let before = format!("{history:?}");
    assert_eq!(history.append(first_canopy.clone()), Err(HistoryError::BranchMismatch));
    assert_eq!(format!("{history:?}"), before);
    let mut restarted = ChainHistoryV1::new(first_canopy).unwrap();
    assert_eq!(restarted.leaf_count(), 1);
    let before = format!("{restarted:?}");
    assert_eq!(restarted.append(leaf(1_028_501)), Err(HistoryError::BranchMismatch));
    assert_eq!(format!("{restarted:?}"), before);
    let mut next = leaf(1_028_501);
    next.consensus_branch_id = 0xe9ff_75a6;
    restarted.append(next).unwrap();
    assert_eq!(restarted.leaf_count(), 2);
}

#[test]
fn authentic_first_canopy_leaf_matches_next_header_without_a_predecessor_snapshot() {
    let first = include_bytes!("fixtures/testnet-heartwood-block-1028500.bin");
    let next = include_bytes!("fixtures/testnet-canopy-block-1028501.bin");
    let block_hash: [u8; 32] = Sha256::digest(Sha256::digest(&first[..1487])).into();
    assert_eq!(&next[4..36], &block_hash);
    // Independent pinned Zebra vectors/block.rs:935–940, display endian.
    // This is isolated authentic leaf metadata, NOT a connected frontier.
    let mut sapling_root = [0x58, 0x0a, 0xdc, 0x02, 0x53, 0xcd, 0x05, 0x45, 0x25, 0x00, 0x39, 0x26, 0x7b, 0x7b, 0x49, 0x44, 0x5c, 0xa0, 0x55, 0x0d, 0xf7, 0x35, 0x92, 0x0b, 0x74, 0x66, 0xbb, 0xa1, 0xa6, 0x4f, 0x7c, 0xf7];
    sapling_root.reverse();
    let history = ChainHistoryV1::new(HistoryLeaf {
        consensus_branch_id: 0xe9ff_75a6,
        subtree_commitment: block_hash,
        start_time: u32::from_le_bytes(first[100..104].try_into().unwrap()),
        end_time: u32::from_le_bytes(first[100..104].try_into().unwrap()),
        start_target: u32::from_le_bytes(first[104..108].try_into().unwrap()),
        end_target: u32::from_le_bytes(first[104..108].try_into().unwrap()),
        start_sapling_root: sapling_root,
        end_sapling_root: sapling_root,
        // Target 0x2007ffff gives 32 units of actual block work.
        subtree_total_work: U256::from(32),
        start_height: 1_028_500,
        end_height: 1_028_500,
        sapling_tx: 0,
    }).unwrap();
    assert_eq!(history.root().as_slice(), &next[68..100]);
    assert_eq!(history.leaf_count(), 1);
}
