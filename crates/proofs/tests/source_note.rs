//! Finite full-validation queries; no connected late-height note archive is available.

use std::io::{self, Read};

use ziquid_proofs::{
    source_replay::{MAX_BLOCK_BYTES, MAX_BLOCK_COUNT, SourceReplayError},
    genesis::ShieldedPool,
    source_note::{
        SourceFundingLocator, SourceNoteError, SourceNoteSelection, replay_note_testnet,
    },
};

struct UnreadHistory;

impl Read for UnreadHistory {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("invalid note selection must be rejected before reading history")
    }
}

fn selection() -> SourceNoteSelection {
    SourceNoteSelection {
        pool: ShieldedPool::Ironwood,
        commitment: [0; 32],
        nullifier: [0; 32],
        funding: SourceFundingLocator {
            block_height: 4_134_000,
            transaction_index: 0,
            action_index: 0,
            effect_id: [0; 32],
            auth_digest: [0; 32],
        },
    }
}

#[test]
fn distinct_unsupported_trees_are_rejected_before_reading_history() {
    for pool in [ShieldedPool::Sprout, ShieldedPool::Sapling] {
        assert_eq!(
            replay_note_testnet(
                &mut UnreadHistory,
                1,
                1700,
                SourceNoteSelection { pool, ..selection() },
            ).unwrap_err(),
            SourceNoteError::InvalidSelection,
        );
    }
}

const GENESIS: &[u8] = include_bytes!("fixtures/testnet-genesis.bin");
const BLOCKS: [&[u8]; 10] = [
    include_bytes!("fixtures/testnet-block-1.bin"),
    include_bytes!("fixtures/testnet-block-2.bin"),
    include_bytes!("fixtures/testnet-block-3.bin"),
    include_bytes!("fixtures/testnet-block-4.bin"),
    include_bytes!("fixtures/testnet-block-5.bin"),
    include_bytes!("fixtures/testnet-block-6.bin"),
    include_bytes!("fixtures/testnet-block-7.bin"),
    include_bytes!("fixtures/testnet-block-8.bin"),
    include_bytes!("fixtures/testnet-block-9.bin"),
    include_bytes!("fixtures/testnet-block-10.bin"),
];

fn framed(blocks: &[&[u8]]) -> Vec<u8> {
    let mut input = u32::try_from(blocks.len()).unwrap().to_le_bytes().to_vec();
    for block in blocks {
        input.extend_from_slice(&u32::try_from(block.len()).unwrap().to_le_bytes());
        input.extend_from_slice(block);
    }
    input
}

fn complete_history() -> Vec<u8> {
    let mut blocks = vec![GENESIS];
    blocks.extend(BLOCKS);
    framed(&blocks)
}

#[test]
fn genuine_connected_zero_through_ten_cannot_manufacture_late_note_membership() {
    let input = complete_history();
    assert_eq!(input.len(), 17_920);
    for pool in [ShieldedPool::Orchard, ShieldedPool::Ironwood] {
        let height = if pool == ShieldedPool::Orchard { 1_842_420 } else { 4_134_000 };
        let query = SourceNoteSelection {
            pool,
            funding: SourceFundingLocator { block_height: height, ..selection().funding },
            ..selection()
        };
        let mut reader = input.as_slice();
        assert_eq!(
            replay_note_testnet(&mut reader, 11, 17_920, query).unwrap_err(),
            SourceNoteError::FundingNotFound,
        );
        assert!(reader.is_empty()); // No note or transaction packet escapes before full replay/EOF.
        let input = framed(&[GENESIS]);
        assert_eq!(
            replay_note_testnet(&mut input.as_slice(), 1, 1700, query).unwrap_err(),
            SourceNoteError::FundingNotFound,
        );
    }
}

#[test]
fn malformed_selection_is_rejected_without_consuming_reader_bytes() {
    let mut invalid = vec![
        SourceNoteSelection { commitment: [0xff; 32], ..selection() },
        SourceNoteSelection { nullifier: [0xff; 32], ..selection() },
    ];
    for height in [0, 4_133_999, MAX_BLOCK_COUNT, u32::MAX] {
        invalid.push(SourceNoteSelection {
            funding: SourceFundingLocator { block_height: height, ..selection().funding },
            ..selection()
        });
    }
    for height in [1_842_419, 4_048_500, 4_051_999] {
        invalid.push(SourceNoteSelection {
            pool: ShieldedPool::Orchard,
            funding: SourceFundingLocator { block_height: height, ..selection().funding },
            ..selection()
        });
    }
    invalid.push(SourceNoteSelection {
        funding: SourceFundingLocator { transaction_index: u32::MAX, ..selection().funding },
        ..selection()
    });
    invalid.push(SourceNoteSelection {
        funding: SourceFundingLocator { action_index: u32::MAX, ..selection().funding },
        ..selection()
    });
    for query in invalid {
        assert_eq!(
            replay_note_testnet(&mut UnreadHistory, 11, 17_920, query).unwrap_err(),
            SourceNoteError::InvalidSelection,
        );
    }
    assert!(!format!("{:?}", selection()).contains("4134000"));
    assert!(!format!("{:?}", selection().funding).contains("4134000"));
}

#[test]
fn absent_note_does_not_hide_late_corrupt_history_count_suffix_or_truncation() {
    let input = complete_history();
    let mut invalid = input.clone();
    let offset = input.len() - BLOCKS[9].len();
    invalid[offset + 1488 + 50] ^= 1;
    assert_eq!(
        replay_note_testnet(&mut invalid.as_slice(), 11, 17_920, selection()).unwrap_err(),
        SourceNoteError::Replay(SourceReplayError::InvalidTransition),
    );
    assert_eq!(
        replay_note_testnet(&mut &input[..input.len() - 1], 11, 17_920, selection()).unwrap_err(),
        SourceNoteError::Replay(SourceReplayError::InvalidFraming),
    );
    let mut incomplete = input.clone();
    incomplete[..4].copy_from_slice(&12u32.to_le_bytes());
    assert_eq!(
        replay_note_testnet(&mut incomplete.as_slice(), 12, u64::MAX, selection()).unwrap_err(),
        SourceNoteError::Replay(SourceReplayError::InvalidFraming),
    );
    let mut suffix = input.clone();
    suffix.push(0);
    assert_eq!(
        replay_note_testnet(&mut suffix.as_slice(), 11, 17_920, selection()).unwrap_err(),
        SourceNoteError::Replay(SourceReplayError::TrailingBytes),
    );
    let no_genesis = framed(&[BLOCKS[0]]);
    assert_eq!(
        replay_note_testnet(&mut no_genesis.as_slice(), 1, u64::MAX, selection()).unwrap_err(),
        SourceNoteError::Replay(SourceReplayError::InvalidGenesis),
    );
}

#[test]
fn public_note_queries_never_accept_an_isolated_late_body_as_checkpoint() {
    let late = include_bytes!("fixtures/testnet-nu5-block-1842467.bin");
    let input = framed(&[GENESIS, late]);
    let query = SourceNoteSelection {
        pool: ShieldedPool::Orchard,
        funding: SourceFundingLocator { block_height: 1_842_467, transaction_index: 1, ..selection().funding },
        ..selection()
    };
    assert_eq!(
        replay_note_testnet(&mut input.as_slice(), 2, input.len() as u64, query).unwrap_err(),
        SourceNoteError::Replay(SourceReplayError::InvalidTransition),
    );
}

#[test]
fn note_query_preserves_exact_replay_budgets_and_declared_frame_bounds() {
    let input = framed(&[GENESIS, BLOCKS[0]]);
    for (max_blocks, max_bytes, expected) in [
        (0, input.len() as u64, SourceReplayError::InvalidPolicy),
        (MAX_BLOCK_COUNT + 1, input.len() as u64, SourceReplayError::InvalidPolicy),
        (2, 0, SourceReplayError::InvalidPolicy),
        (1, input.len() as u64, SourceReplayError::LimitExceeded),
        (2, input.len() as u64 - 1, SourceReplayError::LimitExceeded),
    ] {
        assert_eq!(
            replay_note_testnet(&mut input.as_slice(), max_blocks, max_bytes, selection()).unwrap_err(),
            SourceNoteError::Replay(expected),
        );
    }
    let mut zero = input.clone();
    zero[..4].fill(0);
    assert_eq!(
        replay_note_testnet(&mut zero.as_slice(), 2, u64::MAX, selection()).unwrap_err(),
        SourceNoteError::Replay(SourceReplayError::InvalidFraming),
    );
    let mut oversized = framed(&[GENESIS]);
    oversized[..4].copy_from_slice(&2u32.to_le_bytes());
    oversized.extend_from_slice(&u32::try_from(MAX_BLOCK_BYTES + 1).unwrap().to_le_bytes());
    assert_eq!(
        replay_note_testnet(&mut oversized.as_slice(), 2, u64::MAX, selection()).unwrap_err(),
        SourceNoteError::Replay(SourceReplayError::LimitExceeded),
    );
}

struct Fragmented<'a> {
    bytes: &'a [u8],
    interrupts: usize,
    fail_eof: bool,
    eof_reads: usize,
}

impl Read for Fragmented<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.interrupts != 0 {
            self.interrupts -= 1;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.bytes.is_empty() { self.eof_reads += 1; }
        if self.bytes.is_empty() && self.fail_eof {
            return Err(io::Error::other("private-reader-sentinel"));
        }
        let count = output.len().min(self.bytes.len()).min(7);
        output[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

#[test]
fn final_reader_failure_cannot_be_published_as_absence_and_errors_remain_redacted() {
    let input = complete_history();
    for fail_eof in [false, true] {
        let mut reader = Fragmented { bytes: &input, interrupts: 2, fail_eof, eof_reads: 0 };
        let error = replay_note_testnet(&mut reader, 11, 17_920, selection()).unwrap_err();
        assert_eq!(error, if fail_eof {
            SourceNoteError::Replay(SourceReplayError::InputUnavailable)
        } else { SourceNoteError::FundingNotFound });
        assert!(reader.bytes.is_empty());
        assert_eq!(reader.eof_reads, 1);
        assert!(!error.to_string().contains("private-reader-sentinel"));
        assert!(!format!("{error:?}").contains("private-reader-sentinel"));
    }
}
