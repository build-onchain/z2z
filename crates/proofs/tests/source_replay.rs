//! Offline finite linear replay, not canonical-chain, finality, or financial proof.

use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use primitive_types::U256;
use ziquid_proofs::source_comparison::compare_framed_testnet_prefixes;
use std::io::{self, Read};
use ziquid_proofs::source_replay::{MAX_BLOCK_COUNT, SourceReplayError, replay_framed_testnet};

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
    for body in blocks {
        input.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        input.extend_from_slice(body);
    }
    input
}

fn complete_history() -> Vec<u8> {
    let mut bodies = vec![GENESIS];
    bodies.extend(BLOCKS);
    framed(&bodies)
}

fn hex(input: &str) -> Vec<u8> {
    input.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid pinned hex"),
        };
        digit(pair[0]) * 16 + digit(pair[1])
    }).collect()
}

#[test]
fn exact_bound_complete_history_returns_guest_compatible_height_ten_journal() {
    let input = complete_history();
    assert_eq!(input.len(), 17_920);
    let journal = replay_framed_testnet(&mut input.as_slice(), 11, 17_920).unwrap();
    assert_eq!(journal.len(), 374);
    assert_eq!(&journal[..49], b"ziquid/sprout-through-nu63-ledger/subrelation/v11");
    assert_eq!(&journal[49..81], Sha256::digest(&input).as_slice());
    assert_eq!(&journal[81..85], &10u32.to_le_bytes());
    assert_eq!(&journal[85..117], hex("12c105283c5f4082eb3d2ea2ab3672e3bb2fe4bce91e34e663be2927754c9f07"));
    let mut work = [0; 32];
    work[30..].copy_from_slice(&352u16.to_be_bytes());
    assert_eq!(&journal[117..149], &work);
    assert_eq!(&journal[149..157], &3_437_500u64.to_le_bytes());
    assert_eq!(&journal[157..197], &[0; 40]);
    assert_eq!(&journal[197..205], &3_437_500u64.to_le_bytes());
    assert_eq!(&journal[205..213], &3_437_500u64.to_le_bytes());
    assert_eq!(&journal[213..245], hex("d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259"));
    assert_eq!(&journal[245..277], hex("fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e"));
    let orchard_root = hex("ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f");
    assert_eq!(&journal[277..309], orchard_root);
    assert_eq!(&journal[309..341], orchard_root);
    assert_eq!(&journal[341..], &[0; 33]);
}

#[test]
fn authentic_genesis_alone_returns_zero_height_work_and_accounts() {
    let input = framed(&[GENESIS]);
    let journal = replay_framed_testnet(&mut input.as_slice(), 1, 1700).unwrap();
    assert_eq!(&journal[81..85], &[0; 4]);
    assert_eq!(&journal[85..117], hex("382c4a332661c7ed0671f32a34d724619f086c61873bce7c99859dd9920aa605"));
    let mut work = [0; 32];
    work[31] = 32;
    assert_eq!(&journal[117..149], &work);
    assert_eq!(&journal[149..213], &[0; 64]);
    assert_eq!(&journal[341..], &[0; 33]);
}

#[test]
fn actual_trailing_byte_is_rejected_even_at_exact_payload_budget() {
    let mut input = framed(&[GENESIS]);
    input.push(0);
    assert!(replay_framed_testnet(&mut input.as_slice(), 1, 1700).is_err());
}

#[test]
fn count_and_caller_policies_reject_before_body_consumption() {
    let genesis = framed(&[GENESIS]);
    for max_blocks in [0, 4_465_027, u32::MAX] {
        let mut input = genesis.as_slice();
        assert!(replay_framed_testnet(&mut input, max_blocks, 1700).is_err());
        assert_eq!(input.len(), genesis.len());
    }
    let mut input = genesis.as_slice();
    assert!(replay_framed_testnet(&mut input, 1, 0).is_err());
    assert_eq!(input.len(), genesis.len());
    for count in [0u32, 4_465_027, u32::MAX] {
        assert!(replay_framed_testnet(&mut count.to_le_bytes().as_slice(), 4_465_026, u64::MAX).is_err());
    }
    let mut input = genesis.as_slice();
    assert!(replay_framed_testnet(&mut input, 1, 1699).is_err());
    assert_eq!(input.len(), genesis.len() - 4);
    let history = complete_history();
    assert!(replay_framed_testnet(&mut history.as_slice(), 10, 17_920).is_err());
    assert!(replay_framed_testnet(&mut history.as_slice(), 11, 17_919).is_err());
    assert!(replay_framed_testnet(&mut 4_465_026u32.to_le_bytes().as_slice(), 4_465_026, u64::MAX).is_err());
}

#[test]
fn invalid_declared_lengths_reject_without_reading_payload() {
    for length in [1691u32, 1693, 2_000_001, u32::MAX] {
        let mut input = 1u32.to_le_bytes().to_vec();
        input.extend_from_slice(&length.to_le_bytes());
        assert!(replay_framed_testnet(&mut input.as_slice(), 1, u64::MAX).is_err());
    }
    for length in [2_000_001u32, u32::MAX] {
        let mut input = framed(&[GENESIS]);
        input[..4].copy_from_slice(&2u32.to_le_bytes());
        input.extend_from_slice(&length.to_le_bytes());
        assert!(replay_framed_testnet(&mut input.as_slice(), 2, u64::MAX).is_err());
    }
    let mut input = framed(&[GENESIS]);
    input[..4].copy_from_slice(&2u32.to_le_bytes());
    input.extend_from_slice(&2_000_000u32.to_le_bytes());
    input.resize(input.len() + 2_000_000, 0);
    assert!(replay_framed_testnet(&mut input.as_slice(), 2, u64::MAX).is_err());
}

#[test]
fn only_authentic_complete_genesis_can_start_replay() {
    let mut changed = GENESIS.to_vec();
    changed[152] ^= 1;
    for first in [&changed[..], BLOCKS[0]] {
        let input = framed(&[first]);
        assert!(replay_framed_testnet(&mut input.as_slice(), 1, u64::MAX).is_err());
    }
}

#[test]
fn truncated_count_length_and_complete_body_are_not_successful_prefixes() {
    let input = framed(&[GENESIS, BLOCKS[0]]);
    for length in [0, 1, 2, 3, 4, 5, 6, 7, 1700, 1701, 1702, 1703, 1704, 1704 + 1487, 1704 + 1488, 1704 + 1530, input.len() - 1] {
        assert!(replay_framed_testnet(&mut &input[..length], 2, u64::MAX).is_err(), "truncation {length}");
    }
}

#[test]
fn gaps_duplicates_reordering_and_isolated_activation_bodies_are_rejected() {
    let later: &[u8] = include_bytes!("fixtures/testnet-sapling-block-280000.bin");
    let cases: &[&[&[u8]]] = &[
        &[GENESIS, BLOCKS[1]],
        &[GENESIS, BLOCKS[0], BLOCKS[2]],
        &[GENESIS, BLOCKS[0], BLOCKS[0]],
        &[GENESIS, BLOCKS[1], BLOCKS[0]],
        &[GENESIS, later],
    ];
    for blocks in cases {
        let input = framed(blocks);
        assert!(replay_framed_testnet(&mut input.as_slice(), 11, u64::MAX).is_err());
    }
}

#[test]
fn altered_full_body_header_merkle_count_and_inner_suffix_are_rejected() {
    let mut cases = Vec::new();
    for offset in [4, 36, 100, 104, 108, 143, 1486, 1488 + 50] {
        let mut body = BLOCKS[1].to_vec();
        body[offset] ^= 1;
        cases.push(body);
    }
    let mut body = BLOCKS[1].to_vec();
    body.splice(1487..1488, [0xfd, 1, 0]);
    cases.push(body);
    let mut body = BLOCKS[1].to_vec();
    body.push(0);
    cases.push(body);
    cases.push(Vec::new());
    for body in cases {
        let input = framed(&[GENESIS, BLOCKS[0], &body]);
        assert!(replay_framed_testnet(&mut input.as_slice(), 3, u64::MAX).is_err());
    }
}

#[test]
fn declared_count_must_match_actual_history_and_late_failure_returns_no_journal() {
    let mut input = complete_history();
    input[..4].copy_from_slice(&10u32.to_le_bytes());
    assert!(replay_framed_testnet(&mut input.as_slice(), 11, 17_920).is_err());
    input[..4].copy_from_slice(&12u32.to_le_bytes());
    assert!(replay_framed_testnet(&mut input.as_slice(), 12, u64::MAX).is_err());
    input[..4].copy_from_slice(&11u32.to_le_bytes());
    let late_output = input.len() - 1618 + 1488 + 50;
    input[late_output] ^= 1;
    assert!(replay_framed_testnet(&mut input.as_slice(), 11, 17_920).is_err());
}

struct Fragmented<'a> {
    input: &'a [u8],
    position: usize,
    chunk: usize,
    interrupts: &'a [usize],
    fail_at: Option<usize>,
}

impl Read for Fragmented<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.interrupts.first() == Some(&self.position) {
            self.interrupts = &self.interrupts[1..];
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.fail_at == Some(self.position) {
            return Err(io::Error::other("private-input-sentinel"));
        }
        assert!(output.len() <= 1692, "history-sized read request");
        let next_boundary = self.interrupts.first().copied().into_iter()
            .chain(self.fail_at).filter(|&offset| offset > self.position).min()
            .unwrap_or(self.input.len());
        let length = output.len().min(self.chunk).min(self.input.len() - self.position)
            .min(next_boundary - self.position);
        output[..length].copy_from_slice(&self.input[self.position..self.position + length]);
        self.position += length;
        Ok(length)
    }
}

#[test]
fn short_reads_and_interrupted_prefix_body_and_eof_preserve_exact_journal() {
    let input = complete_history();
    let expected = replay_framed_testnet(&mut input.as_slice(), 11, 17_920).unwrap();
    for chunk in [1, 7] {
        let interrupts = [0, 4, 8, 1700, input.len()];
        let mut reader = Fragmented { input: &input, position: 0, chunk, interrupts: &interrupts, fail_at: None };
        assert_eq!(replay_framed_testnet(&mut reader, 11, 17_920).unwrap(), expected);
    }
}

#[test]
fn reader_failures_at_length_body_and_final_eof_probe_are_not_eof_or_public_errors() {
    let input = framed(&[GENESIS]);
    for offset in [4, 8, input.len()] {
        let mut reader = Fragmented { input: &input, position: 0, chunk: 7, interrupts: &[], fail_at: Some(offset) };
        let error = replay_framed_testnet(&mut reader, 1, 1700).unwrap_err();
        assert!(!error.to_string().contains("private-input-sentinel"));
        assert!(!format!("{error:?}").contains("private-input-sentinel"));
    }
}

#[test]
fn comparison_uses_actual_fully_validated_work_and_completed_boundaries() {
    let left = complete_history();
    let right = framed(&std::iter::once(GENESIS).chain(BLOCKS[..9].iter().copied()).collect::<Vec<_>>());
    let comparison = compare_framed_testnet_prefixes(
        &mut left.as_slice(), &mut right.as_slice(),
        11, left.len() as u64, 10, right.len() as u64,
    ).unwrap();
    assert_eq!(comparison.work_ordering(), Ordering::Greater);
    assert!(!comparison.same_boundary());
    assert_eq!(comparison.left_tip().height(), 10);
    assert_eq!(comparison.right_tip().height(), 9);
    assert_eq!(comparison.left_tip().cumulative_work(), U256::from(352));
    assert_eq!(comparison.right_tip().cumulative_work(), U256::from(320));
    assert_eq!(comparison.left_tip().hash().as_slice(), hex("12c105283c5f4082eb3d2ea2ab3672e3bb2fe4bce91e34e663be2927754c9f07"));
    assert_eq!(comparison.right_tip().hash().as_slice(), &BLOCKS[9][4..36]);
    assert_eq!(comparison.left_journal(), &replay_framed_testnet(&mut left.as_slice(), 11, left.len() as u64).unwrap());
    assert_eq!(comparison.right_journal(), &replay_framed_testnet(&mut right.as_slice(), 10, right.len() as u64).unwrap());
}

#[test]
fn comparison_swapping_inputs_reverses_work_without_choosing_a_chain() {
    let longer = complete_history();
    let shorter = framed(&std::iter::once(GENESIS).chain(BLOCKS[..9].iter().copied()).collect::<Vec<_>>());
    let comparison = compare_framed_testnet_prefixes(
        &mut shorter.as_slice(), &mut longer.as_slice(), 10, 16_302, 11, 17_920,
    ).unwrap();
    assert_eq!(comparison.work_ordering(), Ordering::Less);
    assert!(!comparison.same_boundary());
    assert_eq!(comparison.left_tip().height(), 9);
    assert_eq!(comparison.right_tip().height(), 10);
    assert_eq!(comparison.left_tip().cumulative_work(), U256::from(320));
    assert_eq!(comparison.right_tip().cumulative_work(), U256::from(352));
    assert_eq!(comparison.left_tip().hash().as_slice(), &BLOCKS[9][4..36]);
    assert_eq!(comparison.right_tip().hash().as_slice(), hex("12c105283c5f4082eb3d2ea2ab3672e3bb2fe4bce91e34e663be2927754c9f07"));
}

#[test]
fn comparison_identical_complete_histories_and_genesis_have_equal_boundaries() {
    for (input, max_blocks) in [(complete_history(), 11), (framed(&[GENESIS]), 1)] {
        let comparison = compare_framed_testnet_prefixes(
            &mut input.as_slice(), &mut input.as_slice(),
            max_blocks, input.len() as u64, max_blocks, input.len() as u64,
        ).unwrap();
        assert_eq!(comparison.work_ordering(), Ordering::Equal);
        assert!(comparison.same_boundary());
        assert_eq!(comparison.left_tip(), comparison.right_tip());
        assert_eq!(comparison.left_journal(), comparison.right_journal());
        assert_eq!(&comparison.left_journal()[49..81], Sha256::digest(&input).as_slice());
        let debug = format!("{comparison:?}");
        assert_eq!(debug, "ValidatedPrefixComparison { .. }");
    }
}

#[test]
fn comparison_rejects_early_and_late_invalid_candidates_on_either_side() {
    let valid = complete_history();
    let mut bad_genesis = valid.clone();
    bad_genesis[8 + 152] ^= 1;
    let mut bad_late_body = valid.clone();
    bad_late_body[valid.len() - 1618 + 1488 + 50] ^= 1;
    let gap = framed(&[GENESIS, BLOCKS[1]]);
    for (invalid, expected) in [
        (bad_genesis, SourceReplayError::InvalidGenesis),
        (bad_late_body, SourceReplayError::InvalidTransition),
        (gap, SourceReplayError::InvalidTransition),
    ] {
        for invalid_left in [true, false] {
            let (left, right) = if invalid_left { (&invalid, &valid) } else { (&valid, &invalid) };
            assert_eq!(compare_framed_testnet_prefixes(
                &mut left.as_slice(), &mut right.as_slice(), 11, 17_920, 11, 17_920,
            ).unwrap_err(), expected, "invalid_left={invalid_left}");
        }
    }
}

#[test]
fn comparison_same_height_same_header_cannot_hide_an_invalid_complete_body() {
    let valid = framed(&[GENESIS, BLOCKS[0]]);
    let mut altered = BLOCKS[0].to_vec();
    altered[1488 + 50] ^= 1;
    assert_eq!(&altered[..1487], &BLOCKS[0][..1487]);
    let invalid = framed(&[GENESIS, &altered]);
    for invalid_left in [true, false] {
        let (left, right) = if invalid_left { (&invalid, &valid) } else { (&valid, &invalid) };
        assert_eq!(compare_framed_testnet_prefixes(
            &mut left.as_slice(), &mut right.as_slice(),
            2, left.len() as u64, 2, right.len() as u64,
        ).unwrap_err(), SourceReplayError::InvalidTransition);
    }
}

#[test]
fn comparison_requires_complete_framing_and_actual_eof_on_both_candidates() {
    let valid = complete_history();
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut low_count = valid.clone();
    low_count[..4].copy_from_slice(&10u32.to_le_bytes());
    let mut high_count = valid.clone();
    high_count[..4].copy_from_slice(&12u32.to_le_bytes());
    let mut zero_count = valid.clone();
    zero_count[..4].fill(0);
    let cases = [
        (trailing.as_slice(), SourceReplayError::TrailingBytes),
        (low_count.as_slice(), SourceReplayError::TrailingBytes),
        (high_count.as_slice(), SourceReplayError::InvalidFraming),
        (zero_count.as_slice(), SourceReplayError::InvalidFraming),
        (&valid[..3], SourceReplayError::InvalidFraming),
        (&valid[..7], SourceReplayError::InvalidFraming),
        (&valid[..valid.len() - 1], SourceReplayError::InvalidFraming),
    ];
    for (invalid, expected) in cases {
        // Leave room for announced missing prefixes so this test isolates
        // framing/EOF rejection rather than the independent byte-budget guard.
        for invalid_left in [true, false] {
            let (left, right) = if invalid_left { (invalid, valid.as_slice()) } else { (valid.as_slice(), invalid) };
            assert_eq!(compare_framed_testnet_prefixes(
                &mut &left[..], &mut &right[..], 12, u64::MAX, 12, u64::MAX,
            ).unwrap_err(), expected, "invalid_left={invalid_left}, length={}", invalid.len());
        }
    }
}

#[test]
fn comparison_enforces_each_candidates_own_block_and_byte_limits() {
    let input = complete_history();
    for (max_blocks, max_bytes, expected) in [
        (0, 17_920, SourceReplayError::InvalidPolicy),
        (MAX_BLOCK_COUNT + 1, 17_920, SourceReplayError::InvalidPolicy),
        (11, 0, SourceReplayError::InvalidPolicy),
        (10, 17_920, SourceReplayError::LimitExceeded),
        (11, 3, SourceReplayError::LimitExceeded),
        (11, 17_919, SourceReplayError::LimitExceeded),
    ] {
        assert_eq!(compare_framed_testnet_prefixes(
            &mut input.as_slice(), &mut input.as_slice(), max_blocks, max_bytes, 11, 17_920,
        ).unwrap_err(), expected, "left limit");
        assert_eq!(compare_framed_testnet_prefixes(
            &mut input.as_slice(), &mut input.as_slice(), 11, 17_920, max_blocks, max_bytes,
        ).unwrap_err(), expected, "right limit");
    }
}

#[test]
fn comparison_io_failures_in_either_candidate_including_eof_publish_no_result() {
    let input = complete_history();
    for offset in [0, 4, 8, 1704, input.len() - 1, input.len()] {
        for failing_left in [true, false] {
            let mut failing = Fragmented {
                input: &input, position: 0, chunk: 7, interrupts: &[], fail_at: Some(offset),
            };
            let result = if failing_left {
                compare_framed_testnet_prefixes(&mut failing, &mut input.as_slice(), 11, 17_920, 11, 17_920)
            } else {
                compare_framed_testnet_prefixes(&mut input.as_slice(), &mut failing, 11, 17_920, 11, 17_920)
            };
            let error = result.unwrap_err();
            assert_eq!(error, SourceReplayError::InputUnavailable);
            assert!(!format!("{error:?} {error}").contains("private-input-sentinel"));
        }
    }
}

#[test]
fn comparison_accepts_nonseekable_short_reads_and_interrupted_eof_on_both_inputs() {
    let input = complete_history();
    let interrupts = [0, 4, 8, 1700, input.len()];
    let mut left = Fragmented { input: &input, position: 0, chunk: 1, interrupts: &interrupts, fail_at: None };
    let mut right = Fragmented { input: &input, position: 0, chunk: 7, interrupts: &interrupts, fail_at: None };
    let comparison = compare_framed_testnet_prefixes(&mut left, &mut right, 11, 17_920, 11, 17_920).unwrap();
    assert_eq!(comparison.work_ordering(), Ordering::Equal);
    assert!(comparison.same_boundary());
    assert_eq!(&comparison.left_journal()[49..81], Sha256::digest(&input).as_slice());
    assert_eq!(comparison.left_journal(), comparison.right_journal());
}

#[test]
fn comparison_left_failure_does_not_begin_or_expose_the_right_candidate() {
    let mut invalid = GENESIS.to_vec();
    invalid[152] ^= 1;
    let left = framed(&[&invalid]);
    let input = complete_history();
    let mut right = input.as_slice();
    assert_eq!(compare_framed_testnet_prefixes(
        &mut left.as_slice(), &mut right, 1, 1700, 11, 17_920,
    ).unwrap_err(), SourceReplayError::InvalidGenesis);
    assert_eq!(right.len(), input.len());
}

#[test]
fn comparison_two_invalid_candidates_never_produce_a_work_relation() {
    let mut bad_genesis = GENESIS.to_vec();
    bad_genesis[152] ^= 1;
    let early = framed(&[&bad_genesis]);
    let mut late = complete_history();
    let last = late.len() - 1618 + 1488 + 50;
    late[last] ^= 1;
    for (left, right, expected) in [
        (&early, &late, SourceReplayError::InvalidGenesis),
        (&late, &early, SourceReplayError::InvalidTransition),
    ] {
        assert_eq!(compare_framed_testnet_prefixes(
            &mut left.as_slice(), &mut right.as_slice(), 11, 17_920, 11, 17_920,
        ).unwrap_err(), expected);
    }
}

#[test]
fn comparison_rejects_overlarge_declared_frames_without_reading_their_bodies() {
    let valid = framed(&[GENESIS]);
    let mut invalid = valid.clone();
    invalid[..4].copy_from_slice(&2u32.to_le_bytes());
    invalid.extend_from_slice(&2_000_001u32.to_le_bytes());
    let mut left = invalid.as_slice();
    assert_eq!(compare_framed_testnet_prefixes(
        &mut left, &mut valid.as_slice(), 2, u64::MAX, 1, 1700,
    ).unwrap_err(), SourceReplayError::LimitExceeded);
    assert!(left.is_empty());
    let mut right = invalid.as_slice();
    assert_eq!(compare_framed_testnet_prefixes(
        &mut valid.as_slice(), &mut right, 1, 1700, 2, u64::MAX,
    ).unwrap_err(), SourceReplayError::LimitExceeded);
    assert!(right.is_empty());
}
