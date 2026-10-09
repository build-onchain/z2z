//! Host-local authentic occurrence in a finite prefix, not finality or money authority.

use std::io::{self, Read};

use sha2::{Digest, Sha256};
use primitive_types::U256;
use ziquid_proofs::{
    source_replay::{SourceReplayError, replay_framed_testnet},
    source_selection::{
        SelectedTransactionExpectation, SourceSelectionError, SourceTransactionSelection,
        replay_selected_testnet,
    },
};

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

fn digest(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut result = [0; 32];
    for (byte, pair) in result.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let digit = |value: u8| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid pinned fixture hex"),
        };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    result
}

#[test]
fn authentic_first_and_last_occurrences_retain_exact_bytes_and_completed_boundary() {
    // These txids are independently pinned in ledger.rs from primary full bodies.
    let cases = [
        (1, "755f7c7d27a811596e9fae6dd30ca45be86e901d499909de35b6ff1f699f7ef3"),
        (10, "2edaa1188cc82324f77ab6c52d37a30c2837b4c985681beae1256c321b188738"),
    ];
    let input = complete_history();
    assert_eq!(input.len(), 17_920);
    for (height, effect) in cases {
        let effect_id = digest(effect);
        let selection = SourceTransactionSelection {
            block_height: height,
            transaction_index: 0,
            expected: SelectedTransactionExpectation::Digests {
                effect_id,
                auth_digest: [0xff; 32], // pre-v5 has no separate authorization digest
            },
        };
        let evidence = replay_selected_testnet(&mut input.as_slice(), 11, 17_920, selection).unwrap();
        assert_eq!(evidence.block().height(), height);
        assert_eq!(evidence.block().cumulative_work(), U256::from(32 * (height + 1)));
        let expected_hash: [u8; 32] = if height == 1 {
            BLOCKS[1][4..36].try_into().unwrap() // next authentic header's parent
        } else {
            digest("12c105283c5f4082eb3d2ea2ab3672e3bb2fe4bce91e34e663be2927754c9f07")
        };
        assert_eq!(evidence.block().hash(), expected_hash);
        assert_eq!(evidence.transaction_index(), 0);
        assert_eq!(evidence.effect_id(), effect_id);
        assert_eq!(evidence.auth_digest(), [0xff; 32]);
        assert_eq!(evidence.transaction_bytes(), &BLOCKS[(height - 1) as usize][1488..]);
        let journal = evidence.boundary_journal();
        assert_eq!(&journal[..49], b"ziquid/sprout-through-nu63-ledger/subrelation/v11");
        assert_eq!(&journal[81..85], &10u32.to_le_bytes());
        assert_eq!(&journal[49..81], Sha256::digest(&input).as_slice());
        assert_eq!(&journal[85..117], &digest("12c105283c5f4082eb3d2ea2ab3672e3bb2fe4bce91e34e663be2927754c9f07"));
        assert_eq!(&journal[149..157], &3_437_500u64.to_le_bytes());
    }
}

fn first_selection() -> SourceTransactionSelection<'static> {
    SourceTransactionSelection {
        block_height: 1,
        transaction_index: 0,
        expected: SelectedTransactionExpectation::Digests {
            effect_id: digest("755f7c7d27a811596e9fae6dd30ca45be86e901d499909de35b6ff1f699f7ef3"),
            auth_digest: [0xff; 32],
        },
    }
}

#[test]
fn exact_independently_supplied_canonical_bytes_preserve_the_existing_journal() {
    let input = complete_history();
    let expected = replay_framed_testnet(&mut input.as_slice(), 11, 17_920).unwrap();
    let selection = SourceTransactionSelection {
        expected: SelectedTransactionExpectation::CanonicalBytes(&BLOCKS[0][1488..]),
        ..first_selection()
    };
    let evidence = replay_selected_testnet(&mut input.as_slice(), 11, 17_920, selection).unwrap();
    assert_eq!(evidence.transaction_bytes(), &BLOCKS[0][1488..]);
    assert_eq!(evidence.boundary_journal(), &expected);
    assert!(!format!("{evidence:?}").contains("755f7c7d"));
}

#[test]
fn authentic_genesis_selection_uses_the_authenticated_base_case_not_a_checkpoint() {
    let input = framed(&[GENESIS]);
    let selection = SourceTransactionSelection {
        block_height: 0,
        transaction_index: 0,
        expected: SelectedTransactionExpectation::Digests {
            effect_id: digest("db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4"),
            auth_digest: [0xff; 32],
        },
    };
    let evidence = replay_selected_testnet(&mut input.as_slice(), 1, 1700, selection).unwrap();
    assert_eq!(evidence.block().height(), 0);
    assert_eq!(evidence.block().hash(), digest("382c4a332661c7ed0671f32a34d724619f086c61873bce7c99859dd9920aa605"));
    assert_eq!(evidence.block().cumulative_work(), U256::from(32));
    assert_eq!(evidence.transaction_bytes(), &GENESIS[1488..]);
    assert_eq!(&evidence.boundary_journal()[149..213], &[0; 64]);
}

#[test]
fn missing_height_and_index_never_return_a_different_occurrence() {
    let input = complete_history();
    let absent = [
        SourceTransactionSelection { block_height: 11, ..first_selection() },
        SourceTransactionSelection { block_height: u32::MAX, ..first_selection() },
        SourceTransactionSelection { transaction_index: 1, ..first_selection() },
        SourceTransactionSelection { transaction_index: u32::MAX, ..first_selection() },
        SourceTransactionSelection { block_height: 0, transaction_index: 1, ..first_selection() },
    ];
    for selection in absent {
        assert_eq!(
            replay_selected_testnet(&mut input.as_slice(), 11, 17_920, selection).unwrap_err(),
            SourceSelectionError::SelectionNotFound,
        );
    }
    let wrong_height = SourceTransactionSelection { block_height: 2, ..first_selection() };
    assert_eq!(
        replay_selected_testnet(&mut input.as_slice(), 11, 17_920, wrong_height).unwrap_err(),
        SourceSelectionError::SelectionMismatch,
    );
}

#[test]
fn both_identities_are_required_even_when_the_effect_identity_matches() {
    let input = framed(&[GENESIS, BLOCKS[0]]);
    let effect = digest("755f7c7d27a811596e9fae6dd30ca45be86e901d499909de35b6ff1f699f7ef3");
    let wrong = [
        SelectedTransactionExpectation::Digests { effect_id: [0; 32], auth_digest: [0xff; 32] },
        SelectedTransactionExpectation::Digests { effect_id: effect, auth_digest: [0; 32] },
        SelectedTransactionExpectation::Digests { effect_id: effect, auth_digest: effect },
    ];
    for expected in wrong {
        let selection = SourceTransactionSelection { expected, ..first_selection() };
        assert_eq!(
            replay_selected_testnet(&mut input.as_slice(), 2, input.len() as u64, selection).unwrap_err(),
            SourceSelectionError::SelectionMismatch,
        );
    }
}

#[test]
fn canonical_selected_bytes_reject_substitution_suffix_and_resource_overflow() {
    let input = framed(&[GENESIS, BLOCKS[0]]);
    let mut substituted = BLOCKS[0][1488..].to_vec();
    substituted[50] ^= 1;
    let mut trailing = BLOCKS[0][1488..].to_vec();
    trailing.push(0);
    for bytes in [&substituted[..], &trailing[..], &BLOCKS[1][1488..]] {
        let selection = SourceTransactionSelection {
            expected: SelectedTransactionExpectation::CanonicalBytes(bytes),
            ..first_selection()
        };
        assert_eq!(
            replay_selected_testnet(&mut input.as_slice(), 2, input.len() as u64, selection).unwrap_err(),
            SourceSelectionError::SelectionMismatch,
        );
    }
    let oversized = vec![0; 2_000_001];
    for bytes in [&[][..], oversized.as_slice()] {
        let selection = SourceTransactionSelection {
            expected: SelectedTransactionExpectation::CanonicalBytes(bytes),
            ..first_selection()
        };
        let mut reader = input.as_slice();
        assert_eq!(
            replay_selected_testnet(&mut reader, 2, input.len() as u64, selection).unwrap_err(),
            SourceSelectionError::InvalidSelection,
        );
        assert_eq!(reader.len(), input.len());
    }
}

#[test]
fn late_invalid_history_and_incomplete_framing_publish_no_selected_evidence() {
    let input = complete_history();
    let mut invalid = input.clone();
    invalid[input.len() - 1618 + 1488 + 50] ^= 1;
    assert_eq!(
        replay_selected_testnet(&mut invalid.as_slice(), 11, 17_920, first_selection()).unwrap_err(),
        SourceSelectionError::Replay(SourceReplayError::InvalidTransition),
    );
    assert_eq!(
        replay_selected_testnet(&mut &input[..input.len() - 1], 11, 17_920, first_selection()).unwrap_err(),
        SourceSelectionError::Replay(SourceReplayError::InvalidFraming),
    );
    let mut missing = input.clone();
    missing[..4].copy_from_slice(&12u32.to_le_bytes());
    assert_eq!(
        replay_selected_testnet(&mut missing.as_slice(), 12, u64::MAX, first_selection()).unwrap_err(),
        SourceSelectionError::Replay(SourceReplayError::InvalidFraming),
    );
    let mut trailing = input.clone();
    trailing.push(0);
    assert_eq!(
        replay_selected_testnet(&mut trailing.as_slice(), 11, 17_920, first_selection()).unwrap_err(),
        SourceSelectionError::Replay(SourceReplayError::TrailingBytes),
    );
    // Even a request not found must not turn a corrupt history into mere absence.
    let absent = SourceTransactionSelection { block_height: 11, ..first_selection() };
    assert_eq!(
        replay_selected_testnet(&mut invalid.as_slice(), 11, 17_920, absent).unwrap_err(),
        SourceSelectionError::Replay(SourceReplayError::InvalidTransition),
    );
}

#[test]
fn genuine_isolated_late_body_cannot_be_imported_as_a_selected_checkpoint() {
    let later = include_bytes!("fixtures/testnet-nu5-block-1842467.bin");
    let input = framed(&[GENESIS, later]);
    let selection = SourceTransactionSelection {
        block_height: 1_842_467,
        transaction_index: 1,
        expected: SelectedTransactionExpectation::CanonicalBytes(
            include_bytes!("fixtures/orchard-pure-testnet-1842467.bin"),
        ),
    };
    assert_eq!(
        replay_selected_testnet(&mut input.as_slice(), 2, input.len() as u64, selection).unwrap_err(),
        SourceSelectionError::Replay(SourceReplayError::InvalidTransition),
    );
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
fn short_reads_and_interrupted_final_probe_return_only_the_completed_boundary() {
    let input = complete_history();
    for chunk in [1, 7] {
        let interrupts = [0, 4, 8, 1700, input.len()];
        let mut reader = Fragmented { input: &input, position: 0, chunk, interrupts: &interrupts, fail_at: None };
        let evidence = replay_selected_testnet(&mut reader, 11, 17_920, first_selection()).unwrap();
        assert_eq!(reader.position, input.len());
        assert!(reader.interrupts.is_empty());
        assert_eq!(evidence.transaction_bytes(), &BLOCKS[0][1488..]);
        assert_eq!(&evidence.boundary_journal()[81..85], &10u32.to_le_bytes());
    }
}

#[test]
fn reader_error_at_final_eof_returns_no_evidence_and_reveals_no_io_data() {
    let input = complete_history();
    for fail_at in [4, 8, input.len()] {
        let mut reader = Fragmented { input: &input, position: 0, chunk: 7, interrupts: &[], fail_at: Some(fail_at) };
        let error = replay_selected_testnet(&mut reader, 11, 17_920, first_selection()).unwrap_err();
        assert_eq!(error, SourceSelectionError::Replay(SourceReplayError::InputUnavailable));
        assert!(!error.to_string().contains("private-input-sentinel"));
        assert!(!format!("{error:?}").contains("private-input-sentinel"));
    }
}

#[test]
fn selection_preserves_replay_count_policy_budget_and_declared_frame_failures() {
    let input = framed(&[GENESIS, BLOCKS[0]]);
    let cases = [
        (0, input.len() as u64, SourceReplayError::InvalidPolicy),
        (4_465_027, input.len() as u64, SourceReplayError::InvalidPolicy),
        (2, 0, SourceReplayError::InvalidPolicy),
        (1, input.len() as u64, SourceReplayError::LimitExceeded),
        (2, input.len() as u64 - 1, SourceReplayError::LimitExceeded),
    ];
    for (max_blocks, max_bytes, expected) in cases {
        assert_eq!(
            replay_selected_testnet(&mut input.as_slice(), max_blocks, max_bytes, first_selection()).unwrap_err(),
            SourceSelectionError::Replay(expected),
        );
    }
    let mut zero_count = input.clone();
    zero_count[..4].fill(0);
    assert_eq!(
        replay_selected_testnet(&mut zero_count.as_slice(), 2, u64::MAX, first_selection()).unwrap_err(),
        SourceSelectionError::Replay(SourceReplayError::InvalidFraming),
    );
    let mut no_genesis = framed(&[BLOCKS[0]]);
    assert_eq!(
        replay_selected_testnet(&mut no_genesis.as_slice(), 1, u64::MAX, first_selection()).unwrap_err(),
        SourceSelectionError::Replay(SourceReplayError::InvalidGenesis),
    );
    no_genesis = framed(&[GENESIS]);
    no_genesis[..4].copy_from_slice(&2u32.to_le_bytes());
    no_genesis.extend_from_slice(&2_000_001u32.to_le_bytes());
    assert_eq!(
        replay_selected_testnet(&mut no_genesis.as_slice(), 2, u64::MAX, first_selection()).unwrap_err(),
        SourceSelectionError::Replay(SourceReplayError::LimitExceeded),
    );
}
