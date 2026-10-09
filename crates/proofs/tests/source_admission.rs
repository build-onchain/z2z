//! Host-local future-header admission, not freshness, finality, or settlement.
#![cfg(not(target_os = "zkvm"))]

use zcash_protocol::constants::MAX_BLOCK_BYTES;
use ziquid_proofs::{
    genesis::{
        ShieldedPool, bootstrap_testnet_genesis,
        ledger::{SproutLedgerError, SproutTestnetLedger},
    },
    header::{HeaderError, HeaderTip},
    history::BodyError,
    source_admission::{SourceAdmissionError, apply_block_at},
};

const GENESIS: &[u8; 1692] = include_bytes!("fixtures/testnet-genesis.bin");
const BLOCK_ONE: &[u8; 1618] = include_bytes!("fixtures/testnet-block-1.bin");
// Independent primary timestamp already pinned in tests/header.rs, not derived
// from the admission API. Complete-body provenance lives in tests/ledger.rs.
const BLOCK_ONE_TIME: u64 = 1_477_674_473;

fn ledger() -> SproutTestnetLedger {
    SproutTestnetLedger::from_genesis(bootstrap_testnet_genesis(GENESIS).unwrap())
}

fn assert_genesis_unchanged(state: &SproutTestnetLedger, before: HeaderTip) {
    let genesis = bootstrap_testnet_genesis(GENESIS).unwrap();
    assert_eq!(state.tip(), before);
    assert_eq!(state.utxo_count(), 0);
    assert_eq!(state.utxo_balance(), 0);
    assert_eq!(state.transparent_balance(), 0);
    assert_eq!(state.issued_supply(), 0);
    assert_eq!(state.deferred_balance(), 0);
    assert_eq!(state.history_root(), None);
    assert_eq!(state.sprout_tree_size(), 0);
    assert_eq!(state.sapling_tree_size(), 0);
    assert_eq!(state.orchard_tree_size(), 0);
    assert_eq!(state.ironwood_tree_size(), 0);
    for pool in [ShieldedPool::Sprout, ShieldedPool::Sapling, ShieldedPool::Orchard, ShieldedPool::Ironwood] {
        assert_eq!(state.shielded_root(pool), genesis.shielded_root(pool));
        assert_eq!(state.shielded_balance(pool), 0);
        assert_eq!(state.nullifier_count(pool), 0);
    }
}

fn assert_block_one_applied(state: &SproutTestnetLedger, tip: HeaderTip) {
    assert_eq!(tip.height(), 1);
    assert_eq!(u64::from(tip.time()), BLOCK_ONE_TIME);
    assert_eq!(state.tip(), tip);
    assert_eq!(state.utxo_count(), 2);
    assert_eq!(state.utxo_balance(), 62_500);
    assert_eq!(state.transparent_balance(), 62_500);
    assert_eq!(state.issued_supply(), 62_500);
}

#[test]
fn authentic_complete_block_at_exact_7200_future_boundary_applies_the_whole_ledger() {
    assert_eq!(u64::from(u32::from_le_bytes(BLOCK_ONE[100..104].try_into().unwrap())), BLOCK_ONE_TIME);
    let mut state = ledger();
    let tip = apply_block_at(&mut state, BLOCK_ONE, Some(BLOCK_ONE_TIME - 7200)).unwrap();
    assert_block_one_applied(&state, tip);
}

#[test]
fn authentic_7201_future_block_changes_nothing_and_can_retry_one_second_later() {
    let mut state = ledger();
    let before = state.tip();
    assert_eq!(
        apply_block_at(&mut state, BLOCK_ONE, Some(BLOCK_ONE_TIME - 7201)),
        Err(SourceAdmissionError::TimeTooFarInFuture),
    );
    assert_genesis_unchanged(&state, before);
    let tip = apply_block_at(&mut state, BLOCK_ONE, Some(BLOCK_ONE_TIME - 7200)).unwrap();
    assert_block_one_applied(&state, tip);
}

#[test]
fn missing_clock_fails_closed_without_poisoning_a_later_valid_admission() {
    let mut state = ledger();
    let before = state.tip();
    assert_eq!(apply_block_at(&mut state, BLOCK_ONE, None), Err(SourceAdmissionError::ClockUnavailable));
    assert_genesis_unchanged(&state, before);
    let tip = apply_block_at(&mut state, BLOCK_ONE, Some(BLOCK_ONE_TIME)).unwrap();
    assert_block_one_applied(&state, tip);
}

#[test]
fn maximum_local_unix_time_does_not_overflow_or_impose_a_lower_age_bound() {
    let mut state = ledger();
    let tip = apply_block_at(&mut state, BLOCK_ONE, Some(u64::MAX)).unwrap();
    assert_block_one_applied(&state, tip);
}

#[test]
fn empty_oversize_truncated_and_noncanonical_headers_reject_before_body_validation() {
    let mut state = ledger();
    let before = state.tip();
    for raw in [&[][..], vec![0; MAX_BLOCK_BYTES + 1].as_slice()] {
        assert_eq!(apply_block_at(&mut state, raw, Some(BLOCK_ONE_TIME)), Err(SourceAdmissionError::InvalidBlockSize));
        assert_genesis_unchanged(&state, before);
    }
    for length in [1, 100, 140, 1486] {
        assert_eq!(apply_block_at(&mut state, &BLOCK_ONE[..length], Some(BLOCK_ONE_TIME)), Err(SourceAdmissionError::InvalidHeader));
        assert_genesis_unchanged(&state, before);
    }
    for prefix in [&[0xfd, 0x3f, 0x05][..], &[0xfe, 0x40, 0x05, 0, 0], &[0xff; 9]] {
        let mut raw = BLOCK_ONE.to_vec();
        raw[140..140 + prefix.len()].copy_from_slice(prefix);
        assert_eq!(apply_block_at(&mut state, &raw, Some(BLOCK_ONE_TIME)), Err(SourceAdmissionError::InvalidHeader));
        assert_genesis_unchanged(&state, before);
    }
    let tip = apply_block_at(&mut state, BLOCK_ONE, Some(BLOCK_ONE_TIME)).unwrap();
    assert_block_one_applied(&state, tip);
}

#[test]
fn future_time_guard_precedes_malformed_body_and_equihash_checks() {
    let mut state = ledger();
    let before = state.tip();
    let mut invalid_equihash = BLOCK_ONE.to_vec();
    invalid_equihash[143] ^= 1;
    for raw in [&BLOCK_ONE[..1487], invalid_equihash.as_slice()] {
        assert_eq!(apply_block_at(&mut state, raw, Some(BLOCK_ONE_TIME - 7201)), Err(SourceAdmissionError::TimeTooFarInFuture));
        assert_genesis_unchanged(&state, before);
    }
    assert_eq!(
        apply_block_at(&mut state, &BLOCK_ONE[..1487], Some(BLOCK_ONE_TIME)),
        Err(SourceAdmissionError::Ledger(SproutLedgerError::Body(BodyError::MalformedBlock))),
    );
    assert_genesis_unchanged(&state, before);
    assert_eq!(
        apply_block_at(&mut state, &invalid_equihash, Some(BLOCK_ONE_TIME)),
        Err(SourceAdmissionError::Ledger(SproutLedgerError::Header(HeaderError::InvalidEquihash))),
    );
    assert_genesis_unchanged(&state, before);
    let tip = apply_block_at(&mut state, BLOCK_ONE, Some(BLOCK_ONE_TIME)).unwrap();
    assert_block_one_applied(&state, tip);
}

#[test]
fn trailing_bytes_bad_merkle_body_and_exact_size_bound_preserve_state() {
    let mut state = ledger();
    let before = state.tip();
    let mut trailing = BLOCK_ONE.to_vec();
    trailing.push(0);
    let mut wrong_merkle = BLOCK_ONE.to_vec();
    wrong_merkle[1488 + 50] ^= 1;
    let mut at_limit = BLOCK_ONE.to_vec();
    at_limit.resize(MAX_BLOCK_BYTES, 0);
    for (raw, expected) in [
        (trailing.as_slice(), BodyError::TrailingBytes),
        (wrong_merkle.as_slice(), BodyError::MerkleRootMismatch),
        (at_limit.as_slice(), BodyError::TrailingBytes),
    ] {
        assert_eq!(
            apply_block_at(&mut state, raw, Some(BLOCK_ONE_TIME)),
            Err(SourceAdmissionError::Ledger(SproutLedgerError::Body(expected))),
        );
        assert_genesis_unchanged(&state, before);
    }
    let tip = apply_block_at(&mut state, BLOCK_ONE, Some(BLOCK_ONE_TIME)).unwrap();
    assert_block_one_applied(&state, tip);
}

#[test]
fn historical_deterministic_ledger_replay_remains_clock_free() {
    let mut state = ledger();
    let tip = state.apply_block(BLOCK_ONE).unwrap();
    assert_block_one_applied(&state, tip);
}
