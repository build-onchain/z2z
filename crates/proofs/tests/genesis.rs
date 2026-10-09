//! The authentic fixed bootstrap is not a proof of later source history or finality.

use primitive_types::U256;
use zcash_protocol::consensus::{BranchId, NetworkType};
use ziquid_proofs::genesis::{GenesisError, ShieldedPool, bootstrap_testnet_genesis};

// Immutable primary bytes: Zebra commit e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291,
// https://github.com/ZcashFoundation/zebra/blob/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-test/src/vectors/block-test-0-000-000.txt
// Decoded from hex without constructing or modifying any block fields.
// Header SHA256d, reversed for display:
// 05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38.
// Coinbase SHA256d, reversed for display:
// c4eaa58879081de3c24a7b117ed2b28300e7ec4c4c1dff1d3f1268b7857a4ddb.
// Full binary SHA256: bfd4c0ec211b5c9d28f92ade509651528259dddd81b9edd96f868779edaba8f6.
// zcashd v6.11.0 src/chainparams.cpp::CTestNetParams pins the same identities.
const GENESIS: &[u8; 1692] = include_bytes!("fixtures/testnet-genesis.bin");
const HEADER_LENGTH: usize = 1487;
const COINBASE_OFFSET: usize = HEADER_LENGTH + 1;

fn digest(hex: &str) -> [u8; 32] {
    let mut result = [0; 32];
    for (byte, pair) in result.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let value = |v: u8| match v {
            b'0'..=b'9' => v - b'0',
            b'a'..=b'f' => v - b'a' + 10,
            _ => panic!("invalid fixture hex"),
        };
        *byte = value(pair[0]) * 16 + value(pair[1]);
    }
    assert_eq!(hex.len(), 64);
    result
}

fn error(bytes: &[u8]) -> GenesisError {
    match bootstrap_testnet_genesis(bytes) {
        Ok(_) => panic!("hostile genesis accepted"),
        Err(error) => error,
    }
}

#[test]
fn authentic_primary_genesis_bootstraps_testnet_with_real_work_and_empty_ledger() {
    let state = bootstrap_testnet_genesis(GENESIS).unwrap();
    assert_eq!(state.network(), NetworkType::Test);
    assert_eq!(state.height(), 0);
    assert_eq!(state.consensus_branch(), BranchId::Sprout);
    assert_eq!(
        state.tip(),
        digest("382c4a332661c7ed0671f32a34d724619f086c61873bce7c99859dd9920aa605"),
    );
    assert_eq!(
        state.coinbase_txid(),
        digest("db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4"),
    );
    assert_eq!(state.time(), 1_477_648_033);
    assert_eq!(state.bits(), 0x2007_ffff);
    // Independently computed integer 2^256 / (0x07ffff * 2^232 + 1).
    assert_eq!(state.cumulative_work(), U256::from(32));
    // Zebra's primary sprout/tests/test_vectors.rs::HEX_EMPTY_ROOTS[29].
    assert_eq!(
        state.shielded_root(ShieldedPool::Sprout),
        digest("d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259"),
    );
    assert_eq!(state.sprout_tree_size(), 0);
    assert_eq!(state.transparent_balance(), 0);
    assert_eq!(state.deferred_balance(), 0);
    assert_eq!(state.issued_supply(), 0);
    assert_eq!(state.history_root(), None);
    assert_eq!(state.utxo_count(), 0);
    for pool in [
        ShieldedPool::Sprout,
        ShieldedPool::Sapling,
        ShieldedPool::Orchard,
        ShieldedPool::Ironwood,
    ] {
        assert_eq!(state.shielded_balance(pool), 0);
        assert_eq!(state.nullifier_count(pool), 0);
        assert!(!state.contains_nullifier(pool, &[0; 32]));
        assert_eq!(state.pool_is_active(pool), pool == ShieldedPool::Sprout);
    }
}

#[test]
fn genesis_coinbase_output_is_not_an_initial_utxo_even_though_its_value_is_zero() {
    // zcashd v6.11.0 src/main.cpp::ConnectBlock skips connecting genesis
    // transactions: the coinbase is unspendable, not an ordinary zero-valued UTXO.
    let state = bootstrap_testnet_genesis(GENESIS).unwrap();
    let outpoint_txid = digest("db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4");
    assert!(state.utxo(&outpoint_txid, 0).is_none());
    assert!(state.utxo(&[0; 32], u32::MAX).is_none());
}

#[test]
fn later_pool_roots_are_actual_empty_trees_but_not_active_anchors() {
    let state = bootstrap_testnet_genesis(GENESIS).unwrap();
    assert_eq!(
        state.shielded_root(ShieldedPool::Sapling),
        sapling_crypto::Anchor::empty_tree().to_bytes(),
    );
    let orchard_empty = orchard::Anchor::empty_tree().to_bytes();
    assert_eq!(state.shielded_root(ShieldedPool::Orchard), orchard_empty);
    assert_eq!(state.shielded_root(ShieldedPool::Ironwood), orchard_empty);
    for pool in [
        ShieldedPool::Sapling,
        ShieldedPool::Orchard,
        ShieldedPool::Ironwood,
    ] {
        assert!(!state.pool_is_active(pool));
    }
}

#[test]
fn mainnet_genesis_header_parameters_cannot_bootstrap_testnet() {
    // Authentic mainnet parameters from zcashd's CMainParams. Its coinbase is
    // identical; substituting its header context must not create testnet state.
    let mut mainnet_context = GENESIS.to_vec();
    mainnet_context[100..104].copy_from_slice(&1_477_641_360_u32.to_le_bytes());
    mainnet_context[104..108].copy_from_slice(&0x1f07_ffff_u32.to_le_bytes());
    mainnet_context[108..140].fill(0);
    mainnet_context[108..112].copy_from_slice(&0x1257_u32.to_le_bytes());
    assert_eq!(error(&mainnet_context), GenesisError::WrongGenesis);
}

#[test]
fn changed_header_and_coinbase_fields_do_not_create_arbitrary_initial_state() {
    for offset in [0, 4, 36, 68, 100, 108] {
        let mut changed = GENESIS.to_vec();
        changed[offset] ^= 1;
        assert_eq!(error(&changed), GenesisError::WrongGenesis);
    }
    // V1 input hash/index, scriptSig, sequence, output value/script and lock_time.
    for offset in [
        COINBASE_OFFSET + 5,
        COINBASE_OFFSET + 37,
        COINBASE_OFFSET + 42,
        COINBASE_OFFSET + 119,
        COINBASE_OFFSET + 124,
        COINBASE_OFFSET + 133,
        GENESIS.len() - 4,
    ] {
        let mut changed = GENESIS.to_vec();
        changed[offset] ^= 1;
        assert_eq!(error(&changed), GenesisError::InvalidCoinbase);
    }
}

#[test]
fn invalid_equihash_solution_is_actually_rejected() {
    let mut changed = GENESIS.to_vec();
    // This altered solution still satisfies numeric nBits PoW (independent
    // SHA256d display hash 01cc31e3563c7be29044ea8c7f235c4fe05f78162a8518e000d717617ca50fbc),
    // so only validating Equihash, rather than comparing the pinned hash, catches it here.
    changed[152] ^= 1;
    assert_eq!(error(&changed), GenesisError::InvalidEquihash);
}

#[test]
fn signed_zero_overflow_and_above_limit_work_targets_are_rejected() {
    for bits in [0x2087_ffff_u32, 0, 0x2300_0001, 0x2008_0000] {
        let mut changed = GENESIS.to_vec();
        changed[104..108].copy_from_slice(&bits.to_le_bytes());
        assert_eq!(error(&changed), GenesisError::InvalidTarget);
    }
}

#[test]
fn a_target_below_the_actual_header_hash_fails_proof_of_work() {
    let mut changed = GENESIS.to_vec();
    changed[104..108].copy_from_slice(&0x0101_0000_u32.to_le_bytes());
    assert_eq!(error(&changed), GenesisError::InsufficientWork);
}

#[test]
fn incomplete_extra_and_noncanonical_body_encodings_are_rejected() {
    for len in [
        0,
        107,
        142,
        HEADER_LENGTH - 1,
        COINBASE_OFFSET,
        GENESIS.len() - 1,
    ] {
        assert_eq!(error(&GENESIS[..len]), GenesisError::MalformedBlock);
    }
    let mut suffix = GENESIS.to_vec();
    suffix.push(0);
    assert_eq!(error(&suffix), GenesisError::TrailingBytes);
    let mut count = GENESIS.to_vec();
    count.splice(HEADER_LENGTH..COINBASE_OFFSET, [0xfd, 1, 0]);
    assert_eq!(error(&count), GenesisError::NoncanonicalEncoding);
    let mut input_count = GENESIS.to_vec();
    input_count.splice(COINBASE_OFFSET + 4..COINBASE_OFFSET + 5, [0xfd, 1, 0]);
    assert_eq!(error(&input_count), GenesisError::NoncanonicalEncoding);
    let mut wrong_count = GENESIS.to_vec();
    wrong_count[HEADER_LENGTH] = 2;
    assert_eq!(error(&wrong_count), GenesisError::InvalidCoinbase);
    let mut wrong_version = GENESIS.to_vec();
    wrong_version[COINBASE_OFFSET..COINBASE_OFFSET + 4].copy_from_slice(&2_u32.to_le_bytes());
    assert_eq!(error(&wrong_version), GenesisError::InvalidCoinbase);
    assert_eq!(error(&[0; 2_000_001]), GenesisError::BlockTooLarge);
}
