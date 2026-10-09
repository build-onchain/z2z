//! Complete genesis-connected bodies 1..=10, not all-era history or financial authority.

use primitive_types::U256;
use ziquid_proofs::{
    genesis::{ShieldedPool, bootstrap_testnet_genesis, ledger::{SproutLedgerError, SproutTestnetLedger}},
    history::BodyError,
};

const GENESIS: &[u8; 1692] = include_bytes!("fixtures/testnet-genesis.bin");

// Complete, unmodified primary bodies (not the existing header-only fixtures):
// https://raw.githubusercontent.com/ZcashFoundation/zebra/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-test/src/vectors/block-test-0-000-NNN.txt
// NNN is 001..010 below. Each HTTPS response was bounded to 65536 bytes;
// each original 3237-byte hex text, INCLUDING its newline, was authenticated as
// SHA1("blob 3237\0" || original_text) BEFORE decoding its 1618 complete bytes.
// height: original Git blob; decoded complete-body SHA256
// 1: eba9b29d12cb6cb13bd3439cdf6dc38700af738d; fc1f80eeaa5b19d9907d761ca7892a32f828d8199de25aff0df32af60ce1a4d7
// 2: 8b3dc0c430763a5a188764c512902cbad75d53f4; cb024b260bc78922bcbd803d11bbdaf634e55050ce543f231c5a78e3639ad4c2
// 3: 4dfb2a5e998e53bc2c3164174300ed397ed4baf1; b40234a77ab577bba06c5426df746eef269d00ac3083127e727495e806d735af
// 4: 11fbb61df4de7e28a3a8fda85d62156caba55646; 5b0852a8a7cb250d9e49109e71034c75f8ee6b67e8f5513e01bd9566eac1928f
// 5: 775e8fc49d8f30413c4b7f95ab0f385c0473cb86; dfddfbc62ac416ce91fe6cf30dc9193c07785ca911d4bcc082f44a0ac2693278
// 6: cae5abab04993d56a7ac9c05f1476b4d21f9164e; 6b228fbe4403c35b94e8f48fc4e3f4348a4616fe84ed65d94df4161162d51737
// 7: c9fa50efd35cec49ef6e754ae0533484fdfc7a77; 63ad11574af0c6470298fcca2822fba7571eb99286a13b7a151b1b8aecbe8d05
// 8: 5d562addc06bf1740558c62047c76a815772622b; 84ca928dbff678bf0ee3229e404607f6b38ba3ca9dace202f560d393ca0ad1e8
// 9: 5f5b4d9cd99993a3097c455d978c2cf2e6151213; 78642815295eebde24734bbd1367710d5f570f1667bb1cf94e862627972305d7
// 10: 75df3c1ec51f26628c99910d2c90e1e495cecadb; 5e17fd1b5fd5bfebc16a2930ae863db080b3a13e70435acb146c847aa6d4791f
const BLOCKS: [&[u8; 1618]; 10] = [
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

// Primary coinbase SHA256d identities in internal/wire order; scripts and amounts
// were decoded independently from the authenticated complete texts above.
const COINBASE_TXIDS: [&str; 10] = [
    "755f7c7d27a811596e9fae6dd30ca45be86e901d499909de35b6ff1f699f7ef3",
    "d5b3ccfd5e7828c4b2d221bae3178c500e21d33399c39a2508a0a82d53c02258",
    "50953b3d2510d8708ca94daf3daf9a220997fa8a0c892334f9aea314f8f33b4a",
    "0bf847a21ad1ce24a12ea04cb38029e592dbdfb58d78d810f33011eb6ded7333",
    "ee7bcc689bc163057062897c62e689c396a9fe9288d7b9399e0a58c2f7806447",
    "ab572c332b8774335745715c260810ed0713cfecaceadf09eb5f828d40f8da23",
    "f21731288dc961bc400ecc1f70099b0bb4b887bb319a51199c81597100bdae47",
    "43a443c43f281258a8aba067ddb775c1423ffdecf0007273d8c908e22b98f829",
    "1c78590780f87bccbc7eb483f92fce9f2236c3c3cb729461a02af7f5dc40ec9e",
    "2edaa1188cc82324f77ab6c52d37a30c2837b4c985681beae1256c321b188738",
];
const MINER_SCRIPTS: [&str; 10] = [
    "21025229e1240a21004cf8338db05679fa34753706e84f6aebba086ba04317fd8f99ac",
    "2102acce9f6c16986c525fd34759d851ef5b4b85b5019a57bd59747be0ef1ba62523ac",
    "2102b24776315475d2db96268d6f60cf66db445a3c50f6a3a7a2cb07be45e87b8346ac",
    "210387c8c8f56c95c1a8d40efb54db56158fcdeb5a26a8f57d8be47b7b826223bf76ac",
    "2102171c07a26a7b7f5e8fed66755b01b0ad0d36121ef1979679ca4bddc29da664b9ac",
    "2103aa3e2d213d453dab046457a98d908e81b8e79ee71bb400e3b1868844d85de054ac",
    "2103b5ca53d1dbbc1f9896f3a5fd59715d066f98cecc1f15dfc33d0762f8409e29ddac",
    "21035e017ce17274f75539e35e93ffaae48b91c2cbdf1a982fe37a7ff0e97cac9b19ac",
    "2103aa5dc719593db872a724acc3b73f1aa9b9f27ef495732a610ba1a1c7a26bbbefac",
    "2103a42464b10ec3441beddd662ba25898dd244e7dacc4f06c01a23af82decf95759ac",
];
const FOUNDERS_SCRIPT: &str = "a914ef775f1f997f122a062fff1a2d7443abd1f9c64287";
const BALANCES: [u64; 10] = [
    62_500, 187_500, 375_000, 625_000, 937_500,
    1_312_500, 1_750_000, 2_250_000, 2_812_500, 3_437_500,
];

fn hex(hex: &str) -> Vec<u8> {
    hex.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid pinned fixture hex"),
        };
        digit(pair[0]) * 16 + digit(pair[1])
    }).collect()
}

fn txid(height: usize) -> [u8; 32] {
    hex(COINBASE_TXIDS[height - 1]).try_into().unwrap()
}

fn ledger() -> SproutTestnetLedger {
    SproutTestnetLedger::from_genesis(bootstrap_testnet_genesis(GENESIS).unwrap())
}

fn assert_outputs(state: &SproutTestnetLedger, through_height: usize) {
    for height in 1..=through_height {
        let id = txid(height);
        let miner = state.utxo(&id, 0).expect("actual miner outpoint retained");
        assert_eq!(u64::from(miner.output().value()), 50_000 * u64::try_from(height).unwrap());
        assert_eq!(miner.output().script_pubkey().0.0, hex(MINER_SCRIPTS[height - 1]));
        assert_eq!(miner.created_height(), u32::try_from(height).unwrap());
        assert!(miner.is_coinbase());
        let founders = state.utxo(&id, 1).expect("actual Founders outpoint retained");
        assert_eq!(u64::from(founders.output().value()), 12_500 * u64::try_from(height).unwrap());
        assert_eq!(founders.output().script_pubkey().0.0, hex(FOUNDERS_SCRIPT));
        assert_eq!(founders.created_height(), u32::try_from(height).unwrap());
        assert!(founders.is_coinbase());
        assert!(state.utxo(&id, 2).is_none());
    }
}

#[test]
fn complete_primary_bodies_create_exact_owned_outputs_and_parent_derived_history() {
    let genesis = bootstrap_testnet_genesis(GENESIS).unwrap();
    let genesis_coinbase = genesis.coinbase_txid();
    let pools = [ShieldedPool::Sprout, ShieldedPool::Sapling, ShieldedPool::Orchard, ShieldedPool::Ironwood];
    let roots = pools.map(|pool| genesis.shielded_root(pool));
    let mut state = SproutTestnetLedger::from_genesis(genesis);
    for (index, raw) in BLOCKS.iter().enumerate() {
        let tip = state.apply_block(*raw).unwrap();
        let height = index + 1;
        assert_eq!(tip.height(), u32::try_from(height).unwrap());
        assert_eq!(tip.cumulative_work(), U256::from(32 * (height + 1)));
        assert_eq!(state.tip(), tip);
        assert_eq!(state.utxo_balance(), BALANCES[index]);
        assert_eq!(state.transparent_balance(), BALANCES[index]);
        assert_eq!(state.issued_supply(), BALANCES[index]);
        assert_outputs(&state, height);
        assert!(state.utxo(&genesis_coinbase, 0).is_none());
    }
    assert_eq!(state.utxo_count(), 20);
    assert_eq!(state.tip().hash().as_slice(), hex("12c105283c5f4082eb3d2ea2ab3672e3bb2fe4bce91e34e663be2927754c9f07"));
    for (pool, root) in pools.into_iter().zip(roots) {
        assert_eq!(state.shielded_root(pool), root);
        assert_eq!(state.shielded_balance(pool), 0);
        assert_eq!(state.nullifier_count(pool), 0);
        assert!(!state.contains_nullifier(pool, &[0; 32]));
        assert_eq!(state.pool_is_active(pool), pool == ShieldedPool::Sprout);
    }
    assert_eq!(state.sprout_tree_size(), 0);
    assert_eq!(state.deferred_balance(), 0);
    assert_eq!(state.history_root(), None);
}

#[test]
fn wrong_order_replay_and_wrong_merkle_body_leave_outputs_and_next_transition_unchanged() {
    let mut state = ledger();
    let base = state.tip();
    assert!(state.apply_block(BLOCKS[1]).is_err());
    assert_eq!(state.tip(), base);
    assert_eq!(state.utxo_balance(), 0);
    assert_eq!(state.deferred_balance(), 0);
    assert!(state.utxo(&txid(2), 0).is_none());
    state.apply_block(BLOCKS[0]).unwrap();
    let first = state.tip();
    let mut wrong_merkle = BLOCKS[1].to_vec();
    // Alter an actual output amount while retaining the authentic mined header.
    wrong_merkle[1488 + 50] ^= 1;
    assert_eq!(state.apply_block(&wrong_merkle), Err(SproutLedgerError::Body(BodyError::MerkleRootMismatch)));
    assert!(state.apply_block(BLOCKS[0]).is_err());
    assert_eq!(state.tip(), first);
    assert_eq!(state.utxo_balance(), 62_500);
    assert_eq!(state.transparent_balance(), 62_500);
    assert_eq!(state.issued_supply(), 62_500);
    assert_eq!(state.deferred_balance(), 0);
    assert_outputs(&state, 1);
    assert!(state.utxo(&txid(2), 0).is_none());
    assert_eq!(state.apply_block(BLOCKS[1]).unwrap().height(), 2);
    assert_eq!(state.utxo_balance(), 187_500);
    assert_outputs(&state, 2);
}

#[test]
fn incomplete_noncanonical_suffix_and_hostile_header_bodies_never_partially_commit() {
    let mut state = ledger();
    state.apply_block(BLOCKS[0]).unwrap();
    let before = state.tip();
    let mut cases = Vec::new();
    for length in [0, 1487, 1488, 1530, 1617] {
        cases.push(BLOCKS[1][..length].to_vec());
    }
    let mut suffix = BLOCKS[1].to_vec();
    suffix.push(0);
    cases.push(suffix);
    let mut noncanonical_count = BLOCKS[1].to_vec();
    noncanonical_count.splice(1487..1488, [0xfd, 1, 0]);
    cases.push(noncanonical_count);
    for offset in [4, 36, 100, 104, 108, 143, 1486] {
        let mut mutation = BLOCKS[1].to_vec();
        mutation[offset] ^= 1;
        cases.push(mutation);
    }
    for candidate in cases {
        assert!(state.apply_block(&candidate).is_err());
        assert_eq!(state.tip(), before);
        assert_eq!(state.utxo_balance(), 62_500);
        assert_eq!(state.transparent_balance(), 62_500);
        assert_eq!(state.issued_supply(), 62_500);
        assert_eq!(state.deferred_balance(), 0);
        assert_outputs(&state, 1);
        assert!(state.utxo(&txid(2), 0).is_none());
    }
    state.apply_block(BLOCKS[1]).unwrap();
    assert_eq!(state.utxo_balance(), 187_500);
    assert_outputs(&state, 2);
}

#[test]
fn an_extra_spend_or_oversized_complete_body_is_rejected_without_ignored_transactions() {
    use sha2::{Digest, Sha256};

    let mut state = ledger();
    let base = state.tip();
    let oversized = vec![0; 2_000_001];
    assert_eq!(state.apply_block(&oversized), Err(SproutLedgerError::Body(BodyError::BlockTooLarge)));
    // A structurally complete local mutation, NOT a mined block: there is no
    // fake header acceptance or recomputed PoW. The altered Merkle root is not
    // covered by the original mined Equihash solution; no state may commit.
    let mut extra = BLOCKS[1][1488..].to_vec();
    extra[5..37].copy_from_slice(&txid(1));
    extra[37..41].copy_from_slice(&0_u32.to_le_bytes());
    extra[50..58].copy_from_slice(&10_000_u64.to_le_bytes());
    extra[94..102].copy_from_slice(&10_000_u64.to_le_bytes());
    let extra_id = Sha256::digest(Sha256::digest(&extra));
    let mut root = Sha256::new();
    root.update(txid(1));
    root.update(extra_id);
    let root = Sha256::digest(root.finalize());
    let mut two_transactions = BLOCKS[0].to_vec();
    two_transactions[36..68].copy_from_slice(&root);
    two_transactions[1487] = 2;
    two_transactions.extend_from_slice(&extra);
    assert!(matches!(state.apply_block(&two_transactions), Err(SproutLedgerError::Header(_))));
    assert_eq!(state.tip(), base);
    assert_eq!(state.utxo_balance(), 0);
    assert_eq!(state.transparent_balance(), 0);
    assert_eq!(state.issued_supply(), 0);
    assert_eq!(state.deferred_balance(), 0);
    assert!(state.utxo(&txid(1), 0).is_none());
    state.apply_block(BLOCKS[0]).unwrap();
    assert_outputs(&state, 1);
}
