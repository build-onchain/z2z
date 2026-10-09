#![no_main]

// Compile the exact native ledger and crypto; genesis includes its ledger child.
#[path = "../../../src/canonical_bytes.rs"]
mod canonical_bytes;
#[path = "../../../src/genesis.rs"]
mod genesis;
#[path = "../../../src/header.rs"]
mod header;
#[path = "../../../src/history.rs"]
mod history;
#[path = "../../../src/legacy_sighash.rs"]
mod legacy_sighash;
#[path = "../../../src/legacy_joinsplit.rs"]
mod legacy_joinsplit;
#[path = "../../../src/overwinter.rs"]
mod overwinter;
#[path = "../../../src/sprout.rs"]
mod sprout;
#[path = "../../../src/sapling_sighash.rs"]
mod sapling_sighash;
#[path = "../../../src/sprout_groth16.rs"]
mod sprout_groth16;
#[path = "../../../src/sapling_crypto.rs"]
mod sapling_crypto;
#[path = "../../../src/chain_history.rs"]
mod chain_history;
#[path = "../../../src/sapling_coinbase.rs"]
mod sapling_coinbase;
#[path = "../../../src/post_nu5_body.rs"]
mod post_nu5_body;
#[path = "../../../src/raw_v5.rs"]
mod raw_v5;
#[path = "../../../src/zip244.rs"]
mod zip244;
#[path = "../../../src/orchard_original.rs"]
mod orchard_original;

use genesis::{ShieldedPool, bootstrap_testnet_genesis, ledger::SproutTestnetLedger};
use sha2::{Digest, Sha256};

const JOURNAL_DOMAIN: &[u8] = b"ziquid/sprout-through-nu63-ledger/subrelation/v11";
const JOURNAL_LENGTH: usize = JOURNAL_DOMAIN.len() + 32 + 4 + 32 + 32 + 8 * 8 + 32 * 4 + 1 + 32;
const MAX_BLOCK_BYTES: usize = 2_000_000;

sp1_zkvm::entrypoint!(main);

fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize) -> &'a [u8] {
    let end = offset.checked_add(length).expect("frame offset overflow");
    let bytes = input.get(*offset..end).expect("truncated framed input");
    *offset = end;
    bytes
}

fn read_u32(input: &[u8], offset: &mut usize) -> u32 {
    u32::from_le_bytes(take(input, offset, 4).try_into().unwrap())
}

fn read_block<'a>(input: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let length = usize::try_from(read_u32(input, offset)).expect("block length overflow");
    assert!(length <= MAX_BLOCK_BYTES, "block exceeds platform bound");
    take(input, offset, length)
}

pub fn main() {
    // One witness buffer; complete bodies remain borrowed until the shared parser.
    let input = sp1_zkvm::io::read_vec();
    let mut offset = 0;
    let count = usize::try_from(read_u32(&input, &mut offset)).expect("block count overflow");
    assert!(count >= 1, "missing genesis");
    assert!(
        count <= (input.len() - offset) / 4,
        "block count exceeds available frame prefixes"
    );
    let genesis = read_block(&input, &mut offset);
    assert_eq!(genesis.len(), 1692, "wrong complete genesis length");
    let genesis = bootstrap_testnet_genesis(genesis).expect("invalid authentic testnet genesis");
    let mut ledger = SproutTestnetLedger::from_genesis(genesis);
    for _ in 1..count {
        ledger
            .apply_block(read_block(&input, &mut offset))
            .expect("complete finite source ledger transition failed");
    }
    assert_eq!(offset, input.len(), "trailing bytes after framed blocks");

    let input_digest = Sha256::digest(&input);
    let tip = ledger.tip();
    let height = tip.height().to_le_bytes();
    let hash = tip.hash();
    let mut work = [0u8; 32];
    tip.cumulative_work().to_big_endian(&mut work);
    let transparent = ledger.transparent_balance().to_le_bytes();
    let sprout = ledger.shielded_balance(ShieldedPool::Sprout).to_le_bytes();
    let sapling = ledger.shielded_balance(ShieldedPool::Sapling).to_le_bytes();
    let orchard = ledger.shielded_balance(ShieldedPool::Orchard).to_le_bytes();
    let ironwood = ledger.shielded_balance(ShieldedPool::Ironwood).to_le_bytes();
    let deferred = ledger.deferred_balance().to_le_bytes();
    let issued = ledger.issued_supply().to_le_bytes();
    let utxos = ledger.utxo_balance().to_le_bytes();
    let root = ledger.shielded_root(ShieldedPool::Sprout);
    let sapling_root = ledger.shielded_root(ShieldedPool::Sapling);
    let orchard_root = ledger.shielded_root(ShieldedPool::Orchard);
    let ironwood_root = ledger.shielded_root(ShieldedPool::Ironwood);
    let history_root = ledger.history_root();
    let history_present = [u8::from(history_root.is_some())];
    let history_root = history_root.unwrap_or([0; 32]);

    // Finite ledger subrelation, not all-era acceptance or financial truth.
    let mut journal = [0u8; JOURNAL_LENGTH];
    let mut remaining = journal.as_mut_slice();
    for field in [
        JOURNAL_DOMAIN,
        &input_digest[..],
        &height,
        &hash,
        &work,
        &transparent,
        &sprout,
        &sapling,
        &orchard,
        &ironwood,
        &deferred,
        &issued,
        &utxos,
        &root,
        &sapling_root,
        &orchard_root,
        &ironwood_root,
        &history_present,
        &history_root,
    ] {
        let (destination, rest) = remaining.split_at_mut(field.len());
        destination.copy_from_slice(field);
        remaining = rest;
    }
    assert!(remaining.is_empty(), "incorrect journal layout");
    // No public bytes are committed until all bodies and framing have passed.
    sp1_zkvm::io::commit_slice(&journal);
}
