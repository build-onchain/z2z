//! Authentic testnet height-zero bootstrap, not later history validity or finality.
//!
//! Network identities and coinbase semantics follow zcashd's
//! `chainparams.cpp::{CreateGenesisBlock,CTestNetParams}`. The complete primary
//! vector is pinned in `tests/genesis.rs` to Zebra commit
//! e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291. No caller supplies a ledger snapshot,
//! network selection, source-validity flag, or successor transition.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use corez::io;
use incrementalmerkletree::{Hashable, Level, frontier::Frontier};
use primitive_types::U256;
use zcash_encoding::CompactSize;
use zcash_primitives::{
    block::{BlockHeader, equihash},
    transaction::{Transaction, TxVersion},
};
use zcash_protocol::{
    consensus::{BranchId, NetworkType},
    constants::MAX_BLOCK_BYTES,
};

use crate::history::CanonicalBytes;

#[path = "ledger.rs"]
pub mod ledger;

pub(crate) const TESTNET_POW_LIMIT: U256 =
    U256([u64::MAX, u64::MAX, u64::MAX, 0x07ff_ffff_ffff_ffff]);

const GENESIS_HASH: [u8; 32] = [
    0x38, 0x2c, 0x4a, 0x33, 0x26, 0x61, 0xc7, 0xed, 0x06, 0x71, 0xf3, 0x2a, 0x34, 0xd7, 0x24, 0x61,
    0x9f, 0x08, 0x6c, 0x61, 0x87, 0x3b, 0xce, 0x7c, 0x99, 0x85, 0x9d, 0xd9, 0x92, 0x0a, 0xa6, 0x05,
];
const COINBASE_TXID: [u8; 32] = [
    0xdb, 0x4d, 0x7a, 0x85, 0xb7, 0x68, 0x12, 0x3f, 0x1d, 0xff, 0x1d, 0x4c, 0x4c, 0xec, 0xe7, 0x00,
    0x83, 0xb2, 0xd2, 0x7e, 0x11, 0x7b, 0x4a, 0xc2, 0xe3, 0x1d, 0x08, 0x79, 0x88, 0xa5, 0xea, 0xc4,
];
const COINBASE_SCRIPT_SIG: &[u8] =
    b"\x04\xff\xff\x07\x1f\x01\x04\x45Zcash0b9c4eef8b7cc417ee5001e3500984b6fea35683a7cac141a043c42064835d34";
const COINBASE_SCRIPT_PUBKEY: &[u8] = &[
    0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30,
    0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61,
    0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1,
    0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1,
    0x1d, 0x5f, 0xac,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisError {
    BlockTooLarge,
    MalformedBlock,
    TrailingBytes,
    NoncanonicalEncoding,
    WrongGenesis,
    InvalidCoinbase,
    InvalidEquihash,
    InvalidTarget,
    InsufficientWork,
}

impl fmt::Display for GenesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BlockTooLarge => "genesis body exceeds maximum block size",
            Self::MalformedBlock => "malformed complete genesis body",
            Self::TrailingBytes => "bytes remain after genesis coinbase",
            Self::NoncanonicalEncoding => "genesis encoding is not canonical",
            Self::WrongGenesis => "block is not the authentic testnet genesis",
            Self::InvalidCoinbase => "coinbase is not the authentic genesis transaction",
            Self::InvalidEquihash => "invalid genesis Equihash solution",
            Self::InvalidTarget => "invalid testnet proof-of-work target",
            Self::InsufficientWork => "header hash exceeds proof-of-work target",
        })
    }
}

impl std::error::Error for GenesisError {}

/// Pool identity remains distinct even where two pools share a tree algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShieldedPool {
    Sprout,
    Sapling,
    Orchard,
    Ironwood,
}

impl ShieldedPool {
    fn index(self) -> usize {
        match self {
            Self::Sprout => 0,
            Self::Sapling => 1,
            Self::Orchard => 2,
            Self::Ironwood => 3,
        }
    }
}

/// Actual initial ledger state, constructible only by authenticating genesis.
/// This is not a recursive history proof or a financially verified source fact.
#[derive(Debug)]
pub struct GenesisState {
    tip: [u8; 32],
    coinbase_txid: [u8; 32],
    cumulative_work: U256,
    time: u32,
    bits: u32,
    utxos: BTreeMap<([u8; 32], u32), (u64, Vec<u8>)>,
    nullifiers: [BTreeSet<[u8; 32]>; 4],
    sprout_tree: Frontier<SproutNode, 29>,
    shielded_roots: [[u8; 32]; 4],
    transparent_balance: u64,
    shielded_balances: [u64; 4],
    deferred_balance: u64,
    issued_supply: u64,
    history_root: Option<[u8; 32]>,
}

impl GenesisState {
    pub fn network(&self) -> NetworkType {
        NetworkType::Test
    }

    pub fn height(&self) -> u32 {
        0
    }

    pub fn consensus_branch(&self) -> BranchId {
        BranchId::Sprout
    }

    /// Internal/wire order, not the reversed RPC display order.
    pub fn tip(&self) -> [u8; 32] {
        self.tip
    }

    pub fn coinbase_txid(&self) -> [u8; 32] {
        self.coinbase_txid
    }

    pub fn cumulative_work(&self) -> U256 {
        self.cumulative_work
    }

    pub fn time(&self) -> u32 {
        self.time
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Consults the actual UTXO map; genesis's zero-valued output is absent.
    pub fn utxo(&self, txid: &[u8; 32], output_index: u32) -> Option<&(u64, Vec<u8>)> {
        self.utxos.get(&(*txid, output_index))
    }

    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }

    pub fn contains_nullifier(&self, pool: ShieldedPool, nullifier: &[u8; 32]) -> bool {
        self.nullifiers[pool.index()].contains(nullifier)
    }

    pub fn nullifier_count(&self, pool: ShieldedPool) -> usize {
        self.nullifiers[pool.index()].len()
    }

    pub fn sprout_tree_size(&self) -> u64 {
        self.sprout_tree.tree_size()
    }

    /// Actual empty roots. An inactive pool's root is not an admissible anchor.
    pub fn shielded_root(&self, pool: ShieldedPool) -> [u8; 32] {
        self.shielded_roots[pool.index()]
    }

    pub fn pool_is_active(&self, pool: ShieldedPool) -> bool {
        pool == ShieldedPool::Sprout
    }

    pub fn transparent_balance(&self) -> u64 {
        self.transparent_balance
    }

    pub fn shielded_balance(&self, pool: ShieldedPool) -> u64 {
        self.shielded_balances[pool.index()]
    }

    pub fn deferred_balance(&self) -> u64 {
        self.deferred_balance
    }

    pub fn issued_supply(&self) -> u64 {
        self.issued_supply
    }

    /// History MMR commitments do not exist before Heartwood.
    pub fn history_root(&self) -> Option<[u8; 32]> {
        self.history_root
    }
}

/// Parses and validates the complete fixed base case. Every identity is derived
/// from the supplied bytes and checked against the authentic testnet constants.
pub fn bootstrap_testnet_genesis(raw: &[u8]) -> Result<GenesisState, GenesisError> {
    if raw.len() > MAX_BLOCK_BYTES {
        return Err(GenesisError::BlockTooLarge);
    }
    let mut remaining = raw;
    let header = BlockHeader::read(&mut remaining).map_err(decode_error)?;
    let count: usize = CompactSize::read_t(&mut remaining).map_err(decode_error)?;
    if count != 1 {
        return Err(GenesisError::InvalidCoinbase);
    }
    // Reject other formats before their parser can interpret additional bundles.
    if remaining.get(..4).ok_or(GenesisError::MalformedBlock)? != 1_u32.to_le_bytes() {
        return Err(GenesisError::InvalidCoinbase);
    }
    let coinbase = Transaction::read(&mut remaining, BranchId::Sprout).map_err(decode_error)?;
    if !remaining.is_empty() {
        return Err(GenesisError::TrailingBytes);
    }
    let mut canonical = CanonicalBytes { remaining: raw };
    header
        .write(&mut canonical)
        .and_then(|()| CompactSize::write(&mut canonical, count))
        .and_then(|()| coinbase.write(&mut canonical))
        .map_err(|_| GenesisError::NoncanonicalEncoding)?;
    if !canonical.remaining.is_empty() {
        return Err(GenesisError::NoncanonicalEncoding);
    }

    check_coinbase(&coinbase)?;
    if header.version != 4
        || header.prev_block.0 != [0; 32]
        || header.merkle_root != COINBASE_TXID
        || header.final_sapling_root != [0; 32]
        || header.time != 1_477_648_033
        || header.nonce[0] != 6
        || header.nonce[1..].iter().any(|byte| *byte != 0)
        || header.solution.len() != 1344
    {
        return Err(GenesisError::WrongGenesis);
    }
    let txid: [u8; 32] = coinbase.txid().into();
    if txid != COINBASE_TXID || txid != header.merkle_root {
        return Err(GenesisError::InvalidCoinbase);
    }
    let target = testnet_target_from_compact(header.bits)?;
    if U256::from_little_endian(&header.hash().0) > target {
        return Err(GenesisError::InsufficientWork);
    }
    if header.bits != 0x2007_ffff {
        return Err(GenesisError::WrongGenesis);
    }
    equihash::is_valid_solution(200, 9, &raw[..108], &header.nonce, &header.solution)
        .map_err(|_| GenesisError::InvalidEquihash)?;
    if header.hash().0 != GENESIS_HASH {
        return Err(GenesisError::WrongGenesis);
    }
    let cumulative_work = block_work(target)?;

    let sprout_tree = Frontier::<SproutNode, 29>::empty();
    let sprout_root = sprout_tree.root().0;
    let sapling_root = sapling_crypto::Anchor::empty_tree().to_bytes();
    let orchard_root = orchard::Anchor::empty_tree().to_bytes();
    // zcashd ConnectBlock explicitly skips genesis's transactions: even its
    // zero-valued output never enters the UTXO set, and no value is issued.
    Ok(GenesisState {
        tip: header.hash().0,
        coinbase_txid: txid,
        cumulative_work,
        time: header.time,
        bits: header.bits,
        utxos: BTreeMap::new(),
        nullifiers: std::array::from_fn(|_| BTreeSet::new()),
        sprout_tree,
        shielded_roots: [sprout_root, sapling_root, orchard_root, orchard_root],
        transparent_balance: 0,
        shielded_balances: [0; 4],
        deferred_balance: 0,
        issued_supply: 0,
        history_root: None,
    })
}

fn check_coinbase(transaction: &Transaction) -> Result<(), GenesisError> {
    if transaction.version() != TxVersion::Sprout(1)
        || transaction.consensus_branch_id() != BranchId::Sprout
        || transaction.lock_time() != 0
        || u32::from(transaction.expiry_height()) != 0
        || transaction.sprout_bundle().is_some()
        || transaction.sapling_bundle().is_some()
        || transaction.orchard_bundle().is_some()
        || transaction.ironwood_bundle().is_some()
    {
        return Err(GenesisError::InvalidCoinbase);
    }
    let transparent = transaction
        .transparent_bundle()
        .ok_or(GenesisError::InvalidCoinbase)?;
    if !transparent.is_coinbase() || transparent.vin.len() != 1 || transparent.vout.len() != 1 {
        return Err(GenesisError::InvalidCoinbase);
    }
    let input = &transparent.vin[0];
    let output = &transparent.vout[0];
    if input.prevout().hash() != &[0; 32]
        || input.prevout().n() != u32::MAX
        || input.script_sig().0.0.as_slice() != COINBASE_SCRIPT_SIG
        || input.sequence() != u32::MAX
        || u64::from(output.value()) != 0
        || output.script_pubkey().0.0.as_slice() != COINBASE_SCRIPT_PUBKEY
    {
        return Err(GenesisError::InvalidCoinbase);
    }
    Ok(())
}

fn decode_error(error: io::Error) -> GenesisError {
    if error.kind() == io::ErrorKind::InvalidInput {
        GenesisError::NoncanonicalEncoding
    } else {
        GenesisError::MalformedBlock
    }
}

/// zcashd arith_uint256::SetCompact sign, zero and overflow semantics, with the
/// fixed testnet PoW limit 2^251 - 1. Not a difficulty-retarget check.
pub(crate) fn testnet_target_from_compact(bits: u32) -> Result<U256, GenesisError> {
    let size = bits >> 24;
    let mut word = bits & 0x007f_ffff;
    if size <= 3 {
        word >>= 8 * (3 - size);
    }
    let negative = word != 0 && bits & 0x0080_0000 != 0;
    let overflow =
        word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    if negative || overflow || word == 0 {
        return Err(GenesisError::InvalidTarget);
    }
    let target = if size <= 3 {
        U256::from(word)
    } else {
        U256::from(word) << (8 * (size - 3))
    };
    if target > TESTNET_POW_LIMIT {
        return Err(GenesisError::InvalidTarget);
    }
    Ok(target)
}

pub(crate) fn block_work(target: U256) -> Result<U256, GenesisError> {
    let denominator = target
        .checked_add(U256::one())
        .ok_or(GenesisError::InvalidTarget)?;
    (!target / denominator)
        .checked_add(U256::one())
        .ok_or(GenesisError::InvalidTarget)
}

#[derive(Clone, Copy, Debug)]
struct SproutNode([u8; 32]);

impl Hashable for SproutNode {
    fn empty_leaf() -> Self {
        Self([0; 32])
    }

    fn combine(_level: Level, left: &Self, right: &Self) -> Self {
        // MerkleCRH^Sprout = SHA256Compress(left || right), with no padding.
        // Zebra's pinned sprout/tree.rs implements the same protocol equation.
        let mut block = [0; 64];
        block[..32].copy_from_slice(&left.0);
        block[32..].copy_from_slice(&right.0);
        let mut state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        sha2::compress256(&mut state, &[block.into()]);
        let mut root = [0; 32];
        for (bytes, word) in root.as_chunks_mut::<4>().0.iter_mut().zip(state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        Self(root)
    }
}
