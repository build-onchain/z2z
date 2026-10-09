//! Bounded complete testnet NU5–NU6.3 bodies retaining original V5 Orchard bytes.
//!
//! This checks framing, candidate-height/branch consistency, first/only coinbase
//! and the ordered effect Merkle tree. The authorization tree is derived from
//! the same complete transaction list, but is NOT authenticated against parent
//! history here. Parsing proves no PoW, signature, ledger transition, accepted
//! history, finality or asset-transfer fact. Only pre-NU6.2 Orchard EPKs remain opaque.

use corez::io::ErrorKind;
use orchard::{Proof, bundle::{BundleVersion, Flags}};
use zcash_encoding::CompactSize;
use zcash_primitives::{
    block::BlockHeader,
    transaction::{
        Transaction, TxVersion,
        components::{
            GROTH_PROOF_SIZE,
            sapling::{OUTPUT_DESCRIPTION_SIZE, SPEND_DESCRIPTION_SIZE},
        },
    },
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, TEST_NETWORK},
    constants::MAX_BLOCK_BYTES,
    value::ZatBalance,
};
use zcash_transparent::bundle::{self as transparent, OutPoint};

use crate::{
    history::{BodyError, CanonicalBytes, auth_merkle_root, effect_merkle_root},
    raw_v5::{RawV5, RawV5Error},
};

const HEADER_BYTES: usize = 1487;
const SOLUTION_PREFIX: [u8; 3] = [0xfd, 0x40, 0x05]; // canonical 1344
const MIN_TRANSACTION_BYTES: usize = 25; // V5 header and five empty counts

/// Maintained V4/V6 or exact-byte V5, never a frozen V5 projection.
/// Consuming the variant moves the actual transaction/bundles without cloning;
/// signature contexts require every actual previous output in original order.
/// Boxing keeps count-bounded body storage compact instead of reserving the
/// largest payload for every transaction. No projection freezing or rehashing.
#[derive(Debug)]
pub enum PostNu5Transaction<'a> {
    V4(Box<Transaction>),
    V5(Box<RawV5<'a>>),
    V6(Box<Transaction>),
}

impl PostNu5Transaction<'_> {
    pub fn version(&self) -> TxVersion {
        match self {
            Self::V4(transaction) | Self::V6(transaction) => transaction.version(),
            Self::V5(transaction) => transaction.version(),
        }
    }

    pub fn consensus_branch_id(&self) -> BranchId {
        match self {
            Self::V4(transaction) | Self::V6(transaction) => transaction.consensus_branch_id(),
            Self::V5(transaction) => transaction.consensus_branch_id(),
        }
    }

    pub fn lock_time(&self) -> u32 {
        match self {
            Self::V4(transaction) | Self::V6(transaction) => transaction.lock_time(),
            Self::V5(transaction) => transaction.lock_time(),
        }
    }

    pub fn expiry_height(&self) -> BlockHeight {
        match self {
            Self::V4(transaction) | Self::V6(transaction) => transaction.expiry_height(),
            Self::V5(transaction) => transaction.expiry_height(),
        }
    }

    pub fn transparent_bundle(&self) -> Option<&transparent::Bundle<transparent::Authorized>> {
        match self {
            Self::V4(transaction) | Self::V6(transaction) => transaction.transparent_bundle(),
            Self::V5(transaction) => transaction.transparent_bundle(),
        }
    }

    pub fn sapling_bundle(
        &self,
    ) -> Option<&sapling_crypto::Bundle<sapling_crypto::bundle::Authorized, ZatBalance>> {
        match self {
            Self::V4(transaction) | Self::V6(transaction) => transaction.sapling_bundle(),
            Self::V5(transaction) => transaction.sapling_bundle(),
        }
    }

    /// Typed pools exist only in actual V6; V5 consumers retain raw `orchard()`.
    pub fn orchard_bundle(&self) -> Option<&orchard::Bundle<orchard::bundle::Authorized, ZatBalance>> {
        match self {
            Self::V6(transaction) => transaction.orchard_bundle(),
            Self::V4(_) | Self::V5(_) => None,
        }
    }

    pub fn ironwood_bundle(&self) -> Option<&orchard::Bundle<orchard::bundle::Authorized, ZatBalance>> {
        match self {
            Self::V6(transaction) => transaction.ironwood_bundle(),
            Self::V4(_) | Self::V5(_) => None,
        }
    }

    pub fn effect_id(&self) -> [u8; 32] {
        match self {
            Self::V4(transaction) | Self::V6(transaction) => transaction.txid().into(),
            Self::V5(transaction) => transaction.effect_id(),
        }
    }

    /// V4's effect identity already commits to its complete authorizing bytes.
    /// Its block authorization leaf is FF32, not an invented V5 auth digest.
    pub fn auth_digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::V4(_) => None,
            Self::V5(transaction) => Some(transaction.auth_digest()),
            Self::V6(transaction) => Some(transaction.auth_commitment().as_bytes().try_into()
                .expect("32-byte authorizing commitment")),
        }
    }
}

/// Complete structural body, not a verified block or authenticated ledger state.
#[derive(Debug)]
pub struct PostNu5Block<'a> {
    header: BlockHeader,
    transactions: Vec<PostNu5Transaction<'a>>,
    auth_data_root: [u8; 32],
}

impl<'a> PostNu5Block<'a> {
    /// Parses every original transaction in finite testnet NU5–NU6.3 intervals.
    /// `height` is candidate context, not an assertion of connected chain height.
    /// Header/count and every nested V4/V5/V6 allocation are preflighted first.
    pub fn parse(raw: &'a [u8], height: u32) -> Result<Self, BodyError> {
        if raw.len() > MAX_BLOCK_BYTES {
            return Err(BodyError::BlockTooLarge);
        }
        let branch = BranchId::for_height(&TEST_NETWORK, height.into());
        // Installed protocol scheduling still has NU7=None. The published
        // testnet cutover is authoritative even when that old lookup says NU6.3.
        if height >= 4_465_026 || !matches!(branch,
            BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3)
        {
            return Err(BodyError::WrongConsensusBranch);
        }
        if raw.len() < HEADER_BYTES {
            return Err(BodyError::MalformedBlock);
        }
        if i32::from_le_bytes(raw[..4].try_into().expect("four-byte version")) < 4
            || raw[140..143] != SOLUTION_PREFIX
        {
            return Err(BodyError::InvalidHeader);
        }
        // Restrict the maintained reader to the preflighted canonical 1487-byte
        // testnet header: an attacker cannot make its solution Vec grow first.
        let mut header_reader = &raw[..HEADER_BYTES];
        let header = BlockHeader::read(&mut header_reader).map_err(|_| BodyError::MalformedBlock)?;
        let mut canonical = CanonicalBytes { remaining: &raw[..HEADER_BYTES] };
        header.write(&mut canonical).map_err(|_| BodyError::NoncanonicalEncoding)?;
        if !header_reader.is_empty() || !canonical.remaining.is_empty() {
            return Err(BodyError::NoncanonicalEncoding);
        }

        let mut remaining = &raw[HEADER_BYTES..];
        let count: usize = CompactSize::read_t(&mut remaining).map_err(|error| {
            if error.kind() == ErrorKind::UnexpectedEof {
                BodyError::MalformedBlock
            } else {
                BodyError::NoncanonicalEncoding
            }
        })?;
        if count == 0 || count > remaining.len() / MIN_TRANSACTION_BYTES {
            return Err(BodyError::MalformedBlock);
        }
        let mut transactions = Vec::with_capacity(count);
        for index in 0..count {
            let original = remaining;
            let mut prefix = remaining;
            let version = TxVersion::read(&mut prefix).map_err(|error| {
                if error.kind() == ErrorKind::UnexpectedEof {
                    BodyError::MalformedBlock
                } else {
                    BodyError::WrongConsensusBranch
                }
            })?;
            if !version.valid_in_branch(branch) {
                return Err(BodyError::WrongConsensusBranch);
            }
            let transaction = match version {
                TxVersion::V4 => {
                    // V4 has no encoded branch. Read under the candidate's exact
                    // context directly; do not repair or re-freeze its branch.
                    let consumed = preflight_v4(prefix)? + 8;
                    let mut transaction_reader = &original[..consumed];
                    let transaction = Transaction::read(&mut transaction_reader, branch)
                        .map_err(|_| BodyError::MalformedBlock)?;
                    if !transaction_reader.is_empty() {
                        return Err(BodyError::MalformedBlock);
                    }
                    remaining = &original[consumed..];
                    let mut canonical = CanonicalBytes { remaining: &original[..consumed] };
                    transaction.write(&mut canonical).map_err(|_| BodyError::NoncanonicalEncoding)?;
                    if !canonical.remaining.is_empty() {
                        return Err(BodyError::NoncanonicalEncoding);
                    }
                    PostNu5Transaction::V4(Box::new(transaction))
                }
                TxVersion::V5 => PostNu5Transaction::V5(Box::new(RawV5::parse(&mut remaining).map_err(raw_error)?)),
                TxVersion::V6 => {
                    // Preflight BOTH full slots and every authorization tail
                    // before maintained readers allocate. Never freeze a V6
                    // projection or serialize a replacement transaction.
                    let consumed = preflight_v6(prefix, branch)? + 8;
                    let mut transaction_reader = &original[..consumed];
                    let transaction = Transaction::read(&mut transaction_reader, branch)
                        .map_err(|_| BodyError::MalformedBlock)?;
                    if !transaction_reader.is_empty() {
                        return Err(BodyError::MalformedBlock);
                    }
                    let mut canonical = CanonicalBytes { remaining: &original[..consumed] };
                    transaction.write(&mut canonical).map_err(|_| BodyError::NoncanonicalEncoding)?;
                    if !canonical.remaining.is_empty() {
                        return Err(BodyError::NoncanonicalEncoding);
                    }
                    remaining = &original[consumed..];
                    PostNu5Transaction::V6(Box::new(transaction))
                }
                _ => return Err(BodyError::WrongConsensusBranch),
            };
            if !transaction.version().valid_in_branch(branch)
                || transaction.consensus_branch_id() != branch
            {
                return Err(BodyError::WrongConsensusBranch);
            }
            // ZIP257 disables every present Orchard bundle independently of
            // flags, value, proof or coinbase status, until NU6.2 re-enables it.
            if (4_048_500..4_052_000).contains(&height)
                && matches!(&transaction, PostNu5Transaction::V5(tx) if tx.orchard().is_some())
            {
                return Err(BodyError::MalformedBlock);
            }
            if index == 0 {
                check_coinbase(&transaction, height)?;
            } else if transaction.transparent_bundle().is_some_and(|bundle| {
                bundle.vin.iter().any(|input| input.prevout() == &OutPoint::NULL)
            }) {
                return Err(BodyError::MalformedBlock);
            }
            transactions.push(transaction);
        }
        if !remaining.is_empty() {
            return Err(BodyError::TrailingBytes);
        }

        // Reuse the existing equations and a single buffer for duplicates, the
        // ordered effect tree, then FF32/zero-padded ordered authorization tree.
        let padded_count = count.next_power_of_two();
        let mut nodes = Vec::with_capacity(padded_count);
        nodes.extend(transactions.iter().map(PostNu5Transaction::effect_id));
        nodes.sort_unstable();
        if nodes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BodyError::DuplicateTransaction);
        }
        for (node, transaction) in nodes.iter_mut().zip(&transactions) {
            *node = transaction.effect_id();
        }
        if effect_merkle_root(&mut nodes)? != header.merkle_root {
            return Err(BodyError::MerkleRootMismatch);
        }
        nodes.clear();
        nodes.extend(transactions.iter().map(|tx| tx.auth_digest().unwrap_or([0xff; 32])));
        nodes.resize(padded_count, [0; 32]);
        let auth_data_root = auth_merkle_root(&mut nodes);
        Ok(Self { header, transactions, auth_data_root })
    }

    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn transactions(&self) -> &[PostNu5Transaction<'a>] {
        &self.transactions
    }

    /// Structural auth root only; parent-history/header authentication is a
    /// separate owned ledger relation, never a caller-supplied checkpoint here.
    pub fn auth_data_root(&self) -> [u8; 32] {
        self.auth_data_root
    }

    pub fn into_transactions(self) -> Vec<PostNu5Transaction<'a>> {
        self.transactions
    }
}

fn raw_error(error: RawV5Error) -> BodyError {
    match error {
        RawV5Error::UnsupportedVersion
        | RawV5Error::UnsupportedVersionGroup
        | RawV5Error::UnsupportedBranch => BodyError::WrongConsensusBranch,
        RawV5Error::InvalidCompactSize => BodyError::NoncanonicalEncoding,
        _ => BodyError::MalformedBlock,
    }
}

// Framing only, after the maintained TxVersion reader checked the exact V4
// prefix. No field interpretation, cryptographic predicate or replacement
// Transaction is implemented here. The entire consumed slice is bounded before
// any maintained transparent/Sapling/JoinSplit reader can allocate from counts.
fn preflight_v4(mut reader: &[u8]) -> Result<usize, BodyError> {
    let original_length = reader.len();
    let inputs = v4_count(&mut reader)?;
    if inputs > reader.len() / 41 { // outpoint36 + script length1 + sequence4
        return Err(BodyError::MalformedBlock);
    }
    for _ in 0..inputs {
        v4_skip(&mut reader, 36)?;
        let script_length = v4_count(&mut reader)?;
        v4_skip(&mut reader, script_length)?;
        v4_skip(&mut reader, 4)?;
    }
    let outputs = v4_count(&mut reader)?;
    if outputs > reader.len() / 9 { // amount8 + script length1
        return Err(BodyError::MalformedBlock);
    }
    for _ in 0..outputs {
        v4_skip(&mut reader, 8)?;
        let script_length = v4_count(&mut reader)?;
        v4_skip(&mut reader, script_length)?;
    }
    v4_skip(&mut reader, 16)?; // lock4 + expiry4 + valueBalance8
    let spends = v4_count(&mut reader)?;
    v4_skip_counted(&mut reader, spends, SPEND_DESCRIPTION_SIZE)?;
    let shielded_outputs = v4_count(&mut reader)?;
    v4_skip_counted(&mut reader, shielded_outputs, OUTPUT_DESCRIPTION_SIZE)?;
    let joinsplits = v4_count(&mut reader)?;
    // Maintained sprout::JsDescription::read(use_groth=true): vpubs16,
    // anchor/nf[2]/cm[2]/epk/seed/mac[2] = nine32, Groth192, ct[2]*601.
    v4_skip_counted(&mut reader, joinsplits, 16 + 9 * 32 + GROTH_PROOF_SIZE + 2 * 601)?;
    if joinsplits != 0 {
        v4_skip(&mut reader, 96)?; // JoinSplit public key32 + signature64
    }
    if spends != 0 || shielded_outputs != 0 {
        v4_skip(&mut reader, 64)?; // Sapling binding signature
    }
    Ok(original_length - reader.len())
}

// V6 framing is V5 Sapling followed by two independently bounded pool slots.
// The caller already checked the exact maintained V6 header/version group.
fn preflight_v6(mut reader: &[u8], branch: BranchId) -> Result<usize, BodyError> {
    let original_length = reader.len();
    if reader.len() < 12 {
        return Err(BodyError::MalformedBlock);
    }
    if reader[..4] != u32::from(branch).to_le_bytes() || branch != BranchId::Nu6_3 {
        return Err(BodyError::WrongConsensusBranch);
    }
    v4_skip(&mut reader, 12)?; // branch4 + lock4 + expiry4
    let inputs = v4_count(&mut reader)?;
    if inputs > reader.len() / 41 { return Err(BodyError::MalformedBlock); }
    for _ in 0..inputs {
        v4_skip(&mut reader, 36)?;
        let length = v4_count(&mut reader)?;
        v4_skip(&mut reader, length)?;
        v4_skip(&mut reader, 4)?;
    }
    let outputs = v4_count(&mut reader)?;
    if outputs > reader.len() / 9 { return Err(BodyError::MalformedBlock); }
    for _ in 0..outputs {
        v4_skip(&mut reader, 8)?;
        let length = v4_count(&mut reader)?;
        v4_skip(&mut reader, length)?;
    }
    let spends = v4_count(&mut reader)?;
    if spends > 65_535 { return Err(BodyError::MalformedBlock); }
    v4_skip_counted(&mut reader, spends, 96)?;
    let shielded_outputs = v4_count(&mut reader)?;
    if shielded_outputs > 65_535 { return Err(BodyError::MalformedBlock); }
    v4_skip_counted(&mut reader, shielded_outputs, 756)?;
    if spends != 0 || shielded_outputs != 0 {
        v4_skip(&mut reader, 8)?; // balance
        if spends != 0 { v4_skip(&mut reader, 32)?; }
        v4_skip_counted(&mut reader, spends, GROTH_PROOF_SIZE)?;
        v4_skip_counted(&mut reader, spends, 64)?;
        v4_skip_counted(&mut reader, shielded_outputs, GROTH_PROOF_SIZE)?;
        v4_skip(&mut reader, 64)?;
    }
    for version in [BundleVersion::orchard_v3(), BundleVersion::ironwood_v3()] {
        let actions = v4_count(&mut reader)?;
        if actions > 65_535 { return Err(BodyError::MalformedBlock); }
        if actions == 0 { continue; }
        v4_skip_counted(&mut reader, actions, 820)?;
        let flag_byte = *reader.first().ok_or(BodyError::MalformedBlock)?;
        let flags = Flags::from_byte(flag_byte, version).ok_or(BodyError::MalformedBlock)?;
        if !flags.spends_enabled() && !flags.outputs_enabled() {
            return Err(BodyError::MalformedBlock);
        }
        v4_skip(&mut reader, 41)?; // flags1 + balance8 + anchor32
        let proof_length = v4_count(&mut reader)?;
        if proof_length != Proof::expected_proof_size(actions) {
            return Err(BodyError::MalformedBlock);
        }
        v4_skip(&mut reader, proof_length)?;
        v4_skip_counted(&mut reader, actions, 64)?;
        v4_skip(&mut reader, 64)?;
    }
    Ok(original_length - reader.len())
}

fn v4_count(reader: &mut &[u8]) -> Result<usize, BodyError> {
    CompactSize::read_t(reader).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            BodyError::MalformedBlock
        } else {
            BodyError::NoncanonicalEncoding
        }
    })
}

fn v4_skip_counted(reader: &mut &[u8], count: usize, width: usize) -> Result<(), BodyError> {
    let length = count.checked_mul(width).ok_or(BodyError::MalformedBlock)?;
    v4_skip(reader, length)
}

fn v4_skip(reader: &mut &[u8], length: usize) -> Result<(), BodyError> {
    if length > reader.len() {
        return Err(BodyError::MalformedBlock);
    }
    *reader = &reader[length..];
    Ok(())
}

fn check_coinbase(transaction: &PostNu5Transaction<'_>, height: u32) -> Result<(), BodyError> {
    let bundle = transaction.transparent_bundle()
        .filter(|bundle| bundle.is_coinbase())
        .ok_or(BodyError::MalformedBlock)?;
    if matches!(transaction, PostNu5Transaction::V4(tx) if tx.sprout_bundle().is_some()) {
        return Err(BodyError::MalformedBlock);
    }
    let (prefix, length) = coinbase_height_prefix(height);
    if !bundle.vin[0].script_sig().0.0.starts_with(&prefix[..length]) {
        return Err(BodyError::MalformedBlock);
    }
    Ok(())
}

// The existing native ledger's minimal positive scriptNum encoding, local to
// this finite interval; no generic script parser/evaluator or circular import.
fn coinbase_height_prefix(height: u32) -> ([u8; 6], usize) {
    let mut prefix = [0; 6];
    let mut value = height;
    let mut length = 0;
    while value != 0 {
        length += 1;
        prefix[length] = value as u8;
        value >>= 8;
    }
    if prefix[length] & 0x80 != 0 {
        length += 1;
    }
    prefix[0] = length as u8;
    (prefix, length + 1)
}
