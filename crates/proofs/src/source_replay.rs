//! Bounded offline replay of complete testnet bodies from authentic genesis.
//!
//! This finite linear-ledger journal is not a SNARK, fork choice, freshness,
//! finality, payment classification, or full R2.2 acceptance. Raw bodies share
//! one bounded buffer; the actual validator's UTXOs, nullifiers, and anchors
//! still grow with the admitted history.

use std::{fmt, io::{self, Read}};

use sha2::{Digest, Sha256};

use crate::genesis::{
    ShieldedPool, bootstrap_testnet_genesis,
    ledger::{SproutLedgerError, SproutTestnetLedger},
};

pub const MAX_BLOCK_BYTES: usize = 2_000_000;
/// Includes genesis; the last supported height is 4,465,025.
pub const MAX_BLOCK_COUNT: u32 = 4_465_026;
pub const JOURNAL_LEN: usize = 374;
const GENESIS_BYTES: u32 = 1692;
const JOURNAL_DOMAIN: &[u8; 49] = b"ziquid/sprout-through-nu63-ledger/subrelation/v11";

/// Fixed categories deliberately retain no private or untrusted input/error data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceReplayError {
    InvalidPolicy,
    InvalidFraming,
    LimitExceeded,
    InputUnavailable,
    InvalidGenesis,
    UnsupportedEra,
    InvalidTransition,
    TrailingBytes,
}

impl fmt::Display for SourceReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "source replay policy rejected",
            Self::InvalidFraming => "source history framing rejected",
            Self::LimitExceeded => "source history exceeds replay limits",
            Self::InputUnavailable => "source history unavailable",
            Self::InvalidGenesis => "authentic testnet genesis rejected",
            Self::UnsupportedEra => "unsupported source era",
            Self::InvalidTransition => "complete source ledger transition rejected",
            Self::TrailingBytes => "source history has trailing bytes",
        })
    }
}

impl std::error::Error for SourceReplayError {}

/// Reads count:u32LE followed by length:u32LE/complete-body frames and actual EOF.
/// Caller policies reject rather than clamp; no journal is returned before all
/// framing, genesis, full ledger transitions, and the final EOF probe pass.
pub fn replay_framed_testnet(
    reader: &mut impl Read,
    max_blocks: u32,
    max_input_bytes: u64,
) -> Result<[u8; JOURNAL_LEN], SourceReplayError> {
    replay_framed_testnet_with(reader, max_blocks, max_input_bytes, |_, _, _| Ok(()))
        .map(|(journal, _)| journal)
}

#[derive(Clone, Copy)]
pub(crate) enum ReplayPhase {
    BeforeBlock,
    Admitted,
}

// Only crate-owned consumers can stage an admitted block. The public APIs
// publish their terminal result after this same loop's final EOF check.
pub(crate) fn replay_framed_testnet_with<E: From<SourceReplayError>>(
    reader: &mut impl Read,
    max_blocks: u32,
    max_input_bytes: u64,
    mut observe: impl FnMut(&[u8], &SproutTestnetLedger, ReplayPhase) -> Result<(), E>,
) -> Result<([u8; JOURNAL_LEN], SproutTestnetLedger), E> {
    if !(1..=MAX_BLOCK_COUNT).contains(&max_blocks) || max_input_bytes == 0 {
        return Err(SourceReplayError::InvalidPolicy.into());
    }
    let mut used = 0;
    let mut digest = Sha256::new();
    let count = read_u32(reader, &mut used, max_input_bytes, &mut digest)?;
    if count == 0 {
        return Err(SourceReplayError::InvalidFraming.into());
    }
    if count > max_blocks {
        return Err(SourceReplayError::LimitExceeded.into());
    }
    // All length prefixes plus the one required authentic genesis body.
    let minimum = u64::from(count).checked_mul(4)
        .and_then(|prefixes| prefixes.checked_add(4 + u64::from(GENESIS_BYTES)))
        .ok_or(SourceReplayError::LimitExceeded)?;
    if minimum > max_input_bytes {
        return Err(SourceReplayError::LimitExceeded.into());
    }

    let mut body = Vec::new();
    read_body(reader, &mut body, &mut used, max_input_bytes, &mut digest, true)?;
    let genesis = bootstrap_testnet_genesis(&body).map_err(|_| SourceReplayError::InvalidGenesis)?;
    let mut ledger = SproutTestnetLedger::from_genesis(genesis);
    observe(&body, &ledger, ReplayPhase::Admitted)?;
    for _ in 1..count {
        read_body(reader, &mut body, &mut used, max_input_bytes, &mut digest, false)?;
        observe(&body, &ledger, ReplayPhase::BeforeBlock)?;
        ledger.apply_block(&body).map_err(|error| match error {
            SproutLedgerError::UnsupportedEra => SourceReplayError::UnsupportedEra,
            _ => SourceReplayError::InvalidTransition,
        })?;
        observe(&body, &ledger, ReplayPhase::Admitted)?;
    }
    loop {
        match reader.read(&mut [0]) {
            Ok(0) => break,
            Ok(_) => return Err(SourceReplayError::TrailingBytes.into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(SourceReplayError::InputUnavailable.into()),
        }
    }
    Ok((encode_journal(&ledger, digest.finalize().into()), ledger))
}

fn charge(used: &mut u64, bytes: u64, limit: u64) -> Result<(), SourceReplayError> {
    let next = used.checked_add(bytes).ok_or(SourceReplayError::LimitExceeded)?;
    if next > limit {
        return Err(SourceReplayError::LimitExceeded);
    }
    *used = next;
    Ok(())
}

fn read_exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<(), SourceReplayError> {
    reader.read_exact(bytes).map_err(|error| match error.kind() {
        io::ErrorKind::UnexpectedEof => SourceReplayError::InvalidFraming,
        _ => SourceReplayError::InputUnavailable,
    })
}

fn read_u32(
    reader: &mut impl Read,
    used: &mut u64,
    limit: u64,
    digest: &mut Sha256,
) -> Result<u32, SourceReplayError> {
    charge(used, 4, limit)?;
    let mut prefix = [0; 4];
    read_exact(reader, &mut prefix)?;
    digest.update(prefix);
    Ok(u32::from_le_bytes(prefix))
}

fn read_body(
    reader: &mut impl Read,
    body: &mut Vec<u8>,
    used: &mut u64,
    limit: u64,
    digest: &mut Sha256,
    genesis: bool,
) -> Result<(), SourceReplayError> {
    let length = read_u32(reader, used, limit, digest)?;
    if genesis && length != GENESIS_BYTES {
        return Err(SourceReplayError::InvalidGenesis);
    }
    let length = usize::try_from(length).map_err(|_| SourceReplayError::LimitExceeded)?;
    if length > MAX_BLOCK_BYTES {
        return Err(SourceReplayError::LimitExceeded);
    }
    charge(used, length as u64, limit)?;
    // Reserve once, only after the first admitted length and budget checks.
    if body.capacity() == 0 {
        body.reserve_exact(MAX_BLOCK_BYTES);
    }
    body.resize(length, 0);
    read_exact(reader, body)?;
    digest.update(body.as_slice());
    Ok(())
}

// Exact v11 guest encoding, without changing the guest or its identity.
fn encode_journal(ledger: &SproutTestnetLedger, digest: [u8; 32]) -> [u8; JOURNAL_LEN] {
    let tip = ledger.tip();
    let mut work = [0; 32];
    tip.cumulative_work().to_big_endian(&mut work);
    let accounts = [
        ledger.transparent_balance(),
        ledger.shielded_balance(ShieldedPool::Sprout),
        ledger.shielded_balance(ShieldedPool::Sapling),
        ledger.shielded_balance(ShieldedPool::Orchard),
        ledger.shielded_balance(ShieldedPool::Ironwood),
        ledger.deferred_balance(),
        ledger.issued_supply(),
        ledger.utxo_balance(),
    ].map(u64::to_le_bytes);
    let roots = [ShieldedPool::Sprout, ShieldedPool::Sapling, ShieldedPool::Orchard, ShieldedPool::Ironwood]
        .map(|pool| ledger.shielded_root(pool));
    let history = ledger.history_root();
    let height = tip.height().to_le_bytes();
    let hash = tip.hash();
    let present = [u8::from(history.is_some())];
    let history = history.unwrap_or([0; 32]);
    let mut journal = [0; JOURNAL_LEN];
    let mut remaining = journal.as_mut_slice();
    for field in [JOURNAL_DOMAIN.as_slice(), &digest, &height, &hash, &work].into_iter()
        .chain(accounts.iter().map(|field| field.as_slice()))
        .chain(roots.iter().map(|field| field.as_slice()))
        .chain([present.as_slice(), history.as_slice()])
    {
        let (destination, rest) = remaining.split_at_mut(field.len());
        destination.copy_from_slice(field);
        remaining = rest;
    }
    debug_assert!(remaining.is_empty());
    journal
}
