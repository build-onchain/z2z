//! Host-local future-header admission for complete testnet blocks.
//!
//! Adds the source rule `header.time <= local_now + 7200` before the existing
//! atomic full-ledger transition. Historical/guest replay remains clock-free.
//! This is not freshness, fork choice, finality, or financial authority; a block
//! rejected as too far in the future may be retried when local time advances.
//!
//! Rule: zcashd 86451a18b016af09a4e33c9acc1aa5577e25af17,
//! `src/main.cpp::CheckBlockHeader` and its `GetTime() + 2 * 60 * 60` bound.

use std::fmt;

use zcash_protocol::constants::MAX_BLOCK_BYTES;

use crate::{
    genesis::ledger::{SproutLedgerError, SproutTestnetLedger},
    header::{HeaderTip, block_header_time},
};

/// Fixed categories retain no clock values, raw bodies, or private input data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceAdmissionError {
    ClockUnavailable,
    InvalidBlockSize,
    InvalidHeader,
    TimeTooFarInFuture,
    Ledger(SproutLedgerError),
}

impl fmt::Display for SourceAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockUnavailable => formatter.write_str("trusted local source clock unavailable"),
            Self::InvalidBlockSize => formatter.write_str("complete source block size rejected"),
            Self::InvalidHeader => formatter.write_str("canonical source header rejected"),
            Self::TimeTooFarInFuture => formatter.write_str("source header exceeds local future-time bound"),
            Self::Ledger(error) => write!(formatter, "complete source ledger transition rejected: {error}"),
        }
    }
}

impl std::error::Error for SourceAdmissionError {}

/// Admits one complete block using a caller-owned trusted local Unix clock.
///
/// The caller must supply actual local time, never a peer/RPC timestamp or an
/// assertion that a history is fresh. `None` fails closed; pre-epoch/unavailable
/// clocks must not be wrapped or clamped into `u64`. This pure API reads no clock
/// itself and stores no clock policy. Equality at 7200 seconds is accepted.
/// Every header/body/authorization rule still runs in `ledger.apply_block` after
/// the time guard. All errors leave the ledger unchanged and authorize nothing.
pub fn apply_block_at(
    ledger: &mut SproutTestnetLedger,
    raw: &[u8],
    local_unix_seconds: Option<u64>,
) -> Result<HeaderTip, SourceAdmissionError> {
    let now = local_unix_seconds.ok_or(SourceAdmissionError::ClockUnavailable)?;
    if raw.is_empty() || raw.len() > MAX_BLOCK_BYTES {
        return Err(SourceAdmissionError::InvalidBlockSize);
    }
    let time = u64::from(block_header_time(raw).map_err(|_| SourceAdmissionError::InvalidHeader)?);
    // Widen before subtracting: avoids overflowing now + 7200 at u64::MAX,
    // while past headers have zero future displacement, not a freshness limit.
    if time.saturating_sub(now) > 7200 {
        return Err(SourceAdmissionError::TimeTooFarInFuture);
    }
    ledger.apply_block(raw).map_err(SourceAdmissionError::Ledger)
}
