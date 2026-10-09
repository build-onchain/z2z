//! Owner-local native trade custody and digest-only PostgreSQL lifecycle fences.
//!
//! Saving is not signing or broadcast approval. Unknown and pinned RPC candidates
//! never consume a financial right. Retained program/deployment bindings remain
//! selectable after expiry; there is no latest-artifact or timer refund path.

use std::{fmt, path::Path};

use crate::{custody::CustodyError, database::DatabaseError, native_quote::{AuthenticatedQuote, QuotePhase, QuoteSelection}};

mod capsule;
mod journal;
#[cfg(test)]
mod tests;
pub use journal::NativeTradeStore;
pub use crate::native_quote::NativeRole;
pub use capsule::{MAX_OPERATION_BYTES, save_operation_capsule};

pub(crate) const ENVELOPE_DOMAIN: &[u8] = b"ziquid.native.trade.v1\0";

/// Borrowed encryption capability and independently chosen namespace. Debug is
/// intentionally absent: neither paths nor keys are public lifecycle metadata.
#[derive(Clone, Copy)]
pub struct CapsuleLocation<'a> {
    pub path: &'a Path,
    pub key: &'a [u8; 32],
    pub namespace: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TradeCursor {
    pub version: u64,
    pub generation: u64,
}
impl TradeCursor {
    pub fn validate(self) -> Result<(), NativeTradeError> {
        if self.generation == 0 || self.generation > i64::MAX as u64 { return Err(NativeTradeError::StaleGeneration); }
        if self.version == 0 || self.version > i64::MAX as u64 { return Err(NativeTradeError::StaleVersion); }
        Ok(())
    }
    fn advance(self, writer: bool) -> Result<Self, NativeTradeError> {
        self.validate()?;
        let version = self.version.checked_add(1).filter(|v| *v <= i64::MAX as u64).ok_or(NativeTradeError::StaleVersion)?;
        let generation = if writer {
            self.generation.checked_add(1).filter(|g| *g <= i64::MAX as u64).ok_or(NativeTradeError::StaleGeneration)?
        } else { self.generation };
        Ok(Self { version, generation })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuoteSnapshot {
    pub selection: QuoteSelection,
    pub q: [u8; 32],
    pub phase: QuotePhase,
    pub cursor: TradeCursor,
    pub proposal_hash: [u8; 32],
    pub agreement_digest: Option<[u8; 32]>,
    pub user_acceptance_hash: Option<[u8; 32]>,
    pub solver_acceptance_hash: Option<[u8; 32]>,
    pub capsule_digest: [u8; 32],
    pub stopped: bool,
}
impl QuoteSnapshot {
    fn from_quote(quote: &AuthenticatedQuote, capsule_digest: [u8; 32], cursor: TradeCursor) -> Self {
        Self { selection: *quote.selection(), q: quote.digest(), phase: quote.phase(), cursor,
            proposal_hash: quote.proposal_hash(), agreement_digest: quote.agreement_digest(),
            user_acceptance_hash: quote.user_acceptance_hash(), solver_acceptance_hash: quote.solver_acceptance_hash(),
            capsule_digest, stopped: false }
    }

    /// Only the next authenticated predecessor can extend the immutable proposal.
    fn accept_quote(&self, quote: &AuthenticatedQuote) -> Result<bool, NativeTradeError> {
        if self.selection != *quote.selection() || self.q != quote.digest() || self.proposal_hash != quote.proposal_hash() {
            return Err(NativeTradeError::Conflict);
        }
        if self.stopped { return Err(NativeTradeError::Stopped); }
        let advance = self.phase != quote.phase();
        if advance && phase_code(quote.phase()) != phase_code(self.phase) + 1 { return Err(NativeTradeError::State); }
        if self.user_acceptance_hash.is_some_and(|hash| quote.user_acceptance_hash() != Some(hash))
            || self.solver_acceptance_hash.is_some_and(|hash| quote.solver_acceptance_hash() != Some(hash))
            || self.agreement_digest.is_some_and(|hash| quote.agreement_digest() != Some(hash)) {
            return Err(NativeTradeError::Conflict);
        }
        Ok(advance)
    }

    fn matches_quote(&self, quote: &AuthenticatedQuote) -> bool {
        self.selection == *quote.selection() && self.q == quote.digest() && self.phase == quote.phase()
            && self.proposal_hash == quote.proposal_hash() && self.agreement_digest == quote.agreement_digest()
            && self.user_acceptance_hash == quote.user_acceptance_hash()
            && self.solver_acceptance_hash == quote.solver_acceptance_hash()
    }
}

/// Constructed only after authenticated installed-capsule readback, committed
/// owner-scope CAS, and a second matching database read.
pub struct DurableQuote {
    quote: AuthenticatedQuote,
    snapshot: QuoteSnapshot,
}
impl DurableQuote {
    pub fn quote(&self) -> &AuthenticatedQuote { &self.quote }
    pub fn snapshot(&self) -> &QuoteSnapshot { &self.snapshot }
    pub fn into_quote(self) -> AuthenticatedQuote { self.quote }
}
impl fmt::Debug for DurableQuote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableQuote").field("phase", &self.snapshot.phase).finish_non_exhaustive()
    }
}

/// Caller-local immutable pins, not source, proof or deployment validation.
/// `action` is an explicitly selected positive SQL-smallint action namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationBinding {
    pub op_id: [u8; 32],
    pub context_digest: [u8; 32],
    pub deployment_digest: [u8; 32],
    pub stable_j_tag: [u8; 32],
    pub payload_digest: [u8; 32],
    pub action: u16,
}
impl OperationBinding {
    pub fn validate(&self) -> Result<(), NativeTradeError> {
        if self.action == 0 || self.action > i16::MAX as u16
            || [self.op_id, self.context_digest, self.deployment_digest, self.stable_j_tag, self.payload_digest]
                .contains(&[0; 32]) {
            return Err(NativeTradeError::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i16)]
pub enum OperationState { Prepared = 0, Released = 1, Submitted = 2, Unknown = 3 }
impl OperationState {
    pub fn can_release(self) -> bool { self == Self::Prepared }
    pub fn can_submit(self) -> bool { matches!(self, Self::Released | Self::Unknown) }
    pub fn can_mark_unknown(self) -> bool { matches!(self, Self::Released | Self::Submitted) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSnapshot {
    pub selection: QuoteSelection,
    pub binding: OperationBinding,
    pub state: OperationState,
    /// Current quote-wide writer fence, including unrelated operation mutations.
    pub cursor: TradeCursor,
    pub capsule_digest: Option<[u8; 32]>,
    pub tx_hash: Option<[u8; 32]>,
}

/// Authenticated executable bytes escape only after matching committed readback.
/// This is local custody/retry permission, never signing or submission approval.
pub struct ReleasedOperation {
    payload: zeroize::Zeroizing<Vec<u8>>,
    snapshot: OperationSnapshot,
}
impl ReleasedOperation {
    pub fn payload(&self) -> &[u8] { &self.payload }
    pub fn snapshot(&self) -> &OperationSnapshot { &self.snapshot }
    pub fn into_payload(self) -> zeroize::Zeroizing<Vec<u8>> { self.payload }
}
impl fmt::Debug for ReleasedOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleasedOperation").field("state", &self.snapshot.state).finish_non_exhaustive()
    }
}

/// Sanitized categories never retain SQL diagnostics, secret bytes, paths or keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeTradeError {
    Database(DatabaseError),
    Custody(CustodyError),
    Quote,
    Binding,
    Encoding,
    ResourceLimit,
    Missing,
    Conflict,
    StaleVersion,
    StaleGeneration,
    State,
    Stopped,
}
impl fmt::Display for NativeTradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => fmt::Display::fmt(e, f),
            Self::Custody(e) => fmt::Display::fmt(e, f),
            Self::Quote => f.write_str("native authenticated quote rejected"),
            Self::Binding => f.write_str("native independently retained binding rejected"),
            Self::Encoding => f.write_str("native capsule encoding rejected"),
            Self::ResourceLimit => f.write_str("native custody resource bound exceeded"),
            Self::Missing => f.write_str("native durable operation is absent"),
            Self::Conflict => f.write_str("native immutable operation conflicts"),
            Self::StaleVersion => f.write_str("native operation version is stale"),
            Self::StaleGeneration => f.write_str("native writer generation is stale"),
            Self::State => f.write_str("native operation is not eligible for this action"),
            Self::Stopped => f.write_str("native quote was stopped before release"),
        }
    }
}
impl std::error::Error for NativeTradeError {}
impl From<DatabaseError> for NativeTradeError {
    fn from(error: DatabaseError) -> Self { Self::Database(error) }
}
impl From<sqlx::Error> for NativeTradeError {
    fn from(error: sqlx::Error) -> Self { DatabaseError::from(error).into() }
}
impl From<CustodyError> for NativeTradeError {
    fn from(error: CustodyError) -> Self { Self::Custody(error) }
}

pub(crate) fn phase_code(phase: QuotePhase) -> i16 {
    match phase { QuotePhase::Proposal => 0, QuotePhase::UserAcceptance => 1, QuotePhase::Agreed => 2 }
}
pub(crate) fn decode_phase(code: i16) -> Result<QuotePhase, NativeTradeError> {
    match code { 0 => Ok(QuotePhase::Proposal), 1 => Ok(QuotePhase::UserAcceptance), 2 => Ok(QuotePhase::Agreed), _ => Err(invalid_record()) }
}
pub(crate) fn invalid_record() -> NativeTradeError { DatabaseError::SchemaIdentity.into() }
pub(crate) fn require_one(affected: u64) -> Result<(), NativeTradeError> {
    if affected == 1 { Ok(()) } else { Err(invalid_record()) }
}
pub(crate) fn check_cursor(actual: TradeCursor, expected: TradeCursor) -> Result<(), NativeTradeError> {
    expected.validate()?;
    if actual.generation != expected.generation { return Err(NativeTradeError::StaleGeneration); }
    if actual.version != expected.version { return Err(NativeTradeError::StaleVersion); }
    Ok(())
}
