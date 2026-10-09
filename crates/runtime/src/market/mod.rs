//! Explicit local safety integration, never a source scanner, native signer or network sender.

mod cli;
pub mod config;
pub mod coordinator;
mod facts;
mod fixture;
pub mod ledger;
mod local;
pub mod native;
pub mod process;
mod target;
pub use cli::run_cli;
pub use local::local_safety_scenario;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    Configuration,
    Input,
    Frame,
    Process,
    ProcessTimeout,
    KeyBootstrap,
    NativePlanMismatch,
    TargetReceipt,
    Ledger(crate::market::ledger::LedgerError),
    Custody(ziquid_zcash::custody::CustodyError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ledger(error) => write!(formatter, "ledger rejected: {error}"),
            Self::Custody(error) => write!(formatter, "{error}"),
            error => write!(formatter, "runtime rejected: {error:?}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<crate::market::ledger::LedgerError> for Error {
    fn from(error: crate::market::ledger::LedgerError) -> Self {
        Self::Ledger(error)
    }
}
impl From<ziquid_zcash::custody::CustodyError> for Error {
    fn from(error: ziquid_zcash::custody::CustodyError) -> Self {
        Self::Custody(error)
    }
}
