//! Durable native execution primitives; no signing, source verification or
//! financial terminal state can be inferred from these local records.

#[cfg(all(test, feature = "postgres-tests"))]
extern crate self as ziquid_runtime;

#[cfg(all(test, feature = "postgres-tests"))]
#[path = "../tests/market_support/ledger.rs"]
pub(crate) mod market_ledger_test_support;

pub mod native_quote;
pub mod native_trade;
pub mod native_cli;
pub mod store;
pub mod custody;
pub mod native_recovery;
pub mod native_source;
pub mod database;
pub mod market;
pub mod hypercore;
pub mod samechain;
pub mod node;
