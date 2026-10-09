//! Ziquid Protocol off-chain destination client boundary.
//!
//! Intended implementation: reading destination state and building/submitting
//! calls for selected targets. Target verifier and escrow implementations
//! belong to the separate chain-specific contract packages.
//!
//! Closed HyperCore testnet information reads are implemented; no settlement,
//! signing, exchange submission or financial chain support follows.

mod http;
pub mod hypercore;
pub mod native;
pub mod samechain;
pub mod source;
