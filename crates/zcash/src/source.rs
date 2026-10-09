//! Read-only full-block acquisition from an explicit caller-owned node endpoint.
//!
//! Node observations are not consensus/history validation, payment classification,
//! or a financial fact. No wallet keys, private stores, or runtime are required.

pub use zoss_zcash::{AcquiredBlock, SourceError};

/// Acquires full raw bytes for an explicit NU6.3 testnet height and nonzero policy ID.
///
/// The node cross-checks full transaction authorizing bytes, but its provenance is
/// unverified. Historical acquisition retains canonical eligibility `Unknown` and
/// never implies confirmation eligibility, a trusted checkpoint, or genesis validity.
/// Consumers must apply their own structural and eventual consensus/proof relations.
/// There is no default endpoint, height, policy, confirmation threshold, or fallback.
pub fn acquire_historical_block(
    endpoint: &str,
    height: u32,
    policy_id: [u8; 32],
) -> Result<AcquiredBlock, SourceError> {
    zoss_zcash::NodeRpc::new(endpoint)?.acquire_historical_block(height, policy_id)
}
