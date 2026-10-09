#![cfg_attr(not(feature = "native"), no_std)]
//! Pure native statements and target-safe market rules.
//!
//! With the default `native` feature, `ValidatedContext` validates only shape
//! and canonical encoding; neither it nor `allocate` authenticates source
//! history/payment or authorizes funds. The DEX-specific native-EVM wire is not
//! ABI or a Zoss common-library claim. `market` exposes separate canonical
//! market records and policy predicates, not financial or chain-history proof.

#[cfg(feature = "native")]
mod allocation;
#[cfg(feature = "native")]
mod amount;
#[cfg(feature = "native")]
mod context;
#[cfg(feature = "native")]
pub mod samechain;
#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "native")]
pub use allocation::{Allocation, AllocationError, allocate};
#[cfg(feature = "native")]
pub use amount::{AmountError, MAX_SOURCE_AMOUNT, NativeAmount, SourceAmount};
#[cfg(feature = "native")]
pub use context::{
    CONTEXT_ENCODED_LEN, CONTEXT_SCHEMA_VERSION, ContextError, ContextField, DEX_CONTEXT_DOMAIN,
    IRONWOOD_POOL, MAX_QUOTED_RECEIVERS, PreparationBinding, SOURCE_TESTNET,
    SOURCE_TRANSACTION_VERSION, SemanticCommitmentError, SolverCapsule, StatementContext,
    ValidatedContext, input_commitment, note_consumption_tag, payment_commitment,
    preparation_consent_digest, preparation_packet_binding, solver_capsule_commitment,
};

#[cfg(feature = "market")]
pub mod market;
