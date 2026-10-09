//! Ziquid Protocol settlement proof implementation boundary.
//!
//! Intended implementation: transaction, payment and history relations,
//! circuit witness preparation, proving and verifier artifacts, reusing
//! selected upstream cryptographic primitives. Economic allocation remains
//! the responsibility of the protocol rules and destination contracts.
//!
//! Sender-ciphertext validation is an application subrelation, not settlement
//! verification or accepted-history proof. Remaining financial relations are
//! unavailable until their actual constraints and verifier artifacts exist.

pub mod artifacts;
mod canonical_bytes;
#[path = "native_relation/effects.rs"]
mod native_effects;
pub mod chain_history;
pub mod genesis;
pub mod header;
pub mod history;
pub mod legacy_joinsplit;
pub mod legacy_sighash;
pub mod post_nu5_body;
pub mod native_relation;
pub mod orchard_original;
pub mod overwinter;
pub mod preparation;
pub mod raw_v5;
pub mod samechain;
pub mod sapling_coinbase;
pub mod sapling_crypto;
pub mod sapling_sighash;
#[cfg(not(target_os = "zkvm"))]
pub mod source_admission;
pub mod source_comparison;
pub mod source_note;
pub mod source_replay;
pub mod source_selection;
pub mod sprout;
pub mod sprout_groth16;
pub mod zip244;

#[cfg(test)]
#[path = "../tests/fixtures/overwinter-mined.rs"]
mod overwinter_fixture;

#[cfg(test)]
#[path = "../tests/fixtures/sprout-groth16-testnet-280003.rs"]
mod sprout_groth_fixture;
