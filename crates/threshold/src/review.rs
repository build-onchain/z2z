//! Route-1a §11.2 Q3 signer semantic-review package: the checks a signing
//! participant must run, against data it holds itself, before emitting any
//! share. The coordinator transports bytes and cannot substitute meaning, so
//! a sighash that verifies against `rk` is not enough — the signer compares
//! its own view of the financial effects with the agreed terms.
//!
//! Implemented here (no PCZT decode needed):
//! - §11.2 check 2: the action's `rk` equals the group key randomized by the
//!   carried alpha (a mismatched alpha would make the signer authorize a
//!   re-randomization the counterparty chose adversarially);
//! - §11.2 check 3: observed effects equal the signer's own copy of the
//!   agreed terms (C: S's payout; R: U's return minus agreed fee).
//!
//! Integration-side duties (§11.2 checks 1 and 4) consume orchard/pczt types
//! and stay with the transaction-assembly integration: recomputing the
//! shielded sighash from decoded effects, and nullifier/note consistency for
//! the side that holds the material.

use crate::{Alpha, GroupPublicKey};

/// One output effect as the reviewing signer sees it: the raw 43-byte Orchard
/// address (11-byte diversifier || 32-byte `pk_d`) and the value in zatoshis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputEffect {
    pub recipient: [u8; 43],
    pub value_zat: u64,
}

/// The effect set of the transaction being authorized, in canonical
/// descriptor order (§7.2 Descriptors order is the agreement reference).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effects {
    pub outputs: Vec<OutputEffect>,
    pub fee_zat: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewError {
    /// A supplied key or alpha failed to round-trip through the ciphersuite.
    Encoding,
    /// The action `rk` is not the group key randomized by the carried alpha.
    AlphaMismatch,
    /// Different number of outputs than the agreed terms.
    OutputCountMismatch,
    /// Output `index` pays a different recipient than the agreed terms.
    RecipientMismatch { index: usize },
    /// Output `index` pays a different value than the agreed terms.
    ValueMismatch { index: usize },
    /// The fee differs from the agreed terms.
    FeeMismatch,
}

/// §11.2 check 2.
pub fn check_action_rk(
    group: &GroupPublicKey,
    alpha: &Alpha,
    rk: &[u8; 32],
) -> Result<(), ReviewError> {
    let expected = alpha
        .randomized_public_key(group)
        .map_err(|_| ReviewError::Encoding)?;
    if expected == *rk {
        Ok(())
    } else {
        Err(ReviewError::AlphaMismatch)
    }
}

/// §11.2 check 3: order-sensitive comparison of the observed effects against
/// the signer's own copy of the agreed terms.
pub fn check_effects(agreed: &Effects, observed: &Effects) -> Result<(), ReviewError> {
    if agreed.outputs.len() != observed.outputs.len() {
        return Err(ReviewError::OutputCountMismatch);
    }
    for (index, (agreed, observed)) in agreed.outputs.iter().zip(&observed.outputs).enumerate() {
        if agreed.recipient != observed.recipient {
            return Err(ReviewError::RecipientMismatch { index });
        }
        if agreed.value_zat != observed.value_zat {
            return Err(ReviewError::ValueMismatch { index });
        }
    }
    if agreed.fee_zat != observed.fee_zat {
        return Err(ReviewError::FeeMismatch);
    }
    Ok(())
}