#![forbid(unsafe_code)]
//! Canonical market records and independent safety predicates.
//!
//! `market` requires no I/O, `std` or heap allocation. `market-host` adds
//! ordinary Ed25519 verification, not key custody or signing. Canonical bytes,
//! observed facts, authenticated statements and accepted chain/history/MPC
//! evidence are separate authorities; none of these policy checks is proof.

mod domain;
mod policy;
mod records;

pub use domain::*;
pub use policy::*;
pub use records::*;

#[cfg(feature = "market-host")]
pub use ed25519_dalek::SigningKey;

pub type Id = [u8; 32];

/// SHA256 of exact supplied bytes, with no implicit monetary domain.
pub fn sha256(bytes: &[u8]) -> Id {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidLength,
    UnsupportedVersion,
    UnsupportedSourceNetwork,
    UnsupportedSourcePool,
    UnsupportedSourceBranch,
    UnsupportedTransactionVersion,
    UnsupportedSignatureScheme,
    InvalidDomain,
    DomainMismatch,
    TokenProgramMismatch,
    InvalidGeneration,
    Overflow,
    ZeroUnits,
    ZeroAmount,
    DuplicatePortion,
    OverlappingPortion,
    PartitionMismatch,
    InvalidTransition,
    InvalidDecisionHead,
    EvidenceMismatch,
    IntentNotPermitted,
    CompetingIntent,
    MissingUnanimity,
    DuplicateSigner,
    UnenrolledSigner,
    InvalidAuthorizationKey,
    InvalidSignature,
    WrongAcknowledgement,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        output.write_str(match self {
            Self::InvalidLength => "invalid canonical record length",
            Self::UnsupportedVersion => "unsupported canonical record version",
            Self::UnsupportedSourceNetwork => "unsupported source network",
            Self::UnsupportedSourcePool => "unsupported source pool",
            Self::UnsupportedSourceBranch => "unsupported source branch",
            Self::UnsupportedTransactionVersion => "unsupported source transaction version",
            Self::UnsupportedSignatureScheme => "unsupported signature scheme",
            Self::InvalidDomain => "incomplete domain",
            Self::DomainMismatch => "different monetary domain",
            Self::TokenProgramMismatch => "not the legacy token program",
            Self::InvalidGeneration => "stale generation or prior version",
            Self::Overflow => "economic integer overflow",
            Self::ZeroUnits => "zero economic unit size",
            Self::ZeroAmount => "zero transfer or portion amount",
            Self::DuplicatePortion => "duplicate portion identity",
            Self::OverlappingPortion => "overlapping allocation portions",
            Self::PartitionMismatch => "allocation does not conserve held debit",
            Self::InvalidTransition => "invalid transition tag or record role",
            Self::InvalidDecisionHead => "decision head does not bind predecessor and operation",
            Self::EvidenceMismatch => "missing or inconsistent policy evidence",
            Self::IntentNotPermitted => "native intent not permitted by disposition",
            Self::CompetingIntent => "another potentially live intent owns this portion",
            Self::MissingUnanimity => "exactly three acknowledgements required",
            Self::DuplicateSigner => "duplicate authority key",
            Self::UnenrolledSigner => "acknowledgement signer not enrolled",
            Self::InvalidAuthorizationKey => "invalid ordinary Ed25519 authority key",
            Self::InvalidSignature => "invalid ordinary Ed25519 signature",
            Self::WrongAcknowledgement => "acknowledgement names a different decision",
        })
    }
}

impl core::error::Error for ProtocolError {}

#[cfg(not(target_os = "solana"))]
fn canonical_nonidentity_prime_point(encoded: &Id) -> bool {
    use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
    let Some(point) = CompressedEdwardsY(*encoded).decompress() else {
        return false;
    };
    point.compress().as_bytes() == encoded && !point.is_identity() && point.is_torsion_free()
}

/// The same enrollment predicate using maintained SBF group operations.
/// Adding identity recompresses P canonically; [L-1]P+P checks [L]P==0
/// without passing the noncanonical scalar L to the multiplication syscall.
#[cfg(target_os = "solana")]
fn canonical_nonidentity_prime_point(encoded: &Id) -> bool {
    use solana_curve25519::{
        edwards::{PodEdwardsPoint, add_edwards, multiply_edwards},
        scalar::PodScalar,
    };
    const IDENTITY: PodEdwardsPoint = PodEdwardsPoint([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    // RFC8032 L=2^252+27742317777372353535851937790883648493.
    const L_MINUS_ONE: PodScalar = PodScalar([
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    let point = PodEdwardsPoint(*encoded);
    if point == IDENTITY || add_edwards(&point, &IDENTITY) != Some(point) {
        return false;
    }
    let Some(product) = multiply_edwards(&L_MINUS_ONE, &point) else {
        return false;
    };
    add_edwards(&product, &point) == Some(IDENTITY)
}

/// Canonical prime-subgroup enrollment; never normalizes registered key bytes.
pub fn validate_authorization_key(key: &Id) -> Result<(), ProtocolError> {
    if !canonical_nonidentity_prime_point(key) {
        return Err(ProtocolError::InvalidAuthorizationKey);
    }
    Ok(())
}

/// Shared host/target signature encoding check, before actual verification.
pub fn validate_signature_encoding(signature: &[u8; 64]) -> Result<(), ProtocolError> {
    use curve25519_dalek::scalar::Scalar;
    let mut r = [0; 32];
    r.copy_from_slice(&signature[..32]);
    let mut s = [0; 32];
    s.copy_from_slice(&signature[32..]);
    if !canonical_nonidentity_prime_point(&r)
        || !bool::from(Scalar::from_canonical_bytes(s).is_some())
    {
        return Err(ProtocolError::InvalidSignature);
    }
    Ok(())
}
