//! Actual Sprout/Overwinter PHGR and V4 Groth16 JoinSplits through finite NU6.3.
//!
//! Checks public-value bounds, transaction-local nullifier uniqueness, the
//! branch-selected Ed25519 authorization, and every authenticated fixed-key proof.
//! This is not transparent authorization, UTXO/anchor availability, global
//! nullifier spentness, source history/finality, or a financial settlement fact.
//! It does not repair the historical BCTV14 setup soundness flaw.
//!
//! Zcash source: 0512e9eb00f97172346e0fac854625d59771e4f7,
//! `src/main.cpp::{CheckTransaction,ContextualCheckTransaction}` and
//! `src/primitives/transaction.h::JSDescription::SerializationOp`.
//! Pre-Canopy signature backend: libsodium 1.0.15 without ED25519_COMPAT,
//! commit c5e43f4c1cf62b4669b1f33516fc33ef2d005187,
//! `src/libsodium/crypto_sign/ed25519/ref10/open.c`, Git blob
//! fa1c72d8ed3d2489823495280c04522995aaf11c. Its raw-R exclusions and
//! uncofactored equation are intentionally kept below Canopy. At Canopy, ZIP215
//! (zcash/zips a735caf76ed8d3fa0a50e4f6b706ca9dac39079b) requires complete
//! Edwards decoding, canonical S, and the cofactored equation instead.

/*
Zcash public-value/nullifier checks translated from its MIT sources:
Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-2014 The Bitcoin Core developers
Copyright (c) 2016-2019 The Zcash developers
Copyright (c) 2009-2019 The Bitcoin Core developers
Copyright (c) 2009-2019 Bitcoin Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Original signature recipe and raw-R blacklist translated from libsodium:
ISC License

Copyright (c) 2013-2017
Frank Denis <j at pureftpd dot org>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

use std::fmt;

use corez::io::{self, Write};
use curve25519_dalek::{edwards::{CompressedEdwardsY, EdwardsPoint}, scalar::Scalar, traits::IsIdentity};
use sha2::{Digest, Sha512};
use zcash_primitives::transaction::{Transaction, components::sprout::{Bundle, JsDescription}};
use zcash_protocol::{consensus::BranchId, value::MAX_MONEY};

use crate::{
    legacy_sighash::{LegacySighashError, check_legacy_transaction, legacy_joinsplit_signature_hash},
    overwinter::OverwinterSignatureHash,
    sapling_sighash::SaplingSignatureHash,
    sprout::{LegacyError, LegacyJoinSplit, verify_sprout_legacy},
    sprout_groth16::{GrothError, verify_sprout_groth16},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyJoinSplitError {
    UnsupportedVersion,
    UnsupportedBranch,
    IncompatibleTransaction,
    InvalidPublicValues,
    DebitOutOfRange,
    CreditOutOfRange,
    DuplicateNullifier,
    InvalidSignature,
    Serialization,
    SproutProof { index: usize, error: LegacyError },
    SproutGrothProof { index: usize, error: GrothError },
}

impl fmt::Display for LegacyJoinSplitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => formatter.write_str("not a compatible original JoinSplit transaction version"),
            Self::UnsupportedBranch => formatter.write_str("JoinSplit signature acceptance is not implemented at NU6.3 or later"),
            Self::IncompatibleTransaction => formatter.write_str("transaction contains incompatible legacy fields"),
            Self::InvalidPublicValues => formatter.write_str("invalid legacy JoinSplit public values"),
            Self::DebitOutOfRange => formatter.write_str("legacy transparent-output/JoinSplit debit total is out of range"),
            Self::CreditOutOfRange => formatter.write_str("legacy JoinSplit credit total is out of range"),
            Self::DuplicateNullifier => formatter.write_str("duplicate transaction-local Sprout nullifier"),
            Self::InvalidSignature => formatter.write_str("original legacy JoinSplit signature verification failed"),
            Self::Serialization => formatter.write_str("legacy JoinSplit serialization failed"),
            Self::SproutProof { index, error } => write!(formatter, "legacy JoinSplit {index}: {error}"),
            Self::SproutGrothProof { index, error } => write!(formatter, "Sprout Groth16 JoinSplit {index}: {error}"),
        }
    }
}

impl std::error::Error for LegacyJoinSplitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SproutProof { error, .. } => Some(error),
            Self::SproutGrothProof { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Borrows the actual transaction; no caller-supplied witness, key, digest, or
/// validity flag. The enclosing byte boundary must canonically parse it and
/// consume its reader. Cheap checks precede authorization; failed authorization
/// never starts the more expensive proof equations. No JoinSplits means no
/// JoinSplit signature is required, but legacy shape and output bounds remain.
pub fn verify_legacy_joinsplit_crypto(transaction: &Transaction) -> Result<(), LegacyJoinSplitError> {
    match check_legacy_transaction(transaction) {
        Ok(_) => {}
        Err(LegacySighashError::UnsupportedVersion) => return Err(LegacyJoinSplitError::UnsupportedVersion),
        Err(_) => return Err(LegacyJoinSplitError::IncompatibleTransaction),
    }
    verify_joinsplit_crypto(transaction, || {
        legacy_joinsplit_signature_hash(transaction).map_err(|_| LegacyJoinSplitError::Serialization)
    }, verify_actual_proofs)
}

/// Verifies the SAME transaction borrowed by the checked ZIP143 cache. Original
/// PHGR/public-value/uniqueness and libsodium acceptance are shared with Sprout;
/// the fixed JoinSplit ALL digest is derived internally, never caller supplied.
/// This is still not transparent authorization or contextual ledger acceptance.
pub fn verify_overwinter_joinsplit_crypto(hashes: &OverwinterSignatureHash<'_>) -> Result<(), LegacyJoinSplitError> {
    verify_joinsplit_crypto(hashes.transaction(), || Ok(hashes.joinsplit()), verify_actual_proofs)
}

/// Verifies every Groth16 JoinSplit and branch-selected detached Ed25519 signature
/// of the SAME guarded V4 transaction: original libsodium before Canopy, ZIP215
/// at Canopy through NU6.3. Height/finite-era checks belong to ledger admission.
pub fn verify_sapling_joinsplit_crypto(hashes: &SaplingSignatureHash<'_>) -> Result<(), LegacyJoinSplitError> {
    if !matches!(hashes.transaction().consensus_branch_id(), BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) {
        return Err(LegacyJoinSplitError::UnsupportedBranch);
    }
    verify_joinsplit_crypto(hashes.transaction(), || Ok(hashes.shielded()), verify_actual_groth_proofs)
}

fn verify_joinsplit_crypto(
    transaction: &Transaction,
    signature_hash: impl FnOnce() -> Result<[u8; 32], LegacyJoinSplitError>,
    verify_proofs: impl FnOnce(&Bundle) -> Result<(), LegacyJoinSplitError>,
) -> Result<(), LegacyJoinSplitError> {
    let balance = transaction.sapling_bundle().map_or(0, |bundle| i64::from(*bundle.value_balance()));
    if !(-(MAX_MONEY as i64)..=MAX_MONEY as i64).contains(&balance) {
        return Err(LegacyJoinSplitError::InvalidPublicValues);
    }
    let mut credit = balance.max(0) as u64;
    let mut debit = balance.min(0).unsigned_abs();
    if let Some(transparent) = transaction.transparent_bundle() {
        for output in &transparent.vout {
            debit = debit.checked_add(u64::from(output.value()))
                .filter(|total| *total <= MAX_MONEY)
                .ok_or(LegacyJoinSplitError::DebitOutOfRange)?;
        }
    }
    let Some(bundle) = transaction.sprout_bundle() else {
        return Ok(());
    };
    let mut nullifiers = Vec::with_capacity(bundle.joinsplits.len() * 2);
    for description in &bundle.joinsplits {
        let old = u64::try_from(description.vpub_old()).map_err(|_| LegacyJoinSplitError::InvalidPublicValues)?;
        let new = u64::try_from(description.vpub_new()).map_err(|_| LegacyJoinSplitError::InvalidPublicValues)?;
        if old > MAX_MONEY || new > MAX_MONEY || (old != 0 && new != 0) {
            return Err(LegacyJoinSplitError::InvalidPublicValues);
        }
        debit = debit.checked_add(old).filter(|total| *total <= MAX_MONEY)
            .ok_or(LegacyJoinSplitError::DebitOutOfRange)?;
        credit = credit.checked_add(new).filter(|total| *total <= MAX_MONEY)
            .ok_or(LegacyJoinSplitError::CreditOutOfRange)?;
        nullifiers.extend_from_slice(description.nullifiers());
    }
    nullifiers.sort_unstable();
    if nullifiers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LegacyJoinSplitError::DuplicateNullifier);
    }
    let digest = signature_hash()?;
    let signature_valid = if matches!(transaction.consensus_branch_id(), BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) {
        verify_zip215_ed25519(&bundle.joinsplit_pubkey, &bundle.joinsplit_sig, &digest)
    } else {
        verify_original_ed25519(&bundle.joinsplit_pubkey, &bundle.joinsplit_sig, &digest)
    };
    if !signature_valid {
        return Err(LegacyJoinSplitError::InvalidSignature);
    }
    verify_proofs(bundle)
}

fn verify_actual_proofs(bundle: &Bundle) -> Result<(), LegacyJoinSplitError> {
    for (index, description) in bundle.joinsplits.iter().enumerate() {
        let statement = actual_statement(description, &bundle.joinsplit_pubkey)?;
        let proof = capture_phgr_proof(description)?;
        verify_sprout_legacy(&statement, &proof).map_err(|error| LegacyJoinSplitError::SproutProof { index, error })?;
    }
    Ok(())
}

fn verify_actual_groth_proofs(bundle: &Bundle) -> Result<(), LegacyJoinSplitError> {
    for (index, description) in bundle.joinsplits.iter().enumerate() {
        let statement = actual_statement(description, &bundle.joinsplit_pubkey)?;
        let proof = description.groth_proof_bytes().ok_or(LegacyJoinSplitError::IncompatibleTransaction)?;
        verify_sprout_groth16(&statement, proof)
            .map_err(|error| LegacyJoinSplitError::SproutGrothProof { index, error })?;
    }
    Ok(())
}

fn actual_statement(description: &JsDescription, public_key: &[u8; 32]) -> Result<LegacyJoinSplit, LegacyJoinSplitError> {
    Ok(LegacyJoinSplit {
        anchor: *description.anchor(),
        nullifiers: *description.nullifiers(),
        macs: *description.macs(),
        commitments: *description.commitments(),
        vpub_old: u64::try_from(description.vpub_old()).map_err(|_| LegacyJoinSplitError::InvalidPublicValues)?,
        vpub_new: u64::try_from(description.vpub_new()).map_err(|_| LegacyJoinSplitError::InvalidPublicValues)?,
        random_seed: *description.random_seed(),
        joinsplit_pubkey: *public_key,
    })
}

const PHGR_DESCRIPTION_BYTES: usize = 1802;
const PHGR_PROOF_START: usize = 304;
const PHGR_PROOF_END: usize = 600;

// Only the proof range is copied; the complete write stream is counted rather
// than materialized. No second parser or full 1802-byte description buffer.
struct ProofCapture {
    proof: [u8; PHGR_PROOF_END - PHGR_PROOF_START],
    written: usize,
    captured: usize,
}

impl Write for ProofCapture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self.written.checked_add(bytes.len()).filter(|end| *end <= PHGR_DESCRIPTION_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unexpected PHGR description length"))?;
        let start = self.written.max(PHGR_PROOF_START);
        let stop = end.min(PHGR_PROOF_END);
        if start < stop {
            self.proof[start - PHGR_PROOF_START..stop - PHGR_PROOF_START]
                .copy_from_slice(&bytes[start - self.written..stop - self.written]);
            self.captured += stop - start;
        }
        self.written = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capture_phgr_proof(description: &JsDescription) -> Result<[u8; 296], LegacyJoinSplitError> {
    if description.groth_proof_bytes().is_some() {
        return Err(LegacyJoinSplitError::IncompatibleTransaction);
    }
    let mut writer = ProofCapture { proof: [0; 296], written: 0, captured: 0 };
    description.write(&mut writer).map_err(|_| LegacyJoinSplitError::Serialization)?;
    if writer.written != PHGR_DESCRIPTION_BYTES || writer.captured != writer.proof.len() {
        return Err(LegacyJoinSplitError::Serialization);
    }
    Ok(writer.proof)
}

// Exact 1.0.15 literals, including its erroneous sign-sensitive exclusions.
// A corrected small-order test changes historical acceptance and is forbidden.
const ORIGINAL_R_BLACKLIST: [[u8; 32]; 12] = [
    [0; 32],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
    [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
    [0x13, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x85],
    [0xb4, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa],
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    [0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    [0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
];

fn verify_original_ed25519(public_key: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> bool {
    let (r_bytes, s_bytes) = signature.split_at(32);
    let s_bytes: [u8; 32] = s_bytes.try_into().expect("fixed signature scalar length");
    let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    if ORIGINAL_R_BLACKLIST.iter().any(|excluded| r_bytes == excluded) || *public_key == [0; 32] {
        return false;
    }
    let Some(point) = CompressedEdwardsY(*public_key).decompress() else {
        return false;
    };
    // Original raw public-key encoding enters the challenge, including accepted
    // noncanonical encodings. All inputs are public; variable time is intended.
    let challenge = ed25519_challenge(r_bytes, public_key, message);
    let recompressed = EdwardsPoint::vartime_double_scalar_mul_basepoint(&challenge, &(-point), &scalar).compress().to_bytes();
    recompressed.as_slice() == r_bytes
}

fn verify_zip215_ed25519(public_key: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> bool {
    let (r_bytes, s_bytes) = signature.split_at(32);
    let s_bytes: [u8; 32] = s_bytes.try_into().expect("fixed signature scalar length");
    let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    // Pinned dalek4.1.3 decompress uses the low255 bits as a field element,
    // permits unreduced y, and negates the sqrt without rejecting x=0/sign=1
    // (edwards.rs:194-239; serial u32/u64 field::from_bytes). Do not add a
    // canonical recompression, blacklist, identity or subgroup restriction.
    let Some(point) = CompressedEdwardsY(*public_key).decompress() else {
        return false;
    };
    let r_bytes: [u8; 32] = r_bytes.try_into().expect("fixed signature point length");
    let Some(r_point) = CompressedEdwardsY(r_bytes).decompress() else {
        return false;
    };
    let challenge = ed25519_challenge(&r_bytes, public_key, message);
    let difference = EdwardsPoint::vartime_double_scalar_mul_basepoint(&challenge, &(-point), &scalar) - r_point;
    difference.mul_by_cofactor().is_identity()
}

fn ed25519_challenge(r_bytes: &[u8], public_key: &[u8; 32], message: &[u8]) -> Scalar {
    let challenge: [u8; 64] = Sha512::new().chain_update(r_bytes).chain_update(public_key).chain_update(message).finalize().into();
    Scalar::from_bytes_mod_order_wide(&challenge)
}

#[cfg(test)]
#[path = "../tests/fixtures/legacy-joinsplit-mainnet-396.rs"]
mod primary_fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{overwinter_fixture, sprout_groth_fixture};
    use zcash_protocol::consensus::BranchId;

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), 2 * N);
        let mut result = [0; N];
        for (output, pair) in result.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
            let digit = |value| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid fixture hex"),
            };
            *output = digit(pair[0]) * 16 + digit(pair[1]);
        }
        result
    }

    fn actual_bundle() -> Bundle {
        let raw = bytes::<2022>(primary_fixture::TRANSACTION_HEX);
        let mut remaining = raw.as_slice();
        let transaction = Transaction::read(&mut remaining, BranchId::Sprout).unwrap();
        assert!(remaining.is_empty());
        transaction.sprout_bundle().unwrap().clone()
    }

    #[test]
    fn original_native_oracle_accepts_rfc_and_identity_noncanonical_public_keys() {
        // Independently executed against the original normal-build C verifier:
        // libsodium-1.0.15.tar.gz SHA256
        // fb6a9e879a2f674592e4328c5d9f79f082405ee4bb05cb6e679b90afe9e178f4.
        // These are public-data primitive tuples, not signed transactions or
        // private-key fixtures. Modern strict verification rejects identity A.
        let rfc_key = bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let rfc_sig = bytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assert!(verify_original_ed25519(&rfc_key, &rfc_sig, &[0x72]));
        let identity_signature = bytes("58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000");
        for public_key in [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            assert!(verify_original_ed25519(&bytes(public_key), &identity_signature, &[0x72]), "original accepted {public_key}");
        }
        assert!(!verify_original_ed25519(&[0; 32], &identity_signature, &[0x72]));
        let rfc_s_plus_l = bytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69daf52db7415978abc61b2c2eb6aeebfca0387b2eaeb4302aeeb00d291612bb0c10");
        assert!(!verify_original_ed25519(&rfc_key, &rfc_s_plus_l, &[0x72]));
    }

    #[test]
    fn original_native_oracle_preserves_uncofactored_equation_and_raw_key_challenge() {
        // Six additional literal tuples were observed using the same pinned
        // original normal-build C verifier, independently of this Rust code.
        let basepoint_signature = bytes("58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000");
        let order_two_key = bytes("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert!(verify_original_ed25519(&order_two_key, &basepoint_signature, &[0]));
        assert!(!verify_original_ed25519(&order_two_key, &basepoint_signature, &[1]));
        // For order-two A, R=B and S=1, multiplying the equation by eight
        // discards A for either message. Original rejection of message1 guards
        // against switching to the ZIP-215 cofactored relation. No ZIP backend
        // execution is claimed by this mathematical distinction.

        let noncanonical_order_four = bytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let canonical_order_four = bytes("0000000000000000000000000000000000000000000000000000000000000080");
        assert!(verify_original_ed25519(&noncanonical_order_four, &basepoint_signature, &[2]));
        assert!(!verify_original_ed25519(&canonical_order_four, &basepoint_signature, &[2]));
        // These encodings decode to the same A, but the raw encodings produce
        // different k. Re-encoding A before hashing loses original acceptance.
        let identity_key = bytes("0100000000000000000000000000000000000000000000000000000000000000");
        let excluded_identity_r = bytes("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assert!(!verify_original_ed25519(&identity_key, &excluded_identity_r, &[0x72]));
        let undecodable_key = bytes("0200000000000000000000000000000000000000000000000000000000000000");
        assert!(!verify_original_ed25519(&undecodable_key, &basepoint_signature, &[0x72]));
    }

    #[test]
    fn original_native_oracle_rejects_all_twelve_raw_r_exclusions() {
        // Literal independently observed original-C negatives, not values
        // computed from ORIGINAL_R_BLACKLIST or a modern small-order predicate.
        let key = bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        for raw_r in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "13e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            "b4176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            let mut signature = [0; 64];
            signature[..32].copy_from_slice(&bytes::<32>(raw_r));
            signature[32] = 1;
            assert!(!verify_original_ed25519(&key, &signature, &[0x72]), "original rejected R {raw_r}");
        }
    }

    #[test]
    fn zip215_accepts_complete_torsion_and_noncanonical_point_encodings() {
        // The ZIP215 cofactored equation is identically zero for S=0 and
        // any torsion A/R pair. Literal canonical and alternate encodings:
        // https://github.com/C2SP/CCTV/blob/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/ed25519/README.md
        let encodings = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ];
        for public_key in encodings {
            for raw_r in encodings {
                let mut signature = [0; 64];
                signature[..32].copy_from_slice(&bytes::<32>(raw_r));
                assert!(verify_zip215_ed25519(&bytes(public_key), &signature, b"Zcash"), "A={public_key}, R={raw_r}");
            }
        }
        let order_two_key = bytes("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let basepoint_signature = bytes("58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000");
        assert!(verify_zip215_ed25519(&order_two_key, &basepoint_signature, &[1]));
        assert!(!verify_original_ed25519(&order_two_key, &basepoint_signature, &[1]));
    }

    #[test]
    fn zip215_mixed_order_and_raw_r_challenge_vectors() {
        // Exact independently published CCTV vectors 6, 16, 18, 19. Only
        // point encodings enter SHA512; substituting a canonical R changes k.
        // https://github.com/C2SP/CCTV/blob/50a8ecf2a220f4c8bdc4f085789b8e85c26829e7/ed25519/ed25519vectors.json
        // Git blob ebb2192a14d88c26979c40be0aff4cfba6892ed3,
        // SHA256 b38e84caf3e7e89170ff520292dbeae421b0a794c27408ce5ce973018fe3d7f9.
        let key = bytes("10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f");
        for (signature, message, valid) in [
            ("36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56bc02e2b9e63e385c058bf62b14b3a2b29ccefe8e38ddb536bc3f9865320a3d801", "ed25519vectors 10", true),
            ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f1cb421dfbd92aa6c30d550bff53c81cf650ace6deb96a8ec22d2fef84dbbe20b", "ed25519vectors 6", true),
            ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f5e176f12cfb0d4e6eb6929b19ae4c998ef05c1c2cf628a9b1fa1c21312627108", "ed25519vectors 7", false),
            ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f9472a69cd9a701a50d130ed52189e2455b23767db52cacb8716fb896ffeeac09", "ed25519vectors 3", false),
        ] {
            let signature = bytes(signature);
            assert_eq!(verify_zip215_ed25519(&key, &signature, message.as_bytes()), valid);
            assert!(!verify_original_ed25519(&key, &signature, message.as_bytes()));
        }
    }

    #[test]
    fn ed25519_challenge_preserves_noncanonical_a_with_prime_order_component() {
        // y=3 is a valid non-torsion point; unreduced y=p+3 represents
        // the same point. Literal challenge independently derived with Python
        // hashlib SHA512 over identity_R || original_A || b"ZIP215 raw A",
        // then reduced mod ell. No private key or signed transaction claimed.
        let raw_a = bytes("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let canonical_a = bytes("0300000000000000000000000000000000000000000000000000000000000000");
        let identity_r: [u8; 32] = bytes("0100000000000000000000000000000000000000000000000000000000000000");
        let point = CompressedEdwardsY(raw_a).decompress().unwrap();
        assert_eq!(point, CompressedEdwardsY(canonical_a).decompress().unwrap());
        assert!(!point.is_small_order());
        assert_eq!(ed25519_challenge(&identity_r, &raw_a, b"ZIP215 raw A").to_bytes(), bytes("a9127b1e314adf57496e4aa3ca9c477a6d2737282b6210cdb4e9ee0aa8b05a0e"));
        assert_eq!(ed25519_challenge(&identity_r, &canonical_a, b"ZIP215 raw A").to_bytes(), bytes("a1ec73bee25ce208d1f4c392ec3353b92e19397dba93c41051479ab102c2f804"));
    }

    #[test]
    fn zip215_rejects_scalar_malleation_and_invalid_curve_encodings() {
        let identity = bytes("0100000000000000000000000000000000000000000000000000000000000000");
        // A=identity, R=-B, S=ell-1 satisfies the full equation already.
        let mut signature = bytes("58666666666666666666666666666666666666666666666666666666666666e6ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        assert!(verify_zip215_ed25519(&identity, &signature, b"scalar boundary"));
        signature[..32].copy_from_slice(&identity);
        for scalar in [
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            signature[32..].copy_from_slice(&bytes::<32>(scalar));
            assert!(!verify_zip215_ed25519(&identity, &signature, b"scalar boundary"));
        }
        signature[32..].fill(0);
        assert!(verify_zip215_ed25519(&identity, &signature, b"scalar boundary"));
        let invalid = bytes("0200000000000000000000000000000000000000000000000000000000000000");
        assert!(!verify_zip215_ed25519(&invalid, &signature, b"invalid A"));
        signature[..32].copy_from_slice(&invalid);
        assert!(!verify_zip215_ed25519(&identity, &signature, b"invalid R"));
        let key = bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let signature = bytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assert!(verify_zip215_ed25519(&key, &signature, &[0x72]));
        assert!(!verify_zip215_ed25519(&key, &signature, &[0x73]));
        let signature = bytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69daf52db7415978abc61b2c2eb6aeebfca0387b2eaeb4302aeeb00d291612bb0c10");
        assert!(!verify_zip215_ed25519(&key, &signature, &[0x72]));
    }

    #[test]
    fn proof_stage_checks_every_actual_description_and_every_proof_component() {
        let actual = actual_bundle();
        assert_eq!(verify_actual_proofs(&actual), Ok(()));
        let g1 = bytes::<33>("0230644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46");
        let g2 = bytes::<65>("0a023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a");
        // Stage-only duplicated descriptions intentionally do not constitute a
        // valid transaction: the public helper rejects their repeated nullifiers.
        // They let an invalid later proof expose accidental first-only checking
        // without signing, key generation, or a public authorization bypass.
        for index in 0..2 {
            for (start, end) in [(0, 33), (33, 66), (66, 131), (131, 164), (164, 197), (197, 230), (230, 263), (263, 296)] {
                let mut changed = actual.clone();
                changed.joinsplits.push(changed.joinsplits[0].clone());
                let mut raw = Vec::new();
                changed.joinsplits[index].write(&mut raw).unwrap();
                let replacement: &[u8] = if start == 66 { &g2 } else { &g1 };
                raw[304 + start..304 + end].copy_from_slice(replacement);
                changed.joinsplits[index] = JsDescription::read(&raw[..], false).unwrap();
                assert_eq!(verify_actual_proofs(&changed), Err(LegacyJoinSplitError::SproutProof { index, error: LegacyError::InvalidProof }));
            }
        }
    }

    #[test]
    fn proof_statement_is_derived_from_every_actual_field_and_bundle_key() {
        let actual = actual_bundle();
        for field in 0..11 {
            let mut changed = actual.clone();
            let mut raw = Vec::new();
            changed.joinsplits[0].write(&mut raw).unwrap();
            match field {
                0 => raw[16] ^= 1,
                1 => raw[48] ^= 1,
                2 => raw[80] ^= 1,
                3 => raw[240] ^= 1,
                4 => raw[272] ^= 1,
                5 => raw[112] ^= 1,
                6 => raw[144] ^= 1,
                7 => raw[208] ^= 1,
                8 => changed.joinsplit_pubkey[0] ^= 1,
                9 => raw[0] ^= 1,
                10 => {
                    raw[..8].fill(0);
                    raw[8..16].copy_from_slice(&14_250_000_u64.to_le_bytes());
                }
                _ => unreachable!(),
            }
            changed.joinsplits[0] = JsDescription::read(&raw[..], false).unwrap();
            assert_eq!(verify_actual_proofs(&changed), Err(LegacyJoinSplitError::SproutProof { index: 0, error: LegacyError::InvalidProof }), "unbound actual field {field}");
        }
    }

    #[test]
    fn original_overwinter_phgr_checks_every_equation_even_after_valid_signature_stage() {
        let raw = bytes::<1917>(overwinter_fixture::MINED_V3_TX_HEX);
        let transaction = Transaction::read(raw.as_slice(), BranchId::Overwinter).unwrap();
        let actual = transaction.sprout_bundle().unwrap();
        assert_eq!(verify_actual_proofs(actual), Ok(()));
        let g1 = bytes::<33>("0230644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46");
        let g2 = bytes::<65>("0a023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a");
        for (start, end) in [(0, 33), (33, 66), (66, 131), (131, 164), (164, 197), (197, 230), (230, 263), (263, 296)] {
            let mut changed = actual.clone();
            let mut encoded = Vec::new();
            changed.joinsplits[0].write(&mut encoded).unwrap();
            let replacement: &[u8] = if start == 66 { &g2 } else { &g1 };
            encoded[304 + start..304 + end].copy_from_slice(replacement);
            changed.joinsplits[0] = JsDescription::read(encoded.as_slice(), false).unwrap();
            assert_eq!(verify_actual_proofs(&changed), Err(LegacyJoinSplitError::SproutProof { index: 0, error: LegacyError::InvalidProof }));
        }
        let mut malformed = actual.clone();
        let mut encoded = Vec::new();
        malformed.joinsplits[0].write(&mut encoded).unwrap();
        encoded[304] = 0xff;
        malformed.joinsplits[0] = JsDescription::read(encoded.as_slice(), false).unwrap();
        assert_eq!(verify_actual_proofs(&malformed), Err(LegacyJoinSplitError::SproutProof { index: 0, error: LegacyError::InvalidProofEncoding }));
    }

    #[test]
    fn original_v4_groth_stage_checks_every_proof_component_and_statement_from_actual_bundle() {
        let raw = bytes::<2005>(sprout_groth_fixture::TRANSACTION_HEX);
        let transaction = Transaction::read(raw.as_slice(), BranchId::Sapling).unwrap();
        let actual = transaction.sprout_bundle().unwrap();
        assert_eq!(verify_actual_groth_proofs(actual), Ok(()));
        // Valid encoded subgroup points, wrong equation: a parser-only check
        // would accept these actual mutations. Test-private stage also checks
        // a later bad description without exposing a public signature bypass.
        for index in 0..2 {
            for start in [0, 48, 144] {
                let mut changed = actual.clone();
                changed.joinsplits.push(changed.joinsplits[0].clone());
                let mut encoded = Vec::new();
                changed.joinsplits[index].write(&mut encoded).unwrap();
                encoded[304 + start] ^= 0x20; // opposite sign of the same valid point.
                changed.joinsplits[index] = JsDescription::read(encoded.as_slice(), true).unwrap();
                assert_eq!(verify_actual_groth_proofs(&changed), Err(LegacyJoinSplitError::SproutGrothProof { index, error: GrothError::InvalidProof }));
            }
        }
        for field in 0..11 {
            let mut changed = actual.clone();
            let mut encoded = Vec::new();
            changed.joinsplits[0].write(&mut encoded).unwrap();
            match field {
                0 => encoded[16] ^= 1,
                1 => encoded[48] ^= 1,
                2 => encoded[80] ^= 1,
                3 => encoded[240] ^= 1,
                4 => encoded[272] ^= 1,
                5 => encoded[112] ^= 1,
                6 => encoded[144] ^= 1,
                7 => encoded[208] ^= 1,
                8 => changed.joinsplit_pubkey[0] ^= 1,
                9 => encoded[0] ^= 1,
                10 => { encoded[..8].fill(0); encoded[8..16].copy_from_slice(&1_000_000_000_u64.to_le_bytes()); }
                _ => unreachable!(),
            }
            changed.joinsplits[0] = JsDescription::read(encoded.as_slice(), true).unwrap();
            assert_eq!(verify_actual_groth_proofs(&changed), Err(LegacyJoinSplitError::SproutGrothProof { index: 0, error: GrothError::InvalidProof }), "field{field}");
        }
        let mut changed = actual.clone();
        let mut encoded = Vec::new();
        changed.joinsplits[0].write(&mut encoded).unwrap();
        encoded[304..352].fill(0);
        changed.joinsplits[0] = JsDescription::read(encoded.as_slice(), true).unwrap();
        assert_eq!(verify_actual_groth_proofs(&changed), Err(LegacyJoinSplitError::SproutGrothProof { index: 0, error: GrothError::InvalidProofEncoding }));
    }
}
