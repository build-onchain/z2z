//! Exact V4 Sapling transaction cryptography, not ledger admission.
//!
//! Public inputs follow librustzcash f5e5cb24e1bd756a02fc4a3fd2b824238ccd15ad
//! `src/rustzcash.rs` and sapling-crypto 0.7.0 `src/verifier.rs`. RedJubjub
//! follows sapling-crypto 21084bde2019c04bd34208e63c3560fe2c02fb0e
//! `src/redjubjub.rs`: original raw R, canonical S, and the cofactored equation.
//! ZIP216 changes R decoding at NU5, not the spend-key small-order rule.
//!
//! The embedded network VK prefixes were extracted only after full original
//! parameter SHA256/BLAKE2b512 and size authentication. No caller supplies a
//! key, message, authorization flag or proof-validity result.

/*
Copyrights in the "sapling-crypto" library are retained by their contributors.
Historical/current Sapling verification relations adapted under the MIT option:

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

use std::{fmt, sync::LazyLock};

use bellman::groth16::{PreparedVerifyingKey, Proof, VerifyingKey, prepare_verifying_key, verify_proof};
use bls12_381::{Bls12, Scalar};
use group::GroupEncoding;
use sapling_crypto::constants::{
    SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR, VALUE_COMMITMENT_VALUE_GENERATOR,
};
use sha2::{Digest, Sha256};
use zcash_protocol::{consensus::BranchId, value::ZatBalance};

use crate::sapling_sighash::SaplingSignatureHash;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaplingCryptoError {
    InvalidVerifyingKey,
    InvalidValueBalance,
    InvalidSpendValueCommitment { index: usize },
    InvalidSpendKey { index: usize },
    InvalidSpendProofEncoding { index: usize },
    InvalidSpendProof { index: usize },
    InvalidSpendAuthSignature { index: usize },
    InvalidOutputValueCommitment { index: usize },
    InvalidEphemeralKey { index: usize },
    InvalidOutputCommitment { index: usize },
    InvalidOutputProofEncoding { index: usize },
    InvalidOutputProof { index: usize },
    InvalidBindingSignature,
}

impl fmt::Display for SaplingCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVerifyingKey => formatter.write_str("invalid fixed Sapling verifying key"),
            Self::InvalidValueBalance => formatter.write_str("Sapling value balance is outside monetary bounds"),
            Self::InvalidSpendValueCommitment { index } => write!(formatter, "invalid Sapling spend {index} value commitment"),
            Self::InvalidSpendKey { index } => write!(formatter, "invalid Sapling spend {index} randomized key"),
            Self::InvalidSpendProofEncoding { index } => write!(formatter, "invalid Sapling spend {index} proof encoding"),
            Self::InvalidSpendProof { index } => write!(formatter, "Sapling spend {index} proof verification failed"),
            Self::InvalidSpendAuthSignature { index } => write!(formatter, "Sapling spend {index} authorization failed"),
            Self::InvalidOutputValueCommitment { index } => write!(formatter, "invalid Sapling output {index} value commitment"),
            Self::InvalidEphemeralKey { index } => write!(formatter, "invalid Sapling output {index} ephemeral key"),
            Self::InvalidOutputCommitment { index } => write!(formatter, "invalid Sapling output {index} note commitment"),
            Self::InvalidOutputProofEncoding { index } => write!(formatter, "invalid Sapling output {index} proof encoding"),
            Self::InvalidOutputProof { index } => write!(formatter, "Sapling output {index} proof verification failed"),
            Self::InvalidBindingSignature => formatter.write_str("Sapling binding signature verification failed"),
        }
    }
}

impl std::error::Error for SaplingCryptoError {}

/// Verifies every actual Sapling proof, SpendAuth and binding signature in the
/// immutable transaction borrowed by the guarded ZIP243 cache. The fixed ALL
/// digest and binding commitments are derived internally. Valid typed V4 shape
/// without Sapling succeeds; this says nothing about original-byte canonicality,
/// UTXOs, anchors, spentness, value conservation in history or ledger admission.
pub fn verify_sapling_v4_crypto(hashes: &SaplingSignatureHash<'_>) -> Result<(), SaplingCryptoError> {
    let transaction = hashes.transaction();
    let Some(bundle) = transaction.sapling_bundle() else { return Ok(()); };
    verify_sapling_bundle_crypto(bundle, transaction.consensus_branch_id(), hashes.shielded())
}

pub(crate) fn verify_sapling_bundle_crypto(
    bundle: &sapling_crypto::bundle::Bundle<sapling_crypto::bundle::Authorized, ZatBalance>,
    branch: BranchId,
    sighash: [u8; 32],
) -> Result<(), SaplingCryptoError> {
    let value_balance = i64::from(bundle.value_balance());
    let keys = fixed_keys()?;
    let mut cv_sum = jubjub::ExtendedPoint::identity();

    for (index, spend) in bundle.shielded_spends().iter().enumerate() {
        let cv = spend.cv().as_inner();
        if bool::from(cv.is_small_order()) {
            return Err(SaplingCryptoError::InvalidSpendValueCommitment { index });
        }
        let raw_key = <[u8; 32]>::from(*spend.rk());
        let rk = non_small_order_point(raw_key).ok_or(SaplingCryptoError::InvalidSpendKey { index })?;
        let cv_affine = jubjub::AffinePoint::from(*cv);
        let [nf_low, nf_high] = pack_nullifier(&spend.nullifier().0);
        let inputs = [
            rk.get_u(), rk.get_v(), cv_affine.get_u(), cv_affine.get_v(),
            *spend.anchor(), nf_low, nf_high,
        ];
        let proof = read_proof(spend.zkproof()).ok_or(SaplingCryptoError::InvalidSpendProofEncoding { index })?;
        verify_proof(&keys.spend, &proof, &inputs).map_err(|_| SaplingCryptoError::InvalidSpendProof { index })?;
        let signature = <[u8; 64]>::from(*spend.spend_auth_sig());
        if !verify_redjubjub(branch, &jubjub::ExtendedPoint::from(rk), &raw_key, &signature, &sighash, SPENDING_KEY_GENERATOR) {
            return Err(SaplingCryptoError::InvalidSpendAuthSignature { index });
        }
        cv_sum += cv;
    }

    for (index, output) in bundle.shielded_outputs().iter().enumerate() {
        let cv = output.cv().as_inner();
        if bool::from(cv.is_small_order()) {
            return Err(SaplingCryptoError::InvalidOutputValueCommitment { index });
        }
        // The old decoder's only extra encodings are small-order points, which
        // are prohibited here in every branch; canonical decode is equivalent.
        let epk = non_small_order_point(output.ephemeral_key().0)
            .ok_or(SaplingCryptoError::InvalidEphemeralKey { index })?;
        let cv_affine = jubjub::AffinePoint::from(*cv);
        let cmu = Option::<Scalar>::from(Scalar::from_bytes(&output.cmu().to_bytes()))
            .ok_or(SaplingCryptoError::InvalidOutputCommitment { index })?;
        let inputs = [cv_affine.get_u(), cv_affine.get_v(), epk.get_u(), epk.get_v(), cmu];
        let proof = read_proof(output.zkproof()).ok_or(SaplingCryptoError::InvalidOutputProofEncoding { index })?;
        verify_proof(&keys.output, &proof, &inputs).map_err(|_| SaplingCryptoError::InvalidOutputProof { index })?;
        cv_sum -= cv;
    }

    let bvk = binding_key(cv_sum, value_balance)?;
    let raw_key = bvk.to_bytes();
    let signature = <[u8; 64]>::from(bundle.authorization().binding_sig);
    // Identity/torsion binding keys and R are allowed. Only spend rk gets the
    // separate not-small-order check, never an invented strict-key predicate.
    if !verify_redjubjub(branch, &bvk, &raw_key, &signature, &sighash, VALUE_COMMITMENT_RANDOMNESS_GENERATOR) {
        return Err(SaplingCryptoError::InvalidBindingSignature);
    }
    Ok(())
}

fn non_small_order_point(raw: [u8; 32]) -> Option<jubjub::AffinePoint> {
    let point = Option::<jubjub::AffinePoint>::from(jubjub::AffinePoint::from_bytes(raw))?;
    (!bool::from(point.is_small_order())).then_some(point)
}

fn pack_nullifier(nullifier: &[u8; 32]) -> [Scalar; 2] {
    let mut limbs = [0; 4];
    for (limb, bytes) in limbs.iter_mut().zip(nullifier.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*bytes);
    }
    let high = limbs[3] >> 62;
    limbs[3] &= (1_u64 << 62) - 1;
    // The low254-bit integer is below the BLS scalar modulus, so from_raw
    // is exact. No bit-vector allocation or repeated scalar doubling is needed.
    [Scalar::from_raw(limbs), Scalar::from(high)]
}

fn binding_key(cv_sum: jubjub::ExtendedPoint, value_balance: i64) -> Result<jubjub::ExtendedPoint, SaplingCryptoError> {
    ZatBalance::from_i64(value_balance).map_err(|_| SaplingCryptoError::InvalidValueBalance)?;
    let magnitude = jubjub::Scalar::from(value_balance.unsigned_abs());
    let signed = if value_balance < 0 { -magnitude } else { magnitude };
    Ok(cv_sum - jubjub::ExtendedPoint::from(VALUE_COMMITMENT_VALUE_GENERATOR * signed))
}

fn verify_redjubjub(
    branch: BranchId,
    key: &jubjub::ExtendedPoint,
    raw_key: &[u8; 32],
    signature: &[u8; 64],
    sighash: &[u8; 32],
    base: jubjub::SubgroupPoint,
) -> bool {
    let (raw_r, raw_s) = signature.split_first_chunk::<32>().expect("fixed64-byte signature");
    let decoded_r = if matches!(branch, BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy) {
        jubjub::AffinePoint::from_bytes_pre_zip216_compatibility(*raw_r)
    } else {
        jubjub::AffinePoint::from_bytes(*raw_r)
    };
    let Some(r) = Option::<jubjub::AffinePoint>::from(decoded_r) else { return false; };
    let raw_s = raw_s.first_chunk::<32>().expect("fixed32-byte scalar");
    let Some(s) = Option::<jubjub::Scalar>::from(jubjub::Scalar::from_bytes(raw_s)) else { return false; };
    let hash = blake2b_simd::Params::new().hash_length(64).personal(b"Zcash_RedJubjubH")
        .to_state().update(raw_r).update(raw_key).update(sighash).finalize();
    let challenge = jubjub::Scalar::from_bytes_wide(hash.as_array());
    bool::from((jubjub::ExtendedPoint::from(r) + key * challenge - jubjub::ExtendedPoint::from(base * s)).is_small_order())
}

// Authentic standalone VK prefixes of the fully authenticated historical
// sapling-spend.params (47958396B) and sapling-output.params (3592860B).
const SPEND_VK_BYTES: &[u8; 1636] = include_bytes!("../tests/fixtures/sapling-spend-vk.bin");
const OUTPUT_VK_BYTES: &[u8; 1444] = include_bytes!("../tests/fixtures/sapling-output-vk.bin");
const SPEND_VK_SHA256: [u8; 32] = [
    0xe0, 0xe8, 0x47, 0xa3, 0x93, 0x7c, 0xe7, 0x89, 0x89, 0xe3, 0x41, 0x6e, 0x90, 0x84, 0x39, 0xa1,
    0xd8, 0x53, 0x28, 0x78, 0x63, 0x64, 0x50, 0x95, 0xd5, 0xe2, 0xbb, 0xad, 0xee, 0xec, 0x98, 0x69,
];
const OUTPUT_VK_SHA256: [u8; 32] = [
    0xd7, 0xa6, 0x55, 0xf6, 0xf5, 0x87, 0x45, 0xf1, 0x7b, 0xf5, 0x34, 0x46, 0x82, 0xd2, 0x5d, 0x15,
    0x96, 0x7e, 0x39, 0xb5, 0x75, 0xd0, 0x72, 0x33, 0x5e, 0x14, 0xac, 0xe0, 0xa8, 0x71, 0xbd, 0x0c,
];

#[derive(Clone, Copy)]
enum KeyKind { Spend, Output }

struct FixedKeys {
    spend: PreparedVerifyingKey<Bls12>,
    output: PreparedVerifyingKey<Bls12>,
}

static FIXED_KEYS: LazyLock<Result<FixedKeys, SaplingCryptoError>> = LazyLock::new(|| Ok(FixedKeys {
    spend: prepare_verifying_key(&read_fixed_key(SPEND_VK_BYTES, KeyKind::Spend)?),
    output: prepare_verifying_key(&read_fixed_key(OUTPUT_VK_BYTES, KeyKind::Output)?),
}));

fn fixed_keys() -> Result<&'static FixedKeys, SaplingCryptoError> {
    FIXED_KEYS.as_ref().map_err(|error| *error)
}

fn read_fixed_key(bytes: &[u8], kind: KeyKind) -> Result<VerifyingKey<Bls12>, SaplingCryptoError> {
    let (expected_len, expected_ic, expected_hash) = match kind {
        KeyKind::Spend => (1636, 8_u32, SPEND_VK_SHA256),
        KeyKind::Output => (1444, 6_u32, OUTPUT_VK_SHA256),
    };
    // Exact length and embedded digest authenticate BEFORE Bellman's count-
    // controlled Vec reader. An untrusted IC count cannot drive allocation.
    if bytes.len() != expected_len || <[u8; 32]>::from(Sha256::digest(bytes)) != expected_hash {
        return Err(SaplingCryptoError::InvalidVerifyingKey);
    }
    if bytes[864..868] != expected_ic.to_be_bytes() {
        return Err(SaplingCryptoError::InvalidVerifyingKey);
    }
    let mut remaining = bytes;
    let key = VerifyingKey::<Bls12>::read(&mut remaining).map_err(|_| SaplingCryptoError::InvalidVerifyingKey)?;
    if !remaining.is_empty() || key.ic.len() != expected_ic as usize {
        return Err(SaplingCryptoError::InvalidVerifyingKey);
    }
    Ok(key)
}

fn read_proof(bytes: &[u8]) -> Option<Proof<Bls12>> {
    if bytes.len() != 192 { return None; }
    let mut remaining = bytes;
    // Bellman's checked decoders require canonical coordinates, curve and
    // prime-subgroup membership, and reject encoded A/B/C infinity.
    let proof = Proof::<Bls12>::read(&mut remaining).ok()?;
    remaining.is_empty().then_some(proof)
}



#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::{G1Affine, G2Affine};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use redjubjub::{Binding, Signature, SigningKey, SpendAuth, VerificationKey};
    use zcash_protocol::value::MAX_BALANCE;

    fn identity_signature(noncanonical: bool) -> [u8; 64] {
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&jubjub::AffinePoint::identity().to_bytes());
        if noncanonical { signature[31] |= 0x80; }
        signature
    }

    fn signed<T: redjubjub::SigType>(message: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
        // Deterministic public regression scalars only, never wallet material.
        let key = SigningKey::<T>::try_from(jubjub::Scalar::from(7).to_bytes()).unwrap();
        let verification = VerificationKey::from(&key);
        let signature = key.sign(ChaCha20Rng::from_seed([0x5a; 32]), message);
        assert_eq!(verification.verify(message, &signature), Ok(()));
        (verification.into(), signature.into())
    }

    #[test]
    fn noncanonical_identity_r_is_historically_valid_for_identity_binding_key_only_before_nu5() {
        let key = jubjub::ExtendedPoint::identity();
        let raw_key = jubjub::AffinePoint::identity().to_bytes();
        let signature = identity_signature(true);
        for branch in [BranchId::Sapling, BranchId::Blossom, BranchId::Heartwood, BranchId::Canopy] {
            assert!(verify_redjubjub(branch, &key, &raw_key, &signature, &[0x31; 32], VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        }
        for branch in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1, BranchId::Nu6_2, BranchId::Nu6_3] {
            assert!(!verify_redjubjub(branch, &key, &raw_key, &signature, &[0x31; 32], VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
            assert!(verify_redjubjub(branch, &key, &raw_key, &identity_signature(false), &[0x31; 32], VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        }
        // The signature relation has no blanket small-order key prohibition;
        // the spend-description role imposes that separately.
        assert!(non_small_order_point(raw_key).is_none());
    }

    #[test]
    fn order_two_r_and_binding_key_use_the_cofactored_not_uncofactored_equation() {
        let order_two = jubjub::AffinePoint::from_raw_unchecked(bls12_381::Scalar::zero(), -bls12_381::Scalar::one());
        let key = jubjub::ExtendedPoint::from(order_two);
        let raw_key = order_two.to_bytes();
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&raw_key);
        assert!(verify_redjubjub(BranchId::Sapling, &key, &raw_key, &signature, &[0; 32], VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        assert!(verify_redjubjub(BranchId::Nu5, &key, &raw_key, &signature, &[0; 32], VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        let mut saw_uncofactored_difference = false;
        for byte in 0..16 {
            let message = [byte; 32];
            let hash = blake2b_simd::Params::new().hash_length(64).personal(b"Zcash_RedJubjubH")
                .to_state().update(&signature[..32]).update(&raw_key).update(&message).finalize();
            let challenge = jubjub::Scalar::from_bytes_wide(hash.as_array());
            let uncofactored = key + key * challenge; // S=0, R=A=order two.
            saw_uncofactored_difference |= uncofactored != jubjub::ExtendedPoint::identity();
            assert!(verify_redjubjub(BranchId::Sapling, &key, &raw_key, &signature, &message, VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        }
        assert!(saw_uncofactored_difference, "vector must distinguish an uncofactored verifier");
        signature[31] |= 0x80;
        assert!(verify_redjubjub(BranchId::Canopy, &key, &raw_key, &signature, &[0; 32], VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        assert!(!verify_redjubjub(BranchId::Nu5, &key, &raw_key, &signature, &[0; 32], VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        assert!(non_small_order_point(raw_key).is_none());
    }

    #[test]
    fn current_standard_spend_and_binding_signatures_match_the_independent_installed_oracle() {
        let message = [0x6d; 32];
        let (raw_key, signature) = signed::<SpendAuth>(&message);
        let key = jubjub::ExtendedPoint::from(jubjub::AffinePoint::from_bytes(raw_key).unwrap());
        for branch in [BranchId::Sapling, BranchId::Nu5, BranchId::Nu6_3] {
            assert!(verify_redjubjub(branch, &key, &raw_key, &signature, &message, SPENDING_KEY_GENERATOR));
            assert!(!verify_redjubjub(branch, &key, &raw_key, &signature, &[0x6c; 32], SPENDING_KEY_GENERATOR));
            assert!(!verify_redjubjub(branch, &key, &raw_key, &signature, &message, VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        }
        let (raw_key, signature) = signed::<Binding>(&message);
        let key = jubjub::ExtendedPoint::from(jubjub::AffinePoint::from_bytes(raw_key).unwrap());
        assert!(verify_redjubjub(BranchId::Nu5, &key, &raw_key, &signature, &message, VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        assert!(!verify_redjubjub(BranchId::Nu5, &key, &raw_key, &signature, &message, SPENDING_KEY_GENERATOR));
        let mut altered_key = raw_key;
        altered_key[0] ^= 1;
        assert!(!verify_redjubjub(BranchId::Sapling, &key, &altered_key, &signature, &message, VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
        let raw_identity = jubjub::AffinePoint::identity().to_bytes();
        let identity = jubjub::ExtendedPoint::identity();
        let mut malformed = identity_signature(false);
        malformed[..32].fill(0xff);
        assert!(!verify_redjubjub(BranchId::Sapling, &identity, &raw_identity, &malformed, &message, VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
    }

    #[test]
    fn canonical_s_is_not_reduced_modulo_the_jubjub_scalar_order() {
        let message = [0x61; 32];
        let (raw_key, original) = signed::<Binding>(&message);
        let key = jubjub::ExtendedPoint::from(jubjub::AffinePoint::from_bytes(raw_key).unwrap());
        let modulus = [
            0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0,
            0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
            0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06,
            0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e,
        ];
        let mut below = modulus;
        below[0] -= 1;
        assert!(bool::from(jubjub::Scalar::from_bytes(&below).is_some()));
        for scalar in [modulus, [0xff; 32]] {
            let mut signature = identity_signature(false);
            signature[32..].copy_from_slice(&scalar);
            assert!(!verify_redjubjub(
                BranchId::Sapling, &jubjub::ExtendedPoint::identity(), &jubjub::AffinePoint::identity().to_bytes(),
                &signature, &message, VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            ));
        }
        let mut changed = original;
        let mut carry = 0_u16;
        for index in 0..32 {
            let sum = u16::from(changed[32 + index]) + u16::from(modulus[index]) + carry;
            changed[32 + index] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        // Same mathematical scalar, invalid original serialization.
        assert!(!verify_redjubjub(BranchId::Canopy, &key, &raw_key, &changed, &message, VALUE_COMMITMENT_RANDOMNESS_GENERATOR));
    }

    #[test]
    fn old_noncanonical_r_keeps_its_original_bytes_in_the_challenge() {
        // R is the identity with the legacy sign-bit encoding. A=B and
        // S=H(R_raw||A_raw||M), so the pre-NU5 equation holds only if raw R
        // is retained. Deterministic generated compatibility data, not chain data.
        let raw_key = SPENDING_KEY_GENERATOR.to_bytes();
        let key = jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR);
        let message = [0x49; 32];
        let mut signature = identity_signature(true);
        let hash = blake2b_simd::Params::new().hash_length(64).personal(b"Zcash_RedJubjubH")
            .to_state().update(&signature[..32]).update(&raw_key).update(&message).finalize();
        signature[32..].copy_from_slice(&jubjub::Scalar::from_bytes_wide(hash.as_array()).to_bytes());
        assert!(verify_redjubjub(BranchId::Sapling, &key, &raw_key, &signature, &message, SPENDING_KEY_GENERATOR));
        assert!(!verify_redjubjub(BranchId::Nu5, &key, &raw_key, &signature, &message, SPENDING_KEY_GENERATOR));
        signature[31] &= 0x7f;
        assert!(!verify_redjubjub(BranchId::Sapling, &key, &raw_key, &signature, &message, SPENDING_KEY_GENERATOR));
    }

    #[test]
    fn nullifier_packing_is_little_endian_and_splits_at_exactly_254_bits() {
        let mut nullifier = [0; 32];
        for (bit, expected) in [
            (0, [bls12_381::Scalar::one(), bls12_381::Scalar::zero()]),
            (7, [bls12_381::Scalar::from(128), bls12_381::Scalar::zero()]),
            (8, [bls12_381::Scalar::from(256), bls12_381::Scalar::zero()]),
            (253, [bls12_381::Scalar::from_raw([0, 0, 0, 1 << 61]), bls12_381::Scalar::zero()]),
            (254, [bls12_381::Scalar::zero(), bls12_381::Scalar::one()]),
            (255, [bls12_381::Scalar::zero(), bls12_381::Scalar::from(2)]),
        ] {
            nullifier.fill(0);
            nullifier[bit / 8] = 1 << (bit % 8);
            assert_eq!(pack_nullifier(&nullifier), expected);
        }
        assert_eq!(pack_nullifier(&[0xff; 32]), [
            bls12_381::Scalar::from_raw([u64::MAX, u64::MAX, u64::MAX, (1_u64 << 62) - 1]),
            bls12_381::Scalar::from(3),
        ]);
    }

    #[test]
    fn binding_key_uses_signed_value_balance_without_overflow_or_small_order_ban() {
        let value = jubjub::ExtendedPoint::from(VALUE_COMMITMENT_VALUE_GENERATOR);
        assert_eq!(binding_key(value * jubjub::Scalar::from(7), 7), Ok(jubjub::ExtendedPoint::identity()));
        assert_eq!(binding_key(jubjub::ExtendedPoint::identity(), -7), Ok(value * jubjub::Scalar::from(7)));
        assert_eq!(binding_key(jubjub::ExtendedPoint::identity(), 7), Ok(-(value * jubjub::Scalar::from(7))));
        for balance in [-MAX_BALANCE, 0, MAX_BALANCE] {
            assert!(binding_key(jubjub::ExtendedPoint::identity(), balance).is_ok());
        }
        for balance in [i64::MIN, -MAX_BALANCE - 1, MAX_BALANCE + 1, i64::MAX] {
            assert_eq!(binding_key(jubjub::ExtendedPoint::identity(), balance), Err(SaplingCryptoError::InvalidValueBalance));
        }
    }

    #[test]
    fn authentic_fixed_keys_reject_substitutions_suffixes_and_unbounded_ic_counts() {
        for (bytes, kind, count) in [(SPEND_VK_BYTES.as_slice(), KeyKind::Spend, 8_u32), (OUTPUT_VK_BYTES.as_slice(), KeyKind::Output, 6)] {
            assert!(read_fixed_key(bytes, kind).is_ok());
            for length in [0, 867, bytes.len() - 1] {
                assert!(matches!(read_fixed_key(&bytes[..length], kind), Err(SaplingCryptoError::InvalidVerifyingKey)));
            }
            let mut changed = bytes.to_vec();
            changed.push(0);
            assert!(matches!(read_fixed_key(&changed, kind), Err(SaplingCryptoError::InvalidVerifyingKey)));
            for ic in [0_u32, count - 1, count + 1, u32::MAX] {
                let mut changed = bytes.to_vec();
                changed[864..868].copy_from_slice(&ic.to_be_bytes());
                assert!(matches!(read_fixed_key(&changed, kind), Err(SaplingCryptoError::InvalidVerifyingKey)));
            }
            // Still valid curve data, but no authority to replace the network key.
            let mut changed = bytes.to_vec();
            changed[..96].copy_from_slice(&G1Affine::generator().to_uncompressed());
            assert!(matches!(read_fixed_key(&changed, kind), Err(SaplingCryptoError::InvalidVerifyingKey)));
            let mut changed = bytes.to_vec();
            changed[868] ^= 1;
            assert!(matches!(read_fixed_key(&changed, kind), Err(SaplingCryptoError::InvalidVerifyingKey)));
        }
        assert!(read_fixed_key(SPEND_VK_BYTES, KeyKind::Output).is_err());
        assert!(read_fixed_key(OUTPUT_VK_BYTES, KeyKind::Spend).is_err());
        assert!(std::ptr::eq(fixed_keys().unwrap(), fixed_keys().unwrap()));
    }

    #[test]
    fn exact_proof_boundary_rejects_truncations_suffixes_and_finite_non_subgroup_points() {
        let mut proof = [0; 192];
        proof[..48].copy_from_slice(&G1Affine::generator().to_compressed());
        proof[48..144].copy_from_slice(&G2Affine::generator().to_compressed());
        proof[144..].copy_from_slice(&G1Affine::generator().to_compressed());
        assert!(read_proof(&proof).is_some());
        for length in [0, 47, 48, 143, 144, 191] { assert!(read_proof(&proof[..length]).is_none()); }
        let mut extended = proof.to_vec();
        extended.push(0);
        assert!(read_proof(&extended).is_none());
        // x=0,y=2 is on G1 but has order3, not the BLS prime order.
        let mut non_subgroup = [0; 48];
        non_subgroup[0] = 0x80;
        let decoded = G1Affine::from_compressed_unchecked(&non_subgroup).unwrap();
        assert!(bool::from(decoded.is_on_curve()));
        assert!(!bool::from(decoded.is_identity()));
        assert!(!bool::from(decoded.is_torsion_free()));
        for (start, end) in [(0, 48), (144, 192)] {
            let mut changed = proof;
            changed[start..end].copy_from_slice(&non_subgroup);
            assert!(read_proof(&changed).is_none());
        }
        let non_subgroup_g2 = (0..64).find_map(|coordinate| {
            let mut encoded = [0; 96];
            encoded[0] = 0x80;
            encoded[95] = coordinate;
            let point = Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&encoded))?;
            (!bool::from(point.is_identity()) && !bool::from(point.is_torsion_free())).then_some(encoded)
        }).unwrap();
        proof[48..144].copy_from_slice(&non_subgroup_g2);
        assert!(read_proof(&proof).is_none());
    }

    #[test]
    fn standard_oracle_rejects_legacy_noncanonical_r_while_historical_predicate_accepts_it() {
        let verification = VerificationKey::<Binding>::try_from(jubjub::AffinePoint::identity().to_bytes()).unwrap();
        let signature = Signature::<Binding>::from(identity_signature(true));
        assert!(verification.verify(&[0; 32], &signature).is_err());
    }
}
