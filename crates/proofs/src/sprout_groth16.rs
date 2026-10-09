//! Fixed-key Sprout Groth16 proof verification using the original public inputs.
//!
//! This follows `zcash_proofs/src/sprout.rs::verify_proof` at librustzcash
//! commit 97aefdc39a037da9c4f19a0e8a450d2c7932f53e, with allocation-free
//! public-input packing and bellman 0.14.0 / bls12_381 0.8.0 verification.
//! It does not establish transaction signatures, anchor/nullifier history,
//! accepted ledger state, financial settlement, or repair the legacy PHGR setup.
//!
//! Primary sources:
//! - https://raw.githubusercontent.com/zcash/librustzcash/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_proofs/src/sprout.rs
//! - https://raw.githubusercontent.com/zcash/zcash/86451a18b016af09a4e33c9acc1aa5577e25af17/src/rust/src/sprout-groth16.vk
//! - https://raw.githubusercontent.com/ZcashFoundation/zebra/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-consensus/src/primitives/groth16/sprout-groth16.vk
//!
//! The two key sources contain the same 1828 bytes, Git blob
//! 60f6ee96e0560e3d1e8a025a0e9a51334c9956af, authenticated below by SHA256.

/*
The MIT License (MIT)

Copyright (c) 2017-2021 The Electric Coin Company

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
*/

use std::{fmt, sync::LazyLock};

use bellman::{
    VerificationError,
    groth16::{self, PreparedVerifyingKey, Proof, VerifyingKey},
};
use bls12_381::{Bls12, Scalar};
use sha2::{Digest, Sha256};
use zcash_protocol::value::MAX_MONEY;

use crate::sprout::{LegacyJoinSplit, h_sig};

const VERIFYING_KEY_BYTES: &[u8; 1828] = include_bytes!("../tests/fixtures/sprout-groth16-vk.bin");
// Actual SHA256 of the byte-identical pinned zcashd and Zebra public keys.
const VERIFYING_KEY_SHA256: [u8; 32] = [
    0x4f, 0x88, 0x94, 0xd5, 0x45, 0x65, 0x96, 0xe9, 0x12, 0xd8, 0xa5, 0x5c, 0x13, 0x8c, 0x15, 0x5f,
    0x33, 0x81, 0x31, 0xea, 0x4e, 0xc7, 0x47, 0x84, 0x7b, 0x5d, 0xd6, 0xdb, 0xa5, 0xef, 0xab, 0xdc,
];
// Six uncompressed fixed points occupy 864 bytes, followed by the BE u32 IC count.
const IC_COUNT_OFFSET: usize = 864;
const INPUT_BITS: usize = 254;
static VERIFYING_KEY: LazyLock<Result<PreparedVerifyingKey<Bls12>, GrothError>> =
    LazyLock::new(|| authenticate_key(VERIFYING_KEY_BYTES).map(|key| groth16::prepare_verifying_key(&key)));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrothError {
    InvalidStatement,
    InvalidProofEncoding,
    InvalidVerifyingKey,
    InvalidProof,
}

impl fmt::Display for GrothError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStatement => "invalid Sprout Groth16 JoinSplit public amounts",
            Self::InvalidProofEncoding => "invalid Sprout Groth16 proof encoding",
            Self::InvalidVerifyingKey => "invalid authenticated original Sprout Groth16 verifying key",
            Self::InvalidProof => "Sprout Groth16 acceptance equation failed",
        })
    }
}

impl std::error::Error for GrothError {}

/// Checks the authentic fixed-key Sprout Groth16 relation. The proof must be
/// exactly 192 bytes with canonical, on-curve, finite subgroup points.
/// No caller-supplied key, validity flag, proving key, or prover is used.
pub fn verify_sprout_groth16(
    statement: &LegacyJoinSplit,
    proof: &[u8],
) -> Result<(), GrothError> {
    let inputs = public_inputs(statement)?;
    let proof = decode_proof(proof)?;
    let key = VERIFYING_KEY.as_ref().map_err(|error| *error)?;
    groth16::verify_proof(key, &proof, &inputs).map_err(|error| match error {
        VerificationError::InvalidVerifyingKey => GrothError::InvalidVerifyingKey,
        VerificationError::InvalidProof => GrothError::InvalidProof,
    })
}

fn decode_proof(bytes: &[u8]) -> Result<Proof<Bls12>, GrothError> {
    if bytes.len() != 192 {
        return Err(GrothError::InvalidProofEncoding);
    }
    let mut remaining = bytes;
    // bellman's checked GroupEncoding reader rejects noncanonical coordinates,
    // off-curve/non-subgroup points, and all three points at infinity.
    let proof = Proof::<Bls12>::read(&mut remaining)
        .map_err(|_| GrothError::InvalidProofEncoding)?;
    if !remaining.is_empty() {
        return Err(GrothError::InvalidProofEncoding);
    }
    Ok(proof)
}

fn authenticate_key(bytes: &[u8]) -> Result<VerifyingKey<Bls12>, GrothError> {
    if bytes.len() != VERIFYING_KEY_BYTES.len()
        || Sha256::digest(bytes).as_slice() != VERIFYING_KEY_SHA256
    {
        return Err(GrothError::InvalidVerifyingKey);
    }
    decode_key_format(bytes)
}

fn decode_key_format(bytes: &[u8]) -> Result<VerifyingKey<Bls12>, GrothError> {
    // Bound both the total bytes and the count before bellman's Vec-based reader.
    // Nine public scalars require exactly ten IC points, including the constant.
    if bytes.len() != VERIFYING_KEY_BYTES.len()
        || bytes[IC_COUNT_OFFSET..IC_COUNT_OFFSET + 4] != 10u32.to_be_bytes()
    {
        return Err(GrothError::InvalidVerifyingKey);
    }
    let mut remaining = bytes;
    let key = VerifyingKey::<Bls12>::read(&mut remaining)
        .map_err(|_| GrothError::InvalidVerifyingKey)?;
    // bellman checks every point's encoding, curve and subgroup, and finite IC;
    // explicitly reject infinity in its six other public parameter fields too.
    if !remaining.is_empty() || key.ic.len() != 10
        || bool::from(key.alpha_g1.is_identity())
        || bool::from(key.beta_g1.is_identity())
        || bool::from(key.beta_g2.is_identity())
        || bool::from(key.gamma_g2.is_identity())
        || bool::from(key.delta_g1.is_identity())
        || bool::from(key.delta_g2.is_identity())
    {
        return Err(GrothError::InvalidVerifyingKey);
    }
    Ok(key)
}

fn public_inputs(statement: &LegacyJoinSplit) -> Result<[Scalar; 9], GrothError> {
    if statement.vpub_old > MAX_MONEY || statement.vpub_new > MAX_MONEY
        || (statement.vpub_old != 0 && statement.vpub_new != 0)
    {
        return Err(GrothError::InvalidStatement);
    }
    let mut bytes = [0; 272];
    bytes[..32].copy_from_slice(&statement.anchor);
    bytes[32..64].copy_from_slice(&h_sig(statement));
    bytes[64..96].copy_from_slice(&statement.nullifiers[0]);
    bytes[96..128].copy_from_slice(&statement.macs[0]);
    bytes[128..160].copy_from_slice(&statement.nullifiers[1]);
    bytes[160..192].copy_from_slice(&statement.macs[1]);
    bytes[192..224].copy_from_slice(&statement.commitments[0]);
    bytes[224..256].copy_from_slice(&statement.commitments[1]);
    bytes[256..264].copy_from_slice(&statement.vpub_old.to_le_bytes());
    bytes[264..272].copy_from_slice(&statement.vpub_new.to_le_bytes());
    pack_public_input(&bytes)
}

fn pack_public_input(bytes: &[u8; 272]) -> Result<[Scalar; 9], GrothError> {
    let mut inputs = [Scalar::zero(); 9];
    for (chunk, input) in inputs.iter_mut().enumerate() {
        let start = chunk * INPUT_BITS;
        let mut scalar_bytes = [0; 32];
        // Bytes are MSB-first; the first bit of each chunk has weight 2^0.
        // Eight 254-bit chunks followed by 144 bits, all strictly below r.
        for coefficient in 0..INPUT_BITS.min(bytes.len() * 8 - start) {
            let bit = start + coefficient;
            if (bytes[bit / 8] >> (7 - bit % 8)) & 1 != 0 {
                scalar_bytes[coefficient / 8] |= 1 << (coefficient % 8);
            }
        }
        *input = Option::<Scalar>::from(Scalar::from_bytes(&scalar_bytes))
            .ok_or(GrothError::InvalidStatement)?;
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use bellman::gadgets::multipack;
    use bls12_381::{G1Affine, G2Affine};
    use ff::PrimeField;

    use super::*;

    #[test]
    fn authenticated_original_key_has_exact_inputs_and_roundtrips_original_bytes() {
        let key = authenticate_key(VERIFYING_KEY_BYTES).unwrap();
        assert_eq!(key.ic.len(), 10);
        let mut encoded = Vec::new();
        key.write(&mut encoded).unwrap();
        assert_eq!(encoded.as_slice(), VERIFYING_KEY_BYTES);
    }

    #[test]
    fn key_authentication_rejects_corruption_and_valid_point_substitution() {
        let mut corrupt = *VERIFYING_KEY_BYTES;
        corrupt[1] ^= 1;
        assert!(matches!(authenticate_key(&corrupt), Err(GrothError::InvalidVerifyingKey)));
        let mut changed = *VERIFYING_KEY_BYTES;
        assert_ne!(&changed[..96], &VERIFYING_KEY_BYTES[96..192]);
        changed[..96].copy_from_slice(&VERIFYING_KEY_BYTES[96..192]);
        // All encodings and subgroup checks remain valid: only authentication rejects it.
        let substituted = decode_key_format(&changed).unwrap();
        let original = authenticate_key(VERIFYING_KEY_BYTES).unwrap();
        assert_eq!(substituted.alpha_g1, original.beta_g1);
        assert!(matches!(authenticate_key(&changed), Err(GrothError::InvalidVerifyingKey)));
        assert!(matches!(authenticate_key(&VERIFYING_KEY_BYTES[..1827]), Err(GrothError::InvalidVerifyingKey)));
        let mut extended = VERIFYING_KEY_BYTES.to_vec();
        extended.push(0);
        assert!(matches!(authenticate_key(&extended), Err(GrothError::InvalidVerifyingKey)));
    }

    #[test]
    fn key_decoder_bounds_ic_before_reading_and_rejects_truncation_or_suffix() {
        for count in [0u32, 9, 11, u32::MAX] {
            let mut changed = *VERIFYING_KEY_BYTES;
            changed[IC_COUNT_OFFSET..IC_COUNT_OFFSET + 4].copy_from_slice(&count.to_be_bytes());
            assert!(matches!(decode_key_format(&changed), Err(GrothError::InvalidVerifyingKey)));
        }
        for length in [0, 863, 864, 867, 868, 1827] {
            assert!(matches!(decode_key_format(&VERIFYING_KEY_BYTES[..length]), Err(GrothError::InvalidVerifyingKey)));
        }
        let mut extended = VERIFYING_KEY_BYTES.to_vec();
        extended.push(0);
        assert!(matches!(decode_key_format(&extended), Err(GrothError::InvalidVerifyingKey)));
    }

    #[test]
    fn key_decoder_requires_finite_canonical_on_curve_subgroup_points() {
        for (start, end) in [(0, 96), (96, 192), (192, 384), (384, 576), (576, 672), (672, 864), (868, 964)] {
            for infinity in [false, true] {
                let mut changed = *VERIFYING_KEY_BYTES;
                changed[start..end].fill(0);
                if infinity { changed[start] = 0x40; }
                assert!(matches!(decode_key_format(&changed), Err(GrothError::InvalidVerifyingKey)));
            }
            let mut changed = *VERIFYING_KEY_BYTES;
            changed[start] |= 0x80; // Uncompressed key points cannot set compression.
            assert!(matches!(decode_key_format(&changed), Err(GrothError::InvalidVerifyingKey)));
            let mut changed = *VERIFYING_KEY_BYTES;
            changed[start..start + 48].fill(0xff); // x >= p, not a reduced residue.
            assert!(matches!(decode_key_format(&changed), Err(GrothError::InvalidVerifyingKey)));
        }
        let mut torsion = [0; 96];
        torsion[95] = 2; // Finite order-three (x=0,y=2) on G1.
        let point = Option::<G1Affine>::from(G1Affine::from_uncompressed_unchecked(&torsion)).unwrap();
        assert!(bool::from(point.is_on_curve()));
        assert!(!bool::from(point.is_torsion_free()));
        for start in [0, 96, 576, 868] {
            let mut changed = *VERIFYING_KEY_BYTES;
            changed[start..start + 96].copy_from_slice(&torsion);
            assert!(matches!(decode_key_format(&changed), Err(GrothError::InvalidVerifyingKey)));
        }
        let torsion = (0..64).find_map(|coordinate| {
            let mut encoded = [0; 96];
            encoded[0] = 0x80;
            encoded[95] = coordinate;
            let point = Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&encoded))?;
            assert!(bool::from(point.is_on_curve()));
            (!bool::from(point.is_identity()) && !bool::from(point.is_torsion_free()))
                .then_some(point.to_uncompressed())
        }).unwrap();
        for start in [192, 384, 672] {
            let mut changed = *VERIFYING_KEY_BYTES;
            changed[start..start + 192].copy_from_slice(&torsion);
            assert!(matches!(decode_key_format(&changed), Err(GrothError::InvalidVerifyingKey)));
        }
    }

    #[test]
    fn fixed_bitpacking_matches_maintained_multipack_at_all_chunk_boundaries() {
        assert_eq!(Scalar::CAPACITY as usize, INPUT_BITS);
        let mut patterned = [0; 272];
        for (index, byte) in patterned.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(73).wrapping_add(19);
        }
        for bytes in [[0; 272], [0xff; 272], patterned] {
            let maintained = multipack::compute_multipacking::<Scalar>(&multipack::bytes_to_bits(&bytes));
            assert_eq!(pack_public_input(&bytes).unwrap().as_slice(), maintained.as_slice());
        }
        // Literal weights distinguish byte-MSB order from little-endian byte bits.
        let mut bytes = [0; 272];
        bytes[0] = 0x80;
        bytes[31] = 0x07; // positions 253, 254 and 255 straddle the first chunk.
        bytes[271] = 0x01; // final coefficient 143, not 151 (legacy 253-bit packing).
        let mut expected = [Scalar::zero(); 9];
        expected[0] = Scalar::one() + Scalar::from_raw([0, 0, 0, 1u64 << 61]);
        expected[1] = Scalar::from(3u64);
        expected[8] = Scalar::from_raw([0, 0, 1u64 << 15, 0]);
        assert_eq!(pack_public_input(&bytes).unwrap(), expected);
        for boundary in 1..9 {
            for bit in [boundary * INPUT_BITS - 1, boundary * INPUT_BITS] {
                let mut bytes = [0; 272];
                bytes[bit / 8] = 1 << (7 - bit % 8);
                let maintained = multipack::compute_multipacking::<Scalar>(&multipack::bytes_to_bits(&bytes));
                assert_eq!(pack_public_input(&bytes).unwrap().as_slice(), maintained.as_slice());
            }
        }
    }
}
