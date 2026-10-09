//! Fixed-key historical Sprout BCTV14 (network name PHGR) verification.
//!
//! This translates the original MIT libsnark verifier and Zcash witness map at
//! zcashd commit 0512e9eb00f97172346e0fac854625d59771e4f7, using existing BN
//! field, curve, subgroup, and pairing primitives. All five acceptance equations
//! are checked independently. It neither repairs the disclosed legacy setup
//! flaw nor establishes complete source history, pool balances, or finality.
//!
//! Primary implementation sources at that immutable commit:
//! - `src/snark/libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.tcc`
//!   (`r1cs_ppzksnark_online_verifier_{weak,strong}_IC` and key serialization).
//! - `src/zcash/{Proof.cpp,JoinSplit.cpp,util.cpp}` and
//!   `src/zcash/circuit/gadget.tcc::joinsplit_gadget::witness_map`.
//! - `src/snark/libsnark/algebra/fields/{fp.tcc,field_utils.tcc}`,
//!   `algebra/curves/alt_bn128/alt_bn128_g{1,2}.cpp`, and
//!   `common/data_structures/{accumulation_vector,sparse_vector}.tcc`.

/*
The libsnark library is developed by SCIPR Lab (http://scipr-lab.org)
and contributors.

Copyright (c) 2012-2019 SCIPR Lab and contributors (see AUTHORS file).
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
*/

use std::{fmt, sync::LazyLock};

use sha2::{Digest, Sha256};
use sprout_bn::{AffineG1, AffineG2, Fq, Fq2, Fr, G1, G2, Gt, Group, arith::U256};
use zcash_protocol::value::MAX_MONEY;

// Original public parameters, not Parity JSON or a caller-supplied key.
// URL: https://download.z.cash/downloads/sprout-verifying.key
// SHA256 pin: zcashd's zcutil/fetch-params.sh at the source commit above.
const VERIFYING_KEY_BYTES: &[u8; 1449] = include_bytes!("../tests/fixtures/sprout-vk.bin");
const VERIFYING_KEY_SHA256: [u8; 32] = [
    0x4b, 0xd4, 0x98, 0xda, 0xe0, 0xaa, 0xcf, 0xd8, 0xe9, 0x8d, 0xc3, 0x06, 0x33, 0x8d, 0x01, 0x7d,
    0x9c, 0x08, 0xdd, 0x09, 0x18, 0xea, 0xd1, 0x81, 0x72, 0xbd, 0x0a, 0xec, 0x2f, 0xc5, 0xdf, 0x82,
];
const IC_METADATA: &[u8; 24] = b"9\n9\n0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n";
static VERIFYING_KEY: LazyLock<Result<VerifyingKey, LegacyError>> =
    LazyLock::new(|| authenticate_key(VERIFYING_KEY_BYTES));

/// Complete public statement in raw consensus byte order, not display hash order.
/// Ciphertexts, transaction signatures, historical anchors and nullifier state
/// remain the enclosing transaction/history validator's responsibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyJoinSplit {
    pub anchor: [u8; 32],
    pub nullifiers: [[u8; 32]; 2],
    pub macs: [[u8; 32]; 2],
    pub commitments: [[u8; 32]; 2],
    pub vpub_old: u64,
    pub vpub_new: u64,
    pub random_seed: [u8; 32],
    pub joinsplit_pubkey: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyError {
    InvalidStatement,
    InvalidProofEncoding,
    InvalidVerifyingKey,
    InvalidProof,
}

impl fmt::Display for LegacyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStatement => "invalid legacy JoinSplit public amounts",
            Self::InvalidProofEncoding => "invalid legacy Sprout proof encoding",
            Self::InvalidVerifyingKey => "invalid authenticated original Sprout verifying key",
            Self::InvalidProof => "legacy Sprout acceptance equation failed",
        })
    }
}

impl std::error::Error for LegacyError {}

/// Checks the authentic fixed-key historical acceptance relation, never an
/// arbitrary key, a host-supplied validity flag, or a financial settlement fact.
pub fn verify_sprout_legacy(
    statement: &LegacyJoinSplit,
    proof: &[u8],
) -> Result<(), LegacyError> {
    let inputs = public_inputs(statement)?;
    let proof = decode_proof(proof)?;
    let key = VERIFYING_KEY
        .as_ref()
        .map_err(|error| *error)?;
    verify_equations(key, &inputs, &proof)
}

struct VerifyingKey {
    alpha_a: G2,
    alpha_b: G1,
    alpha_c: G2,
    gamma: G2,
    gamma_beta_1: G1,
    gamma_beta_2: G2,
    zeta: G2,
    ic: [G1; 10],
}

struct Proof {
    a: G1,
    a_prime: G1,
    b: G2,
    b_prime: G1,
    c: G1,
    c_prime: G1,
    k: G1,
    h: G1,
}

fn decode_proof(bytes: &[u8]) -> Result<Proof, LegacyError> {
    if bytes.len() != 296 {
        return Err(LegacyError::InvalidProofEncoding);
    }
    let g1 = |bytes: &[u8]| G1::from_compressed(bytes)
        .map_err(|_| LegacyError::InvalidProofEncoding);
    Ok(Proof {
        a: g1(&bytes[..33])?,
        a_prime: g1(&bytes[33..66])?,
        b: G2::from_compressed(&bytes[66..131])
            .map_err(|_| LegacyError::InvalidProofEncoding)?,
        b_prime: g1(&bytes[131..164])?,
        c: g1(&bytes[164..197])?,
        c_prime: g1(&bytes[197..230])?,
        k: g1(&bytes[230..263])?,
        h: g1(&bytes[263..296])?,
    })
}

fn authenticate_key(bytes: &[u8]) -> Result<VerifyingKey, LegacyError> {
    if bytes.len() != VERIFYING_KEY_BYTES.len()
        || Sha256::digest(bytes).as_slice() != VERIFYING_KEY_SHA256
    {
        return Err(LegacyError::InvalidVerifyingKey);
    }
    decode_key_format(bytes)
}

// The original file uses NO_PT_COMPRESSION and MONTGOMERY_OUTPUT. Coordinates
// are four little-endian u64 limbs, NOT canonical compressed-proof integers.
// Its sparse metadata is ASCII even with binary field/group serialization.
struct KeyReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    inverse_r: Fq,
}

impl KeyReader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], LegacyError> {
        let slice = self.bytes.get(self.offset..self.offset + N)
            .ok_or(LegacyError::InvalidVerifyingKey)?;
        let mut result = [0; N];
        result.copy_from_slice(slice);
        self.offset += N;
        Ok(result)
    }

    fn finite_marker(&mut self) -> Result<(), LegacyError> {
        if self.take::<1>()? != *b"0" {
            return Err(LegacyError::InvalidVerifyingKey);
        }
        Ok(())
    }

    fn fq(&mut self) -> Result<Fq, LegacyError> {
        let mut limbs = self.take::<32>()?;
        limbs.reverse();
        // Strictly reject raw Montgomery residues >=q before converting.
        let residue = Fq::from_slice(&limbs)
            .map_err(|_| LegacyError::InvalidVerifyingKey)?;
        Ok(residue * self.inverse_r)
    }

    fn fq2(&mut self) -> Result<Fq2, LegacyError> {
        Ok(Fq2::new(self.fq()?, self.fq()?)) // Original c0, then c1.
    }

    fn g1(&mut self) -> Result<G1, LegacyError> {
        self.finite_marker()?;
        AffineG1::new(self.fq()?, self.fq()?)
            .map(Into::into)
            .map_err(|_| LegacyError::InvalidVerifyingKey)
    }

    fn g2(&mut self) -> Result<G2, LegacyError> {
        self.finite_marker()?;
        // Checked affine construction enforces BOTH curve and order-r subgroup.
        AffineG2::new(self.fq2()?, self.fq2()?)
            .map(Into::into)
            .map_err(|_| LegacyError::InvalidVerifyingKey)
    }
}

fn decode_key_format(bytes: &[u8]) -> Result<VerifyingKey, LegacyError> {
    if bytes.len() != VERIFYING_KEY_BYTES.len() {
        return Err(LegacyError::InvalidVerifyingKey);
    }
    // Derive R mod q from the existing field's Montgomery encoding of one.
    // No handwritten field reduction or alternate key serialization is used.
    let mut r = [0; 32];
    Fq::one().to_mont_big_endian(&mut r)
        .map_err(|_| LegacyError::InvalidVerifyingKey)?;
    let inverse_r = Fq::from_slice(&r)
        .map_err(|_| LegacyError::InvalidVerifyingKey)?
        .inverse().ok_or(LegacyError::InvalidVerifyingKey)?;
    let mut reader = KeyReader { bytes, offset: 0, inverse_r };
    let alpha_a = reader.g2()?;
    let alpha_b = reader.g1()?;
    let alpha_c = reader.g2()?;
    let gamma = reader.g2()?;
    let gamma_beta_1 = reader.g1()?;
    let gamma_beta_2 = reader.g2()?;
    let zeta = reader.g2()?;
    let mut ic = [G1::zero(); 10];
    ic[0] = reader.g1()?;
    // Exact domain 9, count 9, indices 0..8, value count 9: no permissive zip.
    if reader.take::<24>()? != *IC_METADATA {
        return Err(LegacyError::InvalidVerifyingKey);
    }
    for point in &mut ic[1..] {
        *point = reader.g1()?;
    }
    if reader.offset != bytes.len() {
        return Err(LegacyError::InvalidVerifyingKey);
    }
    Ok(VerifyingKey { alpha_a, alpha_b, alpha_c, gamma, gamma_beta_1, gamma_beta_2, zeta, ic })
}

pub(crate) fn h_sig(statement: &LegacyJoinSplit) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZcashComputehSig")
        .to_state()
        .update(&statement.random_seed)
        .update(&statement.nullifiers[0])
        .update(&statement.nullifiers[1])
        .update(&statement.joinsplit_pubkey)
        .finalize();
    let mut result = [0; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

fn public_inputs(statement: &LegacyJoinSplit) -> Result<[Fr; 9], LegacyError> {
    if statement.vpub_old > MAX_MONEY || statement.vpub_new > MAX_MONEY
        || (statement.vpub_old != 0 && statement.vpub_new != 0)
    {
        return Err(LegacyError::InvalidStatement);
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

    let mut inputs = [Fr::zero(); 9];
    for (chunk, input) in inputs.iter_mut().enumerate() {
        let start = chunk * 253;
        let mut limbs = [0u64; 4];
        // MSB first WITHIN each byte; first bit of a chunk has weight 2^0.
        // Eight 253-bit chunks followed by 152 bits: every scalar <2^253<r.
        for coefficient in 0..253.min(2176 - start) {
            let bit = start + coefficient;
            if (bytes[bit / 8] >> (7 - bit % 8)) & 1 != 0 {
                limbs[coefficient / 64] |= 1 << (coefficient % 64);
            }
        }
        *input = Fr::new(U256::from(limbs)).ok_or(LegacyError::InvalidStatement)?;
    }
    Ok(inputs)
}

// Combine terms ONLY within one equation. The five equations must never be
// folded into an unrandomized product: errors could cancel across equations.
fn pairing_product_is_one<const N: usize>(pairs: [(G1, G2); N]) -> Result<bool, LegacyError> {
    let mut nonzero = [(G2::zero(), G1::zero()); N];
    let mut count = 0;
    for (g1, g2) in pairs {
        // Original pairing at infinity is identity. Derived A+IC or A+IC+C
        // may be zero even though every encoded key/proof point is finite.
        if !g1.is_zero() && !g2.is_zero() {
            nonzero[count] = (g2, g1);
            count += 1;
        }
    }
    if count == 0 {
        return Ok(true);
    }
    let product = sprout_bn::miller_loop_batch(&nonzero[..count])
        .map_err(|_| LegacyError::InvalidProof)?
        .final_exponentiation().ok_or(LegacyError::InvalidProof)?;
    Ok(product == Gt::one())
}

fn verify_equations(key: &VerifyingKey, inputs: &[Fr; 9], proof: &Proof) -> Result<(), LegacyError> {
    let mut acc = key.ic[0];
    for (index, input) in inputs.iter().enumerate() {
        acc = acc + key.ic[index + 1] * *input;
    }
    let generator = G2::one();
    // Knowledge commitments A, B, C, then QAP divisibility and same coefficients.
    if !pairing_product_is_one([(proof.a, key.alpha_a), (-proof.a_prime, generator)])? {
        return Err(LegacyError::InvalidProof);
    }
    if !pairing_product_is_one([(key.alpha_b, proof.b), (-proof.b_prime, generator)])? {
        return Err(LegacyError::InvalidProof);
    }
    if !pairing_product_is_one([(proof.c, key.alpha_c), (-proof.c_prime, generator)])? {
        return Err(LegacyError::InvalidProof);
    }
    let a_acc = proof.a + acc;
    if !pairing_product_is_one([(a_acc, proof.b), (-proof.h, key.zeta), (-proof.c, generator)])? {
        return Err(LegacyError::InvalidProof);
    }
    if !pairing_product_is_one([
        (proof.k, key.gamma),
        (-(a_acc + proof.c), key.gamma_beta_2),
        (-key.gamma_beta_1, proof.b),
    ])? {
        return Err(LegacyError::InvalidProof);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/fixtures/sprout-positive.rs"]
mod positive;

#[cfg(test)]
mod tests {
    use super::*;
    use positive::{KEY_G1_HEX, KEY_G2_HEX, PROOF_HEX, PUBLIC_INPUT_DECIMAL, bytes, statement};

    fn numeric_fq(hex: &str) -> Fq {
        // Upstream coordinates are numerical hex, sometimes shorter than 32 bytes.
        let padded = format!("{hex:0>64}");
        Fq::from_slice(&bytes::<32>(&padded)).unwrap()
    }

    fn append_fq(output: &mut Vec<u8>, coordinate: Fq) {
        let mut montgomery = [0; 32];
        coordinate.to_mont_big_endian(&mut montgomery).unwrap();
        montgomery.reverse();
        output.extend_from_slice(&montgomery);
    }

    fn append_g1(output: &mut Vec<u8>, point: G1) {
        let affine = AffineG1::from_jacobian(point).unwrap();
        output.push(b'0');
        append_fq(output, affine.x());
        append_fq(output, affine.y());
    }

    fn append_g2_coordinates(output: &mut Vec<u8>, x: Fq2, y: Fq2) {
        output.push(b'0');
        for coordinate in [x.real(), x.imaginary(), y.real(), y.imaginary()] {
            append_fq(output, coordinate);
        }
    }

    fn append_g2(output: &mut Vec<u8>, point: G2) {
        let affine = AffineG2::from_jacobian(point).unwrap();
        append_g2_coordinates(output, affine.x(), affine.y());
    }

    #[test]
    fn full_statement_maps_to_independent_nine_public_scalars_and_real_proof() {
        let expected = PUBLIC_INPUT_DECIMAL.map(|decimal| Fr::from_str(decimal).unwrap());
        assert_eq!(public_inputs(&statement()).unwrap(), expected);
        let key = authenticate_key(VERIFYING_KEY_BYTES).unwrap();
        let proof = decode_proof(&bytes::<296>(PROOF_HEX)).unwrap();
        assert_eq!(verify_equations(&key, &expected, &proof), Ok(()));
    }

    #[test]
    fn authenticated_original_key_matches_all_canonical_coordinates_and_original_bytes() {
        let key = authenticate_key(VERIFYING_KEY_BYTES).unwrap();
        // Comparison only: JSON never bypasses authentication or supplies a key.
        for (actual, coordinates) in [
            key.alpha_a, key.alpha_c, key.gamma, key.gamma_beta_2, key.zeta,
        ].into_iter().zip(KEY_G2_HEX) {
            let affine = AffineG2::from_jacobian(actual).unwrap();
            // Numeric JSON order is [x.c1,x.c0,y.c1,y.c0], unlike original binary.
            assert_eq!(affine.x().imaginary(), numeric_fq(coordinates[0]));
            assert_eq!(affine.x().real(), numeric_fq(coordinates[1]));
            assert_eq!(affine.y().imaginary(), numeric_fq(coordinates[2]));
            assert_eq!(affine.y().real(), numeric_fq(coordinates[3]));
        }
        let mut g1 = [G1::zero(); 12];
        g1[0] = key.alpha_b;
        g1[1] = key.gamma_beta_1;
        g1[2..].copy_from_slice(&key.ic);
        for (actual, coordinates) in g1.into_iter().zip(KEY_G1_HEX) {
            let affine = AffineG1::from_jacobian(actual).unwrap();
            assert_eq!(affine.x(), numeric_fq(coordinates[0]));
            assert_eq!(affine.y(), numeric_fq(coordinates[1]));
        }

        let mut encoded = Vec::with_capacity(1449);
        append_g2(&mut encoded, key.alpha_a);
        append_g1(&mut encoded, key.alpha_b);
        append_g2(&mut encoded, key.alpha_c);
        append_g2(&mut encoded, key.gamma);
        append_g1(&mut encoded, key.gamma_beta_1);
        append_g2(&mut encoded, key.gamma_beta_2);
        append_g2(&mut encoded, key.zeta);
        append_g1(&mut encoded, key.ic[0]);
        encoded.extend_from_slice(IC_METADATA);
        for point in &key.ic[1..] {
            append_g1(&mut encoded, *point);
        }
        assert_eq!(encoded.as_slice(), VERIFYING_KEY_BYTES);
    }

    #[test]
    fn key_authentication_rejects_corruption_and_even_well_formed_parameter_substitution() {
        let mut corrupt = *VERIFYING_KEY_BYTES;
        corrupt[1] ^= 1;
        assert!(matches!(authenticate_key(&corrupt), Err(LegacyError::InvalidVerifyingKey)));

        let mut changed = *VERIFYING_KEY_BYTES;
        // Substitute gammaBeta1 for alphaB: all coordinates/subgroups stay valid.
        changed[129..194].copy_from_slice(&VERIFYING_KEY_BYTES[452..517]);
        let substituted = decode_key_format(&changed).unwrap();
        let original = authenticate_key(VERIFYING_KEY_BYTES).unwrap();
        assert_eq!(substituted.alpha_b, original.gamma_beta_1);
        assert!(matches!(authenticate_key(&changed), Err(LegacyError::InvalidVerifyingKey)));

        assert!(matches!(authenticate_key(&VERIFYING_KEY_BYTES[..1448]), Err(LegacyError::InvalidVerifyingKey)));
        let mut extended = VERIFYING_KEY_BYTES.to_vec();
        extended.push(0);
        assert!(matches!(authenticate_key(&extended), Err(LegacyError::InvalidVerifyingKey)));
    }

    #[test]
    fn bounded_key_decoder_rejects_sparse_metadata_infinity_and_noncanonical_coordinates() {
        for (offset, value) in [
            (840, b'8'), // domain size
            (842, b'8'), // index count
            (844, b'1'), // duplicate/out-of-order index
            (846, b'0'),
            (862, b'8'), // value count
            (841, b' '), // noncanonical separator
            (0, b'1'), (0, b'2'), // G2 infinity/invalid marker
            (129, b'1'), (129, 0), // G1 infinity/invalid marker
            (864, b'1'), // sparse IC point infinity
        ] {
            let mut changed = *VERIFYING_KEY_BYTES;
            changed[offset] = value;
            assert!(matches!(decode_key_format(&changed), Err(LegacyError::InvalidVerifyingKey)), "key offset {offset}");
        }
        // Canonical raw integer boundary, before Montgomery interpretation.
        let mut modulus = bytes::<32>("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
        modulus.reverse();
        for offset in [1, 130] {
            let mut changed = *VERIFYING_KEY_BYTES;
            changed[offset..offset + 32].copy_from_slice(&modulus);
            assert!(matches!(decode_key_format(&changed), Err(LegacyError::InvalidVerifyingKey)));
        }
        // Finite marker plus canonical all-zero coordinates is not on either curve.
        for (start, end) in [(1, 129), (130, 194)] {
            let mut changed = *VERIFYING_KEY_BYTES;
            changed[start..end].fill(0);
            assert!(matches!(decode_key_format(&changed), Err(LegacyError::InvalidVerifyingKey)));
        }
        let mut swapped = *VERIFYING_KEY_BYTES;
        swapped[1..33].copy_from_slice(&VERIFYING_KEY_BYTES[33..65]);
        swapped[33..65].copy_from_slice(&VERIFYING_KEY_BYTES[1..33]);
        assert!(matches!(decode_key_format(&swapped), Err(LegacyError::InvalidVerifyingKey)));

        assert!(matches!(decode_key_format(&VERIFYING_KEY_BYTES[..1448]), Err(LegacyError::InvalidVerifyingKey)));
        let mut extended = VERIFYING_KEY_BYTES.to_vec();
        extended.push(0);
        assert!(matches!(decode_key_format(&extended), Err(LegacyError::InvalidVerifyingKey)));
    }

    #[test]
    fn on_curve_non_subgroup_g2_is_rejected_in_key_and_network_proof() {
        // Deterministically derived regression data, NOT an upstream fixed vector.
        // Original MIT test_proofs.cpp::g2_subgroup_check used random points.
        // Use only existing Fq2 square root and checked subgroup construction.
        let (x, y) = (0..64).find_map(|integer| {
            let x = Fq2::new(Fq::from_u256(U256::from(integer)).unwrap(), Fq::one());
            let y = (x * x * x + G2::b()).sqrt()?;
            match AffineG2::new(x, y) {
                Err(sprout_bn::GroupError::NotInSubgroup) => Some((x, y)),
                Ok(_) => None,
                Err(error) => panic!("square root produced invalid curve point: {error}"),
            }
        }).expect("bounded deterministic on-curve nonsubgroup point");
        assert_eq!(y * y, x * x * x + G2::b());

        let mut point = Vec::with_capacity(129);
        append_g2_coordinates(&mut point, x, y);
        let mut key = *VERIFYING_KEY_BYTES;
        key[..129].copy_from_slice(&point);
        assert!(matches!(decode_key_format(&key), Err(LegacyError::InvalidVerifyingKey)));

        // Network Fq2 serialization is c1*q+c0, not separate Montgomery limbs.
        let combined = sprout_bn::arith::U512::new(
            &x.imaginary().into_u256(), &x.real().into_u256(), &Fq::modulus(),
        );
        let mut proof = bytes::<296>(PROOF_HEX);
        proof[66] = 0x0a;
        for (index, limb) in combined.0.iter().rev().enumerate() {
            proof[67 + index * 16..83 + index * 16].copy_from_slice(&limb.to_be_bytes());
        }
        assert_eq!(verify_sprout_legacy(&statement(), &proof), Err(LegacyError::InvalidProofEncoding));
    }

    #[test]
    fn knowledge_commitment_failures_cannot_cancel_across_equations() {
        let key = authenticate_key(VERIFYING_KEY_BYTES).unwrap();
        let inputs = public_inputs(&statement()).unwrap();
        let mut proof = decode_proof(&bytes::<296>(PROOF_HEX)).unwrap();
        proof.a_prime = proof.a_prime + G1::one();
        proof.b_prime = proof.b_prime - G1::one();
        assert!(!proof.a_prime.is_zero() && !proof.b_prime.is_zero());
        // +delta and -delta errors would cancel in one unrandomized product.
        assert_eq!(pairing_product_is_one([
            (proof.a, key.alpha_a), (-proof.a_prime, G2::one()),
            (key.alpha_b, proof.b), (-proof.b_prime, G2::one()),
        ]), Ok(true));
        assert_eq!(verify_equations(&key, &inputs, &proof), Err(LegacyError::InvalidProof));
    }

    #[test]
    fn derived_infinity_terms_have_original_pairing_identity_semantics() {
        assert_eq!(pairing_product_is_one([
            (G1::zero(), G2::one()), (G1::one(), G2::one()), (-G1::one(), G2::one()),
        ]), Ok(true));
        assert_eq!(pairing_product_is_one([
            (G1::zero(), G2::one()), (G1::one(), G2::one()),
        ]), Ok(false));
    }
}
