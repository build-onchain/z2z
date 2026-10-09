// Primary Zebra block fixtures at e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291.
/*
Copyright (c) 2019-2025 Zcash Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

use zcash_protocol::consensus::TEST_NETWORK;
use ziquid_proofs::{history::ParsedBlockBody, sapling_coinbase::recover_sapling_coinbase_output};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::AeadInPlace};
use group::GroupEncoding;
use sapling_crypto::{
    Diversifier,
    bundle::{GrothProofBytes, OutputDescription},
    constants::SPENDING_KEY_GENERATOR,
    keys::OutgoingViewingKey,
    note::{ExtractedNoteCommitment, NoteCommitment},
    note_encryption::{KDF_SAPLING_PERSONALIZATION, prf_ock},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use zcash_note_encryption::EphemeralKeyBytes;
use ziquid_proofs::sapling_coinbase::CoinbaseRecoveryError;
use zcash_spec::PrfExpand;

#[test]
fn original_shielded_coinbase_outputs_recover_with_public_zero_ovk() {
    // Exact primary Zebra e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291 numeric body,
    // MIT notice retained above; isolated crypto only.
    let raw = include_bytes!("fixtures/testnet-heartwood-block-914678.bin");
    let body = ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap();
    let transaction = &body.block().vtx()[0];
    let bundle = transaction.sapling_bundle().expect("primary shielded coinbase");
    assert!(bundle.shielded_spends().is_empty());
    let recovered: u64 = bundle.shielded_outputs().iter().map(|output| recover_sapling_coinbase_output(output, 914_678).unwrap()).sum();
    let balance: i64 = (*bundle.value_balance()).into();
    assert_eq!(recovered, balance.unsigned_abs());
    assert!(balance < 0);
}

fn primary_outputs() -> Vec<(u32, OutputDescription<GrothProofBytes>)> {
    [
        (914_678, &include_bytes!("fixtures/testnet-heartwood-block-914678.bin")[..]),
        (1_101_629, &include_bytes!("fixtures/testnet-canopy-block-1101629.bin")[..]),
    ].into_iter().flat_map(|(height, raw)| {
        ParsedBlockBody::parse(raw, &TEST_NETWORK).unwrap().block().vtx()[0]
            .sapling_bundle().unwrap().shielded_outputs().to_vec()
            .into_iter().map(move |output| (height, output))
    }).collect()
}

#[test]
fn original_outputs_authenticate_every_consumed_wire_field_and_both_tags() {
    for (height, original) in primary_outputs() {
        for field in 0..7 {
            let mut cv = original.cv().clone();
            let mut cmu = *original.cmu();
            let mut epk = original.ephemeral_key().clone();
            let mut enc = *original.enc_ciphertext();
            let mut out = *original.out_ciphertext();
            match field {
                0 => cv = ValueCommitment::derive(NoteValue::from_raw(1), ValueCommitTrapdoor::from_bytes(jubjub::Fr::from(1).to_bytes()).unwrap()),
                1 => cmu = ExtractedNoteCommitment::from_bytes(&bls12_381::Scalar::from(1).to_bytes()).unwrap(),
                2 => epk.0[0] ^= 1,
                3 => enc[0] ^= 1,
                4 => enc[579] ^= 1,
                5 => out[0] ^= 1,
                6 => out[79] ^= 1,
                _ => unreachable!(),
            }
            let changed = OutputDescription::from_parts(cv, cmu, epk, enc, out, *original.zkproof());
            assert_eq!(recover_sapling_coinbase_output(&changed, height), Err(if field == 3 || field == 4 {
                CoinbaseRecoveryError::NoteAuthentication
            } else {
                CoinbaseRecoveryError::OutgoingAuthentication
            }), "field {field}");
        }
    }
}

// This creates real AEAD ciphertexts for recovery edge cases only. The zero
// Groth16 bytes are deliberately not verified and make NO proof-validity claim.
struct EncryptedCase {
    pk_d: jubjub::AffinePoint,
    esk: jubjub::Fr,
    outgoing: [u8; 64],
    note: [u8; 564],
    epk: [u8; 32],
    cmu: ExtractedNoteCommitment,
}

impl EncryptedCase {
    fn new(pk_d: jubjub::AffinePoint) -> Self {
        let g_d = Diversifier([0; 11]).g_d().unwrap();
        let esk = jubjub::Fr::from(7);
        let rcm = jubjub::Fr::from(3);
        let mut outgoing = [0; 64];
        outgoing[..32].copy_from_slice(&pk_d.to_bytes());
        outgoing[32..].copy_from_slice(&esk.to_bytes());
        let mut note = [0; 564];
        note[0] = 1;
        note[12..20].copy_from_slice(&42_u64.to_le_bytes());
        note[20..52].copy_from_slice(&rcm.to_bytes());
        note[52..].fill(0xab);
        Self {
            pk_d, esk, outgoing, note,
            epk: (g_d * esk).to_bytes(),
            cmu: NoteCommitment::temporary_zcashd_derive(g_d.to_bytes(), pk_d.to_bytes(), NoteValue::from_raw(42), rcm).into(),
        }
    }

    fn canopy(pk_d: jubjub::AffinePoint, rseed: [u8; 32]) -> Self {
        let mut case = Self::new(pk_d);
        let g_d = Diversifier([0; 11]).g_d().unwrap();
        let rcm = jubjub::Fr::from_bytes_wide(&PrfExpand::SAPLING_RCM.with(&rseed));
        case.esk = jubjub::Fr::from_bytes_wide(&PrfExpand::SAPLING_ESK.with(&rseed));
        case.outgoing[32..].copy_from_slice(&case.esk.to_bytes());
        case.note[0] = 2;
        case.note[20..52].copy_from_slice(&rseed);
        case.epk = (g_d * case.esk).to_bytes();
        case.cmu = NoteCommitment::temporary_zcashd_derive(
            g_d.to_bytes(), pk_d.to_bytes(), NoteValue::from_raw(42), rcm,
        ).into();
        case
    }

    fn with_value(mut self, value: u64) -> Self {
        self.note[12..20].copy_from_slice(&value.to_le_bytes());
        let randomness: [u8; 32] = self.note[20..52].try_into().unwrap();
        let rcm = if self.note[0] == 1 {
            jubjub::Fr::from_bytes(&randomness).unwrap()
        } else {
            jubjub::Fr::from_bytes_wide(&PrfExpand::SAPLING_RCM.with(&randomness))
        };
        self.cmu = NoteCommitment::temporary_zcashd_derive(
            Diversifier([0; 11]).g_d().unwrap().to_bytes(), self.pk_d.to_bytes(),
            NoteValue::from_raw(value), rcm,
        ).into();
        self
    }

    fn encrypt(&self) -> OutputDescription<GrothProofBytes> {
        let value = u64::from_le_bytes(self.note[12..20].try_into().unwrap());
        let cv = ValueCommitment::derive(NoteValue::from_raw(value), ValueCommitTrapdoor::from_bytes(jubjub::Fr::from(9).to_bytes()).unwrap());
        let epk = EphemeralKeyBytes(self.epk);
        let ock = prf_ock(&OutgoingViewingKey([0; 32]), &cv, &self.cmu.to_bytes(), &epk);
        let shared = (jubjub::ExtendedPoint::from(self.pk_d) * self.esk).mul_by_cofactor().to_bytes();
        let key = blake2b_simd::Params::new().hash_length(32).personal(KDF_SAPLING_PERSONALIZATION)
            .to_state().update(&shared).update(&self.epk).finalize();
        let mut enc = [0; 580];
        enc[..564].copy_from_slice(&self.note);
        let tag = ChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap()
            .encrypt_in_place_detached(Nonce::from_slice(&[0; 12]), &[], &mut enc[..564]).unwrap();
        enc[564..].copy_from_slice(&tag);
        let mut out = [0; 80];
        out[..64].copy_from_slice(&self.outgoing);
        let tag = ChaCha20Poly1305::new_from_slice(&ock.0).unwrap()
            .encrypt_in_place_detached(Nonce::from_slice(&[0; 12]), &[], &mut out[..64]).unwrap();
        out[64..].copy_from_slice(&tag);
        OutputDescription::from_parts(cv, self.cmu, epk, enc, out, [0; 192])
    }
}

#[test]
fn historical_identity_and_alternate_x_zero_encoding_recover_canonical_commitment() {
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Ok(42));
    case.outgoing[31] |= 0x80;
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Ok(42));
    // Prime-order nonidentity recipients are still accepted, too.
    assert_eq!(recover_sapling_coinbase_output(&EncryptedCase::new(jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR))).encrypt(), 914_678), Ok(42));
}

#[test]
fn recovered_pkd_requires_canonical_field_curve_and_prime_subgroup_not_nonidentity() {
    let off_curve = (0..=u8::MAX).map(|first| {
        let mut raw = [2; 32];
        raw[0] = first;
        raw
    }).find(|raw| !bool::from(jubjub::AffinePoint::from_bytes_pre_zip216_compatibility(*raw).is_some())).unwrap();
    for raw in [[0xff; 32], off_curve] {
        let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
        case.outgoing[..32].copy_from_slice(&raw);
        assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::InvalidTransmissionKey));
    }
    let torsion = jubjub::AffinePoint::from_raw_unchecked(bls12_381::Scalar::zero(), -bls12_381::Scalar::one());
    for point in [torsion, jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR) + jubjub::ExtendedPoint::from(torsion))] {
        let case = EncryptedCase::new(point);
        assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::InvalidTransmissionKey));
    }
    let mut case = EncryptedCase::new(torsion);
    case.outgoing[31] |= 0x80;
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::InvalidTransmissionKey));
}

#[test]
fn authenticated_plaintexts_still_require_canonical_scalars_version_and_diversifier() {
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    case.outgoing[32..].fill(0xff);
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::InvalidEphemeralSecret));
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    case.note[20..52].fill(0xff);
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::InvalidCommitmentRandomness));
    for version in [0, 2] {
        let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
        case.note[0] = version;
        assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::InvalidPlaintextVersion));
    }
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    let invalid = (0..=u8::MAX).map(|first| {
        let mut raw = [0; 11];
        raw[0] = first;
        Diversifier(raw)
    }).find(|d| d.g_d().is_none()).unwrap();
    case.note[1..12].copy_from_slice(&invalid.0);
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::InvalidDiversifier));
}

#[test]
fn replay_epk_equation_is_unconditional_even_for_plaintext_v1() {
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    case.epk = (SPENDING_KEY_GENERATOR * jubjub::Fr::from(11)).to_bytes();
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::EphemeralKeyMismatch));
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    case.esk = jubjub::Fr::from(8);
    case.outgoing[32..].copy_from_slice(&case.esk.to_bytes());
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::EphemeralKeyMismatch));
    // Zero esk is canonical; recovery does not invent a nonzero restriction.
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    case.esk = jubjub::Fr::zero();
    case.outgoing[32..].fill(0);
    case.epk = jubjub::AffinePoint::identity().to_bytes();
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Ok(42));
    case.epk[31] |= 0x80;
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::EphemeralKeyMismatch));
}

#[test]
fn authenticated_value_randomness_and_pkd_must_match_actual_commitment() {
    for field in 0..4 {
        let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
        match field {
            0 => case.note[12..20].copy_from_slice(&43_u64.to_le_bytes()),
            1 => case.note[20..52].copy_from_slice(&jubjub::Fr::from(4).to_bytes()),
            2 => {
                case.pk_d = jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR));
                case.outgoing[..32].copy_from_slice(&case.pk_d.to_bytes());
            }
            3 => case.cmu = ExtractedNoteCommitment::from_bytes(&bls12_381::Scalar::from(1).to_bytes()).unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::CommitmentMismatch), "field {field}");
    }
}

#[test]
fn complete_memo_is_authenticated_but_not_interpreted_as_a_consensus_predicate() {
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    case.note[52..].fill(0xff);
    let original = case.encrypt();
    assert_eq!(recover_sapling_coinbase_output(&original, 914_678), Ok(42));
    let mut enc = *original.enc_ciphertext();
    enc[563] ^= 1;
    let changed = OutputDescription::from_parts(original.cv().clone(), *original.cmu(), original.ephemeral_key().clone(), enc, *original.out_ciphertext(), *original.zkproof());
    assert_eq!(recover_sapling_coinbase_output(&changed, 914_678), Err(CoinbaseRecoveryError::NoteAuthentication));
}

#[test]
fn recovery_errors_never_include_private_plaintexts() {
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    case.note[12..20].copy_from_slice(&9_876_543_210_u64.to_le_bytes());
    let error = recover_sapling_coinbase_output(&case.encrypt(), 914_678).unwrap_err();
    assert_eq!(error, CoinbaseRecoveryError::CommitmentMismatch);
    assert!(!format!("{error} {error:?}").contains("9876543210"));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn recovery_does_not_replace_separate_original_output_proof_validation() {
    for (height, original) in primary_outputs() {
        let mut proof = *original.zkproof();
        proof[0] ^= 1;
        let changed = OutputDescription::from_parts(original.cv().clone(), *original.cmu(), original.ephemeral_key().clone(), *original.enc_ciphertext(), *original.out_ciphertext(), proof);
        assert_eq!(recover_sapling_coinbase_output(&changed, height), recover_sapling_coinbase_output(&original, height));
    }
}

#[test]
fn alternate_valid_diversifier_must_match_commitment_after_epk_check() {
    let mut case = EncryptedCase::new(jubjub::AffinePoint::identity());
    let alternative = (1..=u8::MAX).map(|first| {
        let mut raw = [0; 11];
        raw[0] = first;
        Diversifier(raw)
    }).find(|d| d.g_d().is_some()).unwrap();
    case.note[1..12].copy_from_slice(&alternative.0);
    case.epk = (alternative.g_d().unwrap() * case.esk).to_bytes();
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 914_678), Err(CoinbaseRecoveryError::CommitmentMismatch));
}

#[test]
fn original_canopy_shielded_coinbase_uses_height_selected_rseed_recovery() {
    // Unchanged primary Zebra e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291
    // block-test-1-101-629.txt (blob 94f120657e2ab74cd99b57159aaf7e4fad94be41).
    // No plaintext value or rseed is assumed; this checks isolated recovery,
    // not a genesis-connected ledger admission or output-proof verification.
    let body = ParsedBlockBody::parse(include_bytes!("fixtures/testnet-canopy-block-1101629.bin"), &TEST_NETWORK).unwrap();
    let tx = &body.block().vtx()[0];
    assert!(tx.sapling_bundle().unwrap().shielded_spends().is_empty());
    let outputs = tx.sapling_bundle().unwrap().shielded_outputs();
    assert!(!outputs.is_empty());
    let values: Vec<u64> = outputs.iter().map(|output| recover_sapling_coinbase_output(output, 1_101_629).unwrap()).collect();
    let balance: i64 = (*tx.sapling_bundle().unwrap().value_balance()).into();
    assert_eq!(values.iter().sum::<u64>(), balance.unsigned_abs());
    assert!(balance < 0);
    assert_eq!(recover_sapling_coinbase_output(&outputs[0], 1_028_499), Err(CoinbaseRecoveryError::InvalidPlaintextVersion));
}

#[test]
fn canopy_accepts_arbitrary_rseed_not_only_canonical_scalar_bytes() {
    assert!(!bool::from(jubjub::Fr::from_bytes(&[0xff; 32]).is_some()));
    for rseed in [[0xff; 32], [0; 32]] {
        let case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), rseed);
        assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Ok(42));
    }
}

#[test]
fn coinbase_plaintext_version_switches_immediately_without_wallet_grace() {
    let heartwood = EncryptedCase::new(jubjub::AffinePoint::identity()).encrypt();
    let canopy = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]).encrypt();
    assert_eq!(recover_sapling_coinbase_output(&heartwood, 1_028_499), Ok(42));
    assert_eq!(recover_sapling_coinbase_output(&canopy, 1_028_499), Err(CoinbaseRecoveryError::InvalidPlaintextVersion));
    for height in [1_028_500, 1_060_755, 1_060_756, 1_101_629] {
        assert_eq!(recover_sapling_coinbase_output(&heartwood, height), Err(CoinbaseRecoveryError::InvalidPlaintextVersion));
        assert_eq!(recover_sapling_coinbase_output(&canopy, height), Ok(42));
    }
    for version in [0, 3] {
        let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
        case.note[0] = version;
        assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Err(CoinbaseRecoveryError::InvalidPlaintextVersion));
    }
}

#[test]
fn recovery_supports_only_height_selected_heartwood_through_finite_nu63_branches() {
    let heartwood = EncryptedCase::new(jubjub::AffinePoint::identity()).encrypt();
    let canopy = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]).encrypt();
    for height in [903_800, 914_678, 1_028_499] {
        assert_eq!(recover_sapling_coinbase_output(&heartwood, height), Ok(42));
    }
    for height in [1_028_500, 1_101_629, 1_842_419] {
        assert_eq!(recover_sapling_coinbase_output(&canopy, height), Ok(42));
    }
    let recipient = jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR));
    let nu5 = EncryptedCase::canopy(recipient, [0xff; 32]).encrypt();
    for height in [1_842_420, 2_121_199, 2_121_200, 2_975_999, 2_976_000, 3_395_999, 3_396_000, 3_536_499, 3_536_500, 4_048_499, 4_048_500, 4_051_999, 4_052_000, 4_133_999, 4_134_000, 4_465_025] {
        assert_eq!(recover_sapling_coinbase_output(&nu5, height), Ok(42));
        assert_eq!(recover_sapling_coinbase_output(&heartwood, height), Err(if height < 2_121_200 {
            CoinbaseRecoveryError::InvalidPlaintextVersion
        } else {
            CoinbaseRecoveryError::InvalidTransmissionKey
        }));
    }
    for height in [0, 903_799, 4_465_026, u32::MAX] {
        for output in [&heartwood, &canopy, &nu5] {
            assert_eq!(recover_sapling_coinbase_output(output, height), Err(CoinbaseRecoveryError::UnsupportedEra));
        }
    }
}

#[test]
fn canopy_outgoing_secret_must_be_canonical_and_equal_seed_derivation() {
    let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    case.outgoing[32..].fill(0xff);
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Err(CoinbaseRecoveryError::InvalidEphemeralSecret));
    let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    case.esk += jubjub::Fr::from(1);
    case.outgoing[32..].copy_from_slice(&case.esk.to_bytes());
    // Reauthenticate both ciphertexts and satisfy g_d*esk==epk: only the
    // rseed-derived esk comparison can reject this otherwise consistent case.
    case.epk = (Diversifier([0; 11]).g_d().unwrap() * case.esk).to_bytes();
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Err(CoinbaseRecoveryError::EphemeralSecretMismatch));
}

#[test]
fn canopy_checks_original_epk_bytes_after_seed_secret_match() {
    let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    case.epk = (SPENDING_KEY_GENERATOR * jubjub::Fr::from(11)).to_bytes();
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Err(CoinbaseRecoveryError::EphemeralKeyMismatch));
    let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    case.epk[31] ^= 0x80;
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Err(CoinbaseRecoveryError::EphemeralKeyMismatch));
}

#[test]
fn canopy_authenticates_seed_derived_commitment_value_and_canonical_pkd() {
    for field in 0..4 {
        let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
        match field {
            0 => case.note[12..20].copy_from_slice(&43_u64.to_le_bytes()),
            1 => {
                let old_cmu = case.cmu;
                case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0; 32]);
                case.cmu = old_cmu;
            }
            2 => {
                case.pk_d = jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR));
                case.outgoing[..32].copy_from_slice(&case.pk_d.to_bytes());
            }
            3 => case.cmu = ExtractedNoteCommitment::from_bytes(&bls12_381::Scalar::from(1).to_bytes()).unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Err(CoinbaseRecoveryError::CommitmentMismatch), "field {field}");
    }
}

#[test]
fn canopy_retains_historical_identity_and_alternate_x_zero_recipient_keys() {
    let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Ok(42));
    case.outgoing[31] |= 0x80;
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Ok(42));
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_842_419), Ok(42));
    let recipient = jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR));
    let nonidentity = EncryptedCase::canopy(recipient, [0xff; 32]);
    assert_eq!(recover_sapling_coinbase_output(&nonidentity.encrypt(), 1_101_629), Ok(42));
    let torsion = jubjub::AffinePoint::from_raw_unchecked(bls12_381::Scalar::zero(), -bls12_381::Scalar::one());
    for point in [torsion, jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR) + jubjub::ExtendedPoint::from(torsion))] {
        let case = EncryptedCase::canopy(point, [0xff; 32]);
        assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Err(CoinbaseRecoveryError::InvalidTransmissionKey));
    }
}

#[test]
fn canopy_complete_memo_is_authenticated_without_a_content_predicate() {
    let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    case.note[52..].fill(0xff);
    let original = case.encrypt();
    assert_eq!(recover_sapling_coinbase_output(&original, 1_101_629), Ok(42));
    let mut enc = *original.enc_ciphertext();
    enc[563] ^= 1;
    let changed = OutputDescription::from_parts(original.cv().clone(), *original.cmu(), original.ephemeral_key().clone(), enc, *original.out_ciphertext(), *original.zkproof());
    assert_eq!(recover_sapling_coinbase_output(&changed, 1_101_629), Err(CoinbaseRecoveryError::NoteAuthentication));
}

#[test]
fn canopy_rejects_authenticated_invalid_diversifier_and_changed_seed() {
    let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    let invalid = (0..=u8::MAX).map(|first| {
        let mut raw = [0; 11];
        raw[0] = first;
        Diversifier(raw)
    }).find(|d| d.g_d().is_none()).unwrap();
    case.note[1..12].copy_from_slice(&invalid.0);
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Err(CoinbaseRecoveryError::InvalidDiversifier));
    let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    case.note[20] ^= 1;
    assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), 1_101_629), Err(CoinbaseRecoveryError::EphemeralSecretMismatch));
}

#[test]
fn canopy_errors_do_not_disclose_authenticated_value_or_seed() {
    let mut case = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    case.note[12..20].copy_from_slice(&9_876_543_210_u64.to_le_bytes());
    let error = recover_sapling_coinbase_output(&case.encrypt(), 1_101_629).unwrap_err();
    assert_eq!(error, CoinbaseRecoveryError::CommitmentMismatch);
    assert!(!format!("{error} {error:?}").contains("9876543210"));
    assert!(std::error::Error::source(&error).is_none());
    case.note[20] ^= 1;
    let error = recover_sapling_coinbase_output(&case.encrypt(), 1_101_629).unwrap_err();
    assert_eq!(error, CoinbaseRecoveryError::EphemeralSecretMismatch);
    assert!(!format!("{error} {error:?}").contains("9876543210"));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn nu5_canonical_key_and_later_nonidentity_switch_are_height_exact() {
    let canonical = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]).encrypt();
    let mut alternate = EncryptedCase::canopy(jubjub::AffinePoint::identity(), [0xff; 32]);
    alternate.outgoing[31] |= 0x80;
    let alternate = alternate.encrypt();
    for height in [1_028_500, 1_842_419] {
        assert_eq!(recover_sapling_coinbase_output(&alternate, height), Ok(42));
    }
    for height in [1_842_420, 2_121_199] {
        assert_eq!(recover_sapling_coinbase_output(&canonical, height), Ok(42));
        assert_eq!(recover_sapling_coinbase_output(&alternate, height), Err(CoinbaseRecoveryError::InvalidTransmissionKey));
    }
    for height in [2_121_200, 2_975_999, 2_976_000, 3_536_499, 3_536_500, 4_048_500, 4_051_999, 4_052_000, 4_133_999] {
        assert_eq!(recover_sapling_coinbase_output(&canonical, height), Err(CoinbaseRecoveryError::InvalidTransmissionKey));
        assert_eq!(recover_sapling_coinbase_output(&alternate, height), Err(CoinbaseRecoveryError::InvalidTransmissionKey));
    }
    let recipient = jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR));
    let valid = EncryptedCase::canopy(recipient, [0xff; 32]).encrypt();
    let torsion = jubjub::AffinePoint::from_raw_unchecked(bls12_381::Scalar::zero(), -bls12_381::Scalar::one());
    for height in [1_842_419, 1_842_420, 2_121_199, 2_121_200, 2_975_999, 2_976_000, 3_536_499, 3_536_500, 4_048_500, 4_051_999, 4_052_000, 4_133_999] {
        assert_eq!(recover_sapling_coinbase_output(&valid, height), Ok(42));
        for point in [torsion, jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(recipient) + jubjub::ExtendedPoint::from(torsion))] {
            assert_eq!(recover_sapling_coinbase_output(&EncryptedCase::canopy(point, [0xff; 32]).encrypt(), height), Err(CoinbaseRecoveryError::InvalidTransmissionKey));
        }
        let mut invalid = EncryptedCase::canopy(recipient, [0xff; 32]);
        invalid.outgoing[..32].fill(0xff);
        assert_eq!(recover_sapling_coinbase_output(&invalid.encrypt(), height), Err(CoinbaseRecoveryError::InvalidTransmissionKey));
    }
}

#[test]
fn recovered_amount_guard_starts_at_original_rust_switch_not_earlier_history() {
    let recipient = jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR));
    // Literal original Amount boundary; all ciphertexts and commitments bind
    // the actual value, including values that modern Amount cannot construct.
    for value in [0, 2_100_000_000_000_000, 2_100_000_000_000_001, u64::MAX] {
        let heartwood = EncryptedCase::new(recipient).with_value(value).encrypt();
        assert_eq!(recover_sapling_coinbase_output(&heartwood, 914_678), Ok(value));
        let seed_note = EncryptedCase::canopy(recipient, [0xff; 32]).with_value(value).encrypt();
        for height in [1_028_500, 1_842_419, 1_842_420, 2_121_199] {
            assert_eq!(recover_sapling_coinbase_output(&seed_note, height), Ok(value));
        }
        for height in [2_121_200, 2_975_999, 2_976_000, 3_536_499, 3_536_500, 4_048_500, 4_051_999, 4_052_000, 4_133_999] {
            let expected = if value <= 2_100_000_000_000_000 {
                Ok(value)
            } else {
                Err(CoinbaseRecoveryError::RecoveredValueOutOfRange)
            };
            assert_eq!(recover_sapling_coinbase_output(&seed_note, height), expected);
        }
    }
    // The original guard rejects before deriving cmu, with no value payload.
    let mut case = EncryptedCase::canopy(recipient, [0xff; 32]).with_value(u64::MAX);
    case.cmu = ExtractedNoteCommitment::from_bytes(&bls12_381::Scalar::from(1).to_bytes()).unwrap();
    let error = recover_sapling_coinbase_output(&case.encrypt(), 2_121_200).unwrap_err();
    assert_eq!(error, CoinbaseRecoveryError::RecoveredValueOutOfRange);
    assert!(!format!("{error} {error:?}").contains("18446744073709551615"));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn nu5_through_nu63_authenticate_full_ciphertexts_seed_secret_epk_and_commitment() {
    let recipient = jubjub::AffinePoint::from(jubjub::ExtendedPoint::from(SPENDING_KEY_GENERATOR));
    for height in [1_842_420, 2_121_200, 2_975_999, 2_976_000, 3_536_499, 3_536_500, 4_048_500, 4_051_999, 4_052_000, 4_133_999, 4_134_000, 4_465_025] {
        for seed in [[0; 32], [0xff; 32]] {
            assert_eq!(recover_sapling_coinbase_output(&EncryptedCase::canopy(recipient, seed).encrypt(), height), Ok(42));
        }
        for (field, expected) in [
            (0, CoinbaseRecoveryError::InvalidPlaintextVersion),
            (1, CoinbaseRecoveryError::InvalidEphemeralSecret),
            (2, CoinbaseRecoveryError::EphemeralSecretMismatch),
            (3, CoinbaseRecoveryError::EphemeralKeyMismatch),
            (4, CoinbaseRecoveryError::CommitmentMismatch),
        ] {
            let mut case = EncryptedCase::canopy(recipient, [0xff; 32]);
            match field {
                0 => case.note[0] = 1,
                1 => case.outgoing[32..].fill(0xff),
                2 => {
                    case.esk += jubjub::Fr::from(1);
                    case.outgoing[32..].copy_from_slice(&case.esk.to_bytes());
                    case.epk = (Diversifier([0; 11]).g_d().unwrap() * case.esk).to_bytes();
                }
                3 => case.epk[31] ^= 0x80,
                4 => case.note[12..20].copy_from_slice(&43_u64.to_le_bytes()),
                _ => unreachable!(),
            }
            assert_eq!(recover_sapling_coinbase_output(&case.encrypt(), height), Err(expected));
        }
        let mut case = EncryptedCase::canopy(recipient, [0xff; 32]);
        case.note[52..].fill(0xff);
        let original = case.encrypt();
        assert_eq!(recover_sapling_coinbase_output(&original, height), Ok(42));
        for field in 0..4 {
            let mut enc = *original.enc_ciphertext();
            let mut out = *original.out_ciphertext();
            match field {
                0 => enc[563] ^= 1,
                1 => enc[579] ^= 1,
                2 => out[0] ^= 1,
                3 => out[79] ^= 1,
                _ => unreachable!(),
            }
            let changed = OutputDescription::from_parts(original.cv().clone(), *original.cmu(), original.ephemeral_key().clone(), enc, out, *original.zkproof());
            assert_eq!(recover_sapling_coinbase_output(&changed, height), Err(if field < 2 {
                CoinbaseRecoveryError::NoteAuthentication
            } else {
                CoinbaseRecoveryError::OutgoingAuthentication
            }));
        }
    }
}
