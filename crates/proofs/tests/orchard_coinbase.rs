//! Ciphertext-only subrelation fixtures, NOT mined coinbases or valid proofs/signatures.
//! Zebra e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291, orchard_note_encryption.rs
//! ZERO_VECTOR (ten records), source Git blob ff52b661b539f9c2e329d3110e63669ee6de9131.
//! Source SHA256 6ef60be5fe02d1c24fdec82b5ad8e81e5afbf85a748ac0f1018b74ddf6714d7c;
//! extracted fixture SHA256 d4eefe9fd2aefb207b4aa5ce605812a890b82962e4222c871b4c26782c85f1eb.
//! cv/nf=rho/cmx/epk/enc/out/value are literal primary fields; rk is synthetic
//! identity because the source encryption vectors have no randomized key.
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

use chacha20poly1305::{ChaCha20Poly1305, aead::{AeadInPlace, KeyInit}};
use orchard::{
    Note,
    keys::OutgoingViewingKey,
    note::{ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho},
    note_encryption::{CompactAction, OrchardDomain, OrchardNoteEncryption},
    value::{NoteValue, ValueCommitment},
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zcash_note_encryption::{
    Domain, EphemeralKeyBytes, OutPlaintextBytes, ShieldedOutput,
    try_output_recovery_with_ovk,
};
use ziquid_proofs::raw_v5::{RawV5, RawV5Error, recover_orchard_coinbase_action};

const PRIMARY: &[u8; 8280] = include_bytes!("fixtures/orchard-zero-ovk-primary.bin");
const EXPECTED: [u64; 10] = [
    14_705_728_171_106_467_089, 16_644_083_129_188_108_223,
    1_173_411_008_555_061_269, 9_133_066_973_574_047_943,
    15_675_879_937_408_561_761, 2_367_411_484_911_514_344,
    15_057_875_082_412_072_133, 14_069_495_244_536_201_203,
    5_805_053_981_422_670_580, 7_880_286_546_227_755_774,
];

fn primary_action(index: usize) -> [u8; 820] {
    PRIMARY[index * 828..index * 828 + 820].try_into().unwrap()
}

struct Output<'a>(&'a [u8; 820]);

impl ShieldedOutput<OrchardDomain, 580> for Output<'_> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.0[128..160].try_into().unwrap())
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.0[96..128].try_into().unwrap()
    }

    fn enc_ciphertext(&self) -> &[u8; 580] {
        self.0[160..740].try_into().unwrap()
    }
}

fn domain(action: &[u8; 820]) -> OrchardDomain {
    let compact = CompactAction::from_parts(
        Nullifier::from_bytes(action[32..64].try_into().unwrap()).unwrap(),
        ExtractedNoteCommitment::from_bytes(action[96..128].try_into().unwrap()).unwrap(),
        Output(action).ephemeral_key(),
        action[160..212].try_into().unwrap(),
    );
    OrchardDomain::for_compact_action(&compact)
}

fn cv(action: &[u8; 820]) -> ValueCommitment {
    ValueCommitment::from_bytes(action[..32].try_into().unwrap()).unwrap()
}

fn ock(action: &[u8; 820]) -> [u8; 32] {
    OrchardDomain::derive_ock(
        &OutgoingViewingKey::from([0; 32]), &cv(action),
        &Output(action).cmstar_bytes(), &Output(action).ephemeral_key(),
    ).0
}

fn decrypt<const N: usize>(key: &[u8; 32], ciphertext: &[u8]) -> [u8; N] {
    let mut plaintext: [u8; N] = ciphertext[..N].try_into().unwrap();
    ChaCha20Poly1305::new(key.into()).decrypt_in_place_detached(
        (&[0; 12]).into(), &[], &mut plaintext, ciphertext[N..].into(),
    ).unwrap();
    plaintext
}

fn encrypt(key: &[u8; 32], plaintext: &[u8], ciphertext: &mut [u8]) {
    let length = plaintext.len();
    ciphertext[..length].copy_from_slice(plaintext);
    let tag = ChaCha20Poly1305::new(key.into()).encrypt_in_place_detached(
        (&[0; 12]).into(), &[], &mut ciphertext[..length],
    ).unwrap();
    ciphertext[length..].copy_from_slice(&tag);
}

fn note_key(action: &[u8; 820], outgoing: &[u8; 64]) -> [u8; 32] {
    let plaintext = OutPlaintextBytes(*outgoing);
    let pk_d = OrchardDomain::extract_pk_d(&plaintext).unwrap();
    let esk = OrchardDomain::extract_esk(&plaintext).unwrap();
    OrchardDomain::kdf(
        OrchardDomain::ka_agree_enc(&esk, &pk_d), &Output(action).ephemeral_key(),
    ).as_bytes().try_into().unwrap()
}

fn recovered_note(action: &[u8; 820]) -> Note {
    try_output_recovery_with_ovk(
        &domain(action), &OutgoingViewingKey::from([0; 32]), &Output(action),
        &cv(action), action[740..].try_into().unwrap(),
    ).unwrap().0
}

fn encrypt_note(action: &mut [u8; 820], note: Note, ovk: [u8; 32]) {
    let encryption = OrchardNoteEncryption::new(Some(OutgoingViewingKey::from(ovk)), note, [0; 512]);
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let outgoing = encryption.encrypt_outgoing_plaintext(
        &cv(action), &cmx, &mut ChaCha20Rng::from_seed([0; 32]),
    );
    action[96..128].copy_from_slice(&cmx.to_bytes());
    action[128..160].copy_from_slice(&OrchardDomain::epk_bytes(encryption.epk()).0);
    action[160..740].copy_from_slice(&encryption.encrypt_note_plaintext());
    action[740..].copy_from_slice(&outgoing);
}

// Deliberately synthetic V5 framing with empty proof and zero signatures. It is
// solely a parser/all-action recovery consumer, never a production-valid bundle.
fn ciphertext_only_transaction(actions: &[[u8; 820]], flags: u8) -> Vec<u8> {
    assert!(!actions.is_empty() && actions.len() < 253);
    let mut bytes = Vec::new();
    for word in [0x8000_0005u32, 0x26a7_270a, 0xc2d6_d0b4, 0, 1_842_420] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 0, 0, actions.len() as u8]);
    for action in actions {
        bytes.extend_from_slice(action);
    }
    bytes.push(flags);
    bytes.extend_from_slice(&[0; 8 + 32]); // balance and canonical anchor
    bytes.push(0); // explicitly absent/invalid proof
    bytes.resize(bytes.len() + actions.len() * 64 + 64, 0);
    bytes
}

#[test]
fn all_original_zero_ovk_actions_recover_actual_values_including_u64_wide() {
    for (index, expected) in EXPECTED.into_iter().enumerate() {
        assert_eq!(
            u64::from_le_bytes(PRIMARY[index * 828 + 820..(index + 1) * 828].try_into().unwrap()),
            expected,
        );
        assert_eq!(recover_orchard_coinbase_action(&primary_action(index)), Ok(expected));
    }
    // Original Orchard recovery has no per-note MAX_MONEY or signed-i64 cap.
    assert!(EXPECTED.iter().any(|value| *value > i64::MAX as u64));
}

#[test]
fn every_required_field_full_memo_and_both_tags_are_authenticated() {
    for (index, expected) in EXPECTED.into_iter().enumerate() {
        for offset in [0, 32, 96, 128, 160, 171, 172, 180, 212, 723, 724, 739, 740, 771, 772, 803, 804, 819] {
            let mut action = primary_action(index);
            action[offset] ^= 1;
            assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }), "record {index}, offset {offset}");
        }
        for range in [0..32, 32..64, 96..128] {
            let mut action = primary_action(index);
            action[range].fill(0xff);
            assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }));
        }
        for byte in [0, 0xff] {
            let mut action = primary_action(index);
            action[128..160].fill(byte);
            assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }));
        }
        let mut action = primary_action(index);
        action[64..96].fill(0xff); // rk is not part of this subrelation
        assert_eq!(recover_orchard_coinbase_action(&action), Ok(expected));
    }
}

#[test]
fn authenticated_outgoing_plaintext_requires_canonical_nonidentity_pkd_and_nonzero_esk() {
    let original = primary_action(0);
    let key = ock(&original);
    let original_plaintext = decrypt::<64>(&key, &original[740..]);
    for (range, byte) in [(0..32, 0), (0..32, 0xff), (32..64, 0), (32..64, 0xff)] {
        let mut action = original;
        let mut plaintext = original_plaintext;
        plaintext[range].fill(byte);
        encrypt(&key, &plaintext, &mut action[740..]);
        assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }));
    }
}

#[test]
fn authenticated_note_plaintext_requires_original_lead_diversifier_value_and_rseed() {
    let original = primary_action(0);
    let outgoing = decrypt::<64>(&ock(&original), &original[740..]);
    let key = note_key(&original, &outgoing);
    let plaintext = decrypt::<564>(&key, &original[160..740]);
    for offset in [0, 1, 12, 20] {
        let mut action = original;
        let mut changed = plaintext;
        changed[offset] ^= 1;
        encrypt(&key, &changed, &mut action[160..740]);
        assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }), "plaintext offset {offset}");
    }
    // Memo contents are unrestricted, but all 512 bytes must authenticate.
    let mut action = original;
    let mut changed = plaintext;
    changed[52..].fill(0xff);
    encrypt(&key, &changed, &mut action[160..740]);
    assert_eq!(recover_orchard_coinbase_action(&action), Ok(EXPECTED[0]));
}

#[test]
fn authenticated_ciphertexts_still_require_actual_cmx_and_exact_derived_epk() {
    let original = primary_action(0);
    let outgoing = decrypt::<64>(&ock(&original), &original[740..]);
    let plaintext = decrypt::<564>(&note_key(&original, &outgoing), &original[160..740]);
    let other = primary_action(1);
    for range in [96..128, 128..160] {
        let mut action = original;
        action[range.clone()].copy_from_slice(&other[range]);
        // Reauthenticate both ciphertexts against the changed public fields.
        // Failure must be the note/EPK consistency checks, not an AEAD tag.
        encrypt(&note_key(&action, &outgoing), &plaintext, &mut action[160..740]);
        encrypt(&ock(&action), &outgoing, &mut action[740..]);
        assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }));
    }
}

#[test]
fn authenticated_changed_esk_must_match_rseed_even_with_matching_epk_and_note_ciphertext() {
    let original = primary_action(0);
    let note = recovered_note(&original);
    let mut outgoing = decrypt::<64>(&ock(&original), &original[740..]);
    let other = primary_action(1);
    outgoing[32..].copy_from_slice(&decrypt::<64>(&ock(&other), &other[740..])[32..]);
    let esk = OrchardDomain::extract_esk(&OutPlaintextBytes(outgoing)).unwrap();
    let epk = OrchardDomain::epk_bytes(&OrchardDomain::ka_derive_public(&note, &esk));
    let mut action = original;
    action[128..160].copy_from_slice(&epk.0);
    let plaintext = OrchardDomain::note_plaintext_bytes(&note, &[0; 512]);
    encrypt(&note_key(&action, &outgoing), &plaintext.0, &mut action[160..740]);
    encrypt(&ock(&action), &outgoing, &mut action[740..]);
    assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }));
}

#[test]
fn actual_nullifier_context_including_zero_and_dummy_note_is_required() {
    let original = primary_action(0);
    let note = recovered_note(&original);
    let rho = Rho::from_bytes(&[0; 32]).unwrap();
    let dummy = Note::from_parts(
        note.recipient(), NoteValue::ZERO, rho,
        RandomSeed::from_bytes(*note.rseed().as_bytes(), &rho).unwrap(), NoteVersion::V2,
    ).unwrap();
    let mut action = original;
    action[32..64].fill(0);
    encrypt_note(&mut action, dummy, [0; 32]);
    assert_eq!(recover_orchard_coinbase_action(&action), Ok(0));
    let valid_dummy = action;
    action[32] = 1;
    assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }));
    action = original;
    action[32..64].fill(0); // cannot substitute zero for the actual nf/rho
    assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }));
    for flags in [1, 2, 3] {
        let mut corrupted = valid_dummy;
        corrupted[819] ^= 1;
        let bytes = ciphertext_only_transaction(&[original, valid_dummy, corrupted], flags);
        assert_eq!(RawV5::parse_exact(&bytes).unwrap().orchard().unwrap().verify_coinbase_outputs(), Err(RawV5Error::CoinbaseRecovery { index: 2 }));
    }
}

#[test]
fn nonzero_ovk_encryption_is_not_a_zero_ovk_coinbase_output() {
    let mut action = primary_action(0);
    let note = recovered_note(&action);
    encrypt_note(&mut action, note, [1; 32]);
    assert_eq!(recover_orchard_coinbase_action(&action), Err(RawV5Error::CoinbaseRecovery { index: 0 }));
}

#[test]
fn all_action_loop_checks_late_actions_without_filtering_disabled_outputs() {
    let mut actions: Vec<_> = (0..10).map(primary_action).collect();
    for flags in [1, 2, 3] {
        let bytes = ciphertext_only_transaction(&actions, flags);
        let raw = RawV5::parse_exact(&bytes).unwrap();
        assert_eq!(raw.orchard().unwrap().verify_coinbase_outputs(), Ok(()));
        assert!(raw.orchard().unwrap().proof().is_empty(), "not a production proof fixture");
    }
    actions[9][819] ^= 1;
    for flags in [1, 2, 3] {
        let bytes = ciphertext_only_transaction(&actions, flags);
        let error = RawV5::parse_exact(&bytes).unwrap().orchard().unwrap().verify_coinbase_outputs().unwrap_err();
        assert_eq!(error, RawV5Error::CoinbaseRecovery { index: 9 });
        assert_eq!(error.to_string(), "Orchard action 9 coinbase output recovery failed");
    }
}
