//! Public-zero-OVK Sapling and Ironwood coinbase recovery through finite NU6.3.
//!
//! Heartwood preserves the maintained historical replay predicate in zcashd
//! 3.1 (65f0a4736acd9adeb91f11899bcee3439068c771, Note.cpp:362–406), including
//! its ungated June 25, 2020 esk-to-epk tightening. Canopy requires ZIP212
//! plaintext and seed-derived rcm/esk immediately, without wallet grace.
//! NU5 enables canonical ZIP216 pk_d decoding at height 1842420. Historical
//! prime-order identity is allowed until 2121199; the original Rust recovery
//! switch at 2121200 rejects identity and recovered values above MAX_MONEY.
//! Neither restriction is backported to earlier history.
//!
//! Recovery authenticates ciphertexts and the note commitment, NOT Groth16,
//! binding signatures, coinbase context, rewards, value balance or a block.
//! Consumers must separately verify all of those before ledger admission.

use std::fmt;

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag, aead::AeadInPlace};
use group::GroupEncoding;
use sapling_crypto::{
    Diversifier,
    bundle::{GrothProofBytes, OutputDescription},
    keys::OutgoingViewingKey,
    note::{ExtractedNoteCommitment, NoteCommitment},
    note_encryption::{KDF_SAPLING_PERSONALIZATION, prf_ock},
    value::NoteValue,
};
use zcash_protocol::{consensus::{BlockHeight, BranchId, TEST_NETWORK}, value::MAX_MONEY};
use zcash_spec::PrfExpand;

/// Fixed, redacted failure categories; never retain decrypted bytes or scalars.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoinbaseRecoveryError {
    UnsupportedEra,
    OutgoingAuthentication,
    InvalidTransmissionKey,
    InvalidEphemeralSecret,
    EphemeralSecretMismatch,
    NoteAuthentication,
    InvalidPlaintextVersion,
    InvalidDiversifier,
    InvalidCommitmentRandomness,
    RecoveredValueOutOfRange,
    EphemeralKeyMismatch,
    CommitmentMismatch,
    IronwoodOutputRecovery,
}

impl fmt::Display for CoinbaseRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedEra => "unsupported coinbase recovery era",
            Self::OutgoingAuthentication => "Sapling outgoing ciphertext authentication failed",
            Self::InvalidTransmissionKey => "invalid Sapling transmission key",
            Self::InvalidEphemeralSecret => "invalid Sapling ephemeral secret scalar",
            Self::EphemeralSecretMismatch => "Sapling recovered ephemeral secret mismatch",
            Self::NoteAuthentication => "Sapling note ciphertext authentication failed",
            Self::InvalidPlaintextVersion => "invalid Sapling note plaintext version",
            Self::InvalidDiversifier => "invalid Sapling note diversifier",
            Self::InvalidCommitmentRandomness => "invalid Sapling note commitment scalar",
            Self::RecoveredValueOutOfRange => "Sapling recovered value is outside the monetary range",
            Self::EphemeralKeyMismatch => "Sapling recovered ephemeral key mismatch",
            Self::CommitmentMismatch => "Sapling recovered note commitment mismatch",
            Self::IronwoodOutputRecovery => "Ironwood output recovery failed",
        })
    }
}

impl std::error::Error for CoinbaseRecoveryError {}

/// Recovers the commitment-bound value of an actual Sapling output using
/// public zero OVK and the candidate block's height-derived testnet branch.
/// Heartwood through finite NU6.3 are supported; NU7 and later fail closed.
/// This does not validate the output proof or admit a coinbase.
pub fn recover_sapling_coinbase_output(
    output: &OutputDescription<GrothProofBytes>,
    height: u32,
) -> Result<u64, CoinbaseRecoveryError> {
    if height >= 4_465_026 { return Err(CoinbaseRecoveryError::UnsupportedEra); }
    let branch = BranchId::for_height(&TEST_NETWORK, BlockHeight::from_u32(height));
    let plaintext_version = match branch {
        BranchId::Heartwood => 1,
        BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3 => 2,
        _ => return Err(CoinbaseRecoveryError::UnsupportedEra),
    };
    // PRF^ock: BLAKE2b-256, Zcash_Derive_ock, zero OVK | cv | cmu | raw epk.
    // cv and cmu have canonical typed encodings; epk must remain the original
    // transmitted bytes in both derivations, including its original sign bit.
    let ock = prf_ock(
        &OutgoingViewingKey([0; 32]), output.cv(), &output.cmu().to_bytes(),
        output.ephemeral_key(),
    );
    let nonce = Nonce::from_slice(&[0; 12]);
    let mut outgoing = [0; 64];
    outgoing.copy_from_slice(&output.out_ciphertext()[..64]);
    ChaCha20Poly1305::new(Key::from_slice(&ock.0))
        .decrypt_in_place_detached(nonce, &[], &mut outgoing, Tag::from_slice(&output.out_ciphertext()[64..]))
        .map_err(|_| CoinbaseRecoveryError::OutgoingAuthentication)?;

    let mut pk_d_bytes = [0; 32];
    pk_d_bytes.copy_from_slice(&outgoing[..32]);
    let pk_d = Option::<jubjub::AffinePoint>::from(if matches!(branch, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3) {
        jubjub::AffinePoint::from_bytes(pk_d_bytes)
    } else {
        jubjub::AffinePoint::from_bytes_pre_zip216_compatibility(pk_d_bytes)
    }).ok_or(CoinbaseRecoveryError::InvalidTransmissionKey)?;
    // Original zcashd 5.0.0 ZIP216 decoding retained prime-order identity.
    // PR6459 (6ebf01fa831c02c18d6c2cf76c15b0cd2a1fe978) switched both networks
    // to Rust recovery at this same numeric height, including nonidentity.
    if !bool::from(pk_d.is_torsion_free())
        || (height >= 2_121_200 && pk_d == jubjub::AffinePoint::identity()) {
        return Err(CoinbaseRecoveryError::InvalidTransmissionKey);
    }
    let mut esk_bytes = [0; 32];
    esk_bytes.copy_from_slice(&outgoing[32..]);
    let esk = Option::<jubjub::Fr>::from(jubjub::Fr::from_bytes(&esk_bytes))
        .ok_or(CoinbaseRecoveryError::InvalidEphemeralSecret)?;

    let shared = (jubjub::ExtendedPoint::from(pk_d) * esk).mul_by_cofactor();
    let key = blake2b_simd::Params::new().hash_length(32)
        .personal(KDF_SAPLING_PERSONALIZATION).to_state()
        .update(&shared.to_bytes()).update(&output.ephemeral_key().0).finalize();
    let mut note = [0; 564];
    note.copy_from_slice(&output.enc_ciphertext()[..564]);
    ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()))
        .decrypt_in_place_detached(nonce, &[], &mut note, Tag::from_slice(&output.enc_ciphertext()[564..]))
        .map_err(|_| CoinbaseRecoveryError::NoteAuthentication)?;

    if note[0] != plaintext_version {
        return Err(CoinbaseRecoveryError::InvalidPlaintextVersion);
    }
    let mut diversifier = [0; 11];
    diversifier.copy_from_slice(&note[1..12]);
    let g_d = Diversifier(diversifier).g_d().ok_or(CoinbaseRecoveryError::InvalidDiversifier)?;
    let mut value_bytes = [0; 8];
    value_bytes.copy_from_slice(&note[12..20]);
    let value = u64::from_le_bytes(value_bytes);
    // Original primitives 0.10.2 recovered through Amount::from_u64_le_bytes;
    // maintained NoteValue::from_raw alone omits that predicate. Old C++
    // recovery accepted raw u64, so this bound begins only at its Rust switch.
    if height >= 2_121_200 && value > MAX_MONEY {
        return Err(CoinbaseRecoveryError::RecoveredValueOutOfRange);
    }
    let mut randomness = [0; 32];
    randomness.copy_from_slice(&note[20..52]);
    let rcm = match branch {
        BranchId::Heartwood => Option::<jubjub::Fr>::from(jubjub::Fr::from_bytes(&randomness))
            .ok_or(CoinbaseRecoveryError::InvalidCommitmentRandomness)?,
        BranchId::Canopy | BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2 | BranchId::Nu6_3 => {
            // Maintained ZIP212 PRF^expand domains 04/05, Zcash_ExpandSeed.
            // Unlike the outgoing esk, the rseed is arbitrary 32-byte data.
            let derived_esk = jubjub::Fr::from_bytes_wide(&PrfExpand::SAPLING_ESK.with(&randomness));
            if esk != derived_esk {
                return Err(CoinbaseRecoveryError::EphemeralSecretMismatch);
            }
            jubjub::Fr::from_bytes_wide(&PrfExpand::SAPLING_RCM.with(&randomness))
        }
        _ => return Err(CoinbaseRecoveryError::UnsupportedEra),
    };
    // All 512 memo bytes were authenticated; their contents add no predicate.

    if (g_d * esk).to_bytes() != output.ephemeral_key().0 {
        return Err(CoinbaseRecoveryError::EphemeralKeyMismatch);
    }
    let cmu: ExtractedNoteCommitment = NoteCommitment::temporary_zcashd_derive(
        g_d.to_bytes(), pk_d.to_bytes(), NoteValue::from_raw(value), rcm,
    ).into();
    if cmu != *output.cmu() {
        return Err(CoinbaseRecoveryError::CommitmentMismatch);
    }
    Ok(value)
}

/// Recovers one actual Ironwood output under the finite testnet NU6.3 domain.
/// The maintained decoder enforces lead03, all note fields in ZIP2005 rcm,
/// derived esk/EPK, both AEAD tags and the extracted commitment. Recovery is
/// not proof/signature verification, pool balance, coinbase reward or history.
pub fn recover_ironwood_coinbase_output<T>(action: &orchard::Action<T>, height: u32) -> Result<u64, CoinbaseRecoveryError> {
    if !(4_134_000..4_465_026).contains(&height) {
        return Err(CoinbaseRecoveryError::UnsupportedEra);
    }
    let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
    let (note, _, _) = zcash_note_encryption::try_output_recovery_with_ovk(
        &domain, &orchard::keys::OutgoingViewingKey::from([0; 32]), action,
        action.cv_net(), &action.encrypted_note().out_ciphertext,
    ).ok_or(CoinbaseRecoveryError::IronwoodOutputRecovery)?;
    let value = note.value().inner();
    if value > MAX_MONEY { return Err(CoinbaseRecoveryError::RecoveredValueOutOfRange); }
    Ok(value)
}
