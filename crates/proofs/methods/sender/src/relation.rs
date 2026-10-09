//! Sender-ciphertext subrelation only: no source validity, ownership, net payment or allocation.
//! Host reference and SP1 guest compile this exact source. Privacy requires an unpredictable
//! caller-generated CSPRNG blind; rejecting zero detects a missing blind, not weak entropy.

use core::fmt;
use orchard::{
    Address, Note,
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
    value::NoteValue,
};
use sha2::{Digest, Sha256};
use zcash_note_encryption::Domain;

pub const JOURNAL_DOMAIN: &[u8] = b"ziquid.sender.v1";
pub const OUTPUT_DOMAIN: &[u8] = b"ziquid.sender.output.v1";
pub const JOURNAL_LEN: usize = JOURNAL_DOMAIN.len() + 64;
pub const PRIVATE_INPUT_LEN: usize = 1_367;

/// Private, caller-owned opening. Never serialize to logs or export with a proof.
/// All fields have fixed widths; value is little-endian in the witness and commitment.
#[derive(Clone)]
pub struct SenderWitness {
    pub context_digest: [u8; 32],
    pub output_commitment: [u8; 32],
    pub secret_blind: [u8; 32],
    pub recipient: [u8; 43],
    pub value: u64,
    pub rho: [u8; 32],
    pub rseed: [u8; 32],
    pub memo: [u8; 512],
    pub cmx: [u8; 32],
    pub epk: [u8; 32],
    pub enc_ciphertext: [u8; 580],
}

impl fmt::Debug for SenderWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SenderWitness([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderRelationError {
    Encoding,
    Blind,
    Recipient,
    Rho,
    RandomSeed,
    Note,
    NoteCommitment,
    EphemeralKey,
    Ciphertext,
    OutputCommitment,
}

impl fmt::Display for SenderRelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sender relation rejected: {self:?}")
    }
}

impl std::error::Error for SenderRelationError {}

impl SenderWitness {
    /// One SP1 private input buffer, with no bincode or variable-width fields.
    #[cfg(not(target_os = "zkvm"))]
    pub fn encode_private(&self) -> [u8; PRIVATE_INPUT_LEN] {
        let value = self.value.to_le_bytes();
        let mut encoded = [0; PRIVATE_INPUT_LEN];
        let mut offset = 0;
        for field in [
            self.context_digest.as_slice(),
            self.output_commitment.as_slice(),
            self.secret_blind.as_slice(),
            self.recipient.as_slice(),
            value.as_slice(),
            self.rho.as_slice(),
            self.rseed.as_slice(),
            self.memo.as_slice(),
            self.cmx.as_slice(),
            self.epk.as_slice(),
            self.enc_ciphertext.as_slice(),
        ] {
            encoded[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        encoded
    }

    pub fn decode_private(encoded: &[u8]) -> Result<Self, SenderRelationError> {
        if encoded.len() != PRIVATE_INPUT_LEN {
            return Err(SenderRelationError::Encoding);
        }
        fn take<const N: usize>(encoded: &[u8], offset: &mut usize) -> [u8; N] {
            let field = encoded[*offset..*offset + N]
                .try_into()
                .expect("checked witness length");
            *offset += N;
            field
        }
        let mut offset = 0;
        Ok(Self {
            context_digest: take(encoded, &mut offset),
            output_commitment: take(encoded, &mut offset),
            secret_blind: take(encoded, &mut offset),
            recipient: take(encoded, &mut offset),
            value: u64::from_le_bytes(take(encoded, &mut offset)),
            rho: take(encoded, &mut offset),
            rseed: take(encoded, &mut offset),
            memo: take(encoded, &mut offset),
            cmx: take(encoded, &mut offset),
            epk: take(encoded, &mut offset),
            enc_ciphertext: take(encoded, &mut offset),
        })
    }
}

/// Binding hash only, NOT validation or a verified payment fact. The secret blind and
/// note opening prevent a public source-output dictionary attack when kept unpredictable.
pub fn derive_output_commitment(witness: &SenderWitness) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(OUTPUT_DOMAIN);
    hash.update(witness.context_digest);
    hash.update(witness.secret_blind);
    hash.update(witness.recipient);
    hash.update(witness.value.to_le_bytes());
    hash.update(witness.rho);
    hash.update(witness.rseed);
    hash.update(witness.memo);
    hash.update(witness.cmx);
    hash.update(witness.epk);
    hash.update(witness.enc_ciphertext);
    hash.finalize().into()
}

/// Proves a V3 note commitment/ephemeral key and ALL recipient ciphertext bytes,
/// including the memo and AEAD tag, match deterministic sender encryption. It does
/// not prove this output occurred in a source transaction or belongs to a quoted account.
pub fn verify_sender(witness: &SenderWitness) -> Result<[u8; JOURNAL_LEN], SenderRelationError> {
    if witness.secret_blind == [0; 32] {
        return Err(SenderRelationError::Blind);
    }
    let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&witness.recipient))
        .ok_or(SenderRelationError::Recipient)?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&witness.rho)).ok_or(SenderRelationError::Rho)?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(witness.rseed, &rho))
        .ok_or(SenderRelationError::RandomSeed)?;
    let note = Option::<Note>::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(witness.value),
        rho,
        rseed,
        NoteVersion::V3,
    ))
    .ok_or(SenderRelationError::Note)?;
    if ExtractedNoteCommitment::from(note.commitment()).to_bytes() != witness.cmx {
        return Err(SenderRelationError::NoteCommitment);
    }
    let encryption = IronwoodNoteEncryption::new(None, note, witness.memo);
    if IronwoodDomain::epk_bytes(encryption.epk()).0 != witness.epk {
        return Err(SenderRelationError::EphemeralKey);
    }
    if encryption.encrypt_note_plaintext() != witness.enc_ciphertext {
        return Err(SenderRelationError::Ciphertext);
    }
    let commitment = derive_output_commitment(witness);
    if commitment != witness.output_commitment {
        return Err(SenderRelationError::OutputCommitment);
    }
    let mut journal = [0; JOURNAL_LEN];
    journal[..JOURNAL_DOMAIN.len()].copy_from_slice(JOURNAL_DOMAIN);
    journal[JOURNAL_DOMAIN.len()..JOURNAL_DOMAIN.len() + 32]
        .copy_from_slice(&witness.context_digest);
    journal[JOURNAL_DOMAIN.len() + 32..].copy_from_slice(&commitment);
    Ok(journal)
}
