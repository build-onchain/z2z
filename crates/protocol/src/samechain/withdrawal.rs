//! Canonical ordinary-note withdrawal descriptions, without order metadata.
//!
//! Shape validation, terms digests and journals authenticate no owner, root,
//! spentness, backing or transfer. The owner relation must open the terms and
//! verify the private note, membership, exact consent and conservation.

use super::{
    CanonicalFrame, Deployment, HashWriter, OutputDescriptor, Reader, Role,
    SamechainError, RELATION_VERSION, check_frame_size, decode_frame, digest_frame,
    digest_validated_frame, encode_frame, encoding_error, is_zero, outputs_len,
    read_outputs, validate_outputs, write_header, write_outputs,
};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

/// One ordinary note's public identity, not a certificate of ownership or
/// accepted membership. Tree zero and index zero are valid positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteInputDescriptor {
    pub commitment: [u8; 32],
    pub root: [u8; 32],
    pub tree_id: u32,
    pub index: u32,
    pub nullifier: [u8; 32],
    pub owner_key: [u8; 32],
}

/// Exact output manifest with fixed Role A descriptors and a positive exit.
/// Asset conservation, current expiry and actual withdrawal remain unverified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteWithdrawalPacket {
    pub deployment: Deployment,
    pub input: NoteInputDescriptor,
    pub outputs: Vec<OutputDescriptor>,
    pub expiry: u64,
    pub terms_commitment: [u8; 32],
}

/// Descriptive statement bytes only, not an authorizing or verified fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteWithdrawalJournal {
    pub relation_version: u16,
    pub deployment_digest: [u8; 32],
    pub terms_commitment: [u8; 32],
    pub packet_digest: [u8; 32],
    pub input_commitment: [u8; 32],
    pub input_nullifier: [u8; 32],
    pub root: [u8; 32],
    pub tree_id: u32,
    pub index: u32,
}

impl NoteInputDescriptor {
    pub fn validate(&self) -> Result<(), SamechainError> {
        if is_zero(&self.commitment) || is_zero(&self.root)
            || is_zero(&self.nullifier) || is_zero(&self.owner_key)
        {
            return Err(SamechainError::InvalidInput);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }

    fn body_len(&self) -> usize { 32 + 32 + 4 + 4 + 32 + 32 }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&self.commitment)?;
        out.write_all(&self.root)?;
        out.write_all(&self.tree_id.to_be_bytes())?;
        out.write_all(&self.index.to_be_bytes())?;
        out.write_all(&self.nullifier)?;
        out.write_all(&self.owner_key)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self {
            commitment: reader.array()?, root: reader.array()?, tree_id: reader.u32()?,
            index: reader.u32()?, nullifier: reader.array()?, owner_key: reader.array()?,
        })
    }
}

impl NoteWithdrawalPacket {
    pub fn validate(&self) -> Result<(), SamechainError> {
        validate_body(&self.deployment, &self.input, &self.outputs, self.expiry)?;
        if is_zero(&self.terms_commitment) { return Err(SamechainError::InvalidTerms); }
        check_frame_size(self)?;
        Ok(())
    }

    pub fn validate_commitment(&self, blind: &[u8; 32]) -> Result<(), SamechainError> {
        self.validate()?;
        if self.terms_commitment != note_withdrawal_terms_commitment(
            &self.deployment, &self.input, &self.outputs, self.expiry, blind,
        )? {
            return Err(SamechainError::OpeningMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }

    fn body_len(&self) -> usize {
        self.deployment.body_len() + self.input.body_len() + outputs_len(&self.outputs) + 8 + 32
    }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        write_body(out, &self.deployment, &self.input, &self.outputs, self.expiry)?;
        out.write_all(&self.terms_commitment)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self {
            deployment: Deployment::read_body(reader)?, input: NoteInputDescriptor::read_body(reader)?,
            outputs: read_outputs(reader)?, expiry: reader.u64()?, terms_commitment: reader.array()?,
        })
    }
}

/// Salted exact withdrawal terms, excluding the commitment field itself.
/// Uses the packet's body writer directly, not a second serialization path.
pub fn note_withdrawal_terms_commitment(
    deployment: &Deployment, input: &NoteInputDescriptor,
    outputs: &[OutputDescriptor], expiry: u64, blind: &[u8; 32],
) -> Result<[u8; 32], SamechainError> {
    validate_body(deployment, input, outputs, expiry)?;
    if is_zero(blind) { return Err(SamechainError::InvalidBlind); }
    let mut hash = HashWriter(Sha256::new());
    write_header(&mut hash, b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_TERMS_COMMITMENT\0")
        .map_err(encoding_error)?;
    hash.write_all(blind).map_err(encoding_error)?;
    write_body(&mut hash, deployment, input, outputs, expiry).map_err(encoding_error)?;
    Ok(hash.0.finalize().into())
}

fn validate_body(
    deployment: &Deployment, input: &NoteInputDescriptor,
    outputs: &[OutputDescriptor], expiry: u64,
) -> Result<(), SamechainError> {
    deployment.validate()?;
    input.validate()?;
    validate_outputs(outputs)?;
    for output in outputs {
        if output.role() != Role::A { return Err(SamechainError::InvalidRole); }
        if let OutputDescriptor::Note { commitment, .. } = output
            && *commitment == input.commitment
        {
            return Err(SamechainError::DuplicateOutput);
        }
    }
    // Output validation already rejects zero-valued exits.
    if !outputs.iter().any(|output| matches!(output, OutputDescriptor::Exit { .. })) {
        return Err(SamechainError::InvalidOutput);
    }
    if expiry == 0 { return Err(SamechainError::InvalidTerms); }
    // At most eight bounded outputs total below 64 KiB, including frame/terms.
    Ok(())
}

fn write_body(
    out: &mut impl Write, deployment: &Deployment, input: &NoteInputDescriptor,
    outputs: &[OutputDescriptor], expiry: u64,
) -> io::Result<()> {
    deployment.write_body(out)?;
    input.write_body(out)?;
    write_outputs(out, outputs)?;
    out.write_all(&expiry.to_be_bytes())
}

impl NoteWithdrawalJournal {
    pub fn validate(&self) -> Result<(), SamechainError> {
        if self.relation_version != RELATION_VERSION { return Err(SamechainError::UnsupportedSchema); }
        if is_zero(&self.deployment_digest) || is_zero(&self.terms_commitment)
            || is_zero(&self.packet_digest) || is_zero(&self.input_commitment)
            || is_zero(&self.input_nullifier) || is_zero(&self.root)
        {
            return Err(SamechainError::InvalidJournal);
        }
        Ok(())
    }

    /// Describes the complete packet without opening terms or verifying proof,
    /// ownership, accepted membership, current spentness, backing or transfers.
    pub fn from_packet(packet: &NoteWithdrawalPacket) -> Result<Self, SamechainError> {
        packet.validate()?;
        Ok(Self {
            relation_version: RELATION_VERSION,
            deployment_digest: digest_validated_frame(&packet.deployment)?,
            terms_commitment: packet.terms_commitment,
            packet_digest: digest_validated_frame(packet)?,
            input_commitment: packet.input.commitment,
            input_nullifier: packet.input.nullifier,
            root: packet.input.root, tree_id: packet.input.tree_id, index: packet.input.index,
        })
    }

    pub fn digest(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }

    fn body_len(&self) -> usize { 2 + 32 * 6 + 4 + 4 }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&self.relation_version.to_be_bytes())?;
        out.write_all(&self.deployment_digest)?;
        out.write_all(&self.terms_commitment)?;
        out.write_all(&self.packet_digest)?;
        out.write_all(&self.input_commitment)?;
        out.write_all(&self.input_nullifier)?;
        out.write_all(&self.root)?;
        out.write_all(&self.tree_id.to_be_bytes())?;
        out.write_all(&self.index.to_be_bytes())
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self {
            relation_version: reader.u16()?, deployment_digest: reader.array()?,
            terms_commitment: reader.array()?, packet_digest: reader.array()?,
            input_commitment: reader.array()?, input_nullifier: reader.array()?, root: reader.array()?,
            tree_id: reader.u32()?, index: reader.u32()?,
        })
    }
}

/// Checks exact descriptive binding only; never promotes a journal into proof
/// validity, accepted membership, asset permission or completed withdrawal.
pub fn validate_note_withdrawal(
    packet: &NoteWithdrawalPacket, journal: &NoteWithdrawalJournal,
) -> Result<(), SamechainError> {
    journal.validate()?;
    if *journal != NoteWithdrawalJournal::from_packet(packet)? {
        return Err(SamechainError::JournalMismatch);
    }
    Ok(())
}

frame_codec!(NoteInputDescriptor, b"Z2Z_SAMECHAIN_NOTE_INPUT\0");
frame_codec!(NoteWithdrawalPacket, b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_PACKET\0");
frame_codec!(NoteWithdrawalJournal, b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_JOURNAL\0");
