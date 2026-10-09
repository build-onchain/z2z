//! Canonical public note-creation terms and descriptive mint-comparison bytes.
//!
//! Shape checks and journals verify no note opening, owner consent, asset receipt,
//! admitted root, nonce/order uniqueness, proof certificate or financial permission.
//! Initial orders expose only identity; their policy and generation belong to the
//! private creation relation. Owner public keys retain the finite candidate's GD2 hold.

use super::{
    Asset, CanonicalFrame, Deployment, HashWriter, OutputDescriptor, Reader, Role,
    SamechainError, RELATION_VERSION, check_frame_size, decode_frame, digest_frame,
    digest_validated_frame, encode_frame, encoding_error, is_zero, write_atoms,
    write_header,
};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

/// Optional initial order identity, not a hidden policy or current backing claim.
/// The private relation authenticates generation one; it is not caller-selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialOrder {
    pub id: [u8; 32],
}

/// Exact public deposit proposal. Actual payer authentication, receipt, expiry and
/// creation/order replay checks remain target-owned; no root is admitted here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteCreationPacket {
    pub deployment: Deployment,
    pub token: [u8; 20],
    pub payer: [u8; 20],
    pub creation_nonce: [u8; 32],
    pub owner_key: [u8; 32],
    pub role: Role,
    pub asset: Asset,
    pub amount: primitive_types::U256,
    pub order: Option<InitialOrder>,
    pub output: OutputDescriptor,
    pub expiry: u64,
    pub terms_commitment: [u8; 32],
}

/// Descriptive comparison fields for an eventual target receipt/mint predicate.
/// Complete recovery bytes and output version bind through the packet digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteCreationJournal {
    pub relation_version: u16,
    pub deployment_digest: [u8; 32],
    pub packet_digest: [u8; 32],
    pub terms_commitment: [u8; 32],
    pub creation_nonce: [u8; 32],
    pub payer: [u8; 20],
    pub owner_key: [u8; 32],
    pub token: [u8; 20],
    pub role: Role,
    pub asset: Asset,
    pub amount: primitive_types::U256,
    pub order: Option<InitialOrder>,
    pub note_commitment: [u8; 32],
}

impl InitialOrder {
    fn valid(&self) -> bool { !is_zero(&self.id) }
}

fn order_len(order: Option<InitialOrder>) -> usize {
    1 + if order.is_some() { 32 } else { 0 }
}

fn write_order(out: &mut impl Write, order: Option<InitialOrder>) -> io::Result<()> {
    match order {
        None => out.write_all(&[0]),
        Some(order) => { out.write_all(&[1])?; out.write_all(&order.id) }
    }
}

fn read_order(reader: &mut Reader<'_>) -> Result<Option<InitialOrder>, SamechainError> {
    match reader.byte()? {
        0 => Ok(None),
        1 => Ok(Some(InitialOrder { id: reader.array()? })),
        _ => Err(SamechainError::NonCanonical),
    }
}

fn validate_asset(token: &[u8; 20], asset: Asset) -> Result<(), SamechainError> {
    if is_zero(token) || matches!(asset, Asset::Token(address) if address != *token) {
        return Err(SamechainError::InvalidAsset);
    }
    Ok(())
}

impl NoteCreationPacket {
    fn validate_terms(&self) -> Result<(), SamechainError> {
        self.deployment.validate()?;
        validate_asset(&self.token, self.asset)?;
        if is_zero(&self.payer) || is_zero(&self.creation_nonce) || is_zero(&self.owner_key)
            || self.amount.is_zero() || self.expiry == 0
            || self.order.is_some_and(|order| !order.valid())
        {
            return Err(SamechainError::InvalidTerms);
        }
        self.output.validate()?;
        if !matches!(self.output, OutputDescriptor::Note { .. }) {
            return Err(SamechainError::InvalidOutput);
        }
        if self.output.role() != self.role { return Err(SamechainError::InvalidRole); }
        check_frame_size(self)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SamechainError> {
        self.validate_terms()?;
        if is_zero(&self.terms_commitment) { return Err(SamechainError::InvalidTerms); }
        Ok(())
    }

    /// Salted exact terms preimage, excluding this packet's commitment field.
    /// A zero placeholder is permitted here only; the complete packet rejects it.
    pub fn terms_commitment_for(&self, blind: &[u8; 32]) -> Result<[u8; 32], SamechainError> {
        self.validate_terms()?;
        self.hash_terms(blind)
    }

    fn hash_terms(&self, blind: &[u8; 32]) -> Result<[u8; 32], SamechainError> {
        if is_zero(blind) { return Err(SamechainError::InvalidBlind); }
        let mut hash = HashWriter(Sha256::new());
        write_header(&mut hash, b"Z2Z_SAMECHAIN_NOTE_CREATION_TERMS_COMMITMENT\0")
            .map_err(encoding_error)?;
        hash.write_all(blind).map_err(encoding_error)?;
        self.write_terms(&mut hash).map_err(encoding_error)?;
        Ok(hash.0.finalize().into())
    }

    pub fn validate_commitment(&self, blind: &[u8; 32]) -> Result<(), SamechainError> {
        self.validate()?;
        if self.terms_commitment != self.hash_terms(blind)? {
            return Err(SamechainError::OpeningMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }

    fn body_len(&self) -> usize {
        self.deployment.body_len() + 20 + 20 + 32 + 32 + 1 + self.asset.body_len()
            + 32 + order_len(self.order) + self.output.body_len() + 8 + 32
    }

    // One borrowed body writer feeds the canonical packet and streaming preimage.
    fn write_terms(&self, out: &mut impl Write) -> io::Result<()> {
        self.deployment.write_body(out)?;
        out.write_all(&self.token)?;
        out.write_all(&self.payer)?;
        out.write_all(&self.creation_nonce)?;
        out.write_all(&self.owner_key)?;
        out.write_all(&[self.role as u8])?;
        self.asset.write_body(out)?;
        write_atoms(out, self.amount)?;
        write_order(out, self.order)?;
        self.output.write_body(out)?;
        out.write_all(&self.expiry.to_be_bytes())
    }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        self.write_terms(out)?;
        out.write_all(&self.terms_commitment)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self {
            deployment: Deployment::read_body(reader)?, token: reader.array()?,
            payer: reader.array()?, creation_nonce: reader.array()?, owner_key: reader.array()?,
            role: Role::read(reader)?, asset: Asset::read_body(reader)?, amount: reader.atoms()?,
            order: read_order(reader)?, output: OutputDescriptor::read_body(reader)?,
            expiry: reader.u64()?, terms_commitment: reader.array()?,
        })
    }
}

impl NoteCreationJournal {
    pub fn validate(&self) -> Result<(), SamechainError> {
        if self.relation_version != RELATION_VERSION { return Err(SamechainError::UnsupportedSchema); }
        if is_zero(&self.deployment_digest) || is_zero(&self.packet_digest)
            || is_zero(&self.terms_commitment) || is_zero(&self.creation_nonce)
            || is_zero(&self.payer) || is_zero(&self.owner_key) || is_zero(&self.token)
            || self.amount.is_zero() || is_zero(&self.note_commitment)
            || self.order.is_some_and(|order| !order.valid())
        {
            return Err(SamechainError::InvalidJournal);
        }
        validate_asset(&self.token, self.asset)
    }

    /// Describes a shape-valid packet without proving note semantics, owner consent,
    /// actual receipt, admitted membership, replay eligibility or financial authority.
    pub fn from_packet(packet: &NoteCreationPacket) -> Result<Self, SamechainError> {
        packet.validate()?;
        let OutputDescriptor::Note { commitment, .. } = &packet.output else {
            return Err(SamechainError::InvalidOutput);
        };
        Ok(Self {
            relation_version: RELATION_VERSION,
            deployment_digest: digest_validated_frame(&packet.deployment)?,
            packet_digest: digest_validated_frame(packet)?, terms_commitment: packet.terms_commitment,
            creation_nonce: packet.creation_nonce, payer: packet.payer, owner_key: packet.owner_key,
            token: packet.token, role: packet.role, asset: packet.asset, amount: packet.amount,
            order: packet.order, note_commitment: *commitment,
        })
    }

    pub fn digest(&self) -> Result<[u8; 32], SamechainError> { digest_frame(self) }

    fn body_len(&self) -> usize {
        2 + 32 * 5 + 20 * 2 + 1 + self.asset.body_len() + 32 + order_len(self.order) + 32
    }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        out.write_all(&self.relation_version.to_be_bytes())?;
        out.write_all(&self.deployment_digest)?;
        out.write_all(&self.packet_digest)?;
        out.write_all(&self.terms_commitment)?;
        out.write_all(&self.creation_nonce)?;
        out.write_all(&self.payer)?;
        out.write_all(&self.owner_key)?;
        out.write_all(&self.token)?;
        out.write_all(&[self.role as u8])?;
        self.asset.write_body(out)?;
        write_atoms(out, self.amount)?;
        write_order(out, self.order)?;
        out.write_all(&self.note_commitment)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self {
            relation_version: reader.u16()?, deployment_digest: reader.array()?,
            packet_digest: reader.array()?, terms_commitment: reader.array()?,
            creation_nonce: reader.array()?, payer: reader.array()?, owner_key: reader.array()?,
            token: reader.array()?, role: Role::read(reader)?, asset: Asset::read_body(reader)?,
            amount: reader.atoms()?, order: read_order(reader)?, note_commitment: reader.array()?,
        })
    }
}

/// Exact descriptive binding only, not proof verification or permission to mint.
pub fn validate_note_creation(
    packet: &NoteCreationPacket, journal: &NoteCreationJournal,
) -> Result<(), SamechainError> {
    journal.validate()?;
    if *journal != NoteCreationJournal::from_packet(packet)? {
        return Err(SamechainError::JournalMismatch);
    }
    Ok(())
}

frame_codec!(NoteCreationPacket, b"Z2Z_SAMECHAIN_NOTE_CREATION_PACKET\0");
frame_codec!(NoteCreationJournal, b"Z2Z_SAMECHAIN_NOTE_CREATION_JOURNAL\0");
