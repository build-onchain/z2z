//! Independent owner-local leaves over one canonical shared execution.
//! These hashes establish descriptive bindings, not ownership or financial proof.

use super::{
    Asset, CanonicalFrame, HashWriter, OrderPolicy, PublicPacket, Reader, Role, SamechainError,
    check_frame_size, decode_frame, encode_frame, encoding_error, is_zero, write_atoms, write_count,
    write_frame,
};
use std::io::{self, Write};

use primitive_types::U256;
use sha2::{Digest, Sha256};

pub const FILL_RELATION_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillExecution {
    pub asset_a: Asset,
    pub asset_b: Asset,
    pub sell_a: U256,
    pub sell_b: U256,
}

impl FillExecution {
    pub fn validate(&self) -> Result<(), SamechainError> {
        self.asset_a.validate()?;
        self.asset_b.validate()?;
        if self.asset_a == self.asset_b || self.sell_a.is_zero() || self.sell_b.is_zero() {
            return Err(SamechainError::InvalidTerms);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, SamechainError> { encode_frame(self) }
    pub fn decode(bytes: &[u8]) -> Result<Self, SamechainError> { decode_frame(bytes) }

    pub fn encoded_len(&self) -> Result<usize, SamechainError> {
        self.validate()?;
        check_frame_size(self)
    }

    pub fn encode_into(&self, out: &mut impl Write) -> Result<(), SamechainError> {
        self.validate()?;
        check_frame_size(self)?;
        write_frame(self, out).map_err(encoding_error)
    }

    /// Context omits only C; a zero C is allowed during two-owner construction.
    /// Public B and execution are streamed without copying ciphertexts or policies.
    pub fn context_digest(&self, packet: &PublicPacket) -> Result<[u8; 32], SamechainError> {
        packet.validate_body()?;
        self.validate()?;
        let mut hash = HashWriter(Sha256::new());
        write_fill_header(&mut hash, b"Z2Z_SAMECHAIN_FILL_CONTEXT\0").map_err(encoding_error)?;
        hash.write_all(&packet.deployment.schema.to_be_bytes()).map_err(encoding_error)?;
        write_count(&mut hash, packet.body_without_commitment_len()).map_err(encoding_error)?;
        packet.write_body_without_commitment(&mut hash).map_err(encoding_error)?;
        self.write_body(&mut hash).map_err(encoding_error)?;
        Ok(hash.0.finalize().into())
    }

    fn body_len(&self) -> usize { self.asset_a.body_len() + self.asset_b.body_len() + 64 }

    fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
        self.asset_a.write_body(out)?;
        self.asset_b.write_body(out)?;
        write_atoms(out, self.sell_a)?;
        write_atoms(out, self.sell_b)
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> {
        Ok(Self { asset_a: Asset::read_body(reader)?, asset_b: Asset::read_body(reader)?,
            sell_a: reader.atoms()?, sell_b: reader.atoms()? })
    }
}

impl CanonicalFrame for FillExecution {
    const DOMAIN: &'static [u8] = b"Z2Z_SAMECHAIN_FILL_EXECUTION\0";
    const VERSION: u16 = FILL_RELATION_VERSION;
    fn validate_frame(&self) -> Result<(), SamechainError> { self.validate() }
    fn body_len(&self) -> usize { self.body_len() }
    fn write_body(&self, out: &mut impl Write) -> io::Result<()> { self.write_body(out) }
    fn read_body(reader: &mut Reader<'_>) -> Result<Self, SamechainError> { Self::read_body(reader) }
}

/// Opens only the caller's authenticated policy. Does not enforce note economics.
pub fn owner_leaf(packet: &PublicPacket, execution: &FillExecution, role: Role,
    policy: &OrderPolicy, own_salt: &[u8; 32]) -> Result<[u8; 32], SamechainError>
{
    let context = execution.context_digest(packet)?;
    policy.validate_for(role)?;
    let (sell, buy) = match role {
        Role::A => (execution.asset_a, execution.asset_b),
        Role::B => (execution.asset_b, execution.asset_a),
    };
    if policy.sell_asset != sell || policy.buy_asset != buy {
        return Err(SamechainError::InvalidPolicy);
    }
    if is_zero(own_salt) { return Err(SamechainError::InvalidBlind); }
    let mut hash = HashWriter(Sha256::new());
    write_fill_header(&mut hash, b"Z2Z_SAMECHAIN_FILL_OWNER_LEAF\0").map_err(encoding_error)?;
    hash.write_all(&[role as u8]).map_err(encoding_error)?;
    hash.write_all(own_salt).map_err(encoding_error)?;
    hash.write_all(&context).map_err(encoding_error)?;
    write_count(&mut hash, check_frame_size(policy)?).map_err(encoding_error)?;
    write_frame(policy, &mut hash).map_err(encoding_error)?;
    Ok(hash.0.finalize().into())
}

/// Ordered A/B leaves remain opaque to the counterparty; neither policy is needed.
pub fn aggregate_commitment(packet: &PublicPacket, execution: &FillExecution,
    leaves: &[[u8; 32]; 2]) -> Result<[u8; 32], SamechainError>
{
    let context = execution.context_digest(packet)?;
    if leaves.iter().any(|leaf| is_zero(leaf)) { return Err(SamechainError::InvalidTerms); }
    let mut hash = HashWriter(Sha256::new());
    write_fill_header(&mut hash, b"Z2Z_SAMECHAIN_FILL_AGGREGATE\0").map_err(encoding_error)?;
    hash.write_all(&context).map_err(encoding_error)?;
    for leaf in leaves { hash.write_all(leaf).map_err(encoding_error)?; }
    Ok(hash.0.finalize().into())
}

/// Accepted packets require nonzero C as well as its exact ordered opening.
pub fn validate_commitment(packet: &PublicPacket, execution: &FillExecution,
    leaves: &[[u8; 32]; 2]) -> Result<(), SamechainError>
{
    let expected = aggregate_commitment(packet, execution, leaves)?;
    if is_zero(&packet.terms_commitment) { return Err(SamechainError::InvalidTerms); }
    if packet.terms_commitment != expected {
        return Err(SamechainError::OpeningMismatch);
    }
    Ok(())
}

fn write_fill_header(out: &mut impl Write, domain: &[u8]) -> io::Result<()> {
    out.write_all(domain)?;
    out.write_all(&FILL_RELATION_VERSION.to_be_bytes())
}
