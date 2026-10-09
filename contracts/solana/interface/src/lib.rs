#![no_std]
#![forbid(unsafe_code)]
//! Exact public Solana effect encoding, not chain observations or verified funding.
use ziquid_protocol::market::{Decision, Domain, Id, Operation, ProtocolError, Transition};
use sha2::{Digest, Sha256};
pub const INSTRUCTIONS_SYSVAR_ID: Id =
    solana_pubkey::Pubkey::from_str_const("Sysvar1nstructions1111111111111111111111111").to_bytes();

pub fn pair_pda(domain: &Domain, admin: &Id) -> (Id, u8) {
    let (key, bump) = solana_pubkey::Pubkey::find_program_address(
        &[b"pair", admin, &domain.deployment, &domain.pair],
        &solana_pubkey::Pubkey::new_from_array(domain.solana_program),
    );
    (key.to_bytes(), bump)
}
pub fn epoch_pda_at(program: &Id, pair: &Id, number: u64) -> (Id, u8) {
    let (key, bump) = solana_pubkey::Pubkey::find_program_address(
        &[b"epoch", pair, &number.to_le_bytes()],
        &solana_pubkey::Pubkey::new_from_array(*program),
    );
    (key.to_bytes(), bump)
}
pub fn hold_pda_at(program: &Id, epoch: &Id, business: &Id) -> (Id, u8) {
    let (key, bump) = solana_pubkey::Pubkey::find_program_address(
        &[b"hold", epoch, business],
        &solana_pubkey::Pubkey::new_from_array(*program),
    );
    (key.to_bytes(), bump)
}
pub fn escrow_pda_at(program: &Id, hold: &Id) -> (Id, u8) {
    let (key, bump) = solana_pubkey::Pubkey::find_program_address(
        &[b"escrow", hold],
        &solana_pubkey::Pubkey::new_from_array(*program),
    );
    (key.to_bytes(), bump)
}
pub fn portion_pda_at(program: &Id, hold: &Id, business: &Id) -> (Id, u8) {
    let (key, bump) = solana_pubkey::Pubkey::find_program_address(
        &[b"portion", hold, business],
        &solana_pubkey::Pubkey::new_from_array(*program),
    );
    (key.to_bytes(), bump)
}
pub fn epoch_pda(domain: &Domain, pair: &Id) -> (Id, u8) {
    epoch_pda_at(&domain.solana_program, pair, domain.epoch)
}
pub fn hold_pda(domain: &Domain, epoch: &Id, business: &Id) -> (Id, u8) {
    hold_pda_at(&domain.solana_program, epoch, business)
}
pub fn escrow_pda(domain: &Domain, hold: &Id) -> (Id, u8) {
    escrow_pda_at(&domain.solana_program, hold)
}
pub fn portion_pda(domain: &Domain, hold: &Id, business: &Id) -> (Id, u8) {
    portion_pda_at(&domain.solana_program, hold, business)
}
pub fn pair_address(domain: &Domain, admin: &Id) -> Id {
    pair_pda(domain, admin).0
}
pub fn epoch_address(domain: &Domain, pair: &Id) -> Id {
    epoch_pda(domain, pair).0
}
pub fn hold_address(domain: &Domain, epoch: &Id, business: &Id) -> Id {
    hold_pda(domain, epoch, business).0
}
pub fn escrow_address(domain: &Domain, hold: &Id) -> Id {
    escrow_pda(domain, hold).0
}
pub fn portion_address(domain: &Domain, hold: &Id, business: &Id) -> Id {
    portion_pda(domain, hold, business).0
}

pub const COMPACT_ENVELOPE_LEN: usize = 64;
pub const RELEASE_LEN: usize = 72;
pub const PREPARE_FILL_LEN: usize = 72;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub intent: Id,
    pub generation: u64,
    pub prior: u64,
    pub predecessor: Id,
}
/// Packet transport omits generation/prior only: both are reconstructed from checked
/// program-owned state and still occur in the exact full canonical signed Decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactEnvelope {
    pub intent: Id,
    pub predecessor: Id,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseEffects {
    pub amount: u64,
    pub result: Id,
    pub fence: Id,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareFillEffects {
    pub amount: u64,
    pub journal: Id,
    pub fence: Id,
}

fn id(bytes: &[u8]) -> Result<Id, ProtocolError> {
    bytes.try_into().map_err(|_| ProtocolError::InvalidLength)
}
fn effect_fields(bytes: &[u8]) -> Result<(u64, Id, Id), ProtocolError> {
    if bytes.len() != 72 {
        return Err(ProtocolError::InvalidLength);
    }
    let amount = u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| ProtocolError::InvalidLength)?,
    );
    let context = id(&bytes[8..40])?;
    let fence = id(&bytes[40..])?;
    if amount == 0 {
        return Err(ProtocolError::ZeroAmount);
    }
    if context == [0; 32] || fence == [0; 32] {
        return Err(ProtocolError::EvidenceMismatch);
    }
    Ok((amount, context, fence))
}
fn encode_fields(amount: u64, context: &Id, fence: &Id) -> [u8; 72] {
    let mut bytes = [0; 72];
    bytes[..8].copy_from_slice(&amount.to_le_bytes());
    bytes[8..40].copy_from_slice(context);
    bytes[40..].copy_from_slice(fence);
    bytes
}
impl CompactEnvelope {
    pub fn encode(&self) -> [u8; COMPACT_ENVELOPE_LEN] {
        let mut bytes = [0; COMPACT_ENVELOPE_LEN];
        bytes[..32].copy_from_slice(&self.intent);
        bytes[32..].copy_from_slice(&self.predecessor);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != COMPACT_ENVELOPE_LEN {
            return Err(ProtocolError::InvalidLength);
        }
        let state = Self {
            intent: id(&bytes[..32])?,
            predecessor: id(&bytes[32..])?,
        };
        if state.intent == [0; 32] {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(state)
    }
    pub fn bind(self, generation: u64, prior: u64) -> Result<Envelope, ProtocolError> {
        if generation == 0 {
            return Err(ProtocolError::InvalidGeneration);
        }
        Ok(Envelope {
            intent: self.intent,
            generation,
            prior,
            predecessor: self.predecessor,
        })
    }
}
impl Envelope {
    pub fn compact(&self) -> CompactEnvelope {
        CompactEnvelope {
            intent: self.intent,
            predecessor: self.predecessor,
        }
    }
}
impl ReleaseEffects {
    pub fn encode(&self) -> [u8; RELEASE_LEN] {
        encode_fields(self.amount, &self.result, &self.fence)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (amount, result, fence) = effect_fields(bytes)?;
        Ok(Self {
            amount,
            result,
            fence,
        })
    }
}
impl PrepareFillEffects {
    pub fn encode(&self) -> [u8; PREPARE_FILL_LEN] {
        encode_fields(self.amount, &self.journal, &self.fence)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let (amount, journal, fence) = effect_fields(bytes)?;
        Ok(Self {
            amount,
            journal,
            fence,
        })
    }
}
/// The caller supplies only immutable ordered semantic account IDs, excluding creation payer.
/// The program separately enforces canonical owner/PDA/signer/writable roles for these IDs.
pub fn effect_digest(transition: Transition, payload: &[u8], semantic_accounts: &[Id]) -> Id {
    let mut hash = Sha256::new();
    hash.update(b"KERBSFX1");
    hash.update([transition as u8]);
    hash.update(payload);
    for key in semantic_accounts {
        hash.update(key);
    }
    hash.finalize().into()
}
pub fn decision(
    domain: Domain,
    entity: Id,
    portion: Option<Id>,
    transition: Transition,
    envelope: Envelope,
    payload: &[u8],
    semantic_accounts: &[Id],
) -> Result<Decision, ProtocolError> {
    Decision::new(
        Operation {
            domain,
            entity,
            portion: portion.unwrap_or([0; 32]),
            intent: envelope.intent,
            generation: envelope.generation,
            prior_version: envelope.prior,
            transition,
            effects: effect_digest(transition, payload, semantic_accounts),
        },
        envelope.predecessor,
    )
}
