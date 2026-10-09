//! Actual owner-local note mint semantics; no asset receipt, root admission or funding claim.
use super::*;
use ziquid_protocol::samechain::{Deployment, creation::{NoteCreationJournal, NoteCreationPacket}};

const WITNESS_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_NOTE_CREATION_WITNESS\0";
const CONSENT_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_NOTE_CREATION_CONSENT\0";
pub const NOTE_CREATION_CONSENT_BYTES: usize = CONSENT_DOMAIN.len() + 2 + 96;

#[derive(Clone, PartialEq, Eq)]
pub struct NoteCreationWitness {
    pub packet: NoteCreationPacket,
    pub blind: [u8; 32],
    pub owner_seed: [u8; 32],
    pub note: NoteOpening,
    pub recovery_key: [u8; 32],
    pub consent: [u8; 64],
}
redacted_debug!(NoteCreationWitness);
impl Drop for NoteCreationWitness {
    fn drop(&mut self) {
        self.blind.zeroize(); self.owner_seed.zeroize();
        self.recovery_key.zeroize(); self.consent.zeroize();
    }
}

impl NoteCreationWitness {
    /// Canonical shape only: mismatched amount/asset/owner/terms remain encodable.
    /// One completely preallocated guarded private allocation, using parent codecs.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RelationError> {
        self.packet.validate()?;
        self.validate_shape()?;
        let packet = self.packet.encode()?;
        let length = WITNESS_DOMAIN.len() + 2 + 4 + packet.len() + 32 + 32
            + note_blob_len(&self.note)? + 32 + 64;
        let mut out = PrivateWriter::new(length)?;
        header(&mut out, WITNESS_DOMAIN)?;
        write_length(&mut out, packet.len())?;
        put(&mut out, &packet)?;
        put(&mut out, &self.blind)?;
        put(&mut out, &self.owner_seed)?;
        write_note_blob(&mut out, &self.note)?;
        put(&mut out, &self.recovery_key)?;
        put(&mut out, &self.consent)?;
        out.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelationError> {
        let mut reader = PrivateReader::frame(bytes, WITNESS_DOMAIN, MAX_PRIVATE_INPUT_BYTES)?;
        let packet = NoteCreationPacket::decode(reader.blob(MAX_PACKET_BYTES)?)?;
        let blind = Zeroizing::new(reader.array::<32>()?);
        let owner_seed = Zeroizing::new(reader.array::<32>()?);
        let note = NoteOpening::decode(reader.blob(MAX_NOTE_BYTES)?)?;
        let recovery_key = Zeroizing::new(reader.array::<32>()?);
        let consent = Zeroizing::new(reader.array::<64>()?);
        reader.finish()?;
        let witness = Self { packet, blind: *blind, owner_seed: *owner_seed, note,
            recovery_key: *recovery_key, consent: *consent };
        witness.validate_shape()?;
        Ok(witness)
    }

    fn validate_shape(&self) -> Result<(), RelationError> {
        validate_private_fields(&self.blind, &self.owner_seed, &self.note, &[], &[], self.packet.role)?;
        if !nonzero(&self.recovery_key) { return Err(RelationError::Key); }
        Ok(())
    }
}

/// Distinct-domain canonical bytes only, not approval of a note's semantics.
pub fn note_creation_consent_message(packet: &NoteCreationPacket)
    -> Result<[u8; NOTE_CREATION_CONSENT_BYTES], RelationError>
{
    packet.validate()?;
    let mut bytes = [0; NOTE_CREATION_CONSENT_BYTES];
    let mut out = bytes.as_mut_slice();
    header(&mut out, CONSENT_DOMAIN)?;
    put(&mut out, &packet.deployment.digest()?)?;
    put(&mut out, &packet.terms_commitment)?;
    put(&mut out, &packet.digest()?)?;
    Ok(bytes)
}

/// Select deployment, payer and creation nonce independently of private stdin.
/// Existing consent is ignored; review neither signs nor mutates the witness.
pub fn review_note_creation(packet: &NoteCreationPacket, witness: &NoteCreationWitness,
    expected_deployment: &Deployment, expected_payer: [u8; 20],
    expected_creation_nonce: [u8; 32]) -> Result<[u8; NOTE_CREATION_CONSENT_BYTES], RelationError>
{
    if packet.deployment != *expected_deployment {
        return Err(SamechainError::InvalidDeployment.into());
    }
    if !nonzero(&expected_payer) || !nonzero(&expected_creation_nonce)
        || packet.payer != expected_payer || packet.creation_nonce != expected_creation_nonce
        || packet != &witness.packet
    { return Err(RelationError::Manifest); }
    verify_semantics(witness)?;
    note_creation_consent_message(packet)
}

/// Recheck the complete mint predicate and strict owner authorization every time.
/// A journal proves no target payer authentication, nonce uniqueness or asset receipt.
pub fn verify_note_creation_relation(witness: &NoteCreationWitness)
    -> Result<NoteCreationJournal, RelationError>
{
    verify_semantics(witness)?;
    verify_consent(&witness.owner_seed, &witness.packet.owner_key,
        &note_creation_consent_message(&witness.packet)?, &witness.consent)?;
    Ok(NoteCreationJournal::from_packet(&witness.packet)?)
}

fn verify_semantics(witness: &NoteCreationWitness) -> Result<(), RelationError> {
    let packet = &witness.packet;
    // Neither a nonzero commitment nor even fresh owner consent opens deposit terms.
    // Review and signed verification share this real commitment-opening guard.
    packet.validate_commitment(&witness.blind)?;
    let note = &witness.note;
    note.validate()?;
    let deployment = packet.deployment.digest()?;
    let (role, commitment) = match &packet.output {
        OutputDescriptor::Note { role, commitment, .. } => (*role, commitment),
        _ => return Err(RelationError::Note),
    };
    if note.deployment_digest != deployment || note.owner_key != packet.owner_key
        || note.asset != packet.asset || note.value != packet.amount
        || role != packet.role || note.commitment()? != *commitment
    { return Err(RelationError::Note); }
    verify_owner_key(&witness.owner_seed, &packet.owner_key)?;
    let recovered = decrypt_output(&packet.output, &witness.recovery_key, &deployment,
        &packet.owner_key)?;
    if recovered != *note { return Err(RelationError::Note); }
    match (&packet.order, &note.order) {
        (None, None) => {}
        (Some(initial), Some(order)) => {
            if order.id != initial.id || order.generation != 1 {
                return Err(RelationError::Note);
            }
            order.policy.validate_for(packet.role)?;
            let opposite = match packet.asset {
                Asset::Native => Asset::Token(packet.token),
                Asset::Token(_) => Asset::Native,
            };
            if order.policy.sell_asset != packet.asset || order.policy.buy_asset != opposite {
                return Err(RelationError::Policy);
            }
        }
        _ => return Err(RelationError::Note),
    }
    Ok(())
}
