//! Owner-local ordinary note withdrawal, not root admission, backing or transfer.
use super::*;
use ziquid_protocol::samechain::{Deployment, withdrawal::{NoteWithdrawalJournal, NoteWithdrawalPacket}};

const WITNESS_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_WITNESS\0";
const CONSENT_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_CONSENT\0";
pub const NOTE_WITHDRAWAL_CONSENT_BYTES: usize = CONSENT_DOMAIN.len() + 2 + 96 + 2;

#[derive(Clone, PartialEq, Eq)]
pub struct NoteWithdrawalWitness {
    pub packet: NoteWithdrawalPacket,
    pub blind: [u8; 32],
    pub owner_seed: [u8; 32],
    pub input: NoteOpening,
    pub membership: MerkleMembership,
    pub consent: [u8; 64],
    pub owned_outputs: Vec<PreparedOutputOpening>,
}
redacted_debug!(NoteWithdrawalWitness);
impl Drop for NoteWithdrawalWitness {
    fn drop(&mut self) {
        self.blind.zeroize(); self.owner_seed.zeroize(); self.consent.zeroize();
    }
}

impl NoteWithdrawalWitness {
    /// Shape-only private framing; semantic approval is never cached by a codec.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RelationError> {
        self.packet.validate()?;
        validate_private_fields(&self.blind, &self.owner_seed, &self.input,
            &self.owned_outputs, &self.packet.outputs, Role::A)?;
        let packet = self.packet.encode()?;
        let length = WITNESS_DOMAIN.len() + 2 + 4 + packet.len() + 32 + 32
            + note_blob_len(&self.input)? + MEMBERSHIP_LEN + 64
            + owned_list_len(&self.owned_outputs)?;
        let mut out = PrivateWriter::new(length)?;
        header(&mut out, WITNESS_DOMAIN)?;
        write_length(&mut out, packet.len())?;
        put(&mut out, &packet)?;
        put(&mut out, &self.blind)?;
        put(&mut out, &self.owner_seed)?;
        write_note_blob(&mut out, &self.input)?;
        write_membership(&mut out, &self.membership)?;
        put(&mut out, &self.consent)?;
        write_owned(&mut out, &self.owned_outputs)?;
        out.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelationError> {
        let mut reader = PrivateReader::frame(bytes, WITNESS_DOMAIN, MAX_PRIVATE_INPUT_BYTES)?;
        let packet = NoteWithdrawalPacket::decode(reader.blob(MAX_PACKET_BYTES)?)?;
        let blind = Zeroizing::new(reader.array::<32>()?);
        let owner_seed = Zeroizing::new(reader.array::<32>()?);
        let input = NoteOpening::decode(reader.blob(MAX_NOTE_BYTES)?)?;
        let membership = read_membership(&mut reader)?;
        let consent = Zeroizing::new(reader.array::<64>()?);
        let owned_outputs = read_owned(&mut reader)?;
        reader.finish()?;
        let witness = Self { packet, blind: *blind, owner_seed: *owner_seed, input,
            membership, consent: *consent, owned_outputs };
        validate_private_fields(&witness.blind, &witness.owner_seed, &witness.input,
            &witness.owned_outputs, &witness.packet.outputs, Role::A)?;
        Ok(witness)
    }
}

/// Exact distinct-domain bytes only; producing them does not approve semantics.
pub fn note_withdrawal_consent_message(packet: &NoteWithdrawalPacket)
    -> Result<[u8; NOTE_WITHDRAWAL_CONSENT_BYTES], RelationError>
{
    packet.validate()?;
    let mut bytes = [0; NOTE_WITHDRAWAL_CONSENT_BYTES];
    let mut out = bytes.as_mut_slice();
    header(&mut out, CONSENT_DOMAIN)?;
    put(&mut out, &packet.deployment.digest()?)?;
    put(&mut out, &packet.terms_commitment)?;
    put(&mut out, &packet.digest()?)?;
    put(&mut out, &[Role::A as u8, Action::Exit as u8])?;
    Ok(bytes)
}

/// The deployment and input commitment must come from independent owner selection.
/// Consent is deliberately ignored: this function neither signs nor mutates it.
pub fn review_note_withdrawal(packet: &NoteWithdrawalPacket, witness: &NoteWithdrawalWitness,
    expected_deployment: &Deployment, expected_input_commitment: [u8; 32])
    -> Result<[u8; NOTE_WITHDRAWAL_CONSENT_BYTES], RelationError>
{
    if packet.deployment != *expected_deployment {
        return Err(SamechainError::InvalidDeployment.into());
    }
    if !nonzero(&expected_input_commitment)
        || packet.input.commitment != expected_input_commitment
    { return Err(RelationError::Input); }
    if packet != &witness.packet { return Err(RelationError::Manifest); }
    verify_semantics(witness)?;
    note_withdrawal_consent_message(packet)
}

/// Recheck private semantics and strict authorization on every invocation.
/// The returned journal describes only the supplied relation, not funded execution.
pub fn verify_note_withdrawal_relation(witness: &NoteWithdrawalWitness)
    -> Result<NoteWithdrawalJournal, RelationError>
{
    verify_semantics(witness)?;
    let message = note_withdrawal_consent_message(&witness.packet)?;
    verify_consent(&witness.owner_seed, &witness.input.owner_key, &message, &witness.consent)?;
    Ok(NoteWithdrawalJournal::from_packet(&witness.packet)?)
}

fn verify_semantics(witness: &NoteWithdrawalWitness) -> Result<(), RelationError> {
    let packet = &witness.packet;
    // A nonzero label or freshly signed packet is not an opening of these terms.
    // BOTH unsigned review and signed verification enter through this guard.
    packet.validate_commitment(&witness.blind)?;
    let input = &witness.input;
    input.validate()?;
    verify_owner_key(&witness.owner_seed, &input.owner_key)?;
    let deployment = packet.deployment.digest()?;
    let descriptor = &packet.input;
    if input.order.is_some() || input.deployment_digest != deployment
        || input.owner_key != descriptor.owner_key || input.commitment()? != descriptor.commitment
        || input.nullifier()? != descriptor.nullifier
    { return Err(RelationError::Input); }
    let path = &witness.membership;
    if path.tree_id != descriptor.tree_id || path.index != descriptor.index
        || path.root(&deployment, &descriptor.commitment) != descriptor.root
    { return Err(RelationError::Membership); }
    let owned = &witness.owned_outputs;
    if owned.len() > MAX_OUTPUTS { return Err(RelationError::ResourceLimit); }
    if owned.windows(2).any(|pair| pair[0].manifest_index >= pair[1].manifest_index) {
        return Err(RelationError::Manifest);
    }
    let mut next = 0;
    let mut spent = U512::zero();
    let mut output_nullifiers = Zeroizing::new([[0; 32]; MAX_OUTPUTS]);
    for (index, output) in packet.outputs.iter().enumerate() {
        match output {
            OutputDescriptor::Note { .. } => {
                let opening = owned.get(next).ok_or(RelationError::Manifest)?;
                if opening.manifest_index as usize != index { return Err(RelationError::Manifest); }
                if opening.note.owner_key != input.owner_key
                    || opening.note.deployment_digest != deployment
                    || opening.note.asset != input.asset || opening.note.order.is_some()
                { return Err(RelationError::Output); }
                let recovered = decrypt_output(output, &opening.recovery_key, &deployment, &input.owner_key)?;
                if recovered != opening.note { return Err(RelationError::Output); }
                let nullifier = Zeroizing::new(recovered.nullifier()?);
                if *nullifier == descriptor.nullifier || output_nullifiers[..next].contains(&*nullifier) {
                    return Err(RelationError::Output);
                }
                output_nullifiers[next] = *nullifier;
                next += 1;
                spent += U512::from(recovered.value);
            }
            OutputDescriptor::Exit { asset, amount, .. }
                | OutputDescriptor::Fee { asset, amount, .. } => {
                if *asset != input.asset { return Err(RelationError::Output); }
                spent += U512::from(*amount);
            }
        }
    }
    if next != owned.len() { return Err(RelationError::Manifest); }
    // At most eight U256 amounts: exact U512 sum, never cross-asset net or narrowing.
    if spent != U512::from(input.value) { return Err(RelationError::Conservation); }
    Ok(())
}
