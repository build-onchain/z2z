//! Owner-local samechain semantics, shared verbatim with the dedicated guest.
//!
//! A returned journal is not a funded fact or proof certificate. Root eligibility,
//! global spentness, custody, transfers, wrapped proofs and strict GD2 are separate.
//! Callers supply CSPRNG owner salts, note nonces, keys and fresh AEAD nonces;
//! rejecting zero bytes does not prove entropy or backup availability.
use std::{fmt, io::{self, Write}};
use chacha20poly1305::{AeadInPlace, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use primitive_types::{U256, U512};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};
use ziquid_protocol::samechain::{
    Action, Asset, InputDescriptor, OrderPolicy, OutputDescriptor, OwnerJournal,
    PublicPacket, Role, SamechainError, SingleOwnerPacket, owner_relation_version,
    MAX_CIPHERTEXT_BYTES, MAX_OUTPUTS, MAX_PACKET_BYTES,
};
use ziquid_protocol::samechain::fill::{FillExecution, owner_leaf, validate_commitment};

pub const MAX_PRIVATE_INPUT_BYTES: usize = 256 * 1024;
pub const CIPHERTEXT_VERSION: u16 = 1;
pub const FILL_WITNESS_VERSION: u16 = 2;
const VERSION: u16 = 1;
const NOTE_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_NOTE_OPENING\0";
const ORDER_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_ORDER_STATE\0";
const FILL_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_OWNER_WITNESS\0";
const SINGLE_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_CANCEL_EXIT_WITNESS\0";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MAX_NOTE_BYTES: usize = MAX_CIPHERTEXT_BYTES - NONCE_LEN - TAG_LEN;
const MEMBERSHIP_LEN: usize = 8 + 32 * 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationError {
    Protocol(SamechainError), Encoding, ResourceLimit, Note, Key, Input,
    Membership, Policy, Signature, Manifest, Output, Ciphertext,
    Conservation, Successor, Action,
}
impl fmt::Display for RelationError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "samechain owner relation rejected: {self:?}")
    }
}
impl std::error::Error for RelationError {}
impl From<SamechainError> for RelationError {
    fn from(value: SamechainError) -> Self { Self::Protocol(value) }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NoteOpening {
    pub deployment_digest: [u8; 32],
    pub owner_key: [u8; 32],
    pub nf_key: [u8; 32],
    pub nonce: [u8; 32],
    pub salt: [u8; 32],
    pub asset: Asset,
    pub value: U256,
    pub order: Option<OrderState>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct OrderState {
    pub id: [u8; 32],
    pub generation: u64,
    pub remaining_sell: U256,
    pub policy: OrderPolicy,
}
#[derive(Clone, PartialEq, Eq)]
pub struct MerkleMembership {
    pub tree_id: u32,
    pub index: u32,
    pub siblings: [[u8; 32]; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedOutputOpening {
    pub manifest_index: u32,
    pub note: NoteOpening,
    pub recovery_key: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerWitness {
    pub packet: PublicPacket,
    pub execution: FillExecution,
    pub leaves: [[u8; 32]; 2],
    pub own_salt: [u8; 32],
    pub role: Role,
    pub owner_seed: [u8; 32],
    pub input: NoteOpening,
    pub membership: MerkleMembership,
    pub consent: [u8; 64],
    pub owned_outputs: Vec<PreparedOutputOpening>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct CancelExitWitness {
    pub packet: SingleOwnerPacket,
    pub blind: [u8; 32],
    pub role: Role,
    pub action: Action,
    pub owner_seed: [u8; 32],
    pub input: NoteOpening,
    pub membership: MerkleMembership,
    pub consent: [u8; 64],
    pub owned_outputs: Vec<PreparedOutputOpening>,
}

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => { $(
        impl fmt::Debug for $name {
            fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )+ };
}
redacted_debug!(NoteOpening, OrderState, MerkleMembership, PreparedOutputOpening,
    OwnerWitness, CancelExitWitness);

impl Drop for NoteOpening {
    fn drop(&mut self) {
        self.nf_key.zeroize(); self.nonce.zeroize(); self.salt.zeroize();
        self.value.0.zeroize();
    }
}
impl Drop for OrderState {
    fn drop(&mut self) {
        self.id.zeroize(); self.generation.zeroize();
        self.remaining_sell.0.zeroize();
    }
}
impl Drop for PreparedOutputOpening {
    fn drop(&mut self) { self.recovery_key.zeroize(); }
}
impl Drop for OwnerWitness {
    fn drop(&mut self) {
        self.own_salt.zeroize(); self.owner_seed.zeroize(); self.consent.zeroize();
    }
}
impl Drop for CancelExitWitness {
    fn drop(&mut self) {
        self.blind.zeroize(); self.owner_seed.zeroize(); self.consent.zeroize();
    }
}

fn nonzero(bytes: &[u8]) -> bool { bytes.iter().any(|byte| *byte != 0) }
fn owner_key(bytes: &[u8; 32]) -> Result<VerifyingKey, RelationError> {
    if !nonzero(bytes) { return Err(RelationError::Key); }
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| RelationError::Key)?;
    let point = key.to_edwards();
    // Ordinary authorization, deliberately not historical Zcash Ed25519 rules.
    if key.is_weak() || !point.is_torsion_free() || point.compress().to_bytes() != *bytes {
        return Err(RelationError::Key);
    }
    Ok(key)
}

impl OrderState {
    pub fn validate(&self) -> Result<(), RelationError> {
        self.policy.validate()?;
        if !nonzero(&self.id) || self.generation == 0 || self.remaining_sell.is_zero() {
            return Err(RelationError::Note);
        }
        if let Some(first) = self.policy.fee_policy.entries.first()
            && self.policy.fee_policy.entries.iter().any(|entry| entry.payer != first.payer)
        {
            return Err(RelationError::Policy);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RelationError> {
        self.validate()?;
        let length = ORDER_DOMAIN.len() + 2 + order_body_len(self)?;
        let mut out = PrivateWriter::new(length)?;
        header(&mut out, ORDER_DOMAIN)?;
        write_order(&mut out, self)?;
        out.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, RelationError> {
        let mut reader = PrivateReader::frame(bytes, ORDER_DOMAIN, MAX_NOTE_BYTES)?;
        let value = read_order(&mut reader)?;
        reader.finish()?; value.validate()?;
        Ok(value)
    }
}

impl NoteOpening {
    pub fn validate(&self) -> Result<(), RelationError> {
        owner_key(&self.owner_key)?;
        self.asset.validate()?;
        if !nonzero(&self.deployment_digest) || !nonzero(&self.nf_key)
            || !nonzero(&self.nonce) || !nonzero(&self.salt) || self.value.is_zero()
        { return Err(RelationError::Note); }
        if let Some(order) = &self.order {
            order.validate()?;
            if self.asset != order.policy.sell_asset || self.value < order.remaining_sell {
                return Err(RelationError::Note);
            }
        }
        Ok(())
    }
    fn encoded_len(&self) -> Result<usize, RelationError> {
        self.validate()?;
        let length = NOTE_DOMAIN.len() + 2 + 160 + asset_len(self.asset) + 32 + 1
            + match &self.order { Some(order) => order_body_len(order)?, None => 0 };
        if length > MAX_NOTE_BYTES { return Err(RelationError::ResourceLimit); }
        Ok(length)
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RelationError> {
        let mut out = PrivateWriter::new(self.encoded_len()?)?;
        self.encode_into(&mut out)?;
        out.finish()
    }
    fn encode_into(&self, out: &mut impl Write) -> Result<(), RelationError> {
        header(out, NOTE_DOMAIN)?;
        write_note_body(out, self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, RelationError> {
        let mut reader = PrivateReader::frame(bytes, NOTE_DOMAIN, MAX_NOTE_BYTES)?;
        let value = read_note(&mut reader)?;
        reader.finish()?; value.validate()?;
        Ok(value)
    }
    pub fn commitment(&self) -> Result<[u8; 32], RelationError> {
        self.encoded_len()?;
        let mut out = HashWriter(Sha256::new());
        header(&mut out, b"Z2Z_SAMECHAIN_NOTE_COMMITMENT\0")?;
        write_note_body(&mut out, self)?;
        Ok(out.0.finalize().into())
    }
    /// The committed independent nf_key and nonce, never a clamped seed alias.
    /// Fill, cancellation and exit consume this same input identity.
    pub fn nullifier(&self) -> Result<[u8; 32], RelationError> {
        self.validate()?;
        Ok(hash_parts(b"Z2Z_SAMECHAIN_NOTE_NULLIFIER\0",
            &[&self.deployment_digest, &self.nf_key, &self.nonce]))
    }
}

impl MerkleMembership {
    /// Ordered depth-32 SHA256 path to the supplied root only: no root admission.
    pub fn root(&self, deployment: &[u8; 32], commitment: &[u8; 32]) -> [u8; 32] {
        ziquid_protocol::samechain::tree::root_from_path(deployment,
            self.tree_id, self.index, commitment, &self.siblings)
    }
}

const AD_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_RECIPIENT_AD\0";
const AD_LEN: usize = AD_DOMAIN.len() + 2 + 2 + 1 + 32 * 4;

fn recovery_commitment(key: &[u8; 32]) -> Result<[u8; 32], RelationError> {
    if !nonzero(key) { return Err(RelationError::Key); }
    Ok(hash_parts(b"Z2Z_SAMECHAIN_RECOVERY_KEY\0", &[key]))
}

fn recipient_ad(role: Role, deployment: &[u8; 32], owner: &[u8; 32],
    commitment: &[u8; 32], key_commitment: &[u8; 32]) -> Result<[u8; AD_LEN], RelationError>
{
    let mut bytes = [0; AD_LEN];
    let mut out = bytes.as_mut_slice();
    header(&mut out, AD_DOMAIN)?;
    put(&mut out, &CIPHERTEXT_VERSION.to_be_bytes())?;
    put(&mut out, &[role as u8])?;
    for part in [deployment, owner, commitment, key_commitment] { put(&mut out, part)?; }
    Ok(bytes)
}

/// Recipient-local preparation: decrypt, parse and recompute before consent.
/// Role is explicit because a note opening is not permanently tied to a leg.
/// The recovery key never appears in the returned descriptor.
pub fn prepare_output(note: &NoteOpening, role: Role, recovery_key: &[u8; 32],
    nonce: [u8; 24]) -> Result<OutputDescriptor, RelationError>
{
    if !nonzero(&nonce) { return Err(RelationError::Ciphertext); }
    let commitment = note.commitment()?;
    let key_commitment = recovery_commitment(recovery_key)?;
    let ad = recipient_ad(role, &note.deployment_digest, &note.owner_key,
        &commitment, &key_commitment)?;
    let length = NONCE_LEN + note.encoded_len()? + TAG_LEN;
    // Complete envelope capacity before the first secret byte: no allocation
    // growth can free a plaintext-bearing buffer outside its erasure guard.
    let mut out = PrivateWriter::new(length)?;
    put(&mut out, &nonce)?;
    note.encode_into(&mut out)?;
    let tag = XChaCha20Poly1305::new(recovery_key.into())
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &ad,
            &mut out.bytes[NONCE_LEN..])
        .map_err(|_| RelationError::Ciphertext)?;
    put(&mut out, &tag)?;
    let mut ciphertext = out.finish()?;
    // Encryption has replaced every plaintext byte; move this now-public
    // allocation out of its guard rather than copy the complete envelope.
    let descriptor = OutputDescriptor::Note { role, commitment,
        recovery_key_commitment: key_commitment, ciphertext_version: CIPHERTEXT_VERSION,
        ciphertext: std::mem::take(&mut *ciphertext) };
    let recovered = decrypt_output(&descriptor, recovery_key,
        &note.deployment_digest, &note.owner_key)?;
    if recovered != *note { return Err(RelationError::Output); }
    Ok(descriptor)
}

/// Actual recipient decryption and note recomputation, not a recovery-ack flag.
pub fn decrypt_output(output: &OutputDescriptor, recovery_key: &[u8; 32],
    expected_deployment: &[u8; 32], expected_owner: &[u8; 32]) -> Result<NoteOpening, RelationError>
{
    output.validate()?;
    owner_key(expected_owner)?;
    let (role, commitment, key_commitment, version, ciphertext) = match output {
        OutputDescriptor::Note { role, commitment, recovery_key_commitment,
            ciphertext_version, ciphertext } =>
            (*role, commitment, recovery_key_commitment, *ciphertext_version, ciphertext),
        _ => return Err(RelationError::Output),
    };
    if version != CIPHERTEXT_VERSION || ciphertext.len() <= NONCE_LEN + TAG_LEN
        || !nonzero(expected_deployment) || !nonzero(&ciphertext[..NONCE_LEN])
        || recovery_commitment(recovery_key)? != *key_commitment
    { return Err(RelationError::Ciphertext); }
    let ad = recipient_ad(role, expected_deployment, expected_owner, commitment, key_commitment)?;
    let end = ciphertext.len() - TAG_LEN;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(end - NONCE_LEN));
    plaintext.extend_from_slice(&ciphertext[NONCE_LEN..end]);
    XChaCha20Poly1305::new(recovery_key.into()).decrypt_in_place_detached(
        XNonce::from_slice(&ciphertext[..NONCE_LEN]), &ad, &mut plaintext,
        Tag::from_slice(&ciphertext[end..]))
        .map_err(|_| RelationError::Ciphertext)?;
    let note = NoteOpening::decode(&plaintext)?;
    if note.deployment_digest != *expected_deployment || note.owner_key != *expected_owner
        || note.commitment()? != *commitment
    { return Err(RelationError::Output); }
    Ok(note)
}

const CONSENT_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_OWNER_CONSENT\0";
pub const CONSENT_MESSAGE_BYTES: usize = CONSENT_DOMAIN.len() + 2 + 2 + 1 + 1 + 32 * 3;

fn consent_message(deployment: [u8; 32], commitment: [u8; 32], packet: [u8; 32],
    role: Role, action: Action) -> Result<[u8; CONSENT_MESSAGE_BYTES], RelationError>
{
    let mut bytes = [0; CONSENT_MESSAGE_BYTES];
    let mut out = bytes.as_mut_slice();
    header(&mut out, CONSENT_DOMAIN)?;
    put(&mut out, &owner_relation_version(action).to_be_bytes())?;
    put(&mut out, &[action as u8, role as u8])?;
    for part in [&deployment, &commitment, &packet] { put(&mut out, part)?; }
    Ok(bytes)
}

pub fn fill_consent_message(packet: &PublicPacket, role: Role)
    -> Result<[u8; CONSENT_MESSAGE_BYTES], RelationError>
{
    consent_message(packet.deployment.digest()?, packet.terms_commitment,
        packet.digest()?, role, Action::Fill)
}

pub fn single_consent_message(packet: &SingleOwnerPacket, role: Role, action: Action)
    -> Result<[u8; CONSENT_MESSAGE_BYTES], RelationError>
{
    if action == Action::Fill { return Err(RelationError::Action); }
    packet.validate_for(role)?;
    consent_message(packet.deployment.digest()?, packet.terms_commitment,
        packet.digest()?, role, action)
}

fn verify_owner_key(seed: &[u8; 32], owner: &[u8; 32])
    -> Result<VerifyingKey, RelationError>
{
    if !nonzero(seed) { return Err(RelationError::Key); }
    let key = owner_key(owner)?;
    if SigningKey::from_bytes(seed).verifying_key().to_bytes() != *owner {
        return Err(RelationError::Key);
    }
    Ok(key)
}

fn verify_consent(seed: &[u8; 32], owner: &[u8; 32], message: &[u8], signature: &[u8; 64])
    -> Result<(), RelationError>
{
    verify_owner_key(seed, owner)?.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| RelationError::Signature)
}

fn verify_input<'a>(input: &'a NoteOpening, descriptor: &InputDescriptor,
    membership: &MerkleMembership, deployment: &[u8; 32], role: Role)
    -> Result<&'a OrderState, RelationError>
{
    input.encoded_len()?;
    let order = input.order.as_ref().ok_or(RelationError::Input)?;
    order.policy.validate_for(role)?;
    if input.deployment_digest != *deployment || input.owner_key != descriptor.owner_key
        || input.commitment()? != descriptor.commitment || input.nullifier()? != descriptor.nullifier
        || order.id != descriptor.order_id || order.generation != descriptor.generation
    { return Err(RelationError::Input); }
    if membership.tree_id != descriptor.tree_id || membership.index != descriptor.index
        || membership.root(deployment, &descriptor.commitment) != descriptor.root
    { return Err(RelationError::Membership); }
    Ok(order)
}

fn asset_index(asset: Asset, policy: &OrderPolicy) -> Result<usize, RelationError> {
    if asset == policy.sell_asset { Ok(0) }
    else if asset == policy.buy_asset { Ok(1) }
    else { Err(RelationError::Conservation) }
}

/// Exhaustively traverse the common manifest. Only this owner's openings/keys
/// are required; the other owner's leg must produce the identical pair binding.
fn own_note_totals(outputs: &[OutputDescriptor], owned: &[PreparedOutputOpening],
    input: &NoteOpening, role: Role, successor: Option<(u64, U256)>, consumed: &[[u8; 32]])
    -> Result<[U512; 2], RelationError>
{
    if owned.len() > MAX_OUTPUTS { return Err(RelationError::ResourceLimit); }
    if owned.windows(2).any(|pair| pair[0].manifest_index >= pair[1].manifest_index) {
        return Err(RelationError::Manifest);
    }
    let order = input.order.as_ref().ok_or(RelationError::Input)?;
    let mut next = 0;
    let mut successor_count = 0;
    let mut totals = [U512::zero(); 2];
    let mut output_nullifiers = Zeroizing::new([[0; 32]; MAX_OUTPUTS]);
    for (index, output) in outputs.iter().enumerate() {
        if output.role() != role || !matches!(output, OutputDescriptor::Note { .. }) { continue; }
        let opening = owned.get(next).ok_or(RelationError::Manifest)?;
        if opening.manifest_index as usize != index { return Err(RelationError::Manifest); }
        next += 1;
        if opening.note.owner_key != input.owner_key
            || opening.note.deployment_digest != input.deployment_digest
        { return Err(RelationError::Output); }
        let recovered = decrypt_output(output, &opening.recovery_key,
            &input.deployment_digest, &input.owner_key)?;
        if recovered != opening.note { return Err(RelationError::Output); }
        let nullifier = Zeroizing::new(recovered.nullifier()?);
        // A fresh commitment/salt is not a fresh spend identity. No returned
        // right may already be spent by this action or collide with its sibling.
        if consumed.contains(&*nullifier) || output_nullifiers[..next - 1].contains(&*nullifier) {
            return Err(RelationError::Output);
        }
        output_nullifiers[next - 1] = *nullifier;
        if let Some(actual) = &recovered.order {
            let (generation, remaining) = successor.ok_or(RelationError::Successor)?;
            if actual.id != order.id || actual.generation != generation
                || actual.remaining_sell != remaining || actual.policy != order.policy
                || recovered.asset != order.policy.sell_asset || recovered.value < remaining
            { return Err(RelationError::Successor); }
            successor_count += 1;
        }
        let asset = asset_index(recovered.asset, &order.policy)?;
        // Eight U256 outputs cannot overflow U512; no narrowing or cross-asset net.
        totals[asset] += U512::from(recovered.value);
    }
    if next != owned.len() { return Err(RelationError::Manifest); }
    if successor_count != usize::from(successor.is_some()) {
        return Err(RelationError::Successor);
    }
    Ok(totals)
}

fn add_public_effects(totals: &mut [U512; 2], outputs: &[OutputDescriptor],
    role: Role, policy: &OrderPolicy) -> Result<(), RelationError>
{
    for output in outputs {
        match output {
            OutputDescriptor::Exit { role: owner, asset, amount, .. }
                | OutputDescriptor::Fee { payer: owner, asset, amount, .. } if *owner == role => {
                    totals[asset_index(*asset, policy)?] += U512::from(*amount);
                }
            _ => {}
        }
    }
    Ok(())
}

/// Review independently selected deployment/order/role/execution before returning
/// unsigned consent bytes; root eligibility, spentness and backing stay unverified.
pub fn review_owner_fill(packet: &PublicPacket, witness: &OwnerWitness,
    expected_deployment: &ziquid_protocol::samechain::Deployment,
    expected_order_id: [u8; 32], expected_role: Role, expected_execution: &FillExecution)
    -> Result<[u8; CONSENT_MESSAGE_BYTES], RelationError>
{
    if packet.deployment != *expected_deployment {
        return Err(SamechainError::InvalidDeployment.into());
    }
    if witness.role != expected_role { return Err(SamechainError::InvalidRole.into()); }
    if !nonzero(&expected_order_id)
        || witness.input.order.as_ref().map(|order| order.id) != Some(expected_order_id)
        || packet.inputs[expected_role.index()].order_id != expected_order_id
    { return Err(RelationError::Input); }
    if witness.execution != *expected_execution { return Err(SamechainError::OpeningMismatch.into()); }
    verify_owner_fill_opening(packet, witness)?;
    let deployment = packet.deployment.digest()?;
    verify_owner_key(&witness.owner_seed, &witness.input.owner_key)?;
    verify_owner_fill_semantics(packet, witness, &deployment)?;
    fill_consent_message(packet, expected_role)
}

/// Actual private semantic checks. The supplied root's current eligibility and
/// this input's global unspentness are intentionally not asserted here.
pub fn verify_owner_relation(packet: &PublicPacket, witness: &OwnerWitness)
    -> Result<OwnerJournal, RelationError>
{
    verify_owner_fill_opening(packet, witness)?;
    let deployment = packet.deployment.digest()?;
    let message = fill_consent_message(packet, witness.role)?;
    verify_consent(&witness.owner_seed, &witness.input.owner_key, &message, &witness.consent)?;
    verify_owner_fill_semantics(packet, witness, &deployment)?;
    Ok(OwnerJournal::from_packet(packet, witness.role, Action::Fill)?)
}

fn verify_owner_fill_opening(packet: &PublicPacket, witness: &OwnerWitness)
    -> Result<(), RelationError>
{
    if packet != &witness.packet { return Err(SamechainError::OpeningMismatch.into()); }
    validate_commitment(packet, &witness.execution, &witness.leaves)?;
    let order = witness.input.order.as_ref().ok_or(RelationError::Input)?;
    if owner_leaf(packet, &witness.execution, witness.role, &order.policy, &witness.own_salt)?
        != witness.leaves[witness.role.index()]
    { return Err(SamechainError::OpeningMismatch.into()); }
    Ok(())
}

fn verify_owner_fill_semantics(packet: &PublicPacket, witness: &OwnerWitness,
    deployment: &[u8; 32]) -> Result<(), RelationError>
{
    let order = verify_input(&witness.input, &packet.inputs[witness.role.index()],
        &witness.membership, deployment, witness.role)?;
    order.policy.validate_for(witness.role)?;
    let (sell_asset, buy_asset, sold, credit) = match witness.role {
        Role::A => (witness.execution.asset_a, witness.execution.asset_b,
            witness.execution.sell_a, witness.execution.sell_b),
        Role::B => (witness.execution.asset_b, witness.execution.asset_a,
            witness.execution.sell_b, witness.execution.sell_a),
    };
    if order.policy.sell_asset != sell_asset || order.policy.buy_asset != buy_asset {
        return Err(SamechainError::InvalidPolicy.into());
    }
    // The authenticated owner-local policy is the only fee/limit authority.
    // Complete per-key sums use U512; empty allowlists and zero caps stay valid.
    order.policy.fee_policy.validate_fees(witness.role, &packet.outputs)?;
    let mut buy_fees = U512::zero();
    for output in &packet.outputs {
        match output {
            OutputDescriptor::Exit { role, asset, .. } if *role == witness.role => {
                if *asset != sell_asset && *asset != buy_asset {
                    return Err(SamechainError::InvalidOutput.into());
                }
            }
            OutputDescriptor::Fee { payer, asset, amount, .. }
                if *payer == witness.role && *asset == buy_asset => {
                    buy_fees += U512::from(*amount);
                }
            _ => {}
        }
    }
    let net = U512::from(credit).checked_sub(buy_fees).ok_or(SamechainError::LimitNotMet)?;
    // net <= credit <= U256::MAX; both exact products fit in U512.
    if net * U512::from(order.policy.min_sell_den) < sold.full_mul(order.policy.min_buy_num) {
        return Err(SamechainError::LimitNotMet.into());
    }
    let remaining = order.remaining_sell.checked_sub(sold).ok_or(RelationError::Successor)?;
    let successor = if remaining.is_zero() { None } else {
        Some((order.generation.checked_add(1).ok_or(RelationError::Successor)?, remaining))
    };
    let mut spent = own_note_totals(&packet.outputs, &witness.owned_outputs,
        &witness.input, witness.role, successor, &[packet.inputs[0].nullifier, packet.inputs[1].nullifier])?;
    add_public_effects(&mut spent, &packet.outputs, witness.role, &order.policy)?;
    spent[0] += U512::from(sold);
    let available = [U512::from(witness.input.value), U512::from(credit)];
    if spent != available { return Err(RelationError::Conservation); }
    Ok(())
}

/// Review exact independently selected cancellation/exit scope without signing.
/// Existing consent is ignored; root eligibility, spentness and backing are not proven.
pub fn review_owner_cancel_exit(packet: &SingleOwnerPacket, witness: &CancelExitWitness,
    expected_deployment: &ziquid_protocol::samechain::Deployment,
    expected_order_id: [u8; 32], expected_role: Role, expected_action: Action)
    -> Result<[u8; CONSENT_MESSAGE_BYTES], RelationError>
{
    if packet.deployment != *expected_deployment {
        return Err(SamechainError::InvalidDeployment.into());
    }
    if witness.role != expected_role { return Err(SamechainError::InvalidRole.into()); }
    if expected_action == Action::Fill || witness.action != expected_action {
        return Err(RelationError::Action);
    }
    if !nonzero(&expected_order_id) || packet.input.order_id != expected_order_id
        || witness.input.order.as_ref().map(|order| order.id) != Some(expected_order_id)
    { return Err(RelationError::Input); }
    if *packet != witness.packet { return Err(SamechainError::OpeningMismatch.into()); }
    verify_owner_key(&witness.owner_seed, &witness.input.owner_key)?;
    let order = verify_cancel_exit_input(witness)?;
    verify_cancel_exit_effects(witness, order)?;
    single_consent_message(packet, expected_role, expected_action)
}

/// Cancellation/exit use one real input and no artificial trade credits.
/// Consuming its stable N at the eventual target invalidates every fill packet
/// spending it; client-side packet cancellation alone is not that global action.
pub fn verify_cancel_exit_relation(witness: &CancelExitWitness)
    -> Result<OwnerJournal, RelationError>
{
    let order = verify_cancel_exit_input(witness)?;
    let message = single_consent_message(&witness.packet, witness.role, witness.action)?;
    verify_consent(&witness.owner_seed, &witness.input.owner_key, &message, &witness.consent)?;
    verify_cancel_exit_effects(witness, order)?;
    Ok(OwnerJournal::from_single_packet(&witness.packet, witness.role, witness.action)?)
}

fn verify_cancel_exit_input(witness: &CancelExitWitness) -> Result<&OrderState, RelationError> {
    if witness.action == Action::Fill { return Err(RelationError::Action); }
    witness.packet.validate_for(witness.role)?;
    witness.packet.validate_commitment(&witness.blind)?;
    let deployment = witness.packet.deployment.digest()?;
    verify_input(&witness.input, &witness.packet.input, &witness.membership,
        &deployment, witness.role)
}

fn verify_cancel_exit_effects(witness: &CancelExitWitness, order: &OrderState)
    -> Result<(), RelationError>
{
    order.policy.fee_policy.validate_fees(witness.role, &witness.packet.outputs)?;
    let mut spent = own_note_totals(&witness.packet.outputs, &witness.owned_outputs,
        &witness.input, witness.role, None, std::slice::from_ref(&witness.packet.input.nullifier))?;
    add_public_effects(&mut spent, &witness.packet.outputs, witness.role, &order.policy)?;
    if spent != [U512::from(witness.input.value), U512::zero()] {
        return Err(RelationError::Conservation);
    }
    Ok(())
}

impl OwnerWitness {
    /// Shape-only framing. One guarded allocation streams the public packet,
    /// execution and existing note/policy codecs; no financial preflight here.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RelationError> {
        validate_private_fields(&self.own_salt, &self.owner_seed, &self.input,
            &self.owned_outputs, &self.packet.outputs, self.role)?;
        let packet_len = self.packet.encoded_len()?;
        let execution_len = self.execution.encoded_len()?;
        let length = FILL_DOMAIN.len() + 2 + 4 + packet_len + 4 + execution_len + 64 + 32 + 1 + 32
            + note_blob_len(&self.input)? + MEMBERSHIP_LEN + 64
            + owned_list_len(&self.owned_outputs)?;
        let mut out = PrivateWriter::new(length)?;
        header_version(&mut out, FILL_DOMAIN, FILL_WITNESS_VERSION)?;
        write_length(&mut out, packet_len)?;
        self.packet.encode_into(&mut out)?;
        write_length(&mut out, execution_len)?;
        self.execution.encode_into(&mut out)?;
        for leaf in &self.leaves { put(&mut out, leaf)?; }
        put(&mut out, &self.own_salt)?;
        put(&mut out, &[self.role as u8])?;
        put(&mut out, &self.owner_seed)?;
        write_note_blob(&mut out, &self.input)?;
        write_membership(&mut out, &self.membership)?;
        put(&mut out, &self.consent)?;
        write_owned(&mut out, &self.owned_outputs)?;
        out.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelationError> {
        let mut reader = PrivateReader::frame_version(bytes, FILL_DOMAIN,
            FILL_WITNESS_VERSION, MAX_PRIVATE_INPUT_BYTES)?;
        let packet_bytes = reader.blob(MAX_PACKET_BYTES)?;
        let execution_bytes = reader.blob(MAX_PACKET_BYTES)?;
        let leaves = [reader.array()?, reader.array()?];
        let own_salt = Zeroizing::new(reader.array::<32>()?);
        let role = reader.role()?;
        let owner_seed = Zeroizing::new(reader.array::<32>()?);
        let input_bytes = reader.blob(MAX_NOTE_BYTES)?;
        let membership = read_membership(&mut reader)?;
        let consent = Zeroizing::new(reader.array::<64>()?);
        // Exhaust the complete bounded shape before allocating or parsing private
        // note/policy records. Salt, seed and consent temporaries are guarded.
        let owned_bytes = reader.0;
        let count = reader.count(MAX_OUTPUTS)?;
        if count > reader.0.len() / 40 { return Err(RelationError::Encoding); }
        for _ in 0..count {
            reader.take(4)?;
            reader.blob(MAX_NOTE_BYTES)?;
            reader.take(32)?;
        }
        reader.finish()?;
        let packet = PublicPacket::decode(packet_bytes)?;
        let execution = FillExecution::decode(execution_bytes)?;
        let input = NoteOpening::decode(input_bytes)?;
        let mut owned_reader = PrivateReader(owned_bytes);
        let owned_outputs = read_owned(&mut owned_reader)?;
        owned_reader.finish()?;
        let witness = Self { packet, execution, leaves, own_salt: *own_salt, role,
            owner_seed: *owner_seed, input, membership, consent: *consent, owned_outputs };
        validate_private_fields(&witness.own_salt, &witness.owner_seed, &witness.input,
            &witness.owned_outputs, &witness.packet.outputs, witness.role)?;
        Ok(witness)
    }
}

impl CancelExitWitness {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RelationError> {
        if self.action == Action::Fill { return Err(RelationError::Action); }
        self.packet.validate_for(self.role)?;
        validate_private_fields(&self.blind, &self.owner_seed, &self.input,
            &self.owned_outputs, &self.packet.outputs, self.role)?;
        // The packet carries only public effects, never private policy/keys.
        let packet = self.packet.encode()?;
        let length = SINGLE_DOMAIN.len() + 2 + 4 + packet.len() + 32 + 1 + 1 + 32
            + note_blob_len(&self.input)? + MEMBERSHIP_LEN + 64
            + owned_list_len(&self.owned_outputs)?;
        let mut out = PrivateWriter::new(length)?;
        header(&mut out, SINGLE_DOMAIN)?;
        write_length(&mut out, packet.len())?;
        put(&mut out, &packet)?;
        put(&mut out, &self.blind)?;
        put(&mut out, &[self.role as u8, self.action as u8])?;
        put(&mut out, &self.owner_seed)?;
        write_note_blob(&mut out, &self.input)?;
        write_membership(&mut out, &self.membership)?;
        put(&mut out, &self.consent)?;
        write_owned(&mut out, &self.owned_outputs)?;
        out.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelationError> {
        let mut reader = PrivateReader::frame(bytes, SINGLE_DOMAIN, MAX_PRIVATE_INPUT_BYTES)?;
        let packet = SingleOwnerPacket::decode(reader.blob(MAX_PACKET_BYTES)?)?;
        let blind = Zeroizing::new(reader.array::<32>()?);
        let role = reader.role()?;
        let action = reader.action()?;
        if action == Action::Fill { return Err(RelationError::Action); }
        let owner_seed = Zeroizing::new(reader.array::<32>()?);
        let input = NoteOpening::decode(reader.blob(MAX_NOTE_BYTES)?)?;
        let membership = read_membership(&mut reader)?;
        let consent = Zeroizing::new(reader.array::<64>()?);
        let owned_outputs = read_owned(&mut reader)?;
        reader.finish()?;
        let witness = Self { packet, blind: *blind, role, action, owner_seed: *owner_seed,
            input, membership, consent: *consent, owned_outputs };
        witness.packet.validate_for(witness.role)?;
        validate_private_fields(&witness.blind, &witness.owner_seed, &witness.input,
            &witness.owned_outputs, &witness.packet.outputs, witness.role)?;
        Ok(witness)
    }
}

fn validate_private_fields(blind: &[u8; 32], seed: &[u8; 32], input: &NoteOpening,
    owned: &[PreparedOutputOpening], outputs: &[OutputDescriptor], role: Role)
    -> Result<(), RelationError>
{
    if !nonzero(blind) || !nonzero(seed) { return Err(RelationError::Key); }
    input.encoded_len()?;
    if owned.len() > MAX_OUTPUTS { return Err(RelationError::ResourceLimit); }
    if owned.windows(2).any(|pair| pair[0].manifest_index >= pair[1].manifest_index) {
        return Err(RelationError::Manifest);
    }
    for entry in owned {
        entry.note.encoded_len()?;
        if !nonzero(&entry.recovery_key) { return Err(RelationError::Key); }
        let output = outputs.get(entry.manifest_index as usize).ok_or(RelationError::Manifest)?;
        if output.role() != role || !matches!(output, OutputDescriptor::Note { .. }) {
            return Err(RelationError::Manifest);
        }
    }
    Ok(())
}

fn note_blob_len(note: &NoteOpening) -> Result<usize, RelationError> { Ok(4 + note.encoded_len()?) }
fn owned_list_len(owned: &[PreparedOutputOpening]) -> Result<usize, RelationError> {
    let mut length = 4;
    for entry in owned { length += 4 + note_blob_len(&entry.note)? + 32; }
    Ok(length)
}
fn write_note_blob(out: &mut impl Write, note: &NoteOpening) -> Result<(), RelationError> {
    write_length(out, note.encoded_len()?)?;
    note.encode_into(out)
}
fn write_owned(out: &mut impl Write, owned: &[PreparedOutputOpening]) -> Result<(), RelationError> {
    write_length(out, owned.len())?;
    for entry in owned {
        put(out, &entry.manifest_index.to_be_bytes())?;
        write_note_blob(out, &entry.note)?;
        put(out, &entry.recovery_key)?;
    }
    Ok(())
}
fn read_owned(reader: &mut PrivateReader<'_>) -> Result<Vec<PreparedOutputOpening>, RelationError> {
    let count = reader.count(MAX_OUTPUTS)?;
    // Even an invalid entry needs index, note length and key. Bound before Vec.
    if count > reader.0.len() / 40 { return Err(RelationError::Encoding); }
    let mut owned = Vec::with_capacity(count);
    for _ in 0..count {
        let manifest_index = reader.u32()?;
        let note = NoteOpening::decode(reader.blob(MAX_NOTE_BYTES)?)?;
        let recovery_key = reader.array()?;
        owned.push(PreparedOutputOpening { manifest_index, note, recovery_key });
    }
    Ok(owned)
}
fn write_membership(out: &mut impl Write, path: &MerkleMembership) -> Result<(), RelationError> {
    put(out, &path.tree_id.to_be_bytes())?;
    put(out, &path.index.to_be_bytes())?;
    for sibling in &path.siblings { put(out, sibling)?; }
    Ok(())
}
fn read_membership(reader: &mut PrivateReader<'_>) -> Result<MerkleMembership, RelationError> {
    let tree_id = reader.u32()?;
    let index = reader.u32()?;
    let mut siblings = [[0; 32]; 32];
    for sibling in &mut siblings { *sibling = reader.array()?; }
    Ok(MerkleMembership { tree_id, index, siblings })
}

fn asset_len(asset: Asset) -> usize { match asset { Asset::Native => 1, Asset::Token(_) => 21 } }
fn write_asset(out: &mut impl Write, asset: Asset) -> Result<(), RelationError> {
    match asset {
        Asset::Native => put(out, &[0]),
        Asset::Token(address) => { put(out, &[1])?; put(out, &address) }
    }
}
fn order_body_len(order: &OrderState) -> Result<usize, RelationError> {
    Ok(32 + 8 + 32 + 4 + order.policy.encoded_len()?)
}
fn write_order(out: &mut impl Write, order: &OrderState) -> Result<(), RelationError> {
    put(out, &order.id)?;
    put(out, &order.generation.to_be_bytes())?;
    write_atoms(out, order.remaining_sell)?;
    write_length(out, order.policy.encoded_len()?)?;
    order.policy.encode_into(out)?;
    Ok(())
}
fn write_note_body(out: &mut impl Write, note: &NoteOpening) -> Result<(), RelationError> {
    // Salt first: commitment uses this exact private body, not public amounts.
    for field in [&note.salt, &note.deployment_digest, &note.owner_key, &note.nf_key, &note.nonce] {
        put(out, field)?;
    }
    write_asset(out, note.asset)?;
    write_atoms(out, note.value)?;
    match &note.order {
        None => put(out, &[0]),
        Some(order) => { put(out, &[1])?; write_order(out, order) }
    }
}
fn read_order(reader: &mut PrivateReader<'_>) -> Result<OrderState, RelationError> {
    let id = Zeroizing::new(reader.array::<32>()?);
    let generation = Zeroizing::new(reader.u64()?);
    let remaining = Zeroizing::new(reader.array::<32>()?);
    let policy = OrderPolicy::decode(reader.blob(MAX_NOTE_BYTES)?)?;
    Ok(OrderState { id: *id, generation: *generation,
        remaining_sell: U256::from_big_endian(&*remaining), policy })
}
fn read_note(reader: &mut PrivateReader<'_>) -> Result<NoteOpening, RelationError> {
    // Store secrets in their erasing type before subsequent fallible parsing.
    let salt = Zeroizing::new(reader.array::<32>()?);
    let deployment_digest = reader.array()?;
    let owner_key = reader.array()?;
    let nf_key = Zeroizing::new(reader.array::<32>()?);
    let nonce = Zeroizing::new(reader.array::<32>()?);
    let mut note = NoteOpening { salt: *salt, deployment_digest, owner_key,
        nf_key: *nf_key, nonce: *nonce, asset: Asset::Native, value: U256::zero(), order: None };
    note.asset = reader.asset()?;
    note.value = reader.atoms()?;
    note.order = match reader.byte()? {
        0 => None, 1 => Some(read_order(reader)?), _ => return Err(RelationError::Encoding),
    };
    Ok(note)
}

fn put(out: &mut impl Write, bytes: &[u8]) -> Result<(), RelationError> {
    out.write_all(bytes).map_err(|_| RelationError::Encoding)
}
fn header(out: &mut impl Write, domain: &[u8]) -> Result<(), RelationError> {
    header_version(out, domain, VERSION)
}

fn header_version(out: &mut impl Write, domain: &[u8], version: u16) -> Result<(), RelationError> {
    put(out, domain)?;
    put(out, &version.to_be_bytes())
}
fn write_length(out: &mut impl Write, length: usize) -> Result<(), RelationError> {
    let length = u32::try_from(length).map_err(|_| RelationError::ResourceLimit)?;
    put(out, &length.to_be_bytes())
}
fn write_atoms(out: &mut impl Write, mut atoms: U256) -> Result<(), RelationError> {
    let mut bytes = Zeroizing::new([0; 32]);
    atoms.to_big_endian(&mut *bytes);
    atoms.0.zeroize();
    put(out, &*bytes)
}
fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain); hash.update(VERSION.to_be_bytes());
    for part in parts { hash.update(part); }
    hash.finalize().into()
}
struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes); Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

// A capacity mistake is an error, never a secret-bearing Vec reallocation.
struct PrivateWriter { bytes: Zeroizing<Vec<u8>>, length: usize }
impl PrivateWriter {
    fn new(length: usize) -> Result<Self, RelationError> {
        if length > MAX_PRIVATE_INPUT_BYTES { return Err(RelationError::ResourceLimit); }
        Ok(Self { bytes: Zeroizing::new(Vec::with_capacity(length)), length })
    }
    fn finish(self) -> Result<Zeroizing<Vec<u8>>, RelationError> {
        if self.bytes.len() != self.length { return Err(RelationError::Encoding); }
        Ok(self.bytes)
    }
}
impl Write for PrivateWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.length - self.bytes.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

struct PrivateReader<'a>(&'a [u8]);
impl<'a> PrivateReader<'a> {
    fn frame(bytes: &'a [u8], domain: &[u8], max: usize) -> Result<Self, RelationError> {
        Self::frame_version(bytes, domain, VERSION, max)
    }
    fn frame_version(bytes: &'a [u8], domain: &[u8], version: u16, max: usize)
        -> Result<Self, RelationError>
    {
        if bytes.len() > max { return Err(RelationError::ResourceLimit); }
        let mut reader = Self(bytes);
        if reader.take(domain.len())? != domain || reader.u16()? != version {
            return Err(RelationError::Encoding);
        }
        Ok(reader)
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], RelationError> {
        if length > self.0.len() { return Err(RelationError::Encoding); }
        let (front, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(front)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], RelationError> {
        self.take(N)?.try_into().map_err(|_| RelationError::Encoding)
    }
    fn byte(&mut self) -> Result<u8, RelationError> { Ok(self.array::<1>()?[0]) }
    fn u16(&mut self) -> Result<u16, RelationError> { Ok(u16::from_be_bytes(self.array()?)) }
    fn u32(&mut self) -> Result<u32, RelationError> { Ok(u32::from_be_bytes(self.array()?)) }
    fn u64(&mut self) -> Result<u64, RelationError> { Ok(u64::from_be_bytes(self.array()?)) }
    fn atoms(&mut self) -> Result<U256, RelationError> { Ok(U256::from_big_endian(self.take(32)?)) }
    fn count(&mut self, max: usize) -> Result<usize, RelationError> {
        let count = self.u32()? as usize;
        if count > max { return Err(RelationError::ResourceLimit); }
        Ok(count)
    }
    fn blob(&mut self, max: usize) -> Result<&'a [u8], RelationError> {
        let length = self.count(max)?;
        self.take(length)
    }
    fn role(&mut self) -> Result<Role, RelationError> {
        match self.byte()? { 0 => Ok(Role::A), 1 => Ok(Role::B), _ => Err(RelationError::Encoding) }
    }
    fn action(&mut self) -> Result<Action, RelationError> {
        match self.byte()? {
            0 => Ok(Action::Fill), 1 => Ok(Action::Cancel), 2 => Ok(Action::Exit),
            _ => Err(RelationError::Encoding),
        }
    }
    fn asset(&mut self) -> Result<Asset, RelationError> {
        match self.byte()? {
            0 => Ok(Asset::Native), 1 => Ok(Asset::Token(self.array()?)),
            _ => Err(RelationError::Encoding),
        }
    }
    fn finish(&self) -> Result<(), RelationError> {
        if self.0.is_empty() { Ok(()) } else { Err(RelationError::Encoding) }
    }
}

#[path = "samechain/withdrawal.rs"]
pub mod withdrawal;

#[path = "samechain/creation.rs"]
pub mod creation;
