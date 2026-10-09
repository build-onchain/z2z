use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    custody::{EnvelopeFormat, load_encrypted_with_digest, save_encrypted},
    native_quote::{AuthenticatedQuote, NativeRole, QuotePhase, QuoteSelection},
};
use super::{CapsuleLocation, ENVELOPE_DOMAIN, NativeTradeError, OperationBinding, phase_code};

const PAYLOAD_DOMAIN: &[u8] = b"ZIQUID_NATIVE_TRADE_CAPSULE\0";
const CONTEXT_DOMAIN: &[u8] = b"ZIQUID_NATIVE_TRADE_SELECTION\0";
const VERSION: u16 = 1;
const SELECTION_VERSION: u16 = 2;
const OPERATION_PURPOSE: u16 = 3;
const OPERATION_DOMAIN: &[u8] = b"ZIQUID_NATIVE_OPERATION_CAPSULE\0";
const OPERATION_BINDING_BYTES: usize = OPERATION_DOMAIN.len() + 2 + 5 * 32 + 2 + 4;
pub const MAX_OPERATION_BYTES: usize = MAX_PRIVATE_BYTES - OPERATION_BINDING_BYTES;
const MAX_QUOTE_BYTES: usize = 128 * 1024;
const MAX_PRIVATE_BYTES: usize = 96 * 1024 * 1024;
pub(super) const FORMAT: EnvelopeFormat = EnvelopeFormat {
    domain: ENVELOPE_DOMAIN,
    max_plaintext_bytes: PAYLOAD_DOMAIN.len() + 2 + 2 + 32 + 4 + MAX_PRIVATE_BYTES,
};

pub(super) fn quote_selection_digest(selection: &QuoteSelection) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CONTEXT_DOMAIN);
    hash.update(SELECTION_VERSION.to_be_bytes());
    hash.update([match selection.local_role { NativeRole::User => 0, NativeRole::Solver => 1 }]);
    for field in [&selection.owner_scope, &selection.session_id, &selection.initiator_coord_key,
        &selection.responder_coord_key, &selection.chain_context, &selection.deployment_context,
        &selection.quote_id, &selection.s_offer_id, &selection.u_trade_intent_id] {
        hash.update(field);
    }
    hash.update(selection.challenge_i);
    hash.update(selection.challenge_r);
    hash.update(selection.proposal_seq.to_be_bytes());
    hash.update(selection.user_acceptance_seq.to_be_bytes());
    hash.update(selection.solver_acceptance_seq.to_be_bytes());
    hash.finalize().into()
}

fn context(selection: [u8; 32], purpose: u16) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CONTEXT_DOMAIN);
    hash.update(VERSION.to_be_bytes());
    hash.update(selection);
    hash.update(purpose.to_be_bytes());
    hash.finalize().into()
}

pub(super) fn save_bytes(
    location: CapsuleLocation<'_>, selection: [u8; 32], purpose: u16, payload: &[u8],
) -> Result<[u8; 32], NativeTradeError> {
    if location.namespace == [0; 32] || payload.is_empty() { return Err(NativeTradeError::Binding); }
    if payload.len() > MAX_PRIVATE_BYTES { return Err(NativeTradeError::ResourceLimit); }
    let mut bytes = payload_buffer(selection, purpose, payload.len());
    bytes.extend_from_slice(payload);
    save_encrypted(location.path, location.key, location.namespace, context(selection, purpose), FORMAT, bytes)?;
    let (readback, digest) = load_bytes(location, selection, purpose, None)?;
    if !bool::from(readback.ct_eq(payload)) { return Err(NativeTradeError::Conflict); }
    Ok(digest)
}

fn payload_buffer(selection: [u8; 32], purpose: u16, payload_length: usize) -> Zeroizing<Vec<u8>> {
    // Reserve the full envelope before private filling; no growth can free a
    // previous unwiped allocation, including any downstream AEAD tag capacity.
    let length = PAYLOAD_DOMAIN.len() + 2 + 2 + 32 + 4 + payload_length;
    let mut bytes = Zeroizing::new(Vec::with_capacity(length + 16));
    bytes.extend_from_slice(PAYLOAD_DOMAIN);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&purpose.to_be_bytes());
    bytes.extend_from_slice(&selection);
    bytes.extend_from_slice(&(payload_length as u32).to_be_bytes());
    bytes
}

pub(super) fn load_bytes(
    location: CapsuleLocation<'_>, selection: [u8; 32], purpose: u16, expected: Option<[u8; 32]>,
) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), NativeTradeError> {
    if location.namespace == [0; 32] { return Err(NativeTradeError::Binding); }
    let (mut bytes, digest) = load_encrypted_with_digest(location.path, location.key,
        location.namespace, context(selection, purpose), FORMAT)?;
    if expected.is_some_and(|expected| !bool::from(digest.ct_eq(&expected))) {
        return Err(NativeTradeError::Binding);
    }
    let mut reader = Reader(&bytes);
    if reader.take(PAYLOAD_DOMAIN.len())? != PAYLOAD_DOMAIN || reader.u16()? != VERSION
        || reader.u16()? != purpose || reader.array::<32>()? != selection {
        return Err(NativeTradeError::Encoding);
    }
    let payload = reader.blob(MAX_PRIVATE_BYTES)?;
    let offset = bytes.len() - reader.0.len() - payload.len();
    let length = payload.len();
    reader.finish()?;
    use zeroize::Zeroize;
    bytes.copy_within(offset..offset + length, 0);
    bytes[length..].zeroize();
    bytes.truncate(length);
    Ok((bytes, digest))
}

pub(super) fn save_quote(
    location: CapsuleLocation<'_>, quote: &AuthenticatedQuote,
) -> Result<([u8; 32], AuthenticatedQuote), NativeTradeError> {
    let bytes = quote.encode();
    if bytes.len() > MAX_QUOTE_BYTES { return Err(NativeTradeError::ResourceLimit); }
    // The verifier-owned constructor is rerun even for an already typed input.
    let checked = AuthenticatedQuote::decode(&bytes, quote.selection()).map_err(|_| NativeTradeError::Quote)?;
    if checked.digest() != quote.digest() || checked.phase() != quote.phase() {
        return Err(NativeTradeError::Quote);
    }
    let digest = save_bytes(location, quote_selection_digest(quote.selection()), phase_code(quote.phase()) as u16, &bytes)?;
    let restored = load_quote(location, quote.selection(), quote.phase(), digest)?;
    if restored.digest() != quote.digest() || restored.agreement_digest() != quote.agreement_digest()
        || restored.proposal_hash() != quote.proposal_hash()
        || restored.user_acceptance_hash() != quote.user_acceptance_hash()
        || restored.solver_acceptance_hash() != quote.solver_acceptance_hash() {
        return Err(NativeTradeError::Conflict);
    }
    Ok((digest, restored))
}

pub(super) fn load_quote(
    location: CapsuleLocation<'_>, selection: &QuoteSelection, phase: QuotePhase, expected: [u8; 32],
) -> Result<AuthenticatedQuote, NativeTradeError> {
    let (bytes, _) = load_bytes(location, quote_selection_digest(selection), phase_code(phase) as u16, Some(expected))?;
    if bytes.len() > MAX_QUOTE_BYTES { return Err(NativeTradeError::ResourceLimit); }
    let quote = AuthenticatedQuote::decode(&bytes, selection).map_err(|_| NativeTradeError::Quote)?;
    if quote.phase() != phase { return Err(NativeTradeError::Quote); }
    Ok(quote)
}

/// Retain exact executable bytes locally; the Store still must fence their escape.
/// Nonzero pins and this digest check do not validate a financial proof or call.
pub fn save_operation_capsule(
    location: CapsuleLocation<'_>, selection: &QuoteSelection, binding: &OperationBinding, payload: &[u8],
) -> Result<[u8; 32], NativeTradeError> {
    validate_selection(selection)?;
    binding.validate()?;
    validate_payload(binding, payload)?;
    if location.namespace == [0; 32] { return Err(NativeTradeError::Binding); }
    let selection_digest = quote_selection_digest(selection);
    let mut bytes = payload_buffer(selection_digest, OPERATION_PURPOSE, OPERATION_BINDING_BYTES + payload.len());
    bytes.extend_from_slice(OPERATION_DOMAIN);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    for field in [binding.op_id, binding.context_digest, binding.deployment_digest, binding.stable_j_tag, binding.payload_digest] {
        bytes.extend_from_slice(&field);
    }
    bytes.extend_from_slice(&binding.action.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    save_encrypted(location.path, location.key, location.namespace, context(selection_digest, OPERATION_PURPOSE), FORMAT, bytes)?;
    // Digest belongs to this authenticated installed read, not a separately opened
    // raw file. The Store authenticates it again before any Released commit.
    let (readback, digest) = load_bytes(location, selection_digest, OPERATION_PURPOSE, None)?;
    let mut reader = Reader(&readback);
    if reader.take(OPERATION_DOMAIN.len())? != OPERATION_DOMAIN || reader.u16()? != VERSION { return Err(NativeTradeError::Encoding); }
    let restored = OperationBinding { op_id: reader.array()?, context_digest: reader.array()?, deployment_digest: reader.array()?,
        stable_j_tag: reader.array()?, payload_digest: reader.array()?, action: reader.u16()? };
    if restored != *binding { return Err(NativeTradeError::Binding); }
    if !bool::from(reader.blob(MAX_OPERATION_BYTES)?.ct_eq(payload)) { return Err(NativeTradeError::Conflict); }
    reader.finish()?;
    Ok(digest)
}

pub(super) fn load_operation(
    location: CapsuleLocation<'_>, selection: &QuoteSelection, expected: &OperationBinding, digest: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, NativeTradeError> {
    validate_selection(selection)?;
    expected.validate()?;
    if digest == [0; 32] { return Err(NativeTradeError::Binding); }
    let (mut bytes, _) = load_bytes(location, quote_selection_digest(selection), OPERATION_PURPOSE, Some(digest))?;
    let mut reader = Reader(&bytes);
    if reader.take(OPERATION_DOMAIN.len())? != OPERATION_DOMAIN || reader.u16()? != VERSION {
        return Err(NativeTradeError::Encoding);
    }
    let binding = OperationBinding { op_id: reader.array()?, context_digest: reader.array()?,
        deployment_digest: reader.array()?, stable_j_tag: reader.array()?, payload_digest: reader.array()?, action: reader.u16()? };
    if binding != *expected { return Err(NativeTradeError::Binding); }
    let payload = reader.blob(MAX_OPERATION_BYTES)?;
    validate_payload(expected, payload)?;
    let offset = bytes.len() - reader.0.len() - payload.len();
    let length = payload.len();
    reader.finish()?;
    use zeroize::Zeroize;
    bytes.copy_within(offset..offset + length, 0);
    bytes[length..].zeroize();
    bytes.truncate(length);
    Ok(bytes)
}

fn validate_payload(binding: &OperationBinding, payload: &[u8]) -> Result<(), NativeTradeError> {
    if payload.len() > MAX_OPERATION_BYTES { return Err(NativeTradeError::ResourceLimit); }
    if payload.is_empty() || !bool::from(binding.payload_digest.ct_eq(&<[u8; 32]>::from(Sha256::digest(payload)))) {
        return Err(NativeTradeError::Binding);
    }
    Ok(())
}

pub(super) fn validate_selection(selection: &QuoteSelection) -> Result<(), NativeTradeError> {
    crate::native_quote::validate_selection(selection).map_err(|_| NativeTradeError::Binding)
}

pub(super) struct Reader<'a>(pub(super) &'a [u8]);
impl<'a> Reader<'a> {
    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], NativeTradeError> {
        let (bytes, rest) = self.0.split_at_checked(length).ok_or(NativeTradeError::Encoding)?;
        self.0 = rest;
        Ok(bytes)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], NativeTradeError> {
        self.take(N)?.try_into().map_err(|_| NativeTradeError::Encoding)
    }
    pub(super) fn u16(&mut self) -> Result<u16, NativeTradeError> { Ok(u16::from_be_bytes(self.array()?)) }
    pub(super) fn u32(&mut self) -> Result<u32, NativeTradeError> { Ok(u32::from_be_bytes(self.array()?)) }
    pub(super) fn blob(&mut self, max: usize) -> Result<&'a [u8], NativeTradeError> {
        let length = self.u32()? as usize;
        if length > max { return Err(NativeTradeError::ResourceLimit); }
        self.take(length)
    }
    pub(super) fn finish(self) -> Result<(), NativeTradeError> {
        if self.0.is_empty() { Ok(()) } else { Err(NativeTradeError::Encoding) }
    }
}
