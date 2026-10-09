use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::node::session;

const AUTH_QUOTE_DOMAIN: &[u8] = b"Z2Z_NATIVE_AUTH_QUOTE\0";
const QUOTE_DOMAIN: &[u8] = b"Z2Z_NATIVE_QUOTE\0";
const ROUTE_DOMAIN: &[u8] = b"Z2Z_NATIVE_ROUTE\0";
const DEPLOY_DOMAIN: &[u8] = b"Z2Z_NATIVE_DEPLOY\0";
const WINDOW_DOMAIN: &[u8] = b"Z2Z_NATIVE_WINDOW\0";
const ACCEPT_DOMAIN: &[u8] = b"Z2Z_NATIVE_ACCEPT\0";
const AGREED_DOMAIN: &[u8] = b"Z2Z_NATIVE_AGREED\0";
const VERSION: u16 = 1;
const AUTH_HEADER_BYTES: usize = AUTH_QUOTE_DOMAIN.len() + 2 + (3 * 4);
pub(crate) const ACCEPT_BYTES: usize = ACCEPT_DOMAIN.len() + 2 + 1 + (32 * 5);
pub const QUOTE_BYTES: usize = 3244;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeRole {
    User = 0,
    Solver = 1,
}

impl NativeRole {
    fn from_wire(value: u8) -> Result<Self, QuoteError> {
        match value {
            0 => Ok(Self::User),
            1 => Ok(Self::Solver),
            _ => Err(QuoteError::Encoding),
        }
    }

}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotePhase {
    Proposal,
    UserAcceptance,
    Agreed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteSelection {
    pub local_role: NativeRole,
    pub owner_scope: [u8; 32],
    pub session_id: [u8; 32],
    pub initiator_coord_key: [u8; 32],
    pub responder_coord_key: [u8; 32],
    pub chain_context: [u8; 32],
    pub deployment_context: [u8; 32],
    pub quote_id: [u8; 32],
    pub s_offer_id: [u8; 32],
    pub u_trade_intent_id: [u8; 32],
    /// Independently retained confirmed-session challenges, never taken from quote bytes.
    pub challenge_i: [u8; 32],
    pub challenge_r: [u8; 32],
    /// Exact selected sender slots, including intervening session ACKs/control frames.
    pub proposal_seq: u32,
    pub user_acceptance_seq: u32,
    pub solver_acceptance_seq: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuoteError {
    Encoding,
    Selection,
    Authentication,
}

impl fmt::Display for QuoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Encoding => "native quote encoding rejected",
            Self::Selection => "native quote selection rejected",
            Self::Authentication => "native quote authentication rejected",
        })
    }
}
impl std::error::Error for QuoteError {}

/// Fixed-width coordination frame. Only its known framing fields are validated.
/// The remaining 3244-byte layout has no canonical economic schema here: it is
/// opaque, not a review of amounts, beneficiaries, native Statement commitments,
/// source validity, settlement authority, anonymity, or privacy guarantees.
#[derive(Clone, Eq, PartialEq)]
pub struct QuoteV1 {
    bytes: Zeroizing<[u8; QUOTE_BYTES]>,
}

impl fmt::Debug for QuoteV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuoteV1").field("bytes", &QUOTE_BYTES).finish()
    }
}

impl QuoteV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, QuoteError> {
        if bytes.len() != QUOTE_BYTES {
            return Err(QuoteError::Encoding);
        }
        // Validate borrowed input before copying it into guarded owner memory.
        let fixed = bytes.try_into().map_err(|_| QuoteError::Encoding)?;
        validate_quote(fixed)?;
        let mut out = Zeroizing::new([0_u8; QUOTE_BYTES]);
        out.copy_from_slice(bytes);
        Ok(Self { bytes: out })
    }

    pub fn as_bytes(&self) -> &[u8; QUOTE_BYTES] { &self.bytes }
}

impl Zeroize for QuoteV1 {
    fn zeroize(&mut self) { self.bytes.zeroize(); }
}
impl ZeroizeOnDrop for QuoteV1 {}
impl Drop for QuoteV1 {
    fn drop(&mut self) { self.zeroize(); }
}

pub struct AuthenticatedQuote {
    selection: QuoteSelection,
    proposal: Zeroizing<Vec<u8>>,
    terms: QuoteV1,
    user_acceptance: Option<Zeroizing<Vec<u8>>>,
    solver_acceptance: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for AuthenticatedQuote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedQuote")
            .field("phase", &self.phase())
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

impl AuthenticatedQuote {
    pub fn decode(bytes: &[u8], selection: &QuoteSelection) -> Result<Self, QuoteError> {
        validate_selection(selection)?;
        let mut r = Reader::new(bytes);
        if r.take(AUTH_QUOTE_DOMAIN.len())? != AUTH_QUOTE_DOMAIN
            || r.u16()? != VERSION
        {
            return Err(QuoteError::Encoding);
        }
        let proposal = r.frame()?;
        let user = r.frame()?;
        let solver = r.frame()?;
        r.finish()?;
        if proposal.is_empty() || user.is_empty() && !solver.is_empty() {
            return Err(QuoteError::Encoding);
        }

        let mut quote = Self::from_proposal(proposal, selection)?;
        if !user.is_empty() { quote = quote.with_acceptance(user)?; }
        if !solver.is_empty() { quote = quote.with_acceptance(solver)?; }
        Ok(quote)
    }

    /// Verified proposal constructor for the actual session consumer and custody restore.
    pub fn from_proposal(frame: &[u8], selection: &QuoteSelection) -> Result<Self, QuoteError> {
        validate_selection(selection)?;
        let envelope = parse_envelope(frame, selection, session::kind::NATIVE_QUOTE,
            selection.responder_coord_key, selection.proposal_seq)?;
        let terms = QuoteV1::decode(&envelope.body)?;
        if terms.bytes[19..51] != selection.quote_id || terms.bytes[51..83] != selection.s_offer_id
            || sha256(&terms.bytes[91..303]) != selection.chain_context
            || sha256(&terms.bytes[303..587]) != selection.deployment_context
        {
            return Err(QuoteError::Selection);
        }
        Ok(Self { selection: *selection, proposal: Zeroizing::new(frame.to_vec()),
            terms, user_acceptance: None, solver_acceptance: None })
    }

    /// Append exactly the next selected, genuinely signed acceptance. Errors wipe
    /// the consumed private transcript; no partly advanced quote escapes.
    pub fn with_acceptance(mut self, frame: &[u8]) -> Result<Self, QuoteError> {
        let (role, signer, sequence, predecessor) = match self.phase() {
            QuotePhase::Proposal => (NativeRole::User, self.selection.initiator_coord_key,
                self.selection.user_acceptance_seq, self.proposal_hash()),
            QuotePhase::UserAcceptance => (NativeRole::Solver, self.selection.responder_coord_key,
                self.selection.solver_acceptance_seq, self.user_acceptance_hash().ok_or(QuoteError::Encoding)?),
            QuotePhase::Agreed => return Err(QuoteError::Selection),
        };
        let envelope = parse_envelope(frame, &self.selection, session::kind::NATIVE_ACCEPTANCE, signer, sequence)?;
        let accept = parse_accept(&envelope.body)?;
        if accept.role != role || accept.quote_id != self.selection.quote_id
            || accept.q != self.digest() || accept.proposal_hash != self.proposal_hash()
            || accept.intent_id != self.selection.u_trade_intent_id || accept.predecessor != predecessor
        {
            return Err(QuoteError::Selection);
        }
        let owned = Zeroizing::new(frame.to_vec());
        match role {
            NativeRole::User => self.user_acceptance = Some(owned),
            NativeRole::Solver => self.solver_acceptance = Some(owned),
        }
        Ok(self)
    }

    /// Unsigned coordination acceptance bytes; only an explicit local caller may
    /// choose to sign them. An incoming proposal or transport ACK never does so.
    pub fn acceptance_body(&self, role: NativeRole) -> Result<Zeroizing<Vec<u8>>, QuoteError> {
        let predecessor = match (self.phase(), role) {
            (QuotePhase::Proposal, NativeRole::User) => self.proposal_hash(),
            (QuotePhase::UserAcceptance, NativeRole::Solver) => self.user_acceptance_hash().ok_or(QuoteError::Encoding)?,
            _ => return Err(QuoteError::Selection),
        };
        let mut body = Zeroizing::new(Vec::with_capacity(ACCEPT_BYTES));
        body.extend_from_slice(ACCEPT_DOMAIN);
        body.extend_from_slice(&VERSION.to_be_bytes());
        body.push(role as u8);
        for field in [self.selection.quote_id, self.digest(), self.proposal_hash(),
            self.selection.u_trade_intent_id, predecessor] { body.extend_from_slice(&field); }
        Ok(body)
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(AUTH_HEADER_BYTES + self.proposal.len()
            + self.user_acceptance.as_ref().map_or(0, |frame| frame.len())
            + self.solver_acceptance.as_ref().map_or(0, |frame| frame.len())));
        out.extend_from_slice(AUTH_QUOTE_DOMAIN);
        out.extend_from_slice(&VERSION.to_be_bytes());
        append_frame(&mut out, &self.proposal);
        append_frame(&mut out, self.user_acceptance());
        append_frame(&mut out, self.solver_acceptance());
        out
    }

    pub fn selection(&self) -> &QuoteSelection { &self.selection }
    pub fn terms(&self) -> &QuoteV1 { &self.terms }
    pub fn digest(&self) -> [u8; 32] { sha256(self.terms.as_bytes()) }
    pub fn phase(&self) -> QuotePhase {
        match (&self.user_acceptance, &self.solver_acceptance) {
            (Some(_), Some(_)) => QuotePhase::Agreed,
            (Some(_), None) => QuotePhase::UserAcceptance,
            _ => QuotePhase::Proposal,
        }
    }
    pub fn agreement_digest(&self) -> Option<[u8; 32]> {
        match (&self.user_acceptance, &self.solver_acceptance) {
            (Some(user), Some(solver)) => {
                let mut h = Sha256::new();
                h.update(AGREED_DOMAIN);
                h.update(VERSION.to_be_bytes());
                h.update(self.digest());
                h.update(sha256(&self.proposal));
                h.update(sha256(user));
                h.update(sha256(solver));
                Some(h.finalize().into())
            }
            _ => None,
        }
    }
    pub fn proposal_hash(&self) -> [u8; 32] { sha256(&self.proposal) }
    pub fn user_acceptance_hash(&self) -> Option<[u8; 32]> { self.user_acceptance.as_ref().map(|frame| sha256(frame)) }
    pub fn solver_acceptance_hash(&self) -> Option<[u8; 32]> { self.solver_acceptance.as_ref().map(|frame| sha256(frame)) }
    pub fn proposal(&self) -> &[u8] { &self.proposal }
    pub fn user_acceptance(&self) -> &[u8] { self.user_acceptance.as_ref().map_or(&[], |frame| frame.as_slice()) }
    pub fn solver_acceptance(&self) -> &[u8] { self.solver_acceptance.as_ref().map_or(&[], |frame| frame.as_slice()) }
}

impl Zeroize for AuthenticatedQuote {
    fn zeroize(&mut self) {
        self.proposal.zeroize();
        self.terms.zeroize();
        self.user_acceptance.zeroize();
        self.solver_acceptance.zeroize();
    }
}
impl ZeroizeOnDrop for AuthenticatedQuote {}
impl Drop for AuthenticatedQuote {
    fn drop(&mut self) { self.zeroize(); }
}
#[derive(Clone, Copy)]
struct ParsedAccept { role: NativeRole, quote_id: [u8; 32], q: [u8; 32], proposal_hash: [u8; 32], intent_id: [u8; 32], predecessor: [u8; 32] }

fn append_frame(out: &mut Vec<u8>, frame: &[u8]) {
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
}

fn parse_envelope(bytes: &[u8], selection: &QuoteSelection, kind: u8,
    signer: [u8; 32], sequence: u32) -> Result<session::Envelope, QuoteError> {
    // One parser for live and restored transcripts. No wall-clock freshness is
    // applied on durable restore; live admission retains the existing skew gate.
    let envelope = session::parse(bytes).map_err(|_| QuoteError::Encoding)?;
    if envelope.lane_id != 5 || envelope.kind != kind || envelope.role_map != 0
        || envelope.chain_context_digest != selection.chain_context
        || envelope.deployment_digest != selection.deployment_context
        || envelope.session_id != selection.session_id
        || envelope.initiator_coord_key != selection.initiator_coord_key
        || envelope.responder_coord_key != selection.responder_coord_key
        || envelope.challenge_i != selection.challenge_i || envelope.challenge_r != selection.challenge_r
        || envelope.seq != sequence
    {
        return Err(QuoteError::Selection);
    }
    if envelope.sent_at_unix == 0 { return Err(QuoteError::Encoding); }
    let key = VerifyingKey::from_bytes(&signer).map_err(|_| QuoteError::Authentication)?;
    key.verify_strict(&bytes[..bytes.len() - session::SIGNATURE_LEN], &Signature::from_bytes(&envelope.signature))
        .map_err(|_| QuoteError::Authentication)?;
    session::validate_body(&envelope).map_err(|_| QuoteError::Encoding)?;
    Ok(envelope)
}

fn parse_accept(body: &[u8]) -> Result<ParsedAccept, QuoteError> {
    let mut r = Reader::new(body);
    if r.take(ACCEPT_DOMAIN.len())? != ACCEPT_DOMAIN || r.u16()? != VERSION { return Err(QuoteError::Encoding); }
    let role = NativeRole::from_wire(r.u8()?)?;
    let quote_id = r.array()?;
    let q = r.array()?;
    let proposal_hash = r.array()?;
    let intent_id = r.array()?;
    let predecessor = r.array()?;
    r.finish()?;
    if quote_id == [0; 32] || q == [0; 32] || proposal_hash == [0; 32] || intent_id == [0; 32] || predecessor == [0; 32] { return Err(QuoteError::Encoding); }
    Ok(ParsedAccept { role, quote_id, q, proposal_hash, intent_id, predecessor })
}

pub(crate) fn validate_accept(body: &[u8]) -> Result<(), QuoteError> {
    parse_accept(body).map(|_| ())
}

pub(crate) fn validate_quote(bytes: &[u8; QUOTE_BYTES]) -> Result<(), QuoteError> {
    for (offset, domain) in [(0, QUOTE_DOMAIN), (91, ROUTE_DOMAIN), (303, DEPLOY_DOMAIN), (587, WINDOW_DOMAIN)] {
        if &bytes[offset..offset + domain.len()] != domain
            || bytes[offset + domain.len()..offset + domain.len() + 2] != VERSION.to_be_bytes()
        {
            return Err(QuoteError::Encoding);
        }
    }
    if bytes[19..51] == [0; 32] || bytes[51..83] == [0; 32]
        || u64::from_be_bytes(bytes[83..91].try_into().expect("fixed frame")) == 0
    {
        return Err(QuoteError::Encoding);
    }
    // Deliberately do not infer unknown economic fields or Statement commitments.
    Ok(())
}

pub(crate) fn validate_selection(selection: &QuoteSelection) -> Result<(), QuoteError> {
    for field in [&selection.owner_scope, &selection.session_id, &selection.initiator_coord_key,
        &selection.responder_coord_key, &selection.chain_context, &selection.deployment_context,
        &selection.quote_id, &selection.s_offer_id, &selection.u_trade_intent_id,
        &selection.challenge_i, &selection.challenge_r] {
        if *field == [0; 32] { return Err(QuoteError::Selection); }
    }
    if selection.initiator_coord_key == selection.responder_coord_key
        || selection.proposal_seq == 0 || selection.user_acceptance_seq < 2
        || selection.solver_acceptance_seq <= selection.proposal_seq
    {
        return Err(QuoteError::Selection);
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

struct Reader<'a> { bytes: &'a [u8] }
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes } }
    fn take(&mut self, n: usize) -> Result<&'a [u8], QuoteError> { let (v, rest) = self.bytes.split_at_checked(n).ok_or(QuoteError::Encoding)?; self.bytes = rest; Ok(v) }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], QuoteError> { self.take(N)?.try_into().map_err(|_| QuoteError::Encoding) }
    fn u8(&mut self) -> Result<u8, QuoteError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, QuoteError> { Ok(u16::from_be_bytes(self.array()?)) }
    fn u32(&mut self) -> Result<u32, QuoteError> { Ok(u32::from_be_bytes(self.array()?)) }
    fn frame(&mut self) -> Result<&'a [u8], QuoteError> { let len = self.u32()? as usize; if len > 128 * 1024 { return Err(QuoteError::Encoding); } self.take(len) }
    fn finish(self) -> Result<(), QuoteError> { if self.bytes.is_empty() { Ok(()) } else { Err(QuoteError::Encoding) } }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_terms_and_frames_have_guarded_erasure_contracts() {
        fn guarded<T: ZeroizeOnDrop>() {}
        guarded::<QuoteV1>();
        guarded::<AuthenticatedQuote>();
        let mut bytes = [0; QUOTE_BYTES];
        for (offset, domain) in [(0, QUOTE_DOMAIN), (91, ROUTE_DOMAIN), (303, DEPLOY_DOMAIN), (587, WINDOW_DOMAIN)] {
            bytes[offset..offset + domain.len()].copy_from_slice(domain);
            bytes[offset + domain.len()..offset + domain.len() + 2].copy_from_slice(&VERSION.to_be_bytes());
        }
        bytes[19..83].fill(1);
        bytes[90] = 1;
        let mut terms = QuoteV1::decode(&bytes).unwrap();
        terms.zeroize();
        assert!(terms.as_bytes().iter().all(|byte| *byte == 0));
        // Every owned frame uses this allocation guard, including error exits.
        let frames: [Zeroizing<Vec<u8>>; 3] = std::array::from_fn(|_| Zeroizing::new(vec![42; 8]));
        for mut frame in frames {
            frame.zeroize();
            assert!(frame.iter().all(|byte| *byte == 0));
        }
    }
}
