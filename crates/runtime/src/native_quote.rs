use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

const SESSION_DOMAIN: &[u8] = b"Z2Z_SESSION\0";
const AUTH_QUOTE_DOMAIN: &[u8] = b"Z2Z_NATIVE_AUTH_QUOTE\0";
const QUOTE_DOMAIN: &[u8] = b"Z2Z_NATIVE_QUOTE\0";
const ROUTE_DOMAIN: &[u8] = b"Z2Z_NATIVE_ROUTE\0";
const DEPLOY_DOMAIN: &[u8] = b"Z2Z_NATIVE_DEPLOY\0";
const WINDOW_DOMAIN: &[u8] = b"Z2Z_NATIVE_WINDOW\0";
const ACCEPT_DOMAIN: &[u8] = b"Z2Z_NATIVE_ACCEPT\0";
const AGREED_DOMAIN: &[u8] = b"Z2Z_NATIVE_AGREED\0";
const VERSION: u16 = 1;
const AUTH_HEADER_BYTES: usize = AUTH_QUOTE_DOMAIN.len() + 2 + (3 * 4);
const ENVELOPE_HEADER_BYTES: usize = SESSION_DOMAIN.len() + 2 + 2 + (5 * 32) + 1 + (2 * 32) + 4 + 1 + 8 + 4;
const SIGNATURE_BYTES: usize = 64;
const ACCEPT_BYTES: usize = ACCEPT_DOMAIN.len() + 2 + 1 + (32 * 5);
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

/// The canonical, fixed-width quote body. It intentionally exposes no financial
/// authority: this is a signed coordination terms frame only.
#[derive(Clone, Eq, PartialEq)]
pub struct QuoteV1 {
    bytes: [u8; QUOTE_BYTES],
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
        let mut out = [0_u8; QUOTE_BYTES];
        out.copy_from_slice(bytes);
        validate_quote(&out)?;
        Ok(Self { bytes: out })
    }

    pub fn as_bytes(&self) -> &[u8; QUOTE_BYTES] { &self.bytes }
}

pub struct AuthenticatedQuote {
    selection: QuoteSelection,
    proposal: Vec<u8>,
    terms: QuoteV1,
    user_acceptance: Option<Vec<u8>>,
    solver_acceptance: Option<Vec<u8>>,
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

        let p = parse_envelope(proposal, selection, Kind::Proposal, proposal_signer(*selection))?;
        let terms = QuoteV1::decode(p.body)?;
        if terms.bytes[19..51] != selection.quote_id || terms.bytes[51..83] != selection.s_offer_id {
            return Err(QuoteError::Selection);
        }
        let route = &terms.bytes[91..303];
        let deploy = &terms.bytes[303..587];
        if sha256(route) != selection.chain_context || sha256(deploy) != selection.deployment_context {
            return Err(QuoteError::Selection);
        }
        let q = sha256(terms.as_bytes());
        let proposal_hash = sha256(proposal);

        let mut user_acceptance = None;
        let mut solver_acceptance = None;
        if !user.is_empty() {
            let a = parse_envelope(user, selection, Kind::Acceptance, selection.initiator_coord_key)?;
            let accept = parse_accept(a.body)?;
            if accept.role != NativeRole::User
                || accept.quote_id != selection.quote_id
                || accept.q != q
                || accept.proposal_hash != proposal_hash
                || accept.intent_id != selection.u_trade_intent_id
                || accept.predecessor != proposal_hash
            {
                return Err(QuoteError::Selection);
            }
            user_acceptance = Some(user.to_vec());
        }
        if !solver.is_empty() {
            let a = parse_envelope(solver, selection, Kind::Acceptance, selection.responder_coord_key)?;
            let accept = parse_accept(a.body)?;
            let user_hash = user_acceptance.as_deref().map(sha256).ok_or(QuoteError::Encoding)?;
            if accept.role != NativeRole::Solver
                || accept.quote_id != selection.quote_id
                || accept.q != q
                || accept.proposal_hash != proposal_hash
                || accept.intent_id != selection.u_trade_intent_id
                || accept.predecessor != user_hash
            {
                return Err(QuoteError::Selection);
            }
            solver_acceptance = Some(solver.to_vec());
        }
        if (user_acceptance.is_some() || solver_acceptance.is_some()) && selection.u_trade_intent_id == [0; 32] {
            return Err(QuoteError::Selection);
        }
        Ok(Self {
            selection: *selection,
            proposal: proposal.to_vec(),
            terms,
            user_acceptance,
            solver_acceptance,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTH_HEADER_BYTES + self.proposal.len() + self.user_acceptance.as_ref().map_or(0, Vec::len) + self.solver_acceptance.as_ref().map_or(0, Vec::len) + 12);
        out.extend_from_slice(AUTH_QUOTE_DOMAIN);
        out.extend_from_slice(&VERSION.to_be_bytes());
        append_frame(&mut out, &self.proposal);
        append_frame(&mut out, self.user_acceptance.as_deref().unwrap_or(&[]));
        append_frame(&mut out, self.solver_acceptance.as_deref().unwrap_or(&[]));
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
    pub fn user_acceptance_hash(&self) -> Option<[u8; 32]> { self.user_acceptance.as_deref().map(sha256) }
    pub fn solver_acceptance_hash(&self) -> Option<[u8; 32]> { self.solver_acceptance.as_deref().map(sha256) }
}

#[derive(Clone, Copy)]
struct ParsedEnvelope<'a> { body: &'a [u8] }
#[derive(Clone, Copy)]
struct ParsedAccept { role: NativeRole, quote_id: [u8; 32], q: [u8; 32], proposal_hash: [u8; 32], intent_id: [u8; 32], predecessor: [u8; 32] }
#[derive(Clone, Copy)]
enum Kind { Proposal, Acceptance }

fn proposal_signer(selection: QuoteSelection) -> [u8; 32] { selection.responder_coord_key }

fn append_frame(out: &mut Vec<u8>, frame: &[u8]) {
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
}

fn parse_envelope<'a>(bytes: &'a [u8], selection: &QuoteSelection, kind: Kind, signer: [u8; 32]) -> Result<ParsedEnvelope<'a>, QuoteError> {
    if bytes.len() < ENVELOPE_HEADER_BYTES + SIGNATURE_BYTES || &bytes[..SESSION_DOMAIN.len()] != SESSION_DOMAIN {
        return Err(QuoteError::Encoding);
    }
    let mut r = Reader::new(bytes);
    if r.take(SESSION_DOMAIN.len())? != SESSION_DOMAIN || r.u16()? != VERSION || r.u16()? != 5 {
        return Err(QuoteError::Selection);
    }
    if r.take(32)? != selection.chain_context || r.take(32)? != selection.deployment_context || r.take(32)? != selection.session_id
        || r.take(32)? != selection.initiator_coord_key || r.take(32)? != selection.responder_coord_key || r.u8()? != 0
    { return Err(QuoteError::Selection); }
    if r.take(32)? == &[0; 32] || r.take(32)? == &[0; 32] { return Err(QuoteError::Encoding); }
    let seq = r.u32()?;
    let expected_kind = match kind { Kind::Proposal => 13, Kind::Acceptance => 14 };
    if r.u8()? != expected_kind || r.u64()? == 0 { return Err(QuoteError::Encoding); }
    let body_len = r.u32()? as usize;
    let expected_body = match kind { Kind::Proposal => QUOTE_BYTES, Kind::Acceptance => ACCEPT_BYTES };
    if body_len != expected_body || bytes.len() != ENVELOPE_HEADER_BYTES + body_len + SIGNATURE_BYTES || (matches!(kind, Kind::Proposal) && seq != 1) || (matches!(kind, Kind::Acceptance) && seq != 2) {
        return Err(QuoteError::Encoding);
    }
    let body = r.take(body_len)?;
    let signature = r.take(SIGNATURE_BYTES)?;
    r.finish()?;
    let key = VerifyingKey::from_bytes(&signer).map_err(|_| QuoteError::Authentication)?;
    key.verify_strict(&bytes[..ENVELOPE_HEADER_BYTES + body_len], &Signature::from_bytes(signature.try_into().map_err(|_| QuoteError::Encoding)?)).map_err(|_| QuoteError::Authentication)?;
    Ok(ParsedEnvelope { body })
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

fn validate_quote(bytes: &[u8; QUOTE_BYTES]) -> Result<(), QuoteError> {
    if &bytes[..QUOTE_DOMAIN.len()] != QUOTE_DOMAIN
        || u16::from_be_bytes(bytes[QUOTE_DOMAIN.len()..QUOTE_DOMAIN.len() + 2].try_into().unwrap()) != VERSION
    { return Err(QuoteError::Encoding); }
    if &bytes[91..91 + ROUTE_DOMAIN.len()] != ROUTE_DOMAIN
        || &bytes[303..303 + DEPLOY_DOMAIN.len()] != DEPLOY_DOMAIN
        || &bytes[587..587 + WINDOW_DOMAIN.len()] != WINDOW_DOMAIN
    { return Err(QuoteError::Encoding); }
    if bytes[19..51] == [0; 32] || bytes[51..83] == [0; 32]
        || u64::from_be_bytes(bytes[83..91].try_into().unwrap()) == 0
    { return Err(QuoteError::Encoding); }
    Ok(())
}

fn validate_selection(selection: &QuoteSelection) -> Result<(), QuoteError> {
    for field in [&selection.owner_scope, &selection.session_id, &selection.initiator_coord_key, &selection.responder_coord_key, &selection.chain_context, &selection.deployment_context, &selection.quote_id, &selection.s_offer_id, &selection.u_trade_intent_id] {
        if *field == [0; 32] { return Err(QuoteError::Selection); }
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
    fn u64(&mut self) -> Result<u64, QuoteError> { Ok(u64::from_be_bytes(self.array()?)) }
    fn frame(&mut self) -> Result<&'a [u8], QuoteError> { let len = self.u32()? as usize; if len > 128 * 1024 { return Err(QuoteError::Encoding); } self.take(len) }
    fn finish(self) -> Result<(), QuoteError> { if self.bytes.is_empty() { Ok(()) } else { Err(QuoteError::Encoding) } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signed_proposal_decodes_and_round_trips() {
        let solver = SigningKey::from_bytes(&[4; 32]);
        let initiator = SigningKey::from_bytes(&[3; 32]);
        let mut quote = [0_u8; QUOTE_BYTES];
        quote[..QUOTE_DOMAIN.len()].copy_from_slice(QUOTE_DOMAIN);
        quote[QUOTE_DOMAIN.len()..QUOTE_DOMAIN.len() + 2].copy_from_slice(&VERSION.to_be_bytes());
        quote[19..51].copy_from_slice(&[8; 32]);
        quote[51..83].copy_from_slice(&[9; 32]);
        quote[83..91].copy_from_slice(&1_791_504_000_u64.to_be_bytes());
        quote[91..91 + ROUTE_DOMAIN.len()].copy_from_slice(ROUTE_DOMAIN);
        quote[91 + ROUTE_DOMAIN.len()..91 + ROUTE_DOMAIN.len() + 2].copy_from_slice(&VERSION.to_be_bytes());
        quote[303..303 + DEPLOY_DOMAIN.len()].copy_from_slice(DEPLOY_DOMAIN);
        quote[303 + DEPLOY_DOMAIN.len()..303 + DEPLOY_DOMAIN.len() + 2].copy_from_slice(&VERSION.to_be_bytes());
        quote[587..587 + WINDOW_DOMAIN.len()].copy_from_slice(WINDOW_DOMAIN);
        quote[587 + WINDOW_DOMAIN.len()..587 + WINDOW_DOMAIN.len() + 2].copy_from_slice(&VERSION.to_be_bytes());
        let chain_context = sha256(&quote[91..303]);
        let deployment_context = sha256(&quote[303..587]);
        let selection = QuoteSelection {
            local_role: NativeRole::User,
            owner_scope: [1; 32], session_id: [2; 32],
            initiator_coord_key: *initiator.verifying_key().as_bytes(),
            responder_coord_key: *solver.verifying_key().as_bytes(),
            chain_context, deployment_context,
            quote_id: [8; 32], s_offer_id: [9; 32], u_trade_intent_id: [10; 32],
        };
        let mut proposal = Vec::new();
        proposal.extend_from_slice(SESSION_DOMAIN);
        proposal.extend_from_slice(&VERSION.to_be_bytes());
        proposal.extend_from_slice(&5_u16.to_be_bytes());
        for field in [selection.chain_context, selection.deployment_context, selection.session_id,
            selection.initiator_coord_key, selection.responder_coord_key] { proposal.extend_from_slice(&field); }
        proposal.push(0);
        proposal.extend_from_slice(&[11; 32]); proposal.extend_from_slice(&[12; 32]);
        proposal.extend_from_slice(&1_u32.to_be_bytes()); proposal.push(13);
        proposal.extend_from_slice(&1_791_504_000_u64.to_be_bytes());
        proposal.extend_from_slice(&(QUOTE_BYTES as u32).to_be_bytes());
        proposal.extend_from_slice(&quote);
        proposal.extend_from_slice(&solver.sign(&proposal).to_bytes());
        let mut bundle = Vec::new();
        bundle.extend_from_slice(AUTH_QUOTE_DOMAIN);
        bundle.extend_from_slice(&VERSION.to_be_bytes());
        append_frame(&mut bundle, &proposal);
        append_frame(&mut bundle, &[]);
        append_frame(&mut bundle, &[]);
        let decoded = AuthenticatedQuote::decode(&bundle, &selection).expect("signed proposal");
        assert_eq!(decoded.encode(), bundle);
        assert_eq!(decoded.phase(), QuotePhase::Proposal);
        assert_eq!(decoded.digest(), sha256(&quote));
        assert_eq!(decoded.proposal_hash(), sha256(&proposal));
        assert_eq!(decoded.user_acceptance_hash(), None);
        assert_eq!(decoded.solver_acceptance_hash(), None);
    }
}
