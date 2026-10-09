//! `/z2z/session/1` direct bilateral session wire: the P0.07 owner-frozen
//! envelope (docs/V1-P2P-PROTOCOL-SPEC.md §7.2) over a custom
//! `request_response::Codec`.
//!
//! Wire form per stream: one `u32BE(length) || envelope`, then EOF; `length`
//! excludes the four-byte prefix and includes the trailing signature. The
//! envelope layout, kind bytes, role map and hard size caps follow §7.2
//! exactly; anything else is a codec error before any allocation beyond the
//! bounded read buffer.
//!
//! Signature verification is intentionally NOT part of the codec: the codec is
//! transport framing only. Envelope authentication happens in
//! `session::validate` against the dialer's expected Ed25519 coordination key,
//! before any caller-visible effect.
//!
//! ponytail: canonical fixed-width header + bounded body read; no incremental
//! parser. A streaming parser buys nothing at a 128 KiB envelope ceiling.

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use zeroize::Zeroizing;
use std::io;

/// Exact negotiated protocol id (§7.2).
pub(crate) const PROTOCOL_ID: &str = "/z2z/session/1";
/// Hard per-envelope cap from §7.3 framing: 128 KiB envelope, 4-byte prefix.
pub(crate) const MAX_ENVELOPE_BYTES: usize = 131_076;
/// Domain separator; signed bytes start here (§7.2).
pub(crate) const DOMAIN: &[u8] = b"Z2Z_SESSION\0";
/// Current schema version.
pub(crate) const SCHEMA_VERSION: u16 = 1;

/// Header is everything before `body` (see §7.2 grammar).
pub(crate) const HEADER_LEN: usize = DOMAIN.len() + 2 + 2
    + 32 /* chain_context */ + 32 /* deployment */ + 32 /* session */
    + 32 /* initiator_key */ + 32 /* responder_key */ + 1 /* role_map */
    + 32 + 32 /* challenges */ + 4 /* seq */ + 1 /* kind */
    + 8 /* sent_at */ + 4 /* body_len */;
// Ed25519 signature over DOMAIN..body (§7.2).
const _: () = {
    let domain = 12usize;
    let header = domain + 2 + 2 + 32 + 32 + 32 + 32 + 32 + 1 + 32 + 32 + 4 + 1 + 8 + 4;
    assert!(header == HEADER_LEN, "header mismatch");
};

pub(crate) const SIGNATURE_LEN: usize = 64;

/// §7.2 kind bytes and their exact maximum complete-envelope sizes.
pub(crate) mod kind {
    pub(crate) const HELLO: u8 = 0;
    pub(crate) const BACKING_CHALLENGE: u8 = 1;
    pub(crate) const BACKING_CLAIM: u8 = 2;
    pub(crate) const TERMS: u8 = 3;
    pub(crate) const DESCRIPTORS: u8 = 4;
    pub(crate) const LEAF: u8 = 5;
    pub(crate) const PACKET_DIGEST_ACK: u8 = 6;
    pub(crate) const CERTIFICATE: u8 = 7;
    pub(crate) const ABORT: u8 = 8;
    pub(crate) const ACK: u8 = 9;
    // DKG kinds — owner-approved amendment 2026-10-07 (§12.1 of the settlement
    // research, applied to the P2P spec §7.2).
    pub(crate) const DKG_ROUND1: u8 = 10;
    pub(crate) const DKG_ROUND2: u8 = 11;
    pub(crate) const DKG_FINAL_COMMIT: u8 = 12;

    /// Maximum complete envelope bytes per kind (§7.2 table), prefix excluded.
    pub(crate) fn max_envelope(kind: u8) -> usize {
        match kind {
            HELLO => 322,
            BACKING_CHALLENGE => 362,
            BACKING_CLAIM => 4096,
            TERMS => 131_072,
            DESCRIPTORS => 131_072,
            LEAF => 355,
            PACKET_DIGEST_ACK => 386,
            CERTIFICATE => 1742,
            ABORT => 323,
            ACK => 354,
            DKG_ROUND1 => 512,
            DKG_ROUND2 => 512,
            DKG_FINAL_COMMIT => 354,
            _ => 0,
        }
    }
}

/// Decoded session envelope. `body` is validated kind-by-kind by callers via
/// [`validate_body`]; the codec guarantees only framing and header invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    pub lane_id: u16,
    pub chain_context_digest: [u8; 32],
    pub deployment_digest: [u8; 32],
    pub session_id: [u8; 32],
    pub initiator_coord_key: [u8; 32],
    pub responder_coord_key: [u8; 32],
    /// 0 => initiator role A, 1 => initiator role B; other values reject.
    pub role_map: u8,
    pub challenge_i: [u8; 32],
    pub challenge_r: [u8; 32],
    pub seq: u32,
    pub kind: u8,
    pub sent_at_unix: u64,
    pub body: Vec<u8>,
    pub signature: [u8; 64],
}

/// Advisory coordination timestamp gate: reject beyond ±300s (§7).
pub(crate) const MAX_TIMESTAMP_SKEW: u64 = 300;

/// Random nonzero 32 bytes for responder challenges (§7.2).
#[cfg(target_os = "linux")]
pub(crate) fn fresh_nonce() -> [u8; 32] {
    use rand_core::OsRng;
    use rand_core::RngCore;
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    if nonce == [0_u8; 32] {
        nonce[0] = 1;
    }
    nonce
}

impl Envelope {
    /// SHA256 over the complete envelope as received (§7 dedup key).
    pub(crate) fn sha256(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let bytes = Zeroizing::new(self.signed_bytes());
        let mut hasher = Sha256::new();
        hasher.update(bytes.as_slice());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    /// SHA256 over the signed bytes only — the §7.2 `Ack` body convention
    /// (the acknowledged signed envelope; the dedup key [`Envelope::sha256`]
    /// covers the signature as well).
    pub(crate) fn ack_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(Zeroizing::new(self.signed_bytes()).as_slice()).into()
    }

    /// Bytes covered by the signature: DOMAIN through body (§7.2).
    pub(crate) fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len());
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.schema_bytes());
        out.extend_from_slice(&self.header_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    fn schema_bytes(&self) -> [u8; 2] {
        SCHEMA_VERSION.to_be_bytes()
    }

    fn header_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN - DOMAIN.len() - 2);
        out.extend_from_slice(&self.lane_id.to_be_bytes());
        out.extend_from_slice(&self.chain_context_digest);
        out.extend_from_slice(&self.deployment_digest);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.initiator_coord_key);
        out.extend_from_slice(&self.responder_coord_key);
        out.push(self.role_map);
        out.extend_from_slice(&self.challenge_i);
        out.extend_from_slice(&self.challenge_r);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.kind);
        out.extend_from_slice(&self.sent_at_unix.to_be_bytes());
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        out
    }

    /// Serialize into the canonical wire form (signature included).
    pub(crate) fn to_wire(&self) -> Result<Vec<u8>, io::Error> {
        let cap = kind::max_envelope(self.kind);
        let total = HEADER_LEN + self.body.len() + SIGNATURE_LEN;
        if cap == 0 || total > cap || total > MAX_ENVELOPE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "envelope exceeds kind cap"));
        }
        let mut out = Vec::with_capacity(4 + total);
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(Zeroizing::new(self.signed_bytes()).as_slice());
        out.extend_from_slice(&self.signature);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WireError {
    Truncated,
    BadSignature,
    StaleTimestamp,
    SessionFull,
    Oversize,
    BadDomain,
    BadSchema,
    BadRoleMap,
    BodyLengthMismatch,
    TrailingBytes,
    /// §7.2 bootstrap Hello violated its shape (seq/body/zero fields/lane).
    BootstrapMalformed,
    /// Hello is bootstrap-only; it cannot be a response or later request.
    UnexpectedHello,
    /// Established message for a session id this node does not hold.
    UnknownSession,
    /// Session exists but under a different transport peer.
    PeerMismatch,
    /// A frozen §7.2 pin changed; the negotiation ends.
    PinnedFieldChanged,
    /// Not the strictly next seq from that sender (no wrap).
    OutOfSequence,
    /// Financial/private kind before the initiator confirmed the transcript.
    Unconfirmed,
    /// §7.3 session limits: 4 global, 1 per PeerId including Hello.
    SessionLimit,
    /// Fresh-J DKG ceremony failure (state or crypto); never proceeds.
    Dkg,
}

/// Parse one complete envelope (already length-prefixed read). Applies every
/// §7.2 invariant that needs only the bytes themselves.
pub(crate) fn parse(bytes: &[u8]) -> Result<Envelope, WireError> {
    if bytes.len() < HEADER_LEN + SIGNATURE_LEN {
        return Err(WireError::Truncated);
    }
    if &bytes[..DOMAIN.len()] != DOMAIN {
        return Err(WireError::BadDomain);
    }
    let schema = u16::from_be_bytes([bytes[DOMAIN.len()], bytes[DOMAIN.len() + 1]]);
    if schema != SCHEMA_VERSION {
        return Err(WireError::BadSchema);
    }
    let mut cursor = DOMAIN.len() + 2;
    let take = |cursor: &mut usize, n: usize| -> &[u8] {
        let slice = &bytes[*cursor..*cursor + n];
        *cursor += n;
        slice
    };
    let lane_id = u16::from_be_bytes(take(&mut cursor, 2).try_into().expect("fixed"));
    let mut chain_context_digest = [0_u8; 32];
    chain_context_digest.copy_from_slice(take(&mut cursor, 32));
    let mut deployment_digest = [0_u8; 32];
    deployment_digest.copy_from_slice(take(&mut cursor, 32));
    let mut session_id = [0_u8; 32];
    session_id.copy_from_slice(take(&mut cursor, 32));
    let mut initiator_coord_key = [0_u8; 32];
    initiator_coord_key.copy_from_slice(take(&mut cursor, 32));
    let mut responder_coord_key = [0_u8; 32];
    responder_coord_key.copy_from_slice(take(&mut cursor, 32));
    let role_map = take(&mut cursor, 1)[0];
    let mut challenge_i = [0_u8; 32];
    challenge_i.copy_from_slice(take(&mut cursor, 32));
    let mut challenge_r = [0_u8; 32];
    challenge_r.copy_from_slice(take(&mut cursor, 32));
    let seq = u32::from_be_bytes(take(&mut cursor, 4).try_into().expect("fixed"));
    let kind = take(&mut cursor, 1)[0];
    let sent_at_unix = u64::from_be_bytes(take(&mut cursor, 8).try_into().expect("fixed"));
    let body_len = u32::from_be_bytes(take(&mut cursor, 4).try_into().expect("fixed")) as usize;
    if role_map > 1 {
        return Err(WireError::BadRoleMap);
    }
    let cap = kind::max_envelope(kind);
    let total = HEADER_LEN + body_len + SIGNATURE_LEN;
    if cap == 0 || total > cap || total > MAX_ENVELOPE_BYTES {
        return Err(WireError::Oversize);
    }
    if bytes.len() < total {
        return Err(WireError::Truncated);
    }
    if bytes.len() != total {
        return Err(WireError::TrailingBytes);
    }
    let body = bytes[cursor..cursor + body_len].to_vec();
    cursor += body_len;
    let mut signature = [0_u8; 64];
    signature.copy_from_slice(&bytes[cursor..cursor + SIGNATURE_LEN]);
    Ok(Envelope {
        lane_id,
        chain_context_digest,
        deployment_digest,
        session_id,
        initiator_coord_key,
        responder_coord_key,
        role_map,
        challenge_i,
        challenge_r,
        seq,
        kind,
        sent_at_unix,
        body,
        signature,
    })
}

/// Frozen §7.2 pins of one session, plus the role facts a driver needs to build
/// a response envelope: pins are copied verbatim and the local seq is consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundPins {
    pub lane_id: u16,
    pub chain_context_digest: [u8; 32],
    pub deployment_digest: [u8; 32],
    pub session_id: [u8; 32],
    pub initiator_coord_key: [u8; 32],
    pub responder_coord_key: [u8; 32],
    pub role_map: u8,
    pub challenge_i: [u8; 32],
    pub challenge_r: [u8; 32],
}

/// Responder-side fresh-J DKG ceremony state (§12.1 rules, kinds 10-12).
/// Lives inside the session record, so it is bounded by the ≤4 session limit
/// and dies with the session. Holds only secret material the ceremony
/// requires: the round-1 secret (§12.1 rule 3 requires DKGRound2 bodies to be
/// session-memory only) and, after finalize, this side's key share.
struct DkgState {
    session: Option<ziquid_threshold::DkgSession>,
    peer_round1: Option<Vec<u8>>,
    /// `SHA256(PublicKeyPackage)` once finalized.
    commit: Option<[u8; 32]>,
    key_share: Option<ziquid_threshold::KeyShare>,
}

impl DkgState {
    fn new() -> Self {
        Self {
            session: None,
            peer_round1: None,
            commit: None,
            key_share: None,
        }
    }
}

impl SessionTable {
    /// Frozen pins + the next outbound seq (consumed) for a session response.
    pub(crate) fn begin_outbound(
        &mut self,
        peer: &libp2p::PeerId,
        session_id: &[u8; 32],
    ) -> Result<(OutboundPins, u32), WireError> {
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.peer == *peer && &session.session_id == session_id)
            .ok_or(WireError::UnknownSession)?;
        let seq = session.next_local_seq;
        session.next_local_seq = session
            .next_local_seq
            .checked_add(1)
            .ok_or(WireError::OutOfSequence)?;
        Ok((
            OutboundPins {
                lane_id: session.lane_id,
                chain_context_digest: session.chain_context_digest,
                deployment_digest: session.deployment_digest,
                session_id: session.session_id,
                initiator_coord_key: session.initiator_coord_key,
                responder_coord_key: session.responder_coord_key,
                role_map: session.role_map,
                challenge_i: session.challenge_i,
                challenge_r: session.challenge_r,
            },
            seq,
        ))
    }

    /// §12.1 kind 10, responder side: start the ceremony (no peer data yet)
    /// and return our round-1 package bytes. Only a confirmed session reaches
    /// here (inbound gate): the responder's first private DKG step happens
    /// strictly after the initiator's transcript-confirming Ack.
    pub(crate) fn dkg_start<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        peer: &libp2p::PeerId,
        session_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<Zeroizing<Vec<u8>>, WireError> {
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.peer == *peer && &session.session_id == session_id)
            .ok_or(WireError::UnknownSession)?;
        if !session.confirmed || session.dkg.is_some() || session.dkg_started {
            return Err(WireError::Dkg);
        }
        // The session responder is FROST participant First (fixed demo
        // mapping; the financial role binding arrives with the quote layer).
        let (dkg, round1) =
            ziquid_threshold::DkgSession::start(ziquid_threshold::Participant::First, rng)
                .map_err(|_| WireError::Dkg)?;
        let mut state = DkgState::new();
        state.session = Some(dkg);
        session.dkg = Some(state);
        session.dkg_started = true;
        Ok(Zeroizing::new(round1))
    }

    /// §12.1 kind 11, responder side: absorb the peer's round-1 package and
    /// return our round-2 package (a per-recipient secret).
    pub(crate) fn dkg_round1_in(
        &mut self,
        peer: &libp2p::PeerId,
        session_id: &[u8; 32],
        peer_round1: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, WireError> {
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.peer == *peer && &session.session_id == session_id)
            .ok_or(WireError::UnknownSession)?;
        let state = session.dkg.as_mut().ok_or(WireError::Dkg)?;
        if state.peer_round1.is_some() {
            return Err(WireError::Dkg);
        }
        let dkg = state.session.as_mut().ok_or(WireError::Dkg)?;
        let round2 = dkg.round2(peer_round1).map_err(|_| WireError::Dkg)?;
        state.peer_round1 = Some(peer_round1.to_vec());
        Ok(round2)
    }

    /// §12.1 kind 12, responder side: absorb the peer's round-2 package,
    /// finalize, and return our `SHA256(PublicKeyPackage)` digest.
    pub(crate) fn dkg_round2_in(
        &mut self,
        peer: &libp2p::PeerId,
        session_id: &[u8; 32],
        peer_round2: &[u8],
    ) -> Result<[u8; 32], WireError> {
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.peer == *peer && &session.session_id == session_id)
            .ok_or(WireError::UnknownSession)?;
        let state = session.dkg.as_mut().ok_or(WireError::Dkg)?;
        if state.commit.is_some() {
            return Err(WireError::Dkg);
        }
        let dkg = state.session.take().ok_or(WireError::Dkg)?;
        let peer_round1 = state.peer_round1.as_deref().ok_or(WireError::Dkg)?;
        let peer_round2 = Zeroizing::new(peer_round2.to_vec());
        let (key_share, group) = dkg
            .finalize(peer_round1, &peer_round2)
            .map_err(|_| WireError::Dkg)?;
        let commit = public_key_package_digest(&group);
        drop(peer_round2);
        drop(group);
        state.commit = Some(commit);
        state.key_share = Some(key_share);
        Ok(commit)
    }


    /// §12.1 rule 5: record the peer's kind-12 digest; a mismatch is a
    /// ceremony failure (never proceed to signing sessions).
    pub(crate) fn dkg_accept_commit(
        &mut self,
        peer: &libp2p::PeerId,
        session_id: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<(), WireError> {
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.peer == *peer && &session.session_id == session_id)
            .ok_or(WireError::UnknownSession)?;
        let state = session.dkg.as_mut().ok_or(WireError::Dkg)?;
        if state.commit != Some(*digest) {
            return Err(WireError::Dkg);
        }
        session.dkg = None;
        Ok(())
    }

    /// Store the built response envelope for an answered DKG request so an
    /// exact retry re-sends byte-identical bytes.
    pub(crate) fn dkg_store_response(
        &mut self,
        peer: &libp2p::PeerId,
        session_id: &[u8; 32],
        request_digest: [u8; 32],
        response: Vec<u8>,
    ) -> Result<(), WireError> {
        let response = Zeroizing::new(response);
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.peer == *peer && &session.session_id == session_id)
            .ok_or(WireError::UnknownSession)?;
        if session.answered.len() >= 5 || response.len() > kind::max_envelope(kind::DKG_ROUND1) {
            return Err(WireError::Dkg);
        }
        session.answered.push((request_digest, response));
        Ok(())
    }

    /// Look up the stored response for an exact retry of a DKG request.
    pub(crate) fn dkg_retry_response(
        &self,
        peer: &libp2p::PeerId,
        session_id: &[u8; 32],
        request_digest: &[u8; 32],
    ) -> Option<Vec<u8>> {
        self.sessions
            .iter()
            .find(|session| session.peer == *peer && &session.session_id == session_id)
            .and_then(|session| {
                session
                    .answered
                    .iter()
                    .find(|(digest, _)| digest == request_digest)
                    .map(|(_, response)| response.to_vec())
            })
    }
}

/// §12.1 rule 5 digest of a cohort `PublicKeyPackage`.
fn public_key_package_digest(group: &ziquid_threshold::GroupPublicKey) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(group.to_bytes()).into()
}

/// §7.2 DKG kinds rule 6: canonical context digest binding a DKG ceremony to
/// the session, lane, context and the frozen pool/J parameters.
/// `SHA256("Z2Z_DKG_CTX\0" || lane:u16BE || session_id || initiator_key ||
/// responder_key || chain_context_digest || pool_id || j_param_bytes)`.
/// The receiver must recompute and compare it on kinds 10–12 and abort with
/// reason 1 on mismatch.
pub(crate) fn dkg_context_digest(
    lane_id: u16,
    session_id: &[u8; 32],
    initiator_coord_key: &[u8; 32],
    responder_coord_key: &[u8; 32],
    chain_context_digest: &[u8; 32],
    pool_id: u8,
    j_param_bytes: &[u8],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"Z2Z_DKG_CTX\0");
    hasher.update(lane_id.to_be_bytes());
    hasher.update(session_id);
    hasher.update(initiator_coord_key);
    hasher.update(responder_coord_key);
    hasher.update(chain_context_digest);
    hasher.update([pool_id]);
    hasher.update(j_param_bytes);
    hasher.finalize().into()
}

/// §7.3 advisory timestamp gate: absolute difference ≤300s, overflow rejects.
fn check_skew(now: u64, sent_at_unix: u64) -> Result<(), WireError> {
    // Checked absolute difference; overflow rejects rather than wrapping.
    let delta = if sent_at_unix > now {
        sent_at_unix.checked_sub(now)
    } else {
        now.checked_sub(sent_at_unix)
    };
    match delta {
        Some(seconds) if seconds <= MAX_TIMESTAMP_SKEW => Ok(()),
        _ => Err(WireError::StaleTimestamp),
    }
}

/// Bounded per-session SHA256(envelope) dedup table: at most 1024 unique
/// envelopes including ACK/control; at capacity, negotiation closes.
#[derive(Default)]
pub(crate) struct SessionDedup {
    digests: std::collections::HashSet<[u8; 32]>,
}

impl SessionDedup {
    const CAPACITY: usize = 1024;

    fn seen(&self, digest: [u8; 32]) -> bool {
        self.digests.contains(&digest)
    }

    fn record(&mut self, digest: [u8; 32]) -> Result<(), WireError> {
        if self.digests.len() >= Self::CAPACITY && !self.digests.contains(&digest) {
            return Err(WireError::SessionFull);
        }
        self.digests.insert(digest);
        Ok(())
    }
}

/// At most four global sessions, one per PeerId including Hello (§7.3).
pub(crate) const MAX_SESSIONS: usize = 4;
/// §7.3 "30s Hello/message timeout, no waiting sessions": a session whose
/// transcript is still unconfirmed expires after this idle time.
pub(crate) const UNCONFIRMED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// §7.3 total monotonic negotiation lifetime.
pub(crate) const SESSION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(1800);

/// Outcome of admitting one inbound request envelope.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admitted {
    /// Bootstrap Hello accepted: respond with the §7.2 ACK bound to this
    /// responder challenge (an exact retry returns the stored challenge).
    Hello { challenge_r: [u8; 32] },
    /// Established message accepted; its decoded §7.2 body.
    Established(Body),
}

/// One admitted `/z2z/session/1` transcript, responder side: the peer is the
/// initiator (Hello sender), the local node is the responder. Pins are frozen
/// at bootstrap and every later message must match them exactly.
struct Session {
    peer: libp2p::PeerId,
    lane_id: u16,
    chain_context_digest: [u8; 32],
    deployment_digest: [u8; 32],
    session_id: [u8; 32],
    initiator_coord_key: [u8; 32],
    responder_coord_key: [u8; 32],
    role_map: u8,
    challenge_i: [u8; 32],
    challenge_r: [u8; 32],
    /// Strictly next inbound seq from the peer (§7.2, no wrap).
    next_from_peer: u32,
    /// Strictly next outbound seq for this side (the bootstrap ACK consumed 0).
    next_local_seq: u32,
    /// Fresh-J DKG ceremony state (kinds 10-12), if the responder opted in.
    dkg: Option<DkgState>,
    dkg_started: bool,
    /// Signed responses retained only in guarded session memory for exact retries.
    answered: Vec<([u8; 32], Zeroizing<Vec<u8>>)>,
    /// SHA256(signed bytes) of the ACK response we sent; the initiator's
    /// confirming message must carry exactly this digest (§7.2 transcript
    /// confirmation).
    hello_response_digest: Option<[u8; 32]>,
    /// True once the initiator's transcript-confirming message was accepted;
    /// before that no financial/private kind is accepted.
    confirmed: bool,
    /// Per-session bounded SHA256(envelope) table (§7.3; 1024 unique).
    dedup: SessionDedup,
    started: std::time::Instant,
    last_activity: std::time::Instant,
}

/// Bounded session registry: at most [`MAX_SESSIONS`] live transcripts, one
/// per PeerId, each with its own dedup/seq state. Lookup is a ≤4 scan.
#[derive(Default)]
pub(crate) struct SessionTable {
    local_coord_key: [u8; 32],
    sessions: Vec<Session>,
}

impl SessionTable {
    pub(crate) fn new(local_coord_key: [u8; 32]) -> Self {
        Self { local_coord_key, sessions: Vec::new() }
    }

    /// Admit one inbound request: a Hello bootstraps a new responder-side
    /// session; anything else must belong to an existing session.
    pub(crate) fn admit_request(
        &mut self,
        peer: &libp2p::PeerId,
        envelope: &Envelope,
        fresh_challenge_r: [u8; 32],
        now: u64,
    ) -> Result<Admitted, WireError> {
        if envelope.kind == kind::HELLO {
            return self.admit_hello(peer, envelope, fresh_challenge_r, now);
        }
        self.admit_established(peer, envelope, now).map(Admitted::Established)
    }


    /// Record the §7.2 ACK response just sent for a bootstrap Hello, so the
    /// initiator's confirming message can be verified against it.
    pub(crate) fn record_hello_response(
        &mut self,
        peer: &libp2p::PeerId,
        session_id: &[u8; 32],
        response: &Envelope,
    ) {
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|session| session.peer == *peer && &session.session_id == session_id)
        {
            session.hello_response_digest = Some(response.ack_digest());
        }
    }

    /// Sessions are bound to the authenticated direct connection (§7.2).
    pub(crate) fn drop_peer(&mut self, peer: &libp2p::PeerId) {
        self.sessions.retain(|session| session.peer != *peer);
    }

    pub(crate) fn close_session(&mut self, peer: &libp2p::PeerId, session_id: &[u8; 32]) {
        self.sessions.retain(|session| session.peer != *peer || &session.session_id != session_id);
    }

    /// §7.3 total monotonic lifetime plus 30s idle expiry for unconfirmed
    /// sessions and DKG sessions, including their post-completion retry cache.
    pub(crate) fn sweep(&mut self, now: std::time::Instant) {
        self.sessions.retain(|session| {
            now.saturating_duration_since(session.started) <= SESSION_LIFETIME
                && ((session.confirmed && !session.dkg_started)
                    || now.saturating_duration_since(session.last_activity)
                        <= UNCONFIRMED_TIMEOUT)
        });
    }

    /// §7.2 bootstrap: Hello request (seq0, zero responder fields, empty
    /// body), signed by the initiator key; exact retries are idempotent.
    fn admit_hello(
        &mut self,
        peer: &libp2p::PeerId,
        envelope: &Envelope,
        fresh_challenge_r: [u8; 32],
        now: u64,
    ) -> Result<Admitted, WireError> {
        if envelope.seq != 0
            || !envelope.body.is_empty()
            || envelope.responder_coord_key != [0; 32]
            || envelope.challenge_r != [0; 32]
            || envelope.session_id == [0; 32]
            || envelope.challenge_i == [0; 32]
            || envelope.lane_id == 0
            || envelope.lane_id > 5
            || fresh_challenge_r == [0; 32]
        {
            return Err(WireError::BootstrapMalformed);
        }
        use ed25519_dalek::{Signature, VerifyingKey};
        let key = VerifyingKey::from_bytes(&envelope.initiator_coord_key)
            .map_err(|_| WireError::BadSignature)?;
        let signed = Zeroizing::new(envelope.signed_bytes());
        key.verify_strict(&signed, &Signature::from_bytes(&envelope.signature))
            .map_err(|_| WireError::BadSignature)?;
        // §7.3 "1 per PeerId including Hello": an existing same-peer session
        // answers an exact digest retry idempotently (the stored challenge
        // makes the re-sent ACK byte-identical) and rejects any other Hello;
        // a session-id collision from another peer and the global cap reject
        // as well.
        if let Some(session) = self
            .sessions
            .iter()
            .find(|session| session.peer == *peer && session.session_id == envelope.session_id)
        {
            if session.dedup.seen(envelope.sha256()) {
                return Ok(Admitted::Hello { challenge_r: session.challenge_r });
            }
            return Err(WireError::SessionLimit);
        }
        if self.sessions.iter().any(|session| session.peer == *peer)
            || self.sessions.iter().any(|session| session.session_id == envelope.session_id)
            || self.sessions.len() >= MAX_SESSIONS
        {
            return Err(WireError::SessionLimit);
        }
        // New sessions take the full ±300s advisory timestamp gate (§7.3).
        check_skew(now, envelope.sent_at_unix)?;
        let mut dedup = SessionDedup::default();
        dedup.record(envelope.sha256()).map_err(|_| WireError::SessionFull)?;
        let instant = std::time::Instant::now();
        self.sessions.push(Session {
            peer: *peer,
            lane_id: envelope.lane_id,
            chain_context_digest: envelope.chain_context_digest,
            deployment_digest: envelope.deployment_digest,
            session_id: envelope.session_id,
            initiator_coord_key: envelope.initiator_coord_key,
            responder_coord_key: self.local_coord_key,
            role_map: envelope.role_map,
            challenge_i: envelope.challenge_i,
            challenge_r: fresh_challenge_r,
            // The Hello consumed the initiator's seq 0; our ACK uses the
            // responder's seq 0, so both senders start at 1.
            next_from_peer: 1,
            next_local_seq: 1,
            dkg: None,
            dkg_started: false,
            answered: Vec::new(),
            hello_response_digest: None,
            confirmed: false,
            dedup,
            started: instant,
            last_activity: instant,
        });
        Ok(Admitted::Hello { challenge_r: fresh_challenge_r })
    }

    /// §7.2 established-message gate: existing session, same peer, unchanged
    /// pins, strictly next per-sender seq, per-session dedup, transcript
    /// confirmation before any financial kind.
    fn admit_established(
        &mut self,
        peer: &libp2p::PeerId,
        envelope: &Envelope,
        now: u64,
    ) -> Result<Body, WireError> {
        if envelope.kind == kind::HELLO {
            // Hello is bootstrap-only and cannot be a response or a later
            // request on an established transcript.
            return Err(WireError::UnexpectedHello);
        }
        let Some(index) = self
            .sessions
            .iter()
            .position(|session| session.session_id == envelope.session_id)
        else {
            return Err(WireError::UnknownSession);
        };
        let session = &self.sessions[index];
        if session.peer != *peer {
            return Err(WireError::PeerMismatch);
        }
        // Authenticate before any state effect, so unauthenticated frames can
        // never close or mutate a session (the sender key is the peer's
        // initiator key: the node only runs responder-side sessions today).
        use ed25519_dalek::{Signature, VerifyingKey};
        let key = VerifyingKey::from_bytes(&session.initiator_coord_key)
            .map_err(|_| WireError::BadSignature)?;
        let signed = Zeroizing::new(envelope.signed_bytes());
        key.verify_strict(&signed, &Signature::from_bytes(&envelope.signature))
            .map_err(|_| WireError::BadSignature)?;
        let digest = envelope.sha256();
        if session.dedup.seen(digest) {
            // §7.3 exact retry: idempotent, no seq/confirmation effect.
            return validate_body(envelope);
        }
        if envelope.lane_id != session.lane_id
            || envelope.chain_context_digest != session.chain_context_digest
            || envelope.deployment_digest != session.deployment_digest
            || envelope.initiator_coord_key != session.initiator_coord_key
            || envelope.responder_coord_key != session.responder_coord_key
            || envelope.role_map != session.role_map
            || envelope.challenge_i != session.challenge_i
            || envelope.challenge_r != session.challenge_r
        {
            // §7.2: any changed pin ends negotiation, never re-signs.
            self.sessions.remove(index);
            return Err(WireError::PinnedFieldChanged);
        }
        check_skew(now, envelope.sent_at_unix)?;
        if envelope.seq != session.next_from_peer {
            // Strictly next per sender, no wrap: a gap or replay with unseen
            // bytes ends the negotiation.
            self.sessions.remove(index);
            return Err(WireError::OutOfSequence);
        }
        if !session.confirmed {
            // §7.2: the initiator's first established message must confirm
            // the complete transcript (Ack of our signed Hello response)
            // before either side proceeds to any financial kind.
            let confirms = envelope.kind == kind::ACK
                && session.hello_response_digest
                    == envelope.body.as_slice().try_into().ok();
            if !confirms {
                self.sessions.remove(index);
                return Err(WireError::Unconfirmed);
            }
        }
        let body = validate_body(envelope)?;
        if self.sessions[index].dedup.record(digest).is_err() {
            // §7.3: at 1024 unique frames close negotiation, never forget.
            self.sessions.remove(index);
            return Err(WireError::SessionFull);
        }
        let next = envelope.seq.checked_add(1);
        {
            let session = &mut self.sessions[index];
            session.last_activity = std::time::Instant::now();
            session.confirmed = true;
            if let Some(next) = next {
                session.next_from_peer = next;
            }
        }
        if next.is_none() || matches!(body, Body::Abort(_)) {
            self.sessions.remove(index);
        }
        Ok(body)
    }
}

/// Body validators per §7.2 kind contracts. Each returns the decoded fields.
pub(crate) fn validate_body(envelope: &Envelope) -> Result<Body, WireError> {
    match envelope.kind {
        kind::HELLO => {
            if envelope.body.is_empty() {
                Ok(Body::Hello)
            } else {
                Err(WireError::BodyLengthMismatch)
            }
        }
        kind::BACKING_CHALLENGE if envelope.body.len() == 40 => {
            let anchor = envelope.body[..32].try_into().expect("fixed");
            let height = u64::from_be_bytes(envelope.body[32..40].try_into().expect("fixed"));
            Ok(Body::BackingChallenge { anchor, height })
        }
        kind::ABORT if envelope.body.len() == 1 && envelope.body[0] <= 3 => {
            Ok(Body::Abort(envelope.body[0]))
        }
        kind::PACKET_DIGEST_ACK if envelope.body.len() == 64 => {
            let packet = envelope.body[..32].try_into().expect("fixed");
            let execution = envelope.body[32..].try_into().expect("fixed");
            Ok(Body::PacketDigestAck { packet, execution })
        }
        kind::ACK if envelope.body.len() == 32 => {
            Ok(Body::Ack(envelope.body.as_slice().try_into().expect("fixed")))
        }
        // DKG kinds: `context_digest[32]` + serialized package. The transport
        // bounds only; the ceremony layer parses and exhausts the package
        // bytes (postcard does not reject trailing bytes by itself). Maximum
        // body is cap 512 - 322 fixed overhead = 190.
        kind::DKG_ROUND1 | kind::DKG_ROUND2
            if (33..=190).contains(&envelope.body.len()) =>
        {
            Ok(Body::Opaque)
        }
        kind::DKG_FINAL_COMMIT if envelope.body.len() == 32 => {
            Ok(Body::DkgFinalCommit(
                envelope.body.as_slice().try_into().expect("fixed"),
            ))
        }
        // BackingClaim / Terms / Descriptors / Leaf / Certificate bodies bind
        // canonical downstream frames; their byte validation lives with those
        // frame codecs, not here. Size caps are enforced in parse().
        kind::BACKING_CLAIM | kind::TERMS | kind::DESCRIPTORS | kind::LEAF | kind::CERTIFICATE => {
            Ok(Body::Opaque)
        }
        _ => Err(WireError::BodyLengthMismatch),
    }
}

/// Decoded §7.2 body contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Body {
    Hello,
    BackingChallenge { anchor: [u8; 32], height: u64 },
    PacketDigestAck { packet: [u8; 32], execution: [u8; 32] },
    Ack([u8; 32]),
    Abort(u8),
    Opaque,
    /// §7.2 kind 12: `SHA256(PublicKeyPackage)` — both peers must observe the
    /// same digest before any signing session starts.
    DkgFinalCommit([u8; 32]),
}

/// Request/response transport framing for the session codec.
#[derive(Debug, Clone, Default)]
pub(crate) struct SessionCodec;

pub(crate) type SessionRequest = Vec<u8>;
pub(crate) type SessionResponse = Vec<u8>;
/// request-response behaviour event with this codec's request/response types.
pub(crate) type Event = request_response::Event<SessionRequest, SessionResponse>;

#[async_trait::async_trait]
impl request_response::Codec for SessionCodec {
    type Protocol = &'static str;
    type Request = SessionRequest;
    type Response = SessionResponse;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_framed(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_framed(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_framed(io, Zeroizing::new(request).as_slice()).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_framed(io, Zeroizing::new(response).as_slice()).await
    }
}

async fn read_framed<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut prefix = [0_u8; 4];
    io.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_ENVELOPE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "session length prefix"));
    }
    let mut envelope = Zeroizing::new(vec![0_u8; length]);
    io.read_exact(envelope.as_mut_slice()).await?;
    let payload = std::mem::take(&mut *envelope);
    Ok(payload)
}

async fn write_framed<T>(io: &mut T, payload: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    if payload.is_empty() || payload.len() > MAX_ENVELOPE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "session payload size"));
    }
    io.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    io.write_all(payload).await?;
    io.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Envelope {
        Envelope {
            lane_id: 1,
            chain_context_digest: [7; 32],
            deployment_digest: [8; 32],
            session_id: [9; 32],
            initiator_coord_key: [1; 32],
            responder_coord_key: [2; 32],
            role_map: 0,
            challenge_i: [3; 32],
            challenge_r: [4; 32],
            seq: 11,
            kind: kind::HELLO,
            sent_at_unix: 1_800_000_000,
            body: Vec::new(),
            signature: [5; 64],
        }
    }

    #[test]
    fn hello_round_trip_is_exact_and_size_capped() {
        let wire = sample().to_wire().expect("hello fits cap");
        // §7.2: Hello envelope total is 322; the wire carries a 4-byte length
        // prefix in front of it, so the stream frame is 326 bytes.
        assert_eq!(wire.len(), 4 + HEADER_LEN + SIGNATURE_LEN);
        let prefix = u32::from_be_bytes(wire[..4].try_into().expect("prefix"));
        assert_eq!(prefix, 322);
        let decoded = parse(&wire[4..]).expect("round-trip");
        assert_eq!(decoded, sample());
    }

    #[test]
    fn every_kind_header_round_trips_and_ack_body_matches() {
        let mut envelope = sample();
        envelope.kind = kind::ACK;
        envelope.body = vec![9; 32];
        let wire = envelope.to_wire().expect("ack fits cap");
        // Ack envelope total is 354; the framed stream adds the 4-byte prefix.
        assert_eq!(wire.len(), 4 + HEADER_LEN + SIGNATURE_LEN + 32);
        let prefix = u32::from_be_bytes(wire[..4].try_into().expect("prefix"));
        assert_eq!(prefix, 354);
        let decoded = parse(&wire[4..]).expect("round-trip");
        assert_eq!(decoded, envelope);
        assert_eq!(validate_body(&decoded), Ok(Body::Ack([9; 32])));
    }

    #[test]
    fn role_map_two_rejects() {
        let mut envelope = sample();
        envelope.role_map = 2;
        let wire = envelope.to_wire().expect("still framed");
        assert!(matches!(parse(&wire[4..]), Err(WireError::BadRoleMap)));
    }

    #[test]
    fn wrong_domain_rejects() {
        let mut wire = sample().to_wire().expect("framed");
        wire[4] = b'X';
        assert!(matches!(parse(&wire[4..]), Err(WireError::BadDomain)));
    }

    #[test]
    fn unknown_kind_rejects_as_oversize() {
        let mut envelope = sample();
        envelope.kind = 42;
        assert!(envelope.to_wire().is_err());
    }

    #[test]
    fn abort_body_requires_known_reason() {
        let mut envelope = sample();
        envelope.kind = kind::ABORT;
        envelope.body = vec![4];
        let wire = envelope.to_wire().expect("framed");
        let decoded = parse(&wire[4..]).expect("round-trip");
        assert!(validate_body(&decoded).is_err());
    }

    #[test]
    fn trailing_bytes_reject() {
        let mut wire = sample().to_wire().expect("framed");
        wire.extend_from_slice(&[0]);
        assert!(matches!(parse(&wire[4..]), Err(WireError::TrailingBytes)));
    }

    #[test]
    fn truncated_reject() {
        let wire = sample().to_wire().expect("framed");
        assert!(matches!(parse(&wire[4..HEADER_LEN + 10]), Err(WireError::Truncated)));
    }

    // --- §7 session state machine (responder side) ---------------------------

    const NOW: u64 = 1_800_000_000;

    fn hello_envelope(initiator: &ed25519_dalek::SigningKey, session_id: [u8; 32]) -> Envelope {
        use ed25519_dalek::Signer as _;
        let mut envelope = sample();
        envelope.session_id = session_id;
        envelope.challenge_i = [3; 32];
        envelope.responder_coord_key = [0; 32];
        envelope.challenge_r = [0; 32];
        envelope.initiator_coord_key = *initiator.verifying_key().as_bytes();
        envelope.seq = 0;
        envelope.kind = kind::HELLO;
        envelope.sent_at_unix = NOW;
        envelope.body = Vec::new();
        envelope.signature = [0; 64];
        envelope.signature = initiator.sign(&envelope.signed_bytes()).to_bytes();
        envelope
    }

    /// Bootstrap one responder-side session; returns (table, peer, hello).
    fn bootstrapped(
        local: &ed25519_dalek::SigningKey,
        initiator: &ed25519_dalek::SigningKey,
        session_id: [u8; 32],
    ) -> (SessionTable, libp2p::PeerId, Envelope) {
        let mut table = SessionTable::new(*local.verifying_key().as_bytes());
        let peer = libp2p::PeerId::random();
        let hello = hello_envelope(initiator, session_id);
        let admitted = table
            .admit_request(&peer, &hello, [9; 32], NOW)
            .expect("bootstrap hello");
        assert_eq!(admitted, Admitted::Hello { challenge_r: [9; 32] });
        (table, peer, hello)
    }

    /// Established envelope with the frozen pins, signed by `signer`.
    fn established(
        hello: &Envelope,
        local: &ed25519_dalek::SigningKey,
        signer: &ed25519_dalek::SigningKey,
        kind_byte: u8,
        body: Vec<u8>,
        seq: u32,
    ) -> Envelope {
        use ed25519_dalek::Signer as _;
        let mut envelope = hello.clone();
        envelope.kind = kind_byte;
        envelope.responder_coord_key = *local.verifying_key().as_bytes();
        envelope.challenge_r = [9; 32];
        envelope.seq = seq;
        envelope.body = body;
        envelope.signature = [0; 64];
        envelope.signature = signer.sign(&envelope.signed_bytes()).to_bytes();
        envelope
    }

    #[test]
    fn hello_bootstrap_limits_and_exact_retry() {
        use ed25519_dalek::SigningKey;
        let local = SigningKey::from_bytes(&[31; 32]);
        let initiator = SigningKey::from_bytes(&[32; 32]);
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [7; 32]);

        // Exact retry is idempotent and returns the stored challenge, so the
        // re-sent ACK stays byte-identical.
        assert_eq!(
            table.admit_request(&peer, &hello, [8; 32], NOW),
            Ok(Admitted::Hello { challenge_r: [9; 32] })
        );
        // A different Hello from the same peer while one session is live
        // rejects (§7.3 one per PeerId); same for a session-id collision from
        // another peer and the global 4-session cap.
        let other = hello_envelope(&initiator, [10; 32]);
        assert_eq!(
            table.admit_request(&peer, &other, [9; 32], NOW),
            Err(WireError::SessionLimit)
        );
        let stranger = libp2p::PeerId::random();
        assert_eq!(
            table.admit_request(&stranger, &hello, [9; 32], NOW),
            Err(WireError::SessionLimit)
        );
        for _ in 0..3 {
            let signing = SigningKey::from_bytes(&[40; 32]);
            let fresh = hello_envelope(&signing, fresh_session_id());
            assert!(table
                .admit_request(&libp2p::PeerId::random(), &fresh, [9; 32], NOW)
                .is_ok());
        }
        let signing = SigningKey::from_bytes(&[41; 32]);
        let fresh = hello_envelope(&signing, fresh_session_id());
        assert_eq!(
            table.admit_request(&libp2p::PeerId::random(), &fresh, [9; 32], NOW),
            Err(WireError::SessionLimit)
        );
    }

    fn fresh_session_id() -> [u8; 32] {
        use rand_core::RngCore;
        let mut id = [0_u8; 32];
        rand_core::OsRng.fill_bytes(&mut id);
        id
    }

    #[test]
    fn established_gate_requires_session_pins_peer_auth_and_seq() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let local = SigningKey::from_bytes(&[51; 32]);
        let initiator = SigningKey::from_bytes(&[52; 32]);
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [11; 32]);
        let ack_body = [77u8; 32];

        // Unknown session and peer mismatch reject without touching state.
        let mut unknown = hello.clone();
        unknown.kind = kind::ACK;
        unknown.session_id = [12; 32];
        assert_eq!(
            table.admit_established(&peer, &unknown, NOW),
            Err(WireError::UnknownSession)
        );
        let right_session = established(&hello, &local, &initiator, kind::ACK, ack_body.to_vec(), 1);
        assert_eq!(
            table.admit_established(&libp2p::PeerId::random(), &right_session, NOW),
            Err(WireError::PeerMismatch)
        );
        // Wrong signer (the responder key, not the peer's initiator key).
        let forged = established(&hello, &local, &local, kind::ACK, ack_body.to_vec(), 1);
        assert_eq!(
            table.admit_established(&peer, &forged, NOW),
            Err(WireError::BadSignature)
        );
        // Greeting kind cannot be a response.
        let hello_kind = established(&hello, &local, &initiator, kind::HELLO, Vec::new(), 1);
        assert_eq!(
            table.admit_established(&peer, &hello_kind, NOW),
            Err(WireError::UnexpectedHello)
        );
        // Seq gap ends the negotiation.
        let gap = established(&hello, &local, &initiator, kind::ABORT, vec![3], 2);
        assert_eq!(table.admit_established(&peer, &gap, NOW), Err(WireError::OutOfSequence));

        // Re-bootstrap: a changed pin ends the negotiation and drops the
        // session even when the frame is authentic.
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [13; 32]);
        let mut changed = established(&hello, &local, &initiator, kind::ABORT, vec![0], 1);
        changed.lane_id = 4;
        changed.signature = [0; 64];
        changed.signature = initiator.sign(&changed.signed_bytes()).to_bytes();
        assert_eq!(
            table.admit_established(&peer, &changed, NOW),
            Err(WireError::PinnedFieldChanged)
        );
        assert_eq!(
            table.admit_established(&peer, &changed, NOW),
            Err(WireError::UnknownSession)
        );

        // Timestamp gate for unknown frames of a live session.
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [14; 32]);
        let stale = established(&hello, &local, &initiator, kind::ACK, ack_body.to_vec(), 1);
        assert_eq!(
            table.admit_established(&peer, &stale, NOW + 1_000),
            Err(WireError::StaleTimestamp)
        );
    }

    #[test]
    fn confirmation_opens_financial_kinds_and_retries_stay_idempotent() {
        use ed25519_dalek::SigningKey;
        let local = SigningKey::from_bytes(&[61; 32]);
        let initiator = SigningKey::from_bytes(&[62; 32]);
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [15; 32]);

        // Build the ACK the node would send and record it as the transcript.
        let ack = established(&hello, &local, &local, kind::ACK, vec![0; 32], 0);
        table.record_hello_response(&peer, &hello.session_id, &ack);

        // Pre-confirmation: a financial kind ends the session even when it is
        // authenticated and correctly sequenced.
        let terms = established(&hello, &local, &initiator, kind::TERMS, vec![1, 2, 3], 1);
        assert_eq!(table.admit_established(&peer, &terms, NOW), Err(WireError::Unconfirmed));
        assert_eq!(table.admit_established(&peer, &terms, NOW), Err(WireError::UnknownSession));

        // Re-bootstrap: a confirmation body other than SHA256(signed bytes of
        // our ACK) also ends the negotiation.
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [16; 32]);
        table.record_hello_response(&peer, &hello.session_id, &ack);
        let wrong = established(&hello, &local, &initiator, kind::ACK, [0xEE; 32].to_vec(), 1);
        assert_eq!(table.admit_established(&peer, &wrong, NOW), Err(WireError::Unconfirmed));

        // Re-bootstrap: a short or over-long ACK body must reject (never
        // panic): the digest comparison is Option-vs-Option over the exact
        // 32-byte conversion, so any length is total.
        for body in [vec![0xAA], vec![0xAA; 31], vec![0xAA; 33]] {
            let (mut table, peer, hello) = bootstrapped(&local, &initiator, [18; 32]);
            table.record_hello_response(&peer, &hello.session_id, &ack);
            let short = established(&hello, &local, &initiator, kind::ACK, body, 1);
            assert_eq!(table.admit_established(&peer, &short, NOW), Err(WireError::Unconfirmed));
            assert_eq!(table.admit_established(&peer, &short, NOW), Err(WireError::UnknownSession));
        }

        // Pre-confirmation, a DKG kind as the FIRST established message must
        // reject (fail closed): only the transcript-confirming Ack opens the
        // session for private work.
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [19; 32]);
        table.record_hello_response(&peer, &hello.session_id, &ack);
        let early_dkg = established(&hello, &local, &initiator, kind::DKG_ROUND1, vec![7; 167], 1);
        assert_eq!(table.admit_established(&peer, &early_dkg, NOW), Err(WireError::Unconfirmed));
        assert_eq!(table.admit_established(&peer, &early_dkg, NOW), Err(WireError::UnknownSession));

        // Re-bootstrap: the exact confirmation is accepted...
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [17; 32]);
        table.record_hello_response(&peer, &hello.session_id, &ack);
        let confirm = established(&hello, &local, &initiator, kind::ACK, ack.ack_digest().to_vec(), 1);
        assert_eq!(
            table.admit_established(&peer, &confirm, NOW),
            Ok(Body::Ack(ack.ack_digest()))
        );
        // ...an aged exact retry stays idempotent without consuming seq...
        assert_eq!(
            table.admit_established(&peer, &confirm, NOW + 1_000),
            Ok(Body::Ack(ack.ack_digest()))
        );
        // ...and financial kinds are now accepted at the strictly next seq.
        let terms = established(&hello, &local, &initiator, kind::TERMS, vec![1, 2, 3], 2);
        assert_eq!(table.admit_established(&peer, &terms, NOW), Ok(Body::Opaque));
        // DKG kinds (amendment 2026-10-07) are accepted only post-confirmation:
        // a bound round-1 package and the transcript commitment.
        let round1 = established(&hello, &local, &initiator, kind::DKG_ROUND1, vec![7; 167], 3);
        assert_eq!(table.admit_established(&peer, &round1, NOW), Ok(Body::Opaque));
        let commit = established(&hello, &local, &initiator, kind::DKG_FINAL_COMMIT, vec![8; 32], 4);
        assert_eq!(
            table.admit_established(&peer, &commit, NOW),
            Ok(Body::DkgFinalCommit([8; 32]))
        );
        // An abort ends the session after acceptance.
        let abort = established(&hello, &local, &initiator, kind::ABORT, vec![0], 5);
        assert_eq!(table.admit_established(&peer, &abort, NOW), Ok(Body::Abort(0)));
        assert_eq!(
            table.admit_established(&peer, &abort, NOW),
            Err(WireError::UnknownSession)
        );
    }

    #[test]
    fn bootstrap_shape_lifetime_and_drop_rules() {
        use ed25519_dalek::SigningKey;
        let local = SigningKey::from_bytes(&[71; 32]);
        let initiator = SigningKey::from_bytes(&[72; 32]);
        let mut table = SessionTable::new(*local.verifying_key().as_bytes());
        let peer = libp2p::PeerId::random();
        let hello = hello_envelope(&initiator, [21; 32]);

        // Shape violations reject.
        let mut nonzero = hello.clone();
        nonzero.responder_coord_key = [5; 32];
        assert_eq!(
            table.admit_request(&peer, &nonzero, [9; 32], NOW),
            Err(WireError::BootstrapMalformed)
        );
        let mut replays = hello.clone();
        replays.seq = 1;
        assert_eq!(
            table.admit_request(&peer, &replays, [9; 32], NOW),
            Err(WireError::BootstrapMalformed)
        );
        // Zero supplied challenge and zero session id reject.
        assert_eq!(
            table.admit_request(&peer, &hello, [0; 32], NOW),
            Err(WireError::BootstrapMalformed)
        );
        let mut zero_session = hello.clone();
        zero_session.session_id = [0; 32];
        use ed25519_dalek::Signer as _;
        zero_session.signature = initiator.sign(&zero_session.signed_bytes()).to_bytes();
        assert_eq!(
            table.admit_request(&peer, &zero_session, [9; 32], NOW),
            Err(WireError::BootstrapMalformed)
        );
        // Stale and future Hellos reject inside the ±300s gate.
        assert_eq!(
            table.admit_request(&peer, &hello, [9; 32], NOW + 1_000),
            Err(WireError::StaleTimestamp)
        );

        // Unconfirmed sessions expire after the 30s waiting timeout; a
        // connection close drops the peer's session immediately.
        assert!(table.admit_request(&peer, &hello, [9; 32], NOW).is_ok());
        let started = std::time::Instant::now();
        table.sweep(started + std::time::Duration::from_secs(29));
        assert_eq!(table.sessions.len(), 1);
        table.sweep(started + std::time::Duration::from_secs(31));
        assert_eq!(table.sessions.len(), 0);
        assert!(table.admit_request(&peer, &hello, [9; 32], NOW).is_ok());
        table.drop_peer(&libp2p::PeerId::random());
        assert_eq!(table.sessions.len(), 1);
        table.drop_peer(&peer);
        assert_eq!(table.sessions.len(), 0);
    }
    // --- DKG kinds (amendment 2026-10-07) -----------------------------------

    #[test]
    fn dkg_kinds_round_trip_at_measured_sizes_and_reject_oversize() {
        // Measured postcard package sizes: round1 135 B, round2 37 B.
        for (kind_byte, package_len) in
            [(kind::DKG_ROUND1, 135_usize), (kind::DKG_ROUND2, 37)]
        {
            let mut envelope = sample();
            envelope.seq = 7;
            envelope.kind = kind_byte;
            envelope.body = vec![0xAB; 32 + package_len];
            let wire = envelope.to_wire().expect("within cap");
            assert_eq!(wire.len(), 4 + HEADER_LEN + SIGNATURE_LEN + 32 + package_len);
            let decoded = parse(&wire[4..]).expect("round-trip");
            assert_eq!(decoded, envelope);
            assert_eq!(validate_body(&decoded), Ok(Body::Opaque));
        }

        // Body bounds: at least the context digest plus one package byte, at
        // most cap - 322 = 190.
        let mut envelope = sample();
        envelope.kind = kind::DKG_ROUND1;
        envelope.body = vec![0x00; 32];
        assert_eq!(validate_body(&envelope), Err(WireError::BodyLengthMismatch));
        envelope.body = vec![0x00; 33];
        assert_eq!(validate_body(&envelope), Ok(Body::Opaque));
        envelope.body = vec![0x00; 191];
        assert_eq!(validate_body(&envelope), Err(WireError::BodyLengthMismatch));
        assert!(envelope.to_wire().is_err(), "513-byte envelope must exceed the kind cap");

        // Kind 12 is exactly the 32-byte transcript-commitment digest.
        let mut envelope = sample();
        envelope.kind = kind::DKG_FINAL_COMMIT;
        envelope.body = vec![0x11; 31];
        assert_eq!(validate_body(&envelope), Err(WireError::BodyLengthMismatch));
        envelope.body = vec![0x11; 32];
        let wire = envelope.to_wire().expect("kind 12 cap");
        assert_eq!(wire.len(), 4 + 354);
        let decoded = parse(&wire[4..]).expect("round-trip");
        assert_eq!(
            validate_body(&decoded),
            Ok(Body::DkgFinalCommit([0x11; 32]))
        );
    }

    #[test]
    fn dkg_context_digest_is_canonical_and_field_sensitive() {
        let session_id = [1; 32];
        let initiator = [2; 32];
        let responder = [3; 32];
        let context = [4; 32];
        let digest = dkg_context_digest(2, &session_id, &initiator, &responder, &context, 1, &[9, 9]);
        assert_eq!(
            digest,
            dkg_context_digest(2, &session_id, &initiator, &responder, &context, 1, &[9, 9])
        );
        // Manual preimage recomputation pins the exact byte order.
        {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"Z2Z_DKG_CTX\0");
            hasher.update(2_u16.to_be_bytes());
            hasher.update(session_id);
            hasher.update(initiator);
            hasher.update(responder);
            hasher.update(context);
            hasher.update([1_u8]);
            hasher.update([9_u8, 9]);
            let expected: [u8; 32] = hasher.finalize().into();
            assert_eq!(digest, expected);
        }
        // Every pinned field participates.
        assert_ne!(digest, dkg_context_digest(3, &session_id, &initiator, &responder, &context, 1, &[9, 9]));
        assert_ne!(digest, dkg_context_digest(2, &[8; 32], &initiator, &responder, &context, 1, &[9, 9]));
        assert_ne!(digest, dkg_context_digest(2, &session_id, &[8; 32], &responder, &context, 1, &[9, 9]));
        assert_ne!(digest, dkg_context_digest(2, &session_id, &initiator, &[8; 32], &context, 1, &[9, 9]));
        assert_ne!(digest, dkg_context_digest(2, &session_id, &initiator, &responder, &[8; 32], 1, &[9, 9]));
        assert_ne!(digest, dkg_context_digest(2, &session_id, &initiator, &responder, &context, 2, &[9, 9]));
        assert_ne!(digest, dkg_context_digest(2, &session_id, &initiator, &responder, &context, 1, &[9, 8]));
    }
    // --- Fresh-J DKG ceremony over the table (kinds 10-12) -------------------

    #[test]
    fn dkg_ceremony_completes_over_the_session_table_and_commits_must_match() {
        use rand_core::OsRng;
        use ziquid_threshold::{DkgSession, Participant};

        let local = ed25519_dalek::SigningKey::from_bytes(&[81; 32]);
        let initiator = ed25519_dalek::SigningKey::from_bytes(&[82; 32]);
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [31; 32]);
        let ack = established(&hello, &local, &local, kind::ACK, vec![0; 32], 0);
        table.record_hello_response(&peer, &hello.session_id, &ack);
        let confirm = established(&hello, &local, &initiator, kind::ACK, ack.ack_digest().to_vec(), 1);
        assert_eq!(table.admit_established(&peer, &confirm, NOW), Ok(Body::Ack(ack.ack_digest())));

        // Outbound seq bookkeeping: the bootstrap ACK consumed seq 0.
        let (pins, seq) = table.begin_outbound(&peer, &hello.session_id).expect("pins");
        assert_eq!(seq, 1);
        assert_eq!(pins.session_id, hello.session_id);
        assert_eq!(pins.challenge_r, [9; 32]);
        let (_, seq) = table.begin_outbound(&peer, &hello.session_id).expect("pins");
        assert_eq!(seq, 2);
        assert_eq!(
            table.begin_outbound(&libp2p::PeerId::random(), &hello.session_id).unwrap_err(),
            WireError::UnknownSession
        );

        // The peer runs its own participant entirely locally.
        let mut rng = OsRng;
        let (mut peer_dkg, peer_round1) =
            DkgSession::start(Participant::Second, &mut rng).expect("peer start");

        // Responder side: round 1 (with the peer's round-1 package), round 2
        // (with the peer's round-2 package), then finalize.
        let our_round1 = table
            .dkg_start(&peer, &hello.session_id, &mut rng)
            .expect("start");
        assert_eq!(
            table.dkg_start(&peer, &hello.session_id, &mut rng).unwrap_err(),
            WireError::Dkg
        );
        let peer_round2 = peer_dkg.round2(&our_round1).expect("peer round2");
        let our_round2 = table
            .dkg_round1_in(&peer, &hello.session_id, &peer_round1)
            .expect("round1 in");
        let our_commit = table
            .dkg_round2_in(&peer, &hello.session_id, &peer_round2)
            .expect("round2 in");
        let (_, peer_group) = peer_dkg
            .finalize(&our_round1, &our_round2)
            .expect("peer finalize");
        let peer_commit: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(peer_group.to_bytes()).into()
        };
        assert_eq!(our_commit, peer_commit, "both sides must derive the same group");

        // Rule 5: the peer's commit digest must match; a duplicate or a wrong
        // digest is a ceremony failure.
        table
            .dkg_accept_commit(&peer, &hello.session_id, &peer_commit)
            .expect("commit accepted");
        assert!(table.sessions[0].dkg.is_none(), "completed ephemeral share must be dropped");
        assert_eq!(table.dkg_start(&peer, &hello.session_id, &mut rng).err(), Some(WireError::Dkg));
        assert_eq!(
            table.dkg_accept_commit(&peer, &hello.session_id, &peer_commit).unwrap_err(),
            WireError::Dkg
        );

        // Mismatched commit on a fresh ceremony rejects.
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [32; 32]);
        let ack = established(&hello, &local, &local, kind::ACK, vec![0; 32], 0);
        table.record_hello_response(&peer, &hello.session_id, &ack);
        let confirm = established(&hello, &local, &initiator, kind::ACK, ack.ack_digest().to_vec(), 1);
        assert!(table.admit_established(&peer, &confirm, NOW).is_ok());
        let (mut peer_dkg, peer_round1) =
            DkgSession::start(Participant::Second, &mut rng).expect("peer start");
        let our_round1 = table
            .dkg_start(&peer, &hello.session_id, &mut rng)
            .expect("start");
        let peer_round2 = peer_dkg.round2(&our_round1).expect("peer round2");
        let _ = table
            .dkg_round1_in(&peer, &hello.session_id, &peer_round1)
            .expect("round1 in");
        let _ = table
            .dkg_round2_in(&peer, &hello.session_id, &peer_round2)
            .expect("round2 in");
        assert_eq!(
            table.dkg_accept_commit(&peer, &hello.session_id, &[0xEE; 32]).unwrap_err(),
            WireError::Dkg
        );

        // Exact retry: a stored response is re-served byte-identically.
        let request = [0x77u8; 32];
        table
            .dkg_store_response(&peer, &hello.session_id, request, vec![1, 2, 3])
            .expect("store");
        assert_eq!(
            table.dkg_retry_response(&peer, &hello.session_id, &request),
            Some(vec![1, 2, 3])
        );
        assert_eq!(table.dkg_retry_response(&peer, &hello.session_id, &[0x78; 32]), None);
    }

    #[test]
    fn dkg_requires_confirmation_and_idle_expiry_removes_retry_state() {
        let local = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
        let initiator = ed25519_dalek::SigningKey::from_bytes(&[92; 32]);
        let (mut table, peer, hello) = bootstrapped(&local, &initiator, [41; 32]);
        let mut rng = rand_core::OsRng;
        assert_eq!(table.dkg_start(&peer, &hello.session_id, &mut rng).err(), Some(WireError::Dkg));
        let ack = established(&hello, &local, &local, kind::ACK, vec![0; 32], 0);
        table.record_hello_response(&peer, &hello.session_id, &ack);
        let confirm = established(&hello, &local, &initiator, kind::ACK, ack.ack_digest().to_vec(), 1);
        table.admit_established(&peer, &confirm, NOW).unwrap();
        table.dkg_start(&peer, &hello.session_id, &mut rng).unwrap();
        table.dkg_store_response(&peer, &hello.session_id, [7; 32], vec![0; 37]).unwrap();
        let deadline = table.sessions[0].last_activity + UNCONFIRMED_TIMEOUT;
        table.sweep(deadline);
        assert!(table.dkg_retry_response(&peer, &hello.session_id, &[7; 32]).is_some());
        table.sweep(deadline + std::time::Duration::from_nanos(1));
        assert!(table.dkg_retry_response(&peer, &hello.session_id, &[7; 32]).is_none());
        assert_eq!(table.begin_outbound(&peer, &hello.session_id).err(), Some(WireError::UnknownSession));
    }
}