//! Explicit ephemeral FROST key generation; no wallet, persisted share or financial authority.
use super::{Error, Result, config, network, session};
use clap::Args;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use futures_util::StreamExt;
use libp2p::{PeerId, Swarm, request_response, swarm::{SwarmEvent, dial_opts::DialOpts}};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::{ops::{Deref, DerefMut}, path::PathBuf, time::Duration};
use zeroize::{Zeroize, Zeroizing};

#[derive(Args)]
pub(super) struct Options {
    /// Direct literal TCP address ending in /p2p/<expected PeerId>.
    #[arg(long)]
    address: String,
    /// Required expected Ed25519 transport identity; must match the address suffix.
    #[arg(long)]
    peer_id: String,
    /// Explicit session lane, 1..=5; no lane is inferred.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=5))]
    lane_id: u16,
    /// Opt in to the existing immutable owner-private transport identity API.
    #[arg(long)]
    peer_identity_file: Option<PathBuf>,
    /// Exact caller-selected pool byte; its semantics are not inferred.
    #[arg(long)]
    dkg_pool_id: u8,
    /// Exact caller-frozen J bytes, lowercase hex, 1..=256 bytes.
    #[arg(long)]
    dkg_j_params: String,
    /// Required nonzero chain-context digest, 32 bytes of lowercase hex.
    #[arg(long)]
    dkg_chain_context: String,
    /// Required nonzero deployment-context digest, 32 bytes of lowercase hex.
    #[arg(long)]
    dkg_deployment_context: String,
}

/// The wire body can contain round-2 contributions. Never leave a parsed copy unguarded.
pub(super) struct GuardedEnvelope(pub session::Envelope);
impl Deref for GuardedEnvelope {
    type Target = session::Envelope;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl DerefMut for GuardedEnvelope {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}
impl Drop for GuardedEnvelope {
    fn drop(&mut self) { self.0.body.zeroize(); }
}

pub(super) struct Response {
    pub payload: Zeroizing<Vec<u8>>,
    pub completed: Option<[u8; 32]>,
}

fn check_timestamp(envelope: &session::Envelope) -> Result<()> {
    if super::state::now_unix_secs().abs_diff(envelope.sent_at_unix) > session::MAX_TIMESTAMP_SKEW {
        return Err(Error::DkgProtocol);
    }
    Ok(())
}

fn context(parameters: &config::DkgParameters, envelope: &session::Envelope) -> [u8; 32] {
    session::dkg_context_digest(
        envelope.lane_id, &envelope.session_id, &envelope.initiator_coord_key,
        &envelope.responder_coord_key, &parameters.chain_context,
        parameters.pool_id, &parameters.j_params,
    )
}

fn package<'a>(envelope: &'a session::Envelope, digest: &[u8; 32]) -> Result<&'a [u8]> {
    session::validate_body(envelope).map_err(|_| Error::DkgProtocol)?;
    if !matches!(envelope.kind, session::kind::DKG_ROUND1 | session::kind::DKG_ROUND2)
        || envelope.body.get(..32) != Some(digest.as_slice())
    {
        return Err(Error::DkgProtocol);
    }
    envelope.body.get(32..).filter(|bytes| !bytes.is_empty()).ok_or(Error::DkgProtocol)
}

fn package_body(digest: &[u8; 32], package: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(32 + package.len()));
    body.extend_from_slice(digest);
    body.extend_from_slice(package);
    body
}

fn sign(envelope: &mut session::Envelope, key: &SigningKey) {
    let bytes = Zeroizing::new(envelope.signed_bytes());
    envelope.signature = key.sign(&bytes).to_bytes();
}

/// SessionCodec supplies framing. Reuse the serialized allocation, not a second share copy.
fn payload(envelope: &session::Envelope) -> Result<Zeroizing<Vec<u8>>> {
    let mut wire = Zeroizing::new(envelope.to_wire().map_err(|_| Error::SessionEnvelope)?);
    if wire.len() < 4 { return Err(Error::SessionEnvelope); }
    drop(wire.drain(..4));
    Ok(wire)
}

fn envelope_from(
    pins: &session::Envelope, seq: u32, kind: u8, mut body: Zeroizing<Vec<u8>>,
    key: &SigningKey,
) -> GuardedEnvelope {
    let mut envelope = GuardedEnvelope(session::Envelope {
        lane_id: pins.lane_id,
        chain_context_digest: pins.chain_context_digest,
        deployment_digest: pins.deployment_digest,
        session_id: pins.session_id,
        initiator_coord_key: pins.initiator_coord_key,
        responder_coord_key: pins.responder_coord_key,
        role_map: pins.role_map,
        challenge_i: pins.challenge_i,
        challenge_r: pins.challenge_r,
        seq, kind,
        sent_at_unix: super::state::now_unix_secs(),
        body: std::mem::take(&mut *body),
        signature: [0; 64],
    });
    sign(&mut envelope, key);
    envelope
}

/// One inbound operation. A failure destroys this ceremony, never a partially advanced state.
pub(super) fn respond(
    peer: &PeerId, envelope: &session::Envelope, policy: Option<&config::DkgPolicy>,
    key: &SigningKey, sessions: &mut session::SessionTable,
) -> Result<Response> {
    let result = respond_inner(peer, envelope, policy, key, sessions);
    if result.is_err() { sessions.close_session(peer, &envelope.session_id); }
    result
}

fn respond_inner(
    peer: &PeerId, envelope: &session::Envelope, policy: Option<&config::DkgPolicy>,
    key: &SigningKey, sessions: &mut session::SessionTable,
) -> Result<Response> {
    sessions.sweep(std::time::Instant::now());
    let parameters = if envelope.kind == session::kind::HELLO {
        None // Normal Hello is independent of private DKG opt-in.
    } else {
        let policy = policy.filter(|policy| policy.peer == *peer).ok_or(Error::DkgProtocol)?;
        if envelope.chain_context_digest != policy.parameters.chain_context
            || envelope.deployment_digest != policy.parameters.deployment_context
            || config::peer_coord_key(peer)? != envelope.initiator_coord_key
        {
            return Err(Error::DkgProtocol);
        }
        Some(&policy.parameters)
    };
    let request_digest = envelope.sha256();
    if let Some(cached) = sessions.dkg_retry_response(peer, &envelope.session_id, &request_digest) {
        return Ok(Response { payload: Zeroizing::new(cached), completed: None });
    }
    check_timestamp(envelope)?;
    let challenge = if envelope.kind == session::kind::HELLO { session::fresh_nonce() } else { [0; 32] };
    let admitted = sessions.admit_request(peer, envelope, challenge, super::state::now_unix_secs())
        .map_err(|_| Error::DkgProtocol)?;
    let mut completed = None;
    let response = match admitted {
        session::Admitted::Hello { challenge_r } => {
            let mut ack = envelope_from(envelope, 0, session::kind::ACK,
                Zeroizing::new(envelope.ack_digest().to_vec()), key);
            ack.responder_coord_key = *key.verifying_key().as_bytes();
            ack.challenge_r = challenge_r;
            sign(&mut ack, key);
            sessions.record_hello_response(peer, &envelope.session_id, &ack);
            ack
        }
        session::Admitted::Established(body) => {
            let parameters = parameters.ok_or(Error::DkgProtocol)?;
            let digest = context(parameters, envelope);
            let (kind, mut response_body) = match (envelope.kind, envelope.seq, body) {
                (session::kind::ACK, 1, session::Body::Ack(_)) => {
                    let round1 = sessions.dkg_start(peer, &envelope.session_id, &mut OsRng)
                        .map_err(|_| Error::DkgCrypto)?;
                    (session::kind::DKG_ROUND1, package_body(&digest, &round1))
                }
                (session::kind::DKG_ROUND1, 2, session::Body::Opaque) => {
                    let peer_round1 = package(envelope, &digest)?;
                    let round2 = sessions.dkg_round1_in(peer, &envelope.session_id, peer_round1)
                        .map_err(|_| Error::DkgCrypto)?;
                    (session::kind::DKG_ROUND2, package_body(&digest, &round2))
                }
                (session::kind::DKG_ROUND2, 3, session::Body::Opaque) => {
                    let peer_round2 = package(envelope, &digest)?;
                    let commit = sessions.dkg_round2_in(peer, &envelope.session_id, peer_round2)
                        .map_err(|_| Error::DkgCrypto)?;
                    (session::kind::DKG_FINAL_COMMIT, Zeroizing::new(commit.to_vec()))
                }
                (session::kind::DKG_FINAL_COMMIT, 4, session::Body::DkgFinalCommit(commit)) => {
                    sessions.dkg_accept_commit(peer, &envelope.session_id, &commit)
                        .map_err(|_| Error::DkgProtocol)?;
                    completed = Some(commit);
                    (session::kind::ACK, Zeroizing::new(envelope.ack_digest().to_vec()))
                }
                _ => return Err(Error::DkgProtocol),
            };
            let (pins, seq) = sessions.begin_outbound(peer, &envelope.session_id)
                .map_err(|_| Error::DkgProtocol)?;
            if seq != envelope.seq { return Err(Error::DkgProtocol); }
            let mut response = GuardedEnvelope(session::Envelope {
                lane_id: pins.lane_id,
                chain_context_digest: pins.chain_context_digest,
                deployment_digest: pins.deployment_digest,
                session_id: pins.session_id,
                initiator_coord_key: pins.initiator_coord_key,
                responder_coord_key: pins.responder_coord_key,
                role_map: pins.role_map,
                challenge_i: pins.challenge_i,
                challenge_r: pins.challenge_r,
                seq, kind,
                sent_at_unix: super::state::now_unix_secs(),
                body: std::mem::take(&mut *response_body),
                signature: [0; 64],
            });
            sign(&mut response, key);
            response
        }
    };
    let payload = payload(&response)?;
    sessions.dkg_store_response(peer, &envelope.session_id, request_digest, payload.to_vec())
        .map_err(|_| Error::DkgProtocol)?;
    Ok(Response { payload, completed })
}

fn verify_response(
    response: &session::Envelope, request: &session::Envelope, expected_key: &[u8; 32],
    expected_kind: u8, parameters: &config::DkgParameters,
) -> Result<()> {
    check_timestamp(response)?;
    if response.lane_id != request.lane_id
        || response.chain_context_digest != request.chain_context_digest
        || response.chain_context_digest != parameters.chain_context
        || response.deployment_digest != request.deployment_digest
        || response.deployment_digest != parameters.deployment_context
        || response.session_id != request.session_id
        || response.initiator_coord_key != request.initiator_coord_key
        || response.responder_coord_key != *expected_key
        || response.role_map != request.role_map
        || response.challenge_i != request.challenge_i
        || response.seq != request.seq
        || response.kind != expected_kind
        || if request.kind == session::kind::HELLO {
            response.challenge_r == [0; 32]
        } else {
            response.challenge_r != request.challenge_r
                || response.responder_coord_key != request.responder_coord_key
        }
    {
        return Err(Error::DkgProtocol);
    }
    let signed = Zeroizing::new(response.signed_bytes());
    VerifyingKey::from_bytes(expected_key).map_err(|_| Error::DkgProtocol)?
        .verify_strict(&signed, &Signature::from_bytes(&response.signature))
        .map_err(|_| Error::DkgProtocol)?;
    match session::validate_body(response).map_err(|_| Error::DkgProtocol)? {
        session::Body::Ack(digest) if digest != request.ack_digest() => Err(Error::DkgProtocol),
        session::Body::Opaque if matches!(response.kind, session::kind::DKG_ROUND1 | session::kind::DKG_ROUND2) => {
            package(response, &context(parameters, response)).map(|_| ())
        }
        _ => Ok(()),
    }
}

/// Exactly one outstanding request; never let send_request dial an unconnected peer.
async fn exchange(
    swarm: &mut Swarm<network::Behaviour>, peer: PeerId, expected_key: &[u8; 32],
    request: &session::Envelope, expected_kind: u8, parameters: &config::DkgParameters,
    total_deadline: tokio::time::Instant,
) -> Result<GuardedEnvelope> {
    if !swarm.is_connected(&peer) { return Err(Error::Transport); }
    let mut wire = payload(request)?;
    let id = swarm.behaviour_mut().session.send_request(&peer, std::mem::take(&mut *wire));
    let deadline = total_deadline.min(tokio::time::Instant::now() + Duration::from_secs(30));
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Err(Error::SessionTimeout),
            event = swarm.next() => match event.ok_or(Error::Transport)? {
                SwarmEvent::Behaviour(network::Event::Session(request_response::Event::Message {
                    peer: actual_peer, message: request_response::Message::Response { request_id, response }, ..
                })) => {
                    let response = Zeroizing::new(response);
                    if actual_peer != peer || request_id != id { return Err(Error::DkgProtocol); }
                    let response = GuardedEnvelope(session::parse(&response).map_err(|_| Error::SessionEnvelope)?);
                    verify_response(&response, request, expected_key, expected_kind, parameters)?;
                    return Ok(response);
                }
                SwarmEvent::Behaviour(network::Event::Session(request_response::Event::Message {
                    message: request_response::Message::Request { request, .. }, ..
                })) => {
                    let _request = Zeroizing::new(request);
                    return Err(Error::DkgProtocol);
                }
                SwarmEvent::Behaviour(network::Event::Session(request_response::Event::OutboundFailure { .. }))
                    => return Err(Error::SessionTimeout),
                SwarmEvent::Behaviour(network::Event::Session(request_response::Event::InboundFailure { .. }))
                    => return Err(Error::DkgProtocol),
                SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == peer => return Err(Error::Transport),
                SwarmEvent::OutgoingConnectionError { .. } => return Err(Error::Transport),
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id != peer => return Err(Error::DkgProtocol),
                _ => {},
            },
        }
    }
}

async fn connect(swarm: &mut Swarm<network::Behaviour>, peer: PeerId) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Err(Error::SessionTimeout),
            event = swarm.next() => match event.ok_or(Error::Transport)? {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    return if peer_id == peer { Ok(()) } else { Err(Error::DkgProtocol) };
                }
                SwarmEvent::OutgoingConnectionError { .. } => return Err(Error::Transport),
                SwarmEvent::Behaviour(network::Event::Session(request_response::Event::Message { message, .. })) => {
                    match message {
                        request_response::Message::Request { request, .. } => { let _bytes = Zeroizing::new(request); }
                        request_response::Message::Response { response, .. } => { let _bytes = Zeroizing::new(response); }
                    }
                    return Err(Error::DkgProtocol);
                }
                _ => {},
            },
        }
    }
}

async fn ceremony(
    swarm: &mut Swarm<network::Behaviour>, peer: PeerId, expected_key: &[u8; 32],
    hello: &session::Envelope, key: &SigningKey, parameters: &config::DkgParameters,
) -> Result<[u8; 32]> {
    let deadline = tokio::time::Instant::now() + session::SESSION_LIFETIME;
    connect(swarm, peer).await?;
    let hello_ack = exchange(swarm, peer, expected_key, hello, session::kind::ACK, parameters, deadline).await?;
    let confirmation = envelope_from(&hello_ack, 1, session::kind::ACK,
        Zeroizing::new(hello_ack.ack_digest().to_vec()), key);
    let round1 = exchange(swarm, peer, expected_key, &confirmation, session::kind::DKG_ROUND1, parameters, deadline).await?;
    let digest = context(parameters, &round1);
    let peer_round1 = Zeroizing::new(package(&round1, &digest)?.to_vec());
    let (mut dkg, own_round1) = ziquid_threshold::DkgSession::start(ziquid_threshold::Participant::Second, &mut OsRng)
        .map_err(|_| Error::DkgCrypto)?;
    let own_round1 = Zeroizing::new(own_round1);
    let own_round2 = dkg.round2(&peer_round1).map_err(|_| Error::DkgCrypto)?;
    let round1_request = envelope_from(&hello_ack, 2, session::kind::DKG_ROUND1,
        package_body(&digest, &own_round1), key);
    let round2 = exchange(swarm, peer, expected_key, &round1_request, session::kind::DKG_ROUND2, parameters, deadline).await?;
    let peer_round2 = package(&round2, &digest)?;
    let (key_share, group) = dkg.finalize(&peer_round1, peer_round2).map_err(|_| Error::DkgCrypto)?;
    let commit: [u8; 32] = Sha256::digest(group.to_bytes()).into();
    drop(key_share); // Ephemeral keygen only: this command grants no signing/custody capability.
    drop(group);
    drop(round2);
    let round2_request = envelope_from(&hello_ack, 3, session::kind::DKG_ROUND2,
        package_body(&digest, &own_round2), key);
    drop(own_round2);
    let final_commit = exchange(swarm, peer, expected_key, &round2_request, session::kind::DKG_FINAL_COMMIT, parameters, deadline).await?;
    drop(round2_request);
    if final_commit.body.as_slice() != commit.as_slice() { return Err(Error::DkgProtocol); }
    let commit_request = envelope_from(&hello_ack, 4, session::kind::DKG_FINAL_COMMIT,
        Zeroizing::new(commit.to_vec()), key);
    let _terminal_ack = exchange(swarm, peer, expected_key, &commit_request, session::kind::ACK, parameters, deadline).await?;
    Ok(commit) // Terminal ACK is deliberately never acknowledged again.
}

pub(super) async fn handshake(options: Options) -> Result<()> {
    let address = config::address(&options.address, true)?;
    if options.peer_id.len() > 256 { return Err(Error::Configuration); }
    let peer: PeerId = options.peer_id.parse().map_err(|_| Error::Configuration)?;
    if config::dial_peer(&address) != peer { return Err(Error::Configuration); }
    let expected_key = config::peer_coord_key(&peer)?;
    let parameters = config::DkgParameters::parse(options.dkg_pool_id, &options.dkg_j_params,
        &options.dkg_chain_context, &options.dkg_deployment_context)?;
    let identity = match &options.peer_identity_file {
        Some(path) => super::identity::load_or_create(path)?,
        None => libp2p::identity::Keypair::generate_ed25519(),
    };
    if identity.public().to_peer_id() == peer { return Err(Error::Configuration); }
    let pair = identity.clone().try_into_ed25519().map_err(|_| Error::Transport)?;
    let secret = Zeroizing::new(<[u8; 32]>::try_from(pair.secret().as_ref()).map_err(|_| Error::Transport)?);
    let key = SigningKey::from_bytes(&secret);
    drop(secret);
    drop(pair);
    let mut swarm = network::client_swarm(identity)?;
    swarm.dial(DialOpts::peer_id(peer).addresses(vec![address])
        .condition(libp2p::swarm::dial_opts::PeerCondition::Always).build()).map_err(|_| Error::Transport)?;
    let mut hello = GuardedEnvelope(session::Envelope {
        lane_id: options.lane_id,
        chain_context_digest: parameters.chain_context,
        deployment_digest: parameters.deployment_context,
        session_id: session::fresh_nonce(),
        initiator_coord_key: *key.verifying_key().as_bytes(),
        responder_coord_key: [0; 32],
        role_map: 0,
        challenge_i: session::fresh_nonce(),
        challenge_r: [0; 32],
        seq: 0,
        kind: session::kind::HELLO,
        sent_at_unix: super::state::now_unix_secs(),
        body: Vec::new(),
        signature: [0; 64],
    });
    sign(&mut hello, &key);
    let commit = tokio::select! {
        result = ceremony(&mut swarm, peer, &expected_key, &hello, &key, &parameters) => result?,
        result = tokio::signal::ctrl_c() => {
            result.map_err(|_| Error::Signal)?;
            return Err(Error::Signal);
        }
    };
    network::completed(&peer, &commit)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        local: SigningKey,
        initiator: SigningKey,
        policy: config::DkgPolicy,
        sessions: session::SessionTable,
    }

    impl Fixture {
        fn new() -> Self {
            let local = SigningKey::from_bytes(&[1; 32]);
            let initiator = SigningKey::from_bytes(&[2; 32]);
            let public = libp2p::identity::ed25519::PublicKey::try_from_bytes(
                initiator.verifying_key().as_bytes(),
            ).unwrap();
            let public: libp2p::identity::PublicKey = public.into();
            let policy = config::DkgPolicy {
                peer: public.to_peer_id(),
                parameters: config::DkgParameters {
                    pool_id: 0, j_params: vec![0, 1, 127],
                    chain_context: [3; 32], deployment_context: [4; 32],
                },
            };
            let sessions = session::SessionTable::new(*local.verifying_key().as_bytes());
            Self { local, initiator, policy, sessions }
        }

        fn hello(&self) -> GuardedEnvelope {
            let mut hello = GuardedEnvelope(session::Envelope {
                lane_id: 1,
                chain_context_digest: self.policy.parameters.chain_context,
                deployment_digest: self.policy.parameters.deployment_context,
                session_id: session::fresh_nonce(),
                initiator_coord_key: *self.initiator.verifying_key().as_bytes(),
                responder_coord_key: [0; 32], role_map: 0,
                challenge_i: session::fresh_nonce(), challenge_r: [0; 32],
                seq: 0, kind: session::kind::HELLO,
                sent_at_unix: super::super::state::now_unix_secs(),
                body: Vec::new(), signature: [0; 64],
            });
            sign(&mut hello, &self.initiator);
            hello
        }

        fn answer(&mut self, request: &session::Envelope) -> Result<Response> {
            respond(&self.policy.peer, request, Some(&self.policy), &self.local, &mut self.sessions)
        }

        fn exact(&mut self, request: &session::Envelope, kind: u8) -> (GuardedEnvelope, Option<[u8; 32]>) {
            let response = self.answer(request).unwrap();
            let retry = self.answer(request).unwrap();
            assert_eq!(&*response.payload, &*retry.payload, "retry must reuse signed response bytes");
            assert!(retry.completed.is_none(), "retry must not duplicate completion");
            let decoded = GuardedEnvelope(session::parse(&response.payload).unwrap());
            verify_response(&decoded, request, self.local.verifying_key().as_bytes(), kind,
                &self.policy.parameters).unwrap();
            (decoded, response.completed)
        }

        fn start(&mut self) -> (GuardedEnvelope, GuardedEnvelope) {
            let hello = self.hello();
            let (pins, completed) = self.exact(&hello, session::kind::ACK);
            assert!(completed.is_none());
            let confirmation = envelope_from(&pins, 1, session::kind::ACK,
                Zeroizing::new(pins.ack_digest().to_vec()), &self.initiator);
            let (round1, completed) = self.exact(&confirmation, session::kind::DKG_ROUND1);
            assert!(completed.is_none());
            (pins, round1)
        }
    }

    #[test]
    fn every_exact_retry_preserves_real_ceremony_and_terminal_ack_is_not_reacknowledged() {
        let mut fixture = Fixture::new();
        let (pins, round1) = fixture.start();
        let digest = context(&fixture.policy.parameters, &pins);
        let peer_round1 = package(&round1, &digest).unwrap();
        let (mut dkg, own_round1) = ziquid_threshold::DkgSession::start(
            ziquid_threshold::Participant::Second, &mut OsRng,
        ).unwrap();
        let own_round1 = Zeroizing::new(own_round1);
        let own_round2 = dkg.round2(peer_round1).unwrap();
        let round1_request = envelope_from(&pins, 2, session::kind::DKG_ROUND1,
            package_body(&digest, &own_round1), &fixture.initiator);
        let (round2, completed) = fixture.exact(&round1_request, session::kind::DKG_ROUND2);
        assert!(completed.is_none());
        let (share, group) = dkg.finalize(peer_round1, package(&round2, &digest).unwrap()).unwrap();
        drop(share);
        let commit: [u8; 32] = Sha256::digest(group.to_bytes()).into();
        let round2_request = envelope_from(&pins, 3, session::kind::DKG_ROUND2,
            package_body(&digest, &own_round2), &fixture.initiator);
        let (final_commit, completed) = fixture.exact(&round2_request, session::kind::DKG_FINAL_COMMIT);
        assert!(completed.is_none());
        assert_eq!(final_commit.body.as_slice(), commit.as_slice());
        let commit_request = envelope_from(&pins, 4, session::kind::DKG_FINAL_COMMIT,
            Zeroizing::new(commit.to_vec()), &fixture.initiator);
        let (terminal, completed) = fixture.exact(&commit_request, session::kind::ACK);
        assert_eq!(completed, Some(commit));
        // An attempted ACK loop is a new unsupported operation, not an exact retry.
        let reack = envelope_from(&pins, 5, session::kind::ACK,
            Zeroizing::new(terminal.ack_digest().to_vec()), &fixture.initiator);
        assert!(fixture.answer(&reack).is_err());
        assert!(fixture.sessions.dkg_retry_response(&fixture.policy.peer, &pins.session_id,
            &round2_request.sha256()).is_none(), "failure must destroy share-bearing retry bytes");
    }

    #[test]
    fn malformed_or_wrong_context_round1_closes_the_entire_ceremony() {
        for corruption in 0..3 {
            let mut fixture = Fixture::new();
            let (pins, _round1) = fixture.start();
            let (_, own_round1) = ziquid_threshold::DkgSession::start(
                ziquid_threshold::Participant::Second, &mut OsRng,
            ).unwrap();
            let mut own_round1 = Zeroizing::new(own_round1);
            let digest = context(&fixture.policy.parameters, &pins);
            match corruption {
                0 => own_round1.push(0), // A valid package plus trailing bytes is not canonical.
                1 => { own_round1.zeroize(); own_round1.push(0); }
                _ => {},
            }
            let mut request = envelope_from(&pins, 2, session::kind::DKG_ROUND1,
                package_body(&digest, &own_round1), &fixture.initiator);
            if corruption == 2 {
                request.body[0] ^= 1;
                sign(&mut request, &fixture.initiator);
            }
            assert!(fixture.answer(&request).is_err());
            assert!(fixture.answer(&request).is_err(), "a failed operation must never be resumable");
            assert!(fixture.sessions.begin_outbound(&fixture.policy.peer, &pins.session_id).is_err());
        }
    }

    #[test]
    fn malformed_round2_and_mismatched_final_commit_cannot_complete() {
        for wrong_commit in [false, true] {
            let mut fixture = Fixture::new();
            let (pins, round1) = fixture.start();
            let digest = context(&fixture.policy.parameters, &pins);
            let (mut dkg, own_round1) = ziquid_threshold::DkgSession::start(
                ziquid_threshold::Participant::Second, &mut OsRng,
            ).unwrap();
            let own_round1 = Zeroizing::new(own_round1);
            let mut own_round2 = dkg.round2(package(&round1, &digest).unwrap()).unwrap();
            let request = envelope_from(&pins, 2, session::kind::DKG_ROUND1,
                package_body(&digest, &own_round1), &fixture.initiator);
            let (round2, _) = fixture.exact(&request, session::kind::DKG_ROUND2);
            if !wrong_commit {
                let mut malformed = Zeroizing::new(Vec::with_capacity(own_round2.len() + 1));
                malformed.extend_from_slice(&own_round2);
                malformed.push(0);
                own_round2 = malformed;
            }
            let request = envelope_from(&pins, 3, session::kind::DKG_ROUND2,
                package_body(&digest, &own_round2), &fixture.initiator);
            if wrong_commit {
                let (share, group) = dkg.finalize(package(&round1, &digest).unwrap(),
                    package(&round2, &digest).unwrap()).unwrap();
                drop(share);
                let mut commit: [u8; 32] = Sha256::digest(group.to_bytes()).into();
                fixture.exact(&request, session::kind::DKG_FINAL_COMMIT);
                commit[0] ^= 1;
                let request = envelope_from(&pins, 4, session::kind::DKG_FINAL_COMMIT,
                    Zeroizing::new(commit.to_vec()), &fixture.initiator);
                assert!(fixture.answer(&request).is_err());
            } else {
                assert!(fixture.answer(&request).is_err());
            }
            assert!(fixture.sessions.begin_outbound(&fixture.policy.peer, &pins.session_id).is_err());
        }
    }

    #[test]
    fn response_signature_timestamp_every_pin_sequence_and_ack_are_required() {
        let mut fixture = Fixture::new();
        let hello = fixture.hello();
        let response = fixture.answer(&hello).unwrap();
        let ack = GuardedEnvelope(session::parse(&response.payload).unwrap());
        for corruption in 0..14 {
            let mut bad = GuardedEnvelope(ack.0.clone());
            match corruption {
                0 => bad.lane_id += 1,
                1 => bad.chain_context_digest[0] ^= 1,
                2 => bad.deployment_digest[0] ^= 1,
                3 => bad.session_id[0] ^= 1,
                4 => bad.initiator_coord_key[0] ^= 1,
                5 => bad.responder_coord_key[0] ^= 1,
                6 => bad.role_map ^= 1,
                7 => bad.challenge_i[0] ^= 1,
                8 => bad.challenge_r = [0; 32],
                9 => bad.seq += 1,
                10 => bad.kind = session::kind::DKG_FINAL_COMMIT,
                11 => bad.sent_at_unix = 0,
                12 => bad.body[0] ^= 1,
                _ => {},
            }
            sign(&mut bad, &fixture.local);
            if corruption == 13 { bad.signature[0] ^= 1; }
            assert!(verify_response(&bad, &hello, fixture.local.verifying_key().as_bytes(),
                session::kind::ACK, &fixture.policy.parameters).is_err(), "accepted corruption {corruption}");
        }
        let confirmation = envelope_from(&ack, 1, session::kind::ACK,
            Zeroizing::new(ack.ack_digest().to_vec()), &fixture.initiator);
        let response = fixture.answer(&confirmation).unwrap();
        let round1 = GuardedEnvelope(session::parse(&response.payload).unwrap());
        for corruption in 0..5 {
            let mut bad = GuardedEnvelope(round1.0.clone());
            match corruption {
                0 => bad.challenge_r[0] ^= 1,
                1 => bad.body[0] ^= 1,
                2 => bad.chain_context_digest[0] ^= 1,
                3 => bad.deployment_digest[0] ^= 1,
                _ => bad.responder_coord_key[0] ^= 1,
            }
            sign(&mut bad, &fixture.local);
            assert!(verify_response(&bad, &confirmation, fixture.local.verifying_key().as_bytes(),
                session::kind::DKG_ROUND1, &fixture.policy.parameters).is_err());
        }
    }

    #[test]
    fn admitted_exact_retry_survives_timestamp_aging_but_new_stale_bytes_reject() {
        let mut fixture = Fixture::new();
        let mut hello = fixture.hello();
        hello.sent_at_unix = 1;
        sign(&mut hello, &fixture.initiator);
        let session::Admitted::Hello { challenge_r } = fixture.sessions.admit_request(
            &fixture.policy.peer, &hello, [5; 32], 1,
        ).unwrap() else { panic!("Hello must bootstrap at its original admitted time"); };
        let mut ack = envelope_from(&hello, 0, session::kind::ACK,
            Zeroizing::new(hello.ack_digest().to_vec()), &fixture.local);
        ack.responder_coord_key = *fixture.local.verifying_key().as_bytes();
        ack.challenge_r = challenge_r;
        ack.sent_at_unix = 1;
        sign(&mut ack, &fixture.local);
        fixture.sessions.record_hello_response(&fixture.policy.peer, &hello.session_id, &ack);
        let cached = payload(&ack).unwrap();
        fixture.sessions.dkg_store_response(&fixture.policy.peer, &hello.session_id,
            hello.sha256(), cached.to_vec()).unwrap();
        let response = fixture.answer(&hello).unwrap();
        assert_eq!(&*response.payload, &*cached, "known admitted bytes must return their old signed response");
        assert!(response.completed.is_none());
        let confirmation = envelope_from(&ack, 1, session::kind::ACK,
            Zeroizing::new(ack.ack_digest().to_vec()), &fixture.initiator);
        let mut stale = confirmation;
        stale.sent_at_unix = 1;
        sign(&mut stale, &fixture.initiator);
        assert!(fixture.answer(&stale).is_err(), "unknown stale bytes must not gain cache admission");
    }
}
