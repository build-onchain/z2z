use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use ziquid_runtime::native_quote::{AuthenticatedQuote, NativeRole, QuotePhase, QuoteSelection, QUOTE_BYTES};
use ziquid_runtime::native_trade::OperationBinding;

// Genuine signatures over synthetic local decoder terms, not live-session or financial qualification.
pub fn quote(phase: QuotePhase, identity: u8, terms_marker: u8) -> AuthenticatedQuote {
    let user = SigningKey::from_bytes(&[3; 32]);
    let solver = SigningKey::from_bytes(&[4; 32]);
    let mut body = [0_u8; QUOTE_BYTES];
    for (offset, domain) in [(0, b"Z2Z_NATIVE_QUOTE\0".as_slice()),
        (91, b"Z2Z_NATIVE_ROUTE\0".as_slice()), (303, b"Z2Z_NATIVE_DEPLOY\0".as_slice()),
        (587, b"Z2Z_NATIVE_WINDOW\0".as_slice())] {
        body[offset..offset + domain.len()].copy_from_slice(domain);
        body[offset + domain.len()..offset + domain.len() + 2].copy_from_slice(&1_u16.to_be_bytes());
    }
    body[19..51].copy_from_slice(&[identity; 32]);
    body[51..83].copy_from_slice(&[9; 32]);
    body[83..91].copy_from_slice(&1_791_504_000_u64.to_be_bytes());
    body[1000] = terms_marker;
    let selection = QuoteSelection {
        local_role: NativeRole::User, owner_scope: [1; 32], session_id: [2; 32],
        initiator_coord_key: user.verifying_key().to_bytes(), responder_coord_key: solver.verifying_key().to_bytes(),
        chain_context: Sha256::digest(&body[91..303]).into(),
        deployment_context: Sha256::digest(&body[303..587]).into(),
        quote_id: [identity; 32], s_offer_id: [9; 32], u_trade_intent_id: [10; 32],
        challenge_i: [11; 32], challenge_r: [12; 32],
        // Fresh-J ceremony retains both senders through slot4; quote ACKs occupy U5/S6.
        proposal_seq: 5, user_acceptance_seq: 6, solver_acceptance_seq: 7,
    };
    let proposal = envelope(&selection, &solver, selection.proposal_seq, 13, &body);
    let q: [u8; 32] = Sha256::digest(body).into();
    let proposal_hash: [u8; 32] = Sha256::digest(&proposal).into();
    let user_frame = if phase == QuotePhase::Proposal { Vec::new() } else {
        envelope(&selection, &user, selection.user_acceptance_seq, 14, &accept(NativeRole::User, &selection, q, proposal_hash, proposal_hash))
    };
    let solver_frame = if phase != QuotePhase::Agreed { Vec::new() } else {
        envelope(&selection, &solver, selection.solver_acceptance_seq, 14, &accept(NativeRole::Solver, &selection, q,
            proposal_hash, Sha256::digest(&user_frame).into()))
    };
    let mut bundle = b"Z2Z_NATIVE_AUTH_QUOTE\0".to_vec();
    bundle.extend_from_slice(&1_u16.to_be_bytes());
    for frame in [&proposal, &user_frame, &solver_frame] {
        bundle.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        bundle.extend_from_slice(frame);
    }
    AuthenticatedQuote::decode(&bundle, &selection).expect("genuinely signed coordination fixture")
}

fn accept(role: NativeRole, selection: &QuoteSelection, q: [u8; 32], proposal: [u8; 32], predecessor: [u8; 32]) -> Vec<u8> {
    let mut body = b"Z2Z_NATIVE_ACCEPT\0".to_vec();
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.push(role as u8);
    for id in [selection.quote_id, q, proposal, selection.u_trade_intent_id, predecessor] {
        body.extend_from_slice(&id);
    }
    body
}

fn envelope(selection: &QuoteSelection, key: &SigningKey, seq: u32, kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"Z2Z_SESSION\0".to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&5_u16.to_be_bytes());
    for id in [selection.chain_context, selection.deployment_context, selection.session_id,
        selection.initiator_coord_key, selection.responder_coord_key] { bytes.extend_from_slice(&id); }
    bytes.push(0);
    bytes.extend_from_slice(&selection.challenge_i);
    bytes.extend_from_slice(&selection.challenge_r);
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(&1_791_504_000_u64.to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&key.sign(&bytes).to_bytes());
    bytes
}

pub fn binding(op: u8, payload: &[u8]) -> OperationBinding {
    OperationBinding { op_id: [op; 32], context_digest: [21; 32], deployment_digest: [22; 32],
        stable_j_tag: [23; 32], payload_digest: Sha256::digest(payload).into(), action: 1 }
}

#[cfg(target_os = "linux")]
pub fn private_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap()
}
