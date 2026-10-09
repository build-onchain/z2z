use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use ziquid_runtime::native_quote::{
    AuthenticatedQuote, NativeRole, QuoteError, QuotePhase, QuoteSelection, QuoteV1, QUOTE_BYTES,
};

const QUOTE_DOMAIN: &[u8] = b"Z2Z_NATIVE_QUOTE\0";
const ACCEPT_DOMAIN: &[u8] = b"Z2Z_NATIVE_ACCEPT\0";
const VERSION: u16 = 1;

fn digest(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

fn terms() -> Zeroizing<[u8; QUOTE_BYTES]> {
    let mut body = Zeroizing::new([0; QUOTE_BYTES]);
    for (offset, domain) in [(0, QUOTE_DOMAIN), (91, b"Z2Z_NATIVE_ROUTE\0".as_slice()),
        (303, b"Z2Z_NATIVE_DEPLOY\0".as_slice()), (587, b"Z2Z_NATIVE_WINDOW\0".as_slice())] {
        body[offset..offset + domain.len()].copy_from_slice(domain);
        body[offset + domain.len()..offset + domain.len() + 2].copy_from_slice(&VERSION.to_be_bytes());
    }
    body[19..51].copy_from_slice(&[8; 32]);
    body[51..83].copy_from_slice(&[9; 32]);
    body[83..91].copy_from_slice(&1_791_504_000_u64.to_be_bytes());
    body
}

fn selection(body: &[u8]) -> QuoteSelection {
    QuoteSelection {
        local_role: NativeRole::User, owner_scope: [1; 32], session_id: [2; 32],
        initiator_coord_key: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
        responder_coord_key: SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes(),
        chain_context: digest(&body[91..303]), deployment_context: digest(&body[303..587]),
        quote_id: [8; 32], s_offer_id: [9; 32], u_trade_intent_id: [10; 32],
        challenge_i: [11; 32], challenge_r: [12; 32],
        proposal_seq: 5, user_acceptance_seq: 6, solver_acceptance_seq: 7,
    }
}

fn envelope(selection: &QuoteSelection, signer: &SigningKey, seq: u32, kind: u8,
    challenges: ([u8; 32], [u8; 32]), body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(322 + body.len()));
    bytes.extend_from_slice(b"Z2Z_SESSION\0");
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&5_u16.to_be_bytes());
    for field in [selection.chain_context, selection.deployment_context, selection.session_id,
        selection.initiator_coord_key, selection.responder_coord_key] { bytes.extend_from_slice(&field); }
    bytes.push(0);
    bytes.extend_from_slice(&challenges.0);
    bytes.extend_from_slice(&challenges.1);
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.push(kind);
    // Durable decoding verifies the recorded transcript, not today's clock.
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(body);
    let signature = signer.sign(&bytes).to_bytes();
    bytes.extend_from_slice(&signature);
    bytes
}

fn acceptance(role: NativeRole, selection: &QuoteSelection, q: [u8; 32], proposal: [u8; 32],
    predecessor: [u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(ACCEPT_DOMAIN.len() + 163));
    bytes.extend_from_slice(ACCEPT_DOMAIN);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(role as u8);
    for field in [selection.quote_id, q, proposal, selection.u_trade_intent_id, predecessor] {
        bytes.extend_from_slice(&field);
    }
    bytes
}

fn frames(body: &[u8], selected: &QuoteSelection, challenges: [([u8; 32], [u8; 32]); 3],
    sequences: [u32; 3]) -> [Zeroizing<Vec<u8>>; 3] {
    let user = SigningKey::from_bytes(&[3; 32]);
    let solver = SigningKey::from_bytes(&[4; 32]);
    let proposal = envelope(selected, &solver, sequences[0], 13, challenges[0], body);
    let proposal_hash = digest(&proposal);
    let user_body = acceptance(NativeRole::User, selected, digest(body), proposal_hash, proposal_hash);
    let user_frame = envelope(selected, &user, sequences[1], 14, challenges[1], &user_body);
    let solver_body = acceptance(NativeRole::Solver, selected, digest(body), proposal_hash, digest(&user_frame));
    let solver_frame = envelope(selected, &solver, sequences[2], 14, challenges[2], &solver_body);
    [proposal, user_frame, solver_frame]
}

fn bundle(frames: &[Zeroizing<Vec<u8>>], phase: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(36 + frames.iter().map(|f| f.len()).sum::<usize>()));
    bytes.extend_from_slice(b"Z2Z_NATIVE_AUTH_QUOTE\0");
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    for (index, frame) in frames.iter().enumerate() {
        let frame = if index <= phase { frame.as_slice() } else { &[] };
        bytes.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        bytes.extend_from_slice(frame);
    }
    bytes
}

#[test]
fn real_signed_proposal_user_acceptance_and_agreement_round_trip() {
    let body = terms();
    let selected = selection(body.as_slice());
    let frames = frames(body.as_slice(), &selected, [(selected.challenge_i, selected.challenge_r); 3], [5, 6, 7]);
    let mut quote = AuthenticatedQuote::from_proposal(&frames[0], &selected).unwrap();
    for (index, phase) in [QuotePhase::Proposal, QuotePhase::UserAcceptance, QuotePhase::Agreed].into_iter().enumerate() {
        if index != 0 { quote = quote.with_acceptance(&frames[index]).unwrap(); }
        let bytes = bundle(&frames, index);
        let decoded = AuthenticatedQuote::decode(&bytes, &selected).unwrap();
        assert_eq!(quote.phase(), phase);
        assert_eq!(decoded.phase(), phase);
        assert_eq!(quote.encode().as_slice(), bytes.as_slice());
        assert_eq!(decoded.encode().as_slice(), bytes.as_slice());
        assert_eq!(quote.digest(), digest(body.as_slice()));
        assert_eq!(quote.proposal_hash(), digest(&frames[0]));
        assert_eq!(quote.user_acceptance_hash(), (index >= 1).then(|| digest(&frames[1])));
        assert_eq!(quote.solver_acceptance_hash(), (index >= 2).then(|| digest(&frames[2])));
        assert_eq!(quote.agreement_digest().is_some(), index == 2);
    }
}

#[test]
fn challenge_substitution_rejects_every_resigned_frame_and_consistent_replacement() {
    let body = terms();
    let selected = selection(body.as_slice());
    for frame in 0..3 {
        for challenge in 0..2 {
            let mut challenges = [(selected.challenge_i, selected.challenge_r); 3];
            if challenge == 0 { challenges[frame].0[0] ^= 1; } else { challenges[frame].1[0] ^= 1; }
            // Re-sign every frame and rebuild all dependent proposal/predecessor hashes.
            let frames = frames(body.as_slice(), &selected, challenges, [5, 6, 7]);
            assert!(matches!(AuthenticatedQuote::decode(&bundle(&frames, 2), &selected), Err(QuoteError::Selection)));
        }
    }
    let frames = frames(body.as_slice(), &selected, [([21; 32], [22; 32]); 3], [5, 6, 7]);
    assert!(matches!(AuthenticatedQuote::decode(&bundle(&frames, 2), &selected), Err(QuoteError::Selection)));
}

#[test]
fn unsupported_nested_versions_reject_even_when_contexts_and_acceptances_are_resigned() {
    for (offset, domain) in [(91, b"Z2Z_NATIVE_ROUTE\0".as_slice()),
        (303, b"Z2Z_NATIVE_DEPLOY\0".as_slice()), (587, b"Z2Z_NATIVE_WINDOW\0".as_slice())] {
        for version in [0_u16, 2] {
            let mut body = terms();
            body[offset + domain.len()..offset + domain.len() + 2].copy_from_slice(&version.to_be_bytes());
            let selected = selection(body.as_slice());
            let frames = frames(body.as_slice(), &selected, [(selected.challenge_i, selected.challenge_r); 3], [5, 6, 7]);
            assert!(matches!(QuoteV1::decode(body.as_slice()), Err(QuoteError::Encoding)));
            for phase in [0, 2] {
                assert!(matches!(AuthenticatedQuote::decode(&bundle(&frames, phase), &selected), Err(QuoteError::Encoding)));
            }
        }
    }
}

#[test]
fn selected_sender_sequence_slots_reject_reuse_and_gaps_after_resigning() {
    let body = terms();
    let selected = selection(body.as_slice());
    for index in 0..3 {
        for delta in [-1_i32, 1] {
            let mut sequences = [5_u32, 6, 7];
            sequences[index] = (sequences[index] as i32 + delta) as u32;
            let frames = frames(body.as_slice(), &selected, [(selected.challenge_i, selected.challenge_r); 3], sequences);
            assert!(matches!(AuthenticatedQuote::decode(&bundle(&frames, 2), &selected), Err(QuoteError::Selection)));
        }
    }
}

#[test]
fn real_signature_without_selected_signer_or_acceptance_links_never_agrees() {
    let body = terms();
    let selected = selection(body.as_slice());
    let challenges = (selected.challenge_i, selected.challenge_r);
    let mut signed = frames(body.as_slice(), &selected, [challenges; 3], [5, 6, 7]);
    signed[0] = envelope(&selected, &SigningKey::from_bytes(&[7; 32]), 5, 13, challenges, body.as_slice());
    assert!(matches!(AuthenticatedQuote::decode(&bundle(&signed, 0), &selected), Err(QuoteError::Authentication)));
    for field in 0..5 {
        let mut signed = frames(body.as_slice(), &selected, [challenges; 3], [5, 6, 7]);
        let mut accept = acceptance(NativeRole::User, &selected, digest(body.as_slice()), digest(&signed[0]), digest(&signed[0]));
        accept[ACCEPT_DOMAIN.len() + 3 + field * 32] ^= 1;
        signed[1] = envelope(&selected, &SigningKey::from_bytes(&[3; 32]), 6, 14, challenges, &accept);
        assert!(matches!(AuthenticatedQuote::decode(&bundle(&signed, 1), &selected), Err(QuoteError::Selection)));
    }
}

#[test]
fn quote_decoder_rejects_truncation_unknown_domains_and_trailing_bytes() {
    assert!(matches!(QuoteV1::decode(&vec![0; QUOTE_BYTES - 1]), Err(QuoteError::Encoding)));
    assert!(QuoteV1::decode(&vec![0; QUOTE_BYTES]).is_err());
    assert!(QuoteV1::decode(&vec![0; QUOTE_BYTES + 1]).is_err());
    let body = terms();
    let selected = selection(body.as_slice());
    let signed = frames(body.as_slice(), &selected, [(selected.challenge_i, selected.challenge_r); 3], [5, 6, 7]);
    let mut bytes = bundle(&signed, 2);
    bytes.push(0);
    assert!(matches!(AuthenticatedQuote::decode(&bytes, &selected), Err(QuoteError::Encoding)));
    assert!(AuthenticatedQuote::decode(&bytes[..bytes.len() - 2], &selected).is_err());
}
