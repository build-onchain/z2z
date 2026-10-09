#![cfg(target_os = "linux")]

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use ziquid_runtime::{native_quote::{NativeRole, QuotePhase, QuoteSelection, QuoteV1, QUOTE_BYTES},
    node::NativeQuoteSessions};

const NOW: u64 = 1_791_504_000;
fn digest(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }
fn peer(key: &SigningKey) -> libp2p::PeerId {
    let key = libp2p::identity::ed25519::PublicKey::try_from_bytes(key.verifying_key().as_bytes()).unwrap();
    libp2p::identity::PublicKey::from(key).to_peer_id()
}
fn terms() -> QuoteV1 {
    let mut bytes = Zeroizing::new([0; QUOTE_BYTES]);
    for (offset, domain) in [(0, b"Z2Z_NATIVE_QUOTE\0".as_slice()), (91, b"Z2Z_NATIVE_ROUTE\0".as_slice()),
        (303, b"Z2Z_NATIVE_DEPLOY\0".as_slice()), (587, b"Z2Z_NATIVE_WINDOW\0".as_slice())] {
        bytes[offset..offset + domain.len()].copy_from_slice(domain);
        bytes[offset + domain.len()..offset + domain.len() + 2].copy_from_slice(&1_u16.to_be_bytes());
    }
    bytes[19..51].fill(8); bytes[51..83].fill(9);
    bytes[83..91].copy_from_slice(&NOW.to_be_bytes());
    QuoteV1::decode(bytes.as_slice()).unwrap()
}
fn envelope(selected: &QuoteSelection, key: &SigningKey, seq: u32, kind: u8, body: &[u8], bootstrap: bool) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(322 + body.len()));
    bytes.extend_from_slice(b"Z2Z_SESSION\0"); bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&5_u16.to_be_bytes());
    for field in [selected.chain_context, selected.deployment_context, selected.session_id, selected.initiator_coord_key,
        if bootstrap { [0; 32] } else { selected.responder_coord_key }] { bytes.extend_from_slice(&field); }
    bytes.push(0); bytes.extend_from_slice(&selected.challenge_i);
    bytes.extend_from_slice(&if bootstrap { [0; 32] } else { selected.challenge_r });
    bytes.extend_from_slice(&seq.to_be_bytes()); bytes.push(kind); bytes.extend_from_slice(&NOW.to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes()); bytes.extend_from_slice(body);
    let signature = key.sign(&bytes).to_bytes();
    bytes.extend_from_slice(&signature); bytes
}

fn confirmed() -> (NativeQuoteSessions, NativeQuoteSessions, SigningKey, SigningKey, QuoteSelection, QuoteV1) {
    let user = SigningKey::from_bytes(&[3; 32]); let solver = SigningKey::from_bytes(&[4; 32]);
    let terms = terms();
    let selected = QuoteSelection {
        local_role: NativeRole::User, owner_scope: [1; 32], session_id: [2; 32],
        initiator_coord_key: user.verifying_key().to_bytes(), responder_coord_key: solver.verifying_key().to_bytes(),
        chain_context: digest(&terms.as_bytes()[91..303]), deployment_context: digest(&terms.as_bytes()[303..587]),
        quote_id: [8; 32], s_offer_id: [9; 32], u_trade_intent_id: [10; 32],
        challenge_i: [11; 32], challenge_r: [12; 32],
        // Hello confirmation consumes user1; each quote frame also consumes the receiver's ACK.
        proposal_seq: 1, user_acceptance_seq: 3, solver_acceptance_seq: 3,
    };
    let hello = envelope(&selected, &user, 0, 0, &[], true);
    let ack = envelope(&selected, &solver, 0, 9, &digest(&hello[..hello.len() - 64]), false);
    let confirmation = envelope(&selected, &user, 1, 9, &digest(&ack[..ack.len() - 64]), false);
    let mut users = NativeQuoteSessions::new(user.verifying_key().to_bytes());
    let mut solvers = NativeQuoteSessions::new(solver.verifying_key().to_bytes());
    users.retain_confirmed_transcript(&peer(&solver), &hello, &ack, &confirmation, NOW).unwrap();
    solvers.retain_confirmed_transcript(&peer(&user), &hello, &ack, &confirmation, NOW).unwrap();
    users.select_native_quote(&peer(&solver), selected).unwrap();
    let mut solver_selection = selected; solver_selection.local_role = NativeRole::Solver;
    solvers.select_native_quote(&peer(&user), solver_selection).unwrap();
    (users, solvers, user, solver, selected, terms)
}

fn frame(payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes()); bytes.extend_from_slice(payload); bytes
}

#[test]
fn real_dispatch_retains_signed_proposal_and_both_acceptances_with_ack_counters_and_exact_retries() {
    let (mut users, mut solvers, user, solver, selected, terms) = confirmed();
    let proposal = solvers.native_proposal(&peer(&user), &selected.session_id, &terms, &solver, NOW).unwrap();
    let framed = frame(&proposal);
    let prefix = u32::from_be_bytes(framed[..4].try_into().unwrap());
    assert_eq!(prefix, 3566);
    let ack = users.dispatch_native(&peer(&solver), &proposal, &user, NOW).unwrap().unwrap();
    let retry = users.dispatch_native(&peer(&solver), &proposal, &user, NOW + 1000).unwrap().unwrap();
    assert_eq!(ack.as_slice(), retry.as_slice(), "exact admitted retries reuse original signed ACK beyond skew");
    assert_eq!(users.native_quote(&peer(&solver), &selected.session_id).unwrap().phase(), QuotePhase::Proposal);
    assert!(solvers.dispatch_native(&peer(&user), &ack, &solver, NOW).unwrap().is_none(), "ACK is terminal control, not agreement");
    let acceptance = users.native_acceptance(&peer(&solver), &selected.session_id, &user, NOW).unwrap();
    assert_eq!(u32::from_be_bytes(acceptance[241..245].try_into().unwrap()), 3);
    let ack = solvers.dispatch_native(&peer(&user), &acceptance, &solver, NOW).unwrap().unwrap();
    let retry = solvers.dispatch_native(&peer(&user), &acceptance, &solver, NOW + 1000).unwrap().unwrap();
    assert_eq!(ack.as_slice(), retry.as_slice());
    users.dispatch_native(&peer(&solver), &ack, &user, NOW).unwrap();
    let agreement = solvers.native_acceptance(&peer(&user), &selected.session_id, &solver, NOW).unwrap();
    let ack = users.dispatch_native(&peer(&solver), &agreement, &user, NOW).unwrap().unwrap();
    let retry = users.dispatch_native(&peer(&solver), &agreement, &user, NOW + 1000).unwrap().unwrap();
    assert_eq!(ack.as_slice(), retry.as_slice());
    solvers.dispatch_native(&peer(&user), &ack, &solver, NOW).unwrap();
    let user_quote = users.native_quote(&peer(&solver), &selected.session_id).unwrap();
    let solver_quote = solvers.native_quote(&peer(&user), &selected.session_id).unwrap();
    assert_eq!(user_quote.phase(), QuotePhase::Agreed);
    assert_eq!(solver_quote.phase(), QuotePhase::Agreed);
    assert_eq!(user_quote.agreement_digest(), solver_quote.agreement_digest());
}

#[test]
fn actual_dispatch_rejects_unknown_peer_unselected_quote_sequence_reuse_and_gap() {
    for sequence in [0, 2] {
        let (mut users, _solvers, user, solver, selected, terms) = confirmed();
        let proposal = envelope(&selected, &solver, sequence, 13, terms.as_bytes(), false);
        assert!(users.dispatch_native(&peer(&solver), &proposal, &user, NOW).is_err());
        assert!(users.native_quote(&peer(&solver), &selected.session_id).is_none());
    }
    let (mut users, mut solvers, user, solver, selected, terms) = confirmed();
    let proposal = solvers.native_proposal(&peer(&user), &selected.session_id, &terms, &solver, NOW).unwrap();
    assert!(users.dispatch_native(&peer(&SigningKey::from_bytes(&[7; 32])), &proposal, &user, NOW).is_err());
    let mut unknown = NativeQuoteSessions::new(user.verifying_key().to_bytes());
    assert!(unknown.dispatch_native(&peer(&solver), &proposal, &user, NOW).is_err());
    let mut unselected = NativeQuoteSessions::new(user.verifying_key().to_bytes());
    let hello = envelope(&selected, &user, 0, 0, &[], true);
    let ack = envelope(&selected, &solver, 0, 9, &digest(&hello[..hello.len() - 64]), false);
    let confirm = envelope(&selected, &user, 1, 9, &digest(&ack[..ack.len() - 64]), false);
    unselected.retain_confirmed_transcript(&peer(&solver), &hello, &ack, &confirm, NOW).unwrap();
    assert!(unselected.dispatch_native(&peer(&solver), &proposal, &user, NOW).is_err());
    assert!(unknown.native_quote(&peer(&solver), &selected.session_id).is_none());
}

#[test]
fn selection_cannot_replace_admitted_challenges_or_sender_slots() {
    for changed in 0..5 {
        let (mut users, _solvers, _user, solver, mut selected, _terms) = confirmed();
        match changed {
            0 => selected.challenge_i[0] ^= 1,
            1 => selected.challenge_r[0] ^= 1,
            2 => selected.proposal_seq += 1,
            3 => selected.user_acceptance_seq += 1,
            _ => selected.solver_acceptance_seq += 1,
        }
        assert!(users.select_native_quote(&peer(&solver), selected).is_err());
    }
}

#[test]
fn actual_dispatch_rejects_resigned_challenge_substitution_bad_nested_versions_and_wrong_ack() {
    for corruption in 0..6 {
        let (mut users, mut solvers, user, solver, selected, terms) = confirmed();
        let mut proposal = solvers.native_proposal(&peer(&user), &selected.session_id, &terms, &solver, NOW).unwrap();
        match corruption {
            0 => proposal[177] ^= 1,
            1 => proposal[209] ^= 1,
            2 => proposal[258 + 108] = 1,
            3 => proposal[258 + 321] = 1,
            4 => proposal[258 + 605] = 1,
            _ => proposal[241..245].copy_from_slice(&2_u32.to_be_bytes()),
        }
        let length = proposal.len() - 64;
        let signature = solver.sign(&proposal[..length]).to_bytes();
        proposal[length..].copy_from_slice(&signature);
        assert!(users.dispatch_native(&peer(&solver), &proposal, &user, NOW).is_err());
        assert!(users.native_quote(&peer(&solver), &selected.session_id).is_none());
    }
    let (mut users, mut solvers, user, solver, selected, terms) = confirmed();
    let proposal = solvers.native_proposal(&peer(&user), &selected.session_id, &terms, &solver, NOW).unwrap();
    users.dispatch_native(&peer(&solver), &proposal, &user, NOW).unwrap();
    let wrong_ack = envelope(&selected, &user, 2, 9, &[42; 32], false);
    assert!(solvers.dispatch_native(&peer(&user), &wrong_ack, &solver, NOW).is_err());
    assert!(solvers.native_quote(&peer(&user), &selected.session_id).is_none());
}
