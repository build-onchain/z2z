//! Synthetic owner-local keys only; no SQL, network, signing service or funded state.
use ed25519_dalek::{Signer, SigningKey};
use std::io::Write;
use std::process::{Command, Output, Stdio};
use zeroize::Zeroizing;
use ziquid_proofs::samechain::{MAX_PRIVATE_INPUT_BYTES, single_consent_message};
use ziquid_protocol::samechain::{
    Action, Asset, OutputDescriptor, OwnerJournal, PublicPacket, Role, SingleOwnerPacket,
    single_terms_commitment, validate_pair, validate_single,
};
use ziquid_protocol::samechain::fill::FillExecution;

// Shared synthetic fixture has additional helpers used by the proofs suite.
#[allow(dead_code)]
#[path = "../../proofs/tests/support/samechain.rs"]
mod support;

fn run(arguments: &[&str], bytes: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .arg("samechain")
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(bytes) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    let output = child.wait_with_output().unwrap();
    for argument in arguments {
        if argument.contains("sentinel") || argument.starts_with('/') {
            assert_not_disclosed(&output.stderr, argument.as_bytes());
        }
    }
    assert_private_diagnostic(&output.stderr, bytes);
    output
}

fn check_fill(bytes: &[u8]) -> Output {
    run(&["check-fill", "--witness-stdin"], bytes)
}

fn check_cancel_exit(bytes: &[u8]) -> Output {
    run(&["check-cancel-exit", "--witness-stdin"], bytes)
}

fn public_export(output: &Output, kind: &str, role: Role, action: Action) -> serde_json::Value {
    assert!(output.status.success(), "owner-local command failed");
    assert!(output.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut fields: Vec<_> = json.as_object().unwrap().keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(fields, [
        "action", "asset_backing", "evidence", "financial_execution", "global_unspentness",
        "journal", "kind", "packet", "packet_digest", "proof_certificate", "role",
        "root_eligibility", "strict_matching_privacy",
    ]);
    assert_eq!(json["kind"], kind);
    assert_eq!(json["role"], role as u8);
    assert_eq!(json["action"], action as u8);
    assert_eq!(json["evidence"], "native_owner_relation");
    assert_eq!(json["proof_certificate"], false);
    assert_eq!(json["root_eligibility"], "UNVERIFIED");
    assert_eq!(json["global_unspentness"], "UNVERIFIED");
    assert_eq!(json["asset_backing"], "UNVERIFIED");
    assert_eq!(json["financial_execution"], false);
    assert_eq!(json["strict_matching_privacy"], false);
    json
}

fn public_bytes(json: &serde_json::Value, field: &str) -> Vec<u8> {
    serde_json::from_value(json[field].clone()).unwrap()
}

fn assert_not_disclosed(diagnostic: &[u8], private: &[u8]) {
    if private.is_empty() { return; }
    assert!(!diagnostic.windows(private.len()).any(|window| window == private), "private bytes disclosed");
    // Decimal byte JSON needs at most four bytes per input byte plus brackets.
    let mut json = Zeroizing::new(Vec::with_capacity(private.len() * 4 + 2));
    serde_json::to_writer(&mut *json, private).unwrap();
    assert!(!diagnostic.windows(json.len()).any(|window| window == &json[..]), "private serialized bytes disclosed");
    if private.len() == 32 {
        use std::fmt::Write as _;
        let mut hex = Zeroizing::new(String::with_capacity(64));
        for byte in private { write!(&mut *hex, "{byte:02x}").unwrap(); }
        assert!(!diagnostic.windows(64).any(|window| window.eq_ignore_ascii_case(hex.as_bytes())), "private hex bytes disclosed");
    }
}

fn assert_private_diagnostic(diagnostic: &[u8], bytes: &[u8]) {
    if diagnostic.is_empty() { return; }
    assert_not_disclosed(diagnostic, bytes);
    if let Ok(witness) = ziquid_proofs::samechain::OwnerWitness::decode(bytes) {
        assert_not_disclosed(diagnostic, &witness.owner_seed);
        assert_not_disclosed(diagnostic, &witness.own_salt);
        assert_not_disclosed(diagnostic, &witness.input.encode().unwrap());
        for output in &witness.owned_outputs {
            assert_not_disclosed(diagnostic, &output.recovery_key);
            assert_not_disclosed(diagnostic, &output.note.encode().unwrap());
        }
    } else if let Ok(witness) = ziquid_proofs::samechain::CancelExitWitness::decode(bytes) {
        assert_not_disclosed(diagnostic, &witness.owner_seed);
        assert_not_disclosed(diagnostic, &witness.blind);
        assert_not_disclosed(diagnostic, &witness.input.encode().unwrap());
        for output in &witness.owned_outputs {
            assert_not_disclosed(diagnostic, &output.recovery_key);
            assert_not_disclosed(diagnostic, &output.note.encode().unwrap());
        }
    }
}

fn rejected(output: Output) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn controlled_fixture_owner_checks_export_the_same_exact_partial_fill_without_private_openings() {
    let fill = support::known_fill();
    let mut results = Vec::new();
    for owner in [&fill.a, &fill.b] {
        let result = check_fill(&owner.encode().unwrap());
        let json = public_export(&result, "check_fill", owner.role, Action::Fill);
        let packet_bytes = public_bytes(&json, "packet");
        let packet = PublicPacket::decode(&packet_bytes).unwrap();
        let journal_bytes = public_bytes(&json, "journal");
        let journal = OwnerJournal::decode(&journal_bytes).unwrap();
        assert_eq!(packet_bytes, fill.packet.encode().unwrap());
        assert_eq!(packet, fill.packet);
        assert_eq!(journal_bytes, journal.encode().unwrap());
        assert_eq!(public_bytes(&json, "packet_digest"), packet.digest().unwrap());
        assert_eq!(journal.input_nullifier, owner.input.nullifier().unwrap());
        assert_eq!(journal.generation, 7);
        assert_eq!(journal.role, owner.role);
        assert_eq!(journal.action, Action::Fill);
        results.push(journal);
    }
    validate_pair(&fill.packet, &results[0], &results[1]).unwrap();
}

#[test]
fn wrong_recovery_keys_and_freshly_consented_corrupt_ciphertexts_are_rejected() {
    let fill = support::known_fill();
    for owner in [&fill.a, &fill.b] {
        assert!(check_fill(&owner.encode().unwrap()).status.success());
        for owned_index in 0..owner.owned_outputs.len() {
            let mut wrong_key = owner.clone();
            wrong_key.owned_outputs[owned_index].recovery_key[0] ^= 1;
            rejected(check_fill(&wrong_key.encode().unwrap()));

            let mut damaged = owner.clone();
            let manifest_index = damaged.owned_outputs[owned_index].manifest_index as usize;
            let OutputDescriptor::Note { ciphertext, .. } = &mut damaged.packet.outputs[manifest_index] else {
                panic!("synthetic fixture must contain a recipient note");
            };
            ciphertext[24] ^= 1;
            // Fresh synthetic owner consent prevents a stale signature from
            // hiding a skipped recipient AEAD/recomputation check.
            support::rebind(&mut damaged);
            rejected(check_fill(&damaged.encode().unwrap()));
        }
    }
}

#[test]
fn freshly_encrypted_and_consented_invalid_note_semantics_are_rejected() {
    let fill = support::known_fill();
    assert!(check_fill(&fill.a.encode().unwrap()).status.success());
    let mut inflated = fill.a.clone();
    inflated.owned_outputs[1].note.value += primitive_types::U256::one();
    support::replace_note(&mut inflated, 1);
    support::rebind(&mut inflated);
    rejected(check_fill(&inflated.encode().unwrap()));

    let mut reused = fill.a.clone();
    reused.owned_outputs[0].note.nf_key = reused.input.nf_key;
    reused.owned_outputs[0].note.nonce = reused.input.nonce;
    support::replace_note(&mut reused, 0);
    support::rebind(&mut reused);
    rejected(check_fill(&reused.encode().unwrap()));
}


#[test]
fn altered_owner_consent_is_rejected_without_export_or_private_diagnostic() {
    let fill = support::known_fill();
    for owner in [&fill.a, &fill.b] {
        let mut wrong = owner.clone();
        wrong.consent[0] ^= 1;
        rejected(check_fill(&wrong.encode().unwrap()));
    }
    let mut wrong = support::cancel_exit(&fill, Action::Cancel);
    wrong.consent[0] ^= 1;
    rejected(check_cancel_exit(&wrong.encode().unwrap()));
}

#[test]
fn cancellation_and_exit_bind_the_exact_fill_predecessor_without_executing_it() {
    let fill = support::known_fill();
    let fill_output = check_fill(&fill.a.encode().unwrap());
    let fill_json = public_export(&fill_output, "check_fill", Role::A, Action::Fill);
    let fill_journal = OwnerJournal::decode(&public_bytes(&fill_json, "journal")).unwrap();
    for action in [Action::Cancel, Action::Exit] {
        let witness = support::cancel_exit(&fill, action);
        let result = check_cancel_exit(&witness.encode().unwrap());
        let json = public_export(&result, "check_cancel_exit", Role::A, action);
        let packet_bytes = public_bytes(&json, "packet");
        let packet = SingleOwnerPacket::decode(&packet_bytes).unwrap();
        let journal_bytes = public_bytes(&json, "journal");
        let journal = OwnerJournal::decode(&journal_bytes).unwrap();
        assert_eq!(packet, witness.packet);
        assert_eq!(packet_bytes, witness.packet.encode().unwrap());
        assert_eq!(journal_bytes, journal.encode().unwrap());
        assert_eq!(public_bytes(&json, "packet_digest"), packet.digest().unwrap());
        assert_eq!(journal.input_nullifier, fill_journal.input_nullifier);
        assert_eq!(journal.input_commitment, fill_journal.input_commitment);
        assert_eq!(journal.order_id, fill_journal.order_id);
        assert_eq!(journal.generation, fill_journal.generation);
        validate_single(&packet, &journal, Role::A, action).unwrap();

        let mut wrong = witness.clone();
        wrong.packet.input.nullifier[0] ^= 1;
        wrong.packet.terms_commitment = single_terms_commitment(
            &wrong.packet.deployment, &wrong.packet.input, &wrong.packet.outputs,
            wrong.packet.expiry, &wrong.blind,
        ).unwrap();
        wrong.consent = SigningKey::from_bytes(&wrong.owner_seed).sign(
            &single_consent_message(&wrong.packet, wrong.role, wrong.action).unwrap(),
        ).to_bytes();
        rejected(check_cancel_exit(&wrong.encode().unwrap()));

        let mut replay = witness.clone();
        replay.action = if action == Action::Cancel { Action::Exit } else { Action::Cancel };
        rejected(check_cancel_exit(&replay.encode().unwrap()));
    }
}

#[test]
fn malformed_trailing_and_oversize_private_frames_produce_no_public_output() {
    let fill = support::known_fill();
    let single = support::cancel_exit(&fill, Action::Exit);
    for (selector, encoded) in [
        ("check-fill", fill.a.encode().unwrap()),
        ("check-cancel-exit", single.encode().unwrap()),
    ] {
        let mut trailing = Zeroizing::new(vec![0; encoded.len() + 1]);
        trailing[..encoded.len()].copy_from_slice(&encoded);
        let mut oversize = Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES + 1]);
        oversize[..encoded.len()].copy_from_slice(&encoded);
        for bytes in [&[][..], &encoded[..encoded.len() - 1], &trailing[..]] {
            rejected(run(&[selector, "--witness-stdin"], bytes));
        }
        rejected(run(&[selector, "--witness-stdin"], &oversize));
    }
    rejected(check_fill(&single.encode().unwrap()));
    rejected(check_cancel_exit(&fill.a.encode().unwrap()));
}

#[test]
fn private_file_or_argument_selectors_and_missing_stdin_opt_in_are_redacted() {
    for arguments in [
        vec!["check-fill"],
        vec!["check-cancel-exit"],
        vec!["review-fill", "--witness-stdin"],
        vec!["review-fill", "--packet", "/public-packet", "--role", "a"],
        vec!["check-fill", "--witness-stdin", "private-opening-sentinel"],
        vec!["check-fill", "--witness-file", "/private-opening-sentinel"],
        vec!["check-cancel-exit", "--owner-seed", "private-opening-sentinel"],
    ] {
        let result = run(&arguments, &[]);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(!result.stderr.is_empty());
    }
}

fn selected_execution() -> FillExecution {
    FillExecution { asset_a: Asset::Native, asset_b: Asset::Token([7; 20]),
        sell_a: primitive_types::U256::from(40), sell_b: primitive_types::U256::from(50) }
}

fn review_fill(packet: &[u8], role: &str, witness: &[u8]) -> Output {
    review_fill_execution(packet, &selected_execution().encode().unwrap(), role, witness)
}

fn review_fill_execution(packet: &[u8], execution: &[u8], role: &str, witness: &[u8]) -> Output {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(packet).unwrap();
    let mut execution_file = tempfile::NamedTempFile::new().unwrap();
    execution_file.write_all(execution).unwrap();
    run(&["review-fill", "--packet", file.path().to_str().unwrap(),
        "--execution", execution_file.path().to_str().unwrap(), "--role", role, "--witness-stdin"], witness)
}

#[test]
fn unsigned_controlled_fixture_owners_review_selected_packet_before_consent() {
    let fill = support::known_fill();
    for (owner, role) in [(&fill.a, "a"), (&fill.b, "b")] {
        for consent in [[0; 64], [1; 64]] {
            let mut unsigned = owner.clone();
            unsigned.consent = consent;
            let result = review_fill(&fill.packet.encode().unwrap(), role, &unsigned.encode().unwrap());
            assert!(result.status.success(), "unsigned owner review failed");
            assert!(result.stderr.is_empty());
            let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            let mut fields: Vec<_> = json.as_object().unwrap().keys().map(String::as_str).collect();
            fields.sort_unstable();
            assert_eq!(fields, [
                "action", "asset_backing", "consent_message", "evidence", "financial_execution",
                "global_unspentness", "kind", "packet", "packet_digest", "proof_certificate",
                "role", "root_eligibility", "strict_matching_privacy",
            ]);
            assert_eq!(json["kind"], "review_fill");
            assert_eq!(json["role"], owner.role as u8);
            assert_eq!(json["action"], Action::Fill as u8);
            assert_eq!(json["evidence"], "native_owner_preconsent_review");
            for field in ["asset_backing", "global_unspentness", "root_eligibility"] {
                assert_eq!(json[field], "UNVERIFIED");
            }
            for field in ["financial_execution", "proof_certificate", "strict_matching_privacy"] {
                assert_eq!(json[field], false);
            }
            assert_eq!(public_bytes(&json, "packet"), fill.packet.encode().unwrap());
            assert_eq!(public_bytes(&json, "packet_digest"), fill.packet.digest().unwrap());
            assert_eq!(public_bytes(&json, "consent_message"),
                ziquid_proofs::samechain::fill_consent_message(&fill.packet, owner.role).unwrap());
            // Checking is still distinct from unsigned review.
            rejected(check_fill(&unsigned.encode().unwrap()));
        }
    }
}

#[test]
fn preconsent_review_rejects_wrong_selected_scope_and_invalid_successor() {
    let fill = support::known_fill();
    let mut unsigned = fill.a.clone();
    unsigned.consent = [0; 64];
    let bytes = unsigned.encode().unwrap();
    let mut wrong_packet = fill.packet.clone();
    wrong_packet.expiry += 1;
    rejected(review_fill(&wrong_packet.encode().unwrap(), "a", &bytes));
    let mut wrong_deployment = fill.packet.clone();
    wrong_deployment.deployment.chain_id += 1;
    rejected(review_fill(&wrong_deployment.encode().unwrap(), "a", &bytes));
    let mut wrong_order = fill.packet.clone();
    wrong_order.inputs[0].order_id[0] ^= 1;
    rejected(review_fill(&wrong_order.encode().unwrap(), "a", &bytes));
    rejected(review_fill(&fill.packet.encode().unwrap(), "b", &bytes));

    let mut successor = fill.a.clone();
    successor.owned_outputs[0].note.order.as_mut().unwrap().remaining_sell = primitive_types::U256::from(61);
    support::replace_note(&mut successor, 0);
    let selected_packet = support::rebind(&mut successor);
    successor.consent = [0; 64];
    rejected(review_fill(&selected_packet.encode().unwrap(), "a", &successor.encode().unwrap()));

    let mut wrong_key = unsigned.clone();
    wrong_key.owned_outputs[0].recovery_key[0] ^= 1;
    rejected(review_fill(&fill.packet.encode().unwrap(), "a", &wrong_key.encode().unwrap()));

    let mut damaged = unsigned.clone();
    let OutputDescriptor::Note { ciphertext, .. } = &mut damaged.packet.outputs[0] else {
        panic!("synthetic fixture must contain a recipient note");
    };
    ciphertext[24] ^= 1;
    let damaged_packet = support::rebind(&mut damaged);
    rejected(review_fill(&damaged_packet.encode().unwrap(), "a", &damaged.encode().unwrap()));

    let mut wrong_seed = unsigned.clone();
    wrong_seed.owner_seed = fill.b.owner_seed;
    rejected(review_fill(&fill.packet.encode().unwrap(), "a", &wrong_seed.encode().unwrap()));
}

#[test]
fn preconsent_review_bounds_public_packet_and_private_stdin() {
    let fill = support::known_fill();
    let packet = fill.packet.encode().unwrap();
    let encoded = fill.a.encode().unwrap();
    rejected(review_fill(&[], "a", &encoded));
    rejected(review_fill(&packet[..packet.len() - 1], "a", &encoded));
    let mut trailing_packet = packet.clone();
    trailing_packet.push(0);
    rejected(review_fill(&trailing_packet, "a", &encoded));
    let oversized_packet = vec![0; ziquid_protocol::samechain::MAX_PACKET_BYTES + 1];
    rejected(review_fill(&oversized_packet, "a", &encoded));
    let mut trailing_witness = Zeroizing::new(vec![0; encoded.len() + 1]);
    trailing_witness[..encoded.len()].copy_from_slice(&encoded);
    rejected(review_fill(&packet, "a", &trailing_witness));
    let oversized_witness = Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES + 1]);
    rejected(review_fill(&packet, "a", &oversized_witness));
    let invalid_role = review_fill(&packet, "private-role-sentinel", &[]);
    assert_eq!(invalid_role.status.code(), Some(2));
    assert!(invalid_role.stdout.is_empty());
    assert!(!invalid_role.stderr.is_empty());
}

#[test]
fn preconsent_requires_independently_selected_execution_even_when_wrong_amounts_meet_limits() {
    let fill = support::known_fill();
    let mut unsigned = fill.a.clone();
    unsigned.consent = [0; 64];
    let bytes = unsigned.encode().unwrap();
    let packet = fill.packet.encode().unwrap();
    let mut wrong = selected_execution();
    // 49 net token for 39 native still meets A's 1:1 limit; it is not the
    // selected 40/50 execution. Ignoring the independent selection is a bug.
    wrong.sell_a = primitive_types::U256::from(39);
    rejected(review_fill_execution(&packet, &wrong.encode().unwrap(), "a", &bytes));
    let execution = selected_execution().encode().unwrap();
    let mut trailing = execution.clone();
    trailing.push(0);
    let mut legacy = execution.clone();
    legacy[b"Z2Z_SAMECHAIN_FILL_EXECUTION\0".len() + 1] = 1;
    for invalid in [&[][..], &execution[..execution.len() - 1], &trailing, &legacy,
        &packet, &b"{\"sell_a\":40,\"sell_b\":50}"[..]] {
        rejected(review_fill_execution(&packet, invalid, "a", &bytes));
    }
    rejected(review_fill_execution(&packet,
        &vec![0; ziquid_protocol::samechain::MAX_PACKET_BYTES + 1], "a", &bytes));
    let mut wrong_assets = selected_execution();
    std::mem::swap(&mut wrong_assets.asset_a, &mut wrong_assets.asset_b);
    rejected(review_fill_execution(&packet, &wrong_assets.encode().unwrap(), "a", &bytes));
    let unavailable = run(&["review-fill", "--packet", "/missing-public-packet-sentinel",
        "--execution", "/missing-public-execution-sentinel", "--role", "a", "--witness-stdin"], &bytes);
    rejected(unavailable);
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&packet).unwrap();
    let missing = run(&["review-fill", "--packet", file.path().to_str().unwrap(),
        "--role", "a", "--witness-stdin"], &bytes);
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
}


fn review_cancel_exit(packet: &[u8], deployment: &[u8], order: &str, role: &str,
    action: &str, witness: &[u8]) -> Output
{
    let mut packet_file = tempfile::NamedTempFile::new().unwrap();
    packet_file.write_all(packet).unwrap();
    let mut deployment_file = tempfile::NamedTempFile::new().unwrap();
    deployment_file.write_all(deployment).unwrap();
    run(&["review-cancel-exit", "--packet", packet_file.path().to_str().unwrap(),
        "--deployment", deployment_file.path().to_str().unwrap(), "--order-id", order,
        "--role", role, "--action", action, "--witness-stdin"], witness)
}

#[test]
fn unsigned_cancel_exit_reviews_both_restored_owners_before_consent() {
    let fill = support::known_fill();
    let deployment = support::deployment().encode().unwrap();
    for (owner, role, order) in [
        (&fill.a, "a", "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        (&fill.b, "b", "0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
    ] {
        for (action, selector) in [(Action::Cancel, "cancel"), (Action::Exit, "exit")] {
            let mut witness = support::cancel_exit_from_note(owner.owned_outputs[0].note.clone(),
                owner.membership.clone(), owner.role, owner.owner_seed, action);
            for consent in [[0; 64], [44; 64]] {
                witness.consent = consent;
                let bytes = witness.encode().unwrap();
                let result = review_cancel_exit(&witness.packet.encode().unwrap(), &deployment,
                    order, role, selector, &bytes);
                assert!(result.status.success(), "unsigned cancel/exit review failed: {}",
                    String::from_utf8_lossy(&result.stderr));
                assert!(result.stderr.is_empty());
                let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
                assert!(json.get("journal").is_none());
                assert!(json.get("signature").is_none());
                assert_eq!(json["kind"], "review_cancel_exit");
                assert_eq!(json["role"], owner.role as u8);
                assert_eq!(json["action"], action as u8);
                assert_eq!(json["evidence"], "native_owner_preconsent_review");
                for field in ["asset_backing", "global_unspentness", "root_eligibility"] {
                    assert_eq!(json[field], "UNVERIFIED");
                }
                for field in ["financial_execution", "proof_certificate", "signing", "strict_matching_privacy"] {
                    assert_eq!(json[field], false);
                }
                assert_eq!(public_bytes(&json, "packet"), witness.packet.encode().unwrap());
                assert_eq!(public_bytes(&json, "packet_digest"), witness.packet.digest().unwrap());
                assert_eq!(public_bytes(&json, "consent_message"),
                    single_consent_message(&witness.packet, owner.role, action).unwrap());
                assert_private_diagnostic(&result.stdout, &bytes);
                rejected(check_cancel_exit(&bytes));
            }
        }
    }
}

const CANCEL_ORDER: &str = "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

#[test]
fn cancel_exit_review_rejects_independent_scope_mismatches_and_private_semantic_errors() {
    let fill = support::known_fill();
    for (action, selector) in [(Action::Cancel, "cancel"), (Action::Exit, "exit")] {
        let mut witness = support::cancel_exit(&fill, action);
        witness.consent = [0; 64];
        let deployment = support::deployment().encode().unwrap();
        let packet = witness.packet.encode().unwrap();
        let bytes = witness.encode().unwrap();
        assert!(review_cancel_exit(&packet, &deployment, CANCEL_ORDER, "a", selector, &bytes).status.success());
        let mut wrong_packet = witness.packet.clone();
        wrong_packet.expiry += 1;
        rejected(review_cancel_exit(&wrong_packet.encode().unwrap(), &deployment, CANCEL_ORDER, "a", selector, &bytes));
        for change in 0..6 {
            let mut wrong = support::deployment();
            match change {
                0 => wrong.chain_id += 1,
                1 => wrong.authority[0] ^= 1,
                2 => wrong.authority_code[0] ^= 1,
                3 => wrong.verifier[0] ^= 1,
                4 => wrong.verifier_code[0] ^= 1,
                _ => wrong.owner_program[0] ^= 1,
            }
            rejected(review_cancel_exit(&packet, &wrong.encode().unwrap(), CANCEL_ORDER, "a", selector, &bytes));
        }
        rejected(review_cancel_exit(&packet, &deployment,
            "0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "a", selector, &bytes));
        rejected(review_cancel_exit(&packet, &deployment, CANCEL_ORDER, "b", selector, &bytes));
        rejected(review_cancel_exit(&packet, &deployment, CANCEL_ORDER, "a",
            if action == Action::Cancel { "exit" } else { "cancel" }, &bytes));
        for change in 0..5 {
            let mut wrong = witness.clone();
            match change {
                0 => wrong.owner_seed = fill.b.owner_seed,
                1 => wrong.membership.siblings[0][0] ^= 1,
                2 => wrong.owned_outputs[0].recovery_key[0] ^= 1,
                3 => if let OutputDescriptor::Note { ciphertext, .. } = &mut wrong.packet.outputs[0] {
                    ciphertext[24] ^= 1;
                },
                _ => {
                    wrong.owned_outputs[0].note.value += primitive_types::U256::one();
                    let opening = &wrong.owned_outputs[0];
                    wrong.packet.outputs[0] = ziquid_proofs::samechain::prepare_output(&opening.note,
                        wrong.role, &opening.recovery_key, [202; 24]).unwrap();
                }
            }
            wrong.packet.terms_commitment = single_terms_commitment(&wrong.packet.deployment,
                &wrong.packet.input, &wrong.packet.outputs, wrong.packet.expiry, &wrong.blind).unwrap();
            wrong.consent = SigningKey::from_bytes(&wrong.owner_seed).sign(
                &single_consent_message(&wrong.packet, wrong.role, wrong.action).unwrap()).to_bytes();
            let wrong_bytes = wrong.encode().unwrap();
            rejected(check_cancel_exit(&wrong_bytes));
            rejected(review_cancel_exit(&wrong.packet.encode().unwrap(), &deployment,
                CANCEL_ORDER, "a", selector, &wrong_bytes));
        }
    }
}

#[test]
fn cancel_exit_review_bounds_canonical_public_files_and_private_stdin() {
    let mut witness = support::cancel_exit(&support::known_fill(), Action::Cancel);
    witness.consent = [0; 64];
    let packet = witness.packet.encode().unwrap();
    let deployment = support::deployment().encode().unwrap();
    let bytes = witness.encode().unwrap();
    for (is_packet, public) in [(true, &packet), (false, &deployment)] {
        let mut trailing = public.clone();
        trailing.push(0);
        let oversized = vec![0; ziquid_protocol::samechain::MAX_PACKET_BYTES + 1];
        for bad in [&[][..], &public[..public.len() - 1], &trailing, &oversized] {
            rejected(if is_packet {
                review_cancel_exit(bad, &deployment, CANCEL_ORDER, "a", "cancel", &bytes)
            } else {
                review_cancel_exit(&packet, bad, CANCEL_ORDER, "a", "cancel", &bytes)
            });
        }
    }
    let mut trailing = Zeroizing::new(vec![0; bytes.len() + 1]);
    trailing[..bytes.len()].copy_from_slice(&bytes);
    let oversized = Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES + 1]);
    for bad in [&[][..], &bytes[..bytes.len() - 1], &trailing, &oversized] {
        rejected(review_cancel_exit(&packet, &deployment, CANCEL_ORDER, "a", "cancel", bad));
    }
    for order in ["0x00", "private-order-sentinel",
        "0x0000000000000000000000000000000000000000000000000000000000000000"] {
        rejected(review_cancel_exit(&packet, &deployment, order, "a", "cancel", &bytes));
    }
    for (role, action) in [("private-role-sentinel", "cancel"), ("a", "fill")] {
        let result = review_cancel_exit(&packet, &deployment, CANCEL_ORDER, role, action, &[]);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn cancel_exit_review_requires_each_pin_and_stdin_opt_in_and_redacts_private_arguments() {
    let base = ["review-cancel-exit", "--packet", "/public-packet-sentinel", "--deployment",
        "/public-deployment-sentinel", "--order-id", CANCEL_ORDER, "--role", "a", "--action",
        "cancel", "--witness-stdin"];
    for removed in [1, 3, 5, 7, 9, 11] {
        let mut arguments = base.to_vec();
        arguments.remove(removed);
        if removed != 11 { arguments.remove(removed); }
        let result = run(&arguments, &[]);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
    for private_flag in ["--owner-seed", "--private-witness", "--witness-file"] {
        let mut arguments = base.to_vec();
        arguments.extend([private_flag, "private-opening-sentinel"]);
        let result = run(&arguments, &[]);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
    let mut arguments = base.to_vec();
    arguments.push("private-opening-sentinel");
    assert_eq!(run(&arguments, &[]).status.code(), Some(2));
    let bytes = support::cancel_exit(&support::known_fill(), Action::Cancel).encode().unwrap();
    rejected(run(&base, &bytes));
}
