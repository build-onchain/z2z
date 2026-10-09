//! Actual subprocesses over a public synthetic loopback RPC fixture, not financial evidence.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Write, process::{Child, Command, Output, Stdio}, time::{Duration, Instant}};
use ziquid_chains::samechain::inspection::InspectionScope;

#[path = "../../chains/tests/support/samechain_inspection.rs"]
mod support;
use support::{Fault, Fixture};

const ENVIRONMENT: &str = "ZIQUID_INSPECTION_TEST_ENDPOINT";
const SECRET: &str = "inspection-private-query-sentinel";
const STDIN_SECRET: &[u8] = b"unread-private-stdin-sentinel";

fn hex(bytes: &[u8]) -> String {
    let mut value = String::from("0x");
    for byte in bytes { use std::fmt::Write; write!(value, "{byte:02x}").unwrap(); }
    value
}

fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().prefix("inspection public sentinel ").tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn arguments(scope: &InspectionScope, deployment: &tempfile::NamedTempFile) -> Vec<String> {
    vec!["inspect-authority".into(), "--deployment".into(), deployment.path().to_str().unwrap().into(),
        "--token".into(), hex(&scope.token), "--token-code".into(), hex(&scope.token_code),
        "--block-hash".into(), hex(&scope.block_hash), "--policy-id".into(), hex(&scope.policy_id),
        "--endpoint-env".into(), ENVIRONMENT.into(), "--allow-loopback-http".into()]
}

fn spawn(arguments: &[String], endpoint: Option<&str>) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ziquid"));
    command.arg("samechain").args(arguments).env_remove(ENVIRONMENT)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(endpoint) = endpoint { command.env(ENVIRONMENT, endpoint); }
    command.spawn().unwrap()
}

fn finish_with_open_stdin(mut child: Child) -> Output {
    let mut held_stdin = child.stdin.take().unwrap();
    if let Err(error) = held_stdin.write_all(STDIN_SECRET) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("public inspection waited for private stdin or exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(held_stdin);
    let output = child.wait_with_output().unwrap();
    for stream in [&output.stdout, &output.stderr] {
        for secret in [SECRET.as_bytes(), STDIN_SECRET] {
            assert!(!stream.windows(secret.len()).any(|window| window == secret), "secret disclosed");
        }
    }
    output
}

fn invoke(arguments: &[String], endpoint: Option<&str>) -> Output {
    let output = finish_with_open_stdin(spawn(arguments, endpoint));
    if let Some(endpoint) = endpoint.filter(|value| !value.is_empty()) {
        for stream in [&output.stdout, &output.stderr] {
            assert!(!stream.windows(endpoint.len()).any(|window| window == endpoint.as_bytes()),
                "endpoint disclosed");
        }
    }
    for argument in arguments {
        if argument.starts_with('/') || argument.contains("sentinel") {
            assert!(!output.stderr.windows(argument.len()).any(|window| window == argument.as_bytes()),
                "argument diagnostic disclosed");
        }
    }
    output
}

fn rejected(output: Output, code: i32) {
    assert_eq!(output.status.code(), Some(code));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

fn exported(output: Output, fixture: &Fixture) -> Value {
    assert!(output.status.success(), "inspection failed");
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "samechain_authority_observation");
    assert_eq!(value["source_scope"], "TRUSTED_NODE_AT_SELECTED_BLOCK");
    assert_eq!(value["block_number"], "42");
    let scope = fixture.scope();
    assert_eq!(value["block_hash"], hex(&scope.block_hash));
    assert_eq!(value["parent_hash"], hex(&[0x65; 32]));
    assert_eq!(value["policy_id"], hex(&scope.policy_id));
    assert_eq!(value["token"], hex(&scope.token));
    assert_eq!(value["token_code"], hex(&scope.token_code));
    assert_eq!(value["expected_deployment"], json!({
        "chain_id": scope.expected.chain_id.to_string(),
        "authority": hex(&scope.expected.authority), "authority_code": hex(&scope.expected.authority_code),
        "verifier": hex(&scope.expected.verifier), "verifier_code": hex(&scope.expected.verifier_code),
        "owner_program": hex(&scope.expected.owner_program), "schema": scope.expected.schema,
    }));
    assert_eq!(value["tree"], json!({"tree_id": 7, "count": 9, "root": hex(&[0xa5; 32])}));
    assert_eq!(value["appended_notes"], json!([{
        "transaction_hash": hex(&[0x22; 32]), "transaction_index": 0, "log_index": 0,
        "packet_digest": hex(&[0x11;32]), "manifest_index": 2, "role": 0,
        "tree_id": 7, "index": 8, "count": 9, "root": hex(&[0xa5;32]),
        "commitment": hex(&[0xb6;32]), "recovery_key_commitment": hex(&[0xc7;32]),
        "ciphertext_version": 1, "ciphertext": hex(&[0xd8,0xe9,0xfa]),
    }]));
    assert_eq!(value["consumed_nullifiers"], json!([{
        "transaction_hash": hex(&[0x22; 32]), "transaction_index": 0, "log_index": 1,
        "packet_digest": hex(&[0x33; 32]), "nullifier": hex(&[0x55; 32]),
    }]));
    for field in ["finality", "proof_validity", "deployment_profile_qualification", "asset_backing",
        "root_eligibility", "global_unspentness"] { assert_eq!(value[field], "UNVERIFIED"); }
    for field in ["signing", "submission", "financial_execution"] { assert_eq!(value[field], false); }
    for field in ["endpoint", "endpoint_url", "witness", "owner_seed", "payout", "payout_fact", "proof"] {
        assert!(value.get(field).is_none());
    }
    let digests: Vec<String> = fixture.responses().iter().map(|body| hex(&Sha256::digest(body))).collect();
    assert_eq!(value["response_sha256"], json!(digests));
    assert_eq!(value["request_count"], fixture.requests().len());
    value
}

#[test]
fn identity_inspection_is_pinned_honest_about_trust_and_never_reads_stdin() {
    let fixture = Fixture::start();
    let deployment = file(&fixture.scope().expected.encode().unwrap());
    let endpoint = format!("{}?api_key={SECRET}", fixture.endpoint());
    let value = exported(invoke(&arguments(&fixture.scope(), &deployment), Some(&endpoint)), &fixture);
    assert_eq!(value["inputs"], json!([]));
    assert_eq!(value["outputs"], json!([]));
    assert!(value.get("creation").is_none());
    assert!(value.get("packet_digest").is_none());
}

#[test]
fn creation_inspection_reports_nonce_optional_order_and_existing_packet_digest() {
    for initial in [false, true] {
        let fixture = Fixture::start();
        let packet = fixture.creation_packet(initial);
        let packet_file = file(&packet.encode().unwrap());
        let deployment = file(&fixture.scope().expected.encode().unwrap());
        let mut args = arguments(&fixture.scope(), &deployment);
        args.extend(["--packet".into(), packet_file.path().to_str().unwrap().into(),
            "--packet-kind".into(), "creation".into()]);
        let value = exported(invoke(&args, Some(fixture.endpoint())), &fixture);
        assert_eq!(value["packet_digest"], hex(&packet.digest().unwrap()));
        assert_eq!(value["inputs"], json!([]));
        assert_eq!(value["creation"]["nonce_used"], false);
        assert_eq!(value["creation"]["initial_order_used"], if initial { json!(false) } else { Value::Null });
        assert_eq!(value["outputs"].as_array().unwrap().len(), 1);
        assert_eq!(value["outputs"][0]["reported_seen"], false);
    }
}

#[test]
fn fill_inspection_exports_only_public_node_reported_input_and_note_output_state() {
    let fixture = Fixture::start();
    let packet = fixture.fill_packet();
    let packet_file = file(&packet.encode().unwrap());
    let deployment = file(&fixture.scope().expected.encode().unwrap());
    let mut args = arguments(&fixture.scope(), &deployment);
    args.extend(["--packet".into(), packet_file.path().to_str().unwrap().into(),
        "--packet-kind".into(), "fill".into()]);
    let value = exported(invoke(&args, Some(fixture.endpoint())), &fixture);
    assert_eq!(value["packet_digest"], hex(&packet.digest().unwrap()));
    let inputs = value["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 2);
    for (reported, expected) in inputs.iter().zip(&packet.inputs) {
        assert_eq!(reported["tree_id"], expected.tree_id);
        assert_eq!(reported["index"], expected.index);
        assert_eq!(reported["root"], hex(&expected.root));
        assert_eq!(reported["nullifier"], hex(&expected.nullifier));
        assert_eq!(reported["reported_root_count"], 5);
        assert_eq!(reported["reported_spent"], false);
    }
    let outputs = value["outputs"].as_array().unwrap();
    let notes: Vec<_> = packet.outputs.iter().enumerate().filter_map(|(index, output)| {
        match output {
            ziquid_protocol::samechain::OutputDescriptor::Note { commitment, .. } => Some((index, commitment)),
            _ => None,
        }
    }).collect();
    assert_eq!(outputs.len(), notes.len());
    for (reported, (index, commitment)) in outputs.iter().zip(notes) {
        assert_eq!(reported["manifest_index"], index);
        assert_eq!(reported["commitment"], hex(commitment));
        assert_eq!(reported["reported_seen"], false);
    }
    assert!(value.get("creation").is_none());
}

#[test]
fn single_and_withdrawal_inspection_require_no_owner_role_or_private_witness() {
    for kind in ["single", "withdrawal"] {
        let fixture = Fixture::start();
        let (bytes, digest, nullifier) = if kind == "single" {
            let packet = fixture.single_packet();
            (packet.encode().unwrap(), packet.digest().unwrap(), packet.input.nullifier)
        } else {
            let packet = fixture.withdrawal_packet();
            (packet.encode().unwrap(), packet.digest().unwrap(), packet.input.nullifier)
        };
        let packet_file = file(&bytes);
        let deployment = file(&fixture.scope().expected.encode().unwrap());
        let mut args = arguments(&fixture.scope(), &deployment);
        args.extend(["--packet".into(), packet_file.path().to_str().unwrap().into(),
            "--packet-kind".into(), kind.into()]);
        let value = exported(invoke(&args, Some(fixture.endpoint())), &fixture);
        assert_eq!(value["packet_digest"], hex(&digest));
        assert_eq!(value["inputs"].as_array().unwrap().len(), 1);
        assert_eq!(value["inputs"][0]["nullifier"], hex(&nullifier));
        assert_eq!(value["inputs"][0]["reported_root_count"], 5);
        assert_eq!(value["inputs"][0]["reported_spent"], false);
        assert!(value.get("creation").is_none());
    }
}

#[test]
fn a_malformed_public_packet_is_rejected_without_rpc_or_private_stdin() {
    let fixture = Fixture::start();
    let deployment = file(&fixture.scope().expected.encode().unwrap());
    let packet = file(STDIN_SECRET);
    for kind in ["creation", "fill", "single", "withdrawal"] {
        let mut args = arguments(&fixture.scope(), &deployment);
        args.extend(["--packet".into(), packet.path().to_str().unwrap().into(),
            "--packet-kind".into(), kind.into()]);
        rejected(invoke(&args, Some(fixture.endpoint())), 1);
    }
    assert!(fixture.requests().is_empty());
}

#[test]
fn packet_kind_is_required_exactly_when_a_public_packet_is_selected() {
    let fixture = Fixture::start();
    let deployment = file(&fixture.scope().expected.encode().unwrap());
    let packet = file(&fixture.creation_packet(false).encode().unwrap());
    let base = arguments(&fixture.scope(), &deployment);
    for extra in [vec!["--packet", packet.path().to_str().unwrap()],
        vec!["--packet-kind", "creation"], vec!["--packet-kind", SECRET],
        vec!["--witness-stdin"], vec!["--endpoint", SECRET]] {
        let mut args = base.clone();
        args.extend(extra.into_iter().map(String::from));
        rejected(invoke(&args, Some(fixture.endpoint())), 2);
    }
    for flag in ["--deployment", "--token", "--token-code", "--block-hash", "--policy-id", "--endpoint-env"] {
        let mut args = base.clone();
        let index = args.iter().position(|arg| arg == flag).unwrap();
        args.drain(index..index + 2);
        rejected(invoke(&args, Some(fixture.endpoint())), 2);
    }
    assert!(fixture.requests().is_empty());
}

#[test]
fn zero_malformed_and_mismatched_public_scope_fail_before_rpc() {
    let fixture = Fixture::start();
    let deployment = file(&fixture.scope().expected.encode().unwrap());
    let base = arguments(&fixture.scope(), &deployment);
    for flag in ["--token", "--token-code", "--block-hash", "--policy-id"] {
        for value in [SECRET.to_owned(), hex(&vec![0; if flag == "--token" { 20 } else { 32 }])] {
            let mut args = base.clone();
            let index = args.iter().position(|arg| arg == flag).unwrap();
            args[index + 1] = value;
            rejected(invoke(&args, Some(fixture.endpoint())), 1);
        }
    }
    let mut packet = fixture.fill_packet();
    packet.deployment.authority[0] ^= 1;
    let packet_file = file(&packet.encode().unwrap());
    let mut args = base;
    args.extend(["--packet".into(), packet_file.path().to_str().unwrap().into(),
        "--packet-kind".into(), "fill".into()]);
    rejected(invoke(&args, Some(fixture.endpoint())), 1);
    assert!(fixture.requests().is_empty());
}

#[test]
fn missing_invalid_secret_endpoint_and_http_without_opt_in_are_redacted() {
    let fixture = Fixture::start();
    let deployment = file(&fixture.scope().expected.encode().unwrap());
    let mut args = arguments(&fixture.scope(), &deployment);
    for endpoint in [None, Some(SECRET), Some("http://user:inspection-private-query-sentinel@127.0.0.1:1/")] {
        rejected(invoke(&args, endpoint), 1);
    }
    args.pop(); // Explicit HTTP permission is not a default.
    rejected(invoke(&args, Some(fixture.endpoint())), 1);
    let index = args.iter().position(|arg| arg == "--endpoint-env").unwrap();
    args[index + 1] = "invalid=inspection-private-query-sentinel".into();
    rejected(invoke(&args, None), 1);
    assert!(fixture.requests().is_empty());
}

#[test]
fn wrong_chain_block_runtime_code_and_provider_error_never_export_partial_observations() {
    for fault in [Fault::WrongChain, Fault::WrongBlock, Fault::WrongCode, Fault::RpcRejected] {
        let fixture = Fixture::with_fault(fault);
        let deployment = file(&fixture.scope().expected.encode().unwrap());
        let endpoint = format!("{}?api_key={SECRET}", fixture.endpoint());
        let output = invoke(&arguments(&fixture.scope(), &deployment), Some(&endpoint));
        rejected(output, 1);
        assert!(!fixture.requests().is_empty());
    }
}

#[test]
fn unsigned_and_private_commands_keep_their_stdin_boundaries() {
    for command in ["build-note-creation-call", "build-fill-call", "build-cancel-exit-call",
        "build-note-withdrawal-call"] {
        // Parser failure must not fall through to private stdin, even with held-open input.
        rejected(invoke(&[command.into()], None), 2);
    }
    for command in ["check-fill", "check-cancel-exit", "check-note-withdrawal", "review-note-withdrawal",
        "check-note-creation", "review-note-creation", "review-fill", "review-cancel-exit"] {
        rejected(invoke(&[command.into()], None), 2);
    }
    for command in ["check-fill", "check-cancel-exit", "check-note-withdrawal", "check-note-creation"] {
        let mut child = spawn(&[command.into(), "--witness-stdin".into()], None);
        drop(child.stdin.take());
        rejected(child.wait_with_output().unwrap(), 1);
    }
}
