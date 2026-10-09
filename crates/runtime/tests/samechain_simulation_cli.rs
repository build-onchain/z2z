//! Actual native subprocesses over public synthetic HTTP answers only.
//! The zero-pairing proof frames and one-byte runtimes prove NO financial success.
use primitive_types::U256;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
use ziquid_protocol::samechain::{Asset, OutputDescriptor, Role};

#[path = "../../chains/tests/support/samechain_inspection.rs"]
mod support;
use support::{Fault, Fixture, PROVIDER_SENTINEL, hex, unverified_frame};

const ENDPOINT_ENV: &str = "ZIQUID_SIMULATION_TEST_ENDPOINT";
const QUERY_SECRET: &str = "simulation-query-private-sentinel";
const STDIN_SECRET: &[u8] = b"simulation-held-open-private-stdin-sentinel";
const SENDER: &str = "0x0909090909090909090909090909090909090909";
const PAYER: &str = "0x0808080808080808080808080808080808080808";
const GAS: u64 = 1_000_000;

fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().prefix("simulation public sentinel ").tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

struct PublicFiles {
    packet: tempfile::NamedTempFile,
    deployment: tempfile::NamedTempFile,
    proof: tempfile::NamedTempFile,
    proof_b: tempfile::NamedTempFile,
}

impl PublicFiles {
    fn new(fixture: &Fixture, packet: &[u8]) -> Self {
        let mut proof_b = unverified_frame();
        proof_b[99] = 1; // Public framing nonce, not an authenticated proof.
        Self {
            packet: file(packet),
            deployment: file(&fixture.scope().expected.encode().unwrap()),
            proof: file(&unverified_frame()),
            proof_b: file(&proof_b),
        }
    }

    fn arguments(&self, fixture: &Fixture, operation: &str) -> Vec<String> {
        let scope = fixture.scope();
        let mut args = vec![
            "simulate-call".into(), "--operation".into(), operation.into(),
            "--packet".into(), self.packet.path().to_str().unwrap().into(),
            "--deployment".into(), self.deployment.path().to_str().unwrap().into(),
            "--proof".into(), self.proof.path().to_str().unwrap().into(),
            "--token".into(), hex(&scope.token),
            "--token-code".into(), hex(&scope.token_code),
            "--block-hash".into(), hex(&scope.block_hash),
            "--policy-id".into(), hex(&scope.policy_id),
            "--endpoint-env".into(), ENDPOINT_ENV.into(),
            "--allow-loopback-http".into(), "--gas-limit".into(), GAS.to_string(),
        ];
        if operation != "creation" { args.extend(["--sender".into(), SENDER.into()]); }
        if operation == "fill" {
            args.extend(["--proof-b".into(), self.proof_b.path().to_str().unwrap().into()]);
        }
        if matches!(operation, "cancel" | "exit") { args.extend(["--role".into(), "a".into()]); }
        args
    }
}

fn replace(args: &mut [String], flag: &str, value: impl Into<String>) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}

fn remove(args: &mut Vec<String>, flag: &str) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args.drain(index..index + 2);
}

fn not_disclosed(stream: &[u8], secret: &[u8]) {
    if secret.is_empty() { return; }
    assert!(!stream.windows(secret.len()).any(|window| window == secret), "private input disclosed");
    let serialized = serde_json::to_vec(secret).unwrap();
    assert!(!stream.windows(serialized.len()).any(|window| window == serialized), "private JSON disclosed");
}

fn invoke(args: &[String], endpoint: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ziquid"));
    command.arg("samechain").args(args).env_remove(ENDPOINT_ENV)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(endpoint) = endpoint { command.env(ENDPOINT_ENV, endpoint); }
    let mut child = command.spawn().unwrap();
    let mut held_stdin = child.stdin.take().unwrap();
    if let Err(error) = held_stdin.write_all(STDIN_SECRET) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("public simulation waited for private stdin or exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(held_stdin);
    let output = child.wait_with_output().unwrap();
    for stream in [&output.stdout, &output.stderr] {
        for secret in [STDIN_SECRET, QUERY_SECRET.as_bytes(), PROVIDER_SENTINEL.as_bytes()] {
            not_disclosed(stream, secret);
        }
        if let Some(endpoint) = endpoint { not_disclosed(stream, endpoint.as_bytes()); }
        for argument in args {
            if argument.starts_with('/') || argument.contains("sentinel") {
                not_disclosed(stream, argument.as_bytes());
            }
        }
    }
    output
}

fn rejected(output: &Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

fn unhex(text: &str) -> Vec<u8> {
    let text = text.strip_prefix("0x").unwrap();
    assert_eq!(text.len() % 2, 0);
    text.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

fn word(bytes: &[u8]) -> usize {
    assert_eq!(bytes.len(), 32);
    assert!(bytes[..24].iter().all(|byte| *byte == 0));
    usize::try_from(u64::from_be_bytes(bytes[24..].try_into().unwrap())).unwrap()
}

// Independent ABI decoding with actual solc selector literals, not Rust call builders.
fn assert_calldata(data: &[u8], operation: &str, packet: &[u8], role: usize) {
    let (selector, head_words, action) = match operation {
        "creation" => ([0x94, 0x18, 0x4b, 0xa9], 2, None),
        "fill" => ([0xd3, 0x16, 0xbd, 0x1a], 3, None),
        "cancel" => ([0xf6, 0x14, 0x6f, 0x41], 4, Some(1)),
        "exit" => ([0xf6, 0x14, 0x6f, 0x41], 4, Some(2)),
        "withdrawal" => ([0x50, 0xfb, 0xe2, 0xd9], 2, None),
        _ => panic!("unknown operation"),
    };
    assert_eq!(&data[..4], &selector);
    if let Some(action) = action {
        assert_eq!(word(&data[36..68]), role);
        assert_eq!(word(&data[68..100]), action);
    }
    let proof = unverified_frame();
    let mut proof_b = proof.clone();
    proof_b[99] = 1;
    let mut dynamic = vec![(0, packet), (if action.is_some() { 3 } else { 1 }, proof.as_slice())];
    if operation == "fill" { dynamic.push((2, proof_b.as_slice())); }
    let mut end = 4 + head_words * 32;
    for (head, expected) in dynamic {
        assert_eq!(word(&data[4 + head * 32..36 + head * 32]) + 4, end);
        let length = word(&data[end..end + 32]);
        assert_eq!(length, expected.len());
        assert_eq!(&data[end + 32..end + 32 + length], expected);
        let padded = length.div_ceil(32) * 32;
        assert!(data[end + 32 + length..end + 32 + padded].iter().all(|byte| *byte == 0));
        end += 32 + padded;
    }
    assert_eq!(data.len(), end);
}

fn execution(fixture: &Fixture) -> Value {
    let requests = fixture.requests();
    assert_eq!(requests.iter().map(|request| request["method"].as_str().unwrap()).collect::<Vec<_>>(),
        ["eth_chainId", "eth_getBlockByHash", "eth_call", "eth_call", "eth_call", "eth_call",
         "eth_getCode", "eth_getCode", "eth_getCode", "eth_call", "eth_getLogs", "eth_getLogs", "eth_call"]);
    let pinned = json!({"blockHash": hex(&fixture.scope().block_hash), "requireCanonical": true});
    for request in requests[2..].iter().filter(|request| request["method"] != "eth_getLogs") {
        assert_eq!(request["params"].as_array().unwrap().len(), 2);
        assert_eq!(request["params"][1], pinned);
    }
    for request in requests[..10].iter().filter(|request| request["method"] == "eth_call") {
        let call = request["params"][0].as_object().unwrap();
        assert_eq!(call.len(), 2);
        assert!(call.contains_key("to") && call.contains_key("data"));
    }
    let executions: Vec<_> = requests.iter().filter(|request|
        request["method"] == "eth_call" && request["params"][0].get("from").is_some()).collect();
    assert_eq!(executions.len(), 1, "exactly one execution follows fresh inspection");
    assert_eq!(executions[0]["params"][0].as_object().unwrap().len(), 5);
    executions[0]["params"][0].clone()
}

fn exported(output: &Output, fixture: &Fixture, packet_digest: [u8; 32],
    from: &str, value_atoms: &str, value_quantity: &str, gas: u64) -> Value
{
    assert!(output.status.success(), "public simulation rejected");
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "samechain_simulation_observation");
    assert_eq!(value["source_scope"], "TRUSTED_NODE_AT_SELECTED_BLOCK");
    assert_eq!(value["outcome"], "NODE_REPORTED_VOID_EXECUTION");
    assert_eq!(value["block_hash"], hex(&fixture.scope().block_hash));
    assert_eq!(value["block_number"], "42");
    assert_eq!(value["parent_hash"], hex(&[0x65; 32]));
    assert_eq!(value["appended_notes"], json!([{
        "transaction_hash":hex(&[0x22; 32]), "transaction_index":0, "log_index":0,
        "packet_digest":hex(&[0x11; 32]), "manifest_index":2, "role":0,
        "tree_id":7, "index":8, "count":9, "root":hex(&[0xa5; 32]),
        "commitment":hex(&[0xb6; 32]), "recovery_key_commitment":hex(&[0xc7; 32]),
        "ciphertext_version":1, "ciphertext":hex(&[0xd8, 0xe9, 0xfa]),
    }]));
    assert_eq!(value["consumed_nullifiers"], json!([{
        "transaction_hash":hex(&[0x22; 32]), "transaction_index":0, "log_index":1,
        "packet_digest":hex(&[0x33; 32]), "nullifier":hex(&[0x55; 32]),
    }]));
    assert_eq!(value["policy_id"], hex(&fixture.scope().policy_id));
    assert_eq!(value["from"], from);
    assert_eq!(value["to"], "0x0101010101010101010101010101010101010101");
    assert_eq!(value["value_atoms"], value_atoms);
    assert_eq!(value["gas_limit"], gas);
    assert_eq!(value["packet_digest"], hex(&packet_digest));
    for field in ["finality", "proof_validity", "deployment_profile_qualification", "asset_backing"] {
        assert_eq!(value[field], "UNVERIFIED");
    }
    for field in ["signing", "submission", "financial_execution"] { assert_eq!(value[field], false); }
    for forbidden in ["data", "endpoint", "endpoint_url", "witness", "owner_seed", "signature",
        "tx_hash", "proof", "proof_certificate", "payout_fact", "expected_journals"] {
        assert!(value.get(forbidden).is_none());
    }
    let call = execution(fixture);
    assert_eq!(call["from"], from);
    assert_eq!(call["to"], value["to"]);
    assert_eq!(call["value"], value_quantity);
    assert_eq!(call["gas"], format!("0x{gas:x}"));
    let data = unhex(call["data"].as_str().unwrap());
    assert_eq!(value["calldata_sha256"], hex(&Sha256::digest(&data)));
    let responses = fixture.responses();
    let (execution_response, inspection_responses) = responses.split_last().unwrap();
    assert_eq!(value["response_sha256"], hex(&Sha256::digest(execution_response)));
    assert_eq!(value["inspection_response_sha256"], json!(inspection_responses.iter()
        .map(|response| hex(&Sha256::digest(response))).collect::<Vec<_>>()));
    value
}

#[test]
fn actual_public_creation_calls_preserve_native_token_initial_and_u256_value_without_reading_stdin() {
    const MAX: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    for mode in ["native", "token", "initial", "max"] {
        let fixture = Fixture::start();
        let mut packet = fixture.creation_packet(mode == "initial");
        if mode == "token" { packet.asset = Asset::Token(fixture.scope().token); }
        if mode == "max" { packet.amount = U256::MAX; }
        let bytes = packet.encode().unwrap();
        let files = PublicFiles::new(&fixture, &bytes);
        let endpoint = format!("{}?api_key={QUERY_SECRET}", fixture.endpoint());
        let (atoms, quantity) = match mode {
            "native" => ("100", "0x64"), "token" => ("0", "0x0"),
            "initial" => ("105", "0x69"), "max" => (MAX, "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            _ => unreachable!(),
        };
        exported(&invoke(&files.arguments(&fixture, "creation"), Some(&endpoint)), &fixture,
            packet.digest().unwrap(), PAYER, atoms, quantity, GAS);
        let call = execution(&fixture);
        assert_calldata(&unhex(call["data"].as_str().unwrap()), "creation", &bytes, 0);
    }
}

#[test]
fn actual_fill_cancel_exit_and_withdrawal_calls_preserve_exact_public_frames_roles_and_sender() {
    for (operation, role) in [("fill", 0), ("cancel", 0), ("exit", 0), ("cancel", 1),
        ("exit", 1), ("withdrawal", 0)] {
        let fixture = Fixture::start();
        let (bytes, digest) = match operation {
            "fill" => { let packet = fixture.fill_packet(); (packet.encode().unwrap(), packet.digest().unwrap()) },
            "withdrawal" => { let packet = fixture.withdrawal_packet(); (packet.encode().unwrap(), packet.digest().unwrap()) },
            _ => {
                let mut packet = fixture.single_packet();
                if role == 1 {
                    for output in &mut packet.outputs {
                        match output {
                            OutputDescriptor::Note { role, .. } | OutputDescriptor::Exit { role, .. } => *role = Role::B,
                            OutputDescriptor::Fee { payer, .. } => *payer = Role::B,
                        }
                    }
                }
                (packet.encode().unwrap(), packet.digest().unwrap())
            }
        };
        let files = PublicFiles::new(&fixture, &bytes);
        let mut args = files.arguments(&fixture, operation);
        if role == 1 { replace(&mut args, "--role", "b"); }
        exported(&invoke(&args, Some(fixture.endpoint())), &fixture, digest, SENDER, "0", "0x0", GAS);
        let call = execution(&fixture);
        assert_calldata(&unhex(call["data"].as_str().unwrap()), operation, &bytes, role);
    }
}

#[test]
fn every_public_pin_file_operation_and_gas_is_mandatory_without_any_rpc_or_stdin_read() {
    let fixture = Fixture::start();
    let files = PublicFiles::new(&fixture, &fixture.creation_packet(false).encode().unwrap());
    let base = files.arguments(&fixture, "creation");
    for flag in ["--operation", "--packet", "--deployment", "--proof", "--token", "--token-code",
        "--block-hash", "--policy-id", "--endpoint-env", "--gas-limit"] {
        let mut args = base.clone();
        remove(&mut args, flag);
        let output = invoke(&args, Some(fixture.endpoint()));
        rejected(&output);
        assert_eq!(output.status.code(), Some(2));
    }
    for operation in ["single", "fill ", "Creation", "simulation-private-operation-sentinel"] {
        let mut args = base.clone();
        replace(&mut args, "--operation", operation);
        let output = invoke(&args, Some(fixture.endpoint()));
        rejected(&output);
        assert_eq!(output.status.code(), Some(2));
    }
    assert!(fixture.requests().is_empty());
}

#[test]
fn operation_specific_sender_role_and_second_proof_are_required_and_forbidden_elsewhere() {
    let fixture = Fixture::start();
    for operation in ["creation", "fill", "cancel", "exit", "withdrawal"] {
        let bytes = match operation {
            "creation" => fixture.creation_packet(false).encode().unwrap(),
            "fill" => fixture.fill_packet().encode().unwrap(),
            "withdrawal" => fixture.withdrawal_packet().encode().unwrap(),
            _ => fixture.single_packet().encode().unwrap(),
        };
        let files = PublicFiles::new(&fixture, &bytes);
        let base = files.arguments(&fixture, operation);
        let required: &[&str] = match operation {
            "creation" => &[], "fill" => &["--sender", "--proof-b"],
            "cancel" | "exit" => &["--sender", "--role"], "withdrawal" => &["--sender"],
            _ => unreachable!(),
        };
        for flag in required {
            let mut args = base.clone();
            remove(&mut args, flag);
            rejected(&invoke(&args, Some(fixture.endpoint())));
        }
        for (flag, value) in [("--sender", SENDER), ("--role", "a"),
            ("--proof-b", files.proof_b.path().to_str().unwrap())] {
            if base.iter().any(|arg| arg == flag) { continue; }
            let mut args = base.clone();
            args.extend([flag.into(), value.into()]);
            rejected(&invoke(&args, Some(fixture.endpoint())));
        }
    }
    assert!(fixture.requests().is_empty());
}

#[test]
fn malformed_zero_and_out_of_range_gas_never_reach_rpc() {
    let fixture = Fixture::start();
    let files = PublicFiles::new(&fixture, &fixture.creation_packet(false).encode().unwrap());
    let base = files.arguments(&fixture, "creation");
    for gas in ["0", "30000001", "18446744073709551615", "18446744073709551616", "-1", "1.5",
        "simulation-private-gas-sentinel"] {
        let mut args = base.clone();
        replace(&mut args, "--gas-limit", gas);
        rejected(&invoke(&args, Some(fixture.endpoint())));
    }
    assert!(fixture.requests().is_empty());
}

#[test]
fn explicit_smallest_and_operational_ceiling_gas_are_preserved_not_estimated() {
    for gas in [1, 30_000_000] {
        let fixture = Fixture::start();
        let packet = fixture.creation_packet(false);
        let files = PublicFiles::new(&fixture, &packet.encode().unwrap());
        let mut args = files.arguments(&fixture, "creation");
        replace(&mut args, "--gas-limit", gas.to_string());
        exported(&invoke(&args, Some(fixture.endpoint())), &fixture,
            packet.digest().unwrap(), PAYER, "100", "0x64", gas);
    }
}

#[test]
fn invalid_scope_sender_and_packet_deployment_or_creation_token_stop_before_http() {
    let fixture = Fixture::start();
    let files = PublicFiles::new(&fixture, &fixture.creation_packet(false).encode().unwrap());
    let base = files.arguments(&fixture, "creation");
    for flag in ["--token", "--token-code", "--block-hash", "--policy-id"] {
        for bad in ["simulation-private-pin-sentinel".to_owned(), hex(&vec![0; if flag == "--token" { 20 } else { 32 }])] {
            let mut args = base.clone();
            replace(&mut args, flag, bad);
            rejected(&invoke(&args, Some(fixture.endpoint())));
        }
    }
    let mut token = base.clone();
    replace(&mut token, "--token", hex(&[0x77; 20]));
    rejected(&invoke(&token, Some(fixture.endpoint())));
    let withdrawal = PublicFiles::new(&fixture, &fixture.withdrawal_packet().encode().unwrap());
    for sender in ["simulation-private-sender-sentinel".to_owned(), hex(&[0; 20])] {
        let mut args = withdrawal.arguments(&fixture, "withdrawal");
        replace(&mut args, "--sender", sender);
        rejected(&invoke(&args, Some(fixture.endpoint())));
    }
    let mut packet = fixture.creation_packet(false);
    packet.deployment.authority[0] ^= 1;
    let mismatched = PublicFiles::new(&fixture, &packet.encode().unwrap());
    rejected(&invoke(&mismatched.arguments(&fixture, "creation"), Some(fixture.endpoint())));
    assert!(fixture.requests().is_empty());
}

#[test]
fn private_flags_raw_endpoints_default_actions_and_invalid_roles_cannot_enter_public_simulation() {
    let fixture = Fixture::start();
    let files = PublicFiles::new(&fixture, &fixture.single_packet().encode().unwrap());
    let base = files.arguments(&fixture, "cancel");
    for extra in [vec!["--witness-stdin"], vec!["--endpoint", "simulation-private-endpoint-sentinel"],
        vec!["--owner-seed", "simulation-private-owner-sentinel"], vec!["--action", "exit"],
        vec!["--packet-kind", "single"]] {
        let mut args = base.clone();
        args.extend(extra.into_iter().map(String::from));
        let output = invoke(&args, Some(fixture.endpoint()));
        rejected(&output);
        assert_eq!(output.status.code(), Some(2));
    }
    for role in ["fill", "A", "simulation-private-role-sentinel", "b"] {
        let mut args = base.clone();
        replace(&mut args, "--role", role);
        rejected(&invoke(&args, Some(fixture.endpoint())));
    }
    assert!(fixture.requests().is_empty());
}

#[test]
fn malformed_public_packet_deployment_and_either_proof_are_redacted_before_http() {
    let fixture = Fixture::start();
    let files = PublicFiles::new(&fixture, &fixture.fill_packet().encode().unwrap());
    let base = files.arguments(&fixture, "fill");
    let private_file = file(STDIN_SECRET);
    for flag in ["--packet", "--deployment", "--proof", "--proof-b"] {
        let mut args = base.clone();
        replace(&mut args, flag, private_file.path().to_str().unwrap());
        rejected(&invoke(&args, Some(fixture.endpoint())));
    }
    let mut trailing_packet = fixture.fill_packet().encode().unwrap();
    trailing_packet.push(0);
    let trailing = file(&trailing_packet);
    let mut args = base.clone();
    replace(&mut args, "--packet", trailing.path().to_str().unwrap());
    rejected(&invoke(&args, Some(fixture.endpoint())));
    for frame in [vec![], unverified_frame()[..355].to_vec(), {
        let mut frame = unverified_frame(); frame[0] ^= 1; frame
    }, {
        let mut frame = unverified_frame(); frame.push(0); frame
    }] {
        let bad = file(&frame);
        for flag in ["--proof", "--proof-b"] {
            let mut args = base.clone();
            replace(&mut args, flag, bad.path().to_str().unwrap());
            rejected(&invoke(&args, Some(fixture.endpoint())));
        }
    }
    assert!(fixture.requests().is_empty());
}

#[test]
fn endpoint_environment_and_loopback_permission_are_explicit_and_redacted() {
    let fixture = Fixture::start();
    let files = PublicFiles::new(&fixture, &fixture.creation_packet(false).encode().unwrap());
    let base = files.arguments(&fixture, "creation");
    for endpoint in [None, Some("simulation-private-url-sentinel"),
        Some("http://user:simulation-query-private-sentinel@127.0.0.1:1/rpc")] {
        rejected(&invoke(&base, endpoint));
    }
    let mut args = base.clone();
    args.retain(|arg| arg != "--allow-loopback-http");
    rejected(&invoke(&args, Some(fixture.endpoint())));
    let mut args = base;
    replace(&mut args, "--endpoint-env", "invalid=simulation-private-env-sentinel");
    rejected(&invoke(&args, None));
    assert!(fixture.requests().is_empty());
}

#[test]
fn identity_failure_stops_before_execution_and_never_exports_partial_observations() {
    for fault in [Fault::WrongChain, Fault::WrongBlock, Fault::WrongCode, Fault::WrongVerifierCode,
        Fault::WrongTokenCode, Fault::WrongDeployment(5), Fault::WrongDigest, Fault::WrongToken,
        Fault::WrongTokenPin, Fault::RpcRejected] {
        let fixture = Fixture::with_fault(fault);
        let files = PublicFiles::new(&fixture, &fixture.creation_packet(false).encode().unwrap());
        let endpoint = format!("{}?api_key={QUERY_SECRET}", fixture.endpoint());
        rejected(&invoke(&files.arguments(&fixture, "creation"), Some(&endpoint)));
        let requests = fixture.requests();
        assert!(!requests.is_empty());
        assert!(requests.iter().all(|request| request["params"][0].get("gas").is_none()));
    }
}

#[test]
fn only_exact_empty_void_result_succeeds_and_numeric_rejection_is_redacted_and_distinct() {
    let fixture = Fixture::with_fault(Fault::SimulationRpcRejected);
    let files = PublicFiles::new(&fixture, &fixture.creation_packet(false).encode().unwrap());
    let endpoint = format!("{}?api_key={QUERY_SECRET}", fixture.endpoint());
    let rpc_error = invoke(&files.arguments(&fixture, "creation"), Some(&endpoint));
    rejected(&rpc_error);
    execution(&fixture);
    for result in ["0X", "0x00", "0x01", "0x0000000000000000000000000000000000000000000000000000000000000001",
        "simulation-query-private-sentinel"] {
        let fixture = Fixture::with_fault(Fault::SimulationResult(result));
        let files = PublicFiles::new(&fixture, &fixture.creation_packet(false).encode().unwrap());
        let output = invoke(&files.arguments(&fixture, "creation"), Some(fixture.endpoint()));
        rejected(&output);
        assert_ne!(output.stderr, rpc_error.stderr, "malformed output must not be mislabeled RPC rejection");
        execution(&fixture);
    }
    for fault in [Fault::SimulationHttpStatus(503), Fault::SimulationOversizeBody,
        Fault::SimulationChunkedOversize, Fault::SimulationTruncated, Fault::SimulationCompressed,
        Fault::SimulationRedirect] {
        let fixture = Fixture::with_fault(fault);
        let files = PublicFiles::new(&fixture, &fixture.creation_packet(false).encode().unwrap());
        let output = invoke(&files.arguments(&fixture, "creation"), Some(fixture.endpoint()));
        rejected(&output);
        assert_ne!(output.stderr, rpc_error.stderr, "unavailable response must not be mislabeled RPC rejection");
        execution(&fixture);
    }
}

#[test]
fn execution_envelope_malformed_types_ids_duplicate_fields_and_error_data_are_never_exported() {
    let bodies = [
        json!({"jsonrpc":"2.0", "id":13, "result":null}).to_string(),
        json!({"jsonrpc":"2.0", "id":13, "result":true}).to_string(),
        json!({"jsonrpc":"2.0", "id":13, "result":[]}).to_string(),
        json!({"jsonrpc":"2.0", "id":13}).to_string(),
        json!({"jsonrpc":"2.0", "id":14, "result":"0x"}).to_string(),
        json!({"jsonrpc":"1.0", "id":13, "result":"0x"}).to_string(),
        json!({"jsonrpc":"2.0", "id":13, "result":"0x", "error":{
            "code":-32000, "message":PROVIDER_SENTINEL, "data":QUERY_SECRET}}).to_string(),
        json!({"jsonrpc":"2.0", "id":13, "error":{
            "code":2147483648_u64, "message":PROVIDER_SENTINEL, "data":QUERY_SECRET}}).to_string(),
        "{\"jsonrpc\":\"2.0\",\"id\":13,\"result\":\"0x\",\"result\":\"0x\"}".into(),
        "{\"jsonrpc\":\"2.0\",\"id\":13,\"id\":13,\"result\":\"0x\"}".into(),
    ];
    for body in bodies {
        let fixture = Fixture::with_response(13, body.into_bytes());
        let files = PublicFiles::new(&fixture, &fixture.creation_packet(false).encode().unwrap());
        let endpoint = format!("{}?api_key={QUERY_SECRET}", fixture.endpoint());
        rejected(&invoke(&files.arguments(&fixture, "creation"), Some(&endpoint)));
        execution(&fixture);
    }
}
