//! Actual CLI processes against bounded local HTTP fixtures; no real proof or transfer.
#![cfg(target_os = "linux")]
use std::{io::Write, process::{Command, Output, Stdio}, time::{Duration, Instant}};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "../../chains/tests/support/native_inspection.rs"]
mod support;
use support::{Fixture, RowState, WireFault, PROVIDER_SENTINEL, hex, reply};

const ENVIRONMENT: &str = "ZIQUID_NATIVE_INSPECTION_TEST_ENDPOINT";
const STDIN_SECRET: &[u8] = b"native-private-stdin-sentinel";
const MAX_WEI: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";

fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().prefix("native inspection public sentinel ").tempfile().unwrap();
    file.write_all(bytes).unwrap(); file
}
fn arguments(deployment: &tempfile::NamedTempFile) -> Vec<String> {
    vec!["inspect-obligation".into(), "--deployment".into(), deployment.path().to_str().unwrap().into(),
        "--block-hash".into(), hex(&[0x66; 32]), "--endpoint-env".into(), ENVIRONMENT.into(),
        "--allow-loopback-http".into()]
}
fn set(args: &mut [String], flag: &str, value: &str) {
    let index = args.iter().position(|arg| arg == flag).unwrap(); args[index + 1] = value.into();
}
fn invoke(args: &[String], endpoint: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ziquid"));
    command.arg("native").args(args).env_remove(ENVIRONMENT)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(endpoint) = endpoint { command.env(ENVIRONMENT, endpoint); }
    let mut child = command.spawn().unwrap();
    // Deliberately keep stdin open and private content unread through completion.
    let mut stdin = child.stdin.take().unwrap();
    if let Err(error) = stdin.write_all(STDIN_SECRET) { assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe); }
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap(); child.wait().unwrap(); panic!("native inspection blocked on private stdin or transport");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    for stream in [&output.stdout, &output.stderr] {
        for secret in [PROVIDER_SENTINEL.as_bytes(), STDIN_SECRET] {
            assert!(!stream.windows(secret.len()).any(|bytes| bytes == secret));
        }
        if let Some(endpoint) = endpoint.filter(|text| !text.is_empty()) {
            assert!(!stream.windows(endpoint.len()).any(|bytes| bytes == endpoint.as_bytes()));
        }
    }
    for arg in args.iter().filter(|arg| arg.contains("sentinel") || arg.starts_with('/')) {
        assert!(!output.stderr.windows(arg.len()).any(|bytes| bytes == arg.as_bytes()));
    }
    output
}
fn rejected(output: Output) {
    assert_eq!(output.status.code(), Some(2)); assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty()); assert!(output.stderr.len() < 160);
}
fn exported(output: Output, fixture: &Fixture) -> Value {
    assert!(output.status.success()); assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "native_obligation_observation");
    assert_eq!(value["source_scope"], "TRUSTED_NODE_AT_SELECTED_BLOCK");
    assert_eq!(value["block_hash"], hex(&[0x66; 32])); assert_eq!(value["block_number"], "42");
    assert_eq!(value["parent_hash"], hex(&[0x65; 32])); assert_eq!(value["reported_total_liability_wei"], MAX_WEI);
    let deployment = fixture.scope().expected;
    assert_eq!(value["deployment_digest"], hex(&Sha256::digest(deployment.encode())));
    assert_eq!(value["expected_deployment"], json!({
        "schema_version":1, "source_network":1, "source_pool":3, "transaction_version":6,
        "consensus_branch":0x37a5165b, "financial_program":hex(&[1; 32]), "origin_program":hex(&[20; 32]),
        "source_acceptance_program":hex(&[2; 32]), "source_policy_id":hex(&[3; 32]),
        "target_chain_id":"84532", "obligation":hex(&[5; 20]), "obligation_runtime_code":hex(&support::CODE_HASH),
        "verifier":hex(&[7; 20]), "verifier_runtime_code":hex(&support::CODE_HASH),
    }));
    for field in ["finality", "program_qualification", "proof_validity", "source_acceptance",
        "source_finality", "asset_backing", "actual_transfer"] { assert_eq!(value[field], "UNVERIFIED"); }
    for field in ["proof_certificate", "signing", "submission", "financial_execution"] { assert_eq!(value[field], false); }
    for field in ["completed", "refund_eligible", "source_release", "endpoint", "endpoint_env", "witness", "proof", "certificate", "statement"] {
        assert!(value.get(field).is_none());
    }
    let digests: Vec<_> = fixture.responses().iter().map(|bytes| hex(&Sha256::digest(bytes))).collect();
    assert_eq!(value["response_sha256"], json!(digests));
    value
}

#[test]
fn native_inspection_process_reads_real_http_and_no_private_stdin_without_statement() {
    let fixture = Fixture::start(RowState::Absent);
    let deployment = file(&fixture.scope().expected.encode());
    let endpoint = format!("{}?api_key={PROVIDER_SENTINEL}", fixture.endpoint());
    let value = exported(invoke(&arguments(&deployment), Some(&endpoint)), &fixture);
    assert!(value.get("obligation").is_none()); assert_eq!(fixture.requests().len(), 7);
}

#[test]
fn native_inspection_process_reports_all_reachable_rows_without_creating_financial_state() {
    for state in [RowState::Absent, RowState::Armed, RowState::Consumed] {
        let fixture = Fixture::start(state);
        let deployment = file(&fixture.scope().expected.encode());
        let statement = file(&fixture.statement().encode());
        let mut args = arguments(&deployment); args.extend(["--statement".into(), statement.path().to_str().unwrap().into()]);
        let value = exported(invoke(&args, Some(fixture.endpoint())), &fixture);
        let row = &value["obligation"];
        let absent = matches!(state, RowState::Absent);
        assert_eq!(row["context_digest"], hex(&Sha256::digest(fixture.statement().encode())));
        assert_eq!(row["queried_stable_jtag"], hex(&fixture.statement().stable_jtag));
        assert_eq!(row["reported_d_wei"], if absent { "0" } else { MAX_WEI });
        assert_eq!(row["reported_a_zat"], if absent { "0" } else { "100000000" });
        assert_eq!(row["reported_payer"], hex(&if absent { [0; 20] } else { [9; 20] }));
        assert_eq!(row["reported_u_payee"], hex(&if absent { [0; 20] } else { [10; 20] }));
        assert_eq!(row["reported_s_refund"], hex(&if absent { [0; 20] } else { [11; 20] }));
        assert_eq!(row["reported_armed"], !absent);
        assert_eq!(row["reported_consumed"], matches!(state, RowState::Consumed));
        assert_eq!(row["reported_tag_context"], if absent { hex(&[0; 32]) } else { hex(&Sha256::digest(fixture.statement().encode())) });
        assert_eq!(fixture.requests().len(), 9);
    }
}

#[test]
fn native_inspection_process_rejects_endpoint_arguments_environment_and_local_frames_without_rpc() {
    let fixture = Fixture::start(RowState::Absent);
    let deployment = file(&fixture.scope().expected.encode());
    let base = arguments(&deployment);
    for endpoint in [None, Some(""), Some(PROVIDER_SENTINEL), Some("https://user:secret@node.invalid/rpc"), Some("http://localhost/rpc")] {
        rejected(invoke(&base, endpoint));
    }
    for (flag, input) in [("--endpoint-env", PROVIDER_SENTINEL), ("--endpoint-env", ""),
        ("--block-hash", "0x00"), ("--block-hash", "0X1234"), ("--block-hash", &hex(&[0; 32]))] {
        let mut args = base.clone(); set(&mut args, flag, input); rejected(invoke(&args, Some(fixture.endpoint())));
    }
    let mut args = base.clone(); args.retain(|arg| arg != "--allow-loopback-http");
    rejected(invoke(&args, Some(fixture.endpoint())));
    for flag in ["--endpoint", "--private-key", "--rpc", "--witness-stdin", "--submit"] {
        let mut args = base.clone(); args.extend([flag.into(), PROVIDER_SENTINEL.into()]);
        rejected(invoke(&args, Some(fixture.endpoint())));
    }
    for bytes in [vec![], fixture.scope().expected.encode()[..278].to_vec(), {
        let mut bytes = fixture.scope().expected.encode().to_vec(); bytes.push(0); bytes
    }] {
        let bad = file(&bytes); let args = arguments(&bad); rejected(invoke(&args, Some(fixture.endpoint())));
    }
    for bytes in [vec![], fixture.statement().encode()[..637].to_vec(), {
        let mut bytes = fixture.statement().encode().to_vec(); bytes.push(0); bytes
    }, {
        let mut statement = fixture.statement(); statement.origin_program[0] ^= 1; statement.encode().to_vec()
    }] {
        let bad = file(&bytes); let mut args = base.clone(); args.extend(["--statement".into(), bad.path().to_str().unwrap().into()]);
        rejected(invoke(&args, Some(fixture.endpoint())));
    }
    assert!(fixture.requests().is_empty());
}

#[test]
fn native_inspection_process_redacts_changed_chain_runtime_rpc_provider_and_wire_failures() {
    for (id, result) in [(1,json!("0x14a35")), (5,json!("0x01")), (3,json!("0x00"))] {
        let fixture = Fixture::with_response(RowState::Absent, id, reply(id, result));
        let deployment = file(&fixture.scope().expected.encode());
        let endpoint = format!("{}?api_key={PROVIDER_SENTINEL}", fixture.endpoint());
        rejected(invoke(&arguments(&deployment), Some(&endpoint)));
    }
    let body = json!({"jsonrpc":"2.0", "id":1, "error":{"code":-32001, "message":PROVIDER_SENTINEL, "data":PROVIDER_SENTINEL}}).to_string().into_bytes();
    let fixture = Fixture::with_response(RowState::Absent, 1, body);
    let deployment = file(&fixture.scope().expected.encode());
    rejected(invoke(&arguments(&deployment), Some(fixture.endpoint())));
    for wire in [WireFault::Redirect, WireFault::Oversize, WireFault::ChunkedOversize, WireFault::Compressed, WireFault::Truncated] {
        let fixture = Fixture::with_wire(wire);
        let deployment = file(&fixture.scope().expected.encode());
        let endpoint = format!("{}?api_key={PROVIDER_SENTINEL}", fixture.endpoint());
        rejected(invoke(&arguments(&deployment), Some(&endpoint)));
    }
}
