//! Offline public call exports. Synthetic wrappers have invalid zero pairing
//! points and are NOT certificates, source evidence or executed transfers.
#![cfg(target_os = "linux")]
use std::{fs, path::{Path, PathBuf}, process::{Command, Output, Stdio}, time::{Duration, Instant}};
use serde_json::Value;
use ziquid_protocol::native::{DeploymentDescriptor, Statement};

const SENDER: &str = "0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
const MAX_WEI: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";

fn unhex(value: &str) -> Vec<u8> {
    value.strip_prefix("0x").unwrap_or(value).as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}
fn vector(name: &str) -> Vec<u8> {
    let json: Value = serde_json::from_str(include_str!(
        "../../../contracts/evm/test/fixtures/native-financial-vectors.json"
    )).unwrap();
    unhex(json[name].as_str().unwrap())
}
fn deployment() -> DeploymentDescriptor {
    DeploymentDescriptor {
        schema_version: 1, source_network: 1, source_pool: 3,
        transaction_version: 6, consensus_branch: 0x37a5165b,
        financial_program: [1; 32], origin_program: [20; 32],
        source_acceptance_program: [2; 32], source_policy_id: [3; 32],
        target_chain_id: 84532, obligation: [5; 20],
        obligation_runtime_code: [6; 32], verifier: [7; 20], verifier_runtime_code: [8; 32],
    }
}
fn frame(nonce: u8) -> Vec<u8> {
    let mut frame = vec![0; 356];
    frame[..4].copy_from_slice(&unhex("4388a21c"));
    frame[36..68].copy_from_slice(&unhex(
        "002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352"
    ));
    frame[99] = nonce;
    frame
}
struct Fixture { root: tempfile::TempDir }
impl Fixture {
    fn new() -> Self {
        let fixture = Self { root: tempfile::Builder::new().prefix("public native sentinel ").tempdir().unwrap() };
        for (name, bytes) in [
            ("statement", vector("statement")), ("boundary", vector("boundary")),
            ("deployment", deployment().encode().to_vec()),
            ("arm", frame(1)), ("origin", frame(2)), ("acceptance", frame(3)),
            ("financial", frame(4)),
        ] { fs::write(fixture.path(name), bytes).unwrap(); }
        fixture
    }
    fn path(&self, name: &str) -> PathBuf { self.root.path().join(name) }
    fn args(&self, resolve: bool) -> Vec<String> {
        let mut args = vec![if resolve { "build-resolve-call" } else { "build-arm-call" }.into()];
        for (flag, name) in [("--statement", "statement"), ("--boundary", "boundary"),
            ("--deployment", "deployment"), ("--acceptance-proof", "acceptance")] {
            args.extend([flag.into(), self.path(name).to_str().unwrap().into()]);
        }
        if resolve {
            args.extend(["--financial-proof".into(), self.path("financial").to_str().unwrap().into(),
                "--sender".into(), SENDER.into(), "--outcome".into(), "completion".into(),
                "--cnet".into(), "100000000".into()]);
        } else {
            for (flag, name) in [("--arm-proof", "arm"), ("--origin-proof", "origin")] {
                args.extend([flag.into(), self.path(name).to_str().unwrap().into()]);
            }
        }
        args
    }
}
fn set(args: &mut [String], flag: &str, value: &str) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}
fn invoke(args: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .arg("native").args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    // Leave stdin OPEN: successful completion proves this public CLI never waits
    // for stdin, and the deadline catches FIFO/device regressions without hangs.
    let stdin = child.stdin.take().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() { break; }
        if Instant::now() >= deadline {
            child.kill().unwrap(); child.wait().unwrap(); panic!("public native CLI blocked");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    for arg in args {
        if arg.contains("sentinel") {
            assert!(!output.stderr.windows(arg.len()).any(|bytes| bytes == arg.as_bytes()));
        }
    }
    output
}
fn exported(output: Output, operation: &str) -> Value {
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "unsigned_native_call");
    assert_eq!(value["operation"], operation);
    assert_eq!(value["source"], "caller_public_files");
    for flag in ["proof_validity", "deployment_validity", "source_acceptance", "source_finality", "asset_backing"] {
        assert_eq!(value[flag], "UNVERIFIED");
    }
    for flag in ["proof_certificate", "signing", "submission", "financial_execution"] { assert_eq!(value[flag], false); }
    for field in ["signature", "tx_hash", "private_key", "witness", "gas_price", "nonce"] { assert!(value.get(field).is_none()); }
    assert_eq!(value["to"], "0x0505050505050505050505050505050505050505");
    value
}
fn reject(output: Output) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert!(output.stderr.len() < 160);
}
fn word(data: &[u8], offset: usize) -> u64 {
    assert_eq!(&data[offset..offset + 24], &[0; 24]);
    u64::from_be_bytes(data[offset + 24..offset + 32].try_into().unwrap())
}
fn bytes_arg(data: &[u8], head: usize, offset: usize, bytes: &[u8]) {
    assert_eq!(word(data, 4 + 32 * head), offset as u64);
    assert_eq!(word(data, 4 + offset), bytes.len() as u64);
    let start = 36 + offset;
    assert_eq!(&data[start..start + bytes.len()], bytes);
    assert!(data[start + bytes.len()..start + bytes.len().div_ceil(32) * 32].iter().all(|b| *b == 0));
}
#[test]
fn native_arm_process_exports_independent_abi_and_journals_without_stdin() {
    let fixture = Fixture::new();
    let json = exported(invoke(&fixture.args(false)), "build_fund_and_arm_call");
    assert_eq!(json["from"], "0x0909090909090909090909090909090909090909");
    assert_eq!(json["value_wei"], MAX_WEI);
    assert_eq!(unhex(json["context_digest"].as_str().unwrap()), vector("contextHash"));
    let journals: Vec<Vec<u8>> = serde_json::from_value(json["expected_journals"].clone()).unwrap();
    assert_eq!(journals, [vector("armJournal"), vector("originJournal"), vector("acceptanceJournal")]);
    let data = unhex(json["data"].as_str().unwrap());
    assert_eq!(&data[..4], &unhex("0660a602")); assert_eq!(data.len(), 2244);
    bytes_arg(&data, 0, 160, &vector("statement"));
    bytes_arg(&data, 1, 832, &vector("boundary"));
    bytes_arg(&data, 2, 992, &frame(1)); bytes_arg(&data, 3, 1408, &frame(2));
    bytes_arg(&data, 4, 1824, &frame(3));
}
#[test]
fn native_resolve_process_exports_both_outcomes_and_zero_value() {
    let fixture = Fixture::new();
    for (outcome, cnet, journal, number) in [
        ("completion", "100000000", "resolveCJournal", 1), ("recovery", "0", "resolveRJournal", 2),
    ] {
        let mut args = fixture.args(true); set(&mut args, "--outcome", outcome); set(&mut args, "--cnet", cnet);
        let json = exported(invoke(&args), "build_resolve_call");
        assert_eq!(json["from"], SENDER); assert_eq!(json["value_wei"], "0");
        let journals: Vec<Vec<u8>> = serde_json::from_value(json["expected_journals"].clone()).unwrap();
        assert_eq!(journals, [vector(journal), vector("acceptanceJournal")]);
        let data = unhex(json["data"].as_str().unwrap());
        assert_eq!(&data[..4], &unhex("70c1e7b1")); assert_eq!(data.len(), 1860);
        bytes_arg(&data, 0, 192, &vector("statement")); bytes_arg(&data, 1, 864, &vector("boundary"));
        assert_eq!(word(&data, 68), number); assert_eq!(word(&data, 100), cnet.parse::<u64>().unwrap());
        bytes_arg(&data, 4, 1024, &frame(4)); bytes_arg(&data, 5, 1440, &frame(3));
    }
}
#[test]
fn native_cli_rejects_truncated_trailing_and_malformed_files_in_every_position() {
    let fixture = Fixture::new();
    for resolve in [false, true] {
        for name in if resolve { vec!["statement", "boundary", "deployment", "financial", "acceptance"] }
            else { vec!["statement", "boundary", "deployment", "arm", "origin", "acceptance"] } {
            let path = fixture.path(name); let original = fs::read(&path).unwrap();
            let mut trailing = original.clone(); trailing.push(0);
            let mut malformed = original.clone(); malformed[0] ^= 0xff;
            for bytes in [vec![], original[..original.len() - 1].to_vec(), trailing, malformed] {
                fs::write(&path, &bytes).unwrap(); reject(invoke(&fixture.args(resolve)));
            }
            fs::write(&path, original).unwrap();
        }
    }
}
#[test]
fn native_cli_rejects_nonregular_and_missing_paths_without_blocking_or_disclosing() {
    let fixture = Fixture::new();
    let link = fixture.path("sentinel-link"); std::os::unix::fs::symlink(fixture.path("statement"), &link).unwrap();
    let fifo = fixture.path("sentinel-fifo");
    rustix::fs::mknodat(rustix::fs::CWD, &fifo, rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR, 0).unwrap();
    let socket_path = fixture.path("sentinel-socket");
    let _socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    for path in [&link, &fifo, &socket_path, fixture.root.path(), Path::new("/dev/zero"), &fixture.path("sentinel-missing")] {
        for flag in ["--statement", "--boundary", "--deployment", "--arm-proof", "--origin-proof", "--acceptance-proof"] {
            let mut args = fixture.args(false); set(&mut args, flag, path.to_str().unwrap()); reject(invoke(&args));
        }
    }
}
#[test]
fn native_cli_rejects_independent_deployment_and_origin_substitution() {
    let fixture = Fixture::new();
    let mut changed = deployment(); changed.verifier_runtime_code[0] ^= 1;
    fs::write(fixture.path("deployment"), changed.encode()).unwrap();
    reject(invoke(&fixture.args(false))); reject(invoke(&fixture.args(true)));
    fs::write(fixture.path("deployment"), deployment().encode()).unwrap();
    let mut statement = Statement::decode(&vector("statement")).unwrap(); statement.origin_program[0] ^= 1;
    fs::write(fixture.path("statement"), statement.encode()).unwrap();
    reject(invoke(&fixture.args(false))); reject(invoke(&fixture.args(true)));
    changed = deployment(); changed.origin_program = statement.origin_program;
    fs::write(fixture.path("deployment"), changed.encode()).unwrap();
    reject(invoke(&fixture.args(false))); // Same changed program without new digest still fails.
    statement.deployment_descriptor = changed.digest();
    fs::write(fixture.path("statement"), statement.encode()).unwrap();
    exported(invoke(&fixture.args(false)), "build_fund_and_arm_call");
    exported(invoke(&fixture.args(true)), "build_resolve_call");
}
#[test]
fn native_cli_enforces_sender_outcome_scalar_and_u64_bounds_with_sanitized_errors() {
    let fixture = Fixture::new();
    for (flag, value) in [
        ("--sender", "0x0000000000000000000000000000000000000000"),
        ("--sender", "secret-sentinel-not-an-address"), ("--sender", "0x12"),
        ("--outcome", "other-sentinel"), ("--cnet", "0"), ("--cnet", "100000001"),
        ("--cnet", "18446744073709551615"), ("--cnet", "18446744073709551616"),
        ("--cnet", "-1"), ("--cnet", "secret-sentinel"),
    ] {
        let mut args = fixture.args(true); set(&mut args, flag, value);
        let output = invoke(&args);
        assert!(!output.stderr.windows(value.len()).any(|bytes| bytes == value.as_bytes())); reject(output);
    }
    let mut args = fixture.args(true); set(&mut args, "--outcome", "recovery"); set(&mut args, "--cnet", "1"); reject(invoke(&args));
    for name in ["arm", "origin", "acceptance", "financial"] {
        let mut bad = frame(0); bad[68..100].copy_from_slice(&unhex(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"));
        fs::write(fixture.path(name), bad).unwrap();
        reject(invoke(&fixture.args(name == "financial"))); fs::write(fixture.path(name), frame(0)).unwrap();
    }
}
#[test]
fn native_cli_preserves_wide_cnet_and_rejects_zero_funding() {
    let fixture = Fixture::new();
    let mut statement = Statement::decode(&vector("statement")).unwrap();
    statement.a = 0x010203040506; statement.joint_value = statement.a + statement.fees[1];
    statement.r_return = statement.joint_value - statement.fees[2];
    fs::write(fixture.path("statement"), statement.encode()).unwrap();
    let mut args = fixture.args(true); set(&mut args, "--cnet", &statement.a.to_string());
    let json = exported(invoke(&args), "build_resolve_call");
    assert_eq!(word(&unhex(json["data"].as_str().unwrap()), 100), 0x010203040506);
    statement.d.fill(0); fs::write(fixture.path("statement"), statement.encode()).unwrap();
    reject(invoke(&fixture.args(false))); reject(invoke(&args));
}
#[test]
fn native_cli_rejects_unknown_options_without_echoing_the_input() {
    let fixture = Fixture::new();
    for flag in ["--private-key", "--rpc", "--submit", "--database-config", "--witness-stdin"] {
        let mut args = fixture.args(false); args.extend([flag.into(), "private-sentinel".into()]);
        let output = invoke(&args);
        assert!(!output.stderr.windows(16).any(|bytes| bytes == b"private-sentinel")); reject(output);
    }
}
