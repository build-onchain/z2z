//! Offline PUBLIC call construction only. The synthetic Groth16 frame below has
//! zero pairing points: it is NOT a valid certificate or financial evidence.
use primitive_types::U256;
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use ziquid_protocol::samechain::{Deployment, MAX_PACKET_BYTES, OutputDescriptor};
use ziquid_protocol::samechain::creation::NoteCreationPacket;
use ziquid_protocol::samechain::withdrawal::NoteWithdrawalPacket;

const SENDER: &str = "0x0909090909090909090909090909090909090909";
const TOKEN: &str = "0x0707070707070707070707070707070707070707";
const AUTHORITY: &str = "0x0101010101010101010101010101010101010101";

fn unhex(value: &str) -> Vec<u8> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    assert_eq!(value.len() % 2, 0);
    value.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

fn fixture(name: &str) -> Value {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../contracts/evm/test/fixtures/samechain-native-vectors.json")).unwrap();
    let fill2: Value = serde_json::from_str(include_str!(
        "../../../contracts/evm/test/fixtures/samechain-fill2-vectors.json")).unwrap();
    fill2["packets"].as_array().unwrap().iter()
        .chain(vectors["packets"].as_array().unwrap())
        .find(|packet| packet["name"] == name).unwrap().clone()
}

fn field(fixture: &Value, name: &str) -> Vec<u8> {
    unhex(fixture[name].as_str().unwrap())
}

fn proof() -> Vec<u8> {
    let mut frame = vec![0; 356];
    frame[..4].copy_from_slice(&[0x43, 0x88, 0xa2, 0x1c]);
    frame[36..68].copy_from_slice(&unhex(
        "002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352"));
    frame
}

fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().prefix("public call sentinel ").tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn not_disclosed(output: &[u8], bytes: &[u8]) {
    if bytes.is_empty() { return; }
    assert!(!output.windows(bytes.len()).any(|window| window == bytes), "input disclosed");
    let json = serde_json::to_vec(bytes).unwrap();
    assert!(!output.windows(json.len()).any(|window| window == json), "input JSON disclosed");
}

fn invoke(arguments: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .arg("samechain").args(arguments)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(stdin) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    let output = child.wait_with_output().unwrap();
    for argument in arguments {
        if argument.starts_with('/') || argument.contains("sentinel") {
            not_disclosed(&output.stderr, argument.as_bytes());
        }
    }
    for stream in [&output.stdout, &output.stderr] { not_disclosed(stream, stdin); }
    output
}

fn build(operation: &str, packet: &[u8], deployment: &[u8], frame: &[u8],
    frame_b: Option<&[u8]>, extra: &[&str]) -> Output
{
    let packet_file = file(packet);
    let deployment_file = file(deployment);
    let proof_file = file(frame);
    let proof_b_file = frame_b.map(file);
    let mut arguments = vec![operation, "--packet", packet_file.path().to_str().unwrap(),
        "--deployment", deployment_file.path().to_str().unwrap(),
        "--proof", proof_file.path().to_str().unwrap()];
    if let Some(file) = &proof_b_file {
        arguments.extend(["--proof-b", file.path().to_str().unwrap()]);
    }
    arguments.extend_from_slice(extra);
    let output = invoke(&arguments, &[]);
    for bytes in [packet, deployment, frame] { not_disclosed(&output.stderr, bytes); }
    output
}

fn exported(output: Output, operation: &str) -> Value {
    assert!(output.status.success(), "unsigned public command failed");
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "unsigned_samechain_call");
    assert_eq!(json["operation"], operation);
    assert_eq!(json["source"], "caller_public_files");
    assert_eq!(json["to"], AUTHORITY);
    for flag in ["proof_validity", "deployment_validity", "root_eligibility",
        "global_unspentness", "asset_backing"] {
        assert_eq!(json[flag], "UNVERIFIED");
    }
    for flag in ["signing", "submission", "financial_execution"] { assert_eq!(json[flag], false); }
    for forbidden in ["nonce", "gas_price", "signature", "tx_hash", "owner_seed", "witness"] {
        assert!(json.get(forbidden).is_none());
    }
    json
}

fn rejected(output: Output, code: i32) {
    assert_eq!(output.status.code(), Some(code));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

fn word(bytes: &[u8]) -> usize {
    assert_eq!(bytes.len(), 32);
    assert!(bytes[..24].iter().all(|byte| *byte == 0));
    usize::try_from(u64::from_be_bytes(bytes[24..].try_into().unwrap())).unwrap()
}

// Independent ABI decoding; selector literals were read from the actual solc
// methodIdentifiers, not computed by the Rust builder under test. Tests do not
// depend on disposable Foundry out/ build artifacts.
fn calldata(json: &Value, method: &str, packet: &[u8], frame: &[u8], frame_b: Option<&[u8]>,
    role_action: Option<(u8, u8)>)
{
    let selector: &[u8] = match method {
        "create(bytes,bytes)" => &[0x94, 0x18, 0x4b, 0xa9],
        "fill(bytes,bytes,bytes)" => &[0xd3, 0x16, 0xbd, 0x1a],
        "cancelOrExit(bytes,uint8,uint8,bytes)" => &[0xf6, 0x14, 0x6f, 0x41],
        "withdraw(bytes,bytes)" => &[0x50, 0xfb, 0xe2, 0xd9],
        _ => panic!("unknown ABI method"),
    };
    let data = unhex(json["data"].as_str().unwrap());
    assert_eq!(&data[..4], selector);
    let head_words = if role_action.is_some() { 4 } else if frame_b.is_some() { 3 } else { 2 };
    if let Some((role, action)) = role_action {
        assert_eq!(word(&data[36..68]), role as usize);
        assert_eq!(word(&data[68..100]), action as usize);
    }
    let mut expected = vec![(0, packet), (if role_action.is_some() { 3 } else { 1 }, frame)];
    if let Some(frame_b) = frame_b { expected.push((2, frame_b)); }
    let mut end = 4 + head_words * 32;
    for (head, expected_bytes) in expected {
        let offset = word(&data[4 + head * 32..36 + head * 32]);
        assert_eq!(offset + 4, end);
        let length = word(&data[end..end + 32]);
        assert_eq!(length, expected_bytes.len());
        assert_eq!(&data[end + 32..end + 32 + length], expected_bytes);
        let padded = length.div_ceil(32) * 32;
        assert!(data[end + 32 + length..end + 32 + padded].iter().all(|byte| *byte == 0));
        end += 32 + padded;
    }
    assert_eq!(end, data.len());
}

fn bindings(json: &Value, fixture: &Value, journal_fields: &[&str]) {
    assert_eq!(serde_json::from_value::<Vec<u8>>(json["packet_digest"].clone()).unwrap(),
        field(fixture, "digesthex"));
    let expected: Vec<Vec<u8>> = journal_fields.iter().map(|name| field(fixture, name)).collect();
    assert_eq!(serde_json::from_value::<Vec<Vec<u8>>>(json["expected_journals"].clone()).unwrap(), expected);
}

#[test]
fn all_four_public_modes_export_exact_unsigned_abi_and_descriptive_bindings() {
    let frame = proof();
    let mut frame_b = frame.clone();
    frame_b[99] = 1; // Public nonce: framing accepts arbitrary nonce, not proof validity.
    let fill = fixture("known_pair");
    let json = exported(build("build-fill-call", &field(&fill, "packethex"),
        &field(&fill, "deploymenthex"), &frame, Some(&frame_b), &["--sender", SENDER]), "build_fill_call");
    assert_eq!(json["from"], SENDER);
    assert_eq!(json["value_atoms"], "0");
    bindings(&json, &fill, &["journalhexA", "journalhexB"]);
    calldata(&json, "fill(bytes,bytes,bytes)", &field(&fill, "packethex"), &frame, Some(&frame_b), None);
    assert_eq!(json["effects"], serde_json::json!([{
        "manifest_index": 2, "kind": "Fee", "role": 0,
        "asset": TOKEN, "recipient": "0x0808080808080808080808080808080808080808", "amount_atoms": "1"
    }]));

    for (name, action, number) in [("single_cancel", "cancel", 1), ("single_exit", "exit", 2)] {
        let single = fixture(name);
        let json = exported(build("build-cancel-exit-call", &field(&single, "packethex"),
            &field(&single, "deploymenthex"), &frame, None,
            &["--sender", SENDER, "--role", "a", "--action", action]), "build_cancel_exit_call");
        assert_eq!(json["from"], SENDER);
        assert_eq!(json["value_atoms"], "0");
        bindings(&json, &single, &["journalhex"]);
        calldata(&json, "cancelOrExit(bytes,uint8,uint8,bytes)", &field(&single, "packethex"),
            &frame, None, Some((0, number)));
        assert_eq!(json["effects"], serde_json::json!([{
            "manifest_index": 1, "kind": "Exit", "role": 0, "asset": "native",
            "recipient": SENDER, "amount_atoms": "5"
        }]));
    }

    for name in ["received_token_partial", "received_native_full"] {
        let withdrawal = fixture(name);
        let json = exported(build("build-note-withdrawal-call", &field(&withdrawal, "packethex"),
            &field(&withdrawal, "deploymenthex"), &frame, None, &["--sender", SENDER]), "build_note_withdrawal_call");
        assert_eq!(json["from"], SENDER);
        assert_eq!(json["value_atoms"], "0");
        bindings(&json, &withdrawal, &["journalhex"]);
        calldata(&json, "withdraw(bytes,bytes)", &field(&withdrawal, "packethex"), &frame, None, None);
        let effects = if name == "received_token_partial" { serde_json::json!([
            {"manifest_index": 0, "kind": "Exit", "role": 0, "asset": TOKEN, "recipient": SENDER, "amount_atoms": "40"},
            {"manifest_index": 2, "kind": "Fee", "role": 0, "asset": TOKEN, "recipient": "0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", "amount_atoms": "1"}
        ]) } else { serde_json::json!([
            {"manifest_index": 0, "kind": "Exit", "role": 0, "asset": "native", "recipient": SENDER, "amount_atoms": "40"}
        ]) };
        assert_eq!(json["effects"], effects);
    }
}

#[test]
fn ordinary_native_token_and_initial_creation_preserve_payer_value_and_complete_ciphertext() {
    for name in ["ordinary_native", "ordinary_token", "initial_order_a", "initial_order_b"] {
        let creation = fixture(name);
        let packet = field(&creation, "packethex");
        let decoded = NoteCreationPacket::decode(&packet).unwrap();
        let json = exported(build("build-note-creation-call", &packet,
            &field(&creation, "deploymenthex"), &proof(), None, &["--token", TOKEN]), "build_note_creation_call");
        assert_eq!(json["from"], "0x0808080808080808080808080808080808080808");
        assert_eq!(json["value_atoms"], match name { "ordinary_native" => "100", "initial_order_a" => "105", _ => "0" });
        assert_eq!(json["effects"], serde_json::json!([]));
        bindings(&json, &creation, &["journalhex"]);
        calldata(&json, "create(bytes,bytes)", &packet, &proof(), None, None);
        assert_eq!(decoded.order.is_some(), name.starts_with("initial"));
    }
}

#[test]
fn u256_max_is_decimal_without_rounding_for_native_value_and_exit_effect() {
    let creation = fixture("ordinary_native");
    let mut packet = NoteCreationPacket::decode(&field(&creation, "packethex")).unwrap();
    packet.amount = U256::MAX; // Public shape only; no new private relation claim.
    let json = exported(build("build-note-creation-call", &packet.encode().unwrap(),
        &field(&creation, "deploymenthex"), &proof(), None, &["--token", TOKEN]), "build_note_creation_call");
    const MAX: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    assert_eq!(json["value_atoms"], MAX);
    let withdrawal = fixture("received_native_full");
    let mut packet = NoteWithdrawalPacket::decode(&field(&withdrawal, "packethex")).unwrap();
    let OutputDescriptor::Exit { amount, .. } = &mut packet.outputs[0] else { panic!("exit required") };
    *amount = U256::MAX;
    let json = exported(build("build-note-withdrawal-call", &packet.encode().unwrap(),
        &field(&withdrawal, "deploymenthex"), &proof(), None, &["--sender", SENDER]), "build_note_withdrawal_call");
    assert_eq!(json["effects"][0]["amount_atoms"], MAX);
    assert_eq!(json["value_atoms"], "0");
}

#[test]
fn malformed_wrapped_frames_and_missing_fill_proof_are_redacted_before_export() {
    let frame = proof();
    let mut bad_selector = frame.clone(); bad_selector[0] ^= 1;
    let mut bad_exit = frame.clone(); bad_exit[35] = 1;
    let mut bad_root = frame.clone(); bad_root[36] ^= 1;
    let mut trailing = frame.clone(); trailing.push(0);
    let frames = [vec![], frame[..355].to_vec(), trailing, vec![0; MAX_PACKET_BYTES + 1],
        bad_selector, bad_exit, bad_root, b"private witness sentinel not a certificate".to_vec()];
    for (operation, name, extra) in [
        ("build-note-creation-call", "ordinary_native", vec!["--token", TOKEN]),
        ("build-fill-call", "known_pair", vec!["--sender", SENDER]),
        ("build-cancel-exit-call", "single_cancel", vec!["--sender", SENDER, "--role", "a", "--action", "cancel"]),
        ("build-note-withdrawal-call", "received_token_partial", vec!["--sender", SENDER]),
    ] {
        let fixture = fixture(name);
        for invalid in &frames {
            rejected(build(operation, &field(&fixture, "packethex"), &field(&fixture, "deploymenthex"),
                invalid, (operation == "build-fill-call").then_some(frame.as_slice()), &extra), 1);
        }
        if operation == "build-fill-call" {
            for invalid in &frames {
                rejected(build(operation, &field(&fixture, "packethex"), &field(&fixture, "deploymenthex"),
                    &frame, Some(invalid), &extra), 1);
            }
            rejected(build(operation, &field(&fixture, "packethex"), &field(&fixture, "deploymenthex"),
                &frame, None, &extra), 2);
        }
    }
}

#[test]
fn independent_deployment_every_field_packet_eof_and_size_are_enforced_in_each_mode() {
    let mutations: [fn(&mut Deployment); 7] = [
        |d| d.chain_id += 1, |d| d.authority[0] ^= 1, |d| d.authority_code[0] ^= 1,
        |d| d.verifier[0] ^= 1, |d| d.verifier_code[0] ^= 1, |d| d.owner_program[0] ^= 1,
        |d| d.schema += 1,
    ];
    for (operation, name, extra) in [
        ("build-note-creation-call", "ordinary_native", vec!["--token", TOKEN]),
        ("build-fill-call", "known_pair", vec!["--sender", SENDER]),
        ("build-cancel-exit-call", "single_cancel", vec!["--sender", SENDER, "--role", "a", "--action", "cancel"]),
        ("build-note-withdrawal-call", "received_token_partial", vec!["--sender", SENDER]),
    ] {
        let fixture = fixture(name);
        let packet = field(&fixture, "packethex");
        let deployment = field(&fixture, "deploymenthex");
        let frame = proof();
        let second = (operation == "build-fill-call").then_some(frame.as_slice());
        for mutate in mutations {
            let mut expected = Deployment::decode(&deployment).unwrap();
            mutate(&mut expected);
            // Unsupported schema cannot encode canonically; mutate the actual
            // independent file's final schema byte for this decoder rejection.
            let bytes = expected.encode().unwrap_or_else(|_| {
                let mut bytes = deployment.clone(); *bytes.last_mut().unwrap() = 2; bytes
            });
            rejected(build(operation, &packet, &bytes, &frame, second, &extra), 1);
        }
        let mut packet_eof = packet.clone(); packet_eof.push(0);
        let mut deployment_eof = deployment.clone(); deployment_eof.push(0);
        for malformed in [packet_eof, vec![0; MAX_PACKET_BYTES + 1], vec![]] {
            rejected(build(operation, &malformed, &deployment, &frame, second, &extra), 1);
        }
        for malformed in [deployment_eof, vec![0; MAX_PACKET_BYTES + 1], vec![]] {
            rejected(build(operation, &packet, &malformed, &frame, second, &extra), 1);
        }
    }
}

#[test]
fn nonzero_public_addresses_role_action_and_exact_command_flags_are_required() {
    let frame = proof();
    let single = fixture("single_cancel");
    rejected(build("build-cancel-exit-call", &field(&single, "packethex"), &field(&single, "deploymenthex"),
        &frame, None, &["--sender", SENDER, "--role", "b", "--action", "cancel"]), 1);
    for (role, action) in [("a", "fill"), ("owner", "exit"), ("a", "Cancel")] {
        rejected(build("build-cancel-exit-call", &field(&single, "packethex"), &field(&single, "deploymenthex"),
            &frame, None, &["--sender", SENDER, "--role", role, "--action", action]), 2);
    }
    let creation = fixture("ordinary_native");
    for token in ["0x0000000000000000000000000000000000000000", SENDER,
        "sentinel owner secret must not be disclosed", "0707070707070707070707070707070707070707"] {
        rejected(build("build-note-creation-call", &field(&creation, "packethex"), &field(&creation, "deploymenthex"),
            &frame, None, &["--token", token]), 1);
    }
    let withdrawal = fixture("received_native_full");
    for sender in ["0x0000000000000000000000000000000000000000", "0x01", "0xgg09090909090909090909090909090909090909",
        "sentinel private key", "0909090909090909090909090909090909090909"] {
        rejected(build("build-note-withdrawal-call", &field(&withdrawal, "packethex"), &field(&withdrawal, "deploymenthex"),
            &frame, None, &["--sender", sender]), 1);
    }
    let packet = file(&field(&creation, "packethex"));
    let deployment = file(&field(&creation, "deploymenthex"));
    let proof_file = file(&frame);
    let arguments = ["build-note-creation-call", "--packet", packet.path().to_str().unwrap(),
        "--deployment", deployment.path().to_str().unwrap(), "--proof", proof_file.path().to_str().unwrap(), "--token", TOKEN];
    let output = invoke(&arguments, b"private witness stdin sentinel ignored by public branch");
    exported(output, "build_note_creation_call");
    let mut arguments = arguments.to_vec(); arguments.push("--witness-stdin");
    rejected(invoke(&arguments, &[]), 2);
}

#[test]
fn all_private_commands_reject_private_argv_without_disclosure() {
    for command in ["check-fill", "check-cancel-exit", "check-note-withdrawal", "review-note-withdrawal",
        "check-note-creation", "review-note-creation", "review-fill", "review-cancel-exit"] {
        for flag in ["--owner-seed", "--private-witness", "--witness-file"] {
            rejected(invoke(&[command, flag, "private argv sentinel"], b"private stdin sentinel"), 2);
        }
        rejected(invoke(&[command], b"private stdin sentinel"), 2);
    }
}

#[test]
fn fill_review_requires_independently_selected_canonical_execution_file() {
    let fill = fixture("known_pair");
    let packet = file(&field(&fill, "packethex"));
    let execution = file(&field(&fill, "executionhex"));
    let base = ["review-fill", "--packet", packet.path().to_str().unwrap(),
        "--role", "a", "--witness-stdin"];
    rejected(invoke(&base, b"private stdin sentinel"), 2);
    let mut arguments = base.to_vec();
    arguments.extend(["--execution", execution.path().to_str().unwrap()]);
    // The exact public file is accepted by the interface, then the deliberately
    // invalid private frame fails; a public vector is not an owner witness.
    rejected(invoke(&arguments, b"private stdin sentinel"), 1);
}

#[test]
fn role_proof_substitution_is_not_falsely_presented_as_cryptographic_verification() {
    let fill = fixture("known_pair");
    let first = proof();
    let mut second = proof(); second[99] = 2;
    for (a, b) in [(&first, &second), (&second, &first), (&first, &first)] {
        let json = exported(build("build-fill-call", &field(&fill, "packethex"),
            &field(&fill, "deploymenthex"), a, Some(b), &["--sender", SENDER]), "build_fill_call");
        // The frame has no independently inspectable owner role/journal. The
        // actual pinned verifier, not this offline consumer, must reject a
        // certificate substituted for another owner's statement.
        bindings(&json, &fill, &["journalhexA", "journalhexB"]);
        calldata(&json, "fill(bytes,bytes,bytes)", &field(&fill, "packethex"), a, Some(b), None);
    }
}

#[test]
fn absent_public_files_are_redacted_and_never_fall_back_to_private_stdin() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing public file sentinel");
    rejected(invoke(&["build-note-creation-call", "--packet", missing.to_str().unwrap(),
        "--deployment", missing.to_str().unwrap(), "--proof", missing.to_str().unwrap(),
        "--token", TOKEN], b"private stdin sentinel is not a public file fallback"), 1);
}

#[test]
fn role_b_single_call_preserves_the_selected_numeric_role_and_action() {
    use ziquid_protocol::samechain::{Role, SingleOwnerPacket};
    let single = fixture("single_exit");
    let mut packet = SingleOwnerPacket::decode(&field(&single, "packethex")).unwrap();
    for output in &mut packet.outputs {
        match output {
            OutputDescriptor::Note { role, .. } | OutputDescriptor::Exit { role, .. } => *role = Role::B,
            OutputDescriptor::Fee { payer, .. } => *payer = Role::B,
        }
    }
    // A different public role is a different proposal, not an owner proof.
    for (action, numeric) in [("cancel", 1), ("exit", 2)] {
        let bytes = packet.encode().unwrap();
        let json = exported(build("build-cancel-exit-call", &bytes, &field(&single, "deploymenthex"),
            &proof(), None, &["--sender", SENDER, "--role", "b", "--action", action]), "build_cancel_exit_call");
        calldata(&json, "cancelOrExit(bytes,uint8,uint8,bytes)", &bytes, &proof(), None, Some((1, numeric)));
        assert_eq!(json["effects"][0]["role"], 1);
    }
}

#[test]
fn public_branch_finishes_while_private_stdin_remains_open() {
    let creation = fixture("ordinary_native");
    let packet = file(&field(&creation, "packethex"));
    let deployment = file(&field(&creation, "deploymenthex"));
    let proof_file = file(&proof());
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .args(["samechain", "build-note-creation-call", "--packet", packet.path().to_str().unwrap(),
            "--deployment", deployment.path().to_str().unwrap(), "--proof", proof_file.path().to_str().unwrap(),
            "--token", TOKEN])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let private_stdin = child.stdin.take().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("public command waited for private stdin");
        }
        std::thread::yield_now();
    }
    let output = child.wait_with_output().unwrap();
    drop(private_stdin);
    exported(output, "build_note_creation_call");
}

#[cfg(feature = "sp1-local")]
mod verified_call {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn args(operation: &str, packet: &tempfile::NamedTempFile,
        deployment: &tempfile::NamedTempFile, proof_file: &tempfile::NamedTempFile,
        proof_b: Option<&tempfile::NamedTempFile>, extra: &[&str]) -> Vec<String> {
        let mut args = vec!["build-verified-call", "--operation", operation,
            "--packet", packet.path().to_str().unwrap(),
            "--deployment", deployment.path().to_str().unwrap(),
            "--proof", proof_file.path().to_str().unwrap()]
            .into_iter().map(str::to_owned).collect::<Vec<_>>();
        if let Some(proof_b) = proof_b {
            args.extend(["--proof-b", proof_b.path().to_str().unwrap()].map(str::to_owned));
        }
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        args
    }

    fn invoke_verified(operation: &str, fixture_name: &str, proof_bytes: &[u8],
        proof_b_bytes: Option<&[u8]>, extra: &[&str]) -> Output {
        let fixture = fixture(fixture_name);
        let packet = file(&field(&fixture, "packethex"));
        let deployment = file(&field(&fixture, "deploymenthex"));
        let proof_file = file(proof_bytes);
        let proof_b = proof_b_bytes.map(file);
        let command = args(operation, &packet, &deployment, &proof_file, proof_b.as_ref(), extra);
        let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
        invoke(&arguments, &[])
    }

    fn certificate_rejected(output: Output) {
        assert_eq!(output.status.code(), Some(1), "unexpected status: {output:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        assert!(stderr.contains("certificate"), "missing certificate rejection: {stderr}");
        assert!(!stderr.contains("unrecognized") && !stderr.contains("invalid samechain command arguments"),
            "command was not feature-enabled: {stderr}");
    }

    #[test]
    fn every_verified_operation_rejects_framed_zero_pairing_points_as_certificate_failure() {
        let frame = proof();
        for (operation, fixture_name, proof_b, extra) in [
            ("creation", "ordinary_native", None, vec!["--token", TOKEN]),
            ("fill", "known_pair", Some(frame.as_slice()), vec!["--sender", SENDER]),
            ("cancel", "single_cancel", None, vec!["--sender", SENDER, "--role", "a"]),
            ("exit", "single_exit", None, vec!["--sender", SENDER, "--role", "a"]),
            ("withdrawal", "received_token_partial", None, vec!["--sender", SENDER]),
        ] {
            certificate_rejected(invoke_verified(operation, fixture_name, &frame, proof_b, &extra));
        }
    }

    #[test]
    fn verified_call_requires_operation_specific_shape_and_independent_deployment() {
        let fixture = fixture("ordinary_native");
        let packet = file(&field(&fixture, "packethex"));
        let deployment = file(&field(&fixture, "deploymenthex"));
        let frame = file(&proof());
        let base = args("creation", &packet, &deployment, &frame, None, &[]);
        let mut command = base.clone();
        command.extend(["--sender", SENDER].map(str::to_owned));
        let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
        rejected(invoke(&arguments, &[]), 2);

        let mut command = base.clone();
        command.extend(["--token", TOKEN, "--proof-b", frame.path().to_str().unwrap()]
            .into_iter().map(str::to_owned));
        let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
        rejected(invoke(&arguments, &[]), 2);

        let mut command = base;
        command.extend(["--token", TOKEN, "--proof-b"].map(str::to_owned));
        let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
        rejected(invoke(&arguments, &[]), 2);

        let mut changed = Deployment::decode(&field(&fixture, "deploymenthex")).unwrap();
        changed.chain_id += 1;
        let changed_deployment = file(&changed.encode().unwrap());
        let command = args("creation", &packet, &changed_deployment, &frame, None,
            &["--token", TOKEN]);
        let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
        let output = invoke(&arguments, &[]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }

    #[test]
    fn verified_call_rejects_trailing_and_oversized_raw_proof_files() {
        for invalid in [proof().into_iter().chain([0]).collect::<Vec<_>>(), vec![0; 357]] {
            let output = invoke_verified("creation", "ordinary_native", &invalid, None,
                &["--token", TOKEN]);
            rejected(output, 1);
        }
    }

    #[test]
    fn verified_call_finishes_without_reading_an_open_private_stdin() {
        let fixture = fixture("ordinary_native");
        let packet = file(&field(&fixture, "packethex"));
        let deployment = file(&field(&fixture, "deploymenthex"));
        let proof_file = file(&proof());
        let command = args("creation", &packet, &deployment, &proof_file, None,
            &["--token", TOKEN]);
        let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
            .arg("samechain").args(&command).stdin(Stdio::piped())
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let held_stdin = child.stdin.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "verified call waited for private stdin");
            std::thread::yield_now();
        }
        let output = child.wait_with_output().unwrap();
        drop(held_stdin);
        certificate_rejected(output);
    }
}
