//! Actual CLI/public loopback acquisition; generated observations are not financial evidence.
use primitive_types::U256;
use serde_json::{Value, json};
use std::{io::{Read, Write}, process::{Command, Output, Stdio}, time::{Duration, Instant}};
use ziquid_protocol::samechain::tree::root_from_path;

#[path = "../../chains/tests/support/samechain_inspection.rs"]
mod support;
#[path = "../../chains/tests/support/samechain_history.rs"]
mod history_support;
use history_support::{Scenario, block_hash};
use support::{Fault, Fixture, HistoryBlockFixture, hex};

const ENVIRONMENT: &str = "ZIQUID_HISTORY_TEST_ENDPOINT";
const SECRET: &str = "history-private-config-sentinel";
const STDIN_SECRET: &[u8] = b"history-unread-private-stdin-sentinel";

fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().prefix("history public sentinel ").tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn config(blocks: &[HistoryBlockFixture], deployment: &tempfile::NamedTempFile) -> Value {
    let origin = &blocks[0];
    json!({
        "schema_version": 1, "deployment": deployment.path(),
        "token": hex(&origin.scope.token), "token_code": hex(&origin.scope.token_code),
        "policy_id": hex(&origin.scope.policy_id), "endpoint_env": ENVIRONMENT,
        "allow_loopback_http": true, "origin_number": origin.number.to_string(),
        "block_hashes": blocks.iter().map(|block| hex(&block.scope.block_hash)).collect::<Vec<_>>(),
    })
}

fn invoke_bytes(bytes: &[u8], endpoint: Option<&str>, extra: &[&str]) -> Output {
    let configuration = file(bytes);
    let mut command = Command::new(env!("CARGO_BIN_EXE_ziquid"));
    command.args(["samechain", "inspect-history", "--config"])
        .arg(configuration.path()).args(extra).env_remove(ENVIRONMENT)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(endpoint) = endpoint { command.env(ENVIRONMENT, endpoint); }
    let mut child = command.spawn().unwrap();
    let mut held_stdin = child.stdin.take().unwrap();
    if let Err(error) = held_stdin.write_all(STDIN_SECRET) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    // Drain both pipes while stdin stays open, so even complete path exports cannot
    // mistake pipe backpressure for a private-input read.
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new(); stdout.read_to_end(&mut bytes).unwrap(); bytes
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new(); stderr.read_to_end(&mut bytes).unwrap(); bytes
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() { break status; }
        if Instant::now() >= deadline {
            child.kill().unwrap(); child.wait().unwrap();
            panic!("public history waited for private stdin or exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(held_stdin);
    let output = Output { status, stdout: stdout_reader.join().unwrap(), stderr: stderr_reader.join().unwrap() };
    for stream in [&output.stdout, &output.stderr] {
        for secret in [SECRET.as_bytes(), STDIN_SECRET, support::PROVIDER_SENTINEL.as_bytes(), ENVIRONMENT.as_bytes()] {
            assert!(!stream.windows(secret.len()).any(|window| window == secret), "private diagnostic disclosed");
        }
        if let Some(endpoint) = endpoint.filter(|endpoint| !endpoint.is_empty()) {
            assert!(!stream.windows(endpoint.len()).any(|window| window == endpoint.as_bytes()), "endpoint disclosed");
        }
    }
    let path = configuration.path().to_str().unwrap().as_bytes();
    assert!(!output.stderr.windows(path.len()).any(|window| window == path), "config path disclosed");
    output
}

fn invoke(config: &Value, endpoint: Option<&str>) -> Output {
    invoke_bytes(&serde_json::to_vec(config).unwrap(), endpoint, &[])
}

fn rejected(output: Output, code: i32) {
    assert_eq!(output.status.code(), Some(code));
    assert!(output.stdout.is_empty(), "failure exported partial history");
    assert!(!output.stderr.is_empty());
}

fn exported(output: Output) -> Value {
    assert!(output.status.success(), "actual inspect-history command failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["kind"], "samechain_history_observation");
    assert_eq!(value["status"], "APPEND_STATE_COHERENT");
    assert_eq!(value["source_scope"], "TRUSTED_NODE_AT_SELECTED_BLOCK");
    assert_eq!(value["initial_boundary_trust"], "TRUSTED_PROVIDER_INITIAL_EMPTY_BOUNDARY");
    assert_eq!(value["log_completeness_trust"], "TRUSTED_PROVIDER_LOG_COMPLETENESS");
    for field in ["finality", "proof_validity", "deployment_profile_qualification", "root_eligibility",
        "global_unspentness", "asset_backing"] { assert_eq!(value[field], "UNVERIFIED"); }
    for field in ["signing", "submission", "financial_execution"] { assert_eq!(value[field], false); }
    for field in ["endpoint", "witness", "owner_seed", "ownership", "payout", "proof", "response_sha256", "request_count"] {
        assert!(value.get(field).is_none(), "invented/private field {field}");
    }
    value
}

fn selected_hash_order(fixture: &Fixture) -> Vec<String> {
    let mut order = Vec::new();
    for request in fixture.requests() {
        let hash = match request["method"].as_str().unwrap() {
            "eth_chainId" => continue,
            "eth_getBlockByHash" => &request["params"][0],
            "eth_getCode" | "eth_call" => &request["params"][1]["blockHash"],
            "eth_getLogs" => &request["params"][0]["blockHash"],
            method => panic!("unexpected history RPC {method}"),
        }.as_str().unwrap().to_owned();
        if order.last() != Some(&hash) { order.push(hash); }
    }
    order
}

#[test]
fn exports_all_pinned_blocks_paths_ciphertexts_and_nullifiers_without_private_stdin() {
    let scenario = Scenario::new();
    let fixture = Fixture::with_history(scenario.blocks.clone());
    let scope = scenario.blocks[0].scope;
    let deployment = file(&scope.expected.encode().unwrap());
    let endpoint = format!("{}?api_key={SECRET}", fixture.endpoint());
    let value = exported(invoke(&config(&scenario.blocks, &deployment), Some(&endpoint)));
    assert_eq!(value["origin_number"], "42");
    assert_eq!(value["origin_hash"], hex(&block_hash(42)));
    assert_eq!(value["token"], hex(&scope.token));
    assert_eq!(value["token_code"], hex(&scope.token_code));
    assert_eq!(value["policy_id"], hex(&scope.policy_id));
    assert_eq!(value["expected_deployment"], json!({
        "chain_id": scope.expected.chain_id.to_string(), "authority": hex(&scope.expected.authority),
        "authority_code": hex(&scope.expected.authority_code), "verifier": hex(&scope.expected.verifier),
        "verifier_code": hex(&scope.expected.verifier_code), "owner_program": hex(&scope.expected.owner_program),
        "schema": scope.expected.schema,
    }));
    assert_eq!(value["block_count"], 4);
    assert_eq!(value["note_count"], 3);
    assert_eq!(value["nullifier_count"], 2);
    assert_eq!(value["ciphertext_bytes"], 100);
    assert_eq!(value["tree"], json!({"tree_id": 0, "count": 3, "root": hex(&scenario.notes[2].insertion.root)}));
    let blocks: Vec<_> = scenario.blocks.iter().map(|block| json!({
        "number": block.number.to_string(), "hash": hex(&block.scope.block_hash), "parent_hash": hex(&block.parent_hash),
    })).collect();
    assert_eq!(value["blocks"], json!(blocks));
    assert_eq!(selected_hash_order(&fixture), scenario.blocks.iter().map(|block| hex(&block.scope.block_hash)).collect::<Vec<_>>());
    assert_eq!(value["note_order"], "COMMITMENT_KEY");
    assert_eq!(value["nullifier_order"], "NULLIFIER_KEY");
    let notes = value["retained_notes"].as_array().unwrap();
    assert_eq!(notes.len(), scenario.notes.len());
    for (actual, expected) in notes.iter().zip(&scenario.notes) {
        assert_eq!(actual["commitment"], hex(&expected.commitment));
        assert_eq!(actual["ciphertext"], hex(&expected.ciphertext));
        assert_eq!(actual["recovery_key_commitment"], hex(&[0xc7; 32]));
        assert_eq!(actual["ciphertext_version"], 1);
        assert_eq!(actual["packet_digest"], hex(&[0x11; 32]));
        assert_eq!(actual["transaction_hash"], hex(&expected.transaction_hash));
        assert_eq!(actual["transaction_index"], expected.transaction_index);
        assert_eq!(actual["log_index"], expected.log_index);
        assert_eq!(actual["manifest_index"], expected.manifest_index);
        assert_eq!(actual["role"], expected.role as u8);
        let block = scenario.blocks.iter().position(|block| block.scope.block_hash == expected.block_hash).unwrap();
        assert_eq!(actual["block"], blocks[block]);
        assert_eq!(actual["tree_id"], expected.insertion.tree_id);
        assert_eq!(actual["index"], expected.insertion.index);
        assert_eq!(actual["count"], expected.insertion.count);
        assert_eq!(actual["root"], hex(&expected.insertion.root));
        let siblings = actual["insertion_siblings"].as_array().unwrap();
        assert_eq!(siblings.len(), 32);
        assert_eq!(siblings, &expected.insertion.siblings.iter().map(|hash| json!(hex(hash))).collect::<Vec<_>>());
        let mut path = [[0u8; 32]; 32];
        for (hash, encoded) in path.iter_mut().zip(siblings) {
            let digits = encoded.as_str().unwrap().strip_prefix("0x").unwrap();
            assert_eq!(digits.len(), 64);
            for (index, byte) in hash.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).unwrap();
            }
        }
        assert_eq!(root_from_path(&scope.expected.digest().unwrap(), expected.insertion.tree_id,
            expected.insertion.index, &expected.commitment, &path), expected.insertion.root);
    }
    assert_eq!(value["observed_nullifiers"], json!([
        {"block": blocks[1], "transaction_hash": hex(&[0x22;32]), "transaction_index":0,
            "log_index":0, "packet_digest":hex(&[0x11;32]), "nullifier":hex(&[0x55;32])},
        {"block": blocks[3], "transaction_hash": hex(&[0x23;32]), "transaction_index":0,
            "log_index":0, "packet_digest":hex(&[0x11;32]), "nullifier":hex(&[0x56;32])},
    ]));
}

#[test]
fn empty_history_accepts_zero_and_full_u256_origins_without_narrowing() {
    let scenario = Scenario::new();
    for (number, count) in [(U256::zero(), 1), (U256::from(u64::MAX) + U256::one(), 2), (U256::MAX, 1)] {
        let mut blocks = vec![scenario.blocks[0].clone(); count];
        for (index, block) in blocks.iter_mut().enumerate() {
            block.number = number + U256::from(index);
            block.scope.block_hash = block_hash(100 + index as u64);
            block.parent_hash = block_hash(99 + index as u64);
        }
        let fixture = Fixture::with_history(blocks.clone());
        let deployment = file(&blocks[0].scope.expected.encode().unwrap());
        let value = exported(invoke(&config(&blocks, &deployment), Some(fixture.endpoint())));
        assert_eq!(value["origin_number"], number.to_string());
        assert_eq!(value["block_count"], count);
        assert_eq!(value["blocks"][count - 1]["number"], blocks[count - 1].number.to_string());
        assert_eq!(value["retained_notes"], json!([]));
        assert_eq!(value["observed_nullifiers"], json!([]));
        assert_eq!(value["tree"], json!({"tree_id":0,"count":0,"root":hex(&blocks[0].tree_root)}));
    }
}

#[test]
fn validates_all_pins_decimal_bounds_and_scope_before_any_rpc() {
    let scenario = Scenario::new();
    let fixture = Fixture::with_history(scenario.blocks.clone());
    let deployment = file(&scenario.blocks[0].scope.expected.encode().unwrap());
    let base = config(&scenario.blocks, &deployment);
    let mut invalid = Vec::new();
    for origin in ["", "01", "+42", "-1", "42 ", " 42", "4e1", "42.0", "0x2a",
        "115792089237316195423570985008687907853269984665640564039457584007913129639936"] {
        let mut value = base.clone(); value["origin_number"] = json!(origin); invalid.push(value);
    }
    let mut overflow = base.clone(); overflow["origin_number"] = json!(U256::MAX.to_string()); invalid.push(overflow);
    for pin in [hex(&[0; 32]), SECRET.into(), "0x01".into(), "0X0123".into()] {
        let mut value = base.clone(); value["block_hashes"][3] = json!(pin); invalid.push(value);
    }
    let mut duplicate = base.clone(); duplicate["block_hashes"][3] = duplicate["block_hashes"][0].clone(); invalid.push(duplicate);
    let mut empty = base.clone(); empty["block_hashes"] = json!([]); invalid.push(empty);
    let mut excessive = base.clone();
    excessive["block_hashes"] = json!((1..=2049).map(|number| hex(&block_hash(number))).collect::<Vec<_>>()); invalid.push(excessive);
    for field in ["token", "token_code", "policy_id"] {
        let mut value = base.clone(); value[field] = json!(SECRET); invalid.push(value);
        let mut value = base.clone(); value[field] = json!(hex(&vec![0; if field == "token" {20} else {32}])); invalid.push(value);
    }
    let mut unavailable = base.clone(); unavailable["deployment"] = json!("/unreachable/history-private-config-sentinel"); invalid.push(unavailable);
    let malformed_deployment = file(SECRET.as_bytes());
    let mut malformed = base.clone(); malformed["deployment"] = json!(malformed_deployment.path()); invalid.push(malformed);
    for value in invalid { rejected(invoke(&value, Some(fixture.endpoint())), 1); }
    assert!(fixture.requests().is_empty(), "preflight allowed an RPC before validating the full config");
}

#[test]
fn rejects_raw_strict_json_duplicates_types_unknowns_trailing_and_file_overflow_before_rpc() {
    let scenario = Scenario::new();
    let fixture = Fixture::with_history(scenario.blocks.clone());
    let deployment = file(&scenario.blocks[0].scope.expected.encode().unwrap());
    let base = config(&scenario.blocks, &deployment);
    for field in ["schema_version", "deployment", "token", "token_code", "policy_id", "endpoint_env",
        "allow_loopback_http", "origin_number", "block_hashes"] {
        let mut missing = base.clone(); missing.as_object_mut().unwrap().remove(field);
        rejected(invoke(&missing, Some(fixture.endpoint())), 1);
        let mut null = base.clone(); null[field] = Value::Null;
        rejected(invoke(&null, Some(fixture.endpoint())), 1);
    }
    for (field, wrong) in [("schema_version", json!(2)), ("schema_version", json!("1")),
        ("origin_number", json!(42)), ("origin_number", json!({"42":null})),
        ("block_hashes", json!(hex(&block_hash(42)))), ("allow_loopback_http", json!("true")),
        ("token", json!({"address":hex(&scenario.blocks[0].scope.token)})),
        ("witness", json!(SECRET)), ("endpoint", json!(SECRET))] {
        let mut value = base.clone(); value[field] = wrong;
        rejected(invoke(&value, Some(fixture.endpoint())), 1);
    }
    let positional = json!([1, deployment.path(), base["token"], base["token_code"],
        base["policy_id"], ENVIRONMENT, true, "42", base["block_hashes"]]);
    rejected(invoke(&positional, Some(fixture.endpoint())), 1);
    let raw = serde_json::to_string(&base).unwrap();
    for (field, value) in base.as_object().unwrap() {
        let duplicate = format!("{{{}:{value},{}", serde_json::to_string(field).unwrap(), &raw[1..]);
        rejected(invoke_bytes(duplicate.as_bytes(), Some(fixture.endpoint()), &[]), 1);
    }
    for suffix in ["{}", SECRET] {
        rejected(invoke_bytes(format!("{raw}{suffix}").as_bytes(), Some(fixture.endpoint()), &[]), 1);
    }
    let mut oversized = raw.as_bytes().to_vec(); oversized.resize(1024 * 1024 + 1, b' ');
    rejected(invoke_bytes(&oversized, Some(fixture.endpoint()), &[]), 1);
    assert!(fixture.requests().is_empty());
}

#[test]
fn exact_config_limit_is_accepted_and_private_or_endpoint_flags_are_not() {
    let scenario = Scenario::new();
    let blocks = &scenario.blocks[..1];
    let fixture = Fixture::with_history(blocks.to_vec());
    let deployment = file(&blocks[0].scope.expected.encode().unwrap());
    let value = config(blocks, &deployment);
    let mut bytes = serde_json::to_vec(&value).unwrap(); bytes.resize(1024 * 1024, b' ');
    exported(invoke_bytes(&bytes, Some(fixture.endpoint()), &[]));
    for extra in [&["--witness-stdin"][..], &["--endpoint", SECRET], &["--block-hash", SECRET]] {
        rejected(invoke_bytes(&serde_json::to_vec(&value).unwrap(), Some(fixture.endpoint()), extra), 2);
    }
}

#[test]
fn endpoint_permission_and_environment_errors_are_local_and_categorical() {
    let scenario = Scenario::new();
    let fixture = Fixture::with_history(scenario.blocks.clone());
    let deployment = file(&scenario.blocks[0].scope.expected.encode().unwrap());
    let base = config(&scenario.blocks, &deployment);
    for endpoint in [None, Some(SECRET), Some("http://user:history-private-config-sentinel@127.0.0.1:1/")] {
        rejected(invoke(&base, endpoint), 1);
    }
    let mut http = base.clone(); http["allow_loopback_http"] = json!(false);
    rejected(invoke(&http, Some(fixture.endpoint())), 1);
    let mut invalid = base; invalid["endpoint_env"] = json!("invalid=history-private-config-sentinel");
    rejected(invoke(&invalid, None), 1);
    assert!(fixture.requests().is_empty());
}

#[test]
fn late_parent_number_tree_and_pin_order_fail_without_partial_stdout_or_fallback() {
    for fault in 0..4 {
        let scenario = Scenario::new();
        let mut blocks = scenario.blocks.clone();
        match fault {
            0 => blocks[3].parent_hash[0] ^= 1,
            1 => {
                let block = &mut blocks[3];
                block.number += U256::one();
                let number = block.number;
                for log in block.appended_logs.iter_mut().chain(&mut block.nullifier_logs) {
                    log["blockNumber"] = json!(format!("0x{number:x}"));
                }
            }
            2 => blocks[3].tree_root[0] ^= 1,
            3 => {},
            _ => unreachable!(),
        }
        let fixture = Fixture::with_history(blocks.clone());
        let deployment = file(&blocks[0].scope.expected.encode().unwrap());
        let mut value = config(&blocks, &deployment);
        if fault == 3 { value["block_hashes"].as_array_mut().unwrap().swap(1, 2); }
        rejected(invoke(&value, Some(fixture.endpoint())), 1);
        let acquired = selected_hash_order(&fixture);
        let expected = if fault == 3 { vec![hex(&block_hash(42)), hex(&block_hash(44))] }
            else { blocks.iter().map(|block| hex(&block.scope.block_hash)).collect() };
        assert_eq!(acquired, expected);
    }
}

#[test]
fn provider_error_stops_without_retry_alternate_pin_or_output() {
    let fixture = Fixture::with_fault(Fault::RpcRejected);
    let scenario = Scenario::new();
    let deployment = file(&scenario.blocks[0].scope.expected.encode().unwrap());
    rejected(invoke(&config(&scenario.blocks, &deployment), Some(fixture.endpoint())), 1);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 1, "provider failure was retried or followed by fallback");
    assert_eq!(requests[0]["method"], "eth_chainId");
}
