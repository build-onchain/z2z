use serde_json::{Value, json};
use std::{path::PathBuf, process::{Command, Output}};

const BASE: &str = "0xc4bf3f870c0e9465323c0b6ed28096c2";
const QUOTE: &str = "0xeb62eee3685fc4c43992febcd9e75443";
const ACCOUNT: &str = "0x1111111111111111111111111111111111111111";
const CLOID: &str = "0x00000000000000000000000000000001";
const PRIVATE: &str = "PRIVATE_CONFIG_SENTINEL";

struct Inputs {
    _directory: tempfile::TempDir,
    metadata: PathBuf,
    intent: PathBuf,
}

impl Inputs {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let metadata = directory.path().join("spot metadata.json");
        let intent = directory.path().join(format!("owner {PRIVATE} intent.json"));
        std::fs::write(&metadata, include_bytes!("../../chains/tests/fixtures/hypercore-testnet-spot-meta.json")).unwrap();
        Self { _directory: directory, metadata, intent }
    }

    fn run(&self, command: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ziquid"))
            .args(["hypercore", command, "--metadata"]).arg(&self.metadata)
            .arg("--intent").arg(&self.intent).output().unwrap()
    }

    fn prepare(&self, command: &str, intent: &Value) -> Output {
        std::fs::write(&self.intent, serde_json::to_vec(intent).unwrap()).unwrap();
        self.run(command)
    }
}

fn order() -> Value {
    json!({
        "network":"testnet", "account":ACCOUNT,
        "nonce":1700000000000_u64, "expires_after_ms":1700000060000_u64,
        "pair_index":0, "base_token_id":BASE, "quote_token_id":QUOTE,
        "cloid":CLOID, "side":"buy", "size":"2.000", "limit_price":"10.00", "tif":"Gtc",
        "fee_cap":{"token_id":QUOTE, "max_atoms":"100"}
    })
}

fn cancel() -> Value {
    let mut value = order();
    for field in ["cloid", "side", "size", "limit_price", "tif", "fee_cap"] {
        value.as_object_mut().unwrap().remove(field);
    }
    value["oid"] = json!(41);
    value
}

fn prepared(output: Output) -> Value {
    assert!(output.status.success(), "proposal failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    for field in ["signing_material_generated", "signing_ready", "submission_ready", "durable_reservation"] {
        assert_eq!(value[field], false, "{field}");
    }
    for field in ["source_validity", "account_mode", "nonce_validity"] {
        assert_eq!(value[field], "UNVERIFIED", "{field}");
    }
    assert_eq!(value["fee_cap_enforcement"], "NotVenueEnforced");
    assert_eq!(value["outcome"], "PreparedProposal");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["network"], "testnet");
    assert_eq!(value["account"], ACCOUNT);
    assert_eq!(value["signer"], ACCOUNT);
    assert_eq!(value["nonce"], 1700000000000_u64);
    assert_eq!(value["expires_after_ms"], 1700000060000_u64);
    value
}

fn rejected(output: Output, exit: i32) {
    assert_eq!(output.status.code(), Some(exit));
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(!diagnostic.trim().is_empty());
    for forbidden in [PRIVATE, ACCOUNT, CLOID, BASE, QUOTE, "owner ", "spot metadata.json"] {
        assert!(!diagnostic.contains(forbidden), "untrusted value in diagnostic");
    }
}

#[test]
fn actual_cli_prepares_selected_spot_order_and_preserves_fee_gate() {
    let inputs = Inputs::new();
    let value = prepared(inputs.prepare("prepare-order", &order()));
    assert_eq!(value["action_json"], r#"{"type":"order","orders":[{"a":10000,"b":true,"p":"10","s":"2","r":false,"t":{"limit":{"tif":"Gtc"}},"c":"0x00000000000000000000000000000001"}],"grouping":"na"}"#);
    assert_eq!(value["fee_cap"], json!({"token_id":QUOTE,"max_atoms":"100"}));
    // Repeated immutable input cannot gain a hidden nonce/time refresh.
    assert_eq!(value, prepared(inputs.run("prepare-order")));
    let mut normalized = order();
    normalized["size"] = json!("2");
    normalized["limit_price"] = json!("10");
    assert_eq!(value["intent_digest"], prepared(inputs.prepare("prepare-order", &normalized))["intent_digest"]);
}

#[test]
fn actual_cli_retains_explicit_sell_tif_and_base_token_fee_cap() {
    let inputs = Inputs::new();
    for tif in ["Alo", "Ioc"] {
        let mut intent = order();
        intent["side"] = json!("sell");
        intent["tif"] = json!(tif);
        intent["fee_cap"] = json!({"token_id":BASE,"max_atoms":"0"});
        let value = prepared(inputs.prepare("prepare-order", &intent));
        let action: Value = serde_json::from_str(value["action_json"].as_str().unwrap()).unwrap();
        assert_eq!(action["orders"][0]["b"], false);
        assert_eq!(action["orders"][0]["t"]["limit"]["tif"], tif);
        assert_eq!(value["fee_cap"], intent["fee_cap"]);
        assert!(action.get("builder").is_none());
        assert!(action.get("f").is_none());
    }
}

#[test]
fn actual_cli_prepares_distinct_cancel_forms_without_confirming_cancellation() {
    let inputs = Inputs::new();
    let oid = prepared(inputs.prepare("prepare-cancel", &cancel()));
    assert_eq!(oid["action_json"], r#"{"type":"cancel","cancels":[{"a":10000,"o":41}]}"#);
    assert!(oid.get("fee_cap").is_none());
    assert_eq!(oid, prepared(inputs.run("prepare-cancel")));
    let mut intent = cancel();
    intent.as_object_mut().unwrap().remove("oid");
    intent["cloid"] = json!(CLOID);
    let cloid = prepared(inputs.prepare("prepare-cancel", &intent));
    assert_eq!(cloid["action_json"], r#"{"type":"cancelByCloid","cancels":[{"asset":10000,"cloid":"0x00000000000000000000000000000001"}]}"#);
    assert_ne!(oid["intent_digest"], cloid["intent_digest"]);
}

#[test]
fn actual_cli_rejects_valid_selectors_encoded_as_objects() {
    let inputs = Inputs::new();
    for (field, value) in [
        ("network", json!({"testnet":null})),
        ("side", json!({"buy":null})),
        ("side", json!({"sell":null})),
        ("tif", json!({"Gtc":null})),
        ("tif", json!({"Alo":null})),
        ("tif", json!({"Ioc":null})),
    ] {
        let mut intent = order();
        intent[field] = value;
        rejected(inputs.prepare("prepare-order", &intent), 1);
    }
    let mut intent = cancel();
    intent["network"] = json!({"testnet":null});
    rejected(inputs.prepare("prepare-cancel", &intent), 1);
}

#[test]
fn invalid_order_terms_and_strict_config_never_produce_a_proposal_or_echo_input() {
    let inputs = Inputs::new();
    for (field, value) in [
        ("network", json!("mainnet")), ("network", json!(PRIVATE)),
        ("network", Value::Null),
        ("account", json!(PRIVATE)), ("cloid", json!(PRIVATE)),
        ("cloid", json!("0x00000000000000000000000000000000")),
        ("nonce", json!(0)), ("expires_after_ms", json!(1700000000000_u64)),
        ("base_token_id", json!(QUOTE)), ("pair_index", json!(u32::MAX)),
        ("size", json!("2.000000001")), ("limit_price", json!("12345.6")),
        ("size", json!("0")), ("size", json!("+2")), ("size", json!("2e0")),
        ("limit_price", json!("1e1")), ("size", json!(2)),
        ("side", json!("B")), ("tif", json!("gtc")),
        ("side", Value::Null), ("tif", Value::Null),
        ("fee_cap", json!({"token_id":QUOTE,"max_atoms":"-1"})),
        ("fee_cap", json!({"token_id":QUOTE,"max_atoms":"1.5"})),
        ("fee_cap", json!({"token_id":QUOTE,"max_atoms":"01"})),
        ("fee_cap", json!({"token_id":QUOTE,"max_atoms":100})),
        ("fee_cap", json!({"token_id":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","max_atoms":"1"})),
        ("fee_cap", json!({"token_id":QUOTE,"max_atoms":"1","secret":PRIVATE})),
        ("fee_cap", json!({"token_id":QUOTE,"max_atoms":"115792089237316195423570985008687907853269984665640564039457584007913129639936"})),
        ("secret", json!(PRIVATE)), ("vault_address", json!(ACCOUNT)),
    ] {
        let mut intent = order();
        intent[field] = value;
        rejected(inputs.prepare("prepare-order", &intent), 1);
    }
    for field in ["network", "account", "nonce", "expires_after_ms", "pair_index", "base_token_id", "quote_token_id", "cloid", "side", "size", "limit_price", "tif", "fee_cap"] {
        let mut intent = order();
        intent.as_object_mut().unwrap().remove(field);
        rejected(inputs.prepare("prepare-order", &intent), 1);
    }
    for bytes in [format!(r#"{{"secret":"{PRIVATE}""#), format!("{} trailing {PRIVATE}", order()), format!(r#"{{"network":"testnet","network":"{PRIVATE}"}}"#)] {
        std::fs::write(&inputs.intent, bytes).unwrap();
        rejected(inputs.run("prepare-order"), 1);
    }
}

#[test]
fn invalid_cancel_selectors_cannot_default_an_order_or_accept_order_only_fields() {
    let inputs = Inputs::new();
    let mut both = cancel();
    both["cloid"] = json!(CLOID);
    let mut neither = cancel();
    neither.as_object_mut().unwrap().remove("oid");
    let mut null_oid = cancel();
    null_oid["oid"] = Value::Null;
    null_oid["cloid"] = json!(CLOID);
    let mut null_cloid = cancel();
    null_cloid["cloid"] = Value::Null;
    for intent in [both, neither, null_oid, null_cloid, order()] {
        rejected(inputs.prepare("prepare-cancel", &intent), 1);
    }
    for (field, value) in [
        ("oid", json!(0)), ("oid", json!("41")), ("oid", json!(-1)),
        ("network", json!("mainnet")), ("account", json!(PRIVATE)),
        ("network", Value::Null),
        ("nonce", json!(0)), ("expires_after_ms", json!(1700000000000_u64)),
        ("quote_token_id", json!(BASE)), ("secret", json!(PRIVATE)),
        ("cloid", json!("0x00000000000000000000000000000000")),
        ("size", json!("2")), ("fee_cap", json!({"token_id":QUOTE,"max_atoms":"1"})),
    ] {
        let mut intent = cancel();
        if field == "cloid" { intent.as_object_mut().unwrap().remove("oid"); }
        intent[field] = value;
        rejected(inputs.prepare("prepare-cancel", &intent), 1);
    }
    for field in ["network", "account", "nonce", "expires_after_ms", "pair_index", "base_token_id", "quote_token_id"] {
        let mut intent = cancel();
        intent.as_object_mut().unwrap().remove(field);
        rejected(inputs.prepare("prepare-cancel", &intent), 1);
    }
}

#[test]
fn bounded_file_input_and_missing_paths_fail_without_stdout_or_path_diagnostics() {
    let inputs = Inputs::new();
    let mut bytes = serde_json::to_vec(&order()).unwrap();
    bytes.resize(64 * 1024, b' ');
    std::fs::write(&inputs.intent, &bytes).unwrap();
    prepared(inputs.run("prepare-order"));
    bytes.push(b' ');
    std::fs::write(&inputs.intent, bytes).unwrap();
    rejected(inputs.run("prepare-order"), 1);
    std::fs::write(&inputs.intent, serde_json::to_vec(&order()).unwrap()).unwrap();
    let mut metadata = include_bytes!("../../chains/tests/fixtures/hypercore-testnet-spot-meta.json").to_vec();
    metadata.resize(2 * 1024 * 1024, b' ');
    std::fs::write(&inputs.metadata, &metadata).unwrap();
    prepared(inputs.run("prepare-order"));
    std::fs::write(&inputs.metadata, vec![b' '; 2 * 1024 * 1024 + 1]).unwrap();
    rejected(inputs.run("prepare-order"), 1);
    std::fs::write(&inputs.metadata, format!(r#"{{"tokens":"{PRIVATE}"}}"#)).unwrap();
    rejected(inputs.run("prepare-order"), 1);
    std::fs::remove_file(&inputs.metadata).unwrap();
    rejected(inputs.run("prepare-order"), 1);
    std::fs::write(&inputs.metadata, include_bytes!("../../chains/tests/fixtures/hypercore-testnet-spot-meta.json")).unwrap();
    std::fs::remove_file(&inputs.intent).unwrap();
    rejected(inputs.run("prepare-cancel"), 1);
    let output = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .args(["hypercore", "prepare-order", "--intent"]).arg(&inputs.intent)
        .arg(PRIVATE).output().unwrap();
    rejected(output, 2);
}
