#[cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod market_ledger_test_support;
#[path = "market_support/runtime.rs"]
mod support;
use pczt::Pczt;
use serde_json::{Value, json};
use std::process::Command;
use support::*;

#[test]
fn accepted_pczt_with_supplied_unverified_authorization_does_not_claim_signature_absence() {
    let root = fixture_dir();
    let original = Pczt::parse(&std::fs::read(root.join("unsigned.pczt")).unwrap()).unwrap();
    let encoded = pczt::v2::Pczt::try_from(original).unwrap();
    let mut fields = serde_json::to_value(encoded).unwrap();
    fields["ironwood"]["actions"][0]["spend"]["spend_auth_sig"] = json!(vec![7_u8; 64]);
    let encoded: pczt::v2::Pczt = serde_json::from_value(fields).unwrap();
    let bytes = encoded.serialize();
    assert!(
        Pczt::parse(&bytes).unwrap().ironwood().actions()[0]
            .spend()
            .spend_auth_sig()
            .is_some()
    );
    let files = Files::new();
    let path = files.root.join("supplied-authorization.pczt");
    std::fs::write(&path, bytes).unwrap();
    let output = Command::new(binary())
        .args(["market", "inspect-pczt", "--config"])
        .arg(root.join("policy.json"))
        .arg("--pczt")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        summary.get("signed").is_none(),
        "unverified supplied authorization is not proof of signature absence"
    );
    assert_eq!(summary["status"], "effects-checked");
    assert_eq!(summary["signatures_verified"], false);
    assert_eq!(summary["signing_performed"], false);
    assert_eq!(summary["proofs_verified"], false);
    assert_eq!(summary["broadcast"], false);
}

#[test]
fn inspect_pczt_parses_real_native_bytes_and_rejects_substituted_effects_without_dumping_policy() {
    let fixture_dir = fixture_dir();
    let files = Files::new();
    let pczt = fixture_dir.join("unsigned.pczt");
    let config = fixture_dir.join("policy.json");
    let accepted = Command::new(binary())
        .args(["market", "inspect-pczt", "--config"])
        .arg(&config)
        .arg("--pczt")
        .arg(&pczt)
        .output()
        .expect("runnable native inspection CLI required");
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let summary: Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(
        (
            summary["input_count"].as_u64(),
            summary["output_count"].as_u64()
        ),
        (Some(2), Some(2))
    );
    assert_eq!(summary["fee"], 10_000);
    assert_eq!(summary["environment"], "LocalFixture");
    let original: Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    let fvk = serde_json::to_string(&original["inputs"][0]["trusted_fvk"]).unwrap();
    assert!(!String::from_utf8_lossy(&accepted.stdout).contains(&fvk));
    let mut wrong = original;
    wrong["outputs"][0]["value"] = json!(399_999);
    let wrong_path = files.json("wrong.json", &wrong);
    let rejected = Command::new(binary())
        .args(["market", "inspect-pczt", "--config"])
        .arg(&wrong_path)
        .arg("--pczt")
        .arg(&pczt)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("native inspection rejected"));
    assert!(rejected.stdout.is_empty());
}
