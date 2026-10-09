#[cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod market_ledger_test_support;
#[path = "market_support/runtime.rs"]
mod support;
use serde_json::{Value, json};
use std::process::Command;
use support::*;

// Actual ELF transfers have base units 7=5+2; independent native liabilities are
// quote units 34=25+9. No processor, network, source proof or native signer fallback.
#[tokio::test]
async fn local_cli_binds_real_elf_release_to_two_exact_durable_unsigned_native_intents() {
    let files = Files::new();
    let coordinator = Database::new("endtoend").await;
    let replica_databases = [
        Database::new("replica").await,
        Database::new("replica").await,
        Database::new("replica").await,
    ];
    let target_binary = std::env::var_os("Z2Z_TEST_SOLANA_BIN")
        .expect("actual separately built ELF harness binary required");
    let elf = std::env::var_os("Z2Z_SBF_ELF").expect("actual compiled Kerb ELF required");
    let native = fixture_dir();
    let config = files.json("local.json", &json!({ "schema_version": 1, "environment": "LocalFixture",
        "database": coordinator.json(), "replicas": replica_databases.each_ref().map(Database::json),
        "solana_binary": std::path::PathBuf::from(target_binary), "solana_elf": std::path::PathBuf::from(elf),
        "native_policy": native.join("policy.json") }));
    let output = Command::new(binary())
        .args(["market", "local-safety-scenario", "--config"])
        .arg(&config)
        .output()
        .expect("actual runnable local coordinator required");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["environment"], "LocalFixture");
    assert_eq!(report["simulated_operator_independence"], true);
    assert_eq!(report["prepared_debit"], 34);
    assert_eq!(
        (
            report["seller_liability"].as_u64(),
            report["unused_refund"].as_u64()
        ),
        (Some(25), Some(9))
    );
    assert_eq!(report["partial_activation"], "held");
    assert_eq!(report["unknown_restart"], "held");
    assert_eq!(
        report["unused_refund_without_spl"],
        "inspected-and-prepared"
    );
    assert_eq!(
        (
            report["spl_buyer_balance"].as_u64(),
            report["spl_escrow_balance"].as_u64()
        ),
        (Some(5), Some(2))
    );
    assert_eq!(report["native"], "two-unsigned-intents-durable");
    assert_eq!(report["native_fee_each"], 10_000);
    assert_eq!(report["user_inputs"], 34);
    assert_eq!(report["sponsor_fee_capital"], 20_000);
    assert_eq!(report["native_recipient"], 25);
    assert_eq!(report["native_change"], 9);
    assert_eq!(report["refund_recipient"], 9);
    assert_eq!(report["journal_ack_count_each"], 3);
    assert_eq!(report["local_observed_payout"], 25);
    assert_eq!(report["refund_status"], "prepared-unknown");
    assert_eq!(report["real_native_payout"], false);
    assert_eq!(report["real_native_refund"], false);
    assert_eq!(report["native_signed"], false);
    assert_eq!(report["native_broadcast"], false);
    assert_eq!(report["private_enabled"], false);
    assert_ne!(report["journal_head"], report["target_head"]);
    assert_eq!(report["locked_user_inventory"], 9);
    assert!(
        report["replica_process_ids"]
            .as_array()
            .is_some_and(|ids| ids.len() == 3
                && ids[0] != ids[1]
                && ids[0] != ids[2]
                && ids[1] != ids[2])
    );
    assert!(
        report["pczt_digest"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)
    );
    coordinator.remove().await;
    for database in replica_databases {
        database.remove().await;
    }
}
