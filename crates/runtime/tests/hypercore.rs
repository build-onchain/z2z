use std::process::Command;
#[test]
fn native_metadata_inspection_binds_selected_pair_and_rejects_asset_substitution() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../chains/tests/fixtures/hypercore-testnet-spot-meta.json");
    let bytes = std::fs::read(&fixture).unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let tokens = metadata["tokens"].as_array().unwrap();
    let id = |index| tokens.iter().find(|t| t["index"] == index).unwrap()["tokenId"].as_str().unwrap();
    let selected = ["hypercore","inspect-meta","--file",fixture.to_str().unwrap(),"--pair-index","0","--base-token-id",id(1),"--quote-token-id",id(0)];
    let output = Command::new(env!("CARGO_BIN_EXE_ziquid")).args(selected).output().unwrap();
    assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["market"]["action_asset"],10_000);
    assert_eq!(result["market"]["base_index"],1);
    assert_eq!(result["market"]["quote_index"],0);
    assert_eq!(result["source_validity"],"UNVERIFIED");
    assert_eq!(result["signing"],false);
    let mut wrong = selected;wrong[8] = id(0);
    let rejected = Command::new(env!("CARGO_BIN_EXE_ziquid")).args(wrong).output().unwrap();
    assert!(!rejected.status.success());assert!(rejected.stdout.is_empty());
}

#[test]
fn malformed_info_arguments_never_echo_supplied_account_or_private_values() {
    let sentinel="0x1111111111111111111111111111111111111111";
    for arguments in [
        vec!["hypercore","info","--network","testnet","--request",sentinel],
        vec!["hypercore","info","--network",sentinel,"--request","spot-meta"],
        vec!["hypercore","info","--network","mainnet","--request","spot-meta"],
        vec!["hypercore","info","--request","spot-meta"],
        vec!["hypercore","info","--network","testnet","--request","spot-meta",sentinel],
        vec!["hypercore","inspect-meta","--file","unused","--pair-index",sentinel,"--base-token-id","invalid","--quote-token-id","invalid"],
    ] {
        let output=Command::new(env!("CARGO_BIN_EXE_ziquid")).args(arguments).output().unwrap();
        assert_eq!(output.status.code(),Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(sentinel));
    }
}


#[test]
fn invalid_info_selectors_are_rejected_before_network_without_private_diagnostics() {
    let account = "0x112233445566778899aabbccddeeff0011223344";
    let cloid = "0x112233445566778899aabbccddeeff00";
    let private = "PRIVATE_INVALID_VALUE";
    let mut cases = vec![
        vec!["--request", "spot-balances", "--account", account, "--unknown-private-option", private],
        vec!["--request", "spot-balances", "--account", private],
        vec!["--request", "order-status", "--account", account, "--oid", private],
        vec!["--request", "order-status", "--account", account, "--cloid", private],
        vec!["--request", "order-status", "--account", account],
        vec!["--request", "order-status", "--account", account, "--oid", "7", "--cloid", cloid],
        vec!["--request", "order-status", "--account", account, "--oid", "7", "--start-ms", "1"],
        vec!["--request", "order-status", "--account", account, "--oid", "7", "--end-ms", "2"],
        vec!["--request", "fills-by-time", "--account", account, "--start-ms", "1"],
        vec!["--request", "fills-by-time", "--account", account, "--end-ms", "2"],
        vec!["--request", "fills-by-time", "--account", account, "--start-ms", "2", "--end-ms", "1"],
        vec!["--request", "fills-by-time", "--account", account, "--start-ms", private, "--end-ms", "2"],
        vec!["--request", "fills-by-time", "--account", account, "--start-ms", "1", "--end-ms", private],
        vec!["--request", "fills-by-time", "--account", account, "--start-ms", "1", "--end-ms", "2", "--oid", "7"],
        vec!["--request", "fills-by-time", "--account", account, "--start-ms", "1", "--end-ms", "2", "--cloid", cloid],
        vec!["--request", "spot-meta", "--account", account],
        vec!["--request", "spot-meta", "--oid", "7"],
        vec!["--request", "spot-meta", "--cloid", cloid],
        vec!["--request", "spot-meta", "--start-ms", "1"],
        vec!["--request", "spot-meta", "--end-ms", "2"],
    ];
    for request in ["spot-balances", "account-mode", "user-fees", "open-orders", "order-status", "fills-by-time"] {
        cases.push(vec!["--request", request]);
    }
    for request in ["spot-balances", "account-mode", "user-fees", "open-orders"] {
        for (selector, value) in [("--oid", "7"), ("--cloid", cloid), ("--start-ms", "1"), ("--end-ms", "2")] {
            cases.push(vec!["--request", request, "--account", account, selector, value]);
        }
    }
    for arguments in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_ziquid"))
            .args(["hypercore", "info", "--network", "testnet"])
            .args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert!(!diagnostic.trim().is_empty());
        for value in [account, cloid, private, "--unknown-private-option"] {
            assert!(!diagnostic.contains(value));
        }
    }
}

#[test]
fn untrusted_metadata_and_paths_never_enter_error_diagnostics() {
    let directory = tempfile::tempdir().unwrap();
    let sentinel = "PRIVATE_METADATA_VALUE";
    let file = directory.path().join(format!("{sentinel}.json"));
    std::fs::write(&file, format!(r#"{{"tokens":"{sentinel}"}}"#)).unwrap();
    for path in [file.clone(), directory.path().join(format!("MISSING_{sentinel}"))] {
        let output = Command::new(env!("CARGO_BIN_EXE_ziquid"))
            .args(["hypercore", "inspect-meta", "--file"]).arg(path)
            .args(["--pair-index", "0", "--base-token-id", sentinel, "--quote-token-id", sentinel])
            .output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(sentinel));
    }
}
