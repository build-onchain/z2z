#[cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod market_ledger_test_support;
#[path = "market_support/runtime.rs"]
mod support;

use serde_json::json;
use ziquid_protocol::market::ObservationEnvironment;
use ziquid_runtime::market::config::{self, Database, StoreConfig};

#[test]
fn database_transport_contains_only_private_uri_reference_and_authorized_schema() {
    let transport = json!({
        "uri_env": "Z2Z_TEST_DATABASE_URL",
        "schema": "z2z_fixture_configuration",
        "max_connections": 4
    });
    let parsed: Database = serde_json::from_value(transport.clone()).unwrap();
    parsed.config().unwrap();
    for field in ["uri", "url", "socket", "port", "user", "database", "password"] {
        let mut invalid = transport.clone();
        invalid[field] = json!("untrusted-transport");
        assert!(serde_json::from_value::<Database>(invalid).is_err());
    }
    for field in ["uri_env", "schema", "max_connections"] {
        let mut missing = transport.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Database>(missing).is_err());
    }
    for invalid in [
        json!({"uri_env":"", "schema":"z2z_fixture_configuration", "max_connections":4}),
        json!({"uri_env":"BAD=ENV", "schema":"z2z_fixture_configuration", "max_connections":4}),
        json!({"uri_env":"Z2Z_TEST_DATABASE_URL", "schema":"public", "max_connections":4}),
        json!({"uri_env":"Z2Z_TEST_DATABASE_URL", "schema":"schema;DROP", "max_connections":4}),
        json!({"uri_env":"Z2Z_TEST_DATABASE_URL", "schema":"z2z_fixture_configuration", "max_connections":0}),
    ] {
        assert!(serde_json::from_value::<Database>(invalid).unwrap().config().is_err());
    }
    let store: StoreConfig = serde_json::from_value(json!({
        "schema_version": 1, "database": transport
    })).unwrap();
    config::version(store.schema_version).unwrap();
    assert!(config::version(0).is_err());
    assert!(config::version(2).is_err());
}

#[test]
fn canonical_policy_rejects_wrong_scope_and_unknown_environment_without_sql() {
    let keys = std::array::from_fn(|_| support::fixture_key());
    let producers = std::array::from_fn(|_| support::fixture_key());
    let policy = support::policy(&keys, &producers);
    let decoded = config::policy(&policy.canonical_bytes().unwrap()).unwrap();
    assert_eq!(decoded, policy);
    let mut wrong_scope = policy.clone();
    wrong_scope.inventory_scope = [99; 32];
    assert!(config::policy(&wrong_scope.canonical_bytes().unwrap()).is_err());
    assert_eq!(config::environment("LocalFixture").unwrap(), ObservationEnvironment::LocalFixture);
    assert_eq!(config::environment("Network").unwrap(), ObservationEnvironment::Network);
    assert!(config::environment("localfixture").is_err());
    let bytes = policy.canonical_bytes().unwrap();
    for malformed in [bytes[..bytes.len() - 1].to_vec(), [bytes.as_slice(), &[0]].concat(), b"foreign-policy".to_vec()] {
        assert!(config::policy(&malformed).is_err());
    }
    assert!(config::domain(b"substituted-domain").is_err());
}


#[tokio::test]
async fn process_frames_preserve_exact_little_endian_bytes_and_reject_partial_frames() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use ziquid_runtime::market::{Error, process};

    let (mut output, mut input) = tokio::io::duplex(32);
    process::write_frame(&mut output, b"KERBSTOP").await.unwrap();
    let mut encoded = [0; 12];
    input.read_exact(&mut encoded).await.unwrap();
    assert_eq!(&encoded, b"\x08\x00\x00\x00KERBSTOP");
    assert!(matches!(process::write_frame(&mut output, b"").await, Err(Error::Frame)));
    let oversized = vec![0; ziquid_runtime::market::ledger::MAX_JOURNAL_BYTES + 1];
    assert!(matches!(process::write_frame(&mut output, &oversized).await, Err(Error::Frame)));
    let size = u32::try_from(oversized.len()).unwrap().to_le_bytes();
    let mut oversized_header = &size[..];
    assert!(matches!(process::read_frame(&mut oversized_header).await, Err(Error::Frame)));
    for invalid in [&b"\x00\x00\x00\x00"[..], &b"\x01\x00"[..], &b"\x03\x00\x00\x00ab"[..]] {
        let mut stream = invalid;
        assert!(matches!(process::read_frame(&mut stream).await, Err(Error::Frame)));
    }
    let mut valid = &b"\x08\x00\x00\x00KERBSTOP"[..];
    assert_eq!(process::read_frame(&mut valid).await.unwrap().as_deref(), Some(b"KERBSTOP".as_slice()));
    assert!(process::read_frame(&mut valid).await.unwrap().is_none());
    output.shutdown().await.unwrap();
}

#[test]
fn bounded_input_reader_rejects_oversized_configuration_without_reproducing_bytes() {
    let files = support::Files::new();
    let path = files.root.join("bounded config.json");
    std::fs::write(&path, b"abcd").unwrap();
    assert_eq!(config::read_bytes(&path, 4).unwrap(), b"abcd");
    assert!(matches!(config::read_bytes(&path, 3), Err(ziquid_runtime::market::Error::Input)));
    assert!(matches!(config::read::<StoreConfig>(&path), Err(ziquid_runtime::market::Error::Configuration)));
}
