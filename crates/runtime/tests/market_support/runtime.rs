#![allow(dead_code)]
use ed25519_dalek::{Signer, SigningKey};
use ziquid_runtime::market::ledger::{
    MAX_JOURNAL_BYTES, PairPolicy, SignedTargetFacts, TargetFacts,
    TargetHoldBinding, TargetHoldEvidence,
};
use ziquid_protocol::market::*;
use serde_json::Value;
#[cfg(feature = "postgres-tests")]
use serde_json::json;
#[cfg(feature = "postgres-tests")]
use ziquid_runtime::database::DatabaseConfig;
#[cfg(feature = "postgres-tests")]
use crate::market_ledger_test_support as ledger_support;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);

pub fn binary() -> PathBuf {
    std::env::var_os("Z2Z_RUNTIME_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_ziquid").map(PathBuf::from))
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/ziquid")
        })
}

pub fn fixture_dir() -> PathBuf {
    std::env::var_os("Z2Z_TEST_NATIVE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/market"))
}

pub fn fixture_key() -> SigningKey {
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}

pub fn domain() -> Domain {
    Domain {
        schema_version: SCHEMA_VERSION,
        deployment: [1; 32],
        solana_genesis: [2; 32],
        solana_program: [3; 32],
        mint: [4; 32],
        token_program: LEGACY_TOKEN_PROGRAM,
        source_network: SOURCE_NETWORK_TESTNET,
        source_pool: SOURCE_POOL_IRONWOOD,
        source_branch: SOURCE_BRANCH_NU6_3,
        source_tx_version: SOURCE_TRANSACTION_VERSION,
        source_genesis: [5; 32],
        receiver_policy: [6; 32],
        pair: [7; 32],
        epoch: 1,
        rules_hash: [8; 32],
        roster_version: 1,
        signature_scheme: SIGNATURE_SCHEME_ED25519,
    }
}

pub fn policy(keys: &[SigningKey; 3], producers: &[SigningKey; 3]) -> PairPolicy {
    PairPolicy {
        domain: domain(),
        environment: ObservationEnvironment::LocalFixture,
        source_policy: [20; 32],
        history_anchor: [21; 32],
        minimum_confirmations: 10,
        receiver: [22; 43],
        inventory_scope: domain().pair,
        sponsor_scope: [24; 32],
        source_producer: producers[0].verifying_key().to_bytes(),
        inventory_producer: producers[1].verifying_key().to_bytes(),
        target_observer: producers[2].verifying_key().to_bytes(),
        target_admin: [25; 32],
        roster: keys.each_ref().map(|key| key.verifying_key().to_bytes()),
    }
}

// Producer-authenticated local facts for storage/process tests, not an ELF or
// network observation. The separate solana_safety case consumes actual execution.
pub fn target_binding(policy: &PairPolicy, hold: Id, observer: &SigningKey) -> TargetHoldBinding {
    use ziquid_solana_interface as target;
    let pair = target::pair_address(&policy.domain, &policy.target_admin);
    let epoch = target::epoch_address(&policy.domain, &pair);
    let target_hold = target::hold_address(&policy.domain, &epoch, &hold);
    let accounts = [pair, epoch, target_hold, target::INSTRUCTIONS_SYSVAR_ID];
    let decision = target::decision(
        policy.domain,
        target_hold,
        None,
        Transition::PrepareSeller,
        target::Envelope {
            intent: [26; 32],
            generation: 1,
            prior: 1,
            predecessor: [0; 32],
        },
        &[],
        &accounts,
    )
    .unwrap();
    let facts = TargetFacts {
        decision,
        observation: ChainObservation {
            environment: policy.environment,
            operation: decision.operation.id().unwrap(),
            transaction: [27; 32],
            slot: 100,
            commitment: ChainCommitment::Finalized,
            effects: decision.operation.effects,
        },
    };
    let prepared = SignedTargetFacts {
        signature: observer.sign(&facts.signing_bytes().unwrap()).to_bytes(),
        facts,
    };
    let mut binding = TargetHoldBinding {
        domain: policy.domain,
        hold_business: hold,
        maximum_base: 7,
        expected_chunks: 2,
        refund_token: [28; 32],
        epoch_version: 3,
        evidence: TargetHoldEvidence::Prepared { prepare: prepared },
        signature: [0; 64],
    };
    binding.signature = observer.sign(&binding.signing_bytes().unwrap()).to_bytes();
    binding
}

#[cfg(feature = "postgres-tests")]
pub struct Database {
    pub config: DatabaseConfig,
}
#[cfg(feature = "postgres-tests")]
impl Database {
    pub async fn new(label: &str) -> Self {
        let mut config = ledger_support::TestDatabase::create(label).await.config;
        config.max_connections = 4;
        Self { config }
    }
    pub fn json(&self) -> Value {
        serde_json::to_value(&self.config).unwrap()
    }
    pub async fn remove(self) {
        ledger_support::TestDatabase { config: self.config }.remove().await;
    }
}

pub struct Files {
    pub root: PathBuf,
}
impl Files {
    pub fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "z2z-runtime-tests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self { root }
    }
    pub fn json(&self, name: &str, content: &Value) -> PathBuf {
        let path = self.root.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true).create_new(true).mode(0o600).open(&path).unwrap();
        file.write_all(&serde_json::to_vec(content).unwrap()).unwrap();
        path
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[cfg(feature = "postgres-tests")]
pub fn replica_config(
    files: &Files,
    name: &str,
    database: &Database,
    policy: &PairPolicy,
    signer: Id,
) -> PathBuf {
    files.json(
        name,
        &json!({ "schema_version": 1, "database": database.json(),
        "policy": policy.canonical_bytes().unwrap(), "expected_signer": signer }),
    )
}

pub struct Process {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}
impl Process {
    pub fn launch(config: &Path, signer: &SigningKey) -> Self {
        let replica: ziquid_runtime::market::config::ReplicaConfig =
            ziquid_runtime::market::config::read(config).unwrap();
        replica.database.config().unwrap();
        let mut command = Command::new(binary());
        command.env_clear();
        if let Some(uri) = std::env::var_os(&replica.database.uri_env) {
            command.env(&replica.database.uri_env, uri);
        }
        let mut child = command
            .args(["market", "replica", "--config"])
            .arg(config)
            .arg("--local-fixture-key-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("runnable ziquid market replica binary required");
        let mut input = child.stdin.take().unwrap();
        input.write_all(b"KERBFX01").unwrap();
        input.write_all(&signer.to_bytes()).unwrap();
        input.flush().unwrap();
        let output = child.stdout.take().unwrap();
        let mut process = Self {
            child,
            input,
            output,
        };
        let hello = process.read();
        assert_eq!(&hello[..8], b"KERBRD01");
        assert_eq!(&hello[8..40], signer.verifying_key().as_bytes());
        process
    }
    pub fn read(&mut self) -> Vec<u8> {
        let mut length = [0; 4];
        self.output.read_exact(&mut length).unwrap();
        let length = u32::from_le_bytes(length) as usize;
        assert!(
            length <= MAX_JOURNAL_BYTES,
            "replica response exceeds bounded frame"
        );
        let mut bytes = vec![0; length];
        self.output.read_exact(&mut bytes).unwrap();
        bytes
    }
    pub fn request(&mut self, kind: u8, body: &[u8]) -> Vec<u8> {
        assert!(body.len() < MAX_JOURNAL_BYTES);
        self.input
            .write_all(&u32::try_from(body.len() + 1).unwrap().to_le_bytes())
            .unwrap();
        self.input.write_all(&[kind]).unwrap();
        self.input.write_all(body).unwrap();
        self.input.flush().unwrap();
        self.read()
    }
    pub fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
    pub fn shutdown(mut self) {
        assert_eq!(self.request(3, &[]), b"KERBSTOP");
        assert!(self.child.wait().unwrap().success());
    }
    pub fn id(&self) -> u32 {
        self.child.id()
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
