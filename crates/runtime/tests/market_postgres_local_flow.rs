#[cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod market_ledger_test_support;
#[path = "market_support/runtime.rs"]
mod support;
use ed25519_dalek::{Signer, SigningKey};
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use serde_json::json;
use std::process::Command;
use support::*;

fn operation(
    policy: &PairPolicy,
    generation: u64,
    entity: Id,
    intent: Id,
    version: u64,
    transition: Transition,
    command: &LedgerCommand,
) -> Operation {
    let mut operation = Operation {
        domain: policy.domain,
        entity,
        portion: [0; 32],
        intent,
        generation,
        prior_version: version,
        transition,
        effects: [0; 32],
    };
    operation.effects = command.operation_effects(&operation).unwrap();
    operation
}

fn funding(
    policy: &PairPolicy,
    producers: &[SigningKey; 3],
    claimant: &SigningKey,
) -> LedgerCommand {
    let occurrence = SourceOccurrence {
        network: policy.domain.source_network,
        pool: policy.domain.source_pool,
        txid: [50; 32],
        action_index: 0,
    };
    let source = SourceFacts {
        domain: policy.domain,
        provenance: ObservationEnvironment::LocalFixture,
        occurrence,
        receiver: policy.receiver,
        value: 34,
        block: [30; 32],
        height: 100,
        confirmations: 12,
        history_anchor: policy.history_anchor,
        policy: policy.source_policy,
        effect: SourceEffect::Deposit {
            claimant: claimant.verifying_key().to_bytes(),
            credit_intent: [51; 32],
        },
    };
    let mut claim = FundingClaim {
        domain: policy.domain,
        occurrence,
        claimant: claimant.verifying_key().to_bytes(),
        receiver: policy.receiver,
        value: 34,
        block_policy: policy.source_policy,
        inventory_note: [52; 32],
        evidence_digest: source.digest().unwrap(),
        credit_intent: [51; 32],
        authorization: [0; 64],
    };
    claim.authorization = claimant.sign(&claim.signing_bytes().unwrap()).to_bytes();
    let inventory = InventoryFacts {
        domain: policy.domain,
        provenance: ObservationEnvironment::LocalFixture,
        note: [52; 32],
        occurrence,
        note_commitment: [53; 32],
        nullifier: [54; 32],
        receiver: policy.receiver,
        value: 34,
        scope: policy.inventory_scope,
        control: policy.inventory_producer,
        origin: InventoryOrigin::Deposit,
        condition: InventoryCondition::Spendable,
        history_anchor: policy.history_anchor,
    };
    LedgerCommand::IssueCredit {
        claim,
        source: SignedSourceFacts {
            signature: producers[0]
                .sign(&source.signing_bytes().unwrap())
                .to_bytes(),
            facts: source,
        },
        inventory: SignedInventoryFacts {
            signature: producers[1]
                .sign(&inventory.signing_bytes().unwrap())
                .to_bytes(),
            facts: inventory,
        },
    }
}

#[tokio::test]
async fn three_real_processes_retain_exact_prepared_34_after_lost_ack_and_restart() {
    let files = Files::new();
    let database = Database::new("coordinator").await;
    let replica_databases = [
        Database::new("replica").await,
        Database::new("replica").await,
        Database::new("replica").await,
    ];
    let keys = std::array::from_fn(|_| fixture_key());
    let producers = std::array::from_fn(|_| fixture_key());
    let claimant = fixture_key();
    let policy = policy(&keys, &producers);
    let ledger = Ledger::connect(&database.config).await.unwrap();
    ledger.migrate().await.unwrap();
    ledger.enroll_pair(&policy).await.unwrap();
    let fence = ledger.claim_writer(policy.domain.pair, 0).await.unwrap();
    let paths: [_; 3] = std::array::from_fn(|i| {
        replica_config(
            &files,
            &format!("replica{i}.json"),
            &replica_databases[i],
            &policy,
            policy.roster[i],
        )
    });
    let mut replicas: [_; 3] = std::array::from_fn(|i| Process::launch(&paths[i], &keys[i]));
    assert_ne!(replicas[0].id(), replicas[1].id());
    assert_ne!(replicas[1].id(), replicas[2].id());
    let command = funding(&policy, &producers, &claimant);
    let op = operation(
        &policy,
        fence.generation,
        [51; 32],
        [51; 32],
        0,
        Transition::IssueCredit,
        &command,
    );
    let credit_decision = ledger.prepare_decision(op, command).await.unwrap();
    let bytes = credit_decision.canonical_bytes().unwrap();
    let acks: Vec<_> = replicas
        .iter_mut()
        .map(|replica| JournalAcknowledgement::decode(&replica.request(1, &bytes)).unwrap())
        .collect();
    ledger
        .commit_decision(&credit_decision, &acks)
        .await
        .unwrap();
    let mut command = LedgerCommand::PrepareHold {
        credit: [51; 32],
        amount: 34,
        refund_receiver: [40; 43],
        target: target_binding(&policy, [60; 32], &producers[2]),
        authorization: [0; 64],
    };
    let op = operation(
        &policy,
        fence.generation,
        [60; 32],
        [60; 32],
        0,
        Transition::PrepareHold,
        &command,
    );
    if let LedgerCommand::PrepareHold { authorization, .. } = &mut command {
        *authorization = claimant
            .sign(&op.signing_bytes(SignatureRole::Application).unwrap())
            .to_bytes();
    }
    let decision = ledger.prepare_decision(op, command.clone()).await.unwrap();
    let bytes = decision.canonical_bytes().unwrap();
    let acknowledged: Vec<_> = replicas
        .iter_mut()
        .map(|replica| JournalAcknowledgement::decode(&replica.request(1, &bytes)).unwrap())
        .collect();
    assert_eq!(
        ledger.commit_decision(&decision, &acknowledged[..2]).await,
        Err(LedgerError::MissingUnanimity)
    );
    let before = ledger.snapshot(policy.domain.pair).await.unwrap();
    assert_eq!(
        (before.available_credit, before.prepared, before.sequence),
        (0, 34, 1)
    );
    assert_eq!(before.target_head, [0; 32]);
    replicas[1].kill();
    ledger.close().await;
    replicas[1] = Process::launch(&paths[1], &keys[1]);
    assert_eq!(
        JournalAcknowledgement::decode(&replicas[1].request(1, &bytes)).unwrap(),
        acknowledged[1]
    );
    let reopened = Ledger::connect(&database.config).await.unwrap();
    let challenge = reopened
        .begin_reconciliation(policy.domain.pair)
        .await
        .unwrap();
    let heads: Vec<_> = replicas
        .iter_mut()
        .map(|replica| {
            RetainedHead::decode(&replica.request(2, &challenge.canonical_bytes())).unwrap()
        })
        .collect();
    assert_eq!(
        reopened.reconcile_heads(&challenge, &heads).await.unwrap(),
        RecoveryState::PendingRetained
    );
    assert_eq!(
        reopened.pending_decision(policy.domain.pair).await.unwrap(),
        Some(decision.clone())
    );
    let after = reopened.snapshot(policy.domain.pair).await.unwrap();
    assert_eq!(
        (after.available_credit, after.prepared, after.sequence),
        (0, 34, 1)
    );
    let mut altered = bytes.clone();
    *altered.last_mut().unwrap() ^= 1;
    let rejection = replicas[0].request(1, &altered);
    assert!(rejection.starts_with(b"KERBER01"));
    reopened
        .commit_decision(&decision, &acknowledged)
        .await
        .unwrap();
    assert_eq!(
        reopened
            .snapshot(policy.domain.pair)
            .await
            .unwrap()
            .sequence,
        2
    );
    reopened.close().await;
    for replica in replicas {
        replica.shutdown();
    }
    database.remove().await;
    for database in replica_databases {
        database.remove().await;
    }
}

#[tokio::test]
async fn reconciliation_with_no_external_retained_heads_halts_instead_of_freeing_prepare() {
    let files = Files::new();
    let database = Database::new("missingheads").await;
    let keys = std::array::from_fn(|_| fixture_key());
    let producers = std::array::from_fn(|_| fixture_key());
    let policy = policy(&keys, &producers);
    let ledger = Ledger::connect(&database.config).await.unwrap();
    ledger.migrate().await.unwrap();
    ledger.enroll_pair(&policy).await.unwrap();
    ledger.close().await;
    let config = files.json(
        "coordinator.json",
        &json!({ "schema_version": 1, "database": database.json(),
        "policy": policy.canonical_bytes().unwrap(), "replicas": [] }),
    );
    let result = Command::new(binary())
        .args(["market", "reconcile", "--config"])
        .arg(&config)
        .output()
        .expect("runnable reconciliation CLI required");
    assert!(!result.status.success());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("RecoveryEvidenceMissing")
    );
    database.remove().await;
}

#[tokio::test]
async fn inspection_rejects_same_pair_with_wrong_enrolled_domain_environment_or_roster() {
    let files = Files::new();
    let database = Database::new("wrongpolicy").await;
    let keys = std::array::from_fn(|_| fixture_key());
    let producers = std::array::from_fn(|_| fixture_key());
    let policy = policy(&keys, &producers);
    let ledger = Ledger::connect(&database.config).await.unwrap();
    ledger.migrate().await.unwrap();
    ledger.enroll_pair(&policy).await.unwrap();
    ledger.close().await;
    let mutations: [fn(&mut ziquid_runtime::market::ledger::PairPolicy); 3] = [
        |policy| policy.domain.source_genesis = [42; 32],
        |policy| policy.environment = ziquid_protocol::market::ObservationEnvironment::Network,
        |policy| policy.roster[0] = policy.roster[1],
    ];
    for (i, mutate) in mutations.into_iter().enumerate() {
        let mut changed = policy.clone();
        mutate(&mut changed);
        let config = files.json(&format!("wrong{i}.json"), &json!({ "schema_version": 1,
            "database": database.json(), "policy": changed.canonical_bytes().unwrap(), "replicas": [] }));
        let result = Command::new(binary())
            .args(["market", "inspect-ledger", "--config"])
            .arg(&config)
            .output()
            .unwrap();
        assert!(
            !result.status.success(),
            "same-pair substituted policy must not be accepted"
        );
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("Configuration"));
    }
    database.remove().await;
}
