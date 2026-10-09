#[cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod market_ledger_test_support;
#[path = "market_support/runtime.rs"]
mod support;
use ed25519_dalek::Signer;
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use ziquid_runtime::market::process::ReplicaProcess;
use std::{sync::mpsc, thread, time::Duration};
use support::*;

// Test-only watchdog kills exactly the child we launched, making the unfixed
// blocking read fail safely instead of stranding the test indefinitely.
fn signal(pid: u32, signal: &str) {
    assert!(
        std::process::Command::new("/bin/kill")
            .arg(signal)
            .arg(pid.to_string())
            .status()
            .unwrap()
            .success()
    );
}
async fn within<T>(pid: u32, deadline: Duration, action: impl Future<Output = T>) -> (bool, T) {
    let (cancel, receive) = mpsc::sync_channel(1);
    let watchdog = thread::spawn(move || match receive.recv_timeout(deadline) {
        Err(mpsc::RecvTimeoutError::Timeout) => {
            signal(pid, "-KILL");
            false
        }
        _ => true,
    });
    let result = action.await;
    let _ = cancel.send(());
    (watchdog.join().unwrap(), result)
}
fn run<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}
fn assert_reaped(pid: u32) {
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "owned child must be reaped before returning timeout"
    );
}

#[test]
fn stopped_ready_replica_shutdown_returns_error_and_reaps_before_deadline() {
    run(async {
        let files = Files::new();
        let database = Database::new("stoppedshutdown").await;
        let keys = std::array::from_fn(|_| fixture_key());
        let producers = std::array::from_fn(|_| fixture_key());
        let policy = policy(&keys, &producers);
        let path = replica_config(&files, "replica.json", &database, &policy, policy.roster[0]);
        let mut process = ReplicaProcess::launch(&binary(), &path, &keys[0], &policy)
            .await
            .unwrap();
        let pid = process.id();
        signal(pid, "-STOP");
        let (bounded, result) = within(pid, Duration::from_secs(10), process.shutdown()).await;
        assert_reaped(pid);
        database.remove().await;
        assert!(
            bounded,
            "stop exchange blocked before its advertised shutdown deadline"
        );
        assert!(matches!(result, Err(ziquid_runtime::market::Error::ProcessTimeout)));
    });
}

#[test]
fn stopped_acknowledgement_replica_returns_error_without_releasing_prepared_credit() {
    run(async {
        let files = Files::new();
        let database = Database::new("stoppedack").await;
        let replica_db = Database::new("replica").await;
        let keys = std::array::from_fn(|_| fixture_key());
        let producers = std::array::from_fn(|_| fixture_key());
        let claimant = fixture_key();
        let policy = policy(&keys, &producers);
        let ledger = Ledger::connect(&database.config).await.unwrap();
        ledger.migrate().await.unwrap();
        ledger.enroll_pair(&policy).await.unwrap();
        let fence = ledger.claim_writer(policy.domain.pair, 0).await.unwrap();
        let mut enrollment = Vec::new();
        let local_databases = [
            Database::new("replica").await,
            Database::new("replica").await,
        ];
        let replicas = [
            Replica::connect(&local_databases[0].config)
                .await
                .unwrap(),
            Replica::connect(&local_databases[1].config)
                .await
                .unwrap(),
        ];
        for replica in &replicas {
            replica.migrate().await.unwrap();
            replica.enroll_pair(&policy).await.unwrap();
        }
        let path = replica_config(
            &files,
            "replica.json",
            &replica_db,
            &policy,
            policy.roster[0],
        );
        let mut process = ReplicaProcess::launch(&binary(), &path, &keys[0], &policy)
            .await
            .unwrap();
        let occurrence = SourceOccurrence {
            network: policy.domain.source_network,
            pool: policy.domain.source_pool,
            txid: [50; 32],
            action_index: 0,
        };
        let source = SourceFacts {
            domain: policy.domain,
            provenance: policy.environment,
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
            provenance: policy.environment,
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
        let command = LedgerCommand::IssueCredit {
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
        };
        let make_op = |entity, intent, transition, command: &LedgerCommand| {
            let mut op = Operation {
                domain: policy.domain,
                entity,
                portion: [0; 32],
                intent,
                generation: fence.generation,
                prior_version: 0,
                transition,
                effects: [0; 32],
            };
            op.effects = command.operation_effects(&op).unwrap();
            op
        };
        let credit = ledger
            .prepare_decision(
                make_op([51; 32], [51; 32], Transition::IssueCredit, &command),
                command,
            )
            .await
            .unwrap();
        enrollment.push(process.acknowledge(&credit).await.unwrap());
        for (replica, key) in replicas.iter().zip(&keys[1..]) {
            enrollment.push(replica.acknowledge(&credit, key).await.unwrap());
        }
        ledger.commit_decision(&credit, &enrollment).await.unwrap();
        let mut command = LedgerCommand::PrepareHold {
            credit: [51; 32],
            amount: 34,
            refund_receiver: [40; 43],
            target: target_binding(&policy, [60; 32], &producers[2]),
            authorization: [0; 64],
        };
        let operation = make_op([60; 32], [60; 32], Transition::PrepareHold, &command);
        if let LedgerCommand::PrepareHold { authorization, .. } = &mut command {
            *authorization = claimant
                .sign(&operation.signing_bytes(SignatureRole::Application).unwrap())
                .to_bytes();
        }
        let prepared = ledger.prepare_decision(operation, command).await.unwrap();
        let expected = prepared.clone();
        let pid = process.id();
        signal(pid, "-STOP");
        let (bounded, result) =
            within(pid, Duration::from_secs(35), process.acknowledge(&prepared)).await;
        assert_reaped(pid);
        let state = ledger.snapshot(policy.domain.pair).await.unwrap();
        let pending = ledger.pending_decision(policy.domain.pair).await.unwrap();
        ledger.close().await;
        for replica in replicas {
            replica.close().await;
        }
        database.remove().await;
        replica_db.remove().await;
        for database in local_databases {
            database.remove().await;
        }
        assert!(
            bounded,
            "ready live nonresponder must return an error before watchdog cleanup"
        );
        assert!(matches!(result, Err(ziquid_runtime::market::Error::ProcessTimeout)));
        assert_eq!((state.available_credit, state.prepared), (0, 34));
        assert_eq!(pending, Some(expected));
    });
}
