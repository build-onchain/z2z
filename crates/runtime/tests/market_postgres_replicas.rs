#![cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod support;
use ed25519_dalek::Signer;
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use sqlx::{Connection, Executor};
use support::*;

// Two keys or duplicate/mutated signatures must never apply business state.
#[tokio::test]
async fn requires_three_distinct_exact_durable_acknowledgements() {
    let f = Fixture::new("unanimity").await;
    let credit = f.issue(34, 50).await;
    let (operation, command) = f.prepare(credit, [60; 32], 34);
    let decision = f.ledger.prepare_decision(operation, command).await.unwrap();
    let acknowledgements = f.acknowledge(&decision).await;
    assert_eq!(
        f.ledger
            .commit_decision(&decision, &acknowledgements[..2])
            .await,
        Err(LedgerError::MissingUnanimity)
    );
    let duplicate = [
        acknowledgements[0].clone(),
        acknowledgements[0].clone(),
        acknowledgements[2].clone(),
    ];
    assert_eq!(
        f.ledger.commit_decision(&decision, &duplicate).await,
        Err(LedgerError::MissingUnanimity)
    );
    let mut corrupt = acknowledgements.clone();
    corrupt[1].signature[0] ^= 1;
    assert_eq!(
        f.ledger.commit_decision(&decision, &corrupt).await,
        Err(LedgerError::MissingUnanimity)
    );
    let before = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!((before.prepared, before.sequence), (34, 1));
    f.ledger
        .commit_decision(&decision, &acknowledgements)
        .await
        .unwrap();
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .sequence,
        2
    );
    // Replays are identical after storage, not another journal append.
    f.ledger
        .commit_decision(&decision, &acknowledgements)
        .await
        .unwrap();
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .sequence,
        2
    );
    for (replica, key) in f.replicas.iter().zip(&f.keys) {
        let challenge = f
            .ledger
            .begin_reconciliation(f.policy.domain.pair)
            .await
            .unwrap();
        let retained = replica.retained_head(&challenge, key).await.unwrap();
        assert_eq!((retained.head, retained.sequence), (decision.next_head, 2));
    }
    f.remove().await;
}

// Stored predecessor and effects survive process restart; changed bytes cannot re-sign.
#[tokio::test]
async fn replica_persists_before_signing_and_rejects_equivocation_stale_head_and_writer() {
    let f = Fixture::new("replicastore").await;
    let credit = f.issue(34, 50).await;
    let (operation, command) = f.prepare(credit, [60; 32], 34);
    let decision = f.ledger.prepare_decision(operation, command).await.unwrap();
    let original = f.replicas[0]
        .acknowledge(&decision, &f.keys[0])
        .await
        .unwrap();
    f.replicas[0].close().await;
    let reopened = Replica::connect(&f.replica_dbs[0].config)
        .await
        .unwrap();
    assert_eq!(
        reopened.acknowledge(&decision, &f.keys[0]).await.unwrap(),
        original
    );
    let mut changed = decision.clone();
    if let LedgerCommand::PrepareHold {
        refund_receiver, ..
    } = &mut changed.command
    {
        *refund_receiver = [41; 43];
    }
    assert_eq!(
        reopened.acknowledge(&changed, &f.keys[0]).await,
        Err(LedgerError::Conflict)
    );
    let mut predecessor = decision.clone();
    predecessor.predecessor = [199; 32];
    assert!(matches!(
        reopened.acknowledge(&predecessor, &f.keys[0]).await,
        Err(LedgerError::Conflict | LedgerError::HeadMismatch)
    ));
    let mut stale = decision.clone();
    stale.operation.generation = 0;
    assert!(matches!(
        reopened.acknowledge(&stale, &f.keys[0]).await,
        Err(LedgerError::Conflict | LedgerError::StaleWriter | LedgerError::Protocol)
    ));
    let challenge = f
        .ledger
        .begin_reconciliation(f.policy.domain.pair)
        .await
        .unwrap();
    let retained = reopened
        .retained_head(&challenge, &f.keys[0])
        .await
        .unwrap();
    assert_eq!((retained.head, retained.sequence), (decision.next_head, 2));
    reopened.close().await;
    f.remove().await;
}

// Host journal and observed Solana decision heads are distinct namespaces.
#[tokio::test]
async fn host_events_do_not_advance_target_head_and_target_events_require_both_ack_roles() {
    let f = Fixture::new("heads").await;
    let (_, hold) = f.held().await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_ne!(snapshot.head, [0; 32]);
    let predecessor = snapshot.target_head;
    let mut auth = f.authorization(
        (hold, [0; 32]),
        Transition::CommitEpoch,
        3,
        [62; 32],
        [64; 32].to_vec(),
        predecessor,
    );
    auth.decision.operation.generation = snapshot.target_generation.checked_add(1).unwrap();
    auth.decision = Decision::new(auth.decision.operation, predecessor).unwrap();
    let expected_target = auth.decision;
    let command = LedgerCommand::AuthorizeTarget(auth);
    let operation = f.operation(
        hold,
        [0; 32],
        [63; 32],
        1,
        Transition::PrepareFill,
        &command,
    );
    let decision = f.ledger.prepare_decision(operation, command).await.unwrap();
    assert_eq!(decision.target, Some(expected_target));
    let acknowledgements = f.acknowledge(&decision).await;
    let mut journal_only = acknowledgements.clone();
    for ack in &mut journal_only {
        ack.target = None;
    }
    assert_eq!(
        f.ledger.commit_decision(&decision, &journal_only).await,
        Err(LedgerError::MissingUnanimity)
    );
    let mut wrong_target = acknowledgements.clone();
    let wrong = Decision::new(expected_target.operation, [200; 32]).unwrap();
    wrong_target[0].target = Some(Acknowledgement {
        signer: f.keys[0].verifying_key().to_bytes(),
        signature: f.keys[0].sign(&wrong.signing_bytes().unwrap()).to_bytes(),
        decision: wrong,
    });
    assert_eq!(
        f.ledger.commit_decision(&decision, &wrong_target).await,
        Err(LedgerError::MissingUnanimity)
    );
    f.ledger
        .commit_decision(&decision, &acknowledgements)
        .await
        .unwrap();
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(snapshot.target_head, predecessor);
    assert_ne!(snapshot.head, snapshot.target_head);
    assert_eq!((snapshot.prepared, snapshot.encumbered), (34, 0));
    let command = LedgerCommand::ObserveEpoch {
        target: f.observed(expected_target),
    };
    let op = f.operation(
        expected_target.operation.entity,
        [0; 32],
        [64; 32],
        2,
        Transition::CommitEpoch,
        &command,
    );
    f.apply(op, command).await;
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .target_head,
        expected_target.next_head
    );
    f.remove().await;
}

// An old coordinator clone cannot reopen while independent stores retain a newer head.
#[tokio::test]
async fn externally_retained_heads_detect_restored_old_coordinator_database() {
    let f = Fixture::new("restore").await;
    f.ledger.close().await;
    let old = f.db.fork("oldcoordinator").await;
    let coordinator = Ledger::connect(&f.db.config).await.unwrap();
    assert_eq!(f.reconcile(&coordinator).await, RecoveryState::Current);
    let command = f.funding(34, 50);
    let operation = f.operation(
        [51; 32],
        [0; 32],
        [51; 32],
        0,
        Transition::IssueCredit,
        &command,
    );
    let decision = coordinator
        .prepare_decision(operation, command)
        .await
        .unwrap();
    let acknowledgements = f.acknowledge(&decision).await;
    coordinator
        .commit_decision(&decision, &acknowledgements)
        .await
        .unwrap();
    let restored = Ledger::connect(&old.config).await.unwrap();
    let challenge = restored
        .begin_reconciliation(f.policy.domain.pair)
        .await
        .unwrap();
    let mut retained = Vec::new();
    for (replica, key) in f.replicas.iter().zip(&f.keys) {
        retained.push(replica.retained_head(&challenge, key).await.unwrap());
    }
    assert_eq!(
        restored.reconcile_heads(&challenge, &retained).await,
        Err(LedgerError::RollbackDetected)
    );
    let (op, command) = f.prepare([51; 32], [60; 32], 34);
    assert_eq!(
        restored.prepare_decision(op, command).await,
        Err(LedgerError::RollbackDetected)
    );
    assert_eq!(
        restored
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .available_credit,
        0
    );
    restored.close().await;
    old.remove().await;
    coordinator.close().await;
    f.remove().await;
}

// Self-contained hash chains cannot prove freshness when all retained heads are lost.
#[tokio::test]
async fn all_head_loss_duplicate_retention_and_replayed_challenges_halt() {
    let f = Fixture::new("headloss").await;
    f.issue(34, 50).await;
    let challenge = f
        .ledger
        .begin_reconciliation(f.policy.domain.pair)
        .await
        .unwrap();
    assert_eq!(
        f.ledger.reconcile_heads(&challenge, &[]).await,
        Err(LedgerError::RecoveryEvidenceMissing)
    );
    let (op, command) = f.prepare([51; 32], [60; 32], 34);
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::RecoveryEvidenceMissing)
    );
    let mut heads = Vec::new();
    for (replica, key) in f.replicas.iter().zip(&f.keys) {
        heads.push(replica.retained_head(&challenge, key).await.unwrap());
    }
    assert_eq!(
        f.ledger
            .reconcile_heads(
                &challenge,
                &[heads[0].clone(), heads[0].clone(), heads[2].clone()]
            )
            .await,
        Err(LedgerError::RecoveryEvidenceMissing)
    );
    let fresh = f
        .ledger
        .begin_reconciliation(f.policy.domain.pair)
        .await
        .unwrap();
    assert_eq!(
        f.ledger.reconcile_heads(&fresh, &heads).await,
        Err(LedgerError::RecoveryEvidenceMissing)
    );
    let mut current = Vec::new();
    for (replica, key) in f.replicas.iter().zip(&f.keys) {
        current.push(replica.retained_head(&fresh, key).await.unwrap());
    }
    assert_eq!(
        f.ledger.reconcile_heads(&fresh, &current).await.unwrap(),
        RecoveryState::Current
    );
    f.remove().await;
}

// A crash after acknowledgements must retain exact pending bytes and its reservations.
#[tokio::test]
async fn retained_pending_decision_recovers_without_releasing_held_credit() {
    let f = Fixture::new("pendingrecovery").await;
    let credit = f.issue(34, 50).await;
    let (operation, command) = f.prepare(credit, [60; 32], 34);
    let decision = f.ledger.prepare_decision(operation, command).await.unwrap();
    let acknowledgements = f.acknowledge(&decision).await;
    f.ledger.close().await;
    let recovered = Ledger::connect(&f.db.config).await.unwrap();
    let challenge = recovered
        .begin_reconciliation(f.policy.domain.pair)
        .await
        .unwrap();
    let mut retained = Vec::new();
    for (replica, key) in f.replicas.iter().zip(&f.keys) {
        retained.push(replica.retained_head(&challenge, key).await.unwrap());
    }
    assert_eq!(
        recovered
            .reconcile_heads(&challenge, &retained)
            .await
            .unwrap(),
        RecoveryState::PendingRetained
    );
    assert_eq!(
        recovered
            .pending_decision(f.policy.domain.pair)
            .await
            .unwrap(),
        Some(decision.clone())
    );
    assert_eq!(
        recovered
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .prepared,
        34
    );
    recovered
        .commit_decision(&decision, &acknowledgements)
        .await
        .unwrap();
    assert_eq!(
        recovered
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .prepared,
        34
    );
    recovered.close().await;
    f.remove().await;
}

// Database-level append-only constraints block mutation or deletion of intent history.
#[tokio::test]
async fn native_intent_nonce_and_journal_are_durable_append_only_before_export() {
    let f = Fixture::new("tombstones").await;
    let (_, hold, _) = f.active().await;
    let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    let decision = f.ledger.prepare_decision(operation, command).await.unwrap();
    let intent = f
        .ledger
        .intent(f.policy.domain.pair, [100; 32])
        .await
        .unwrap();
    assert_eq!(
        (intent.state, intent.nonce),
        (IntentStatus::Prepared, [102; 32])
    );
    let mut sql = f.db.connection().await;
    for statement in [
        "DELETE FROM ledger_journal",
        "UPDATE ledger_journal SET body = '\\x00'::bytea",
        "DELETE FROM ledger_nonce_tombstones",
        "DELETE FROM ledger_intent_records",
    ] {
        assert!(
            sql.execute(statement).await.is_err(),
            "append-only history allowed {statement}"
        );
    }
    sql.close().await.unwrap();
    let acknowledgements = f.acknowledge(&decision).await;
    f.ledger
        .commit_decision(&decision, &acknowledgements)
        .await
        .unwrap();
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .locked_inventory,
        34
    );
    f.remove().await;
}

// One exact native Operation remains portable, while private signatures bind all PCZT metadata.
#[tokio::test]
async fn native_operation_matches_portable_intent_and_full_plan_bytes_cannot_equivocate() {
    let f = Fixture::new("nativebinding").await;
    let (_, hold, _) = f.active().await;
    let (mut operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    let LedgerCommand::PrepareNative(plan) = &command else {
        unreachable!()
    };
    let native = NativeIntent {
        operation,
        kind: plan.kind,
        recipient: plan.recipient,
        amount: plan.amount,
        inventory_scope: plan.inventory_scope,
    };
    operation.effects = native.effects_digest().unwrap();
    let decision = f
        .ledger
        .prepare_decision(operation, command.clone())
        .await
        .unwrap();
    assert_eq!(decision.operation, operation);
    let acknowledgements = f.acknowledge(&decision).await;
    let mut altered = command;
    if let LedgerCommand::PrepareNative(plan) = &mut altered {
        plan.pczt_digest = [201; 32];
    }
    assert_eq!(
        f.ledger.prepare_decision(operation, altered.clone()).await,
        Err(LedgerError::Conflict)
    );
    let mut equivocation = decision.clone();
    equivocation.command = altered;
    assert_eq!(
        f.replicas[0].acknowledge(&equivocation, &f.keys[0]).await,
        Err(LedgerError::Conflict)
    );
    assert_eq!(
        f.ledger
            .commit_decision(&equivocation, &acknowledgements)
            .await,
        Err(LedgerError::Conflict)
    );
    f.ledger
        .commit_decision(&decision, &acknowledgements)
        .await
        .unwrap();
    assert_eq!(
        f.ledger
            .native_plan(f.policy.domain.pair, [100; 32])
            .await
            .unwrap()
            .pczt_digest,
        [103; 32]
    );
    f.remove().await;
}

// Canonical bytes and three signing keys do not authorize a forged economic promise.
#[tokio::test]
async fn each_replica_independently_rejects_oversized_or_wrong_claimant_preparation() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new("replicapolicy").await;
    let credit = f.issue(34, 50).await;
    let (mut operation, mut command) = f.prepare(credit, [60; 32], 35);
    operation.effects = command.operation_effects(&operation).unwrap();
    if let LedgerCommand::PrepareHold { authorization, .. } = &mut command {
        *authorization = f
            .claimant
            .sign(&operation.signing_bytes(SignatureRole::Application).unwrap())
            .to_bytes();
    }
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let mut body = b"KERBJH02".to_vec();
    let mut encoded = [0; OPERATION_LEN];
    operation.encode_into(&mut encoded).unwrap();
    body.extend_from_slice(&encoded);
    body.extend_from_slice(&snapshot.head);
    body.extend_from_slice(&2_u64.to_le_bytes());
    let encoded_command = command.canonical_bytes().unwrap();
    body.extend_from_slice(&(encoded_command.len() as u32).to_le_bytes());
    body.extend_from_slice(&encoded_command);
    body.push(0);
    let next_head: Id = Sha256::digest(&body).into();
    body.extend_from_slice(&next_head);
    let decision = JournalDecision::decode(&body).unwrap();
    for (replica, key) in f.replicas.iter().zip(&f.keys) {
        assert_eq!(
            replica.acknowledge(&decision, key).await,
            Err(LedgerError::InsufficientCredit)
        );
    }
    let challenge = f
        .ledger
        .begin_reconciliation(f.policy.domain.pair)
        .await
        .unwrap();
    for (replica, key) in f.replicas.iter().zip(&f.keys) {
        assert_eq!(
            replica
                .retained_head(&challenge, key)
                .await
                .unwrap()
                .sequence,
            1
        );
    }
    f.reconcile(&f.ledger).await;
    f.remove().await;
}
