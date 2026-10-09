//! Operator-rendezvous server restart proof, never part of the default test suite.
//! Run `cargo run -p ziquid-runtime --features postgres-tests --example market_postgres_restart`
//! only after the operator explicitly authorizes schema changes and a server restart.
//! Configure the private URI in Z2Z_TEST_DATABASE_URL, an authorized unique-schema
//! prefix in Z2Z_TEST_PG_SCHEMA_PREFIX, Z2Z_TEST_PG_ALLOW_SCHEMA_CHANGES=yes, and
//! Z2Z_TEST_PG_ALLOW_SERVER_RESTART=yes. No URI is accepted on argv or printed.
//! The selected role also needs pg_read_file access for a real postmaster identity.
//! At READY_FOR_POSTGRES_RESTART every store/connection is closed. The operator,
//! using separately authorized administration, restarts the same server/data state,
//! waits for readiness, then sends exactly `POSTGRES_RESTARTED\n` on stdin.
//! This example never starts, stops or controls a server. Private comparison bytes
//! and generated synthetic business fixture keys remain only in process memory.

#[path = "../tests/market_support/ledger.rs"]
mod support;

use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use sqlx::Connection;
use std::{
    collections::BTreeMap,
    io::{self, Write},
};
use support::{Fixture, TestDatabase};

type PrivateRows = BTreeMap<String, Vec<String>>;

async fn server_identity(db: &TestDatabase) -> (String, i64, String) {
    let mut connection = db.connection().await;
    let identity = sqlx::query_as::<_, (String, i64, String)>(
        "SELECT extract(epoch FROM pg_postmaster_start_time())::text, \
         split_part(pg_read_file('postmaster.pid'), E'\\n', 1)::bigint, \
         current_setting('data_directory')",
    )
    .fetch_one(&mut connection)
    .await
    .expect("cannot inspect owned postmaster identity");
    connection.close().await.unwrap();
    identity
}

// Compare complete rows (including private history/body bytes) without exposing
// them through assertion diagnostics. Ordering does not depend on physical rows.
async fn private_rows(db: &TestDatabase) -> PrivateRows {
    let mut connection = db.connection().await;
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname=$1 \
         AND (tablename LIKE 'ledger\\_%' ESCAPE '\\' \
         OR tablename LIKE 'replica\\_%' ESCAPE '\\') ORDER BY tablename",
    )
    .bind(&db.config.schema)
    .fetch_all(&mut connection)
    .await
    .unwrap();
    let mut retained = BTreeMap::new();
    for table in tables {
        let quoted = table.replace('"', "\"\"");
        let schema = &db.config.schema;
        let rows = sqlx::query_scalar::<_, String>(&format!(
            "SELECT row_to_json(t)::text FROM \"{schema}\".\"{quoted}\" t ORDER BY row_to_json(t)::text"
        ))
        .fetch_all(&mut connection)
        .await
        .unwrap();
        retained.insert(table, rows);
    }
    connection.close().await.unwrap();
    retained
}

async fn journal_body(db: &TestDatabase, decision: &JournalDecision, replica: bool) -> Vec<u8> {
    let mut connection = db.connection().await;
    let query = if replica {
        "SELECT body FROM replica_journal WHERE pair=$1 AND operation=$2"
    } else {
        "SELECT body FROM ledger_journal WHERE pair=$1 AND operation=$2"
    };
    let body = sqlx::query_scalar::<_, Vec<u8>>(query)
        .bind(decision.operation.domain.pair.as_slice())
        .bind(decision.operation.id().unwrap().as_slice())
        .fetch_one(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
    body
}

async fn assert_reservations(f: &Fixture) {
    let mut connection = f.db.connection().await;
    let intact = sqlx::query_scalar::<_, bool>(
        "SELECT \
         (SELECT count(*) FROM ledger_inventory WHERE pair=$1)=1 AND \
         EXISTS(SELECT 1 FROM ledger_inventory WHERE pair=$1 AND note=$2 \
                AND amount=34 AND status=2 AND live_intent=$3) AND \
         EXISTS(SELECT 1 FROM ledger_inventory WHERE pair=$1 AND note=$2 \
                AND source_network=$7 AND source_pool=$8 AND source_genesis=$9 \
                AND txid=$10 AND action_index=0 AND note_commitment=$11 AND nullifier=$12) AND \
         (SELECT count(*) FROM ledger_physical_claims WHERE pair=$1)=2 AND \
         EXISTS(SELECT 1 FROM ledger_physical_claims WHERE pair=$1 AND note=$5 AND change_intent=$3 \
                AND source_network=$7 AND source_pool=$8 AND source_genesis=$9 \
                AND txid=$13 AND action_index=1 AND note_commitment=$14 AND nullifier=$15) AND \
         (SELECT count(*) FROM ledger_intent_records WHERE pair=$1)=1 AND \
         EXISTS(SELECT 1 FROM ledger_intent_states WHERE pair=$1 AND intent=$3 AND status=2) AND \
         (SELECT count(*) FROM ledger_nonce_tombstones WHERE pair=$1)=1 AND \
         EXISTS(SELECT 1 FROM ledger_nonce_tombstones WHERE pair=$1 AND nonce=$4 AND intent=$3) AND \
         (SELECT count(*) FROM ledger_change_reservations WHERE pair=$1)=1 AND \
         EXISTS(SELECT 1 FROM ledger_change_reservations WHERE pair=$1 AND note=$5 AND intent=$3) AND \
         EXISTS(SELECT 1 FROM ledger_portions WHERE pair=$1 AND portion=$6 AND amount=9 AND live_intent=$3) AND \
         NOT EXISTS(SELECT 1 FROM ledger_inventory WHERE pair=$1 AND note=$5) AND \
         NOT EXISTS(SELECT 1 FROM ledger_consumptions WHERE pair=$1) AND \
         NOT EXISTS(SELECT 1 FROM ledger_native_observations WHERE pair=$1)",
    )
    .bind(f.policy.domain.pair.as_slice())
    .bind([52_u8; 32].as_slice())
    .bind([100_u8; 32].as_slice())
    .bind([102_u8; 32].as_slice())
    .bind([101_u8; 32].as_slice())
    .bind([68_u8; 32].as_slice())
    .bind(i16::from(f.policy.domain.source_network))
    .bind(i16::from(f.policy.domain.source_pool))
    .bind(f.policy.domain.source_genesis.as_slice())
    .bind([50_u8; 32].as_slice())
    .bind([53_u8; 32].as_slice())
    .bind([54_u8; 32].as_slice())
    .bind([105_u8; 32].as_slice())
    .bind([106_u8; 32].as_slice())
    .bind([107_u8; 32].as_slice())
    .fetch_one(&mut connection)
    .await
    .unwrap();
    connection.close().await.unwrap();
    assert!(
        intact,
        "Unknown intent lost an exact input/nonce/change/portion reservation"
    );
}

async fn retained_heads(f: &Fixture, challenge: &RecoveryChallenge) -> Vec<RetainedHead> {
    let mut heads = Vec::with_capacity(3);
    for (replica, key) in f.replicas.iter().zip(&f.keys) {
        heads.push(replica.retained_head(challenge, key).await.unwrap());
    }
    heads
}

fn assert_pending_heads(
    heads: &[RetainedHead],
    decision: &JournalDecision,
    snapshot: &PairSnapshot,
    f: &Fixture,
    challenge: &RecoveryChallenge,
) {
    assert_eq!(heads.len(), 3);
    for (index, head) in heads.iter().enumerate() {
        assert!(
            head.domain == f.policy.domain
                && head.pair == f.policy.domain.pair
                && head.signer == f.policy.roster[index]
                && head.head == decision.next_head
                && head.target_head == snapshot.target_head
                && head.sequence == decision.sequence
                && head.generation == decision.operation.generation
                && head.challenge == challenge.nonce,
            "retained replica head is not the exact pending head"
        );
    }
}

async fn close_stores(f: &Fixture) {
    f.ledger.close().await;
    for replica in &f.replicas {
        replica.close().await;
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    assert!(
        std::env::var("Z2Z_TEST_PG_ALLOW_SERVER_RESTART").as_deref() == Ok("yes"),
        "operator must explicitly authorize the separate server-restart rendezvous"
    );
    let mut f = Fixture::new("postgresrestart").await;
    let pair = f.policy.domain.pair;
    let (_, hold, _) = f.active().await;
    let active = f.ledger.snapshot(pair).await.unwrap();
    assert_eq!(
        (
            active.seller_outstanding,
            active.buyer_unused_outstanding,
            active.available_credit
        ),
        (25, 9, 0)
    );

    // Do not use Fixture::apply here: exact operation identities must not be
    // silently rewritten when an entity version advances.
    let (prepare_operation, prepare_command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    let LedgerCommand::PrepareNative(plan) = &prepare_command else {
        unreachable!()
    };
    let plan = plan.clone();
    assert!(
        plan.kind == NativeIntentKind::BuyerRefund
            && plan.amount == 9
            && plan.inputs == vec![[52; 32]]
            && plan.change
                == vec![ChangeOutput {
                    note: [101; 32],
                    action_index: 1,
                    note_commitment: [106; 32],
                    nullifier: [107; 32],
                    receiver: f.policy.receiver,
                    value: 25,
                }],
        "fixture does not describe the exact refund partition"
    );
    let prepared = f
        .ledger
        .prepare_decision(prepare_operation, prepare_command)
        .await
        .unwrap();
    let prepare_acks = f.acknowledge(&prepared).await;
    f.ledger
        .commit_decision(&prepared, &prepare_acks)
        .await
        .unwrap();

    let command = LedgerCommand::NativeUnknown {
        intent: [100; 32],
        transaction: [105; 32],
    };
    let version = f
        .ledger
        .entity_version(pair, [100; 32], [0; 32])
        .await
        .unwrap();
    assert_eq!(version, 1);
    let operation = f.operation(
        [100; 32],
        [0; 32],
        [120; 32],
        version,
        Transition::ObserveNative,
        &command,
    );
    let unknown = f
        .ledger
        .prepare_decision(operation, command.clone())
        .await
        .unwrap();
    let unknown_acks = f.acknowledge(&unknown).await;
    f.ledger
        .commit_decision(&unknown, &unknown_acks)
        .await
        .unwrap();
    let intent = f.ledger.intent(pair, [100; 32]).await.unwrap();
    assert_eq!(intent.state, IntentStatus::Unknown);
    assert_reservations(&f).await;
    let unknown_snapshot = f.ledger.snapshot(pair).await.unwrap();

    // A new immutable operation on the same Unknown intent is legal, but stays
    // pending in the coordinator after all three independent replicas ACK it.
    let version = f
        .ledger
        .entity_version(pair, [100; 32], [0; 32])
        .await
        .unwrap();
    assert_eq!(version, 2);
    let operation = f.operation(
        [100; 32],
        [0; 32],
        [121; 32],
        version,
        Transition::ObserveNative,
        &command,
    );
    assert!(operation.id().unwrap() != unknown.operation.id().unwrap());
    let pending = f.ledger.prepare_decision(operation, command).await.unwrap();
    let pending_bytes = pending.canonical_bytes().unwrap();
    let immutable_acks = f.acknowledge(&pending).await;
    assert_eq!(immutable_acks.len(), 3);
    assert!(
        journal_body(&f.db, &pending, false).await == pending_bytes,
        "coordinator changed pending bytes"
    );
    for db in &f.replica_dbs {
        assert!(
            journal_body(db, &pending, true).await == pending_bytes,
            "replica changed pending bytes"
        );
    }

    let snapshot = f.ledger.snapshot(pair).await.unwrap();
    assert!(
        snapshot == unknown_snapshot,
        "preparing pending Unknown changed backing or committed heads"
    );
    assert!(snapshot.head == pending.predecessor && snapshot.sequence + 1 == pending.sequence);
    assert_eq!(
        (
            snapshot.locked_inventory,
            snapshot.seller_outstanding,
            snapshot.buyer_unused_outstanding
        ),
        (34, 25, 9)
    );
    assert!(f.ledger.pending_decision(pair).await.unwrap() == Some(pending.clone()));
    let before_challenge = f.ledger.begin_reconciliation(pair).await.unwrap();
    let before_heads = retained_heads(&f, &before_challenge).await;
    assert_pending_heads(&before_heads, &pending, &snapshot, &f, &before_challenge);
    assert_eq!(
        f.ledger
            .reconcile_heads(&before_challenge, &before_heads)
            .await
            .unwrap(),
        RecoveryState::PendingRetained
    );
    let before_rows = private_rows(&f.db).await;
    let mut before_replica_rows = Vec::with_capacity(3);
    for db in &f.replica_dbs {
        before_replica_rows.push(private_rows(db).await);
    }
    let before_identity = server_identity(&f.db).await;
    close_stores(&f).await;

    println!(
        "READY_FOR_POSTGRES_RESTART harness_pid={} postmaster_pid={} coordinator_sequence={} retained_sequence={} replicas=3 locked_inventory=34 intents=1 nonce_tombstones=1 change_reservations=1",
        std::process::id(),
        before_identity.1,
        snapshot.sequence,
        pending.sequence
    );
    io::stdout().flush().unwrap();
    let mut line = String::new();
    assert!(
        io::stdin().read_line(&mut line).unwrap() > 0,
        "restart barrier reached EOF"
    );
    assert_eq!(
        line.trim_end_matches(['\r', '\n']),
        "POSTGRES_RESTARTED",
        "restart barrier requires the explicit continuation line"
    );

    let after_identity = server_identity(&f.db).await;
    let genuinely_restarted =
        before_identity.0 != after_identity.0 || before_identity.1 != after_identity.1;
    let same_data_directory = before_identity.2 == after_identity.2;
    if !genuinely_restarted || !same_data_directory {
        f.remove().await;
        panic!("postmaster did not genuinely restart in the same owned data directory");
    }
    f.ledger = Ledger::connect(&f.db.config).await.unwrap();
    f.replicas = [
        Replica::connect(&f.replica_dbs[0].config)
            .await
            .unwrap(),
        Replica::connect(&f.replica_dbs[1].config)
            .await
            .unwrap(),
        Replica::connect(&f.replica_dbs[2].config)
            .await
            .unwrap(),
    ];

    assert!(
        f.ledger.snapshot(pair).await.unwrap() == snapshot,
        "full coordinator snapshot changed across restart"
    );
    assert!(
        private_rows(&f.db).await == before_rows,
        "coordinator exact rows changed across restart"
    );
    for (index, db) in f.replica_dbs.iter().enumerate() {
        assert!(
            private_rows(db).await == before_replica_rows[index],
            "replica exact rows changed across restart"
        );
        assert!(
            journal_body(db, &pending, true).await == pending_bytes,
            "replica pending bytes changed across restart"
        );
    }
    let stored = f
        .ledger
        .pending_decision(pair)
        .await
        .unwrap()
        .expect("pending decision was lost");
    assert!(
        stored == pending && stored.canonical_bytes().unwrap() == pending_bytes,
        "immutable pending decision changed across restart"
    );
    assert!(
        journal_body(&f.db, &stored, false).await == pending_bytes,
        "stored coordinator pending bytes changed"
    );
    assert!(
        f.ledger.intent(pair, [100; 32]).await.unwrap() == intent,
        "Unknown intent changed across restart"
    );
    assert!(
        f.ledger.native_plan(pair, [100; 32]).await.unwrap() == plan,
        "exact native plan changed across restart"
    );
    assert_reservations(&f).await;

    assert!(
        matches!(
            f.ledger
                .prepare_decision(stored.operation, stored.command.clone())
                .await,
            Err(LedgerError::RecoveryEvidenceMissing)
        ),
        "reopened coordinator preparation was not fenced"
    );
    assert!(
        matches!(
            f.ledger.commit_decision(&stored, &immutable_acks).await,
            Err(LedgerError::RecoveryEvidenceMissing)
        ),
        "reopened coordinator commit was not fenced"
    );
    assert!(
        private_rows(&f.db).await == before_rows,
        "fenced mutation changed retained state"
    );
    let challenge = f.ledger.begin_reconciliation(pair).await.unwrap();
    assert!(
        challenge.nonce != before_challenge.nonce,
        "recovery challenge was reused"
    );
    let heads = retained_heads(&f, &challenge).await;
    assert_pending_heads(&heads, &stored, &snapshot, &f, &challenge);
    for (before, after) in before_heads.iter().zip(&heads) {
        assert!(
            before.domain == after.domain
                && before.pair == after.pair
                && before.signer == after.signer
                && before.head == after.head
                && before.target_head == after.target_head
                && before.sequence == after.sequence
                && before.generation == after.generation,
            "retained head changed across restart"
        );
    }
    // This validates all three signatures against the fresh challenge and the
    // exact retained pending head; no parent-supplied assertion is trusted.
    assert_eq!(
        f.ledger.reconcile_heads(&challenge, &heads).await.unwrap(),
        RecoveryState::PendingRetained
    );
    f.ledger
        .commit_decision(&stored, &immutable_acks)
        .await
        .unwrap();

    let mut expected_snapshot = snapshot.clone();
    expected_snapshot.head = stored.next_head;
    expected_snapshot.sequence = stored.sequence;
    assert!(
        f.ledger.snapshot(pair).await.unwrap() == expected_snapshot,
        "commit changed economic backing or target/writer generation"
    );
    assert!(f.ledger.pending_decision(pair).await.unwrap().is_none());
    assert!(
        f.ledger.intent(pair, [100; 32]).await.unwrap() == intent,
        "recovery changed Unknown status or nonce"
    );
    assert!(
        f.ledger.native_plan(pair, [100; 32]).await.unwrap() == plan,
        "recovery changed exact native plan"
    );
    assert_reservations(&f).await;
    let committed_rows = private_rows(&f.db).await;
    for (table, rows) in &before_rows {
        if !matches!(
            table.as_str(),
            "ledger_pairs" | "ledger_versions" | "ledger_commits"
        ) {
            assert!(
                committed_rows.get(table) == Some(rows),
                "commit changed non-journal bookkeeping/history/backing"
            );
        }
    }
    assert_eq!(
        f.ledger
            .entity_version(pair, [100; 32], [0; 32])
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        committed_rows["ledger_commits"].len(),
        before_rows["ledger_commits"].len() + 1
    );
    let current_challenge = f.ledger.begin_reconciliation(pair).await.unwrap();
    let current_heads = retained_heads(&f, &current_challenge).await;
    assert_pending_heads(&current_heads, &stored, &snapshot, &f, &current_challenge);
    assert_eq!(
        f.ledger
            .reconcile_heads(&current_challenge, &current_heads)
            .await
            .unwrap(),
        RecoveryState::Current
    );
    f.ledger
        .commit_decision(&stored, &immutable_acks)
        .await
        .unwrap();
    assert!(
        private_rows(&f.db).await == committed_rows,
        "exact commit replay was not idempotent"
    );
    for (index, db) in f.replica_dbs.iter().enumerate() {
        assert!(
            private_rows(db).await == before_replica_rows[index],
            "recovery/replay changed replica rows"
        );
    }
    f.remove().await;
    println!(
        "POSTGRES_RESTART_PROOF_PASSED postmaster_pid_before={} postmaster_pid_after={} sequence={} replicas=3 locked_inventory=34 intents=1 nonce_tombstones=1 change_reservations=1 unknown=1 schemas_removed=4",
        before_identity.1, after_identity.1, stored.sequence
    );
}
