#![cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod support;
use ed25519_dalek::Signer;
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::{
    ObservationEnvironment, SOURCE_NETWORK_TESTNET, SOURCE_POOL_IRONWOOD, SourceOccurrence,
    Transition,
};
use support::*;

// A pair's claimant inventory must be the portable native pair scope, not an alias.
#[tokio::test]
async fn pair_enrollment_rejects_native_inventory_scope_alias() {
    let f = Fixture::new("scoperule").await;
    let database = TestDatabase::create("scopealias").await;
    let ledger = Ledger::connect(&database.config).await.unwrap();
    ledger.migrate().await.unwrap();
    let mut policy = f.policy.clone();
    policy.inventory_scope = [230; 32];
    assert_eq!(
        ledger.enroll_pair(&policy).await,
        Err(LedgerError::InvalidPolicy)
    );
    ledger.close().await;
    database.remove().await;
    f.remove().await;
}

// Even identical pair IDs/keys/challenges at an empty head cannot cross deployments.
#[tokio::test]
async fn retained_head_rejects_same_pair_and_keys_from_another_deployment() {
    let f = Fixture::new("headcontext").await;
    let database = TestDatabase::create("wrongcontext").await;
    let replica = Replica::connect(&database.config).await.unwrap();
    replica.migrate().await.unwrap();
    let mut policy = f.policy.clone();
    policy.domain.deployment = [231; 32];
    policy.domain.solana_genesis = [232; 32];
    replica.enroll_pair(&policy).await.unwrap();
    let challenge = f
        .ledger
        .begin_reconciliation(f.policy.domain.pair)
        .await
        .unwrap();
    let mut heads = Vec::new();
    heads.push(replica.retained_head(&challenge, &f.keys[0]).await.unwrap());
    for (replica, key) in f.replicas[1..].iter().zip(&f.keys[1..]) {
        heads.push(replica.retained_head(&challenge, key).await.unwrap());
    }
    assert_eq!(
        f.ledger.reconcile_heads(&challenge, &heads).await,
        Err(LedgerError::RecoveryEvidenceMissing)
    );
    replica.close().await;
    database.remove().await;
    f.remove().await;
}

// Sponsor inputs pay the actual fee; claimant34 remains recipient9+change25 exactly.
#[tokio::test]
async fn native_fee_consumes_only_separate_sponsor_inputs() {
    let f = Fixture::new("feesponsor").await;
    let (_, hold, _) = f.active().await;
    let facts = InventoryFacts {
        domain: f.policy.domain,
        provenance: ObservationEnvironment::LocalFixture,
        note: [150; 32],
        occurrence: SourceOccurrence {
            network: SOURCE_NETWORK_TESTNET,
            pool: SOURCE_POOL_IRONWOOD,
            txid: [151; 32],
            action_index: 0,
        },
        note_commitment: [152; 32],
        nullifier: [153; 32],
        receiver: f.policy.receiver,
        value: 10_000,
        scope: f.policy.sponsor_scope,
        control: f.policy.inventory_producer,
        origin: InventoryOrigin::Sponsor,
        condition: InventoryCondition::Spendable,
        history_anchor: f.policy.history_anchor,
    };
    let command = LedgerCommand::RegisterSponsor {
        inventory: SignedInventoryFacts {
            signature: f
                .inventory_key
                .sign(&facts.signing_bytes().unwrap())
                .to_bytes(),
            facts,
        },
    };
    let operation = f.operation(
        [150; 32],
        [0; 32],
        [152; 32],
        0,
        Transition::ReserveInputs,
        &command,
    );
    f.apply(operation, command).await;
    let (_, mut wrong) = f.refund(hold, [68; 32], [52; 32], 100).await;
    if let LedgerCommand::PrepareNative(plan) = &mut wrong {
        plan.fee = 1;
        plan.change[0].value = 24;
    }
    let operation = f.operation(
        hold,
        [68; 32],
        [100; 32],
        0,
        Transition::PrepareNative,
        &wrong,
    );
    assert_eq!(
        f.ledger.prepare_decision(operation, wrong).await,
        Err(LedgerError::InvalidEvidence)
    );
    let (_, mut wrong_scope) = f.refund(hold, [68; 32], [52; 32], 100).await;
    if let LedgerCommand::PrepareNative(plan) = &mut wrong_scope {
        plan.fee = 34;
        plan.fee_inputs = vec![[52; 32]];
    }
    let operation = f.operation(
        hold,
        [68; 32],
        [100; 32],
        0,
        Transition::PrepareNative,
        &wrong_scope,
    );
    assert_eq!(
        f.ledger.prepare_decision(operation, wrong_scope).await,
        Err(LedgerError::InventoryUnavailable)
    );
    let (_, mut command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    if let LedgerCommand::PrepareNative(plan) = &mut command {
        plan.fee = 10_000;
        plan.fee_inputs = vec![[150; 32]];
    }
    let operation = f.operation(
        hold,
        [68; 32],
        [100; 32],
        0,
        Transition::PrepareNative,
        &command,
    );
    f.apply(operation, command).await;
    let plan = f
        .ledger
        .native_plan(f.policy.domain.pair, [100; 32])
        .await
        .unwrap();
    assert_eq!(
        (plan.amount, plan.change[0].value, plan.fee),
        (9, 25, 10_000)
    );
    assert_eq!(plan.fee_inputs, vec![[150; 32]]);
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (snapshot.locked_inventory, snapshot.sponsor_inventory),
        (34, 0)
    );
    assert_eq!(
        (
            snapshot.seller_outstanding,
            snapshot.buyer_unused_outstanding,
            snapshot.available_credit
        ),
        (25, 9, 0)
    );
    let facts = NativeFacts {
        domain: f.policy.domain,
        provenance: ObservationEnvironment::LocalFixture,
        intent: [100; 32],
        transaction: [105; 32],
        inputs: vec![[52; 32], [150; 32]],
        recipient: [40; 43],
        amount: 9,
        change: vec![ChangeOutput {
            note: [101; 32],
            action_index: 1,
            note_commitment: [106; 32],
            nullifier: [107; 32],
            receiver: f.policy.receiver,
            value: 25,
        }],
        block: [153; 32],
        height: 200,
        confirmations: 12,
        history_anchor: f.policy.history_anchor,
    };
    let command = LedgerCommand::ObserveNative(SignedNativeFacts {
        signature: f
            .inventory_key
            .sign(&facts.signing_bytes().unwrap())
            .to_bytes(),
        facts,
    });
    let operation = f.operation(
        [100; 32],
        [0; 32],
        [154; 32],
        1,
        Transition::ObserveNative,
        &command,
    );
    f.apply(operation, command).await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.usable_inventory,
            snapshot.sponsor_inventory,
            snapshot.final_refund,
            snapshot.seller_outstanding
        ),
        (25, 0, 9, 25)
    );
    f.remove().await;
}

#[tokio::test]
async fn missing_schema_requires_explicit_migrate_and_concurrent_initializers_keep_original_history() {
    use sha2::{Digest, Sha384};
    use sqlx::Connection;
    let db = TestDatabase::create("schemafresh").await;
    let first = Ledger::connect(&db.config).await.unwrap();
    let second = Ledger::connect(&db.config).await.unwrap();
    assert_eq!(first.entity_version(domain().pair,[1;32],[0;32]).await, Err(LedgerError::Database));
    let mut connection = db.connection().await;
    assert!(!sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=$1)")
        .bind(&db.config.schema).fetch_one(&mut connection).await.unwrap());
    let (a,b) = tokio::join!(first.migrate(),second.migrate());
    a.unwrap(); b.unwrap();
    let rows = sqlx::query_as::<_,(i64,Vec<u8>,bool)>(&format!("SELECT version,checksum,success FROM {}._sqlx_migrations ORDER BY version",db.config.schema))
        .fetch_all(&mut connection).await.unwrap();
    let scripts = [
        include_str!("../migrations/market/0001_safety.sql"), include_str!("../migrations/market/0002_target_authorizations.sql"),
        include_str!("../migrations/market/0003_target_state.sql"), include_str!("../migrations/market/0004_native_conflicts.sql"),
        include_str!("../migrations/market/0005_target_lifecycle.sql"), include_str!("../migrations/market/0006_shared_epoch.sql"),
        include_str!("../migrations/market/0007_shared_allocation_result.sql"), include_str!("../migrations/market/0008_physical_inventory.sql"),
    ];
    assert_eq!(rows.len(),8);
    for (index,((version,checksum,success),script)) in rows.iter().zip(scripts).enumerate() {
        assert_eq!(*version,index as i64+1); assert!(*success);
        assert_eq!(checksum.as_slice(),Sha384::digest(script.as_bytes()).as_slice());
    }
    connection.close().await.unwrap(); first.close().await; second.close().await; db.remove().await;
}

#[tokio::test]
async fn empty_foreign_and_partial_schemas_are_rejected_without_mutation_or_cleanup_adoption() {
    use sqlx::Connection;
    for partial in [false,true] {
        let db = TestDatabase::create("foreignschema").await;
        let ledger = Ledger::connect(&db.config).await.unwrap();
        let mut connection = db.connection().await;
        sqlx::raw_sql(&format!("CREATE SCHEMA {}",db.config.schema)).execute(&mut connection).await.unwrap();
        if partial {
            sqlx::raw_sql(&format!("CREATE TABLE {}.ledger_pairs(sentinel TEXT); INSERT INTO {}.ledger_pairs VALUES('retained foreign data')",db.config.schema,db.config.schema))
                .execute(&mut connection).await.unwrap();
        }
        let before = sqlx::query_scalar::<_,String>("SELECT c.relname::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 ORDER BY c.relname")
            .bind(&db.config.schema).fetch_all(&mut connection).await.unwrap();
        assert!(matches!(Ledger::connect(&db.config).await,Err(LedgerError::Database)));
        assert_eq!(ledger.migrate().await,Err(LedgerError::Database));
        assert!(ziquid_runtime::database::test_drop_schema(&db.config).await.is_err());
        let after = sqlx::query_scalar::<_,String>("SELECT c.relname::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 ORDER BY c.relname")
            .bind(&db.config.schema).fetch_all(&mut connection).await.unwrap();
        assert_eq!(before,after);
        if partial {
            assert_eq!(sqlx::query_scalar::<_,String>(&format!("SELECT sentinel FROM {}.ledger_pairs",db.config.schema)).fetch_one(&mut connection).await.unwrap(),"retained foreign data");
        }
        ledger.close().await;
        // Only this exact successful CREATE's connection may clean a foreign fixture.
        sqlx::raw_sql(&format!("DROP SCHEMA {} CASCADE",db.config.schema)).execute(&mut connection).await.unwrap();
        connection.close().await.unwrap();
    }
}

#[tokio::test]
async fn missing_application_relation_cannot_fall_back_to_another_schema() {
    use sqlx::Connection;
    let db = TestDatabase::create("missingtable").await;
    let ledger = Ledger::connect(&db.config).await.unwrap(); ledger.migrate().await.unwrap();
    let other = db.fork("unrelated").await;
    let mut connection = db.connection().await;
    sqlx::raw_sql(&format!("ALTER TABLE {}.ledger_versions RENAME TO retained_versions",db.config.schema))
        .execute(&mut connection).await.unwrap();
    assert_eq!(ledger.entity_version(domain().pair,[1;32],[0;32]).await,Err(LedgerError::Database));
    assert!(matches!(Ledger::connect(&db.config).await,Err(LedgerError::Database)));
    assert_eq!(sqlx::query_scalar::<_,i64>(&format!("SELECT count(*) FROM {}.ledger_versions",other.config.schema))
        .fetch_one(&mut connection).await.unwrap(),0);
    sqlx::raw_sql(&format!("ALTER TABLE {}.retained_versions RENAME TO ledger_versions",db.config.schema))
        .execute(&mut connection).await.unwrap();
    assert_eq!(ledger.entity_version(domain().pair,[1;32],[0;32]).await.unwrap(),0);
    ledger.close().await; connection.close().await.unwrap(); other.remove().await; db.remove().await;
}

#[tokio::test]
async fn migration_checksum_tampering_halts_without_rewriting_retained_history() {
    use sqlx::Connection;
    let db = TestDatabase::create("checksum").await;
    let ledger = Ledger::connect(&db.config).await.unwrap(); ledger.migrate().await.unwrap();
    let mut connection = db.connection().await;
    let checksum = sqlx::query_scalar::<_,Vec<u8>>(&format!("SELECT checksum FROM {}._sqlx_migrations WHERE version=1",db.config.schema))
        .fetch_one(&mut connection).await.unwrap();
    let mut changed = checksum.clone(); changed[0]^=1;
    sqlx::query(&format!("UPDATE {}._sqlx_migrations SET checksum=$1 WHERE version=1",db.config.schema)).bind(&changed).execute(&mut connection).await.unwrap();
    assert_eq!(ledger.migrate().await,Err(LedgerError::Database));
    assert_eq!(sqlx::query_scalar::<_,Vec<u8>>(&format!("SELECT checksum FROM {}._sqlx_migrations WHERE version=1",db.config.schema))
        .fetch_one(&mut connection).await.unwrap(),changed);
    sqlx::query(&format!("UPDATE {}._sqlx_migrations SET checksum=$1 WHERE version=1",db.config.schema)).bind(checksum).execute(&mut connection).await.unwrap();
    ledger.close().await; connection.close().await.unwrap(); db.remove().await;
}
