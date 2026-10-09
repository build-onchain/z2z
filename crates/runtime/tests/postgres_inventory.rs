#![cfg(feature = "postgres-tests")]

#[path = "market_support/ledger.rs"]
mod support;

use std::{sync::Arc, time::Duration};

use sqlx::Row;
use tokio::{process::Command, sync::Barrier};
use ziquid_protocol::NativeAmount;
use ziquid_runtime::{
    database::DatabaseConfig,
    store::{
        ActorStore, FundingIntent, FundingState, InventoryScope, Reservation, ReservationState,
        StoreError,
    },
};

use support::TestDatabase;

fn amount(value: u64) -> NativeAmount {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    NativeAmount::from_be_bytes(bytes)
}

fn scope() -> InventoryScope {
    InventoryScope { actor: [1; 32], asset: [2; 32], deployment: [3; 32] }
}

async fn open(database: &TestDatabase, scope: InventoryScope) -> ActorStore {
    ActorStore::connect(database.config.clone(), scope).await.unwrap()
}

#[tokio::test]
async fn two_connections_cannot_reserve_the_same_fresh_scope_capacity() {
    let database = TestDatabase::create("inventory_cap").await;
    let mut first = open(&database, scope()).await;
    first.migrate().await.unwrap();
    let mut second = open(&database, scope()).await;
    let barrier = Arc::new(Barrier::new(2));
    let other_barrier = Arc::clone(&barrier);
    let (first_result, second_result) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(
            async {
                barrier.wait().await;
                first.reserve([1; 32], [3; 32], amount(7), amount(10)).await
            },
            async {
                other_barrier.wait().await;
                second.reserve([2; 32], [3; 32], amount(7), amount(10)).await
            }
        )
    }).await.expect("scope lock did not complete");
    let winner = match (&first_result, &second_result) {
        (Ok(_), Err(StoreError::InsufficientInventory)) => [1; 32],
        (Err(StoreError::InsufficientInventory), Ok(_)) => [2; 32],
        other => panic!("exactly one reservation must acquire the capacity: {other:?}"),
    };
    drop(first);
    drop(second);
    let mut reopened = open(&database, scope()).await;
    assert_eq!(reopened.reservation(winner).await.unwrap().unwrap().amount, amount(7));
    assert_eq!(
        reopened.reservation(if winner == [1; 32] { [2; 32] } else { [1; 32] }).await.unwrap(),
        None
    );
    assert!(matches!(
        reopened.reserve([4; 32], [3; 32], amount(4), amount(10)).await,
        Err(StoreError::InsufficientInventory)
    ));
    reopened.cancel(winner).await.unwrap();
    assert_eq!(
        reopened.reserve([4; 32], [3; 32], amount(10), amount(10)).await.unwrap().state,
        ReservationState::Reserved
    );
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn concurrent_fresh_migrations_and_scope_initializers_share_the_funding_fence() {
    let database = TestDatabase::create("inventory_fresh").await;
    let mut first = open(&database, scope()).await;
    let mut second = open(&database, scope()).await;
    let barrier = Arc::new(Barrier::new(2));
    let other_barrier = Arc::clone(&barrier);
    let (first_records, second_records) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(
            async {
                barrier.wait().await;
                first.migrate().await.unwrap();
                first.reserve([1; 32], [2; 32], amount(10), amount(10)).await.unwrap();
                first.prepare_funding([1; 32], [3; 32], [4; 32]).await.unwrap();
                let intent = first.mark_submission_unknown([3; 32], [5; 32]).await.unwrap();
                assert!(matches!(first.cancel([1; 32]).await, Err(StoreError::FundingFenced)));
                (intent, first.reservation([1; 32]).await.unwrap().unwrap())
            },
            async {
                other_barrier.wait().await;
                second.migrate().await.unwrap();
                second.reserve([1; 32], [2; 32], amount(10), amount(10)).await.unwrap();
                second.prepare_funding([1; 32], [3; 32], [4; 32]).await.unwrap();
                let intent = second.mark_submission_unknown([3; 32], [5; 32]).await.unwrap();
                assert!(matches!(second.cancel([1; 32]).await, Err(StoreError::FundingFenced)));
                (intent, second.reservation([1; 32]).await.unwrap().unwrap())
            }
        )
    }).await.expect("fresh schema initialization did not complete");
    let expected_intent = FundingIntent {
        order_id: [1; 32], context_digest: [2; 32], operation_id: [3; 32],
        unsigned_payload_digest: [4; 32], transaction_hash: Some([5; 32]),
        state: FundingState::SubmissionUnknown,
    };
    let expected_reservation = Reservation {
        order_id: [1; 32], context_digest: [2; 32], amount: amount(10),
        state: ReservationState::SubmissionUnknown,
    };
    assert_eq!(first_records, (expected_intent, expected_reservation));
    assert_eq!(second_records, (expected_intent, expected_reservation));
    drop(first);
    drop(second);
    let mut reopened = open(&database, scope()).await;
    assert_eq!(reopened.funding([3; 32]).await.unwrap(), Some(expected_intent));
    assert_eq!(reopened.reservation([1; 32]).await.unwrap(), Some(expected_reservation));
    assert!(matches!(reopened.cancel([1; 32]).await, Err(StoreError::FundingFenced)));
    assert!(matches!(
        reopened.reserve([6; 32], [2; 32], amount(1), amount(10)).await,
        Err(StoreError::InsufficientInventory)
    ));
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn all_256_amount_bits_round_trip_as_bytea_without_sql_integer_truncation() {
    let database = TestDatabase::create("inventory_amount").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    let mut high = [0; 32];
    high[0] = 0x80;
    let mut low = [0xff; 32];
    low[0] = 0x7f;
    let capacity = NativeAmount::from_be_bytes([0xff; 32]);
    store.reserve([1; 32], [3; 32], NativeAmount::from_be_bytes(high), capacity).await.unwrap();
    store.reserve([2; 32], [3; 32], NativeAmount::from_be_bytes(low), capacity).await.unwrap();
    drop(store);
    let reopened = open(&database, scope()).await;
    let mut connection = database.connection().await;
    let query = format!(
        "SELECT pg_catalog.pg_typeof(amount)::text AS storage_type, amount FROM {}.reservations \
         WHERE actor = $1 AND asset = $2 AND deployment = $3 AND order_id = $4",
        database.config.schema
    );
    for (order, expected) in [(1_u8, high), (2, low)] {
        assert_eq!(reopened.reservation([order; 32]).await.unwrap().unwrap().amount.to_be_bytes(), expected);
        let order_id = [order; 32];
        let row = sqlx::query(&query)
            .bind(scope().actor.as_slice()).bind(scope().asset.as_slice())
            .bind(scope().deployment.as_slice()).bind(order_id.as_slice())
            .fetch_one(&mut connection).await.expect("amount storage read failed");
        assert_eq!(row.try_get::<String, _>("storage_type").unwrap(), "bytea");
        assert_eq!(row.try_get::<&[u8], _>("amount").unwrap(), expected.as_slice());
    }
    drop(connection);
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn uint256_max_and_checked_aggregation_reject_overflow_without_mutation() {
    let database = TestDatabase::create("inventory_overflow").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    let maximum = NativeAmount::from_be_bytes([0xff; 32]);
    store.reserve([1; 32], [2; 32], maximum, maximum).await.unwrap();
    assert!(matches!(
        store.reserve([3; 32], [2; 32], amount(1), maximum).await,
        Err(StoreError::AmountOverflow)
    ));
    assert_eq!(store.reservation([3; 32]).await.unwrap(), None);
    assert_eq!(store.reservation([1; 32]).await.unwrap().unwrap().amount, maximum);
    store.cancel([1; 32]).await.unwrap();
    assert_eq!(store.reserve([3; 32], [2; 32], maximum, maximum).await.unwrap().amount, maximum);
    drop(store);
    let reopened = open(&database, scope()).await;
    assert_eq!(reopened.reservation([3; 32]).await.unwrap().unwrap().amount, maximum);
    assert_eq!(reopened.reservation([1; 32]).await.unwrap().unwrap().state, ReservationState::Cancelled);
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn duplicate_order_and_cancelled_replay_keep_exact_context_and_amount() {
    let database = TestDatabase::create("inventory_replay").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    let original = store.reserve([1; 32], [2; 32], amount(10), amount(10)).await.unwrap();
    assert_eq!(store.reserve([1; 32], [2; 32], amount(10), amount(0)).await.unwrap(), original);
    for (context, value) in [([3; 32], 10), ([2; 32], 9)] {
        assert!(matches!(
            store.reserve([1; 32], context, amount(value), amount(10)).await,
            Err(StoreError::ReservationMismatch)
        ));
    }
    assert_eq!(store.reservation([1; 32]).await.unwrap(), Some(original));
    let cancelled = store.cancel([1; 32]).await.unwrap();
    assert_eq!(cancelled.state, ReservationState::Cancelled);
    assert_eq!(store.cancel([1; 32]).await.unwrap(), cancelled);
    drop(store);
    let mut reopened = open(&database, scope()).await;
    assert_eq!(reopened.reserve([1; 32], [2; 32], amount(10), amount(0)).await.unwrap(), cancelled);
    assert!(matches!(
        reopened.reserve([1; 32], [3; 32], amount(10), amount(10)).await,
        Err(StoreError::ReservationMismatch)
    ));
    assert!(matches!(
        reopened.prepare_funding([1; 32], [4; 32], [5; 32]).await,
        Err(StoreError::FundingFenced)
    ));
    assert_eq!(reopened.funding([4; 32]).await.unwrap(), None);
    assert_eq!(reopened.reserve([6; 32], [2; 32], amount(10), amount(10)).await.unwrap().state,
               ReservationState::Reserved);
    assert_eq!(reopened.reservation([1; 32]).await.unwrap(), Some(cancelled));
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn zero_amount_and_unreserved_funding_are_rejected_without_records() {
    let database = TestDatabase::create("inventory_zero").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    assert!(matches!(
        store.reserve([1; 32], [2; 32], amount(0), amount(10)).await,
        Err(StoreError::ZeroAmount)
    ));
    assert!(matches!(store.cancel([1; 32]).await, Err(StoreError::UnknownOrder)));
    assert!(matches!(
        store.prepare_funding([1; 32], [3; 32], [4; 32]).await,
        Err(StoreError::UnknownOrder)
    ));
    assert_eq!(store.reservation([1; 32]).await.unwrap(), None);
    assert_eq!(store.funding([3; 32]).await.unwrap(), None);
    drop(store);
    database.remove().await;
}

#[tokio::test]
async fn funding_operation_and_payload_cannot_rebind_or_double_fund() {
    let database = TestDatabase::create("inventory_binding").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    store.reserve([1; 32], [2; 32], amount(6), amount(10)).await.unwrap();
    let other = store.reserve([3; 32], [2; 32], amount(4), amount(10)).await.unwrap();
    let original = store.prepare_funding([1; 32], [4; 32], [5; 32]).await.unwrap();
    assert_eq!(original.state, FundingState::Prepared);
    assert_eq!(store.prepare_funding([1; 32], [4; 32], [5; 32]).await.unwrap(), original);
    for (order, operation, payload) in [([1; 32], [4; 32], [6; 32]), ([3; 32], [4; 32], [5; 32])] {
        assert!(matches!(
            store.prepare_funding(order, operation, payload).await,
            Err(StoreError::OperationMismatch)
        ));
    }
    assert!(matches!(
        store.prepare_funding([1; 32], [7; 32], [5; 32]).await,
        Err(StoreError::OrderAlreadyPrepared)
    ));
    assert_eq!(store.funding([7; 32]).await.unwrap(), None);
    assert_eq!(store.reservation([3; 32]).await.unwrap(), Some(other));
    assert_eq!(store.funding([4; 32]).await.unwrap(), Some(original));
    assert!(matches!(store.cancel([1; 32]).await, Err(StoreError::FundingFenced)));
    drop(store);
    let reopened = open(&database, scope()).await;
    assert_eq!(reopened.funding([4; 32]).await.unwrap(), Some(original));
    assert_eq!(reopened.reservation([3; 32]).await.unwrap(), Some(other));
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn all_active_states_keep_capacity_after_reconnect_and_only_reserved_can_cancel() {
    let database = TestDatabase::create("inventory_states").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    for (order, value) in [(1_u8, 2), (2, 3), (3, 4), (4, 1)] {
        store.reserve([order; 32], [9; 32], amount(value), amount(10)).await.unwrap();
    }
    for order in [2_u8, 3, 4] {
        store.prepare_funding([order; 32], [order + 10; 32], [20; 32]).await.unwrap();
    }
    store.mark_submission_unknown([13; 32], [30; 32]).await.unwrap();
    store.mark_armed([14; 32], [9; 32]).await.unwrap();
    drop(store);
    let mut reopened = open(&database, scope()).await;
    for (order, expected) in [
        (1_u8, ReservationState::Reserved), (2, ReservationState::FundingPrepared),
        (3, ReservationState::SubmissionUnknown), (4, ReservationState::Armed),
    ] {
        assert_eq!(reopened.reservation([order; 32]).await.unwrap().unwrap().state, expected);
    }
    assert!(matches!(
        reopened.reserve([5; 32], [9; 32], amount(1), amount(10)).await,
        Err(StoreError::InsufficientInventory)
    ));
    for order in [2_u8, 3, 4] {
        assert!(matches!(reopened.cancel([order; 32]).await, Err(StoreError::FundingFenced)));
    }
    reopened.cancel([1; 32]).await.unwrap();
    reopened.reserve([5; 32], [9; 32], amount(2), amount(10)).await.unwrap();
    assert!(matches!(
        reopened.reserve([6; 32], [9; 32], amount(1), amount(10)).await,
        Err(StoreError::InsufficientInventory)
    ));
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn unknown_operation_cannot_create_a_record_or_release_inventory() {
    let database = TestDatabase::create("inventory_unknown").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    store.reserve([1; 32], [2; 32], amount(10), amount(10)).await.unwrap();
    let original = store.prepare_funding([1; 32], [3; 32], [4; 32]).await.unwrap();
    assert!(matches!(
        store.mark_submission_unknown([9; 32], [5; 32]).await,
        Err(StoreError::UnknownOperation)
    ));
    assert!(matches!(store.mark_armed([9; 32], [2; 32]).await, Err(StoreError::UnknownOperation)));
    assert_eq!(store.funding([9; 32]).await.unwrap(), None);
    assert_eq!(store.funding([3; 32]).await.unwrap(), Some(original));
    assert!(matches!(store.cancel([1; 32]).await, Err(StoreError::FundingFenced)));
    assert!(matches!(
        store.reserve([6; 32], [2; 32], amount(1), amount(10)).await,
        Err(StoreError::InsufficientInventory)
    ));
    drop(store);
    database.remove().await;
}

#[tokio::test]
async fn submission_and_arming_keep_immutable_bindings_and_never_downgrade_armed() {
    let database = TestDatabase::create("inventory_arming").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    store.reserve([1; 32], [2; 32], amount(10), amount(10)).await.unwrap();
    let prepared = store.prepare_funding([1; 32], [3; 32], [4; 32]).await.unwrap();
    assert!(matches!(store.mark_armed([3; 32], [7; 32]).await, Err(StoreError::ContextMismatch)));
    assert_eq!(store.funding([3; 32]).await.unwrap(), Some(prepared));
    let unknown = store.mark_submission_unknown([3; 32], [5; 32]).await.unwrap();
    assert_eq!(unknown.state, FundingState::SubmissionUnknown);
    assert_eq!(store.mark_submission_unknown([3; 32], [5; 32]).await.unwrap(), unknown);
    assert!(matches!(
        store.mark_submission_unknown([3; 32], [6; 32]).await,
        Err(StoreError::SubmissionMismatch)
    ));
    assert!(matches!(store.mark_armed([3; 32], [7; 32]).await, Err(StoreError::ContextMismatch)));
    assert_eq!(store.funding([3; 32]).await.unwrap(), Some(unknown));
    let armed = store.mark_armed([3; 32], [2; 32]).await.unwrap();
    assert_eq!(armed.state, FundingState::Armed);
    assert_eq!(store.mark_armed([3; 32], [2; 32]).await.unwrap(), armed);
    assert_eq!(store.mark_submission_unknown([3; 32], [5; 32]).await.unwrap(), armed);
    assert_eq!(store.prepare_funding([1; 32], [3; 32], [4; 32]).await.unwrap(), armed);
    drop(store);
    let mut reopened = open(&database, scope()).await;
    assert_eq!(reopened.funding([3; 32]).await.unwrap(), Some(armed));
    assert_eq!(reopened.reservation([1; 32]).await.unwrap().unwrap().state, ReservationState::Armed);
    assert!(matches!(reopened.cancel([1; 32]).await, Err(StoreError::FundingFenced)));
    assert!(matches!(
        reopened.reserve([8; 32], [2; 32], amount(1), amount(10)).await,
        Err(StoreError::InsufficientInventory)
    ));
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn armed_without_submission_hash_accepts_one_hash_without_losing_its_fence() {
    let database = TestDatabase::create("inventory_armed_hash").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    store.reserve([1; 32], [2; 32], amount(10), amount(10)).await.unwrap();
    store.prepare_funding([1; 32], [3; 32], [4; 32]).await.unwrap();
    let armed = store.mark_armed([3; 32], [2; 32]).await.unwrap();
    assert_eq!(armed.transaction_hash, None);
    assert_eq!(armed.state, FundingState::Armed);
    let with_hash = store.mark_submission_unknown([3; 32], [5; 32]).await.unwrap();
    assert_eq!(with_hash.state, FundingState::Armed);
    assert_eq!(with_hash.transaction_hash, Some([5; 32]));
    assert!(matches!(
        store.mark_submission_unknown([3; 32], [6; 32]).await,
        Err(StoreError::SubmissionMismatch)
    ));
    assert_eq!(store.funding([3; 32]).await.unwrap(), Some(with_hash));
    drop(store);
    let mut reopened = open(&database, scope()).await;
    assert_eq!(reopened.funding([3; 32]).await.unwrap(), Some(with_hash));
    assert!(matches!(reopened.cancel([1; 32]).await, Err(StoreError::FundingFenced)));
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn actor_asset_and_deployment_each_isolate_order_operation_and_capacity() {
    let database = TestDatabase::create("inventory_scopes").await;
    let scopes = [
        scope(),
        InventoryScope { actor: [4; 32], ..scope() },
        InventoryScope { asset: [4; 32], ..scope() },
        InventoryScope { deployment: [4; 32], ..scope() },
    ];
    let first = open(&database, scopes[0]).await;
    first.migrate().await.unwrap();
    drop(first);
    for (index, current_scope) in scopes.iter().copied().enumerate() {
        let mut store = open(&database, current_scope).await;
        assert_eq!(store.reservation([1; 32]).await.unwrap(), None);
        assert_eq!(store.funding([3; 32]).await.unwrap(), None);
        assert!(matches!(store.cancel([1; 32]).await, Err(StoreError::UnknownOrder)));
        assert!(matches!(store.mark_armed([3; 32], [2; 32]).await, Err(StoreError::UnknownOperation)));
        assert!(matches!(
            store.mark_submission_unknown([3; 32], [5; 32]).await,
            Err(StoreError::UnknownOperation)
        ));
        let context = [10 + index as u8; 32];
        store.reserve([1; 32], context, amount(10), amount(10)).await.unwrap();
        store.prepare_funding([1; 32], [3; 32], [20 + index as u8; 32]).await.unwrap();
        store.mark_submission_unknown([3; 32], [30 + index as u8; 32]).await.unwrap();
        assert!(matches!(
            store.reserve([6; 32], context, amount(1), amount(10)).await,
            Err(StoreError::InsufficientInventory)
        ));
    }
    let mut last = open(&database, scopes[3]).await;
    assert!(matches!(last.mark_armed([3; 32], [10; 32]).await, Err(StoreError::ContextMismatch)));
    last.mark_armed([3; 32], [13; 32]).await.unwrap();
    drop(last);
    for (index, current_scope) in scopes.iter().copied().enumerate() {
        let mut reopened = open(&database, current_scope).await;
        assert_eq!(reopened.funding([3; 32]).await.unwrap(), Some(FundingIntent {
            order_id: [1; 32], context_digest: [10 + index as u8; 32], operation_id: [3; 32],
            unsigned_payload_digest: [20 + index as u8; 32], transaction_hash: Some([30 + index as u8; 32]),
            state: if index == 3 { FundingState::Armed } else { FundingState::SubmissionUnknown },
        }));
        assert!(matches!(reopened.cancel([1; 32]).await, Err(StoreError::FundingFenced)));
    }
    database.remove().await;
}

#[tokio::test]
async fn sql_constraints_reject_bad_lengths_zero_and_invalid_funding_shapes() {
    let database = TestDatabase::create("inventory_constraints").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    let original = store.reserve([1; 32], [2; 32], amount(1), amount(10)).await.unwrap();
    let mut connection = database.connection().await;
    for assignment in [
        "actor = decode('00', 'hex')", "asset = decode('00', 'hex')",
        "deployment = decode('00', 'hex')", "order_id = decode('00', 'hex')",
        "context_digest = decode('00', 'hex')", "amount = decode('00', 'hex')",
        "amount = decode(repeat('00', 32), 'hex')", "state = 5", "state = 1", "state = 2", "state = 3",
        "operation_id = decode(repeat('01', 32), 'hex')",
        "unsigned_payload_digest = decode(repeat('01', 32), 'hex')",
        "transaction_hash = decode(repeat('01', 32), 'hex')",
    ] {
        let query = format!("UPDATE {}.reservations SET {assignment} WHERE order_id = $1", database.config.schema);
        assert!(sqlx::query(&query).bind([1_u8; 32].as_slice()).execute(&mut connection).await.is_err());
    }
    drop(connection);
    assert_eq!(store.reservation([1; 32]).await.unwrap(), Some(original));
    drop(store);
    database.remove().await;
}

#[tokio::test]
async fn missing_schema_never_falls_back_before_explicit_inventory_migration() {
    let database = TestDatabase::create("inventory_unmigrated").await;
    let mut store = open(&database, scope()).await;
    assert!(matches!(store.reservation([1; 32]).await, Err(StoreError::Database(_))));
    assert!(matches!(
        store.reserve([1; 32], [2; 32], amount(1), amount(10)).await,
        Err(StoreError::Database(_))
    ));
    store.migrate().await.unwrap();
    assert_eq!(store.reservation([1; 32]).await.unwrap(), None);
    store.reserve([1; 32], [2; 32], amount(1), amount(10)).await.unwrap();
    store.migrate().await.unwrap();
    assert_eq!(store.reservation([1; 32]).await.unwrap().unwrap().amount, amount(1));
    drop(store);
    database.remove().await;
}

#[tokio::test]
async fn schema_drift_is_rejected_before_inventory_mutation() {
    let database = TestDatabase::create("inventory_drift").await;
    let mut store = open(&database, scope()).await;
    store.migrate().await.unwrap();
    store.reserve([1; 32], [2; 32], amount(10), amount(10)).await.unwrap();
    let mut connection = database.connection().await;
    let query = format!("ALTER TABLE {}.reservations DROP CONSTRAINT reservation_amount_nonzero", database.config.schema);
    sqlx::query(&query).execute(&mut connection).await.expect("authorized schema-drift setup failed");
    assert!(matches!(store.cancel([1; 32]).await, Err(StoreError::Database(_))));
    let query = format!("SELECT state FROM {}.reservations WHERE order_id = $1", database.config.schema);
    assert_eq!(sqlx::query(&query).bind([1_u8; 32].as_slice()).fetch_one(&mut connection).await
        .expect("original reservation read failed").try_get::<i16, _>("state").unwrap(), 0);
    drop(store);
    // This exact schema was created above under the test authorization. Generic
    // cleanup rightly refuses its deliberately damaged catalog fingerprint.
    let query = format!("DROP SCHEMA {} CASCADE", database.config.schema);
    sqlx::query(&query).execute(&mut connection).await
        .map_err(ziquid_runtime::database::DatabaseError::from)
        .expect("exact-created damaged inventory schema cleanup failed");
    drop(connection);
}

#[tokio::test]
async fn rewrite_suppression_never_returns_an_unpersisted_inventory_transition() {
    for mutation in ["reserve", "cancel", "unknown", "armed"] {
        let database = TestDatabase::create("inventory_rewrite").await;
        let mut store = open(&database, scope()).await;
        store.migrate().await.unwrap();
        if mutation == "reserve" {
            store.reserve([8; 32], [2; 32], amount(1), amount(10)).await.unwrap();
        } else {
            store.reserve([1; 32], [2; 32], amount(6), amount(10)).await.unwrap();
        }
        let prepared = matches!(mutation, "unknown" | "armed");
        if prepared {
            store.prepare_funding([1; 32], [3; 32], [4; 32]).await.unwrap();
        }
        let mut connection = database.connection().await;
        let relation = format!("\"{}\".reservations", database.config.schema);
        let (event, predicate, statement) = match mutation {
            "reserve" => ("INSERT", "", format!(
                "INSERT INTO {relation} (actor,asset,deployment,order_id,context_digest,amount,state) \
                 VALUES ($1,$2,$3,$4,$5,$6,0)"
            )),
            "cancel" => ("UPDATE", "WHERE NEW.state = 4", format!(
                "UPDATE {relation} SET state=4 WHERE actor=$1 AND asset=$2 AND deployment=$3 AND order_id=$4"
            )),
            "unknown" => ("UPDATE", "WHERE NEW.state = 2", format!(
                "UPDATE {relation} SET state=2,transaction_hash=$5 \
                 WHERE actor=$1 AND asset=$2 AND deployment=$3 AND order_id=$4"
            )),
            "armed" => ("UPDATE", "WHERE NEW.state = 3", format!(
                "UPDATE {relation} SET state=3 WHERE actor=$1 AND asset=$2 AND deployment=$3 AND order_id=$4"
            )),
            _ => unreachable!(),
        };
        let rule = format!(
            "CREATE RULE inventory_suppress AS ON {event} TO {relation} {predicate} DO INSTEAD NOTHING"
        );
        sqlx::query(&rule).execute(&mut connection).await
            .map_err(ziquid_runtime::database::DatabaseError::from)
            .expect("authorized inventory rewrite fixture setup failed");
        // Exercise the actual rule, not a mock: the financial statement reports
        // zero affected rows while the original persisted state stays unchanged.
        let scope = scope();
        let order = [1_u8; 32];
        let context = [2_u8; 32];
        let operation = [3_u8; 32];
        let payload = [4_u8; 32];
        let hash = [5_u8; 32];
        let encoded_amount = amount(6).to_be_bytes();
        let statement = sqlx::query(&statement)
            .bind(scope.actor.as_slice()).bind(scope.asset.as_slice())
            .bind(scope.deployment.as_slice()).bind(order.as_slice());
        let statement = match mutation {
            "reserve" => statement.bind(context.as_slice()).bind(encoded_amount.as_slice()),
            "unknown" => statement.bind(hash.as_slice()),
            _ => statement,
        };
        assert_eq!(statement.execute(&mut connection).await
            .map_err(ziquid_runtime::database::DatabaseError::from)
            .expect("conditional suppression fixture did not execute").rows_affected(), 0);
        let error = match mutation {
            "reserve" => store.reserve(order, context, amount(6), amount(10)).await.unwrap_err(),
            "cancel" => store.cancel(order).await.unwrap_err(),
            "unknown" => store.mark_submission_unknown(operation, hash).await.unwrap_err(),
            "armed" => store.mark_armed(operation, context).await.unwrap_err(),
            _ => unreachable!(),
        };
        assert!(matches!(error, StoreError::Database(_)), "mutation {mutation} must fail closed");
        let read = format!(
            "SELECT context_digest,amount,state,operation_id,unsigned_payload_digest,transaction_hash \
             FROM {relation} WHERE actor=$1 AND asset=$2 AND deployment=$3 AND order_id=$4"
        );
        let persisted = sqlx::query(&read)
            .bind(scope.actor.as_slice()).bind(scope.asset.as_slice())
            .bind(scope.deployment.as_slice()).bind(order.as_slice())
            .fetch_optional(&mut connection).await
            .map_err(ziquid_runtime::database::DatabaseError::from)
            .expect("suppressed inventory state could not be read");
        if mutation == "reserve" {
            assert!(persisted.is_none());
        } else {
            let persisted = persisted.expect("suppression must not delete the original reservation");
            assert_eq!(persisted.try_get::<&[u8], _>("context_digest").unwrap(), context.as_slice());
            assert_eq!(persisted.try_get::<&[u8], _>("amount").unwrap(), encoded_amount.as_slice());
            assert_eq!(persisted.try_get::<i16, _>("state").unwrap(), if prepared { 1 } else { 0 });
            assert_eq!(persisted.try_get::<Option<&[u8]>, _>("operation_id").unwrap(),
                       prepared.then_some(operation.as_slice()));
            assert_eq!(persisted.try_get::<Option<&[u8]>, _>("unsigned_payload_digest").unwrap(),
                       prepared.then_some(payload.as_slice()));
            assert_eq!(persisted.try_get::<Option<&[u8]>, _>("transaction_hash").unwrap(), None);
        }
        drop(store);
        // This exact authorized generated schema is deliberately damaged, so
        // cleanup uses only the connection that created its suppression rule.
        let cleanup = format!("DROP SCHEMA \"{}\" CASCADE", database.config.schema);
        sqlx::query(&cleanup).execute(&mut connection).await
            .map_err(ziquid_runtime::database::DatabaseError::from)
            .expect("exact-created inventory rewrite schema cleanup failed");
        drop(connection);
    }
}

#[tokio::test]
async fn crash_reconnect_after_prepared_or_unknown_funding_keeps_inventory_fenced() {
    if let Some(schema) = std::env::var_os("Z2Z_INVENTORY_CRASH_SCHEMA") {
        let config = DatabaseConfig {
            uri_env: "Z2Z_TEST_DATABASE_URL".into(),
            schema: schema.into_string().expect("invalid synthetic crash schema"),
            max_connections: 2,
        };
        // The secure test bridge enforces the same schema-prefix/opt-in gates in
        // the child. Only the name is passed; the private URI is inherited.
        drop(ziquid_runtime::database::test_connection(&config).await.unwrap());
        let mut store = ActorStore::connect(config, scope()).await.unwrap();
        store.migrate().await.unwrap();
        store.reserve([1; 32], [2; 32], amount(10), amount(10)).await.unwrap();
        store.prepare_funding([1; 32], [3; 32], [4; 32]).await.unwrap();
        if std::env::var_os("Z2Z_INVENTORY_CRASH_UNKNOWN").is_some() {
            store.mark_submission_unknown([3; 32], [5; 32]).await.unwrap();
        }
        // Abrupt exit skips Rust destructors and leaves the returned committed
        // PostgreSQL intent for a separate process; no DB restart is requested.
        std::process::exit(93);
    }
    for unknown in [false, true] {
        let database = TestDatabase::create(if unknown { "inventory_crash_unknown" } else { "inventory_crash_prepared" }).await;
        let mut child = Command::new(std::env::current_exe().unwrap());
        child.arg("--exact")
            .arg("crash_reconnect_after_prepared_or_unknown_funding_keeps_inventory_fenced")
            .env("Z2Z_INVENTORY_CRASH_SCHEMA", &database.config.schema)
            .env_remove("Z2Z_INVENTORY_CRASH_UNKNOWN")
            .kill_on_drop(true);
        if unknown { child.env("Z2Z_INVENTORY_CRASH_UNKNOWN", "1"); }
        let output = tokio::time::timeout(Duration::from_secs(60), child.output()).await
            .expect("inventory crash child did not exit").expect("inventory crash child could not start");
        assert_eq!(output.status.code(), Some(93));
        let mut store = open(&database, scope()).await;
        store.migrate().await.unwrap();
        let intent = store.funding([3; 32]).await.unwrap().unwrap();
        assert_eq!(intent, FundingIntent {
            order_id: [1; 32], context_digest: [2; 32], operation_id: [3; 32], unsigned_payload_digest: [4; 32],
            transaction_hash: if unknown { Some([5; 32]) } else { None },
            state: if unknown { FundingState::SubmissionUnknown } else { FundingState::Prepared },
        });
        assert_eq!(store.reservation([1; 32]).await.unwrap(), Some(Reservation {
            order_id: [1; 32], context_digest: [2; 32], amount: amount(10),
            state: if unknown { ReservationState::SubmissionUnknown } else { ReservationState::FundingPrepared },
        }));
        assert!(matches!(store.cancel([1; 32]).await, Err(StoreError::FundingFenced)));
        assert!(matches!(
            store.reserve([6; 32], [2; 32], amount(1), amount(10)).await,
            Err(StoreError::InsufficientInventory)
        ));
        assert_eq!(store.prepare_funding([1; 32], [3; 32], [4; 32]).await.unwrap(), intent);
        drop(store);
        database.remove().await;
    }
}
