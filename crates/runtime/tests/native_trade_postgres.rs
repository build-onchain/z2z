//! Real digest-journal tests; require separately authorized isolated SQL execution.
#![cfg(all(feature = "postgres-tests", target_os = "linux"))]

#[path = "market_support/ledger.rs"]
mod support;
mod native_trade_support;

use ziquid_runtime::{
    database::{DatabaseError, DatabaseConfig}, native_quote::QuotePhase,
    native_trade::{CapsuleLocation, NativeTradeError, NativeTradeStore, OperationState, TradeCursor, save_operation_capsule},
};
use support::TestDatabase;

async fn agreed(store: &NativeTradeStore, directory: &std::path::Path, id: u8) -> ziquid_runtime::native_trade::DurableQuote {
    let key = [71; 32];
    let mut expected = None;
    let mut result = None;
    for (index, phase) in [QuotePhase::Proposal, QuotePhase::UserAcceptance, QuotePhase::Agreed].into_iter().enumerate() {
        let path = directory.join(format!("quote-{id}-{index}"));
        let quote = native_trade_support::quote(phase, id, 1);
        let durable = store.save_quote(CapsuleLocation { path: &path, key: &key, namespace: [72; 32] }, &quote, expected).await.unwrap();
        expected = Some(durable.snapshot().cursor);
        result = Some(durable);
    }
    result.unwrap()
}

#[tokio::test]
async fn native_connect_never_initializes_and_rejects_foreign_application_schema() {
    let database = TestDatabase::create("native_init").await;
    let store = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    assert_eq!(store.list_owner([0x51; 32]).await.unwrap_err(), NativeTradeError::Database(DatabaseError::SchemaNotReady));
    store.migrate().await.unwrap();
    store.migrate().await.unwrap();
    assert!(store.list_owner([0x51; 32]).await.unwrap().is_empty());
    let foreign = ziquid_runtime::samechain::journal::ReleaseJournal::connect(database.config.clone()).await.unwrap();
    assert_eq!(foreign.migrate().await.unwrap_err(), ziquid_runtime::samechain::journal::JournalError::Database(DatabaseError::SchemaIdentity));
    drop(foreign);
    drop(store);
    let restarted = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    assert!(restarted.list_owner([0x51; 32]).await.unwrap().is_empty());
    drop(restarted);
    database.remove().await;
}

#[tokio::test]
async fn native_schema_has_no_executable_or_secret_columns() {
    let database = TestDatabase::create("native_shape").await;
    let store = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    store.migrate().await.unwrap();
    let mut connection = database.connection().await;
    let names: Vec<String> = sqlx::query_scalar("SELECT column_name FROM information_schema.columns WHERE table_schema=$1 AND table_name IN ('quotes','trades','releases','reservations') ORDER BY table_name,ordinal_position")
        .bind(&database.config.schema).fetch_all(&mut connection).await.unwrap();
    assert!(names.iter().all(|name| !["payload", "secret", "witness", "pczt", "proof_bytes", "key", "path"].contains(&name.as_str())));
    for name in ["writer_generation", "capsule_digest", "stable_j_tag", "payload_digest", "challenge_i", "proposal_seq"] {
        assert!(names.iter().any(|actual| actual == name));
    }
    drop(connection);
    drop(store);
    database.remove().await;
}

#[tokio::test]
async fn quote_phase_cas_and_stopped_restore_retain_exact_signed_terms() {
    let database = TestDatabase::create("native_quote").await;
    let store = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    store.migrate().await.unwrap();
    let directory = native_trade_support::private_directory();
    let proposal = native_trade_support::quote(QuotePhase::Proposal, 8, 1);
    let key = [71; 32];
    let path = directory.path().join("proposal");
    let location = CapsuleLocation { path: &path, key: &key, namespace: [72; 32] };
    let first = store.save_quote(location, &proposal, None).await.unwrap();
    assert_eq!(first.snapshot().cursor, TradeCursor { version: 1, generation: 1 });
    let retry = store.save_quote(location, &proposal, Some(first.snapshot().cursor)).await.unwrap();
    assert_eq!(retry.snapshot(), first.snapshot());
    let changed_path = directory.path().join("changed");
    let changed = native_trade_support::quote(QuotePhase::Proposal, 8, 2);
    assert_eq!(store.save_quote(CapsuleLocation { path: &changed_path, ..location }, &changed, Some(first.snapshot().cursor)).await.unwrap_err(), NativeTradeError::Conflict);
    assert!(!changed_path.exists());
    let complete = native_trade_support::quote(QuotePhase::Agreed, 8, 1);
    assert_eq!(store.save_quote(CapsuleLocation { path: &changed_path, ..location }, &complete, Some(first.snapshot().cursor)).await.unwrap_err(), NativeTradeError::State);
    let takeover = store.claim_writer(proposal.selection(), first.snapshot().cursor).await.unwrap();
    assert_eq!(takeover.cursor, TradeCursor { version: 2, generation: 2 });
    assert_eq!(store.stop_quote(proposal.selection(), first.snapshot().cursor).await.unwrap_err(), NativeTradeError::StaleGeneration);
    let stopped = store.stop_quote(proposal.selection(), takeover.cursor).await.unwrap();
    assert!(stopped.stopped);
    assert_eq!(store.save_quote(location, &proposal, Some(stopped.cursor)).await.unwrap_err(), NativeTradeError::Stopped);
    let restored = store.restore_quote(location, proposal.selection(), stopped.cursor).await.unwrap();
    assert_eq!(restored.quote().encode(), proposal.encode());
    assert_eq!(restored.snapshot(), &stopped);
    assert_eq!(store.stop_quote(proposal.selection(), stopped.cursor).await.unwrap(), stopped);
    drop(store);
    database.remove().await;
}

#[tokio::test]
async fn concurrent_writers_are_fenced_across_independent_store_connections() {
    let database = TestDatabase::create("native_writers").await;
    let first = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    first.migrate().await.unwrap();
    let second = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    let directory = native_trade_support::private_directory();
    let proposal = native_trade_support::quote(QuotePhase::Proposal, 8, 1);
    let path = directory.path().join("proposal");
    let key = [71; 32];
    let location = CapsuleLocation { path: &path, key: &key, namespace: [72; 32] };
    let (a, b) = tokio::join!(first.save_quote(location, &proposal, None), second.save_quote(location, &proposal, None));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let cursor = a.ok().or_else(|| b.ok()).unwrap().snapshot().cursor;
    let (a, b) = tokio::join!(first.claim_writer(proposal.selection(), cursor), second.claim_writer(proposal.selection(), cursor));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(a.as_ref().err().or_else(|| b.as_ref().err()), Some(NativeTradeError::StaleGeneration)));
    drop(first);
    drop(second);
    database.remove().await;
}

#[tokio::test]
async fn release_requires_authenticated_capsule_and_unknown_retains_known_hash_across_restart() {
    let database = TestDatabase::create("native_restart").await;
    let store = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    store.migrate().await.unwrap();
    let directory = native_trade_support::private_directory();
    let quote = agreed(&store, directory.path(), 8).await;
    let selection = quote.snapshot().selection;
    let payload = b"exact original executable payload";
    let binding = native_trade_support::binding(31, payload);
    let prepared = store.prepare_operation(&selection, quote.snapshot().cursor, binding).await.unwrap();
    let path = directory.path().join("operation");
    let key = [71; 32];
    let location = CapsuleLocation { path: &path, key: &key, namespace: [72; 32] };
    assert!(store.release_operation(location, &selection, prepared.cursor, binding.op_id, [99; 32]).await.is_err());
    assert_eq!(store.operation(&selection, binding.op_id).await.unwrap(), prepared);
    assert_eq!(store.mark_unknown(&selection, prepared.cursor, binding.op_id).await.unwrap_err(), NativeTradeError::State);
    let digest = save_operation_capsule(location, &selection, &binding, payload).unwrap();
    let wrong_key = [73; 32];
    assert!(store.release_operation(CapsuleLocation { key: &wrong_key, ..location }, &selection, prepared.cursor, binding.op_id, digest).await.is_err());
    assert_eq!(store.operation(&selection, binding.op_id).await.unwrap(), prepared);
    let released = store.release_operation(location, &selection, prepared.cursor, binding.op_id, digest).await.unwrap();
    assert_eq!(released.payload(), payload);
    let tx_hash = [81; 32];
    let submitted = store.mark_submitted(&selection, released.snapshot().cursor, binding.op_id, tx_hash).await.unwrap();
    let unknown = store.mark_unknown(&selection, submitted.cursor, binding.op_id).await.unwrap();
    assert_eq!(unknown.state, OperationState::Unknown);
    assert_eq!(unknown.tx_hash, Some(tx_hash));
    assert_eq!(unknown.capsule_digest, Some(digest));
    assert_eq!(unknown.binding, binding);
    let stopped = store.stop_quote(&selection, unknown.cursor).await.unwrap();
    drop(store);
    let restarted = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    let read = restarted.operation(&selection, binding.op_id).await.unwrap();
    assert_eq!(read.state, OperationState::Unknown);
    assert_eq!(read.tx_hash, Some(tx_hash));
    assert_eq!(read.cursor, stopped.cursor);
    assert!(restarted.release_operation(location, &selection, read.cursor, binding.op_id, digest).await.is_err());
    let restored = restarted.restore_operation(location, &selection, read.cursor, binding.op_id).await.unwrap();
    assert_eq!(restored.payload(), payload);
    assert_eq!(restarted.mark_submitted(&selection, read.cursor, binding.op_id, [82; 32]).await.unwrap_err(), NativeTradeError::Conflict);
    let reconciled = restarted.mark_submitted(&selection, read.cursor, binding.op_id, tx_hash).await.unwrap();
    assert_eq!(reconciled.state, OperationState::Submitted);
    assert_eq!(reconciled.tx_hash, Some(tx_hash));
    let mut changed = binding;
    changed.payload_digest = [83; 32];
    assert_eq!(restarted.prepare_operation(&selection, reconciled.cursor, changed).await.unwrap_err(), NativeTradeError::Stopped);
    drop(restarted);
    database.remove().await;
}

#[tokio::test]
async fn cross_quote_concurrency_and_restart_never_free_stable_note_reservation() {
    let database = TestDatabase::create("native_reserve").await;
    let first = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    first.migrate().await.unwrap();
    let second = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    let directory = native_trade_support::private_directory();
    let a = agreed(&first, directory.path(), 8).await;
    let b = agreed(&second, directory.path(), 9).await;
    let payload = b"original operation";
    let binding_a = native_trade_support::binding(31, payload);
    let binding_b = native_trade_support::binding(32, payload);
    let (left, right) = tokio::join!(first.prepare_operation(a.quote().selection(), a.snapshot().cursor, binding_a),
        second.prepare_operation(b.quote().selection(), b.snapshot().cursor, binding_b));
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let (winner, loser, winning_binding, losing_binding, prepared) = if let Ok(prepared) = left {
        (&a, &b, binding_a, binding_b, prepared)
    } else {
        (&b, &a, binding_b, binding_a, right.unwrap())
    };
    let path = directory.path().join("operation");
    let key = [71; 32];
    let location = CapsuleLocation { path: &path, key: &key, namespace: [72; 32] };
    let digest = save_operation_capsule(location, winner.quote().selection(), &winning_binding, payload).unwrap();
    let released = first.release_operation(location, winner.quote().selection(), prepared.cursor, winning_binding.op_id, digest).await.unwrap();
    let unknown = first.mark_unknown(winner.quote().selection(), released.snapshot().cursor, winning_binding.op_id).await.unwrap();
    assert_eq!(unknown.state, OperationState::Unknown);
    assert_eq!(unknown.tx_hash, None);
    let retry = first.prepare_operation(winner.quote().selection(), unknown.cursor, winning_binding).await.unwrap();
    assert_eq!(retry, unknown);
    drop(first);
    drop(second);
    let restarted = NativeTradeStore::connect(DatabaseConfig { max_connections: 2, ..database.config.clone() }).await.unwrap();
    assert_eq!(restarted.prepare_operation(loser.quote().selection(), loser.snapshot().cursor, losing_binding).await.unwrap_err(), NativeTradeError::Conflict);
    let read = restarted.operation(winner.quote().selection(), winning_binding.op_id).await.unwrap();
    assert_eq!(read.state, OperationState::Unknown);
    assert_eq!(read.binding, winning_binding);
    drop(restarted);
    database.remove().await;
}

#[tokio::test]
async fn operation_release_cas_takeover_and_exact_retry_never_replace_original_bytes() {
    let database = TestDatabase::create("native_opcas").await;
    let first = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    first.migrate().await.unwrap();
    let second = NativeTradeStore::connect(database.config.clone()).await.unwrap();
    let directory = native_trade_support::private_directory();
    let quote = agreed(&first, directory.path(), 8).await;
    let selection = *quote.quote().selection();
    let payload = b"exact original operation after takeover";
    let binding = native_trade_support::binding(31, payload);
    let prepared = first.prepare_operation(&selection, quote.snapshot().cursor, binding).await.unwrap();
    let retry = second.prepare_operation(&selection, prepared.cursor, binding).await.unwrap();
    assert_eq!(retry, prepared);
    let mut changed = binding;
    changed.context_digest = [84; 32];
    assert_eq!(second.prepare_operation(&selection, prepared.cursor, changed).await.unwrap_err(), NativeTradeError::Conflict);
    let takeover = second.claim_writer(&selection, prepared.cursor).await.unwrap();
    let path = directory.path().join("operation");
    let key = [71; 32];
    let location = CapsuleLocation { path: &path, key: &key, namespace: [72; 32] };
    let digest = save_operation_capsule(location, &selection, &binding, payload).unwrap();
    assert_eq!(first.release_operation(location, &selection, prepared.cursor, binding.op_id, digest).await.unwrap_err(), NativeTradeError::StaleGeneration);
    let (left, right) = tokio::join!(first.release_operation(location, &selection, takeover.cursor, binding.op_id, digest),
        second.release_operation(location, &selection, takeover.cursor, binding.op_id, digest));
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let released = left.ok().or_else(|| right.ok()).unwrap();
    assert_eq!(released.payload(), payload);
    let retry = first.release_operation(location, &selection, released.snapshot().cursor, binding.op_id, digest).await.unwrap();
    assert_eq!(retry.snapshot(), released.snapshot());
    assert_eq!(retry.payload(), payload);
    assert_eq!(second.mark_submitted(&selection, takeover.cursor, binding.op_id, [85; 32]).await.unwrap_err(), NativeTradeError::StaleVersion);
    let unknown = first.mark_unknown(&selection, retry.snapshot().cursor, binding.op_id).await.unwrap();
    let observed = second.mark_submitted(&selection, unknown.cursor, binding.op_id, [85; 32]).await.unwrap();
    assert_eq!(observed.state, OperationState::Submitted);
    assert_eq!(observed.tx_hash, Some([85; 32]));
    assert_eq!(observed.binding, binding);
    assert_eq!(observed.capsule_digest, Some(digest));
    drop(first);
    drop(second);
    database.remove().await;
}
