//! Real PostgreSQL behavior tests. Compile-only until an isolated SQL scope is approved.
#![cfg(feature = "postgres-tests")]

#[path = "market_support/ledger.rs"]
mod support;

use sqlx::Row;
use ziquid_protocol::samechain::{Deployment, Role};
use ziquid_runtime::{
    database::DatabaseError,
    samechain::{
        backup::SnapshotOperation,
        journal::{JournalError, ReleaseJournal},
        release::{ReleaseBinding, ReleaseDigest},
    },
};
use support::TestDatabase;

fn binding() -> ReleaseBinding {
    ReleaseBinding {
        op_id: [0x11; 32],
        deployment: Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
            verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 },
        operation: SnapshotOperation::Fill, role: Role::A,
        packet_digest: [0x12; 32], program_vkey: [5; 32], journal_digest: [0x13; 32],
        expiry: u64::MAX, required_nfs: vec![[0x14; 32], [0x15; 32]],
    }
}

async fn open(database: &TestDatabase) -> ReleaseJournal {
    ReleaseJournal::connect(database.config.clone()).await.unwrap()
}

#[tokio::test]
async fn connecting_does_not_migrate_and_authorize_retries_do_not_rewrite_binding() {
    let database = TestDatabase::create("release_auth").await;
    let journal = open(&database).await;
    let selected = binding();
    assert_eq!(journal.authorize(&selected).await,
        Err(JournalError::Database(DatabaseError::SchemaNotReady)));
    journal.migrate().await.unwrap();
    journal.migrate().await.unwrap();
    let version = journal.authorize(&selected).await.unwrap();
    assert_eq!(version, 1);
    assert_eq!(journal.authorize(&selected).await.unwrap(), version);
    let mut other = selected.clone();
    other.packet_digest = [0x21; 32];
    assert_eq!(journal.authorize(&other).await, Err(JournalError::Conflict));
    assert_eq!(journal.authorize(&selected).await.unwrap(), version);
    assert_eq!(journal.read_release(&selected).await, Err(JournalError::NotReleased));
    drop(journal);
    database.remove().await;
}

#[tokio::test]
async fn commit_cas_rejects_stale_versions_and_conflicting_capsule_digests() {
    let database = TestDatabase::create("release_cas").await;
    let first = open(&database).await;
    first.migrate().await.unwrap();
    let second = open(&database).await;
    let selected = binding();
    let version = first.authorize(&selected).await.unwrap();
    let digest = ReleaseDigest([0x31; 32]);
    assert_eq!(second.commit_release(&selected, version + 1, digest).await,
        Err(JournalError::StaleVersion));
    assert_eq!(first.read_release(&selected).await, Err(JournalError::NotReleased));
    let committed = first.commit_release(&selected, version, digest).await.unwrap();
    assert_eq!(committed.op_id(), selected.op_id);
    assert_eq!(committed.binding_digest(), selected.digest().unwrap());
    assert_eq!(committed.release_digest(), digest);
    assert_eq!(second.commit_release(&selected, version, digest).await.unwrap(), committed);
    assert_eq!(second.commit_release(&selected, u64::MAX, digest).await.unwrap(), committed);
    assert_eq!(second.read_release(&selected).await.unwrap(), committed);
    assert_eq!(second.commit_release(&selected, version, ReleaseDigest([0x32; 32])).await,
        Err(JournalError::Conflict));
    assert_eq!(second.read_release(&selected).await.unwrap(), committed);
    let mut connection = database.connection().await;
    let row = sqlx::query(&format!("SELECT state,version,writer_generation FROM \"{}\".ops WHERE op_id=$1", database.config.schema))
        .bind(selected.op_id.as_slice()).fetch_one(&mut connection).await.unwrap();
    assert_eq!(row.get::<i16, _>("state"), 1);
    assert_eq!(row.get::<i64, _>("version"), 2);
    assert_eq!(row.get::<i64, _>("writer_generation"), 1);
    drop(connection);
    drop(first);
    drop(second);
    database.remove().await;
}

#[tokio::test]
async fn every_supplied_binding_field_is_checked_at_commit_and_read() {
    let database = TestDatabase::create("release_bound").await;
    let journal = open(&database).await;
    journal.migrate().await.unwrap();
    let selected = binding();
    let version = journal.authorize(&selected).await.unwrap();
    let digest = ReleaseDigest([0x31; 32]);
    let mut variants = Vec::new();
    for field in 0..9 {
        let mut changed = selected.clone();
        match field {
            0 => changed.deployment.chain_id += 1,
            1 => changed.operation = SnapshotOperation::Exit,
            2 => changed.role = Role::B,
            3 => changed.packet_digest = [0x21; 32],
            4 => changed.program_vkey = [0x22; 32],
            5 => changed.journal_digest = [0x23; 32],
            6 => changed.expiry -= 1,
            7 => changed.required_nfs[0] = [0x24; 32],
            _ => changed.required_nfs[1] = [0x25; 32],
        }
        if field == 1 { changed.required_nfs.truncate(1); }
        variants.push(changed);
    }
    for changed in &variants {
        assert_eq!(journal.commit_release(changed, version, digest).await,
            Err(JournalError::BindingMismatch));
        assert_eq!(journal.read_release(changed).await, Err(JournalError::BindingMismatch));
    }
    let mut missing = selected.clone();
    missing.op_id = [0x41; 32];
    assert_eq!(journal.commit_release(&missing, version, digest).await, Err(JournalError::NotReleased));
    assert_eq!(journal.read_release(&missing).await, Err(JournalError::NotReleased));
    journal.commit_release(&selected, version, digest).await.unwrap();
    for changed in &variants {
        assert_eq!(journal.read_release(changed).await, Err(JournalError::BindingMismatch));
    }
    drop(journal);
    database.remove().await;
}

#[tokio::test]
async fn stored_columns_cannot_hide_behind_an_unchanged_binding_digest() {
    let database = TestDatabase::create("release_cols").await;
    let journal = open(&database).await;
    journal.migrate().await.unwrap();
    // Each mutation leaves binding_digest unchanged: checking only that digest
    // would return a Committed for a row whose immutable statement was changed.
    for (index, assignment) in [
        "deployment_digest=decode(repeat('21',32),'hex')",
        "operation=2", "role=1", "packet_digest=decode(repeat('22',32),'hex')",
        "program_vkey=decode(repeat('23',32),'hex')",
        "journal_digest=decode(repeat('24',32),'hex')", "expiry=7",
        "required_nf_count=1,required_nf1=NULL",
        "required_nf0=decode(repeat('25',32),'hex')",
        "required_nf1=decode(repeat('26',32),'hex')",
        "binding_digest=decode(repeat('27',32),'hex')",
    ].iter().enumerate() {
        let mut selected = binding();
        selected.op_id = [u8::try_from(index + 1).unwrap(); 32];
        let version = journal.authorize(&selected).await.unwrap();
        let mut connection = database.connection().await;
        sqlx::query(&format!("UPDATE \"{}\".ops SET {assignment} WHERE op_id=$1", database.config.schema))
            .bind(selected.op_id.as_slice()).execute(&mut connection).await.unwrap();
        assert_eq!(journal.commit_release(&selected, version, ReleaseDigest([0x31; 32])).await,
            Err(JournalError::BindingMismatch));
        assert_eq!(journal.read_release(&selected).await, Err(JournalError::BindingMismatch));
    }
    drop(journal);
    database.remove().await;
}

#[tokio::test]
async fn authorized_restart_requires_commit_before_any_release_read() {
    let database = TestDatabase::create("release_restart").await;
    let selected = binding();
    let first = open(&database).await;
    first.migrate().await.unwrap();
    let version = first.authorize(&selected).await.unwrap();
    drop(first);
    let restarted = open(&database).await;
    assert_eq!(restarted.authorize(&selected).await.unwrap(), version);
    assert_eq!(restarted.read_release(&selected).await, Err(JournalError::NotReleased));
    // The journal accepts only the caller's capsule digest, not capsule bytes;
    // authentication/existence are exercised separately by release custody tests.
    let digest = ReleaseDigest([0x31; 32]);
    let committed = restarted.commit_release(&selected, version, digest).await.unwrap();
    drop(restarted);
    let reopened = open(&database).await;
    assert_eq!(reopened.read_release(&selected).await.unwrap(), committed);
    assert_eq!(reopened.authorize(&selected).await.unwrap(), 2);
    assert_eq!(reopened.commit_release(&selected, 2, digest).await.unwrap(), committed);
    drop(reopened);
    database.remove().await;
}

#[tokio::test]
async fn creation_accepts_both_roles_and_invalid_bindings_never_insert() {
    let database = TestDatabase::create("release_roles").await;
    let journal = open(&database).await;
    journal.migrate().await.unwrap();
    for (index, role) in [Role::A, Role::B].into_iter().enumerate() {
        let mut selected = binding();
        selected.op_id = [u8::try_from(index + 1).unwrap(); 32];
        selected.operation = SnapshotOperation::Creation;
        selected.role = role;
        selected.required_nfs.clear();
        let version = journal.authorize(&selected).await.unwrap();
        assert!(journal.commit_release(&selected, version, ReleaseDigest([0x31; 32])).await.is_ok());
    }
    let mut invalid = binding();
    invalid.expiry = 0;
    assert_eq!(journal.authorize(&invalid).await, Err(JournalError::InvalidBinding));
    assert_eq!(journal.commit_release(&invalid, 1, ReleaseDigest([0x31; 32])).await,
        Err(JournalError::InvalidBinding));
    assert_eq!(journal.read_release(&invalid).await, Err(JournalError::InvalidBinding));
    drop(journal);
    database.remove().await;
}

#[tokio::test]
async fn raw_insert_of_a_33_byte_digest_is_rejected_by_the_database_check() {
    let database = TestDatabase::create("release_check").await;
    let journal = open(&database).await;
    journal.migrate().await.unwrap();
    journal.authorize(&binding()).await.unwrap();
    let mut connection = database.connection().await;
    let error = sqlx::query(&format!(
        "INSERT INTO \"{0}\".ops (op_id,deployment_digest,operation,role,packet_digest,program_vkey,journal_digest,expiry,required_nf_count,required_nf0,required_nf1,binding_digest,release_digest,state,version,writer_generation) \
         SELECT $1,deployment_digest,operation,role,$2,program_vkey,journal_digest,expiry,required_nf_count,required_nf0,required_nf1,binding_digest,release_digest,state,version,writer_generation FROM \"{0}\".ops", database.config.schema))
        .bind([0x41_u8; 32].as_slice()).bind([0x42_u8; 33].as_slice())
        .execute(&mut connection).await.unwrap_err();
    assert_eq!(error.as_database_error().unwrap().code().as_deref(), Some("23514"));
    let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM \"{}\".ops", database.config.schema))
        .fetch_one(&mut connection).await.unwrap();
    assert_eq!(count, 1);
    drop(connection);
    drop(journal);
    database.remove().await;
}
