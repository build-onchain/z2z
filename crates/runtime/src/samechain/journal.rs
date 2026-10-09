//! Digests-only certificate release journal; not settlement, finality or payment authority.
//! Connecting never migrates. Successful release handles follow a synchronous commit
//! and a matching row read. Capsule authentication remains the caller's responsibility.
use std::{fmt, path::Path};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction, migrate::Migrator, postgres::PgRow};
use crate::database::{self, DatabaseConfig, DatabaseError, SchemaSpec};
use super::release::{BindingDigest, ReleaseBinding, ReleaseDigest};

const SCHEMA: SchemaSpec = SchemaSpec {
    application: "samechain", version: 1, relations: &["ops"], domains: &[], functions: &[],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    Database(DatabaseError), Conflict, BindingMismatch, NotReleased, StaleVersion, InvalidBinding,
}
impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => fmt::Display::fmt(error, formatter),
            Self::Conflict => formatter.write_str("samechain release journal conflict"),
            Self::BindingMismatch => formatter.write_str("samechain release binding mismatch"),
            Self::NotReleased => formatter.write_str("samechain certificate is not released"),
            Self::StaleVersion => formatter.write_str("samechain release version is stale"),
            Self::InvalidBinding => formatter.write_str("samechain release binding is invalid"),
        }
    }
}
impl std::error::Error for JournalError {}
impl From<DatabaseError> for JournalError {
    fn from(error: DatabaseError) -> Self { Self::Database(error) }
}
impl From<sqlx::Error> for JournalError {
    fn from(error: sqlx::Error) -> Self { DatabaseError::from(error).into() }
}

/// Only this journal can construct a handle, after a matching transaction commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Committed {
    op_id: [u8; 32], binding: BindingDigest, release: ReleaseDigest,
}
impl Committed {
    pub fn op_id(&self) -> [u8; 32] { self.op_id }
    pub fn binding_digest(&self) -> BindingDigest { self.binding }
    pub fn release_digest(&self) -> ReleaseDigest { self.release }
}

pub struct ReleaseJournal {
    pool: PgPool, config: DatabaseConfig, queries: Queries,
}

struct Queries { row: String, authorize: String, release: String }
impl Queries {
    fn new(schema: &str) -> Self {
        let ops = format!("\"{schema}\".ops");
        Self {
            row: format!("SELECT op_id,deployment_digest,operation,role,packet_digest,program_vkey,\
                journal_digest,expiry::text AS expiry,required_nf_count,required_nf0,required_nf1,\
                binding_digest,release_digest,state,version,writer_generation FROM {ops} WHERE op_id=$1 FOR UPDATE"),
            authorize: format!("INSERT INTO {ops} (op_id,deployment_digest,operation,role,packet_digest,\
                program_vkey,journal_digest,expiry,required_nf_count,required_nf0,required_nf1,\
                binding_digest,release_digest,state,version,writer_generation) \
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8::text::numeric,$9,$10,$11,$12,NULL,0,1,1)"),
            release: format!("UPDATE {ops} SET release_digest=$2,state=1,version=version+1 \
                WHERE op_id=$1 AND state=0 AND version=$3"),
        }
    }
}

// SQL stores these fixed typed columns, never a binding frame or certificate bytes.
#[derive(Eq, PartialEq)]
struct BindingColumns {
    op_id: [u8; 32], deployment: [u8; 32], operation: i16, role: i16,
    packet: [u8; 32], program: [u8; 32], journal: [u8; 32], expiry: u64,
    nf_count: i16, nfs: [Option<[u8; 32]>; 2], digest: BindingDigest,
}
impl BindingColumns {
    fn selected(binding: &ReleaseBinding) -> Result<Self, JournalError> {
        let digest = binding.digest().map_err(|_| JournalError::InvalidBinding)?;
        let deployment = binding.deployment.encode().map_err(|_| JournalError::InvalidBinding)?;
        Ok(Self {
            op_id: binding.op_id, deployment: Sha256::digest(&deployment).into(),
            operation: binding.operation as i16, role: binding.role as i16,
            packet: binding.packet_digest, program: binding.program_vkey, journal: binding.journal_digest,
            expiry: binding.expiry, nf_count: binding.required_nfs.len() as i16,
            nfs: [binding.required_nfs.first().copied(), binding.required_nfs.get(1).copied()], digest,
        })
    }

    fn stored(row: &PgRow) -> Result<Self, JournalError> {
        let expiry: &str = row.try_get("expiry")?;
        Ok(Self {
            op_id: id(row.try_get("op_id")?)?, deployment: id(row.try_get("deployment_digest")?)?,
            operation: row.try_get("operation")?, role: row.try_get("role")?,
            packet: id(row.try_get("packet_digest")?)?, program: id(row.try_get("program_vkey")?)?,
            journal: id(row.try_get("journal_digest")?)?,
            expiry: expiry.parse().map_err(|_| invalid_record())?, nf_count: row.try_get("required_nf_count")?,
            nfs: [optional_id(row, "required_nf0")?, optional_id(row, "required_nf1")?],
            digest: BindingDigest(id(row.try_get("binding_digest")?)?),
        })
    }
}

struct Stored { binding: BindingColumns, release: Option<ReleaseDigest>, state: i16, version: u64 }
impl Stored {
    fn decode(row: PgRow) -> Result<Self, JournalError> {
        let binding = BindingColumns::stored(&row)?;
        let release = optional_id(&row, "release_digest")?.map(ReleaseDigest);
        let state = row.try_get("state")?;
        let version = u64::try_from(row.try_get::<i64, _>("version")?).map_err(|_| invalid_record())?;
        if version == 0 || !matches!((state, release), (0, None) | (1, Some(_))) {
            return Err(invalid_record());
        }
        Ok(Self { binding, release, state, version })
    }
}

impl ReleaseJournal {
    /// Verified TLS and session policy only; absent schemas require explicit migrate.
    pub async fn connect(config: DatabaseConfig) -> Result<Self, JournalError> {
        let pool = database::connect(&config).await?;
        let queries = Queries::new(&config.schema);
        Ok(Self { pool, config, queries })
    }

    pub async fn migrate(&self) -> Result<(), JournalError> {
        let migrations = Migrator::new(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/samechain")))
            .await.map_err(|_| DatabaseError::Migration)?;
        database::migrate(&self.pool, &self.config, SCHEMA, &migrations).await?;
        Ok(())
    }

    async fn lock_scope(&self, op_id: &[u8; 32]) -> Result<Transaction<'static, Postgres>, JournalError> {
        database::ensure_ready(&self.pool, &self.config, SCHEMA).await?;
        let mut transaction = self.pool.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await?;
        sqlx::query("SET LOCAL synchronous_commit TO on").execute(&mut *transaction).await?;
        // The stable advisory scope also serializes absent-row authorization.
        // Read the row in a separate statement after waiting, under READ COMMITTED.
        sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(current_database()||':'||$1||':'||pg_catalog.encode($2::bytea,'hex'),0))")
            .bind(&self.config.schema).bind(op_id.as_slice()).execute(&mut *transaction).await?;
        Ok(transaction)
    }

    async fn row(&self, transaction: &mut Transaction<'_, Postgres>, op_id: &[u8; 32]) -> Result<Option<Stored>, JournalError> {
        sqlx::query(&self.queries.row).bind(op_id.as_slice()).fetch_optional(&mut **transaction).await?
            .map(Stored::decode).transpose()
    }

    pub async fn authorize(&self, binding: &ReleaseBinding) -> Result<u64, JournalError> {
        let selected = BindingColumns::selected(binding)?;
        let mut transaction = self.lock_scope(&selected.op_id).await?;
        if let Some(row) = self.row(&mut transaction, &selected.op_id).await? {
            if row.binding != selected { return Err(JournalError::Conflict); }
            transaction.commit().await?;
            return Ok(row.version);
        }
        let affected = sqlx::query(&self.queries.authorize)
            .bind(selected.op_id.as_slice()).bind(selected.deployment.as_slice())
            .bind(selected.operation).bind(selected.role).bind(selected.packet.as_slice())
            .bind(selected.program.as_slice()).bind(selected.journal.as_slice())
            .bind(selected.expiry.to_string()).bind(selected.nf_count)
            .bind(selected.nfs[0].as_ref().map(|nf| nf.as_slice()))
            .bind(selected.nfs[1].as_ref().map(|nf| nf.as_slice()))
            .bind(selected.digest.0.as_slice()).execute(&mut *transaction).await?.rows_affected();
        require_one(affected)?;
        let row = self.row(&mut transaction, &selected.op_id).await?.ok_or_else(invalid_record)?;
        if row.binding != selected || row.state != 0 || row.version != 1 { return Err(invalid_record()); }
        transaction.commit().await?;
        Ok(row.version)
    }

    pub async fn commit_release(&self, binding: &ReleaseBinding, expected_version: u64, release: ReleaseDigest) -> Result<Committed, JournalError> {
        let selected = BindingColumns::selected(binding)?;
        let mut transaction = self.lock_scope(&selected.op_id).await?;
        let mut row = self.row(&mut transaction, &selected.op_id).await?.ok_or(JournalError::NotReleased)?;
        if row.binding != selected { return Err(JournalError::BindingMismatch); }
        if row.state == 0 {
            if row.version != expected_version { return Err(JournalError::StaleVersion); }
            let next = row.version.checked_add(1).filter(|v| *v <= i64::MAX as u64)
                .ok_or(JournalError::StaleVersion)?;
            let affected = sqlx::query(&self.queries.release).bind(selected.op_id.as_slice())
                .bind(release.0.as_slice()).bind(expected_version as i64)
                .execute(&mut *transaction).await?.rows_affected();
            require_one(affected)?;
            row = self.row(&mut transaction, &selected.op_id).await?.ok_or_else(invalid_record)?;
            if row.binding != selected || row.state != 1 || row.version != next || row.release != Some(release) {
                return Err(invalid_record());
            }
        } else if row.release != Some(release) {
            return Err(JournalError::Conflict);
        }
        let release = row.release.ok_or_else(invalid_record)?;
        transaction.commit().await?;
        Ok(Committed { op_id: row.binding.op_id, binding: row.binding.digest, release })
    }

    pub async fn read_release(&self, binding: &ReleaseBinding) -> Result<Committed, JournalError> {
        let selected = BindingColumns::selected(binding)?;
        let mut transaction = self.lock_scope(&selected.op_id).await?;
        let row = self.row(&mut transaction, &selected.op_id).await?.ok_or(JournalError::NotReleased)?;
        if row.binding != selected { return Err(JournalError::BindingMismatch); }
        let release = row.release.ok_or(JournalError::NotReleased)?;
        transaction.commit().await?;
        Ok(Committed { op_id: row.binding.op_id, binding: row.binding.digest, release })
    }
}

fn invalid_record() -> JournalError { DatabaseError::SchemaIdentity.into() }
fn require_one(affected: u64) -> Result<(), JournalError> {
    if affected == 1 { Ok(()) } else { Err(invalid_record()) }
}
fn id(bytes: &[u8]) -> Result<[u8; 32], JournalError> {
    bytes.try_into().map_err(|_| invalid_record())
}
fn optional_id(row: &PgRow, field: &str) -> Result<Option<[u8; 32]>, JournalError> {
    row.try_get::<Option<&[u8]>, _>(field)?.map(id).transpose()
}
