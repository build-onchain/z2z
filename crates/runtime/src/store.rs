//! Actor-private inventory reservations and persist-before-send funding intents.
//!
//! Each record belongs to an explicit actor/asset/deployment [`InventoryScope`].
//! These IDs separate accounting; they do not authenticate an actor or establish
//! ownership. The owner must select the correct private PostgreSQL configuration
//! and scope. This schema/history never shares market credit or settlement state.
//! `available` is caller-authenticated TOTAL allocation capacity, including every
//! Reserved, FundingPrepared, SubmissionUnknown and Armed reservation. It is not
//! a post-reservation/post-funding spendable balance. The caller must exclude
//! unrelated obligations and execution fees before supplying this cap.
//!
//! Only an unfunded Reserved record can release capacity. Preparing a funding
//! intent irreversibly fences local cancellation before any transaction hash
//! exists. No TTL, missing receipt, worker result or observer cache frees funds.
//! Armed records are caller-authenticated observations, NOT verified financial
//! facts or proof of finality. There is deliberately no paid/refunded/finish API.
//! This journal holds IDs, context/payload digests and exact amounts, never keys,
//! unsigned/signed transaction bodies, Q packets or private proving witnesses.
//! Connecting never migrates or imports old files. Existing SQLite journals and
//! sidecars must remain untouched; a new scope is not recovery of funded records.

use std::{error::Error, fmt, path::Path};

use futures_util::TryStreamExt;
use sqlx::{
    PgConnection, PgPool, Postgres, Row, Transaction,
    migrate::Migrator,
    postgres::{PgArguments, PgRow},
    query::Query,
};
use ziquid_protocol::NativeAmount;

use crate::database::{self, DatabaseConfig, DatabaseError, SchemaSpec};

const SCHEMA: SchemaSpec = SchemaSpec {
    application: "inventory",
    version: 1,
    relations: &["inventory_scopes", "reservations"],
    domains: &[],
    functions: &[],
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Database(DatabaseError),
    ZeroAmount,
    AmountOverflow,
    InsufficientInventory,
    ReservationMismatch,
    UnknownOrder,
    UnknownOperation,
    OperationMismatch,
    OrderAlreadyPrepared,
    FundingFenced,
    SubmissionMismatch,
    ContextMismatch,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Database(error) => return fmt::Display::fmt(error, f),
            Self::ZeroAmount => "reservation amount must be nonzero",
            Self::AmountOverflow => "aggregate reservation amount exceeds 256 bits",
            Self::InsufficientInventory => "reservation exceeds total inventory capacity",
            Self::ReservationMismatch => "order is already bound to a different context or amount",
            Self::UnknownOrder => "order has no reservation",
            Self::UnknownOperation => "operation has no persisted funding intent",
            Self::OperationMismatch => "funding operation is bound to a different order or payload",
            Self::OrderAlreadyPrepared => "order already has another funding operation",
            Self::FundingFenced => "funding preparation or cancellation prevents this transition",
            Self::SubmissionMismatch => "funding operation is bound to a different transaction hash",
            Self::ContextMismatch => "arming observation does not match the reserved context",
        };
        f.write_str(message)
    }
}

// Never retain a raw SQLx/server error or expose its source, URI or SQL payload.
impl fmt::Debug for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => f.debug_tuple("Database").field(error).finish(),
            _ => fmt::Display::fmt(self, f),
        }
    }
}

impl Error for StoreError {}

impl From<DatabaseError> for StoreError {
    fn from(error: DatabaseError) -> Self { Self::Database(error) }
}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self { DatabaseError::from(error).into() }
}

/// Accounting labels only: caller authentication and actual asset authority are
/// outside this journal. Changing any field selects a different inventory pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryScope {
    pub actor: [u8; 32],
    pub asset: [u8; 32],
    pub deployment: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationState {
    Reserved,
    FundingPrepared,
    SubmissionUnknown,
    /// Caller-authenticated arming observation, not a verified settlement fact.
    Armed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub order_id: [u8; 32],
    pub context_digest: [u8; 32],
    pub amount: NativeAmount,
    pub state: ReservationState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingState {
    Prepared,
    SubmissionUnknown,
    /// Caller-authenticated arming observation, not proof of payment/finality.
    Armed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundingIntent {
    pub order_id: [u8; 32],
    pub context_digest: [u8; 32],
    pub operation_id: [u8; 32],
    pub unsigned_payload_digest: [u8; 32],
    pub transaction_hash: Option<[u8; 32]>,
    pub state: FundingState,
}

/// A private SQLx pool and immutable scope. Every operation uses READ COMMITTED
/// and locks the stable parent scope before reading or changing reservations.
/// Fresh scopes serialize at parent insertion uniqueness before the row lock;
/// subsequent statements see fresh committed snapshots after a lock wait.
/// A successful mutating return follows synchronous PostgreSQL commit. Server
/// storage/replication durability and private-role administration remain operator
/// responsibilities, not source/destination payment guarantees from this store.
pub struct ActorStore {
    pool: PgPool,
    config: DatabaseConfig,
    scope: InventoryScope,
    queries: Queries,
}

// Schema qualification is constructed once from a validated identifier, never
// from a URI or caller-supplied SQL. Per-operation queries need no formatting.
struct Queries {
    create_scope: String,
    lock_scope: String,
    reservation: String,
    funding: String,
    active_amounts: String,
    reserve: String,
    cancel: String,
    prepare: String,
    unknown: String,
    armed: String,
}

impl Queries {
    fn new(schema: &str) -> Self {
        let scopes = format!("\"{schema}\".inventory_scopes");
        let reservations = format!("\"{schema}\".reservations");
        let scope = "actor = $1 AND asset = $2 AND deployment = $3";
        let record = format!(
            "SELECT actor, asset, deployment, order_id, context_digest, amount, state, \
             operation_id, unsigned_payload_digest, transaction_hash FROM {reservations} WHERE {scope}"
        );
        Self {
            create_scope: format!(
                "INSERT INTO {scopes} (actor, asset, deployment) VALUES ($1, $2, $3) \
                 ON CONFLICT (actor, asset, deployment) DO NOTHING"
            ),
            lock_scope: format!("SELECT actor FROM {scopes} WHERE {scope} FOR UPDATE"),
            reservation: format!("{record} AND order_id = $4"),
            funding: format!("{record} AND operation_id = $4"),
            active_amounts: format!("SELECT amount FROM {reservations} WHERE {scope} AND state <> 4"),
            reserve: format!(
                "INSERT INTO {reservations} (actor, asset, deployment, order_id, context_digest, amount, state) \
                 VALUES ($1, $2, $3, $4, $5, $6, 0)"
            ),
            cancel: format!("UPDATE {reservations} SET state = 4 WHERE {scope} AND order_id = $4"),
            prepare: format!(
                "UPDATE {reservations} SET state = 1, operation_id = $5, unsigned_payload_digest = $6 \
                 WHERE {scope} AND order_id = $4"
            ),
            unknown: format!(
                "UPDATE {reservations} SET transaction_hash = $5, state = CASE WHEN state = 1 THEN 2 ELSE state END \
                 WHERE {scope} AND operation_id = $4"
            ),
            armed: format!("UPDATE {reservations} SET state = 3 WHERE {scope} AND operation_id = $4"),
        }
    }
}

impl ActorStore {
    /// Establish only the verified private transport. An absent authorized schema
    /// permits construction for explicit `migrate`; operations require completed
    /// inventory identity. Never creates/adopts/imports a schema implicitly.
    pub async fn connect(config: DatabaseConfig, scope: InventoryScope) -> Result<Self, StoreError> {
        let pool = database::connect(&config).await?;
        let queries = Queries::new(&config.schema);
        Ok(Self { pool, config, scope, queries })
    }

    /// Create only the absent configured inventory schema or validate its exact
    /// existing identity/history. The shared helper commits migration atomically.
    /// Distribution must retain the original crate-local migration bytes.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let migrations = Migrator::new(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/inventory")))
            .await.map_err(|_| StoreError::Database(DatabaseError::Migration))?;
        database::migrate(&self.pool, &self.config, SCHEMA, &migrations).await?;
        Ok(())
    }

    fn query<'q>(&'q self, sql: &'q str) -> Query<'q, Postgres, PgArguments> {
        sqlx::query(sql)
            .bind(self.scope.actor.as_slice())
            .bind(self.scope.asset.as_slice())
            .bind(self.scope.deployment.as_slice())
    }

    async fn lock_scope(&self) -> Result<Transaction<'static, Postgres>, StoreError> {
        database::ensure_ready(&self.pool, &self.config, SCHEMA).await?;
        let mut transaction = self.pool.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await?;
        sqlx::query("SET LOCAL synchronous_commit TO on").execute(&mut *transaction).await?;
        // New parents compete at the primary key. Do not combine this insertion
        // and the SELECT into a single snapshot/CTE: a waiting fresh inserter
        // must issue a fresh statement before locking/reading the winning row.
        self.query(&self.queries.create_scope).execute(&mut *transaction).await?;
        self.query(&self.queries.lock_scope).fetch_one(&mut *transaction).await?;
        Ok(transaction)
    }

    async fn find_reservation(
        &self, connection: &mut PgConnection, order_id: [u8; 32],
    ) -> Result<Option<Reservation>, StoreError> {
        self.query(&self.queries.reservation).bind(order_id.as_slice())
            .fetch_optional(connection).await?
            .map(|row| decode_record(&row, self.scope).map(|record| record.0)).transpose()
    }

    async fn find_funding(
        &self, connection: &mut PgConnection, operation_id: [u8; 32],
    ) -> Result<Option<FundingIntent>, StoreError> {
        self.query(&self.queries.funding).bind(operation_id.as_slice())
            .fetch_optional(connection).await?
            .map(|row| {
                decode_record(&row, self.scope)?.1.ok_or_else(invalid_record)
            }).transpose()
    }

    /// Reserve exact native amount against caller-provided TOTAL capacity.
    /// Exact order/context/amount retries return the existing state, including
    /// Cancelled; retries never resurrect an order or reserve its amount twice.
    pub async fn reserve(
        &mut self,
        order_id: [u8; 32],
        context_digest: [u8; 32],
        amount: NativeAmount,
        available: NativeAmount,
    ) -> Result<Reservation, StoreError> {
        let mut transaction = self.lock_scope().await?;
        if let Some(existing) = self.find_reservation(&mut transaction, order_id).await? {
            if existing.context_digest != context_digest || existing.amount != amount {
                return Err(StoreError::ReservationMismatch);
            }
            transaction.commit().await?;
            return Ok(existing);
        }
        if amount.get().is_zero() { return Err(StoreError::ZeroAmount); }
        let mut total = amount.get();
        {
            // ponytail: O(n) active-reservation scan; retain checked Rust U256
            // accounting if measured throughput warrants a durable aggregate.
            let mut rows = self.query(&self.queries.active_amounts).fetch(&mut *transaction);
            while let Some(row) = rows.try_next().await? {
                let active = decode_amount(row.try_get::<&[u8], _>("amount")?)?;
                total = total.checked_add(active.get()).ok_or(StoreError::AmountOverflow)?;
            }
        }
        if total > available.get() { return Err(StoreError::InsufficientInventory); }
        let encoded = amount.to_be_bytes();
        require_one(self.query(&self.queries.reserve)
            .bind(order_id.as_slice()).bind(context_digest.as_slice()).bind(encoded.as_slice())
            .execute(&mut *transaction).await?.rows_affected())?;
        transaction.commit().await?;
        Ok(Reservation { order_id, context_digest, amount, state: ReservationState::Reserved })
    }

    pub async fn reservation(&self, order_id: [u8; 32]) -> Result<Option<Reservation>, StoreError> {
        let mut transaction = self.lock_scope().await?;
        let reservation = self.find_reservation(&mut transaction, order_id).await?;
        transaction.commit().await?;
        Ok(reservation)
    }

    /// Idempotently cancel only a Reserved order. Preparing funding closes this
    /// path before the intent can be returned for export/sign/send.
    pub async fn cancel(&mut self, order_id: [u8; 32]) -> Result<Reservation, StoreError> {
        let mut transaction = self.lock_scope().await?;
        let mut reservation = self.find_reservation(&mut transaction, order_id).await?
            .ok_or(StoreError::UnknownOrder)?;
        match reservation.state {
            ReservationState::Reserved => {
                require_one(self.query(&self.queries.cancel).bind(order_id.as_slice())
                    .execute(&mut *transaction).await?.rows_affected())?;
                reservation.state = ReservationState::Cancelled;
            }
            ReservationState::Cancelled => {}
            _ => return Err(StoreError::FundingFenced),
        }
        transaction.commit().await?;
        Ok(reservation)
    }

    /// Persist the immutable operation/payload digest before any payload leaves
    /// the actor or any signing/submission request. The caller must ensure the
    /// digest covers the exact authorized unsigned call; this store cannot inspect
    /// a payload or authorize a signer. Each order has at most one operation,
    /// including after crash, unknown submission and arming observations.
    pub async fn prepare_funding(
        &mut self,
        order_id: [u8; 32],
        operation_id: [u8; 32],
        unsigned_payload_digest: [u8; 32],
    ) -> Result<FundingIntent, StoreError> {
        let mut transaction = self.lock_scope().await?;
        if let Some(existing) = self.find_funding(&mut transaction, operation_id).await? {
            if existing.order_id != order_id || existing.unsigned_payload_digest != unsigned_payload_digest {
                return Err(StoreError::OperationMismatch);
            }
            transaction.commit().await?;
            return Ok(existing);
        }
        let reservation = self.find_reservation(&mut transaction, order_id).await?
            .ok_or(StoreError::UnknownOrder)?;
        match reservation.state {
            ReservationState::Reserved => {}
            ReservationState::Cancelled => return Err(StoreError::FundingFenced),
            _ => return Err(StoreError::OrderAlreadyPrepared),
        }
        require_one(self.query(&self.queries.prepare)
            .bind(order_id.as_slice()).bind(operation_id.as_slice()).bind(unsigned_payload_digest.as_slice())
            .execute(&mut *transaction).await?.rows_affected())?;
        transaction.commit().await?;
        Ok(FundingIntent {
            order_id, context_digest: reservation.context_digest, operation_id,
            unsigned_payload_digest, transaction_hash: None, state: FundingState::Prepared,
        })
    }

    pub async fn funding(&self, operation_id: [u8; 32]) -> Result<Option<FundingIntent>, StoreError> {
        let mut transaction = self.lock_scope().await?;
        let intent = self.find_funding(&mut transaction, operation_id).await?;
        transaction.commit().await?;
        Ok(intent)
    }

    /// Record uncertain submission against a persisted prepared operation.
    /// A transaction hash is not evidence of acceptance, payment or failure.
    /// Exact retries preserve Armed rather than downgrading the observation.
    pub async fn mark_submission_unknown(
        &mut self,
        operation_id: [u8; 32],
        transaction_hash: [u8; 32],
    ) -> Result<FundingIntent, StoreError> {
        let mut transaction = self.lock_scope().await?;
        let mut intent = self.find_funding(&mut transaction, operation_id).await?
            .ok_or(StoreError::UnknownOperation)?;
        if let Some(existing) = intent.transaction_hash {
            if existing != transaction_hash { return Err(StoreError::SubmissionMismatch); }
        } else {
            require_one(self.query(&self.queries.unknown)
                .bind(operation_id.as_slice()).bind(transaction_hash.as_slice())
                .execute(&mut *transaction).await?.rows_affected())?;
            intent.transaction_hash = Some(transaction_hash);
        }
        if intent.state == FundingState::Prepared { intent.state = FundingState::SubmissionUnknown; }
        transaction.commit().await?;
        Ok(intent)
    }

    /// Record ONLY a caller-authenticated, exact-context arming observation.
    /// The caller must independently check destination identity, amount, fixed
    /// beneficiaries and finality. Matching the digest does not do those checks
    /// and creates no verified fact. Mismatches leave Prepared/Unknown intact;
    /// Armed still consumes capacity and forbids cancellation.
    pub async fn mark_armed(
        &mut self,
        operation_id: [u8; 32],
        observed_context_digest: [u8; 32],
    ) -> Result<FundingIntent, StoreError> {
        let mut transaction = self.lock_scope().await?;
        let mut intent = self.find_funding(&mut transaction, operation_id).await?
            .ok_or(StoreError::UnknownOperation)?;
        if intent.context_digest != observed_context_digest { return Err(StoreError::ContextMismatch); }
        if intent.state != FundingState::Armed {
            require_one(self.query(&self.queries.armed).bind(operation_id.as_slice())
                .execute(&mut *transaction).await?.rows_affected())?;
            intent.state = FundingState::Armed;
        }
        transaction.commit().await?;
        Ok(intent)
    }
}

fn invalid_record() -> StoreError { DatabaseError::SchemaIdentity.into() }

// Suppressed/re-written SQL must never yield an invented financial transition.
// The locked parent and immutable scope/order keys make exactly one row the
// only valid result for every actual reservation insert/state mutation.
fn require_one(affected: u64) -> Result<(), StoreError> {
    if affected == 1 { Ok(()) } else { Err(invalid_record()) }
}

fn decode_id(encoded: &[u8]) -> Result<[u8; 32], StoreError> {
    encoded.try_into().map_err(|_| invalid_record())
}

fn decode_amount(encoded: &[u8]) -> Result<NativeAmount, StoreError> {
    let amount = NativeAmount::from_be_bytes(decode_id(encoded)?);
    if amount.get().is_zero() { return Err(invalid_record()); }
    Ok(amount)
}

fn optional_id(row: &PgRow, field: &str) -> Result<Option<[u8; 32]>, StoreError> {
    row.try_get::<Option<&[u8]>, _>(field)?.map(decode_id).transpose()
}

fn decode_state(
    state: i16,
    operation: Option<[u8; 32]>,
    payload: Option<[u8; 32]>,
    hash: Option<[u8; 32]>,
) -> Result<ReservationState, StoreError> {
    match (state, operation, payload, hash) {
        (0, None, None, None) => Ok(ReservationState::Reserved),
        (1, Some(_), Some(_), None) => Ok(ReservationState::FundingPrepared),
        (2, Some(_), Some(_), Some(_)) => Ok(ReservationState::SubmissionUnknown),
        (3, Some(_), Some(_), _) => Ok(ReservationState::Armed),
        (4, None, None, None) => Ok(ReservationState::Cancelled),
        _ => Err(invalid_record()),
    }
}

fn decode_record(row: &PgRow, scope: InventoryScope) -> Result<(Reservation, Option<FundingIntent>), StoreError> {
    let stored_scope = InventoryScope {
        actor: decode_id(row.try_get::<&[u8], _>("actor")?)?,
        asset: decode_id(row.try_get::<&[u8], _>("asset")?)?,
        deployment: decode_id(row.try_get::<&[u8], _>("deployment")?)?,
    };
    if stored_scope != scope { return Err(invalid_record()); }
    let operation_id = optional_id(row, "operation_id")?;
    let unsigned_payload_digest = optional_id(row, "unsigned_payload_digest")?;
    let transaction_hash = optional_id(row, "transaction_hash")?;
    let state = decode_state(row.try_get("state")?, operation_id, unsigned_payload_digest, transaction_hash)?;
    let reservation = Reservation {
        order_id: decode_id(row.try_get::<&[u8], _>("order_id")?)?,
        context_digest: decode_id(row.try_get::<&[u8], _>("context_digest")?)?,
        amount: decode_amount(row.try_get::<&[u8], _>("amount")?)?,
        state,
    };
    let funding_state = match state {
        ReservationState::FundingPrepared => Some(FundingState::Prepared),
        ReservationState::SubmissionUnknown => Some(FundingState::SubmissionUnknown),
        ReservationState::Armed => Some(FundingState::Armed),
        ReservationState::Reserved | ReservationState::Cancelled => None,
    };
    let funding = match funding_state {
        Some(state) => Some(FundingIntent {
            order_id: reservation.order_id, context_digest: reservation.context_digest,
            operation_id: operation_id.ok_or_else(invalid_record)?,
            unsigned_payload_digest: unsigned_payload_digest.ok_or_else(invalid_record)?,
            transaction_hash, state,
        }),
        None => None,
    };
    Ok((reservation, funding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_funding_shapes_reject_inconsistent_nullable_fields() {
        let id = Some([1; 32]);
        for state in [-1, 0, 1, 2, 3, 4, 5] {
            for operation in [None, id] {
                for payload in [None, id] {
                    for hash in [None, id] {
                        let expected = match (state, operation.is_some(), payload.is_some(), hash.is_some()) {
                            (0, false, false, false) => Some(ReservationState::Reserved),
                            (1, true, true, false) => Some(ReservationState::FundingPrepared),
                            (2, true, true, true) => Some(ReservationState::SubmissionUnknown),
                            (3, true, true, _) => Some(ReservationState::Armed),
                            (4, false, false, false) => Some(ReservationState::Cancelled),
                            _ => None,
                        };
                        assert_eq!(decode_state(state, operation, payload, hash).ok(), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn persisted_amounts_are_exact_nonzero_unsigned_256_bits() {
        for bytes in [&[][..], &[1; 31][..], &[1; 33][..], &[0; 32][..]] {
            assert!(decode_amount(bytes).is_err());
        }
        let maximum = [0xff; 32];
        assert_eq!(decode_amount(&maximum).unwrap().to_be_bytes(), maximum);
        let mut high = [0; 32];
        high[0] = 0x80;
        assert_eq!(decode_amount(&high).unwrap().to_be_bytes(), high);
    }

    #[test]
    fn raw_database_failures_are_discarded_before_reporting() {
        let error = StoreError::from(sqlx::Error::Protocol("synthetic-private-uri-and-password".into()));
        assert_eq!(error, StoreError::Database(DatabaseError::Query));
        assert!(!format!("{error} {error:?} {error:#?}").contains("synthetic-private"));
        assert!(error.source().is_none());
    }
}
