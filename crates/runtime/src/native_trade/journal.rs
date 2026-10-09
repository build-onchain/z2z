//! Digest-only local CAS and permanent reservations, never financial authority.
use std::path::Path;
use sqlx::{PgPool, Postgres, Row, Transaction, migrate::Migrator, postgres::{PgArguments, PgRow}, query::Query};
use crate::{database::{self, DatabaseConfig, DatabaseError, SchemaSpec}, native_quote::{AuthenticatedQuote, NativeRole, QuotePhase, QuoteSelection}};
use super::{CapsuleLocation, DurableQuote, NativeTradeError, OperationBinding, OperationSnapshot, OperationState, QuoteSnapshot,
    ReleasedOperation, TradeCursor, capsule, check_cursor, decode_phase, invalid_record, phase_code, require_one};

const SCHEMA: SchemaSpec = SchemaSpec {
    application: "native_trade", version: 1, relations: &["quotes", "trades", "releases", "reservations"], domains: &[], functions: &[],
};

pub struct NativeTradeStore { pool: PgPool, config: DatabaseConfig, queries: Queries }

struct Queries {
    quote: String, owner: String, insert_quote: String, update_quote: String, bump: String,
    operation: String, insert_operation: String, reservation: String, insert_reservation: String,
    update_operation: String, release: String, insert_release: String,
}
impl Queries {
    fn new(schema: &str) -> Self {
        let quotes = format!("\"{schema}\".quotes");
        let trades = format!("\"{schema}\".trades");
        let releases = format!("\"{schema}\".releases");
        let reservations = format!("\"{schema}\".reservations");
        let scope = "owner_scope=$1 AND session_id=$2 AND quote_id=$3 AND local_role=$4";
        Self {
            quote: format!("SELECT * FROM {quotes} WHERE {scope} FOR UPDATE"),
            owner: format!("SELECT * FROM {quotes} WHERE owner_scope=$1 ORDER BY session_id,quote_id,local_role"),
            insert_quote: format!("INSERT INTO {quotes} (owner_scope,session_id,quote_id,local_role,initiator_coord_key,responder_coord_key,chain_context,deployment_context,s_offer_id,u_trade_intent_id,challenge_i,challenge_r,proposal_seq,user_acceptance_seq,solver_acceptance_seq,q_digest,proposal_hash,user_acceptance_hash,solver_acceptance_hash,agreement_digest,phase,capsule_digest,stopped,version,writer_generation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,false,1,1)"),
            update_quote: format!("UPDATE {quotes} SET user_acceptance_hash=$5,solver_acceptance_hash=$6,agreement_digest=$7,phase=$8,capsule_digest=$9,version=$10 WHERE {scope} AND version=$11 AND writer_generation=$12 AND NOT stopped"),
            bump: format!("UPDATE {quotes} SET version=$5,writer_generation=$6,stopped=$7 WHERE {scope} AND version=$8 AND writer_generation=$9"),
            operation: format!("SELECT * FROM {trades} WHERE {scope} AND op_id=$5 FOR UPDATE"),
            insert_operation: format!("INSERT INTO {trades} (owner_scope,session_id,quote_id,local_role,op_id,context_digest,deployment_digest,stable_j_tag,payload_digest,action,state,version,writer_generation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,$11,$12)"),
            reservation: format!("SELECT * FROM {reservations} WHERE owner_scope=$1 AND deployment_digest=$2 AND stable_j_tag=$3 AND action=$4"),
            insert_reservation: format!("INSERT INTO {reservations} (owner_scope,deployment_digest,stable_j_tag,action,op_id,session_id,quote_id,local_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (owner_scope,deployment_digest,stable_j_tag,action) DO NOTHING"),
            update_operation: format!("UPDATE {trades} SET state=$6,capsule_digest=$7,tx_hash=$8,version=$9,writer_generation=$10 WHERE {scope} AND op_id=$5 AND version=$11 AND writer_generation=$12"),
            release: format!("SELECT * FROM {releases} WHERE {scope} AND op_id=$5"),
            insert_release: format!("INSERT INTO {releases} (owner_scope,session_id,quote_id,local_role,op_id,capsule_digest,version) VALUES ($1,$2,$3,$4,$5,$6,$7)"),
        }
    }
}

type PgQuery<'a> = Query<'a, Postgres, PgArguments>;
fn scoped<'a>(query: PgQuery<'a>, selection: &'a QuoteSelection) -> PgQuery<'a> {
    query.bind(selection.owner_scope.as_slice()).bind(selection.session_id.as_slice())
        .bind(selection.quote_id.as_slice()).bind(selection.local_role as i16)
}

struct StoredOperation {
    selection: QuoteSelection, binding: OperationBinding, state: OperationState,
    cursor: TradeCursor, capsule_digest: Option<[u8; 32]>, tx_hash: Option<[u8; 32]>,
}
impl StoredOperation {
    fn snapshot(&self, cursor: TradeCursor) -> OperationSnapshot {
        OperationSnapshot { selection: self.selection, binding: self.binding, state: self.state,
            cursor, capsule_digest: self.capsule_digest, tx_hash: self.tx_hash }
    }
}

impl NativeTradeStore {
    /// Connect never initializes or adopts a schema; transport policy is shared.
    pub async fn connect(config: DatabaseConfig) -> Result<Self, NativeTradeError> {
        let pool = database::connect(&config).await?;
        let queries = Queries::new(&config.schema);
        Ok(Self { pool, config, queries })
    }

    /// Operational use requires separately authorized schema initialization.
    pub async fn migrate(&self) -> Result<(), NativeTradeError> {
        let migrations = Migrator::new(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/native_trade")))
            .await.map_err(|_| DatabaseError::Migration)?;
        database::migrate(&self.pool, &self.config, SCHEMA, &migrations).await?;
        Ok(())
    }

    pub async fn list_owner(&self, owner_scope: [u8; 32]) -> Result<Vec<QuoteSnapshot>, NativeTradeError> {
        if owner_scope == [0; 32] { return Err(NativeTradeError::Binding); }
        database::ensure_ready(&self.pool, &self.config, SCHEMA).await?;
        sqlx::query(&self.queries.owner).bind(owner_scope.as_slice()).fetch_all(&self.pool).await?
            .into_iter().map(decode_quote).collect()
    }

    async fn lock_scope(&self, selection: &QuoteSelection) -> Result<Transaction<'static, Postgres>, NativeTradeError> {
        use sha2::{Digest, Sha256};
        capsule::validate_selection(selection)?;
        database::ensure_ready(&self.pool, &self.config, SCHEMA).await?;
        let mut transaction = self.pool.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await?;
        sqlx::query("SET LOCAL synchronous_commit TO on").execute(&mut *transaction).await?;
        // Match the primary key, not the complete mutable input selection. Competing
        // first writers with different retained transcript pins must share this lock.
        let mut hash = Sha256::new();
        hash.update(b"ZIQUID_NATIVE_TRADE_SCOPE\0");
        hash.update(selection.owner_scope);
        hash.update(selection.session_id);
        hash.update(selection.quote_id);
        hash.update([selection.local_role as u8]);
        let scope: [u8; 32] = hash.finalize().into();
        sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(current_database()||':'||$1||':'||pg_catalog.encode($2::bytea,'hex'),0))")
            .bind(&self.config.schema).bind(scope.as_slice()).execute(&mut *transaction).await?;
        Ok(transaction)
    }

    async fn quote_row(&self, transaction: &mut Transaction<'_, Postgres>, selection: &QuoteSelection) -> Result<Option<QuoteSnapshot>, NativeTradeError> {
        let row = scoped(sqlx::query(&self.queries.quote), selection).fetch_optional(&mut **transaction).await?
            .map(decode_quote).transpose()?;
        if row.as_ref().is_some_and(|row| row.selection != *selection) { return Err(NativeTradeError::Conflict); }
        Ok(row)
    }

    async fn checked_quote(&self, transaction: &mut Transaction<'_, Postgres>, selection: &QuoteSelection, expected: TradeCursor) -> Result<QuoteSnapshot, NativeTradeError> {
        let row = self.quote_row(transaction, selection).await?.ok_or(NativeTradeError::Missing)?;
        check_cursor(row.cursor, expected)?;
        Ok(row)
    }

    async fn quote_readback(&self, expected: &QuoteSnapshot) -> Result<QuoteSnapshot, NativeTradeError> {
        let mut transaction = self.lock_scope(&expected.selection).await?;
        let row = self.checked_quote(&mut transaction, &expected.selection, expected.cursor).await?;
        if row != *expected { return Err(invalid_record()); }
        transaction.commit().await?;
        Ok(row)
    }

    pub async fn save_quote(&self, location: CapsuleLocation<'_>, quote: &AuthenticatedQuote, expected: Option<TradeCursor>) -> Result<DurableQuote, NativeTradeError> {
        if let Some(cursor) = expected { cursor.validate()?; }
        let selection = quote.selection();
        let mut transaction = self.lock_scope(selection).await?;
        let current = self.quote_row(&mut transaction, selection).await?;
        let advance = if let Some(row) = &current {
            check_cursor(row.cursor, expected.ok_or(NativeTradeError::StaleVersion)?)?;
            row.accept_quote(quote)?
        } else {
            if expected.is_some() { return Err(NativeTradeError::Missing); }
            if quote.phase() != QuotePhase::Proposal { return Err(NativeTradeError::State); }
            false
        };
        let cursor = match &current {
            Some(row) if advance => row.cursor.advance(false)?,
            Some(row) => row.cursor,
            None => TradeCursor { version: 1, generation: 1 },
        };
        // Publish and authenticate immutable installed bytes before any SQL change.
        let (digest, restored) = capsule::save_quote(location, quote)?;
        if current.as_ref().is_some_and(|row| !advance && row.capsule_digest != digest) {
            return Err(NativeTradeError::Conflict);
        }
        let snapshot = QuoteSnapshot::from_quote(&restored, digest, cursor);
        if let Some(row) = &current {
            if advance {
                require_one(scoped(sqlx::query(&self.queries.update_quote), selection)
                    .bind(snapshot.user_acceptance_hash.as_ref().map(|hash| hash.as_slice()))
                    .bind(snapshot.solver_acceptance_hash.as_ref().map(|hash| hash.as_slice()))
                    .bind(snapshot.agreement_digest.as_ref().map(|hash| hash.as_slice()))
                    .bind(phase_code(snapshot.phase)).bind(digest.as_slice()).bind(cursor.version as i64)
                    .bind(row.cursor.version as i64).bind(row.cursor.generation as i64)
                    .execute(&mut *transaction).await?.rows_affected())?;
            }
        } else {
            require_one(scoped(sqlx::query(&self.queries.insert_quote), selection)
                .bind(selection.initiator_coord_key.as_slice()).bind(selection.responder_coord_key.as_slice())
                .bind(selection.chain_context.as_slice()).bind(selection.deployment_context.as_slice())
                .bind(selection.s_offer_id.as_slice()).bind(selection.u_trade_intent_id.as_slice())
                .bind(selection.challenge_i.as_slice()).bind(selection.challenge_r.as_slice())
                .bind(i64::from(selection.proposal_seq)).bind(i64::from(selection.user_acceptance_seq)).bind(i64::from(selection.solver_acceptance_seq))
                .bind(snapshot.q.as_slice()).bind(snapshot.proposal_hash.as_slice())
                .bind(snapshot.user_acceptance_hash.as_ref().map(|hash| hash.as_slice()))
                .bind(snapshot.solver_acceptance_hash.as_ref().map(|hash| hash.as_slice()))
                .bind(snapshot.agreement_digest.as_ref().map(|hash| hash.as_slice()))
                .bind(phase_code(snapshot.phase)).bind(digest.as_slice())
                .execute(&mut *transaction).await?.rows_affected())?;
        }
        let row = self.checked_quote(&mut transaction, selection, cursor).await?;
        if row != snapshot { return Err(invalid_record()); }
        transaction.commit().await?;
        let snapshot = self.quote_readback(&snapshot).await?;
        Ok(DurableQuote { quote: restored, snapshot })
    }

    /// Stopped quotes remain restorable: stop never destroys recovery/armed rights.
    pub async fn restore_quote(&self, location: CapsuleLocation<'_>, selection: &QuoteSelection, expected: TradeCursor) -> Result<DurableQuote, NativeTradeError> {
        expected.validate()?;
        let mut transaction = self.lock_scope(selection).await?;
        let snapshot = self.checked_quote(&mut transaction, selection, expected).await?;
        let quote = capsule::load_quote(location, selection, snapshot.phase, snapshot.capsule_digest)?;
        if !snapshot.matches_quote(&quote) { return Err(NativeTradeError::Conflict); }
        transaction.commit().await?;
        let snapshot = self.quote_readback(&snapshot).await?;
        Ok(DurableQuote { quote, snapshot })
    }

    pub async fn claim_writer(&self, selection: &QuoteSelection, expected: TradeCursor) -> Result<QuoteSnapshot, NativeTradeError> {
        self.change_quote(selection, expected, true).await
    }

    /// Local negotiation stop only, never a destination refund or reservation release.
    pub async fn stop_quote(&self, selection: &QuoteSelection, expected: TradeCursor) -> Result<QuoteSnapshot, NativeTradeError> {
        self.change_quote(selection, expected, false).await
    }

    async fn change_quote(&self, selection: &QuoteSelection, expected: TradeCursor, writer: bool) -> Result<QuoteSnapshot, NativeTradeError> {
        expected.validate()?;
        let mut transaction = self.lock_scope(selection).await?;
        let mut snapshot = self.checked_quote(&mut transaction, selection, expected).await?;
        if writer || !snapshot.stopped {
            let next = snapshot.cursor.advance(writer)?;
            self.bump_quote(&mut transaction, &snapshot, next, snapshot.stopped || !writer).await?;
            snapshot.cursor = next;
            snapshot.stopped |= !writer;
        }
        let row = self.checked_quote(&mut transaction, selection, snapshot.cursor).await?;
        if row != snapshot { return Err(invalid_record()); }
        transaction.commit().await?;
        self.quote_readback(&snapshot).await
    }

    async fn bump_quote(&self, transaction: &mut Transaction<'_, Postgres>, current: &QuoteSnapshot, next: TradeCursor, stopped: bool) -> Result<(), NativeTradeError> {
        next.validate()?;
        require_one(scoped(sqlx::query(&self.queries.bump), &current.selection)
            .bind(next.version as i64).bind(next.generation as i64).bind(stopped)
            .bind(current.cursor.version as i64).bind(current.cursor.generation as i64)
            .execute(&mut **transaction).await?.rows_affected())
    }
}

impl NativeTradeStore {
    pub async fn prepare_operation(&self, selection: &QuoteSelection, expected: TradeCursor, binding: OperationBinding) -> Result<OperationSnapshot, NativeTradeError> {
        binding.validate()?;
        expected.validate()?;
        let mut transaction = self.lock_scope(selection).await?;
        let quote = self.checked_quote(&mut transaction, selection, expected).await?;
        if quote.stopped { return Err(NativeTradeError::Stopped); }
        if quote.phase != QuotePhase::Agreed { return Err(NativeTradeError::State); }
        if let Some(stored) = self.operation_row(&mut transaction, &quote, binding.op_id).await? {
            if stored.binding != binding { return Err(NativeTradeError::Conflict); }
            // Exact retry only reads the retained state; it never re-prepares Unknown.
            let snapshot = stored.snapshot(quote.cursor);
            transaction.commit().await?;
            return self.operation_readback(&snapshot).await;
        }
        let next = quote.cursor.advance(false)?;
        require_one(scoped(sqlx::query(&self.queries.insert_operation), selection)
            .bind(binding.op_id.as_slice()).bind(binding.context_digest.as_slice()).bind(binding.deployment_digest.as_slice())
            .bind(binding.stable_j_tag.as_slice()).bind(binding.payload_digest.as_slice()).bind(binding.action as i16)
            .bind(next.version as i64).bind(next.generation as i64)
            .execute(&mut *transaction).await?.rows_affected())?;
        // PostgreSQL's unique key serializes even different quote scopes. The
        // losing transaction rolls back its operation row with no released right.
        let affected = sqlx::query(&self.queries.insert_reservation)
            .bind(selection.owner_scope.as_slice()).bind(binding.deployment_digest.as_slice())
            .bind(binding.stable_j_tag.as_slice()).bind(binding.action as i16).bind(binding.op_id.as_slice())
            .bind(selection.session_id.as_slice()).bind(selection.quote_id.as_slice()).bind(selection.local_role as i16)
            .execute(&mut *transaction).await?.rows_affected();
        if affected != 1 { return Err(NativeTradeError::Conflict); }
        self.bump_quote(&mut transaction, &quote, next, quote.stopped).await?;
        let quote = self.checked_quote(&mut transaction, selection, next).await?;
        let stored = self.operation_row(&mut transaction, &quote, binding.op_id).await?.ok_or_else(invalid_record)?;
        if stored.binding != binding || stored.state != OperationState::Prepared || stored.cursor != next {
            return Err(invalid_record());
        }
        let snapshot = stored.snapshot(quote.cursor);
        transaction.commit().await?;
        self.operation_readback(&snapshot).await
    }

    /// Authenticate the exact existing encrypted capsule before committing release.
    /// A digest alone cannot enter this API: borrowed owner-local key/path are required.
    pub async fn release_operation(&self, location: CapsuleLocation<'_>, selection: &QuoteSelection, expected: TradeCursor,
        op_id: [u8; 32], capsule_digest: [u8; 32]) -> Result<ReleasedOperation, NativeTradeError> {
        expected.validate()?;
        let mut transaction = self.lock_scope(selection).await?;
        let quote = self.checked_quote(&mut transaction, selection, expected).await?;
        let stored = self.operation_row(&mut transaction, &quote, op_id).await?.ok_or(NativeTradeError::Missing)?;
        if !matches!(stored.state, OperationState::Prepared | OperationState::Released) { return Err(NativeTradeError::State); }
        if quote.stopped { return Err(NativeTradeError::Stopped); }
        if stored.capsule_digest.is_some_and(|digest| digest != capsule_digest) { return Err(NativeTradeError::Conflict); }
        let payload = capsule::load_operation(location, selection, &stored.binding, capsule_digest)?;
        let snapshot = if stored.state.can_release() {
            let next = quote.cursor.advance(false)?;
            require_one(scoped(sqlx::query(&self.queries.insert_release), selection).bind(op_id.as_slice())
                .bind(capsule_digest.as_slice()).bind(next.version as i64)
                .execute(&mut *transaction).await?.rows_affected())?;
            self.update_operation(&mut transaction, &stored, next, OperationState::Released, Some(capsule_digest), None).await?;
            self.bump_quote(&mut transaction, &quote, next, quote.stopped).await?;
            let quote = self.checked_quote(&mut transaction, selection, next).await?;
            let released = self.operation_row(&mut transaction, &quote, op_id).await?.ok_or_else(invalid_record)?;
            if released.binding != stored.binding || released.state != OperationState::Released
                || released.capsule_digest != Some(capsule_digest) || released.tx_hash.is_some() || released.cursor != next {
                return Err(invalid_record());
            }
            released.snapshot(next)
        } else { stored.snapshot(quote.cursor) };
        transaction.commit().await?;
        let snapshot = self.operation_readback(&snapshot).await?;
        Ok(ReleasedOperation { payload, snapshot })
    }

    /// Retained release is reloadable after stop, Unknown and writer takeover.
    /// Reloading never moves a state backwards, clears a hash or frees a reservation.
    pub async fn restore_operation(&self, location: CapsuleLocation<'_>, selection: &QuoteSelection, expected: TradeCursor,
        op_id: [u8; 32]) -> Result<ReleasedOperation, NativeTradeError> {
        expected.validate()?;
        let mut transaction = self.lock_scope(selection).await?;
        let quote = self.checked_quote(&mut transaction, selection, expected).await?;
        let stored = self.operation_row(&mut transaction, &quote, op_id).await?.ok_or(NativeTradeError::Missing)?;
        let digest = stored.capsule_digest.ok_or(NativeTradeError::State)?;
        let payload = capsule::load_operation(location, selection, &stored.binding, digest)?;
        let snapshot = stored.snapshot(quote.cursor);
        transaction.commit().await?;
        let snapshot = self.operation_readback(&snapshot).await?;
        Ok(ReleasedOperation { payload, snapshot })
    }

    /// Records an observed submission identifier, not inclusion, transfer or finality.
    /// Unknown may reconcile to this same retained operation, never a replacement.
    pub async fn mark_submitted(&self, selection: &QuoteSelection, expected: TradeCursor, op_id: [u8; 32], tx_hash: [u8; 32]) -> Result<OperationSnapshot, NativeTradeError> {
        if tx_hash == [0; 32] { return Err(NativeTradeError::Binding); }
        self.change_operation(selection, expected, op_id, Some(tx_hash)).await
    }

    /// Missing response preserves exact bytes, known tx hash and permanent tag hold.
    pub async fn mark_unknown(&self, selection: &QuoteSelection, expected: TradeCursor, op_id: [u8; 32]) -> Result<OperationSnapshot, NativeTradeError> {
        self.change_operation(selection, expected, op_id, None).await
    }

    pub async fn operation(&self, selection: &QuoteSelection, op_id: [u8; 32]) -> Result<OperationSnapshot, NativeTradeError> {
        let mut transaction = self.lock_scope(selection).await?;
        let quote = self.quote_row(&mut transaction, selection).await?.ok_or(NativeTradeError::Missing)?;
        let stored = self.operation_row(&mut transaction, &quote, op_id).await?.ok_or(NativeTradeError::Missing)?;
        let snapshot = stored.snapshot(quote.cursor);
        transaction.commit().await?;
        Ok(snapshot)
    }

    async fn change_operation(&self, selection: &QuoteSelection, expected: TradeCursor, op_id: [u8; 32], submitted: Option<[u8; 32]>) -> Result<OperationSnapshot, NativeTradeError> {
        expected.validate()?;
        let mut transaction = self.lock_scope(selection).await?;
        let quote = self.checked_quote(&mut transaction, selection, expected).await?;
        let stored = self.operation_row(&mut transaction, &quote, op_id).await?.ok_or(NativeTradeError::Missing)?;
        let (target, hash, changed) = operation_transition(stored.state, stored.tx_hash, submitted)?;
        let snapshot = if !changed {
            stored.snapshot(quote.cursor)
        } else {
            let next = quote.cursor.advance(false)?;
            self.update_operation(&mut transaction, &stored, next, target, stored.capsule_digest, hash).await?;
            self.bump_quote(&mut transaction, &quote, next, quote.stopped).await?;
            let quote = self.checked_quote(&mut transaction, selection, next).await?;
            let updated = self.operation_row(&mut transaction, &quote, op_id).await?.ok_or_else(invalid_record)?;
            if updated.binding != stored.binding || updated.state != target || updated.capsule_digest != stored.capsule_digest
                || updated.tx_hash != hash || updated.cursor != next { return Err(invalid_record()); }
            updated.snapshot(next)
        };
        transaction.commit().await?;
        self.operation_readback(&snapshot).await
    }

    async fn update_operation(&self, transaction: &mut Transaction<'_, Postgres>, stored: &StoredOperation,
        next: TradeCursor, state: OperationState, capsule: Option<[u8; 32]>, tx_hash: Option<[u8; 32]>) -> Result<(), NativeTradeError> {
        require_one(scoped(sqlx::query(&self.queries.update_operation), &stored.selection).bind(stored.binding.op_id.as_slice())
            .bind(state as i16).bind(capsule.as_ref().map(|digest| digest.as_slice())).bind(tx_hash.as_ref().map(|hash| hash.as_slice()))
            .bind(next.version as i64).bind(next.generation as i64).bind(stored.cursor.version as i64).bind(stored.cursor.generation as i64)
            .execute(&mut **transaction).await?.rows_affected())
    }

    async fn operation_readback(&self, expected: &OperationSnapshot) -> Result<OperationSnapshot, NativeTradeError> {
        let mut transaction = self.lock_scope(&expected.selection).await?;
        let quote = self.checked_quote(&mut transaction, &expected.selection, expected.cursor).await?;
        let stored = self.operation_row(&mut transaction, &quote, expected.binding.op_id).await?.ok_or_else(invalid_record)?;
        let actual = stored.snapshot(quote.cursor);
        if actual != *expected { return Err(invalid_record()); }
        transaction.commit().await?;
        Ok(actual)
    }
}

impl NativeTradeStore {
    async fn operation_row(&self, transaction: &mut Transaction<'_, Postgres>, quote: &QuoteSnapshot, op_id: [u8; 32]) -> Result<Option<StoredOperation>, NativeTradeError> {
        if op_id == [0; 32] { return Err(NativeTradeError::Binding); }
        let Some(row) = scoped(sqlx::query(&self.queries.operation), &quote.selection).bind(op_id.as_slice())
            .fetch_optional(&mut **transaction).await? else { return Ok(None); };
        if quote.phase != QuotePhase::Agreed { return Err(invalid_record()); }
        let binding = OperationBinding { op_id: id(row.try_get("op_id")?)?,
            context_digest: id(row.try_get("context_digest")?)?, deployment_digest: id(row.try_get("deployment_digest")?)?,
            stable_j_tag: id(row.try_get("stable_j_tag")?)?, payload_digest: id(row.try_get("payload_digest")?)?,
            action: u16::try_from(row.try_get::<i16, _>("action")?).map_err(|_| invalid_record())? };
        binding.validate().map_err(|_| invalid_record())?;
        if binding.op_id != op_id || !same_scope(&row, &quote.selection)? { return Err(invalid_record()); }
        let capsule_digest = optional_id(&row, "capsule_digest")?;
        let tx_hash = optional_id(&row, "tx_hash")?;
        let state = decode_operation_state(row.try_get("state")?, capsule_digest, tx_hash)?;
        let cursor = decode_cursor(&row)?;
        if cursor.version > quote.cursor.version || cursor.generation > quote.cursor.generation { return Err(invalid_record()); }
        let reservation = sqlx::query(&self.queries.reservation).bind(quote.selection.owner_scope.as_slice())
            .bind(binding.deployment_digest.as_slice()).bind(binding.stable_j_tag.as_slice()).bind(binding.action as i16)
            .fetch_optional(&mut **transaction).await?.ok_or_else(invalid_record)?;
        if !same_scope(&reservation, &quote.selection)? || id(reservation.try_get("op_id")?)? != op_id
            || id(reservation.try_get("deployment_digest")?)? != binding.deployment_digest
            || id(reservation.try_get("stable_j_tag")?)? != binding.stable_j_tag
            || reservation.try_get::<i16, _>("action")? != binding.action as i16 { return Err(invalid_record()); }
        let release = scoped(sqlx::query(&self.queries.release), &quote.selection).bind(op_id.as_slice())
            .fetch_optional(&mut **transaction).await?;
        match (capsule_digest, release) {
            (None, None) => {},
            (Some(digest), Some(release)) => {
                let release_version = positive(release.try_get("version")?)?;
                if !same_scope(&release, &quote.selection)? || id(release.try_get("op_id")?)? != op_id
                    || id(release.try_get("capsule_digest")?)? != digest || release_version > cursor.version {
                    return Err(invalid_record());
                }
            },
            _ => return Err(invalid_record()),
        }
        Ok(Some(StoredOperation { selection: quote.selection, binding, state, cursor, capsule_digest, tx_hash }))
    }
}

fn decode_quote(row: PgRow) -> Result<QuoteSnapshot, NativeTradeError> {
    let selection = QuoteSelection { local_role: role(row.try_get("local_role")?)?,
        owner_scope: id(row.try_get("owner_scope")?)?, session_id: id(row.try_get("session_id")?)?, quote_id: id(row.try_get("quote_id")?)?,
        initiator_coord_key: id(row.try_get("initiator_coord_key")?)?, responder_coord_key: id(row.try_get("responder_coord_key")?)?,
        chain_context: id(row.try_get("chain_context")?)?, deployment_context: id(row.try_get("deployment_context")?)?,
        s_offer_id: id(row.try_get("s_offer_id")?)?, u_trade_intent_id: id(row.try_get("u_trade_intent_id")?)?,
        challenge_i: id(row.try_get("challenge_i")?)?, challenge_r: id(row.try_get("challenge_r")?)?,
        proposal_seq: sequence(row.try_get("proposal_seq")?)?, user_acceptance_seq: sequence(row.try_get("user_acceptance_seq")?)?,
        solver_acceptance_seq: sequence(row.try_get("solver_acceptance_seq")?)? };
    capsule::validate_selection(&selection).map_err(|_| invalid_record())?;
    let snapshot = QuoteSnapshot { selection, q: id(row.try_get("q_digest")?)?, phase: decode_phase(row.try_get("phase")?)?,
        cursor: decode_cursor(&row)?, proposal_hash: id(row.try_get("proposal_hash")?)?,
        agreement_digest: optional_id(&row, "agreement_digest")?, user_acceptance_hash: optional_id(&row, "user_acceptance_hash")?,
        solver_acceptance_hash: optional_id(&row, "solver_acceptance_hash")?, capsule_digest: id(row.try_get("capsule_digest")?)?,
        stopped: row.try_get("stopped")? };
    if !matches!((snapshot.phase, snapshot.user_acceptance_hash, snapshot.solver_acceptance_hash, snapshot.agreement_digest),
        (QuotePhase::Proposal, None, None, None) | (QuotePhase::UserAcceptance, Some(_), None, None) | (QuotePhase::Agreed, Some(_), Some(_), Some(_)))
        || snapshot.cursor.version < phase_code(snapshot.phase) as u64 + 1 { return Err(invalid_record()); }
    Ok(snapshot)
}

pub(super) fn decode_operation_state(code: i16, capsule: Option<[u8; 32]>, tx_hash: Option<[u8; 32]>) -> Result<OperationState, NativeTradeError> {
    if capsule == Some([0; 32]) || tx_hash == Some([0; 32]) { return Err(invalid_record()); }
    match (code, capsule, tx_hash) {
        (0, None, None) => Ok(OperationState::Prepared),
        (1, Some(_), None) => Ok(OperationState::Released),
        (2, Some(_), Some(_)) => Ok(OperationState::Submitted),
        (3, Some(_), _) => Ok(OperationState::Unknown),
        _ => Err(invalid_record()),
    }
}

pub(super) fn operation_transition(state: OperationState, retained: Option<[u8; 32]>, submitted: Option<[u8; 32]>)
    -> Result<(OperationState, Option<[u8; 32]>, bool), NativeTradeError> {
    if submitted == Some([0; 32]) { return Err(NativeTradeError::Binding); }
    if submitted.is_some_and(|hash| retained.is_some_and(|old| old != hash)) { return Err(NativeTradeError::Conflict); }
    let target = if submitted.is_some() { OperationState::Submitted } else { OperationState::Unknown };
    let changed = state != target;
    if changed && ((submitted.is_some() && !state.can_submit()) || (submitted.is_none() && !state.can_mark_unknown())) {
        return Err(NativeTradeError::State);
    }
    Ok((target, submitted.or(retained), changed))
}

fn id(bytes: &[u8]) -> Result<[u8; 32], NativeTradeError> {
    let id = <[u8; 32]>::try_from(bytes).map_err(|_| invalid_record())?;
    if id == [0; 32] { return Err(invalid_record()); }
    Ok(id)
}
fn optional_id(row: &PgRow, name: &str) -> Result<Option<[u8; 32]>, NativeTradeError> {
    row.try_get::<Option<&[u8]>, _>(name)?.map(id).transpose()
}
fn positive(value: i64) -> Result<u64, NativeTradeError> {
    u64::try_from(value).ok().filter(|value| *value > 0).ok_or_else(invalid_record)
}
fn decode_cursor(row: &PgRow) -> Result<TradeCursor, NativeTradeError> {
    let cursor = TradeCursor { version: positive(row.try_get("version")?)?, generation: positive(row.try_get("writer_generation")?)? };
    if cursor.generation > cursor.version { return Err(invalid_record()); }
    Ok(cursor)
}
fn sequence(value: i64) -> Result<u32, NativeTradeError> {
    u32::try_from(value).ok().filter(|value| *value > 0).ok_or_else(invalid_record)
}
fn role(code: i16) -> Result<NativeRole, NativeTradeError> {
    match code { 0 => Ok(NativeRole::User), 1 => Ok(NativeRole::Solver), _ => Err(invalid_record()) }
}
fn same_scope(row: &PgRow, selection: &QuoteSelection) -> Result<bool, NativeTradeError> {
    Ok(id(row.try_get("owner_scope")?)? == selection.owner_scope && id(row.try_get("session_id")?)? == selection.session_id
        && id(row.try_get("quote_id")?)? == selection.quote_id && role(row.try_get("local_role")?)? == selection.local_role)
}

#[cfg(test)]
mod record_checks {
    use super::*;

    #[test]
    fn persisted_ids_counters_and_roles_fail_closed_without_sql() {
        assert_eq!(id(&[1; 31]), Err(invalid_record()));
        assert_eq!(id(&[1; 33]), Err(invalid_record()));
        assert_eq!(id(&[0; 32]), Err(invalid_record()));
        assert_eq!(id(&[1; 32]).unwrap(), [1; 32]);
        for value in [i64::MIN, -1, 0] { assert_eq!(positive(value), Err(invalid_record())); }
        assert_eq!(positive(i64::MAX).unwrap(), i64::MAX as u64);
        for value in [-1, 0, i64::from(u32::MAX) + 1] { assert_eq!(sequence(value), Err(invalid_record())); }
        assert_eq!(sequence(i64::from(u32::MAX)).unwrap(), u32::MAX);
        for value in [-1, 2, i16::MAX] { assert_eq!(role(value), Err(invalid_record())); }
        assert_eq!(role(0).unwrap(), NativeRole::User);
        assert_eq!(role(1).unwrap(), NativeRole::Solver);
    }
}
