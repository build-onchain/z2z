use super::codec;
use super::target::{observed_head, validate_path as validate_target_path};
use super::*;
use ed25519_dalek::{Signature, VerifyingKey};
use ziquid_protocol::market::{
    AllocationPartition, AllocationPortion, ChainCommitment, Disposition, SignatureRole,
    Transition, verify_funding_claim, verify_operation, verify_unanimous,
};
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::PgRow,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::Mutex;

pub(crate) type Tx = Transaction<'static, Postgres>;
const ZERO: Id = [0; 32];
pub(crate) const SCHEMA: crate::database::SchemaSpec = crate::database::SchemaSpec {
    application: "market",
    version: 8,
    relations: &[
        "ledger_pairs", "ledger_versions", "ledger_journal", "ledger_commits", "ledger_credits",
        "ledger_holds", "ledger_allocations", "ledger_allocation_chunks", "ledger_portions",
        "ledger_inventory", "ledger_intent_records", "ledger_intent_states", "ledger_nonce_tombstones",
        "ledger_consumptions", "ledger_native_observations", "replica_pairs", "replica_journal",
        "replica_intents", "ledger_target_authorizations", "ledger_target_observations",
        "ledger_target_versions", "ledger_change_reservations", "ledger_epoch_terminal", "ledger_physical_claims",
    ],
    domains: &["kerb_u64", "kerb_id", "kerb_receiver"],
    functions: &["kerb_append_only"],
};

pub(crate) async fn migrations() -> Result<sqlx::migrate::Migrator, LedgerError> {
    sqlx::migrate::Migrator::new(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/market")))
        .await.map_err(|_| LedgerError::Database)
}

// Operational SQL stays allocation-free and unqualified only inside this private
// pool. Every acquisition pins the namespace and validates the entire schema,
// migration identity and absence of temporary objects before any business SQL.
#[derive(Default)]
struct Session {
    trusted: bool,
    challenge: Option<Id>,
    error: Option<LedgerError>,
}
#[derive(Clone)]
pub struct Ledger {
    pool: PgPool,
    config: DatabaseConfig,
    sessions: Arc<Mutex<HashMap<Id, Session>>>,
}

pub(crate) fn database_error(error: sqlx::Error) -> LedgerError {
    match error.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("40001" | "40P01") => LedgerError::SerializationFailure,
        Some("23505") => LedgerError::Conflict,
        _ => LedgerError::Database,
    }
}
pub(crate) async fn serializable(pool: &PgPool) -> Result<Tx, LedgerError> {
    pool.begin_with("BEGIN ISOLATION LEVEL SERIALIZABLE")
        .await
        .map_err(database_error)
}
pub(crate) fn id(row: &PgRow, field: &str) -> Result<Id, LedgerError> {
    row.try_get::<Vec<u8>, _>(field)
        .map_err(database_error)?
        .try_into()
        .map_err(|_| LedgerError::Database)
}
fn receiver(row: &PgRow, field: &str) -> Result<[u8; 43], LedgerError> {
    row.try_get::<Vec<u8>, _>(field)
        .map_err(database_error)?
        .try_into()
        .map_err(|_| LedgerError::Database)
}
fn inventory_row_input(row: &PgRow, note: Id) -> Result<InventoryInput, LedgerError> {
    let network = row
        .try_get::<i16, _>("source_network")
        .map_err(database_error)?;
    let pool = row
        .try_get::<i16, _>("source_pool")
        .map_err(database_error)?;
    let action_index = row
        .try_get::<i64, _>("action_index")
        .map_err(database_error)?;
    let input = InventoryInput {
        note,
        occurrence: SourceOccurrence {
            network: network
                .try_into()
                .map_err(|_| LedgerError::InvalidEvidence)?,
            pool: pool.try_into().map_err(|_| LedgerError::InvalidEvidence)?,
            txid: id(row, "txid")?,
            action_index: action_index
                .try_into()
                .map_err(|_| LedgerError::InvalidEvidence)?,
        },
        note_commitment: id(row, "note_commitment")?,
        nullifier: id(row, "nullifier")?,
        value: number(row, "amount")?,
        scope: id(row, "scope")?,
    };
    if input.occurrence.txid == ZERO || input.note_commitment == ZERO || input.nullifier == ZERO {
        return Err(LedgerError::InvalidEvidence);
    }
    Ok(input)
}
pub(crate) fn number(row: &PgRow, field: &str) -> Result<u64, LedgerError> {
    row.try_get::<String, _>(field)
        .map_err(database_error)?
        .parse()
        .map_err(|_| LedgerError::Database)
}
pub(crate) fn validate_policy(policy: &PairPolicy) -> Result<(), LedgerError> {
    policy
        .domain
        .validate()
        .map_err(|_| LedgerError::InvalidPolicy)?;
    if policy.minimum_confirmations == 0
        || policy.inventory_scope != policy.domain.pair
        || policy.sponsor_scope == ZERO
        || policy.inventory_scope == policy.sponsor_scope
        || policy.source_policy == ZERO
        || policy.history_anchor == ZERO
        || policy.receiver == [0; 43]
    {
        return Err(LedgerError::InvalidPolicy);
    }
    let mut distinct = HashSet::new();
    for key in policy.roster.iter().chain([
        &policy.source_producer,
        &policy.inventory_producer,
        &policy.target_observer,
    ]) {
        let verifying = VerifyingKey::from_bytes(key).map_err(|_| LedgerError::InvalidPolicy)?;
        if verifying.is_weak() || !distinct.insert(*key) {
            return Err(LedgerError::InvalidPolicy);
        }
    }
    Ok(())
}
pub(crate) fn verify(key: &Id, message: &[u8], signature: &[u8; 64]) -> Result<(), LedgerError> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| LedgerError::InvalidAuthorization)?;
    if key.is_weak() {
        return Err(LedgerError::InvalidAuthorization);
    }
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| LedgerError::InvalidAuthorization)
}
pub(crate) fn policy(row: &PgRow) -> Result<PairPolicy, LedgerError> {
    codec::policy_decode(
        &row.try_get::<Vec<u8>, _>("policy")
            .map_err(database_error)?,
    )
}
async fn pair_row(tx: &mut Tx, pair: Id) -> Result<PgRow, LedgerError> {
    sqlx::query("SELECT policy, writer_generation::text AS generation, head, target_head, sequence::text AS sequence, impaired, halt, target_inflight, authorized_target_head,COALESCE(target_generation,0)::text AS target_generation FROM ledger_pairs WHERE pair=$1 FOR UPDATE")
        .bind(pair.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(LedgerError::MissingEntity)
}
impl Ledger {
    async fn ready(&self) -> Result<(), LedgerError> {
        crate::database::ensure_ready(&self.pool, &self.config, SCHEMA).await.map_err(|_| LedgerError::Database)
    }
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, LedgerError> {
        Ok(Self {
            pool: crate::database::connect(config).await.map_err(|_| LedgerError::Database)?,
            config: config.clone(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub async fn migrate(&self) -> Result<(), LedgerError> {
        let migrations = migrations().await?;
        crate::database::migrate(&self.pool, &self.config, SCHEMA, &migrations).await.map_err(|_| LedgerError::Database)
    }
    pub async fn close(&self) {
        self.pool.close().await;
    }
    async fn trusted(&self, pair: Id) -> Result<(), LedgerError> {
        let sessions = self.sessions.lock().await;
        match sessions.get(&pair) {
            Some(s) if s.error.is_some() => {
                Err(s.error.unwrap_or(LedgerError::RecoveryEvidenceMissing))
            }
            Some(s) if s.trusted => Ok(()),
            _ => Err(LedgerError::RecoveryEvidenceMissing),
        }
    }
    pub async fn pair_policy(&self, pair: Id) -> Result<PairPolicy, LedgerError> {
        self.ready().await?;
        let row = sqlx::query("SELECT policy FROM ledger_pairs WHERE pair=$1")
            .bind(pair.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(LedgerError::MissingEntity)?;
        policy(&row)
    }
    pub async fn entity_version(
        &self,
        pair: Id,
        entity: Id,
        portion: Id,
    ) -> Result<u64, LedgerError> {
        self.ready().await?;
        let row=sqlx::query("SELECT version::text AS version FROM ledger_versions WHERE pair=$1 AND entity=$2 AND portion=$3")
            .bind(pair.as_slice()).bind(entity.as_slice()).bind(portion.as_slice()).fetch_optional(&self.pool).await.map_err(database_error)?;
        row.map(|r| number(&r, "version"))
            .transpose()
            .map(|v| v.unwrap_or(0))
    }
    pub async fn enroll_pair(&self, policy: &PairPolicy) -> Result<(), LedgerError> {
        self.ready().await?;
        validate_policy(policy)?;
        let bytes = codec::policy_bytes(policy)?;
        let mut tx = serializable(&self.pool).await?;
        let existing = sqlx::query("SELECT policy FROM ledger_pairs WHERE pair=$1 FOR UPDATE")
            .bind(policy.domain.pair.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(database_error)?;
        let new = existing.is_none();
        if let Some(row) = existing {
            if row
                .try_get::<Vec<u8>, _>("policy")
                .map_err(database_error)?
                != bytes
            {
                return Err(LedgerError::Conflict);
            }
        } else {
            sqlx::query(
                "INSERT INTO ledger_pairs(pair,policy,head,target_head) VALUES ($1,$2,$3,$3)",
            )
            .bind(policy.domain.pair.as_slice())
            .bind(bytes)
            .bind(ZERO.as_slice())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        }
        tx.commit().await.map_err(database_error)?;
        if new {
            self.sessions.lock().await.insert(
                policy.domain.pair,
                Session {
                    trusted: true,
                    ..Session::default()
                },
            );
        }
        Ok(())
    }
    pub async fn claim_writer(
        &self,
        pair: Id,
        prior_generation: u64,
    ) -> Result<WriterFence, LedgerError> {
        self.ready().await?;
        self.trusted(pair).await?;
        let mut tx = serializable(&self.pool).await?;
        let row = pair_row(&mut tx, pair).await?;
        if row.try_get::<i16, _>("halt").map_err(database_error)? != 0 {
            return Err(LedgerError::RollbackDetected);
        }
        if number(&row, "generation")? != prior_generation {
            return Err(LedgerError::StaleWriter);
        }
        if pending_tx(&mut tx, pair).await?.is_some() {
            return Err(LedgerError::Conflict);
        }
        let generation = prior_generation
            .checked_add(1)
            .ok_or(LedgerError::StaleWriter)?;
        sqlx::query("UPDATE ledger_pairs SET writer_generation=$2::text::numeric WHERE pair=$1")
            .bind(pair.as_slice())
            .bind(generation.to_string())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(WriterFence { pair, generation })
    }
    pub async fn prepare_decision(
        &self,
        operation: Operation,
        command: LedgerCommand,
    ) -> Result<JournalDecision, LedgerError> {
        self.ready().await?;
        self.trusted(operation.domain.pair).await?;
        // Only whole PostgreSQL transactions are retried. No signature or external action occurs here.
        for _ in 0..8 {
            match self.prepare_once(operation, &command).await {
                Err(LedgerError::SerializationFailure) => tokio::task::yield_now().await,
                result => return result,
            }
        }
        Err(LedgerError::SerializationFailure)
    }
    async fn prepare_once(
        &self,
        operation: Operation,
        command: &LedgerCommand,
    ) -> Result<JournalDecision, LedgerError> {
        operation.validate().map_err(|_| LedgerError::Protocol)?;
        if operation.effects != command.operation_effects(&operation)? {
            return Err(LedgerError::Conflict);
        }
        let pair = operation.domain.pair;
        let operation_id = operation.id().map_err(|_| LedgerError::Protocol)?;
        let mut tx = serializable(&self.pool).await?;
        let row = pair_row(&mut tx, pair).await?;
        if row.try_get::<i16, _>("halt").map_err(database_error)? != 0 {
            return Err(LedgerError::RollbackDetected);
        }
        let policy = policy(&row)?;
        if operation.domain != policy.domain {
            return Err(LedgerError::InvalidEvidence);
        }
        if let Some(stored) =
            sqlx::query("SELECT body FROM ledger_journal WHERE pair=$1 AND operation=$2")
                .bind(pair.as_slice())
                .bind(operation_id.as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(database_error)?
        {
            let decision = JournalDecision::decode(
                &stored
                    .try_get::<Vec<u8>, _>("body")
                    .map_err(database_error)?,
            )?;
            if decision.operation != operation || decision.command != *command {
                return Err(LedgerError::Conflict);
            }
            return Ok(decision);
        }
        if number(&row, "generation")? != operation.generation {
            return Err(LedgerError::StaleWriter);
        }
        if pending_tx(&mut tx, pair).await?.is_some() {
            return Err(LedgerError::Conflict);
        }
        validate_command_identity(&operation, command)?;
        let target = codec::command_signing_target(command);
        validate_target_path(&mut tx, &policy, &row, command).await?;
        let impaired = row.try_get::<bool, _>("impaired").map_err(database_error)?;
        if impaired
            && matches!(
                command,
                LedgerCommand::PrepareHold { .. }
                    | LedgerCommand::ActivateAllocation { .. }
                    | LedgerCommand::PrepareFirstLeg { .. }
                    | LedgerCommand::ReserveInputs { .. }
                    | LedgerCommand::PrepareNative(_)
                    | LedgerCommand::AuthorizeTarget(_)
            )
        {
            return Err(LedgerError::InventoryImpaired);
        }
        // Consumer-facing policy errors take precedence over absent portion/version rows.
        validate_command(&mut tx, &operation, command, &policy).await?;
        let version = sqlx::query("SELECT version::text AS version, reservation FROM ledger_versions WHERE pair=$1 AND entity=$2 AND portion=$3 FOR UPDATE")
            .bind(pair.as_slice()).bind(operation.entity.as_slice()).bind(operation.portion.as_slice())
            .fetch_optional(&mut *tx).await.map_err(database_error)?;
        let current = version
            .as_ref()
            .map(|r| number(r, "version"))
            .transpose()?
            .unwrap_or(0);
        if current != operation.prior_version {
            return Err(LedgerError::VersionConflict);
        }
        if version
            .as_ref()
            .map(|r| {
                r.try_get::<Option<Vec<u8>>, _>("reservation")
                    .map_err(database_error)
            })
            .transpose()?
            .flatten()
            .is_some()
        {
            return Err(LedgerError::Conflict);
        }
        reserve_command(&mut tx, &operation, command, &policy).await?;
        let sequence = number(&row, "sequence")?
            .checked_add(1)
            .ok_or(LedgerError::Conflict)?;
        let mut decision = JournalDecision {
            operation,
            command: command.clone(),
            predecessor: id(&row, "head")?,
            next_head: ZERO,
            sequence,
            target,
        };
        decision.next_head = codec::hash(&codec::journal_body(&decision)?);
        let body = decision.canonical_bytes()?;
        sqlx::query("INSERT INTO ledger_journal(pair,operation,sequence,predecessor,next_head,writer_generation,body) VALUES ($1,$2,$3::text::numeric,$4,$5,$6::text::numeric,$7)")
            .bind(pair.as_slice()).bind(operation_id.as_slice()).bind(sequence.to_string()).bind(decision.predecessor.as_slice())
            .bind(decision.next_head.as_slice()).bind(operation.generation.to_string()).bind(body).execute(&mut *tx).await.map_err(database_error)?;
        sqlx::query("INSERT INTO ledger_versions(pair,entity,portion,version,reservation) VALUES ($1,$2,$3,0,$4) ON CONFLICT(pair,entity,portion) DO UPDATE SET reservation=EXCLUDED.reservation")
            .bind(pair.as_slice()).bind(operation.entity.as_slice()).bind(operation.portion.as_slice()).bind(operation_id.as_slice())
            .execute(&mut *tx).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(decision)
    }
    pub async fn commit_decision(
        &self,
        decision: &JournalDecision,
        acks: &[JournalAcknowledgement],
    ) -> Result<(), LedgerError> {
        self.ready().await?;
        self.trusted(decision.operation.domain.pair).await?;
        for _ in 0..8 {
            match self.commit_once(decision, acks).await {
                Err(LedgerError::SerializationFailure) => tokio::task::yield_now().await,
                result => return result,
            }
        }
        Err(LedgerError::SerializationFailure)
    }
    async fn commit_once(
        &self,
        decision: &JournalDecision,
        acks: &[JournalAcknowledgement],
    ) -> Result<(), LedgerError> {
        let body = decision.canonical_bytes()?;
        let pair = decision.operation.domain.pair;
        let operation_id = decision.operation.id().map_err(|_| LedgerError::Protocol)?;
        let mut tx = serializable(&self.pool).await?;
        let row = pair_row(&mut tx, pair).await?;
        if row.try_get::<i16, _>("halt").map_err(database_error)? != 0 {
            return Err(LedgerError::RollbackDetected);
        }
        let policy = policy(&row)?;
        let certificate = verify_acknowledgements(decision, acks, &policy)?;
        let stored = sqlx::query("SELECT body FROM ledger_journal WHERE pair=$1 AND operation=$2")
            .bind(pair.as_slice())
            .bind(operation_id.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(database_error)?
            .ok_or(LedgerError::MissingEntity)?;
        if stored
            .try_get::<Vec<u8>, _>("body")
            .map_err(database_error)?
            != body
        {
            return Err(LedgerError::Conflict);
        }
        if sqlx::query("SELECT 1 FROM ledger_commits WHERE pair=$1 AND operation=$2")
            .bind(pair.as_slice())
            .bind(operation_id.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(database_error)?
            .is_some()
        {
            return Ok(());
        }
        if number(&row, "generation")? != decision.operation.generation {
            return Err(LedgerError::StaleWriter);
        }
        if id(&row, "head")? != decision.predecessor
            || number(&row, "sequence")?.checked_add(1) != Some(decision.sequence)
        {
            return Err(LedgerError::HeadMismatch);
        }
        if !matches!(decision.command, LedgerCommand::AuthorizeTarget(_)) {
            validate_target_path(&mut tx, &policy, &row, &decision.command).await?;
        }
        apply_command(&mut tx, &decision.operation, &decision.command, &policy).await?;
        let next_version = decision
            .operation
            .prior_version
            .checked_add(1)
            .ok_or(LedgerError::VersionConflict)?;
        let changed = sqlx::query("UPDATE ledger_versions SET version=$5::text::numeric,reservation=NULL WHERE pair=$1 AND entity=$2 AND portion=$3 AND reservation=$4 AND version=$6::text::numeric")
            .bind(pair.as_slice()).bind(decision.operation.entity.as_slice()).bind(decision.operation.portion.as_slice())
            .bind(operation_id.as_slice()).bind(next_version.to_string()).bind(decision.operation.prior_version.to_string())
            .execute(&mut *tx).await.map_err(database_error)?.rows_affected();
        if changed != 1 {
            return Err(LedgerError::VersionConflict);
        }
        let target_head = observed_head(&decision.command, id(&row, "target_head")?);
        sqlx::query("INSERT INTO ledger_commits(pair,operation,certificate) VALUES ($1,$2,$3)")
            .bind(pair.as_slice())
            .bind(operation_id.as_slice())
            .bind(certificate)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("UPDATE ledger_pairs SET head=$2,target_head=$3,sequence=$4::text::numeric WHERE pair=$1")
            .bind(pair.as_slice()).bind(decision.next_head.as_slice()).bind(target_head.as_slice()).bind(decision.sequence.to_string())
            .execute(&mut *tx).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)
    }
    pub async fn pending_decision(&self, pair: Id) -> Result<Option<JournalDecision>, LedgerError> {
        self.ready().await?;
        let mut tx = serializable(&self.pool).await?;
        let pending = pending_tx(&mut tx, pair).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(pending)
    }
    pub async fn credit(&self, pair: Id, credit: Id) -> Result<CreditState, LedgerError> {
        self.ready().await?;
        let row = sqlx::query("SELECT claimant,amount::text AS amount,available::text AS available FROM ledger_credits WHERE pair=$1 AND credit=$2")
            .bind(pair.as_slice()).bind(credit.as_slice()).fetch_optional(&self.pool).await.map_err(database_error)?.ok_or(LedgerError::MissingEntity)?;
        Ok(CreditState {
            credit,
            claimant: id(&row, "claimant")?,
            amount: number(&row, "amount")?,
            available: number(&row, "available")?,
        })
    }
    pub async fn hold(&self, pair: Id, hold: Id) -> Result<HoldState, LedgerError> {
        self.ready().await?;
        let row = sqlx::query("SELECT amount::text AS amount,disposition,COALESCE(v.version,0)::text AS version FROM ledger_holds h LEFT JOIN ledger_versions v ON v.pair=h.pair AND v.entity=h.hold AND v.portion=$3 WHERE h.pair=$1 AND h.hold=$2")
            .bind(pair.as_slice()).bind(hold.as_slice()).bind(ZERO.as_slice()).fetch_optional(&self.pool).await.map_err(database_error)?.ok_or(LedgerError::MissingEntity)?;
        Ok(HoldState {
            hold,
            amount: number(&row, "amount")?,
            version: number(&row, "version")?,
            disposition: disposition(row.try_get("disposition").map_err(database_error)?)?,
        })
    }
    pub async fn intent(&self, pair: Id, intent: Id) -> Result<IntentState, LedgerError> {
        self.ready().await?;
        let row = sqlx::query("SELECT r.transaction,r.nonce,s.status FROM ledger_intent_records r JOIN ledger_intent_states s USING(pair,intent) WHERE pair=$1 AND intent=$2")
            .bind(pair.as_slice()).bind(intent.as_slice()).fetch_optional(&self.pool).await.map_err(database_error)?.ok_or(LedgerError::MissingEntity)?;
        Ok(IntentState {
            intent,
            transaction: id(&row, "transaction")?,
            nonce: id(&row, "nonce")?,
            state: intent_status(row.try_get("status").map_err(database_error)?)?,
        })
    }
    pub async fn inventory_input(&self, pair: Id, note: Id) -> Result<InventoryInput, LedgerError> {
        self.ready().await?;
        let row = sqlx::query(
            "SELECT amount::text AS amount,scope,source_network,source_pool,txid,action_index,note_commitment,nullifier FROM ledger_inventory WHERE pair=$1 AND note=$2",
        )
        .bind(pair.as_slice())
        .bind(note.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or(LedgerError::MissingEntity)?;
        inventory_row_input(&row, note)
    }
    pub async fn native_plan(&self, pair: Id, intent: Id) -> Result<NativePlan, LedgerError> {
        self.ready().await?;
        let row = sqlx::query("SELECT plan FROM ledger_intent_records WHERE pair=$1 AND intent=$2")
            .bind(pair.as_slice())
            .bind(intent.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
            .ok_or(LedgerError::MissingEntity)?;
        codec::decode_native_plan(&row.try_get::<Vec<u8>, _>("plan").map_err(database_error)?)
    }
    pub async fn begin_reconciliation(&self, pair: Id) -> Result<RecoveryChallenge, LedgerError> {
        self.ready().await?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| LedgerError::RecoveryEvidenceMissing)?;
        let mut sessions = self.sessions.lock().await;
        let session = sessions.entry(pair).or_default();
        session.trusted = false;
        session.challenge = Some(nonce);
        if session.error != Some(LedgerError::RollbackDetected) {
            session.error = None;
        }
        Ok(RecoveryChallenge { pair, nonce })
    }
    pub async fn reconcile_heads(
        &self,
        challenge: &RecoveryChallenge,
        heads: &[RetainedHead],
    ) -> Result<RecoveryState, LedgerError> {
        self.ready().await?;
        let mut sessions = self.sessions.lock().await;
        let session = sessions.entry(challenge.pair).or_default();
        if session.error == Some(LedgerError::RollbackDetected) {
            return Err(LedgerError::RollbackDetected);
        }
        if session.challenge != Some(challenge.nonce) || heads.len() != 3 {
            session.error = Some(LedgerError::RecoveryEvidenceMissing);
            return Err(LedgerError::RecoveryEvidenceMissing);
        }
        let mut tx = serializable(&self.pool).await?;
        let row = pair_row(&mut tx, challenge.pair).await?;
        if row.try_get::<i16, _>("halt").map_err(database_error)? != 0 {
            session.error = Some(LedgerError::RollbackDetected);
            return Err(LedgerError::RollbackDetected);
        }
        let policy = policy(&row)?;
        let mut distinct = HashSet::new();
        for head in heads {
            if head.domain != policy.domain
                || head.pair != challenge.pair
                || head.challenge != challenge.nonce
                || !policy.roster.contains(&head.signer)
                || !distinct.insert(head.signer)
                || verify(
                    &head.signer,
                    &codec::signing(b"KERB_RETAINED_HEAD_V1", &codec::retained_bytes(head)?),
                    &head.signature,
                )
                .is_err()
            {
                session.error = Some(LedgerError::RecoveryEvidenceMissing);
                return Err(LedgerError::RecoveryEvidenceMissing);
            }
        }
        let current_head = id(&row, "head")?;
        let current_target = id(&row, "target_head")?;
        let current_sequence = number(&row, "sequence")?;
        let generation = number(&row, "generation")?;
        let pending = pending_tx(&mut tx, challenge.pair).await?;
        let all_current = heads.iter().all(|h| {
            h.head == current_head
                && h.target_head == current_target
                && h.sequence == current_sequence
                && h.generation <= generation
        });
        let all_pending = pending.as_ref().is_some_and(|p| {
            heads.iter().all(|h| {
                h.head == p.next_head
                    && h.sequence == p.sequence
                    && h.generation == p.operation.generation
                    && h.target_head == observed_head(&p.command, current_target)
            })
        });
        let mixed_pending = pending.as_ref().is_some_and(|p| {
            heads.iter().all(|h| {
                (h.head == current_head
                    && h.target_head == current_target
                    && h.sequence == current_sequence
                    && h.generation <= generation)
                    || (h.head == p.next_head
                        && h.sequence == p.sequence
                        && h.generation == p.operation.generation
                        && h.target_head == observed_head(&p.command, current_target))
            })
        });
        if !all_current && !all_pending && mixed_pending {
            tx.commit().await.map_err(database_error)?;
            session.trusted = false;
            session.error = Some(LedgerError::RecoveryEvidenceMissing);
            session.challenge = None;
            return Err(LedgerError::RecoveryEvidenceMissing);
        }
        if !all_current && !all_pending {
            sqlx::query("UPDATE ledger_pairs SET halt=1 WHERE pair=$1")
                .bind(challenge.pair.as_slice())
                .execute(&mut *tx)
                .await
                .map_err(database_error)?;
            tx.commit().await.map_err(database_error)?;
            session.trusted = false;
            session.error = Some(LedgerError::RollbackDetected);
            session.challenge = None;
            return Err(LedgerError::RollbackDetected);
        }
        tx.commit().await.map_err(database_error)?;
        session.trusted = true;
        session.error = None;
        session.challenge = None;
        Ok(if all_pending {
            RecoveryState::PendingRetained
        } else {
            RecoveryState::Current
        })
    }
    pub async fn snapshot(&self, pair: Id) -> Result<PairSnapshot, LedgerError> {
        self.ready().await?;
        let mut tx = serializable(&self.pool).await?;
        let row = pair_row(&mut tx, pair).await?;
        let policy = policy(&row)?;
        let mut s = PairSnapshot {
            available_credit: 0,
            prepared: 0,
            encumbered: 0,
            seller_outstanding: 0,
            buyer_unused_outstanding: 0,
            final_payout: 0,
            final_refund: 0,
            usable_inventory: 0,
            locked_inventory: 0,
            provisional_change: 0,
            pending_recipient: 0,
            sponsor_inventory: 0,
            impaired: row.try_get("impaired").map_err(database_error)?,
            head: id(&row, "head")?,
            target_head: id(&row, "target_head")?,
            sequence: number(&row, "sequence")?,
            writer_generation: number(&row, "generation")?,
            target_generation: number(&row, "target_generation")?,
        };
        for row in sqlx::query("SELECT available::text AS amount FROM ledger_credits WHERE pair=$1")
            .bind(pair.as_slice())
            .fetch_all(&mut *tx)
            .await
            .map_err(database_error)?
        {
            add(&mut s.available_credit, number(&row, "amount")?)?;
        }
        for row in sqlx::query("SELECT h.amount::text AS amount,h.disposition,a.active FROM ledger_holds h LEFT JOIN ledger_allocations a USING(pair,hold) WHERE h.pair=$1").bind(pair.as_slice()).fetch_all(&mut *tx).await.map_err(database_error)? {
            if row.try_get::<Option<bool>, _>("active").map_err(database_error)? == Some(true) { continue; }
            let amount = number(&row, "amount")?; match row.try_get::<i16, _>("disposition").map_err(database_error)? {
                2 => add(&mut s.prepared, amount)?, 3 => add(&mut s.encumbered, amount)?, 5..=7 => add(&mut s.buyer_unused_outstanding, amount)?, _ => {}
            }
        }
        for row in sqlx::query("SELECT p.amount::text AS amount,p.kind,p.disposition,i.status,r.kind AS intent_kind FROM ledger_portions p LEFT JOIN ledger_intent_states i ON i.pair=p.pair AND i.intent=p.live_intent LEFT JOIN ledger_intent_records r ON r.pair=p.pair AND r.intent=p.live_intent WHERE p.pair=$1 AND p.active=true").bind(pair.as_slice()).fetch_all(&mut *tx).await.map_err(database_error)? {
            let amount = number(&row, "amount")?; let state: i16 = row.try_get("disposition").map_err(database_error)?;
            let kind: i16 = row.try_get("kind").map_err(database_error)?;
            if state == 12 { add(&mut s.final_payout, amount)?; }
            else if state == 13 { add(&mut s.final_refund, amount)?; }
            else if row.try_get::<Option<i16>,_>("intent_kind").map_err(database_error)?==Some(NativeIntentKind::BuyerRefund as i16) { add(&mut s.buyer_unused_outstanding,amount)?; }
            else if kind == 1 && state != 8 { add(&mut s.seller_outstanding, amount)?; }
            else { add(&mut s.buyer_unused_outstanding, amount)?; }
            if row.try_get::<Option<i16>, _>("status").map_err(database_error)? == Some(3) { add(&mut s.pending_recipient, amount)?; }
        }
        for row in sqlx::query(
            "SELECT amount::text AS amount,scope,status FROM ledger_inventory WHERE pair=$1",
        )
        .bind(pair.as_slice())
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?
        {
            let amount = number(&row, "amount")?;
            let status: i16 = row.try_get("status").map_err(database_error)?;
            if id(&row, "scope")? == policy.sponsor_scope {
                if status == 1 {
                    add(&mut s.sponsor_inventory, amount)?;
                }
                continue;
            }
            match status {
                1 => add(&mut s.usable_inventory, amount)?,
                2 => add(&mut s.locked_inventory, amount)?,
                4 => add(&mut s.provisional_change, amount)?,
                _ => {}
            }
        }
        tx.commit().await.map_err(database_error)?;
        Ok(s)
    }
}
fn add(total: &mut u128, value: u64) -> Result<(), LedgerError> {
    *total = total
        .checked_add(u128::from(value))
        .ok_or(LedgerError::Database)?;
    Ok(())
}
pub(crate) async fn pending_tx(
    tx: &mut Tx,
    pair: Id,
) -> Result<Option<JournalDecision>, LedgerError> {
    let row = sqlx::query("SELECT j.body FROM ledger_journal j LEFT JOIN ledger_commits c USING(pair,operation) WHERE j.pair=$1 AND c.operation IS NULL ORDER BY j.sequence LIMIT 1")
        .bind(pair.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?;
    row.map(|r| JournalDecision::decode(&r.try_get::<Vec<u8>, _>("body").map_err(database_error)?))
        .transpose()
}
pub(crate) async fn replay_replica_command(
    tx: &mut Tx,
    decision: &JournalDecision,
    policy: &PairPolicy,
) -> Result<(), LedgerError> {
    let op = decision.operation;
    let pair = op.domain.pair;
    let row = pair_row(tx, pair).await?;
    if id(&row, "head")? != decision.predecessor
        || number(&row, "sequence")?.checked_add(1) != Some(decision.sequence)
    {
        return Err(LedgerError::HeadMismatch);
    }
    validate_command_identity(&op, &decision.command)?;
    validate_target_path(tx, policy, &row, &decision.command).await?;
    if row.try_get::<bool, _>("impaired").map_err(database_error)?
        && matches!(
            &decision.command,
            LedgerCommand::PrepareHold { .. }
                | LedgerCommand::ActivateAllocation { .. }
                | LedgerCommand::PrepareFirstLeg { .. }
                | LedgerCommand::ReserveInputs { .. }
                | LedgerCommand::PrepareNative(_)
                | LedgerCommand::AuthorizeTarget(_)
        )
    {
        return Err(LedgerError::InventoryImpaired);
    }
    validate_command(tx, &op, &decision.command, policy).await?;
    let version = sqlx::query("SELECT version::text AS version FROM ledger_versions WHERE pair=$1 AND entity=$2 AND portion=$3 FOR UPDATE")
        .bind(pair.as_slice()).bind(op.entity.as_slice()).bind(op.portion.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?;
    if version
        .as_ref()
        .map(|r| number(r, "version"))
        .transpose()?
        .unwrap_or(0)
        != op.prior_version
    {
        return Err(LedgerError::VersionConflict);
    }
    reserve_command(tx, &op, &decision.command, policy).await?;
    apply_command(tx, &op, &decision.command, policy).await?;
    let next_version = op
        .prior_version
        .checked_add(1)
        .ok_or(LedgerError::VersionConflict)?;
    sqlx::query("INSERT INTO ledger_versions(pair,entity,portion,version) VALUES ($1,$2,$3,$4::text::numeric) ON CONFLICT(pair,entity,portion) DO UPDATE SET version=EXCLUDED.version")
        .bind(pair.as_slice()).bind(op.entity.as_slice()).bind(op.portion.as_slice()).bind(next_version.to_string())
        .execute(&mut **tx).await.map_err(database_error)?;
    let target_head = observed_head(&decision.command, id(&row, "target_head")?);
    sqlx::query("UPDATE ledger_pairs SET head=$2,target_head=$3,sequence=$4::text::numeric,writer_generation=$5::text::numeric WHERE pair=$1")
        .bind(pair.as_slice()).bind(decision.next_head.as_slice()).bind(target_head.as_slice()).bind(decision.sequence.to_string())
        .bind(op.generation.to_string()).execute(&mut **tx).await.map_err(database_error)?;
    Ok(())
}
fn verify_acknowledgements(
    decision: &JournalDecision,
    acks: &[JournalAcknowledgement],
    policy: &PairPolicy,
) -> Result<Vec<u8>, LedgerError> {
    if acks.len() != 3 {
        return Err(LedgerError::MissingUnanimity);
    }
    let signing = decision.signing_bytes()?;
    let mut distinct = HashSet::new();
    let mut target_acks = Vec::new();
    let mut certificate = codec::Encoder::new(b"KERBAC01");
    for ack in acks {
        if ack.decision != *decision
            || !policy.roster.contains(&ack.signer)
            || !distinct.insert(ack.signer)
            || verify(&ack.signer, &signing, &ack.signature).is_err()
        {
            return Err(LedgerError::MissingUnanimity);
        }
        certificate.raw(&ack.signer);
        certificate.raw(&ack.signature);
        match (decision.target, ack.target) {
            (Some(target), Some(target_ack))
                if target_ack.decision == target && target_ack.signer == ack.signer =>
            {
                target_acks.push(target_ack);
                certificate.raw(&target_ack.signature);
            }
            (None, None) => {}
            _ => return Err(LedgerError::MissingUnanimity),
        }
    }
    if let Some(target) = decision.target {
        verify_unanimous(&target, &target_acks, &policy.roster)
            .map_err(|_| LedgerError::MissingUnanimity)?;
    }
    Ok(certificate.0)
}
pub(crate) fn validate_target(
    policy: &PairPolicy,
    target: &SignedTargetFacts,
    predecessor: Id,
) -> Result<(), LedgerError> {
    if target.facts.decision.operation.domain != policy.domain
        || target.facts.decision.predecessor != predecessor
    {
        return Err(LedgerError::InvalidEvidence);
    }
    target
        .facts
        .decision
        .validate()
        .map_err(|_| LedgerError::InvalidEvidence)?;
    target
        .facts
        .observation
        .matches(
            &target.facts.decision.operation,
            policy.environment,
            ChainCommitment::Finalized,
        )
        .map_err(|_| LedgerError::InvalidEvidence)?;
    if target.facts.observation.transaction == ZERO {
        return Err(LedgerError::InvalidEvidence);
    }
    verify(
        &policy.target_observer,
        &target.facts.signing_bytes()?,
        &target.signature,
    )
}
fn disposition(value: i16) -> Result<Disposition, LedgerError> {
    match value {
        1 => Ok(Disposition::Available),
        2 => Ok(Disposition::Prepared),
        3 => Ok(Disposition::EpochEncumbered),
        4 => Ok(Disposition::SellerLiability),
        5 => Ok(Disposition::BuyerUnused),
        6 => Ok(Disposition::Excluded),
        7 => Ok(Disposition::FencedAborted),
        8 => Ok(Disposition::SafelyCancelled),
        9 => Ok(Disposition::FirstLegPrepared),
        10 => Ok(Disposition::SplReleased),
        11 => Ok(Disposition::NativePending),
        12 => Ok(Disposition::FinalPayout),
        13 => Ok(Disposition::FinalRefund),
        14 => Ok(Disposition::Disputed),
        15 => Ok(Disposition::SponsorAvailable),
        _ => Err(LedgerError::Database),
    }
}
fn intent_status(value: i16) -> Result<IntentStatus, LedgerError> {
    match value {
        1 => Ok(IntentStatus::Prepared),
        2 => Ok(IntentStatus::Unknown),
        3 => Ok(IntentStatus::InputConsumed),
        4 => Ok(IntentStatus::Finalized),
        5 => Ok(IntentStatus::Disputed),
        _ => Err(LedgerError::Database),
    }
}
pub(crate) fn validate_command_identity(
    op: &Operation,
    command: &LedgerCommand,
) -> Result<(), LedgerError> {
    let (entity, portion, transition) = match command {
        LedgerCommand::IssueCredit { claim, .. } => {
            if op.intent != claim.credit_intent {
                return Err(LedgerError::InvalidEvidence);
            }
            (claim.credit_intent, ZERO, Transition::IssueCredit)
        }
        LedgerCommand::RegisterSponsor { inventory } => {
            (inventory.facts.note, ZERO, Transition::ReserveInputs)
        }
        LedgerCommand::PrepareHold { .. } => {
            if op.entity != op.intent || op.entity == ZERO {
                return Err(LedgerError::InvalidEvidence);
            }
            (op.entity, ZERO, Transition::PrepareHold)
        }
        LedgerCommand::ObserveEpoch { target } => (
            target.facts.decision.operation.entity,
            ZERO,
            target.facts.decision.operation.transition,
        ),
        LedgerCommand::PrepareAllocation(plan) => (plan.hold, ZERO, Transition::RecordAllocation),
        LedgerCommand::RecordAllocationChunk { hold, .. } => {
            (*hold, ZERO, Transition::RecordAllocation)
        }
        LedgerCommand::ActivateAllocation { target } => (
            target.facts.decision.operation.entity,
            ZERO,
            Transition::ActivateAllocation,
        ),
        LedgerCommand::PrepareFirstLeg { hold, portion } => {
            (*hold, *portion, Transition::PrepareFill)
        }
        LedgerCommand::ObserveSplRelease { hold, portion, .. } => {
            (*hold, *portion, Transition::ReleaseSpl)
        }
        LedgerCommand::CancelFirstLeg { hold, portion, .. } => {
            (*hold, *portion, Transition::CancelFill)
        }
        LedgerCommand::ReserveInputs { .. } => (op.entity, ZERO, Transition::ReserveInputs),
        LedgerCommand::PrepareNative(plan) => (plan.hold, plan.portion, Transition::PrepareNative),
        LedgerCommand::NativeUnknown { intent, .. } => (*intent, ZERO, Transition::ObserveNative),
        LedgerCommand::ObserveNative(facts) => {
            (facts.facts.intent, ZERO, Transition::ObserveNative)
        }
        LedgerCommand::ImpairInventory { inventory } => {
            (inventory.facts.note, ZERO, Transition::ObserveNative)
        }
        LedgerCommand::AuthorizeTarget(v) => (v.hold, v.portion, Transition::PrepareFill),
        LedgerCommand::ObserveTarget(fact) => (
            fact.facts
                .decision
                .operation
                .id()
                .map_err(|_| LedgerError::Protocol)?,
            ZERO,
            Transition::ObserveNative,
        ),
    };
    if op.entity != entity || op.portion != portion || op.transition != transition {
        return Err(LedgerError::InvalidEvidence);
    }
    Ok(())
}
fn inventory_context(
    policy: &PairPolicy,
    inventory: &SignedInventoryFacts,
) -> Result<(), LedgerError> {
    let f = &inventory.facts;
    if f.domain != policy.domain
        || f.provenance != policy.environment
        || f.receiver != policy.receiver
        || f.control != policy.inventory_producer
        || f.history_anchor != policy.history_anchor
        || f.value == 0
        || f.note == ZERO
        || f.note_commitment == ZERO
        || f.nullifier == ZERO
        || f.occurrence.txid == ZERO
        || f.occurrence.network != policy.domain.source_network
        || f.occurrence.pool != policy.domain.source_pool
    {
        return Err(LedgerError::InvalidEvidence);
    }
    verify(
        &policy.inventory_producer,
        &f.signing_bytes()?,
        &inventory.signature,
    )
}
async fn validate_physical_admission(
    tx: &mut Tx,
    domain: &Domain,
    note: Id,
    occurrence: &SourceOccurrence,
    note_commitment: Id,
    nullifier: Id,
    operation: Option<Id>,
) -> Result<(), LedgerError> {
    let row = sqlx::query("SELECT pair,note,source_network,source_pool,source_genesis,txid,action_index,note_commitment,nullifier,operation,change_intent FROM ledger_physical_claims WHERE (pair=$1 AND note=$2) OR (source_network=$3 AND source_pool=$4 AND source_genesis=$5 AND ((txid=$6 AND action_index=$7) OR note_commitment=$8 OR nullifier=$9)) LIMIT 1")
        .bind(domain.pair.as_slice()).bind(note.as_slice()).bind(i16::from(occurrence.network)).bind(i16::from(occurrence.pool))
        .bind(domain.source_genesis.as_slice()).bind(occurrence.txid.as_slice()).bind(i64::from(occurrence.action_index))
        .bind(note_commitment.as_slice()).bind(nullifier.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?;
    if let Some(row) = row
        && (operation != Some(id(&row, "operation")?)
            || row
                .try_get::<Option<Vec<u8>>, _>("change_intent")
                .map_err(database_error)?
                .is_some()
            || id(&row, "pair")? != domain.pair
            || id(&row, "note")? != note
            || row
                .try_get::<i16, _>("source_network")
                .map_err(database_error)?
                != i16::from(occurrence.network)
            || row
                .try_get::<i16, _>("source_pool")
                .map_err(database_error)?
                != i16::from(occurrence.pool)
            || id(&row, "source_genesis")? != domain.source_genesis
            || id(&row, "txid")? != occurrence.txid
            || row
                .try_get::<i64, _>("action_index")
                .map_err(database_error)?
                != i64::from(occurrence.action_index)
            || id(&row, "note_commitment")? != note_commitment
            || id(&row, "nullifier")? != nullifier)
    {
        return Err(LedgerError::Conflict);
    }
    Ok(())
}
async fn validate_inventory_admission(
    tx: &mut Tx,
    op: &Operation,
    facts: &InventoryFacts,
) -> Result<(), LedgerError> {
    if sqlx::query("SELECT 1 FROM ledger_inventory WHERE pair=$1 AND note=$2 UNION ALL SELECT 1 FROM ledger_change_reservations WHERE pair=$1 AND note=$2 LIMIT 1")
        .bind(op.domain.pair.as_slice()).bind(facts.note.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?.is_some()
    {
        return Err(LedgerError::Conflict);
    }
    validate_physical_admission(
        tx,
        &facts.domain,
        facts.note,
        &facts.occurrence,
        facts.note_commitment,
        facts.nullifier,
        Some(op.id().map_err(|_| LedgerError::Protocol)?),
    )
    .await
}
fn change_occurrence(domain: &Domain, transaction: Id, action_index: u32) -> SourceOccurrence {
    SourceOccurrence {
        network: domain.source_network,
        pool: domain.source_pool,
        txid: transaction,
        action_index,
    }
}
async fn reserve_physical_claim(
    tx: &mut Tx,
    op: &Operation,
    note: Id,
    occurrence: &SourceOccurrence,
    note_commitment: Id,
    nullifier: Id,
    change_intent: Option<Id>,
) -> Result<(), LedgerError> {
    sqlx::query("INSERT INTO ledger_physical_claims(pair,note,source_network,source_pool,source_genesis,txid,action_index,note_commitment,nullifier,operation,change_intent) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(op.domain.pair.as_slice()).bind(note.as_slice()).bind(i16::from(occurrence.network)).bind(i16::from(occurrence.pool))
        .bind(op.domain.source_genesis.as_slice()).bind(occurrence.txid.as_slice()).bind(i64::from(occurrence.action_index))
        .bind(note_commitment.as_slice()).bind(nullifier.as_slice()).bind(op.id().map_err(|_| LedgerError::Protocol)?.as_slice())
        .bind(change_intent.as_ref().map(|intent| intent.as_slice())).execute(&mut **tx).await.map_err(database_error)?;
    Ok(())
}
async fn validate_change_reservations(
    tx: &mut Tx,
    domain: &Domain,
    plan: &NativePlan,
    intent: Id,
) -> Result<(), LedgerError> {
    for change in &plan.change {
        let owned = sqlx::query("SELECT 1 FROM ledger_physical_claims c JOIN ledger_change_reservations r USING(pair,note) WHERE c.pair=$1 AND c.note=$2 AND c.change_intent=$3 AND r.intent=$3 AND c.source_network=$4 AND c.source_pool=$5 AND c.source_genesis=$6 AND c.txid=$7 AND c.action_index=$8 AND c.note_commitment=$9 AND c.nullifier=$10")
            .bind(domain.pair.as_slice()).bind(change.note.as_slice()).bind(intent.as_slice())
            .bind(i16::from(domain.source_network)).bind(i16::from(domain.source_pool)).bind(domain.source_genesis.as_slice())
            .bind(plan.transaction.as_slice()).bind(i64::from(change.action_index)).bind(change.note_commitment.as_slice()).bind(change.nullifier.as_slice())
            .fetch_optional(&mut **tx).await.map_err(database_error)?;
        if owned.is_none() {
            return Err(LedgerError::Conflict);
        }
    }
    Ok(())
}
async fn validate_credit(
    tx: &mut Tx,
    op: &Operation,
    claim: &FundingClaim,
    source: &SignedSourceFacts,
    inventory: &SignedInventoryFacts,
    policy: &PairPolicy,
) -> Result<(), LedgerError> {
    verify_funding_claim(claim).map_err(|_| LedgerError::InvalidAuthorization)?;
    verify(
        &policy.source_producer,
        &source.facts.signing_bytes()?,
        &source.signature,
    )?;
    inventory_context(policy, inventory)?;
    let s = &source.facts;
    let i = &inventory.facts;
    if claim.domain != policy.domain
        || claim.block_policy != policy.source_policy
        || claim.receiver != policy.receiver
        || claim.value == 0
        || s.domain != policy.domain
        || s.provenance != policy.environment
        || s.occurrence != claim.occurrence
        || s.receiver != claim.receiver
        || s.value != claim.value
        || s.block == ZERO
        || s.confirmations < policy.minimum_confirmations
        || s.history_anchor != policy.history_anchor
        || s.policy != policy.source_policy
        || s.effect
            != (SourceEffect::Deposit {
                claimant: claim.claimant,
                credit_intent: claim.credit_intent,
            })
        || claim.evidence_digest != s.digest()?
        || i.note != claim.inventory_note
        || i.occurrence != claim.occurrence
        || i.value != claim.value
        || i.scope != policy.inventory_scope
        || i.origin != InventoryOrigin::Deposit
        || i.condition != InventoryCondition::Spendable
    {
        return Err(LedgerError::InvalidEvidence);
    }
    if sqlx::query("SELECT 1 FROM ledger_credits WHERE source_network=$1 AND source_pool=$2 AND source_genesis=$3 AND txid=$4 AND action_index=$5")
        .bind(i16::from(claim.occurrence.network)).bind(i16::from(claim.occurrence.pool)).bind(claim.domain.source_genesis.as_slice())
        .bind(claim.occurrence.txid.as_slice()).bind(i64::from(claim.occurrence.action_index)).fetch_optional(&mut **tx).await.map_err(database_error)?.is_some() { return Err(LedgerError::DuplicateOccurrence); }
    validate_inventory_admission(tx, op, i).await
}
async fn hold_row(tx: &mut Tx, pair: Id, hold: Id) -> Result<PgRow, LedgerError> {
    sqlx::query("SELECT credit,amount::text AS amount,refund_receiver,disposition FROM ledger_holds WHERE pair=$1 AND hold=$2 FOR UPDATE")
        .bind(pair.as_slice()).bind(hold.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(LedgerError::MissingEntity)
}
async fn portion_row(tx: &mut Tx, pair: Id, hold: Id, portion: Id) -> Result<PgRow, LedgerError> {
    sqlx::query("SELECT allocation,amount::text AS amount,kind,native_recipient,spl_recipient,target_base_amount::text AS target_base_amount,disposition,active,live_intent FROM ledger_portions WHERE pair=$1 AND hold=$2 AND portion=$3 FOR UPDATE")
        .bind(pair.as_slice()).bind(hold.as_slice()).bind(portion.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(LedgerError::NotReturnable)
}
pub(crate) async fn validate_epoch_activation(
    tx: &mut Tx,
    policy: &PairPolicy,
) -> Result<(), LedgerError> {
    let row = sqlx::query("SELECT target_result FROM ledger_pairs WHERE pair=$1")
        .bind(policy.domain.pair.as_slice())
        .fetch_one(&mut **tx)
        .await
        .map_err(database_error)?;
    let result = id(&row, "target_result")?;
    let holds=sqlx::query("SELECT hold,amount::text AS amount,target_binding FROM ledger_holds WHERE pair=$1 AND disposition=3")
        .bind(policy.domain.pair.as_slice()).fetch_all(&mut **tx).await.map_err(database_error)?;
    if holds.is_empty() {
        return Err(LedgerError::IncompleteAllocation);
    }
    for hold in holds {
        let hold_id = id(&hold, "hold")?;
        let binding = codec::target_binding_decode(
            &hold
                .try_get::<Vec<u8>, _>("target_binding")
                .map_err(database_error)?,
        )?;
        if !matches!(binding.evidence, TargetHoldEvidence::Prepared { .. }) {
            return Err(LedgerError::InvalidEvidence);
        }
        let allocation = sqlx::query(
            "SELECT allocation,active FROM ledger_allocations WHERE pair=$1 AND hold=$2",
        )
        .bind(policy.domain.pair.as_slice())
        .bind(hold_id.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
        .ok_or(LedgerError::IncompleteAllocation)?;
        if id(&allocation, "allocation")? != result
            || allocation
                .try_get::<bool, _>("active")
                .map_err(database_error)?
        {
            return Err(LedgerError::IncompleteAllocation);
        }
        let chunks = sqlx::query(
            "SELECT authenticated FROM ledger_allocation_chunks WHERE pair=$1 AND hold=$2",
        )
        .bind(policy.domain.pair.as_slice())
        .bind(hold_id.as_slice())
        .fetch_all(&mut **tx)
        .await
        .map_err(database_error)?;
        if chunks.len() != binding.expected_chunks as usize
            || chunks
                .iter()
                .any(|r| r.try_get::<bool, _>("authenticated").ok() != Some(true))
        {
            return Err(LedgerError::IncompleteAllocation);
        }
        let portions=sqlx::query("SELECT portion,offset_amount::text AS offset_amount,amount::text AS amount,target_base_offset::text AS base_offset,target_base_amount::text AS base_amount,kind FROM ledger_portions WHERE pair=$1 AND hold=$2")
            .bind(policy.domain.pair.as_slice()).bind(hold_id.as_slice()).fetch_all(&mut **tx).await.map_err(database_error)?;
        if portions.len() != chunks.len() {
            return Err(LedgerError::IncompleteAllocation);
        }
        let mut quote = Vec::with_capacity(portions.len());
        let mut base = Vec::with_capacity(portions.len());
        for portion in portions {
            let kind = match portion.try_get::<i16, _>("kind").map_err(database_error)? {
                1 => AllocationKind::SellerLiability,
                2 => AllocationKind::BuyerUnused,
                _ => return Err(LedgerError::Database),
            };
            let p = id(&portion, "portion")?;
            quote.push(AllocationPortion {
                portion: p,
                offset: number(&portion, "offset_amount")?,
                amount: number(&portion, "amount")?,
                kind,
            });
            base.push(AllocationPortion {
                portion: p,
                offset: number(&portion, "base_offset")?,
                amount: number(&portion, "base_amount")?,
                kind,
            });
        }
        AllocationPartition { portions: &quote }
            .validate(number(&hold, "amount")?)
            .map_err(|_| LedgerError::IncompleteAllocation)?;
        AllocationPartition { portions: &base }
            .validate(binding.maximum_base)
            .map_err(|_| LedgerError::IncompleteAllocation)?;
    }
    Ok(())
}
async fn validate_command(
    tx: &mut Tx,
    op: &Operation,
    command: &LedgerCommand,
    policy: &PairPolicy,
) -> Result<(), LedgerError> {
    let pair = op.domain.pair;
    match command {
        LedgerCommand::IssueCredit {
            claim,
            source,
            inventory,
        } => validate_credit(tx, op, claim, source, inventory, policy).await?,
        LedgerCommand::RegisterSponsor { inventory } => {
            inventory_context(policy, inventory)?;
            if inventory.facts.origin != InventoryOrigin::Sponsor
                || inventory.facts.scope != policy.sponsor_scope
                || inventory.facts.condition != InventoryCondition::Spendable
            {
                return Err(LedgerError::InvalidEvidence);
            }
            validate_inventory_admission(tx, op, &inventory.facts).await?;
        }
        LedgerCommand::PrepareHold {
            credit,
            amount,
            refund_receiver,
            authorization,
            ..
        } => {
            let row = sqlx::query("SELECT claimant,available::text AS available FROM ledger_credits WHERE pair=$1 AND credit=$2 FOR UPDATE")
                .bind(pair.as_slice()).bind(credit.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(LedgerError::MissingEntity)?;
            verify_operation(
                op,
                SignatureRole::Application,
                &id(&row, "claimant")?,
                authorization,
            )
            .map_err(|_| LedgerError::InvalidAuthorization)?;
            if *amount == 0 || *refund_receiver == [0; 43] {
                return Err(LedgerError::InvalidEvidence);
            }
            if number(&row, "available")? < *amount {
                return Err(LedgerError::InsufficientCredit);
            }
        }
        LedgerCommand::ObserveEpoch { target } => {
            if !matches!(
                target.facts.decision.operation.transition,
                Transition::CommitEpoch | Transition::AbortEpoch
            ) {
                return Err(LedgerError::InvalidEvidence);
            }
            let rows = sqlx::query("SELECT disposition FROM ledger_holds WHERE pair=$1")
                .bind(pair.as_slice())
                .fetch_all(&mut **tx)
                .await
                .map_err(database_error)?;
            if rows.is_empty()
                || rows
                    .iter()
                    .any(|r| r.try_get::<i16, _>("disposition").ok() != Some(2))
            {
                return Err(LedgerError::NotReturnable);
            }
        }
        LedgerCommand::PrepareAllocation(plan) => {
            let row = hold_row(tx, pair, plan.hold).await?;
            if row
                .try_get::<i16, _>("disposition")
                .map_err(database_error)?
                != 3
                || plan.allocation == ZERO
                || plan.chunks.is_empty()
                || plan.chunks.len() > codec::MAX_ITEMS
            {
                return Err(LedgerError::IncompleteAllocation);
            }
            let portions: Vec<_> = plan
                .portions
                .iter()
                .map(|p| AllocationPortion {
                    portion: p.portion,
                    offset: p.offset,
                    amount: p.amount,
                    kind: p.kind,
                })
                .collect();
            AllocationPartition {
                portions: &portions,
            }
            .validate(number(&row, "amount")?)
            .map_err(|_| LedgerError::InvalidEvidence)?;
            let binding = super::target::binding(tx, pair, plan.hold).await?;
            let base: Vec<_> = plan
                .portions
                .iter()
                .map(|p| AllocationPortion {
                    portion: p.portion,
                    offset: p.target_base_offset,
                    amount: p.target_base_amount,
                    kind: p.kind,
                })
                .collect();
            AllocationPartition { portions: &base }
                .validate(binding.maximum_base)
                .map_err(|_| LedgerError::InvalidEvidence)?;
            if plan.chunks.len() != binding.expected_chunks as usize
                || plan.portions.len() != plan.chunks.len()
            {
                return Err(LedgerError::IncompleteAllocation);
            }
            for p in &plan.portions {
                if p.native_recipient == [0; 43]
                    || (p.kind == AllocationKind::BuyerUnused
                        && (p.native_recipient != receiver(&row, "refund_receiver")?
                            || p.spl_recipient != binding.refund_token))
                    || (p.kind == AllocationKind::SellerLiability
                        && (p.target_base_amount == 0
                            || p.spl_recipient == ZERO
                            || p.fill_fence == ZERO))
                {
                    return Err(LedgerError::InvalidEvidence);
                }
            }
            if sqlx::query("SELECT 1 FROM ledger_allocations WHERE pair=$1 AND hold=$2")
                .bind(pair.as_slice())
                .bind(plan.hold.as_slice())
                .fetch_optional(&mut **tx)
                .await
                .map_err(database_error)?
                .is_some()
            {
                return Err(LedgerError::Conflict);
            }
        }
        LedgerCommand::RecordAllocationChunk {
            hold,
            allocation,
            index,
            digest,
            target,
        } => {
            let row = sqlx::query("SELECT a.allocation,a.active,c.digest,c.authenticated FROM ledger_allocations a JOIN ledger_allocation_chunks c USING(pair,hold) WHERE a.pair=$1 AND a.hold=$2 AND c.chunk_index=$3 FOR UPDATE")
                .bind(pair.as_slice()).bind(hold.as_slice()).bind(i64::from(*index)).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(LedgerError::IncompleteAllocation)?;
            if id(&row, "allocation")? != *allocation
                || id(&row, "digest")? != *digest
                || row.try_get::<bool, _>("active").map_err(database_error)?
                || row
                    .try_get::<bool, _>("authenticated")
                    .map_err(database_error)?
                || target.facts.decision.operation.transition != Transition::RecordAllocation
                || target.facts.decision.operation.effects != *digest
            {
                return Err(LedgerError::InvalidEvidence);
            }
        }
        LedgerCommand::ActivateAllocation { target } => {
            if target.facts.decision.operation.transition != Transition::ActivateAllocation {
                return Err(LedgerError::InvalidEvidence);
            }
            validate_epoch_activation(tx, policy).await?;
        }
        LedgerCommand::PrepareFirstLeg { hold, portion } => {
            let row = portion_row(tx, pair, *hold, *portion).await?;
            if !row.try_get::<bool, _>("active").map_err(database_error)? {
                return Err(LedgerError::IncompleteAllocation);
            }
            if row
                .try_get::<i16, _>("disposition")
                .map_err(database_error)?
                != 4
                || row
                    .try_get::<Option<Vec<u8>>, _>("live_intent")
                    .map_err(database_error)?
                    .is_some()
            {
                return Err(LedgerError::CompetingIntent);
            }
        }
        LedgerCommand::ObserveSplRelease {
            hold,
            portion,
            recipient: recipient_id,
            target_base_amount,
            target,
        } => {
            let row = portion_row(tx, pair, *hold, *portion).await?;
            if !row.try_get::<bool, _>("active").map_err(database_error)?
                || row
                    .try_get::<i16, _>("disposition")
                    .map_err(database_error)?
                    != 9
            {
                return Err(LedgerError::CompetingIntent);
            }
            if id(&row, "spl_recipient")? != *recipient_id
                || number(&row, "target_base_amount")? != *target_base_amount
                || target.facts.decision.operation.transition != Transition::ReleaseSpl
            {
                return Err(LedgerError::InvalidEvidence);
            }
        }
        LedgerCommand::CancelFirstLeg {
            hold,
            portion,
            target,
        } => {
            let row = portion_row(tx, pair, *hold, *portion).await?;
            if !row.try_get::<bool, _>("active").map_err(database_error)?
                || !matches!(
                    row.try_get::<i16, _>("disposition")
                        .map_err(database_error)?,
                    4 | 9
                )
                || row
                    .try_get::<Option<Vec<u8>>, _>("live_intent")
                    .map_err(database_error)?
                    .is_some()
            {
                return Err(LedgerError::CompetingIntent);
            }
            if target.facts.decision.operation.transition != Transition::CancelFill {
                return Err(LedgerError::InvalidEvidence);
            }
        }
        LedgerCommand::ReserveInputs { inputs, scope } => {
            validate_inputs(tx, pair, inputs, *scope, policy, None).await?;
        }
        LedgerCommand::PrepareNative(plan) => validate_native_plan(tx, op, plan, policy).await?,
        LedgerCommand::NativeUnknown {
            intent,
            transaction,
        } => {
            let row = sqlx::query("SELECT r.transaction,s.status FROM ledger_intent_records r JOIN ledger_intent_states s USING(pair,intent) WHERE pair=$1 AND intent=$2 FOR UPDATE")
                .bind(pair.as_slice()).bind(intent.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(LedgerError::MissingEntity)?;
            if id(&row, "transaction")? != *transaction
                || !matches!(
                    row.try_get::<i16, _>("status").map_err(database_error)?,
                    1 | 2
                )
            {
                return Err(LedgerError::Conflict);
            }
        }
        LedgerCommand::ObserveNative(facts) => validate_native_facts(tx, facts, policy).await?,
        LedgerCommand::ImpairInventory { inventory } => {
            inventory_context(policy, inventory)?;
            if inventory.facts.condition == InventoryCondition::Spendable
                || (inventory.facts.scope != policy.inventory_scope
                    && inventory.facts.scope != policy.sponsor_scope)
            {
                return Err(LedgerError::InvalidEvidence);
            }
            let row = sqlx::query("SELECT scope,amount::text AS amount,receiver,origin,parent_intent,source_network,source_pool,source_genesis,txid,action_index,note_commitment,nullifier FROM ledger_inventory WHERE pair=$1 AND note=$2")
                .bind(pair.as_slice()).bind(inventory.facts.note.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(LedgerError::MissingEntity)?;
            let f = &inventory.facts;
            let retained = inventory_row_input(&row, f.note)?;
            let parent = row
                .try_get::<Option<Vec<u8>>, _>("parent_intent")
                .map_err(database_error)?;
            let origin: i16 = row.try_get("origin").map_err(database_error)?;
            let same_origin = match f.origin {
                InventoryOrigin::Deposit => origin == 1 && parent.is_none(),
                InventoryOrigin::Sponsor => origin == 3 && parent.is_none(),
                InventoryOrigin::Change { parent_intent } => {
                    origin == 2 && parent.as_deref() == Some(parent_intent.as_slice())
                }
            };
            if retained.value != f.value
                || retained.scope != f.scope
                || retained.occurrence != f.occurrence
                || retained.note_commitment != f.note_commitment
                || retained.nullifier != f.nullifier
                || id(&row, "source_genesis")? != f.domain.source_genesis
                || receiver(&row, "receiver")? != f.receiver
                || !same_origin
            {
                return Err(LedgerError::InvalidEvidence);
            }
        }
        LedgerCommand::AuthorizeTarget(auth) => {
            super::target::validate_authorization(tx, policy, auth).await?
        }
        LedgerCommand::ObserveTarget(fact) => {
            if !matches!(
                fact.facts.decision.operation.transition,
                Transition::PrepareFill | Transition::ReturnUnused
            ) {
                return Err(LedgerError::InvalidEvidence);
            }
        }
    }
    Ok(())
}
async fn validate_inputs(
    tx: &mut Tx,
    pair: Id,
    inputs: &[Id],
    scope: Id,
    policy: &PairPolicy,
    intent: Option<Id>,
) -> Result<u128, LedgerError> {
    if inputs.is_empty()
        || inputs.len() > codec::MAX_ITEMS
        || (scope != policy.inventory_scope && scope != policy.sponsor_scope)
    {
        return Err(LedgerError::InventoryUnavailable);
    }
    let mut distinct = HashSet::new();
    let mut total = 0_u128;
    for note in inputs {
        if !distinct.insert(*note) {
            return Err(LedgerError::InventoryUnavailable);
        }
        let row = sqlx::query("SELECT scope,amount::text AS amount,status,live_intent,source_network,source_pool,source_genesis,txid,action_index,note_commitment,nullifier FROM ledger_inventory WHERE pair=$1 AND note=$2 FOR UPDATE")
            .bind(pair.as_slice()).bind(note.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(LedgerError::InventoryUnavailable)?;
        let retained = inventory_row_input(&row, *note)?;
        if retained.occurrence.network != policy.domain.source_network
            || retained.occurrence.pool != policy.domain.source_pool
            || id(&row, "source_genesis")? != policy.domain.source_genesis
        {
            return Err(LedgerError::InvalidEvidence);
        }
        let status: i16 = row.try_get("status").map_err(database_error)?;
        let live = row
            .try_get::<Option<Vec<u8>>, _>("live_intent")
            .map_err(database_error)?;
        if retained.scope != scope
            || (status != 1
                && !(status == 2 && intent.is_some_and(|i| live.as_deref() == Some(i.as_slice()))))
        {
            return Err(LedgerError::InventoryUnavailable);
        }
        add(&mut total, retained.value)?;
    }
    Ok(total)
}
async fn validate_native_plan(
    tx: &mut Tx,
    op: &Operation,
    plan: &NativePlan,
    policy: &PairPolicy,
) -> Result<(), LedgerError> {
    let pair = op.domain.pair;
    if plan.amount == 0
        || plan.recipient == [0; 43]
        || plan.nonce == ZERO
        || plan.pczt_digest == ZERO
        || plan.sighash == ZERO
        || plan.transaction == ZERO
    {
        return Err(LedgerError::InvalidEvidence);
    }
    if plan.kind == NativeIntentKind::SponsorFee {
        if plan.inventory_scope != policy.sponsor_scope
            || plan.hold != op.entity
            || plan.portion == ZERO
            || !plan.fee_inputs.is_empty()
        {
            return Err(LedgerError::InventoryUnavailable);
        }
    } else {
        let row = portion_row(tx, pair, plan.hold, plan.portion).await?;
        if !row.try_get::<bool, _>("active").map_err(database_error)? {
            return Err(LedgerError::NotReturnable);
        }
        if row
            .try_get::<Option<Vec<u8>>, _>("live_intent")
            .map_err(database_error)?
            .is_some()
        {
            return Err(LedgerError::CompetingIntent);
        }
        let state: i16 = row.try_get("disposition").map_err(database_error)?;
        match plan.kind {
            NativeIntentKind::BuyerRefund if !matches!(state, 5..=8) => {
                return Err(LedgerError::NotReturnable);
            }
            NativeIntentKind::SellerPayout if state != 10 => {
                return Err(LedgerError::NotReturnable);
            }
            _ => {}
        }
        let expected_receiver = if state == 8 {
            receiver(&hold_row(tx, pair, plan.hold).await?, "refund_receiver")?
        } else {
            receiver(&row, "native_recipient")?
        };
        if plan.recipient != expected_receiver
            || plan.amount != number(&row, "amount")?
            || plan.inventory_scope != policy.inventory_scope
        {
            return Err(LedgerError::InvalidEvidence);
        }
    }
    let total = validate_inputs(
        tx,
        pair,
        &plan.inputs,
        plan.inventory_scope,
        policy,
        Some(op.intent),
    )
    .await?;
    let mut outputs = u128::from(plan.amount);
    if plan.kind == NativeIntentKind::SponsorFee {
        add(&mut outputs, plan.fee)?;
    }
    let mut distinct = HashSet::new();
    let mut action_indices = HashSet::new();
    let mut commitments = HashSet::new();
    let mut nullifiers = HashSet::new();
    for change in &plan.change {
        if change.note == ZERO
            || change.value == 0
            || change.note_commitment == ZERO
            || change.nullifier == ZERO
            || !action_indices.insert(change.action_index)
            || !commitments.insert(change.note_commitment)
            || !nullifiers.insert(change.nullifier)
            || change.receiver != policy.receiver
            || !distinct.insert(change.note)
            || plan.inputs.contains(&change.note)
            || plan.fee_inputs.contains(&change.note)
        {
            return Err(LedgerError::InvalidEvidence);
        }
        if sqlx::query("SELECT 1 FROM ledger_inventory WHERE pair=$1 AND note=$2")
            .bind(pair.as_slice())
            .bind(change.note.as_slice())
            .fetch_optional(&mut **tx)
            .await
            .map_err(database_error)?
            .is_some()
        {
            return Err(LedgerError::Conflict);
        }
        if sqlx::query("SELECT 1 FROM ledger_change_reservations WHERE pair=$1 AND note=$2")
            .bind(pair.as_slice())
            .bind(change.note.as_slice())
            .fetch_optional(&mut **tx)
            .await
            .map_err(database_error)?
            .is_some()
        {
            return Err(LedgerError::Conflict);
        }
        let occurrence = change_occurrence(&policy.domain, plan.transaction, change.action_index);
        validate_physical_admission(
            tx,
            &policy.domain,
            change.note,
            &occurrence,
            change.note_commitment,
            change.nullifier,
            None,
        )
        .await?;
        add(&mut outputs, change.value)?;
    }
    if total != outputs {
        return Err(LedgerError::InvalidEvidence);
    }
    if plan.kind != NativeIntentKind::SponsorFee {
        if plan.fee == 0 {
            if !plan.fee_inputs.is_empty() {
                return Err(LedgerError::InvalidEvidence);
            }
        } else {
            if plan
                .fee_inputs
                .iter()
                .any(|note| plan.inputs.contains(note))
            {
                return Err(LedgerError::InventoryUnavailable);
            }
            let sponsor = validate_inputs(
                tx,
                pair,
                &plan.fee_inputs,
                policy.sponsor_scope,
                policy,
                Some(op.intent),
            )
            .await?;
            if sponsor != u128::from(plan.fee) {
                return Err(LedgerError::InvalidEvidence);
            }
        }
    }
    if sqlx::query("SELECT 1 FROM ledger_intent_records WHERE pair=$1 AND (intent=$2 OR nonce=$3 OR transaction=$4)")
        .bind(pair.as_slice()).bind(op.intent.as_slice()).bind(plan.nonce.as_slice()).bind(plan.transaction.as_slice())
        .fetch_optional(&mut **tx).await.map_err(database_error)?.is_some() { return Err(LedgerError::CompetingIntent); }
    Ok(())
}
async fn validate_native_facts(
    tx: &mut Tx,
    signed: &SignedNativeFacts,
    policy: &PairPolicy,
) -> Result<(), LedgerError> {
    let facts = &signed.facts;
    verify(
        &policy.inventory_producer,
        &facts.signing_bytes()?,
        &signed.signature,
    )?;
    if facts.domain != policy.domain
        || facts.provenance != policy.environment
        || facts.history_anchor != policy.history_anchor
        || facts.block == ZERO
    {
        return Err(LedgerError::InvalidEvidence);
    }
    let row = sqlx::query("SELECT r.plan,s.status FROM ledger_intent_records r JOIN ledger_intent_states s USING(pair,intent) WHERE pair=$1 AND intent=$2 FOR UPDATE")
        .bind(policy.domain.pair.as_slice()).bind(facts.intent.as_slice()).fetch_optional(&mut **tx).await.map_err(database_error)?.ok_or(LedgerError::MissingEntity)?;
    let plan =
        codec::decode_native_plan(&row.try_get::<Vec<u8>, _>("plan").map_err(database_error)?)?;
    let expected_inputs: Vec<Id> = plan
        .inputs
        .iter()
        .chain(&plan.fee_inputs)
        .copied()
        .collect();
    if facts.transaction == plan.transaction && facts.inputs != expected_inputs {
        return Err(LedgerError::InvalidEvidence);
    }
    let incompatible = facts.transaction != plan.transaction
        || facts.recipient != plan.recipient
        || facts.amount != plan.amount
        || facts.change != plan.change
        || facts.inputs != expected_inputs;
    if incompatible {
        let mut distinct = HashSet::new();
        if facts.transaction == ZERO
            || facts.confirmations < policy.minimum_confirmations
            || facts.inputs.is_empty()
            || !facts
                .inputs
                .iter()
                .any(|input| expected_inputs.contains(input))
            || facts.inputs.iter().any(|input| !distinct.insert(*input))
        {
            return Err(LedgerError::InvalidEvidence);
        }
    } else {
        validate_change_reservations(tx, &policy.domain, &plan, facts.intent).await?;
    }
    if !matches!(
        row.try_get::<i16, _>("status").map_err(database_error)?,
        1..=5
    ) {
        return Err(LedgerError::Conflict);
    }
    Ok(())
}
async fn lock_inputs(tx: &mut Tx, pair: Id, inputs: &[Id], intent: Id) -> Result<(), LedgerError> {
    for note in inputs {
        sqlx::query(
            "UPDATE ledger_inventory SET status=2,live_intent=$3 WHERE pair=$1 AND note=$2",
        )
        .bind(pair.as_slice())
        .bind(note.as_slice())
        .bind(intent.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    }
    Ok(())
}
async fn reserve_command(
    tx: &mut Tx,
    op: &Operation,
    command: &LedgerCommand,
    _: &PairPolicy,
) -> Result<(), LedgerError> {
    let pair = op.domain.pair;
    match command {
        LedgerCommand::IssueCredit { inventory, .. }
        | LedgerCommand::RegisterSponsor { inventory } => {
            let facts = &inventory.facts;
            reserve_physical_claim(
                tx,
                op,
                facts.note,
                &facts.occurrence,
                facts.note_commitment,
                facts.nullifier,
                None,
            )
            .await?;
        }
        LedgerCommand::PrepareHold {
            credit,
            amount,
            refund_receiver,
            target,
            ..
        } => {
            sqlx::query("UPDATE ledger_credits SET available=available-$3::text::numeric WHERE pair=$1 AND credit=$2")
                .bind(pair.as_slice()).bind(credit.as_slice()).bind(amount.to_string()).execute(&mut **tx).await.map_err(database_error)?;
            sqlx::query("INSERT INTO ledger_holds(pair,hold,credit,amount,refund_receiver,disposition,target_binding) VALUES ($1,$2,$3,$4::text::numeric,$5,2,$6)")
                .bind(pair.as_slice()).bind(op.entity.as_slice()).bind(credit.as_slice()).bind(amount.to_string()).bind(refund_receiver.as_slice())
                .bind(codec::target_binding_stored(target)?).execute(&mut **tx).await.map_err(database_error)?;
        }
        LedgerCommand::AuthorizeTarget(auth) => super::target::reserve(tx, op, auth).await?,
        LedgerCommand::ReserveInputs { inputs, .. } => {
            lock_inputs(tx, pair, inputs, op.intent).await?
        }
        LedgerCommand::PrepareNative(plan) => {
            lock_inputs(tx, pair, &plan.inputs, op.intent).await?;
            lock_inputs(tx, pair, &plan.fee_inputs, op.intent).await?;
            sqlx::query("INSERT INTO ledger_intent_records(pair,intent,hold,portion,kind,transaction,nonce,plan) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(pair.as_slice()).bind(op.intent.as_slice()).bind(plan.hold.as_slice()).bind(plan.portion.as_slice()).bind(plan.kind as i16)
                .bind(plan.transaction.as_slice()).bind(plan.nonce.as_slice()).bind(codec::native_plan_bytes(plan)?).execute(&mut **tx).await.map_err(database_error)?;
            for change in &plan.change {
                let occurrence =
                    change_occurrence(&op.domain, plan.transaction, change.action_index);
                reserve_physical_claim(
                    tx,
                    op,
                    change.note,
                    &occurrence,
                    change.note_commitment,
                    change.nullifier,
                    Some(op.intent),
                )
                .await?;
                sqlx::query(
                    "INSERT INTO ledger_change_reservations(pair,note,intent) VALUES($1,$2,$3)",
                )
                .bind(pair.as_slice())
                .bind(change.note.as_slice())
                .bind(op.intent.as_slice())
                .execute(&mut **tx)
                .await
                .map_err(database_error)?;
            }
            sqlx::query("INSERT INTO ledger_intent_states(pair,intent,status) VALUES ($1,$2,1)")
                .bind(pair.as_slice())
                .bind(op.intent.as_slice())
                .execute(&mut **tx)
                .await
                .map_err(database_error)?;
            sqlx::query("INSERT INTO ledger_nonce_tombstones(pair,nonce,intent) VALUES ($1,$2,$3)")
                .bind(pair.as_slice())
                .bind(plan.nonce.as_slice())
                .bind(op.intent.as_slice())
                .execute(&mut **tx)
                .await
                .map_err(database_error)?;
            if plan.kind != NativeIntentKind::SponsorFee {
                sqlx::query("UPDATE ledger_portions SET live_intent=$4 WHERE pair=$1 AND hold=$2 AND portion=$3")
                    .bind(pair.as_slice()).bind(plan.hold.as_slice()).bind(plan.portion.as_slice()).bind(op.intent.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
            }
            sqlx::query("INSERT INTO ledger_versions(pair,entity,portion,version) VALUES ($1,$2,$3,1) ON CONFLICT DO NOTHING")
                .bind(pair.as_slice()).bind(op.intent.as_slice()).bind(ZERO.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
        }
        _ => {}
    }
    Ok(())
}
async fn insert_inventory(tx: &mut Tx, facts: &InventoryFacts) -> Result<(), LedgerError> {
    let (origin, parent) = match facts.origin {
        InventoryOrigin::Deposit => (1_i16, None),
        InventoryOrigin::Change { parent_intent } => (2, Some(parent_intent.to_vec())),
        InventoryOrigin::Sponsor => (3, None),
    };
    sqlx::query("INSERT INTO ledger_inventory(pair,note,scope,receiver,amount,origin,parent_intent,status,facts,source_network,source_pool,source_genesis,txid,action_index,note_commitment,nullifier) VALUES ($1,$2,$3,$4,$5::text::numeric,$6,$7,1,$8,$9,$10,$11,$12,$13,$14,$15)")
        .bind(facts.domain.pair.as_slice()).bind(facts.note.as_slice()).bind(facts.scope.as_slice()).bind(facts.receiver.as_slice())
        .bind(facts.value.to_string()).bind(origin).bind(parent).bind(codec::inventory_bytes(facts)?)
        .bind(i16::from(facts.occurrence.network)).bind(i16::from(facts.occurrence.pool)).bind(facts.domain.source_genesis.as_slice())
        .bind(facts.occurrence.txid.as_slice()).bind(i64::from(facts.occurrence.action_index)).bind(facts.note_commitment.as_slice()).bind(facts.nullifier.as_slice())
        .execute(&mut **tx).await.map_err(database_error)?;
    Ok(())
}
async fn apply_command(
    tx: &mut Tx,
    op: &Operation,
    command: &LedgerCommand,
    policy: &PairPolicy,
) -> Result<(), LedgerError> {
    let pair = op.domain.pair;
    match command {
        LedgerCommand::IssueCredit {
            claim,
            source,
            inventory,
        } => {
            validate_credit(tx, op, claim, source, inventory, policy).await?;
            sqlx::query("INSERT INTO ledger_credits(pair,credit,claimant,amount,available,note,source_network,source_pool,source_genesis,txid,action_index,claim) VALUES ($1,$2,$3,$4::text::numeric,$4::text::numeric,$5,$6,$7,$8,$9,$10,$11)")
                .bind(pair.as_slice()).bind(claim.credit_intent.as_slice()).bind(claim.claimant.as_slice()).bind(claim.value.to_string())
                .bind(claim.inventory_note.as_slice()).bind(i16::from(claim.occurrence.network)).bind(i16::from(claim.occurrence.pool))
                .bind(claim.domain.source_genesis.as_slice()).bind(claim.occurrence.txid.as_slice()).bind(i64::from(claim.occurrence.action_index))
                .bind(codec::command_bytes(command, true)?).execute(&mut **tx).await.map_err(database_error)?;
            insert_inventory(tx, &inventory.facts).await?;
        }
        LedgerCommand::RegisterSponsor { inventory } => {
            inventory_context(policy, inventory)?;
            validate_inventory_admission(tx, op, &inventory.facts).await?;
            insert_inventory(tx, &inventory.facts).await?
        }
        LedgerCommand::PrepareHold { target, .. } => {
            super::target::bootstrap(tx, policy, target).await?
        }
        LedgerCommand::ReserveInputs { .. } | LedgerCommand::PrepareNative(_) => {}
        LedgerCommand::ObserveEpoch { target } => {
            let outcome = target.facts.decision.operation.transition;
            let rows=sqlx::query("SELECT hold,amount::text AS amount,refund_receiver,target_binding FROM ledger_holds WHERE pair=$1 FOR UPDATE")
                .bind(pair.as_slice()).fetch_all(&mut **tx).await.map_err(database_error)?;
            for row in rows {
                let hold = id(&row, "hold")?;
                let binding = codec::target_binding_decode(
                    &row.try_get::<Vec<u8>, _>("target_binding")
                        .map_err(database_error)?,
                )?;
                let state = if outcome == Transition::AbortEpoch {
                    7_i16
                } else {
                    match binding.evidence {
                        TargetHoldEvidence::Prepared { .. } => 3,
                        TargetHoldEvidence::Locked { .. } => 6,
                    }
                };
                sqlx::query("UPDATE ledger_holds SET disposition=$3 WHERE pair=$1 AND hold=$2")
                    .bind(pair.as_slice())
                    .bind(hold.as_slice())
                    .bind(state)
                    .execute(&mut **tx)
                    .await
                    .map_err(database_error)?;
                if state == 6 || state == 7 {
                    let mut allocation_bytes = [0; 64];
                    allocation_bytes[..32]
                        .copy_from_slice(&op.id().map_err(|_| LedgerError::Protocol)?);
                    allocation_bytes[32..].copy_from_slice(&hold);
                    let plan = AllocationPlan {
                        hold,
                        allocation: codec::hash(&allocation_bytes),
                        chunks: vec![],
                        portions: vec![PortionSpec {
                            portion: hold,
                            offset: 0,
                            amount: number(&row, "amount")?,
                            kind: AllocationKind::BuyerUnused,
                            native_recipient: receiver(&row, "refund_receiver")?,
                            spl_recipient: binding.refund_token,
                            target_base_offset: 0,
                            target_base_amount: binding.maximum_base,
                            fill_fence: ZERO,
                        }],
                    };
                    insert_allocation(tx, pair, &plan, true, state).await?;
                }
                if hold != op.entity || op.portion != ZERO {
                    sqlx::query("UPDATE ledger_versions SET version=version+1 WHERE pair=$1 AND entity=$2 AND portion=$3")
                        .bind(pair.as_slice()).bind(hold.as_slice()).bind(ZERO.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
                }
            }
            let mut decision = [0; ziquid_protocol::market::DECISION_LEN];
            target
                .facts
                .decision
                .encode_into(&mut decision)
                .map_err(|_| LedgerError::Protocol)?;
            sqlx::query("INSERT INTO ledger_epoch_terminal(pair,decision,private_operation,outcome) VALUES($1,$2,$3,$4)")
                .bind(pair.as_slice()).bind(decision.as_slice()).bind(op.id().map_err(|_|LedgerError::Protocol)?.as_slice())
                .bind(if outcome==Transition::CommitEpoch {1_i16}else{2_i16}).execute(&mut **tx).await.map_err(database_error)?;
        }
        LedgerCommand::PrepareAllocation(plan) => {
            insert_allocation(tx, pair, plan, false, 3).await?
        }
        LedgerCommand::RecordAllocationChunk { hold, index, .. } => {
            sqlx::query("UPDATE ledger_allocation_chunks SET authenticated=true WHERE pair=$1 AND hold=$2 AND chunk_index=$3")
                .bind(pair.as_slice()).bind(hold.as_slice()).bind(i64::from(*index)).execute(&mut **tx).await.map_err(database_error)?;
        }
        LedgerCommand::ActivateAllocation { .. } => {
            sqlx::query("UPDATE ledger_allocations a SET active=true FROM ledger_holds h WHERE a.pair=$1 AND h.pair=a.pair AND h.hold=a.hold AND h.disposition=3")
                .bind(pair.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
            sqlx::query("UPDATE ledger_portions p SET active=true,disposition=CASE p.kind WHEN 1 THEN 4 ELSE 5 END FROM ledger_holds h WHERE p.pair=$1 AND h.pair=p.pair AND h.hold=p.hold AND h.disposition=3")
                .bind(pair.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
        }
        LedgerCommand::PrepareFirstLeg { hold, portion } => {
            update_portion(tx, pair, *hold, *portion, 9).await?
        }
        LedgerCommand::ObserveSplRelease { hold, portion, .. } => {
            update_portion(tx, pair, *hold, *portion, 10).await?
        }
        LedgerCommand::CancelFirstLeg { hold, portion, .. } => {
            update_portion(tx, pair, *hold, *portion, 8).await?
        }
        LedgerCommand::NativeUnknown { intent, .. } => {
            sqlx::query("UPDATE ledger_intent_states SET status=2 WHERE pair=$1 AND intent=$2")
                .bind(pair.as_slice())
                .bind(intent.as_slice())
                .execute(&mut **tx)
                .await
                .map_err(database_error)?;
        }
        LedgerCommand::ObserveNative(facts) => apply_native_facts(tx, op, facts, policy).await?,
        LedgerCommand::ImpairInventory { inventory } => {
            sqlx::query("UPDATE ledger_pairs SET impaired=true WHERE pair=$1")
                .bind(pair.as_slice())
                .execute(&mut **tx)
                .await
                .map_err(database_error)?;
            // Existing locks are preserved; the pair-level fence stops new sends/activation.
            sqlx::query("UPDATE ledger_inventory SET status=CASE WHEN status=1 THEN 5 ELSE status END WHERE pair=$1 AND note=$2")
                .bind(pair.as_slice()).bind(inventory.facts.note.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
        }
        LedgerCommand::AuthorizeTarget(_) | LedgerCommand::ObserveTarget(_) => {}
    }
    if let Some(fact) = codec::command_target(command) {
        super::target::observe(tx, op, fact, policy).await?;
    }
    Ok(())
}
async fn update_portion(
    tx: &mut Tx,
    pair: Id,
    hold: Id,
    portion: Id,
    state: i16,
) -> Result<(), LedgerError> {
    sqlx::query(
        "UPDATE ledger_portions SET disposition=$4 WHERE pair=$1 AND hold=$2 AND portion=$3",
    )
    .bind(pair.as_slice())
    .bind(hold.as_slice())
    .bind(portion.as_slice())
    .bind(state)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    Ok(())
}
async fn insert_allocation(
    tx: &mut Tx,
    pair: Id,
    plan: &AllocationPlan,
    active: bool,
    initial_state: i16,
) -> Result<(), LedgerError> {
    sqlx::query(
        "INSERT INTO ledger_allocations(pair,hold,allocation,body,active) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(pair.as_slice())
    .bind(plan.hold.as_slice())
    .bind(plan.allocation.as_slice())
    .bind(codec::allocation_bytes(plan)?)
    .bind(active)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    for (index, chunk) in plan.chunks.iter().enumerate() {
        sqlx::query("INSERT INTO ledger_allocation_chunks(pair,hold,chunk_index,digest) VALUES ($1,$2,$3,$4)")
            .bind(pair.as_slice()).bind(plan.hold.as_slice()).bind(index as i64).bind(chunk.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
    }
    for p in &plan.portions {
        sqlx::query("INSERT INTO ledger_portions(pair,hold,portion,allocation,offset_amount,amount,kind,native_recipient,spl_recipient,target_base_amount,disposition,active,target_base_offset,fill_fence) VALUES ($1,$2,$3,$4,$5::text::numeric,$6::text::numeric,$7,$8,$9,$10::text::numeric,$11,$12,$13::text::numeric,$14)")
            .bind(pair.as_slice()).bind(plan.hold.as_slice()).bind(p.portion.as_slice()).bind(plan.allocation.as_slice()).bind(p.offset.to_string())
            .bind(p.amount.to_string()).bind(p.kind as i16).bind(p.native_recipient.as_slice()).bind(p.spl_recipient.as_slice())
            .bind(p.target_base_amount.to_string()).bind(initial_state).bind(active).bind(p.target_base_offset.to_string()).bind(p.fill_fence.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
    }
    Ok(())
}
async fn apply_native_facts(
    tx: &mut Tx,
    op: &Operation,
    signed: &SignedNativeFacts,
    policy: &PairPolicy,
) -> Result<(), LedgerError> {
    validate_native_facts(tx, signed, policy).await?;
    let facts = &signed.facts;
    let pair = op.domain.pair;
    let row = sqlx::query("SELECT r.plan,s.status FROM ledger_intent_records r JOIN ledger_intent_states s USING(pair,intent) WHERE pair=$1 AND intent=$2 FOR UPDATE")
        .bind(pair.as_slice()).bind(facts.intent.as_slice()).fetch_one(&mut **tx).await.map_err(database_error)?;
    let plan =
        codec::decode_native_plan(&row.try_get::<Vec<u8>, _>("plan").map_err(database_error)?)?;
    let status: i16 = row.try_get("status").map_err(database_error)?;
    let incompatible = facts.transaction != plan.transaction
        || facts.recipient != plan.recipient
        || facts.amount != plan.amount
        || facts.change != plan.change
        || !facts
            .inputs
            .iter()
            .copied()
            .eq(plan.inputs.iter().chain(&plan.fee_inputs).copied());
    if incompatible || status == 5 {
        sqlx::query("UPDATE ledger_intent_states SET status=5 WHERE pair=$1 AND intent=$2")
            .bind(pair.as_slice())
            .bind(facts.intent.as_slice())
            .execute(&mut **tx)
            .await
            .map_err(database_error)?;
        sqlx::query("UPDATE ledger_pairs SET impaired=true WHERE pair=$1")
            .bind(pair.as_slice())
            .execute(&mut **tx)
            .await
            .map_err(database_error)?;
        sqlx::query("UPDATE ledger_inventory SET status=5 WHERE pair=$1 AND parent_intent=$2 AND status IN (1,4)").bind(pair.as_slice()).bind(facts.intent.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
        if plan.kind != NativeIntentKind::SponsorFee {
            update_portion(tx, pair, plan.hold, plan.portion, 14).await?;
        }
        sqlx::query("INSERT INTO ledger_native_observations(pair,operation,intent,facts) VALUES($1,$2,$3,$4)")
            .bind(pair.as_slice()).bind(op.id().map_err(|_|LedgerError::Protocol)?.as_slice()).bind(facts.intent.as_slice()).bind(codec::native_facts_bytes(facts)?).execute(&mut **tx).await.map_err(database_error)?;
        return Ok(());
    }
    let first = matches!(status, 1 | 2);
    if first {
        for note in &facts.inputs {
            let affected = sqlx::query("UPDATE ledger_inventory SET status=3 WHERE pair=$1 AND note=$2 AND status=2 AND live_intent=$3")
                .bind(pair.as_slice()).bind(note.as_slice()).bind(facts.intent.as_slice()).execute(&mut **tx).await.map_err(database_error)?.rows_affected();
            if affected != 1 {
                return Err(LedgerError::InventoryUnavailable);
            }
            sqlx::query("INSERT INTO ledger_consumptions(pair,note,intent,transaction) VALUES ($1,$2,$3,$4)")
                .bind(pair.as_slice()).bind(note.as_slice()).bind(facts.intent.as_slice()).bind(facts.transaction.as_slice()).execute(&mut **tx).await.map_err(database_error)?;
        }
        for c in &facts.change {
            sqlx::query("INSERT INTO ledger_inventory(pair,note,scope,receiver,amount,origin,parent_intent,status,facts,source_network,source_pool,source_genesis,txid,action_index,note_commitment,nullifier) VALUES ($1,$2,$3,$4,$5::text::numeric,2,$6,4,$7,$8,$9,$10,$11,$12,$13,$14)")
                .bind(pair.as_slice()).bind(c.note.as_slice()).bind(plan.inventory_scope.as_slice()).bind(c.receiver.as_slice()).bind(c.value.to_string())
                .bind(facts.intent.as_slice()).bind(codec::native_facts_bytes(facts)?)
                .bind(i16::from(policy.domain.source_network)).bind(i16::from(policy.domain.source_pool)).bind(policy.domain.source_genesis.as_slice())
                .bind(plan.transaction.as_slice()).bind(i64::from(c.action_index)).bind(c.note_commitment.as_slice()).bind(c.nullifier.as_slice())
                .execute(&mut **tx).await.map_err(database_error)?;
        }
    }
    let finalized = status == 4 || facts.confirmations >= policy.minimum_confirmations;
    sqlx::query("UPDATE ledger_intent_states SET status=$3 WHERE pair=$1 AND intent=$2")
        .bind(pair.as_slice())
        .bind(facts.intent.as_slice())
        .bind(if finalized { 4_i16 } else { 3_i16 })
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    if finalized {
        sqlx::query(
            "UPDATE ledger_inventory SET status=1 WHERE pair=$1 AND parent_intent=$2 AND status=4",
        )
        .bind(pair.as_slice())
        .bind(facts.intent.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        if plan.kind != NativeIntentKind::SponsorFee {
            update_portion(
                tx,
                pair,
                plan.hold,
                plan.portion,
                if plan.kind == NativeIntentKind::SellerPayout {
                    12
                } else {
                    13
                },
            )
            .await?;
        }
    }
    sqlx::query(
        "INSERT INTO ledger_native_observations(pair,operation,intent,facts) VALUES ($1,$2,$3,$4)",
    )
    .bind(pair.as_slice())
    .bind(op.id().map_err(|_| LedgerError::Protocol)?.as_slice())
    .bind(facts.intent.as_slice())
    .bind(codec::native_facts_bytes(facts)?)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    Ok(())
}
