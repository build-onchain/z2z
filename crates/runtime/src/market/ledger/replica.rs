use super::*;
use super::{codec, store};
use ed25519_dalek::Signer;
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct Replica {
    pool: PgPool,
    config: DatabaseConfig,
}
impl Replica {
    async fn ready(&self) -> Result<(), LedgerError> {
        crate::database::ensure_ready(&self.pool, &self.config, store::SCHEMA).await.map_err(|_| LedgerError::Database)
    }
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, LedgerError> {
        Ok(Self {
            pool: crate::database::connect(config).await.map_err(|_| LedgerError::Database)?,
            config: config.clone(),
        })
    }
    pub async fn migrate(&self) -> Result<(), LedgerError> {
        let migrations = store::migrations().await?;
        crate::database::migrate(&self.pool, &self.config, store::SCHEMA, &migrations).await.map_err(|_| LedgerError::Database)
    }
    pub async fn close(&self) {
        self.pool.close().await;
    }
    pub async fn enroll_pair(&self, policy: &PairPolicy) -> Result<(), LedgerError> {
        self.ready().await?;
        store::validate_policy(policy)?;
        let bytes = codec::policy_bytes(policy)?;
        let mut tx = store::serializable(&self.pool).await?;
        let row = sqlx::query("SELECT policy FROM replica_pairs WHERE pair=$1 FOR UPDATE")
            .bind(policy.domain.pair.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(store::database_error)?;
        if let Some(row) = row {
            if row
                .try_get::<Vec<u8>, _>("policy")
                .map_err(store::database_error)?
                != bytes
            {
                return Err(LedgerError::Conflict);
            }
        } else {
            sqlx::query(
                "INSERT INTO replica_pairs(pair,policy,head,target_head) VALUES ($1,$2,$3,$3)",
            )
            .bind(policy.domain.pair.as_slice())
            .bind(&bytes)
            .bind([0_u8; 32].as_slice())
            .execute(&mut *tx)
            .await
            .map_err(store::database_error)?;
        }
        sqlx::query("INSERT INTO ledger_pairs(pair,policy,head,target_head) VALUES ($1,$2,$3,$3) ON CONFLICT DO NOTHING")
            .bind(policy.domain.pair.as_slice()).bind(&bytes).bind([0_u8; 32].as_slice()).execute(&mut *tx).await.map_err(store::database_error)?;
        tx.commit().await.map_err(store::database_error)
    }
    pub async fn acknowledge(
        &self,
        decision: &JournalDecision,
        signer: &SigningKey,
    ) -> Result<JournalAcknowledgement, LedgerError> {
        self.ready().await?;
        for _ in 0..8 {
            match self
                .store_decision(decision, signer.verifying_key().to_bytes())
                .await
            {
                Err(LedgerError::SerializationFailure) => tokio::task::yield_now().await,
                Ok(()) => {
                    // The SQL transaction committed before either signature can leave this function.
                    let signature = signer.sign(&decision.signing_bytes()?).to_bytes();
                    let target = decision
                        .target
                        .map(|d| {
                            d.signing_bytes()
                                .map(|message| ziquid_protocol::market::Acknowledgement {
                                    signer: signer.verifying_key().to_bytes(),
                                    signature: signer.sign(&message).to_bytes(),
                                    decision: d,
                                })
                        })
                        .transpose()
                        .map_err(|_| LedgerError::Protocol)?;
                    return Ok(JournalAcknowledgement {
                        signer: signer.verifying_key().to_bytes(),
                        signature,
                        decision: decision.clone(),
                        target,
                    });
                }
                Err(error) => return Err(error),
            }
        }
        Err(LedgerError::SerializationFailure)
    }
    async fn store_decision(
        &self,
        decision: &JournalDecision,
        signer: Id,
    ) -> Result<(), LedgerError> {
        let pair = decision.operation.domain.pair;
        let operation_id = decision.operation.id().map_err(|_| LedgerError::Protocol)?;
        let mut tx = store::serializable(&self.pool).await?;
        let row = sqlx::query("SELECT policy,head,target_head,sequence::text AS sequence,writer_generation::text AS generation FROM replica_pairs WHERE pair=$1 FOR UPDATE")
            .bind(pair.as_slice()).fetch_optional(&mut *tx).await.map_err(store::database_error)?.ok_or(LedgerError::MissingEntity)?;
        let policy = store::policy(&row)?;
        if !policy.roster.contains(&signer) || decision.operation.domain != policy.domain {
            return Err(LedgerError::InvalidAuthorization);
        }
        if let Some(existing) =
            sqlx::query("SELECT body FROM replica_journal WHERE pair=$1 AND operation=$2")
                .bind(pair.as_slice())
                .bind(operation_id.as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(store::database_error)?
        {
            let stored = JournalDecision::decode(
                &existing
                    .try_get::<Vec<u8>, _>("body")
                    .map_err(store::database_error)?,
            )?;
            if stored != *decision {
                return Err(LedgerError::Conflict);
            }
            return Ok(());
        }
        let body = decision.canonical_bytes()?;
        let generation = store::number(&row, "generation")?;
        if decision.operation.generation < generation || decision.operation.generation == 0 {
            return Err(LedgerError::StaleWriter);
        }
        if store::id(&row, "head")? != decision.predecessor
            || store::number(&row, "sequence")?.checked_add(1) != Some(decision.sequence)
        {
            return Err(LedgerError::HeadMismatch);
        }
        store::replay_replica_command(&mut tx, decision, &policy).await?;
        if let LedgerCommand::PrepareNative(plan) = &decision.command {
            sqlx::query("INSERT INTO replica_intents(pair,intent,nonce,transaction,body) VALUES ($1,$2,$3,$4,$5)")
                .bind(pair.as_slice()).bind(decision.operation.intent.as_slice()).bind(plan.nonce.as_slice()).bind(plan.transaction.as_slice())
                .bind(codec::native_plan_bytes(plan)?).execute(&mut *tx).await.map_err(store::database_error)?;
        }
        sqlx::query("INSERT INTO replica_journal(pair,operation,sequence,predecessor,next_head,body) VALUES ($1,$2,$3::text::numeric,$4,$5,$6)")
            .bind(pair.as_slice()).bind(operation_id.as_slice()).bind(decision.sequence.to_string()).bind(decision.predecessor.as_slice())
            .bind(decision.next_head.as_slice()).bind(body).execute(&mut *tx).await.map_err(store::database_error)?;
        let target_head =
            super::target::observed_head(&decision.command, store::id(&row, "target_head")?);
        sqlx::query("UPDATE replica_pairs SET head=$2,target_head=$3,sequence=$4::text::numeric,writer_generation=$5::text::numeric WHERE pair=$1")
            .bind(pair.as_slice()).bind(decision.next_head.as_slice()).bind(target_head.as_slice()).bind(decision.sequence.to_string())
            .bind(decision.operation.generation.to_string()).execute(&mut *tx).await.map_err(store::database_error)?;
        tx.commit().await.map_err(store::database_error)
    }
    pub async fn retained_head(
        &self,
        challenge: &RecoveryChallenge,
        signer: &SigningKey,
    ) -> Result<RetainedHead, LedgerError> {
        self.ready().await?;
        if challenge.nonce == [0; 32] {
            return Err(LedgerError::InvalidEvidence);
        }
        let mut tx = store::serializable(&self.pool).await?;
        let row = sqlx::query("SELECT policy,head,target_head,sequence::text AS sequence,writer_generation::text AS generation FROM replica_pairs WHERE pair=$1 FOR UPDATE")
            .bind(challenge.pair.as_slice()).fetch_optional(&mut *tx).await.map_err(store::database_error)?.ok_or(LedgerError::RecoveryEvidenceMissing)?;
        let policy = store::policy(&row)?;
        if !policy.roster.contains(&signer.verifying_key().to_bytes()) {
            return Err(LedgerError::InvalidAuthorization);
        }
        let mut retained = RetainedHead {
            domain: policy.domain,
            pair: challenge.pair,
            signer: signer.verifying_key().to_bytes(),
            head: store::id(&row, "head")?,
            target_head: store::id(&row, "target_head")?,
            sequence: store::number(&row, "sequence")?,
            generation: store::number(&row, "generation")?,
            challenge: challenge.nonce,
            signature: [0; 64],
        };
        tx.commit().await.map_err(store::database_error)?;
        retained.signature = signer
            .sign(&codec::signing(
                b"KERB_RETAINED_HEAD_V1",
                &codec::retained_bytes(&retained)?,
            ))
            .to_bytes();
        Ok(retained)
    }
}
