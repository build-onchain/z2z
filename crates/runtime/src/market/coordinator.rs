use super::{
    Error, Result,
    config::{self, CoordinatorConfig, StoreConfig},
    native,
    process::ReplicaProcess,
};
use ed25519_dalek::SigningKey;
use ziquid_zcash::custody::UnsignedNativeInspection;
use crate::market::ledger::{
    JournalAcknowledgement, JournalDecision, Ledger, LedgerCommand, LedgerError, NativePlan,
    PairPolicy, PairSnapshot, RecoveryState,
};
use ziquid_protocol::market::{Id, Operation};
use serde_json::{Value, json};
use std::path::Path;

pub async fn migrate(config: StoreConfig) -> Result<Value> {
    config::version(config.schema_version)?;
    let ledger = Ledger::connect(&config.database.config()?).await?;
    let result = ledger.migrate().await;
    ledger.close().await;
    result?;
    Ok(json!({ "status": "migrated" }))
}

pub async fn inspect(config: CoordinatorConfig) -> Result<Value> {
    config::version(config.schema_version)?;
    let policy = config::policy(&config.policy)?;
    let ledger = Ledger::connect(&config.database.config()?).await?;
    let result = async {
        if ledger.pair_policy(policy.domain.pair).await? != policy {
            return Err(Error::Configuration);
        }
        Ok(ledger.snapshot(policy.domain.pair).await?)
    }
    .await;
    ledger.close().await;
    Ok(snapshot(&result?))
}

pub async fn reconcile(
    config: CoordinatorConfig,
    executable: &Path,
    keys: Option<[SigningKey; 3]>,
) -> Result<Value> {
    config::version(config.schema_version)?;
    let policy = config::policy(&config.policy)?;
    let ledger = Ledger::connect(&config.database.config()?).await?;
    let result = async {
        if ledger.pair_policy(policy.domain.pair).await? != policy {
            return Err(Error::Configuration);
        }
        let challenge = ledger.begin_reconciliation(policy.domain.pair).await?;
        if config.replicas.len() != 3 {
            ledger.reconcile_heads(&challenge, &[]).await?;
            return Err(Error::Ledger(LedgerError::RecoveryEvidenceMissing));
        }
        let keys = keys.ok_or(Error::KeyBootstrap)?;
        let mut processes = Vec::with_capacity(3);
        for (path, key) in config.replicas.iter().zip(&keys) {
            processes.push(ReplicaProcess::launch(executable, path, key, &policy).await?);
        }
        let pair = policy.domain.pair;
        let mut coordinator = Coordinator {
            ledger: ledger.clone(),
            policy,
            replicas: processes,
        };
        let recovered = coordinator.reconcile().await;
        let stopped = coordinator.shutdown().await;
        let state = recovered?;
        stopped?;
        let state = match state {
            RecoveryState::Current => "current",
            RecoveryState::PendingRetained => "exact-pending-retained",
        };
        let mut summary = snapshot(&ledger.snapshot(pair).await?);
        summary["recovery"] = json!(state);
        Ok(summary)
    }
    .await;
    ledger.close().await;
    result
}

pub struct Coordinator {
    pub ledger: Ledger,
    pub policy: PairPolicy,
    pub replicas: Vec<ReplicaProcess>,
}
impl Coordinator {
    pub async fn reconcile(&mut self) -> Result<RecoveryState> {
        let challenge = self
            .ledger
            .begin_reconciliation(self.policy.domain.pair)
            .await?;
        let mut heads = Vec::with_capacity(self.replicas.len());
        for replica in &mut self.replicas {
            heads.push(replica.retained(&challenge).await?);
        }
        Ok(self.ledger.reconcile_heads(&challenge, &heads).await?)
    }
    pub async fn acknowledge(
        &mut self,
        decision: &JournalDecision,
    ) -> Result<Vec<JournalAcknowledgement>> {
        let mut acknowledgements = Vec::with_capacity(self.replicas.len());
        for replica in &mut self.replicas {
            acknowledgements.push(replica.acknowledge(decision).await?);
        }
        Ok(acknowledgements)
    }
    pub async fn apply(
        &mut self,
        operation: Operation,
        command: LedgerCommand,
    ) -> Result<JournalDecision> {
        let decision = self.ledger.prepare_decision(operation, command).await?;
        let acks = self.acknowledge(&decision).await?;
        self.ledger.commit_decision(&decision, &acks).await?;
        Ok(decision)
    }
    /// No handoff is possible from inspection alone: prepare locks inputs/nonces,
    /// all replicas persist the full exact plan, and the committed plan is reread.
    pub async fn prepare_native(
        &mut self,
        operation: Operation,
        plan: NativePlan,
        inspection: &UnsignedNativeInspection<'_>,
    ) -> Result<JournalDecision> {
        native::bind_plan(&operation, &plan, inspection)?;
        let user_scope = if plan.kind == ziquid_protocol::market::NativeIntentKind::SponsorFee {
            self.policy.sponsor_scope
        } else {
            self.policy.inventory_scope
        };
        if plan.inventory_scope != user_scope {
            return Err(Error::NativePlanMismatch);
        }
        for input in inspection.inputs() {
            let scope = if plan.inputs.contains(input.inventory_note()) {
                user_scope
            } else {
                self.policy.sponsor_scope
            };
            let retained = self
                .ledger
                .inventory_input(self.policy.domain.pair, *input.inventory_note())
                .await?;
            if retained.note != *input.inventory_note()
                || retained.value != input.value()
                || retained.scope != scope
                || retained.occurrence != *input.source_occurrence()
                || retained.note_commitment != *input.note_commitment()
                || retained.nullifier != *input.nullifier()
            {
                return Err(Error::NativePlanMismatch);
            }
        }
        let decision = self
            .apply(operation, LedgerCommand::PrepareNative(plan.clone()))
            .await?;
        let stored = self
            .ledger
            .native_plan(self.policy.domain.pair, operation.intent)
            .await?;
        if stored != plan {
            return Err(Error::NativePlanMismatch);
        }
        native::bind_plan(&operation, &stored, inspection)?;
        Ok(decision)
    }
    pub async fn shutdown(&mut self) -> Result<()> {
        let mut failure = None;
        for replica in &mut self.replicas {
            if let Err(error) = replica.shutdown().await {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

pub fn snapshot(snapshot: &PairSnapshot) -> Value {
    json!({ "available_credit": snapshot.available_credit.to_string(), "prepared": snapshot.prepared.to_string(),
        "encumbered": snapshot.encumbered.to_string(), "seller_outstanding": snapshot.seller_outstanding.to_string(),
        "buyer_unused_outstanding": snapshot.buyer_unused_outstanding.to_string(), "final_payout": snapshot.final_payout.to_string(),
        "final_refund": snapshot.final_refund.to_string(), "usable_inventory": snapshot.usable_inventory.to_string(),
        "locked_inventory": snapshot.locked_inventory.to_string(), "provisional_change": snapshot.provisional_change.to_string(),
        "pending_recipient": snapshot.pending_recipient.to_string(), "sponsor_inventory": snapshot.sponsor_inventory.to_string(),
        "impaired": snapshot.impaired, "journal_head": native::hex(&snapshot.head), "target_head": native::hex(&snapshot.target_head),
        "sequence": snapshot.sequence, "writer_generation": snapshot.writer_generation })
}

pub fn operation(
    policy: &PairPolicy,
    generation: u64,
    (entity, portion): (Id, Id),
    intent: Id,
    prior_version: u64,
    transition: ziquid_protocol::market::Transition,
    command: &LedgerCommand,
) -> Result<Operation> {
    let mut operation = Operation {
        domain: policy.domain,
        entity,
        portion,
        intent,
        generation,
        prior_version,
        transition,
        effects: [0; 32],
    };
    operation.effects = command.operation_effects(&operation)?;
    Ok(operation)
}

#[cfg(all(test, feature = "postgres-tests"))]
#[path = "input_binding_tests.rs"]
mod input_binding_tests;
