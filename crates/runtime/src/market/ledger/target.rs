use super::*;
use super::{codec, store};
use ziquid_protocol::market::Transition;
use ziquid_solana_interface as target;
use sqlx::{Row, postgres::PgRow};
const ZERO: Id = [0; 32];
fn db(e: sqlx::Error) -> LedgerError {
    store::database_error(e)
}
fn number(r: &PgRow, field: &str) -> Result<u64, LedgerError> {
    store::number(r, field)
}
fn id(r: &PgRow, field: &str) -> Result<Id, LedgerError> {
    store::id(r, field)
}
pub(crate) fn observed_head(command: &LedgerCommand, current: Id) -> Id {
    match command {
        LedgerCommand::PrepareHold { target, .. } => {
            target.evidence.anchor().facts.decision.next_head
        }
        _ => codec::command_target(command)
            .map(|t| t.facts.decision.next_head)
            .unwrap_or(current),
    }
}
pub(crate) async fn binding(
    tx: &mut store::Tx,
    pair: Id,
    hold: Id,
) -> Result<TargetHoldBinding, LedgerError> {
    let row = sqlx::query("SELECT target_binding FROM ledger_holds WHERE pair=$1 AND hold=$2")
        .bind(pair.as_slice())
        .bind(hold.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
        .ok_or(LedgerError::MissingEntity)?;
    codec::target_binding_decode(&row.try_get::<Vec<u8>, _>("target_binding").map_err(db)?)
}
pub(crate) fn addresses(
    policy: &PairPolicy,
    b: &TargetHoldBinding,
    portion: Id,
) -> (Id, Id, Id, Id, Id) {
    let pair = target::pair_address(&policy.domain, &policy.target_admin);
    let epoch = target::epoch_address(&policy.domain, &pair);
    let hold = target::hold_address(&policy.domain, &epoch, &b.hold_business);
    (
        pair,
        epoch,
        hold,
        target::escrow_address(&policy.domain, &hold),
        target::portion_address(&policy.domain, &hold, &portion),
    )
}
pub(crate) fn validate_binding(
    policy: &PairPolicy,
    b: &TargetHoldBinding,
    predecessor: Id,
) -> Result<(), LedgerError> {
    if b.domain != policy.domain
        || b.hold_business == ZERO
        || b.maximum_base == 0
        || b.expected_chunks == 0
        || u64::from(b.expected_chunks) > b.maximum_base
        || b.refund_token == ZERO
        || b.epoch_version == 0
    {
        return Err(LedgerError::InvalidEvidence);
    }
    store::verify(&policy.target_observer, &b.signing_bytes()?, &b.signature)?;
    let (pair, epoch, hold, _, _) = addresses(policy, b, ZERO);
    let anchor = b.evidence.anchor();
    let d = anchor.facts.decision;
    if d.operation.portion != ZERO {
        return Err(LedgerError::InvalidEvidence);
    }
    match &b.evidence {
        TargetHoldEvidence::Prepared { .. } => {
            if d.operation.entity != hold
                || d.operation.transition != Transition::PrepareSeller
                || d.operation.effects
                    != target::effect_digest(
                        Transition::PrepareSeller,
                        &[],
                        &[pair, epoch, hold, target::INSTRUCTIONS_SYSVAR_ID],
                    )
                || (predecessor != ZERO && d.predecessor != predecessor)
            {
                return Err(LedgerError::InvalidEvidence);
            }
        }
        TargetHoldEvidence::Locked {
            lock_transaction,
            lock_slot,
            ..
        } => {
            let canonical_anchor = match d.operation.transition {
                Transition::OpenEpoch => {
                    d.operation.entity == epoch
                        && d.operation.effects
                            == target::effect_digest(
                                Transition::OpenEpoch,
                                &policy.domain.epoch.to_le_bytes(),
                                &[pair, epoch, ZERO, target::INSTRUCTIONS_SYSVAR_ID],
                            )
                        && b.epoch_version
                            >= d.operation
                                .prior_version
                                .checked_add(2)
                                .ok_or(LedgerError::InvalidEvidence)?
                }
                Transition::PrepareSeller => true,
                _ => false,
            };
            if !canonical_anchor
                || *lock_transaction == ZERO
                || *lock_slot < anchor.facts.observation.slot
                || (predecessor != ZERO && d.next_head != predecessor)
            {
                return Err(LedgerError::InvalidEvidence);
            }
        }
    }
    store::validate_target(policy, anchor, d.predecessor)
}
pub(crate) async fn validate_path(
    tx: &mut store::Tx,
    policy: &PairPolicy,
    pair_row: &PgRow,
    command: &LedgerCommand,
) -> Result<(), LedgerError> {
    let inflight = pair_row
        .try_get::<Option<Vec<u8>>, _>("target_inflight")
        .map_err(db)?;
    if let Some(fact) = codec::command_target(command) {
        store::validate_target(policy, fact, id(pair_row, "target_head")?)?;
        let operation = fact
            .facts
            .decision
            .operation
            .id()
            .map_err(|_| LedgerError::Protocol)?;
        if inflight.as_deref() != Some(operation.as_slice()) {
            return Err(LedgerError::InvalidEvidence);
        }
        let row = sqlx::query("SELECT decision,hold,portion FROM ledger_target_authorizations WHERE pair=$1 AND target_operation=$2")
            .bind(policy.domain.pair.as_slice()).bind(operation.as_slice()).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(LedgerError::InvalidEvidence)?;
        let exact = Decision::decode(&row.try_get::<Vec<u8>, _>("decision").map_err(db)?)
            .map_err(|_| LedgerError::Database)?;
        if exact != fact.facts.decision {
            return Err(LedgerError::InvalidEvidence);
        }
        let authorized_hold = id(&row, "hold")?;
        let authorized_portion = id(&row, "portion")?;
        let matches = match command {
            LedgerCommand::ObserveEpoch { .. } | LedgerCommand::ActivateAllocation { .. } => true,
            LedgerCommand::RecordAllocationChunk { hold, .. } => *hold == authorized_hold,
            LedgerCommand::ObserveSplRelease { hold, portion, .. }
            | LedgerCommand::CancelFirstLeg { hold, portion, .. } => {
                *hold == authorized_hold && *portion == authorized_portion
            }
            LedgerCommand::ObserveTarget(_) => true,
            _ => false,
        };
        if !matches {
            return Err(LedgerError::InvalidEvidence);
        }
    } else if inflight.is_some()
        && matches!(
            command,
            LedgerCommand::AuthorizeTarget(_)
                | LedgerCommand::PrepareHold { .. }
                | LedgerCommand::PrepareFirstLeg { .. }
                | LedgerCommand::PrepareNative(_)
                | LedgerCommand::PrepareAllocation(_)
        )
    {
        return Err(LedgerError::CompetingIntent);
    }
    if let LedgerCommand::PrepareHold { target, .. } = command {
        if sqlx::query("SELECT 1 FROM ledger_epoch_terminal WHERE pair=$1")
            .bind(policy.domain.pair.as_slice())
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .is_some()
        {
            return Err(LedgerError::NotReturnable);
        }
        let current = id(pair_row, "target_head")?;
        validate_binding(policy, target, current)?;
        let (_, epoch, _, _, _) = addresses(policy, target, ZERO);
        let version=sqlx::query("SELECT version::text AS version FROM ledger_target_versions WHERE pair=$1 AND entity=$2")
            .bind(policy.domain.pair.as_slice()).bind(epoch.as_slice()).fetch_optional(&mut **tx).await.map_err(db)?;
        if version
            .as_ref()
            .map(|r| number(r, "version"))
            .transpose()?
            .is_some_and(|v| target.epoch_version < v)
        {
            return Err(LedgerError::InvalidEvidence);
        }
        let anchor = target.evidence.anchor().facts.decision;
        if current != ZERO {
            let row = sqlx::query(
                "SELECT target_generation::text AS generation FROM ledger_pairs WHERE pair=$1",
            )
            .bind(policy.domain.pair.as_slice())
            .fetch_one(&mut **tx)
            .await
            .map_err(db)?;
            let generation = number(&row, "generation")?;
            let expected = match &target.evidence {
                TargetHoldEvidence::Prepared { .. } => generation.checked_add(1),
                TargetHoldEvidence::Locked { .. } => Some(generation),
            };
            if expected != Some(anchor.operation.generation) {
                return Err(LedgerError::InvalidEvidence);
            }
        }
        if matches!(&target.evidence, TargetHoldEvidence::Locked { .. })
            && anchor.operation.transition == Transition::PrepareSeller
        {
            let rows = sqlx::query("SELECT target_binding FROM ledger_holds WHERE pair=$1")
                .bind(policy.domain.pair.as_slice())
                .fetch_all(&mut **tx)
                .await
                .map_err(db)?;
            let mut retained = false;
            for row in rows {
                let binding = codec::target_binding_decode(
                    &row.try_get::<Vec<u8>, _>("target_binding").map_err(db)?,
                )?;
                if let TargetHoldEvidence::Prepared { prepare } = &binding.evidence {
                    retained |= prepare.facts.decision == anchor;
                }
            }
            if !retained {
                return Err(LedgerError::InvalidEvidence);
            }
        }
    }
    Ok(())
}
fn payload_id(payload: &[u8]) -> Result<Id, LedgerError> {
    payload.try_into().map_err(|_| LedgerError::InvalidEvidence)
}
async fn portion(tx: &mut store::Tx, pair: Id, hold: Id, p: Id) -> Result<PgRow, LedgerError> {
    sqlx::query("SELECT allocation,kind,disposition,active,live_intent,target_base_offset::text AS base_offset,target_base_amount::text AS base_amount,fill_fence,spl_recipient,first_leg_intent,custody_fence,target_return_intent,target_returned FROM ledger_portions WHERE pair=$1 AND hold=$2 AND portion=$3 FOR UPDATE")
        .bind(pair.as_slice()).bind(hold.as_slice()).bind(p.as_slice()).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(LedgerError::NotReturnable)
}
pub(crate) async fn validate_authorization(
    tx: &mut store::Tx,
    policy: &PairPolicy,
    auth: &TargetAuthorization,
) -> Result<(), LedgerError> {
    let b = binding(tx, policy.domain.pair, auth.hold).await?;
    let (pair, epoch, hold, escrow, p) = addresses(policy, &b, auth.portion);
    let d = auth.decision;
    d.validate().map_err(|_| LedgerError::InvalidEvidence)?;
    let head=sqlx::query("SELECT target_head,target_generation::text AS generation,target_result,target_activation_journal FROM ledger_pairs WHERE pair=$1 FOR UPDATE")
        .bind(policy.domain.pair.as_slice()).fetch_one(&mut **tx).await.map_err(db)?;
    if d.operation.domain != policy.domain
        || d.predecessor != id(&head, "target_head")?
        || Some(d.operation.generation) != number(&head, "generation")?.checked_add(1)
        || d.operation.effects
            != target::effect_digest(d.operation.transition, &auth.payload, &auth.accounts)
    {
        return Err(LedgerError::InvalidEvidence);
    }
    let mut expected = vec![pair, epoch, target::INSTRUCTIONS_SYSVAR_ID];
    let (entity, part) = match d.operation.transition {
        Transition::CommitEpoch | Transition::AbortEpoch => {
            let row = sqlx::query("SELECT disposition FROM ledger_holds WHERE pair=$1 AND hold=$2")
                .bind(policy.domain.pair.as_slice())
                .bind(auth.hold.as_slice())
                .fetch_one(&mut **tx)
                .await
                .map_err(db)?;
            if row.try_get::<i16, _>("disposition").map_err(db)? != 2 {
                return Err(LedgerError::NotReturnable);
            }
            if auth.portion != ZERO
                || (d.operation.transition == Transition::AbortEpoch && !auth.payload.is_empty())
                || (d.operation.transition == Transition::CommitEpoch
                    && payload_id(&auth.payload)? == ZERO)
            {
                return Err(LedgerError::InvalidEvidence);
            }
            (epoch, ZERO)
        }
        Transition::RecordAllocation => {
            let row = portion(tx, policy.domain.pair, auth.hold, auth.portion).await?;
            if auth.payload.len() != 81 || row.try_get::<bool, _>("active").map_err(db)? {
                return Err(LedgerError::InvalidEvidence);
            }
            let mut bytes = codec::Encoder::new(&[]);
            bytes.raw(&auth.portion);
            bytes.u64(number(&row, "base_offset")?);
            bytes.u64(number(&row, "base_amount")?);
            bytes.byte(row.try_get::<i16, _>("kind").map_err(db)? as u8);
            bytes.raw(&id(&row, "allocation")?);
            if auth.payload != bytes.0 || id(&row, "allocation")? != id(&head, "target_result")? {
                return Err(LedgerError::InvalidEvidence);
            }
            expected = vec![
                pair,
                epoch,
                hold,
                p,
                id(&row, "spl_recipient")?,
                policy.domain.mint,
                policy.domain.token_program,
                ZERO,
                target::INSTRUCTIONS_SYSVAR_ID,
            ];
            (hold, p)
        }
        Transition::ActivateAllocation => {
            if auth.payload.len() != 64
                || auth.portion != ZERO
                || payload_id(&auth.payload[..32])? != id(&head, "target_result")?
                || payload_id(&auth.payload[32..])? == ZERO
            {
                return Err(LedgerError::InvalidEvidence);
            }
            store::validate_epoch_activation(tx, policy).await?;
            (epoch, ZERO)
        }
        Transition::ReturnUnused if auth.portion == ZERO => {
            let row=sqlx::query("SELECT disposition,target_return_intent,target_returned FROM ledger_holds WHERE pair=$1 AND hold=$2 FOR UPDATE")
                .bind(policy.domain.pair.as_slice()).bind(auth.hold.as_slice()).fetch_one(&mut **tx).await.map_err(db)?;
            if row.try_get::<bool, _>("target_returned").map_err(db)?
                || row
                    .try_get::<Option<Vec<u8>>, _>("target_return_intent")
                    .map_err(db)?
                    .is_some()
            {
                return Err(LedgerError::CompetingIntent);
            }
            if auth.payload.len() != 33
                || auth.payload[0] != 0
                || payload_id(&auth.payload[1..])? != ZERO
                || !matches!(row.try_get::<i16, _>("disposition").map_err(db)?, 6 | 7)
            {
                return Err(LedgerError::NotReturnable);
            }
            if sqlx::query(
                "SELECT 1 FROM ledger_allocation_chunks WHERE pair=$1 AND hold=$2 LIMIT 1",
            )
            .bind(policy.domain.pair.as_slice())
            .bind(auth.hold.as_slice())
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .is_some()
            {
                return Err(LedgerError::NotReturnable);
            }
            expected = vec![
                pair,
                epoch,
                hold,
                escrow,
                policy.domain.mint,
                b.refund_token,
                policy.domain.token_program,
                target::INSTRUCTIONS_SYSVAR_ID,
            ];
            (hold, ZERO)
        }
        Transition::PrepareFill
        | Transition::ReleaseSpl
        | Transition::CancelFill
        | Transition::ReturnUnused => {
            let row = portion(tx, policy.domain.pair, auth.hold, auth.portion).await?;
            if !row.try_get::<bool, _>("active").map_err(db)? {
                return Err(LedgerError::CompetingIntent);
            }
            let state: i16 = row.try_get("disposition").map_err(db)?;
            let kind: i16 = row.try_get("kind").map_err(db)?;
            let live = row
                .try_get::<Option<Vec<u8>>, _>("live_intent")
                .map_err(db)?;
            let first_leg = row
                .try_get::<Option<Vec<u8>>, _>("first_leg_intent")
                .map_err(db)?;
            let independent_cancelled = if d.operation.transition == Transition::ReturnUnused
                && kind == 1
                && matches!(state, 8 | 11 | 13)
                && id(&row, "custody_fence")? != ZERO
            {
                let native_refund = if let Some(intent) = &live {
                    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM ledger_intent_records r JOIN ledger_intent_states s USING(pair,intent) WHERE r.pair=$1 AND r.intent=$2 AND r.hold=$3 AND r.portion=$4 AND r.kind=$5 AND s.status BETWEEN 1 AND 4)")
                        .bind(policy.domain.pair.as_slice()).bind(intent).bind(auth.hold.as_slice()).bind(auth.portion.as_slice())
                        .bind(NativeIntentKind::BuyerRefund as i16).fetch_one(&mut **tx).await.map_err(db)?
                } else {
                    state == 8
                };
                if native_refund {
                    let cancellation = sqlx::query("SELECT a.decision FROM ledger_target_authorizations a JOIN ledger_target_observations o USING(pair,target_operation) WHERE a.pair=$1 AND a.hold=$2 AND a.portion=$3 AND a.payload=$4")
                        .bind(policy.domain.pair.as_slice()).bind(auth.hold.as_slice()).bind(auth.portion.as_slice())
                        .bind(id(&row, "custody_fence")?.as_slice()).fetch_optional(&mut **tx).await.map_err(db)?;
                    if let Some(cancellation) = cancellation {
                        let cancelled = Decision::decode(
                            &cancellation.try_get::<Vec<u8>, _>("decision").map_err(db)?,
                        )
                        .map_err(|_| LedgerError::Database)?;
                        cancelled.operation.domain == policy.domain
                            && cancelled.operation.entity == p
                            && cancelled.operation.portion == p
                            && cancelled.operation.transition == Transition::CancelFill
                            && first_leg.as_deref().is_none_or(|intent| {
                                intent == cancelled.operation.intent.as_slice()
                            })
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };
            let independent_unused =
                d.operation.transition == Transition::ReturnUnused && kind == 2;
            if live.is_some() && !independent_unused && !independent_cancelled {
                return Err(LedgerError::CompetingIntent);
            }
            if row.try_get::<bool, _>("target_returned").map_err(db)?
                || row
                    .try_get::<Option<Vec<u8>>, _>("target_return_intent")
                    .map_err(db)?
                    .is_some()
            {
                return Err(LedgerError::CompetingIntent);
            }
            if matches!(
                d.operation.transition,
                Transition::ReleaseSpl | Transition::CancelFill
            ) && first_leg
                .as_deref()
                .is_some_and(|intent| intent != d.operation.intent.as_slice())
            {
                return Err(LedgerError::InvalidEvidence);
            }
            expected = vec![pair, epoch, hold, p, target::INSTRUCTIONS_SYSVAR_ID];
            match d.operation.transition {
                Transition::PrepareFill => {
                    let e = target::PrepareFillEffects::decode(&auth.payload)
                        .map_err(|_| LedgerError::InvalidEvidence)?;
                    if kind != 1
                        || !matches!(state, 4 | 9)
                        || first_leg.is_some()
                        || e.amount != number(&row, "base_amount")?
                        || e.fence != id(&row, "fill_fence")?
                        || e.journal != id(&head, "target_activation_journal")?
                    {
                        return Err(LedgerError::InvalidEvidence);
                    }
                }
                Transition::ReleaseSpl => {
                    let e = target::ReleaseEffects::decode(&auth.payload)
                        .map_err(|_| LedgerError::InvalidEvidence)?;
                    if kind != 1
                        || state != 9
                        || first_leg.is_none()
                        || e.amount != number(&row, "base_amount")?
                        || e.fence != id(&row, "fill_fence")?
                        || e.result != id(&row, "allocation")?
                    {
                        return Err(LedgerError::InvalidEvidence);
                    }
                    expected = vec![
                        pair,
                        epoch,
                        hold,
                        p,
                        escrow,
                        policy.domain.mint,
                        id(&row, "spl_recipient")?,
                        policy.domain.token_program,
                        target::INSTRUCTIONS_SYSVAR_ID,
                    ];
                }
                Transition::CancelFill => {
                    if kind != 1 || !matches!(state, 4 | 9) || payload_id(&auth.payload)? == ZERO {
                        return Err(LedgerError::CompetingIntent);
                    }
                }
                Transition::ReturnUnused => {
                    if auth.payload.len() != 33 {
                        return Err(LedgerError::InvalidEvidence);
                    }
                    let custody = payload_id(&auth.payload[1..])?;
                    match (auth.payload[0], kind, state) {
                        (1, 2, 5 | 6 | 7 | 8 | 13) if custody == ZERO => {}
                        (2, 1, 8 | 11 | 13)
                            if independent_cancelled
                                && custody != ZERO
                                && custody == id(&row, "custody_fence")? => {}
                        (1, 2, _) | (2, 1, 8 | 11 | 13) => {
                            return Err(LedgerError::InvalidEvidence);
                        }
                        _ => return Err(LedgerError::NotReturnable),
                    }
                    expected = vec![
                        pair,
                        epoch,
                        hold,
                        escrow,
                        policy.domain.mint,
                        b.refund_token,
                        policy.domain.token_program,
                        target::INSTRUCTIONS_SYSVAR_ID,
                        p,
                    ];
                }
                _ => return Err(LedgerError::InvalidEvidence),
            }
            (p, p)
        }
        _ => return Err(LedgerError::InvalidEvidence),
    };
    if d.operation.entity != entity || d.operation.portion != part || auth.accounts != expected {
        return Err(LedgerError::InvalidEvidence);
    }
    let row = sqlx::query(
        "SELECT version::text AS version FROM ledger_target_versions WHERE pair=$1 AND entity=$2",
    )
    .bind(policy.domain.pair.as_slice())
    .bind(entity.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?
    .ok_or(LedgerError::VersionConflict)?;
    if number(&row, "version")? != d.operation.prior_version {
        return Err(LedgerError::VersionConflict);
    }
    Ok(())
}
pub(crate) async fn reserve(
    tx: &mut store::Tx,
    op: &Operation,
    a: &TargetAuthorization,
) -> Result<(), LedgerError> {
    let mut decision = [0; ziquid_protocol::market::DECISION_LEN];
    a.decision
        .encode_into(&mut decision)
        .map_err(|_| LedgerError::Protocol)?;
    let mut accounts = codec::Encoder::new(&[]);
    for account in &a.accounts {
        accounts.raw(account);
    }
    let target_id = a
        .decision
        .operation
        .id()
        .map_err(|_| LedgerError::Protocol)?;
    sqlx::query("INSERT INTO ledger_target_authorizations(pair,target_operation,private_operation,hold,portion,decision,payload,accounts) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(op.domain.pair.as_slice()).bind(target_id.as_slice()).bind(op.id().map_err(|_|LedgerError::Protocol)?.as_slice())
        .bind(a.hold.as_slice()).bind(a.portion.as_slice()).bind(decision.as_slice()).bind(&a.payload).bind(accounts.0).execute(&mut **tx).await.map_err(db)?;
    sqlx::query(
        "UPDATE ledger_pairs SET target_inflight=$2,authorized_target_head=$3 WHERE pair=$1",
    )
    .bind(op.domain.pair.as_slice())
    .bind(target_id.as_slice())
    .bind(a.decision.next_head.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    if a.decision.operation.transition == Transition::PrepareFill {
        sqlx::query("UPDATE ledger_portions SET disposition=9,first_leg_intent=$4 WHERE pair=$1 AND hold=$2 AND portion=$3")
            .bind(op.domain.pair.as_slice()).bind(a.hold.as_slice()).bind(a.portion.as_slice()).bind(a.decision.operation.intent.as_slice()).execute(&mut **tx).await.map_err(db)?;
    }
    if a.decision.operation.transition == Transition::CancelFill {
        sqlx::query(
            "UPDATE ledger_portions SET custody_fence=$4 WHERE pair=$1 AND hold=$2 AND portion=$3",
        )
        .bind(op.domain.pair.as_slice())
        .bind(a.hold.as_slice())
        .bind(a.portion.as_slice())
        .bind(payload_id(&a.payload)?.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    }
    if a.decision.operation.transition == Transition::ReturnUnused {
        if a.portion == ZERO {
            sqlx::query(
                "UPDATE ledger_holds SET target_return_intent=$3 WHERE pair=$1 AND hold=$2",
            )
            .bind(op.domain.pair.as_slice())
            .bind(a.hold.as_slice())
            .bind(target_id.as_slice())
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        } else {
            sqlx::query("UPDATE ledger_portions SET target_return_intent=$4 WHERE pair=$1 AND hold=$2 AND portion=$3")
                .bind(op.domain.pair.as_slice()).bind(a.hold.as_slice()).bind(a.portion.as_slice()).bind(target_id.as_slice()).execute(&mut **tx).await.map_err(db)?;
        }
    }
    Ok(())
}
async fn set_version(
    tx: &mut store::Tx,
    pair: Id,
    entity: Id,
    version: u64,
) -> Result<(), LedgerError> {
    sqlx::query("INSERT INTO ledger_target_versions(pair,entity,version) VALUES($1,$2,$3::text::numeric) ON CONFLICT(pair,entity) DO UPDATE SET version=EXCLUDED.version")
        .bind(pair.as_slice()).bind(entity.as_slice()).bind(version.to_string()).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
async fn bump(tx: &mut store::Tx, pair: Id, entity: Id) -> Result<(), LedgerError> {
    let row=sqlx::query("SELECT version::text AS version FROM ledger_target_versions WHERE pair=$1 AND entity=$2 FOR UPDATE")
        .bind(pair.as_slice()).bind(entity.as_slice()).fetch_one(&mut **tx).await.map_err(db)?;
    set_version(
        tx,
        pair,
        entity,
        number(&row, "version")?
            .checked_add(1)
            .ok_or(LedgerError::VersionConflict)?,
    )
    .await
}
pub(crate) async fn bootstrap(
    tx: &mut store::Tx,
    policy: &PairPolicy,
    b: &TargetHoldBinding,
) -> Result<(), LedgerError> {
    let (_, epoch, hold, _, _) = addresses(policy, b, ZERO);
    set_version(tx, policy.domain.pair, epoch, b.epoch_version).await?;
    let hold_version = match &b.evidence {
        TargetHoldEvidence::Prepared { prepare } => prepare
            .facts
            .decision
            .operation
            .prior_version
            .checked_add(1)
            .ok_or(LedgerError::VersionConflict)?,
        TargetHoldEvidence::Locked { .. } => 1,
    };
    set_version(tx, policy.domain.pair, hold, hold_version).await?;
    sqlx::query("UPDATE ledger_pairs SET target_generation=$2::text::numeric WHERE pair=$1")
        .bind(policy.domain.pair.as_slice())
        .bind(
            b.evidence
                .anchor()
                .facts
                .decision
                .operation
                .generation
                .to_string(),
        )
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
pub(crate) async fn observe(
    tx: &mut store::Tx,
    op: &Operation,
    fact: &SignedTargetFacts,
    policy: &PairPolicy,
) -> Result<(), LedgerError> {
    let d = fact.facts.decision;
    let target_id = d.operation.id().map_err(|_| LedgerError::Protocol)?;
    let row=sqlx::query("SELECT hold,portion,payload FROM ledger_target_authorizations WHERE pair=$1 AND target_operation=$2")
        .bind(policy.domain.pair.as_slice()).bind(target_id.as_slice()).fetch_one(&mut **tx).await.map_err(db)?;
    let business_hold = id(&row, "hold")?;
    let business_portion = id(&row, "portion")?;
    let payload: Vec<u8> = row.try_get("payload").map_err(db)?;
    let b = binding(tx, policy.domain.pair, business_hold).await?;
    let (_, epoch, hold, _, p) = addresses(policy, &b, business_portion);
    set_version(
        tx,
        policy.domain.pair,
        d.operation.entity,
        d.operation
            .prior_version
            .checked_add(1)
            .ok_or(LedgerError::VersionConflict)?,
    )
    .await?;
    match d.operation.transition {
        Transition::CommitEpoch => {
            sqlx::query("UPDATE ledger_pairs SET target_result=$2 WHERE pair=$1")
                .bind(policy.domain.pair.as_slice())
                .bind(payload.as_slice())
                .execute(&mut **tx)
                .await
                .map_err(db)?;
        }
        Transition::RecordAllocation => {
            set_version(tx, policy.domain.pair, p, 1).await?;
            bump(tx, policy.domain.pair, epoch).await?;
        }
        Transition::ActivateAllocation => {
            sqlx::query("UPDATE ledger_pairs SET target_activation_journal=$2 WHERE pair=$1")
                .bind(policy.domain.pair.as_slice())
                .bind(&payload[32..])
                .execute(&mut **tx)
                .await
                .map_err(db)?;
        }
        Transition::ReleaseSpl => {
            bump(tx, policy.domain.pair, hold).await?;
        }
        Transition::ReturnUnused => {
            if business_portion == ZERO {
                sqlx::query(
                    "UPDATE ledger_holds SET target_returned=true WHERE pair=$1 AND hold=$2",
                )
                .bind(policy.domain.pair.as_slice())
                .bind(business_hold.as_slice())
                .execute(&mut **tx)
                .await
                .map_err(db)?;
            } else {
                bump(tx, policy.domain.pair, hold).await?;
                sqlx::query("UPDATE ledger_portions SET target_returned=true WHERE pair=$1 AND hold=$2 AND portion=$3")
                    .bind(policy.domain.pair.as_slice()).bind(business_hold.as_slice()).bind(business_portion.as_slice()).execute(&mut **tx).await.map_err(db)?;
            }
        }
        _ => {}
    }
    sqlx::query("INSERT INTO ledger_target_observations(pair,target_operation,private_operation,facts) VALUES($1,$2,$3,$4)")
        .bind(policy.domain.pair.as_slice()).bind(target_id.as_slice()).bind(op.id().map_err(|_|LedgerError::Protocol)?.as_slice())
        .bind(codec::target_bytes(&fact.facts)?).execute(&mut **tx).await.map_err(db)?;
    sqlx::query("UPDATE ledger_pairs SET target_inflight=NULL,authorized_target_head=NULL,target_generation=$2::text::numeric WHERE pair=$1")
        .bind(policy.domain.pair.as_slice()).bind(d.operation.generation.to_string()).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
