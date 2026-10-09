#![cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod support;
use ed25519_dalek::Signer;
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use ziquid_solana_interface as target;
use support::*;

fn open_anchor(f: &Fixture) -> SignedTargetFacts {
    let pair = target::pair_address(&f.policy.domain, &f.policy.target_admin);
    let epoch = target::epoch_address(&f.policy.domain, &pair);
    let decision = target::decision(
        f.policy.domain,
        epoch,
        None,
        Transition::OpenEpoch,
        target::Envelope {
            intent: [25; 32],
            generation: 1,
            prior: 0,
            predecessor: [0; 32],
        },
        &f.policy.domain.epoch.to_le_bytes(),
        &[pair, epoch, [0; 32], target::INSTRUCTIONS_SYSVAR_ID],
    )
    .unwrap();
    f.observed(decision)
}
fn prepared_binding(
    f: &Fixture,
    hold: Id,
    predecessor: Id,
    generation: u64,
    epoch_version: u64,
) -> TargetHoldBinding {
    let mut binding = f.target_binding(hold);
    let pair = target::pair_address(&f.policy.domain, &f.policy.target_admin);
    let epoch = target::epoch_address(&f.policy.domain, &pair);
    let target_hold = target::hold_address(&f.policy.domain, &epoch, &hold);
    let decision = target::decision(
        f.policy.domain,
        target_hold,
        None,
        Transition::PrepareSeller,
        target::Envelope {
            intent: hold,
            generation,
            prior: 1,
            predecessor,
        },
        &[],
        &[pair, epoch, target_hold, target::INSTRUCTIONS_SYSVAR_ID],
    )
    .unwrap();
    binding.evidence = TargetHoldEvidence::Prepared {
        prepare: f.observed(decision),
    };
    binding.epoch_version = epoch_version;
    binding.signature = f
        .target_key
        .sign(&binding.signing_bytes().unwrap())
        .to_bytes();
    binding
}
fn locked_binding(
    f: &Fixture,
    hold: Id,
    anchor: SignedTargetFacts,
    epoch_version: u64,
) -> TargetHoldBinding {
    let mut binding = f.target_binding(hold);
    binding.evidence = TargetHoldEvidence::Locked {
        anchor,
        lock_transaction: hold,
        lock_slot: 201,
    };
    binding.epoch_version = epoch_version;
    binding.signature = f
        .target_key
        .sign(&binding.signing_bytes().unwrap())
        .to_bytes();
    binding
}
async fn prepare(
    f: &Fixture,
    credit: Id,
    hold: Id,
    binding: TargetHoldBinding,
) -> Result<(), LedgerError> {
    let mut command = LedgerCommand::PrepareHold {
        credit,
        amount: 34,
        refund_receiver: [40; 43],
        target: binding,
        authorization: [0; 64],
    };
    let op = f.operation(hold, [0; 32], hold, 0, Transition::PrepareHold, &command);
    if let LedgerCommand::PrepareHold { authorization, .. } = &mut command {
        *authorization = f
            .claimant
            .sign(&op.signing_bytes(SignatureRole::Application).unwrap())
            .to_bytes();
    }
    let decision = f.ledger.prepare_decision(op, command).await?;
    let acks = f.acknowledge(&decision).await;
    f.ledger.commit_decision(&decision, &acks).await
}
async fn epoch(f: &Fixture, hold: Id, transition: Transition, prior: u64) -> SignedTargetFacts {
    let head = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let pair = target::pair_address(&f.policy.domain, &f.policy.target_admin);
    let epoch = target::epoch_address(&f.policy.domain, &pair);
    let payload = if transition == Transition::CommitEpoch {
        [64; 32].to_vec()
    } else {
        vec![]
    };
    let decision = target::decision(
        f.policy.domain,
        epoch,
        None,
        transition,
        target::Envelope {
            intent: [80; 32],
            generation: head.target_generation + 1,
            prior,
            predecessor: head.target_head,
        },
        &payload,
        &[pair, epoch, target::INSTRUCTIONS_SYSVAR_ID],
    )
    .unwrap();
    let command = LedgerCommand::AuthorizeTarget(TargetAuthorization {
        hold,
        portion: [0; 32],
        decision,
        payload,
        accounts: vec![pair, epoch, target::INSTRUCTIONS_SYSVAR_ID],
    });
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, [0; 32])
        .await
        .unwrap();
    let op = f.operation(
        hold,
        [0; 32],
        [81; 32],
        version,
        Transition::PrepareFill,
        &command,
    );
    f.apply(op, command).await;
    let target = f.observed(decision);
    let command = LedgerCommand::ObserveEpoch {
        target: target.clone(),
    };
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, epoch, [0; 32])
        .await
        .unwrap();
    let op = f.operation(epoch, [0; 32], [82; 32], version, transition, &command);
    f.apply(op, command).await;
    target
}

#[tokio::test]
async fn multi_prepared_holds_share_one_canonical_epoch_commit() {
    let f = Fixture::new("sharedepoch").await;
    let credit_a = f.issue(34, 50).await;
    let credit_b = f.issue(34, 55).await;
    let hold_a = [60; 32];
    let hold_b = [61; 32];
    let first = prepared_binding(&f, hold_a, [0; 32], 2, 3);
    let first_head = first.evidence.clone();
    prepare(&f, credit_a, hold_a, first).await.unwrap();
    let TargetHoldEvidence::Prepared { prepare: anchor } = first_head else {
        unreachable!()
    };
    let second = prepared_binding(&f, hold_b, anchor.facts.decision.next_head, 3, 5);
    prepare(&f, credit_b, hold_b, second).await.unwrap();
    let target = epoch(&f, hold_a, Transition::CommitEpoch, 5).await;
    assert_eq!(
        f.ledger
            .hold(f.policy.domain.pair, hold_a)
            .await
            .unwrap()
            .disposition,
        Disposition::EpochEncumbered
    );
    assert_eq!(
        f.ledger
            .hold(f.policy.domain.pair, hold_b)
            .await
            .unwrap()
            .disposition,
        Disposition::EpochEncumbered
    );
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (snapshot.prepared, snapshot.encumbered, snapshot.target_head),
        (0, 68, target.facts.decision.next_head)
    );
    f.remove().await;
}

#[tokio::test]
async fn prepared_and_locked_members_share_one_canonical_epoch_abort() {
    let f = Fixture::new("sharedabort").await;
    let credit_a = f.issue(34, 50).await;
    let credit_b = f.issue(34, 55).await;
    let hold_a = [60; 32];
    let hold_b = [61; 32];
    let anchor = open_anchor(&f);
    prepare(
        &f,
        credit_a,
        hold_a,
        locked_binding(&f, hold_a, anchor.clone(), 2),
    )
    .await
    .unwrap();
    prepare(
        &f,
        credit_b,
        hold_b,
        prepared_binding(&f, hold_b, anchor.facts.decision.next_head, 2, 4),
    )
    .await
    .unwrap();
    epoch(&f, hold_b, Transition::AbortEpoch, 4).await;
    assert_eq!(
        f.ledger
            .hold(f.policy.domain.pair, hold_a)
            .await
            .unwrap()
            .disposition,
        Disposition::FencedAborted
    );
    assert_eq!(
        f.ledger
            .hold(f.policy.domain.pair, hold_b)
            .await
            .unwrap()
            .disposition,
        Disposition::FencedAborted
    );
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .buyer_unused_outstanding,
        68
    );
    f.remove().await;
}

#[tokio::test]
async fn later_locked_binding_uses_signed_actual_epoch_version_without_rewinding_anchor() {
    let f = Fixture::new("laterlock").await;
    let credit_a = f.issue(34, 50).await;
    let credit_b = f.issue(34, 55).await;
    let hold_a = [60; 32];
    let hold_b = [61; 32];
    let first = prepared_binding(&f, hold_a, [0; 32], 2, 3);
    let TargetHoldEvidence::Prepared { prepare: anchor } = &first.evidence else {
        unreachable!()
    };
    let anchor = anchor.clone();
    prepare(&f, credit_a, hold_a, first).await.unwrap();
    let before = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    prepare(&f, credit_b, hold_b, locked_binding(&f, hold_b, anchor, 4))
        .await
        .unwrap();
    let after = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (after.target_head, after.target_generation),
        (before.target_head, before.target_generation)
    );
    let target = epoch(&f, hold_a, Transition::CommitEpoch, 4).await;
    assert_eq!(
        f.ledger
            .hold(f.policy.domain.pair, hold_a)
            .await
            .unwrap()
            .disposition,
        Disposition::EpochEncumbered
    );
    assert_eq!(
        f.ledger
            .hold(f.policy.domain.pair, hold_b)
            .await
            .unwrap()
            .disposition,
        Disposition::Excluded
    );
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.encumbered,
            snapshot.buyer_unused_outstanding,
            snapshot.target_head
        ),
        (34, 34, target.facts.decision.next_head)
    );
    f.remove().await;
}

#[tokio::test]
async fn closed_epoch_rejects_new_hold_before_reserved_credit_or_head_changes() {
    let f = Fixture::new("closedadmission").await;
    let credit_a = f.issue(34, 50).await;
    let credit_b = f.issue(34, 55).await;
    let hold_a = [60; 32];
    let hold_b = [61; 32];
    prepare(
        &f,
        credit_a,
        hold_a,
        prepared_binding(&f, hold_a, [0; 32], 2, 3),
    )
    .await
    .unwrap();
    epoch(&f, hold_a, Transition::CommitEpoch, 3).await;
    let before = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let binding = prepared_binding(
        &f,
        hold_b,
        before.target_head,
        before.target_generation + 1,
        5,
    );
    assert_eq!(
        prepare(&f, credit_b, hold_b, binding).await,
        Err(LedgerError::NotReturnable)
    );
    let after = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            after.available_credit,
            after.prepared,
            after.encumbered,
            after.head,
            after.target_head
        ),
        (34, 0, 34, before.head, before.target_head)
    );
    f.remove().await;
}

#[tokio::test]
async fn hold_business_equal_to_epoch_address_commits_shared_epoch_once() {
    let f = Fixture::new("epochalias").await;
    let credit = f.issue(34, 50).await;
    let pair = target::pair_address(&f.policy.domain, &f.policy.target_admin);
    let hold = target::epoch_address(&f.policy.domain, &pair);
    prepare(&f, credit, hold, prepared_binding(&f, hold, [0; 32], 2, 3))
        .await
        .unwrap();
    let receipt = epoch(&f, hold, Transition::CommitEpoch, 3).await;
    let state = f.ledger.hold(f.policy.domain.pair, hold).await.unwrap();
    assert_eq!(
        (state.version, state.disposition),
        (3, Disposition::EpochEncumbered)
    );
    assert_eq!(
        f.ledger
            .pending_decision(f.policy.domain.pair)
            .await
            .unwrap(),
        None
    );
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (snapshot.prepared, snapshot.encumbered, snapshot.target_head),
        (0, 34, receipt.facts.decision.next_head)
    );
    f.remove().await;
}

fn allocation_plan(f: &Fixture, hold: Id, tag: u8) -> AllocationPlan {
    let pair = target::pair_address(&f.policy.domain, &f.policy.target_admin);
    let epoch = target::epoch_address(&f.policy.domain, &pair);
    let target_hold = target::hold_address(&f.policy.domain, &epoch, &hold);
    let mut plan = AllocationPlan {
        hold,
        allocation: [64; 32],
        portions: vec![
            PortionSpec {
                portion: [tag; 32],
                offset: 0,
                amount: 25,
                kind: AllocationKind::SellerLiability,
                native_recipient: [66; 43],
                spl_recipient: [67; 32],
                target_base_offset: 0,
                target_base_amount: 5,
                fill_fence: [72; 32],
            },
            PortionSpec {
                portion: [tag + 1; 32],
                offset: 25,
                amount: 9,
                kind: AllocationKind::BuyerUnused,
                native_recipient: [40; 43],
                spl_recipient: [28; 32],
                target_base_offset: 5,
                target_base_amount: 2,
                fill_fence: [0; 32],
            },
        ],
        chunks: vec![],
    };
    for p in &plan.portions {
        let portion = target::portion_address(&f.policy.domain, &target_hold, &p.portion);
        let mut payload = p.portion.to_vec();
        payload.extend_from_slice(&p.target_base_offset.to_le_bytes());
        payload.extend_from_slice(&p.target_base_amount.to_le_bytes());
        payload.push(p.kind as u8);
        payload.extend_from_slice(&plan.allocation);
        plan.chunks.push(target::effect_digest(
            Transition::RecordAllocation,
            &payload,
            &[
                pair,
                epoch,
                target_hold,
                portion,
                p.spl_recipient,
                f.policy.domain.mint,
                f.policy.domain.token_program,
                [0; 32],
                target::INSTRUCTIONS_SYSVAR_ID,
            ],
        ));
    }
    plan
}
async fn store_allocation(f: &Fixture, plan: &AllocationPlan, tag: u8) -> Result<(), LedgerError> {
    let command = LedgerCommand::PrepareAllocation(plan.clone());
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, plan.hold, [0; 32])
        .await
        .unwrap();
    let op = f.operation(
        plan.hold,
        [0; 32],
        [tag; 32],
        version,
        Transition::RecordAllocation,
        &command,
    );
    let decision = f.ledger.prepare_decision(op, command).await?;
    let acks = f.acknowledge(&decision).await;
    f.ledger.commit_decision(&decision, &acks).await
}
async fn accepted_pair(f: &Fixture) -> (Id, Id) {
    let credit_a = f.issue(34, 50).await;
    let credit_b = f.issue(34, 55).await;
    let a = [60; 32];
    let b = [61; 32];
    let binding = prepared_binding(f, a, [0; 32], 2, 3);
    let TargetHoldEvidence::Prepared { prepare: anchor } = &binding.evidence else {
        unreachable!()
    };
    let head = anchor.facts.decision.next_head;
    prepare(f, credit_a, a, binding).await.unwrap();
    prepare(f, credit_b, b, prepared_binding(f, b, head, 3, 5))
        .await
        .unwrap();
    epoch(f, a, Transition::CommitEpoch, 5).await;
    (a, b)
}
#[tokio::test]
async fn accepted_holds_retain_same_shared_epoch_result_in_disjoint_allocations() {
    let f = Fixture::new("sharedresult").await;
    let (a, b) = accepted_pair(&f).await;
    store_allocation(&f, &allocation_plan(&f, a, 65), 110)
        .await
        .unwrap();
    store_allocation(&f, &allocation_plan(&f, b, 75), 111)
        .await
        .unwrap();
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .encumbered,
        68
    );
    f.remove().await;
}
async fn record_chunks(f: &Fixture, plan: &AllocationPlan, tag: u8) {
    let pair = target::pair_address(&f.policy.domain, &f.policy.target_admin);
    let epoch = target::epoch_address(&f.policy.domain, &pair);
    let hold = target::hold_address(&f.policy.domain, &epoch, &plan.hold);
    for (index, p) in plan.portions.iter().enumerate() {
        let portion = target::portion_address(&f.policy.domain, &hold, &p.portion);
        let mut payload = p.portion.to_vec();
        payload.extend_from_slice(&p.target_base_offset.to_le_bytes());
        payload.extend_from_slice(&p.target_base_amount.to_le_bytes());
        payload.push(p.kind as u8);
        payload.extend_from_slice(&plan.allocation);
        let accounts = vec![
            pair,
            epoch,
            hold,
            portion,
            p.spl_recipient,
            f.policy.domain.mint,
            f.policy.domain.token_program,
            [0; 32],
            target::INSTRUCTIONS_SYSVAR_ID,
        ];
        let head = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
        let decision = target::decision(
            f.policy.domain,
            hold,
            Some(portion),
            Transition::RecordAllocation,
            target::Envelope {
                intent: [tag + index as u8; 32],
                generation: head.target_generation + 1,
                prior: 2 + index as u64,
                predecessor: head.target_head,
            },
            &payload,
            &accounts,
        )
        .unwrap();
        let command = LedgerCommand::AuthorizeTarget(TargetAuthorization {
            hold: plan.hold,
            portion: p.portion,
            decision,
            payload,
            accounts,
        });
        let op = f.operation(
            plan.hold,
            p.portion,
            [tag + 2 + index as u8; 32],
            f.ledger
                .entity_version(f.policy.domain.pair, plan.hold, p.portion)
                .await
                .unwrap(),
            Transition::PrepareFill,
            &command,
        );
        f.apply(op, command).await;
        let command = LedgerCommand::RecordAllocationChunk {
            hold: plan.hold,
            allocation: plan.allocation,
            index: index as u32,
            digest: plan.chunks[index],
            target: f.observed(decision),
        };
        let op = f.operation(
            plan.hold,
            [0; 32],
            [tag + 4 + index as u8; 32],
            f.ledger
                .entity_version(f.policy.domain.pair, plan.hold, [0; 32])
                .await
                .unwrap(),
            Transition::RecordAllocation,
            &command,
        );
        f.apply(op, command).await;
    }
}
async fn activation(
    f: &Fixture,
    hold: Id,
    prior: u64,
    tag: u8,
) -> (Operation, LedgerCommand, Decision) {
    let pair = target::pair_address(&f.policy.domain, &f.policy.target_admin);
    let epoch = target::epoch_address(&f.policy.domain, &pair);
    let mut payload = [64; 32].to_vec();
    payload.extend_from_slice(&[73; 32]);
    let accounts = vec![pair, epoch, target::INSTRUCTIONS_SYSVAR_ID];
    let head = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let decision = target::decision(
        f.policy.domain,
        epoch,
        None,
        Transition::ActivateAllocation,
        target::Envelope {
            intent: [tag; 32],
            generation: head.target_generation + 1,
            prior,
            predecessor: head.target_head,
        },
        &payload,
        &accounts,
    )
    .unwrap();
    let command = LedgerCommand::AuthorizeTarget(TargetAuthorization {
        hold,
        portion: [0; 32],
        decision,
        payload,
        accounts,
    });
    let op = f.operation(
        hold,
        [0; 32],
        [tag + 1; 32],
        f.ledger
            .entity_version(f.policy.domain.pair, hold, [0; 32])
            .await
            .unwrap(),
        Transition::PrepareFill,
        &command,
    );
    (op, command, decision)
}
#[tokio::test]
async fn global_activation_requires_all_accepted_holds_and_activates_all_liabilities_once() {
    let f = Fixture::new("globalactivation").await;
    let (a, b) = accepted_pair(&f).await;
    let plan_a = allocation_plan(&f, a, 65);
    store_allocation(&f, &plan_a, 110).await.unwrap();
    record_chunks(&f, &plan_a, 120).await;
    let (op, command, _) = activation(&f, a, 8, 130).await;
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::IncompleteAllocation)
    );
    assert_eq!(
        f.ledger
            .pending_decision(f.policy.domain.pair)
            .await
            .unwrap(),
        None
    );
    let plan_b = allocation_plan(&f, b, 75);
    store_allocation(&f, &plan_b, 111).await.unwrap();
    record_chunks(&f, &plan_b, 140).await;
    let (op, command, decision) = activation(&f, a, 10, 150).await;
    f.apply(op, command).await;
    let epoch = decision.operation.entity;
    let command = LedgerCommand::ActivateAllocation {
        target: f.observed(decision),
    };
    let op = f.operation(
        epoch,
        [0; 32],
        [152; 32],
        f.ledger
            .entity_version(f.policy.domain.pair, epoch, [0; 32])
            .await
            .unwrap(),
        Transition::ActivateAllocation,
        &command,
    );
    let observed = f.apply(op, command).await;
    let s = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            s.encumbered,
            s.seller_outstanding,
            s.buyer_unused_outstanding
        ),
        (0, 50, 18)
    );
    assert_eq!(
        f.ledger
            .prepare_decision(observed.operation, observed.command.clone())
            .await
            .unwrap(),
        observed
    );
    f.remove().await;
}
