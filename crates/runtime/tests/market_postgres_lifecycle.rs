#![cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod support;
use ed25519_dalek::Signer;
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use ziquid_solana_interface as target;
use support::*;

async fn authorization(
    f: &Fixture,
    hold: Id,
    portion: Id,
    transition: Transition,
    prior: u64,
    intent: Id,
    payload: Vec<u8>,
) -> TargetAuthorization {
    let binding = f.target_binding(hold);
    let d = f.policy.domain;
    let pair = target::pair_address(&d, &f.policy.target_admin);
    let epoch = target::epoch_address(&d, &pair);
    let h = target::hold_address(&d, &epoch, &binding.hold_business);
    let p = target::portion_address(&d, &h, &portion);
    let (entity, part, accounts) = match transition {
        Transition::CommitEpoch | Transition::AbortEpoch => (
            epoch,
            None,
            vec![pair, epoch, target::INSTRUCTIONS_SYSVAR_ID],
        ),
        Transition::PrepareFill | Transition::CancelFill => (
            p,
            Some(p),
            vec![pair, epoch, h, p, target::INSTRUCTIONS_SYSVAR_ID],
        ),
        Transition::ReleaseSpl => (
            p,
            Some(p),
            vec![
                pair,
                epoch,
                h,
                p,
                target::escrow_address(&d, &h),
                d.mint,
                [67; 32],
                d.token_program,
                target::INSTRUCTIONS_SYSVAR_ID,
            ],
        ),
        Transition::ReturnUnused => {
            let mut accounts = vec![
                pair,
                epoch,
                h,
                target::escrow_address(&d, &h),
                d.mint,
                [28; 32],
                d.token_program,
                target::INSTRUCTIONS_SYSVAR_ID,
            ];
            if portion == [0; 32] {
                (h, None, accounts)
            } else {
                accounts.push(p);
                (p, Some(p), accounts)
            }
        }
        _ => panic!("not a lifecycle fixture transition"),
    };
    let snapshot = f.ledger.snapshot(d.pair).await.unwrap();
    TargetAuthorization {
        hold,
        portion,
        decision: target::decision(
            d,
            entity,
            part,
            transition,
            target::Envelope {
                intent,
                generation: snapshot.target_generation.checked_add(1).unwrap(),
                prior,
                predecessor: snapshot.target_head,
            },
            &payload,
            &accounts,
        )
        .unwrap(),
        payload,
        accounts,
    }
}
async fn prepare_authorization(
    f: &Fixture,
    auth: TargetAuthorization,
    private_intent: Id,
) -> Result<JournalDecision, LedgerError> {
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, auth.hold, auth.portion)
        .await
        .unwrap();
    let command = LedgerCommand::AuthorizeTarget(auth.clone());
    let op = f.operation(
        auth.hold,
        auth.portion,
        private_intent,
        version,
        Transition::PrepareFill,
        &command,
    );
    f.ledger.prepare_decision(op, command).await
}
async fn authorize(
    f: &Fixture,
    auth: TargetAuthorization,
    private_intent: Id,
) -> SignedTargetFacts {
    let decision = prepare_authorization(f, auth, private_intent)
        .await
        .unwrap();
    let acks = f.acknowledge(&decision).await;
    f.ledger.commit_decision(&decision, &acks).await.unwrap();
    f.observed(decision.target.unwrap())
}
async fn observe(f: &Fixture, facts: SignedTargetFacts, private_intent: Id) {
    let entity = facts.facts.decision.operation.id().unwrap();
    let command = LedgerCommand::ObserveTarget(facts);
    let op = f.operation(
        entity,
        [0; 32],
        private_intent,
        0,
        Transition::ObserveNative,
        &command,
    );
    f.apply(op, command).await;
}
async fn observe_epoch(f: &Fixture, target: SignedTargetFacts, tag: u8) {
    let transition = target.facts.decision.operation.transition;
    let epoch = target.facts.decision.operation.entity;
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, epoch, [0; 32])
        .await
        .unwrap();
    let command = LedgerCommand::ObserveEpoch { target };
    let op = f.operation(epoch, [0; 32], [tag; 32], version, transition, &command);
    f.apply(op, command).await;
}
async fn prepare_fill(f: &Fixture, hold: Id) {
    let payload = target::PrepareFillEffects {
        amount: 5,
        journal: [73; 32],
        fence: [72; 32],
    }
    .encode()
    .to_vec();
    let auth = authorization(
        f,
        hold,
        [65; 32],
        Transition::PrepareFill,
        1,
        [95; 32],
        payload,
    )
    .await;
    let fact = authorize(f, auth, [96; 32]).await;
    observe(f, fact, [97; 32]).await;
}
async fn cancel_fill(f: &Fixture, hold: Id) {
    let auth = authorization(
        f,
        hold,
        [65; 32],
        Transition::CancelFill,
        2,
        [95; 32],
        [98; 32].to_vec(),
    )
    .await;
    let target = authorize(f, auth, [99; 32]).await;
    let command = LedgerCommand::CancelFirstLeg {
        hold,
        portion: [65; 32],
        target,
    };
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, [65; 32])
        .await
        .unwrap();
    let op = f.operation(
        hold,
        [65; 32],
        [90; 32],
        version,
        Transition::CancelFill,
        &command,
    );
    f.apply(op, command).await;
}
async fn native_refund(f: &Fixture, hold: Id, portion: Id, amount: u64, tag: u8) {
    let change = if amount == 34 {
        vec![]
    } else {
        vec![ChangeOutput {
            note: [tag + 1; 32],
            action_index: 1,
            note_commitment: [tag + 6; 32],
            nullifier: [tag + 7; 32],
            receiver: f.policy.receiver,
            value: 34 - amount,
        }]
    };
    let command = LedgerCommand::PrepareNative(NativePlan {
        hold,
        portion,
        kind: NativeIntentKind::BuyerRefund,
        recipient: [40; 43],
        amount,
        inventory_scope: f.policy.inventory_scope,
        inputs: vec![[52; 32]],
        fee_inputs: vec![],
        change,
        fee: 0,
        nonce: [tag + 2; 32],
        pczt_digest: [tag + 3; 32],
        sighash: [tag + 4; 32],
        transaction: [tag + 5; 32],
    });
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, portion)
        .await
        .unwrap();
    let op = f.operation(
        hold,
        portion,
        [tag; 32],
        version,
        Transition::PrepareNative,
        &command,
    );
    f.apply(op, command).await;
}
fn return_payload(mode: u8, custody: Id) -> Vec<u8> {
    let mut bytes = vec![mode];
    bytes.extend_from_slice(&custody);
    bytes
}

#[tokio::test]
async fn mixed_pending_retained_heads_can_replay_lagging_replica_without_rollback() {
    let f = Fixture::new("mixedheads").await;
    let credit = f.issue(34, 50).await;
    let (op, command) = f.prepare(credit, [60; 32], 34);
    let decision = f.ledger.prepare_decision(op, command).await.unwrap();
    for index in 0..2 {
        f.replicas[index]
            .acknowledge(&decision, &f.keys[index])
            .await
            .unwrap();
    }
    let challenge = f
        .ledger
        .begin_reconciliation(f.policy.domain.pair)
        .await
        .unwrap();
    let mut heads = vec![];
    for (replica, key) in f.replicas.iter().zip(&f.keys) {
        heads.push(replica.retained_head(&challenge, key).await.unwrap());
    }
    assert_eq!(
        f.ledger.reconcile_heads(&challenge, &heads).await,
        Err(LedgerError::RecoveryEvidenceMissing)
    );
    let acks = f.acknowledge(&decision).await;
    assert_eq!(
        f.ledger.commit_decision(&decision, &acks).await,
        Err(LedgerError::RecoveryEvidenceMissing)
    );
    assert_eq!(f.reconcile(&f.ledger).await, RecoveryState::PendingRetained);
    f.ledger.commit_decision(&decision, &acks).await.unwrap();
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .prepared,
        34
    );
    f.remove().await;
}

#[tokio::test]
async fn unused_spl_return_is_independent_of_pending_native_refund_and_is_single_use() {
    let f = Fixture::new("independentreturn").await;
    let (_, hold, _) = f.active().await;
    native_refund(&f, hold, [68; 32], 9, 100).await;
    let auth = authorization(
        &f,
        hold,
        [68; 32],
        Transition::ReturnUnused,
        1,
        [120; 32],
        return_payload(1, [0; 32]),
    )
    .await;
    let facts = authorize(&f, auth, [121; 32]).await;
    observe(&f, facts, [122; 32]).await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.final_refund,
            snapshot.buyer_unused_outstanding,
            snapshot.locked_inventory
        ),
        (0, 9, 34)
    );
    assert_eq!(
        f.ledger
            .intent(f.policy.domain.pair, [100; 32])
            .await
            .unwrap()
            .state,
        IntentStatus::Prepared
    );
    let duplicate = authorization(
        &f,
        hold,
        [68; 32],
        Transition::ReturnUnused,
        2,
        [123; 32],
        return_payload(1, [0; 32]),
    )
    .await;
    assert_eq!(
        prepare_authorization(&f, duplicate, [124; 32]).await,
        Err(LedgerError::CompetingIntent)
    );
    f.remove().await;
}

#[tokio::test]
async fn aborted_whole_spl_return_and_native_refund_preserve_distinct_terminal_claims() {
    let f = Fixture::new("abortreturn").await;
    let (_, hold) = f.held().await;
    let auth = authorization(
        &f,
        hold,
        [0; 32],
        Transition::AbortEpoch,
        3,
        [120; 32],
        vec![],
    )
    .await;
    let facts = authorize(&f, auth, [121; 32]).await;
    observe_epoch(&f, facts, 122).await;
    native_refund(&f, hold, hold, 34, 100).await;
    let auth = authorization(
        &f,
        hold,
        [0; 32],
        Transition::ReturnUnused,
        2,
        [123; 32],
        return_payload(0, [0; 32]),
    )
    .await;
    let facts = authorize(&f, auth, [124; 32]).await;
    observe(&f, facts, [125; 32]).await;
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .buyer_unused_outstanding,
        34
    );
    let duplicate = authorization(
        &f,
        hold,
        [0; 32],
        Transition::ReturnUnused,
        3,
        [126; 32],
        return_payload(0, [0; 32]),
    )
    .await;
    assert_eq!(
        prepare_authorization(&f, duplicate, [127; 32]).await,
        Err(LedgerError::CompetingIntent)
    );
    f.remove().await;
}

#[tokio::test]
async fn excluded_whole_return_requires_locked_observer_evidence_and_canonical_commit() {
    let f = Fixture::new("excludedreturn").await;
    let credit = f.issue(34, 50).await;
    let hold = [60; 32];
    let pair = target::pair_address(&f.policy.domain, &f.policy.target_admin);
    let epoch = target::epoch_address(&f.policy.domain, &pair);
    let anchor = target::decision(
        f.policy.domain,
        epoch,
        None,
        Transition::OpenEpoch,
        target::Envelope {
            intent: [26; 32],
            generation: 1,
            prior: 0,
            predecessor: [0; 32],
        },
        &f.policy.domain.epoch.to_le_bytes(),
        &[pair, epoch, [0; 32], target::INSTRUCTIONS_SYSVAR_ID],
    )
    .unwrap();
    let mut binding = f.target_binding(hold);
    binding.evidence = TargetHoldEvidence::Locked {
        anchor: f.observed(anchor),
        lock_transaction: [130; 32],
        lock_slot: 201,
    };
    binding.epoch_version = 2;
    binding.signature = f
        .target_key
        .sign(&binding.signing_bytes().unwrap())
        .to_bytes();
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
    f.apply(op, command).await;
    let auth = authorization(
        &f,
        hold,
        [0; 32],
        Transition::CommitEpoch,
        2,
        [120; 32],
        [64; 32].to_vec(),
    )
    .await;
    let facts = authorize(&f, auth, [121; 32]).await;
    observe_epoch(&f, facts, 122).await;
    native_refund(&f, hold, hold, 34, 100).await;
    let auth = authorization(
        &f,
        hold,
        [0; 32],
        Transition::ReturnUnused,
        1,
        [123; 32],
        return_payload(0, [0; 32]),
    )
    .await;
    let facts = authorize(&f, auth, [124; 32]).await;
    observe(&f, facts, [125; 32]).await;
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .buyer_unused_outstanding,
        34
    );
    f.remove().await;
}

#[tokio::test]
async fn cancelled_fill_return_uses_exact_custody_fence_and_cannot_return_twice() {
    let f = Fixture::new("cancelreturn").await;
    let (_, hold, _) = f.active().await;
    prepare_fill(&f, hold).await;
    cancel_fill(&f, hold).await;
    let wrong = authorization(
        &f,
        hold,
        [65; 32],
        Transition::ReturnUnused,
        3,
        [130; 32],
        return_payload(2, [131; 32]),
    )
    .await;
    assert_eq!(
        prepare_authorization(&f, wrong, [132; 32]).await,
        Err(LedgerError::InvalidEvidence)
    );
    let auth = authorization(
        &f,
        hold,
        [65; 32],
        Transition::ReturnUnused,
        3,
        [133; 32],
        return_payload(2, [98; 32]),
    )
    .await;
    let facts = authorize(&f, auth, [134; 32]).await;
    observe(&f, facts, [135; 32]).await;
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .buyer_unused_outstanding,
        34
    );
    let duplicate = authorization(
        &f,
        hold,
        [65; 32],
        Transition::ReturnUnused,
        4,
        [136; 32],
        return_payload(2, [98; 32]),
    )
    .await;
    assert_eq!(
        prepare_authorization(&f, duplicate, [137; 32]).await,
        Err(LedgerError::CompetingIntent)
    );
    f.remove().await;
}

#[tokio::test]
async fn release_and_cancel_bind_first_leg_identity_and_live_native_payout_blocks_cancel() {
    let f = Fixture::new("fillidentity").await;
    let (_, hold, _) = f.active().await;
    prepare_fill(&f, hold).await;
    let payload = target::ReleaseEffects {
        amount: 5,
        result: [64; 32],
        fence: [72; 32],
    }
    .encode()
    .to_vec();
    let wrong = authorization(
        &f,
        hold,
        [65; 32],
        Transition::ReleaseSpl,
        2,
        [130; 32],
        payload.clone(),
    )
    .await;
    assert_eq!(
        prepare_authorization(&f, wrong, [131; 32]).await,
        Err(LedgerError::InvalidEvidence)
    );
    let wrong = authorization(
        &f,
        hold,
        [65; 32],
        Transition::CancelFill,
        2,
        [130; 32],
        [98; 32].to_vec(),
    )
    .await;
    assert_eq!(
        prepare_authorization(&f, wrong, [132; 32]).await,
        Err(LedgerError::InvalidEvidence)
    );
    let auth = authorization(
        &f,
        hold,
        [65; 32],
        Transition::ReleaseSpl,
        2,
        [95; 32],
        payload,
    )
    .await;
    let target = authorize(&f, auth, [133; 32]).await;
    let command = LedgerCommand::ObserveSplRelease {
        hold,
        portion: [65; 32],
        recipient: [67; 32],
        target_base_amount: 5,
        target,
    };
    let op = f.operation(
        hold,
        [65; 32],
        [134; 32],
        f.ledger
            .entity_version(f.policy.domain.pair, hold, [65; 32])
            .await
            .unwrap(),
        Transition::ReleaseSpl,
        &command,
    );
    f.apply(op, command).await;
    let command = LedgerCommand::PrepareNative(NativePlan {
        hold,
        portion: [65; 32],
        kind: NativeIntentKind::SellerPayout,
        recipient: [66; 43],
        amount: 25,
        inventory_scope: f.policy.inventory_scope,
        inputs: vec![[52; 32]],
        fee_inputs: vec![],
        change: vec![ChangeOutput {
            note: [101; 32],
            action_index: 1,
            note_commitment: [106; 32],
            nullifier: [107; 32],
            receiver: f.policy.receiver,
            value: 9,
        }],
        fee: 0,
        nonce: [102; 32],
        pczt_digest: [103; 32],
        sighash: [104; 32],
        transaction: [105; 32],
    });
    let op = f.operation(
        hold,
        [65; 32],
        [100; 32],
        f.ledger
            .entity_version(f.policy.domain.pair, hold, [65; 32])
            .await
            .unwrap(),
        Transition::PrepareNative,
        &command,
    );
    f.apply(op, command).await;
    let cancel = authorization(
        &f,
        hold,
        [65; 32],
        Transition::CancelFill,
        3,
        [95; 32],
        [98; 32].to_vec(),
    )
    .await;
    assert_eq!(
        prepare_authorization(&f, cancel, [136; 32]).await,
        Err(LedgerError::CompetingIntent)
    );
    f.remove().await;
}

#[tokio::test]
async fn disputed_cancelled_fill_refund_retains_buyer_liability() {
    let f = Fixture::new("cancelleddispute").await;
    let (_, hold, _) = f.active().await;
    prepare_fill(&f, hold).await;
    cancel_fill(&f, hold).await;
    native_refund(&f, hold, [65; 32], 25, 100).await;
    for (tag, transaction) in [(150, [105; 32]), (151, [152; 32])] {
        let facts = NativeFacts {
            domain: f.policy.domain,
            provenance: f.policy.environment,
            intent: [100; 32],
            transaction,
            inputs: vec![[52; 32]],
            recipient: [40; 43],
            amount: 25,
            change: vec![ChangeOutput {
                note: [101; 32],
                action_index: 1,
                note_commitment: [106; 32],
                nullifier: [107; 32],
                receiver: f.policy.receiver,
                value: 9,
            }],
            block: [153; 32],
            height: 200,
            confirmations: 12,
            history_anchor: f.policy.history_anchor,
        };
        let command = LedgerCommand::ObserveNative(SignedNativeFacts {
            signature: f
                .inventory_key
                .sign(&facts.signing_bytes().unwrap())
                .to_bytes(),
            facts,
        });
        let op = f.operation(
            [100; 32],
            [0; 32],
            [tag; 32],
            f.ledger
                .entity_version(f.policy.domain.pair, [100; 32], [0; 32])
                .await
                .unwrap(),
            Transition::ObserveNative,
            &command,
        );
        f.apply(op, command).await;
    }
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.seller_outstanding,
            snapshot.buyer_unused_outstanding,
            snapshot.final_refund
        ),
        (0, 34, 0)
    );
    assert!(snapshot.impaired);
    f.remove().await;
}

async fn observe_cancelled_native_refund(f: &Fixture, transaction: Id, tag: u8) {
    let facts = NativeFacts {
        domain: f.policy.domain,
        provenance: f.policy.environment,
        intent: [100; 32],
        transaction,
        inputs: vec![[52; 32]],
        recipient: [40; 43],
        amount: 25,
        change: vec![ChangeOutput {
            note: [101; 32],
            action_index: 1,
            note_commitment: [106; 32],
            nullifier: [107; 32],
            receiver: f.policy.receiver,
            value: 9,
        }],
        block: [153; 32],
        height: 200,
        confirmations: 12,
        history_anchor: f.policy.history_anchor,
    };
    let command = LedgerCommand::ObserveNative(SignedNativeFacts {
        signature: f
            .inventory_key
            .sign(&facts.signing_bytes().unwrap())
            .to_bytes(),
        facts,
    });
    let operation = f.operation(
        [100; 32],
        [0; 32],
        [tag; 32],
        f.ledger
            .entity_version(f.policy.domain.pair, [100; 32], [0; 32])
            .await
            .unwrap(),
        Transition::ObserveNative,
        &command,
    );
    f.apply(operation, command).await;
}

async fn return_cancelled_spl(f: &Fixture, hold: Id) {
    let before = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let before_intent = f.ledger.intent(f.policy.domain.pair, [100; 32]).await.ok();
    let wrong = authorization(
        f,
        hold,
        [65; 32],
        Transition::ReturnUnused,
        3,
        [130; 32],
        return_payload(2, [131; 32]),
    )
    .await;
    assert!(matches!(
        prepare_authorization(f, wrong, [132; 32]).await,
        Err(LedgerError::InvalidEvidence | LedgerError::CompetingIntent)
    ));
    assert_eq!(
        f.ledger.snapshot(f.policy.domain.pair).await.unwrap(),
        before
    );
    let auth = authorization(
        f,
        hold,
        [65; 32],
        Transition::ReturnUnused,
        3,
        [133; 32],
        return_payload(2, [98; 32]),
    )
    .await;
    let facts = authorize(f, auth, [134; 32]).await;
    observe(f, facts, [135; 32]).await;
    let after = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        after.buyer_unused_outstanding,
        before.buyer_unused_outstanding
    );
    assert_eq!(after.final_refund, before.final_refund);
    assert_eq!(after.locked_inventory, before.locked_inventory);
    for db in std::iter::once(&f.db).chain(&f.replica_dbs) {
        let state = Ledger::connect(&db.config).await.unwrap();
        assert_eq!(state.snapshot(f.policy.domain.pair).await.unwrap(), after);
        assert_eq!(
            state.intent(f.policy.domain.pair, [100; 32]).await.ok(),
            before_intent
        );
        state.close().await;
        let mut connection = db.connection().await;
        let retained = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, bool)>(
            "SELECT first_leg_intent,custody_fence,target_returned FROM ledger_portions WHERE pair=$1 AND hold=$2 AND portion=$3",
        )
        .bind(f.policy.domain.pair.as_slice())
        .bind(hold.as_slice())
        .bind([65_u8; 32].as_slice())
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(retained, (vec![95; 32], vec![98; 32], true));
    }
    let duplicate = authorization(
        f,
        hold,
        [65; 32],
        Transition::ReturnUnused,
        4,
        [136; 32],
        return_payload(2, [98; 32]),
    )
    .await;
    assert_eq!(
        prepare_authorization(f, duplicate, [137; 32]).await,
        Err(LedgerError::CompetingIntent)
    );
    assert_eq!(
        f.ledger.snapshot(f.policy.domain.pair).await.unwrap(),
        after
    );
}

#[tokio::test]
async fn cancelled_spl_return_remains_available_during_prepared_and_unknown_buyer_refund() {
    for unknown in [false, true] {
        let f = Fixture::new("cancelpendingrefund").await;
        let (_, hold, _) = f.active().await;
        prepare_fill(&f, hold).await;
        cancel_fill(&f, hold).await;
        native_refund(&f, hold, [65; 32], 25, 100).await;
        if unknown {
            let command = LedgerCommand::NativeUnknown {
                intent: [100; 32],
                transaction: [105; 32],
            };
            let operation = f.operation(
                [100; 32],
                [0; 32],
                [120; 32],
                1,
                Transition::ObserveNative,
                &command,
            );
            f.apply(operation, command).await;
        }
        return_cancelled_spl(&f, hold).await;
        observe_cancelled_native_refund(&f, [105; 32], 150).await;
        let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
        assert_eq!(
            (snapshot.final_refund, snapshot.buyer_unused_outstanding),
            (25, 9)
        );
        f.remove().await;
    }
}

#[tokio::test]
async fn cancelled_spl_return_remains_available_after_final_buyer_refund() {
    let f = Fixture::new("cancelfinalrefund").await;
    let (_, hold, _) = f.active().await;
    prepare_fill(&f, hold).await;
    cancel_fill(&f, hold).await;
    native_refund(&f, hold, [65; 32], 25, 100).await;
    observe_cancelled_native_refund(&f, [105; 32], 150).await;
    return_cancelled_spl(&f, hold).await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (snapshot.final_refund, snapshot.buyer_unused_outstanding),
        (25, 9)
    );
    f.remove().await;
}

#[tokio::test]
async fn returned_cancelled_spl_does_not_block_subsequent_buyer_refund() {
    let f = Fixture::new("cancelreturnfirst").await;
    let (_, hold, _) = f.active().await;
    prepare_fill(&f, hold).await;
    cancel_fill(&f, hold).await;
    return_cancelled_spl(&f, hold).await;
    native_refund(&f, hold, [65; 32], 25, 100).await;
    observe_cancelled_native_refund(&f, [105; 32], 150).await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (snapshot.final_refund, snapshot.buyer_unused_outstanding),
        (25, 9)
    );
    f.remove().await;
}

#[tokio::test]
async fn cancel_before_prepare_preserves_spl_return_and_buyer_refund_in_either_order() {
    for native_first in [false, true] {
        let f = Fixture::new("directcancelreturn").await;
        let (_, hold, _) = f.active().await;
        let auth = authorization(
            &f,
            hold,
            [65; 32],
            Transition::CancelFill,
            1,
            [95; 32],
            [98; 32].to_vec(),
        )
        .await;
        let target = authorize(&f, auth, [99; 32]).await;
        let command = LedgerCommand::CancelFirstLeg {
            hold,
            portion: [65; 32],
            target,
        };
        let operation = f.operation(
            hold,
            [65; 32],
            [90; 32],
            f.ledger
                .entity_version(f.policy.domain.pair, hold, [65; 32])
                .await
                .unwrap(),
            Transition::CancelFill,
            &command,
        );
        f.apply(operation, command).await;
        if native_first {
            native_refund(&f, hold, [65; 32], 25, 100).await;
            observe_cancelled_native_refund(&f, [105; 32], 150).await;
        }
        let auth = authorization(
            &f,
            hold,
            [65; 32],
            Transition::ReturnUnused,
            2,
            [133; 32],
            return_payload(2, [98; 32]),
        )
        .await;
        let facts = authorize(&f, auth, [134; 32]).await;
        observe(&f, facts, [135; 32]).await;
        if !native_first {
            native_refund(&f, hold, [65; 32], 25, 100).await;
            observe_cancelled_native_refund(&f, [105; 32], 150).await;
        }
        let pair = f.policy.domain.pair;
        let snapshot = f.ledger.snapshot(pair).await.unwrap();
        assert_eq!(
            (snapshot.final_refund, snapshot.buyer_unused_outstanding),
            (25, 9)
        );
        for db in std::iter::once(&f.db).chain(&f.replica_dbs) {
            let state = Ledger::connect(&db.config).await.unwrap();
            assert_eq!(state.snapshot(pair).await.unwrap(), snapshot);
            assert_eq!(
                state.intent(pair, [100; 32]).await.unwrap().state,
                IntentStatus::Finalized
            );
            state.close().await;
            let mut connection = db.connection().await;
            let retained = sqlx::query_as::<_, (Option<Vec<u8>>, Vec<u8>, bool)>(
                "SELECT first_leg_intent,custody_fence,target_returned FROM ledger_portions WHERE pair=$1 AND hold=$2 AND portion=$3",
            )
            .bind(pair.as_slice())
            .bind(hold.as_slice())
            .bind([65_u8; 32].as_slice())
            .fetch_one(&mut connection)
            .await
            .unwrap();
            assert_eq!(retained, (None, vec![98; 32], true));
        }
        let duplicate = authorization(
            &f,
            hold,
            [65; 32],
            Transition::ReturnUnused,
            3,
            [136; 32],
            return_payload(2, [98; 32]),
        )
        .await;
        assert_eq!(
            prepare_authorization(&f, duplicate, [137; 32]).await,
            Err(LedgerError::CompetingIntent)
        );
        assert_eq!(f.ledger.snapshot(pair).await.unwrap(), snapshot);
        f.remove().await;
    }
}
