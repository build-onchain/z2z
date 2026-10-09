#![cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod support;
use ed25519_dalek::{Signer, SigningKey};
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use rand_core::OsRng;
use sqlx::Connection;
use support::*;

// Removing the prepare-time reservation would let two promises consume the same34.
#[tokio::test]
async fn concurrent_prepares_reserve_full_debit_before_acknowledgements() {
    let f = Fixture::new("concurrent").await;
    let credit = f.issue(34, 50).await;
    let (op_a, command_a) = f.prepare(credit, [60; 32], 34);
    let (op_b, command_b) = f.prepare(credit, [61; 32], 34);
    let (a, b) = tokio::join!(
        f.ledger.prepare_decision(op_a, command_a),
        f.ledger.prepare_decision(op_b, command_b)
    );
    assert!(matches!((&a, &b), (Ok(_), Err(_)) | (Err(_), Ok(_))));
    let rejected = if let Err(error) = &a {
        error
    } else {
        b.as_ref().unwrap_err()
    };
    assert!(matches!(
        rejected,
        LedgerError::InsufficientCredit | LedgerError::Conflict | LedgerError::SerializationFailure
    ));
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!((snapshot.available_credit, snapshot.prepared), (0, 34));
    let decision = a.or(b).unwrap();
    f.ledger.close().await;
    let reopened = Ledger::connect(&f.db.config).await.unwrap();
    assert_eq!(
        reopened
            .pending_decision(f.policy.domain.pair)
            .await
            .unwrap(),
        Some(decision.clone())
    );
    assert_eq!(
        reopened
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .prepared,
        34
    );
    let acknowledgements = f.acknowledge(&decision).await;
    assert_eq!(
        reopened.commit_decision(&decision, &acknowledgements).await,
        Err(LedgerError::RecoveryEvidenceMissing)
    );
    assert_eq!(f.reconcile(&reopened).await, RecoveryState::PendingRetained);
    reopened
        .commit_decision(&decision, &acknowledgements)
        .await
        .unwrap();
    assert_eq!(
        reopened
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .prepared,
        34
    );
    reopened.close().await;
    f.remove().await;
}

// A repeated occurrence must never issue again when its eligible block changes.
#[tokio::test]
async fn stable_occurrence_dedup_survives_reinclusion_copied_memo_and_restart() {
    let f = Fixture::new("dedup").await;
    let command = f.funding(34, 50);
    let credit = [51; 32];
    let op = f.operation(
        credit,
        [0; 32],
        credit,
        0,
        Transition::IssueCredit,
        &command,
    );
    let original = f.apply(op, command.clone()).await;
    let retry = f
        .ledger
        .prepare_decision(op, command.clone())
        .await
        .unwrap();
    assert_eq!(retry, original);
    let mut changed = command;
    if let LedgerCommand::IssueCredit { claim, source, .. } = &mut changed {
        source.facts.block = [31; 32];
        source.facts.height = 101;
        source.signature = f
            .source_key
            .sign(&source.facts.signing_bytes().unwrap())
            .to_bytes();
        claim.evidence_digest = source.facts.digest().unwrap();
        claim.authorization = f.claimant.sign(&claim.signing_bytes().unwrap()).to_bytes();
    }
    let changed_op = f.operation(
        credit,
        [0; 32],
        credit,
        0,
        Transition::IssueCredit,
        &changed,
    );
    assert_eq!(
        f.ledger.prepare_decision(changed_op, changed.clone()).await,
        Err(LedgerError::Conflict)
    );
    if let LedgerCommand::IssueCredit { claim, source, .. } = &mut changed {
        claim.credit_intent = [90; 32];
        source.facts.effect = SourceEffect::Deposit {
            claimant: claim.claimant,
            credit_intent: claim.credit_intent,
        };
        source.signature = f
            .source_key
            .sign(&source.facts.signing_bytes().unwrap())
            .to_bytes();
        claim.evidence_digest = source.facts.digest().unwrap();
        claim.authorization = f.claimant.sign(&claim.signing_bytes().unwrap()).to_bytes();
    }
    let copied = f.operation(
        [90; 32],
        [0; 32],
        [90; 32],
        0,
        Transition::IssueCredit,
        &changed,
    );
    assert_eq!(
        f.ledger.prepare_decision(copied, changed).await,
        Err(LedgerError::DuplicateOccurrence)
    );
    f.ledger.close().await;
    let reopened = Ledger::connect(&f.db.config).await.unwrap();
    assert_eq!(
        reopened
            .credit(f.policy.domain.pair, credit)
            .await
            .unwrap()
            .available,
        34
    );
    assert_eq!(
        reopened
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .available_credit,
        34
    );
    reopened.close().await;
    f.remove().await;
}

// Producer enrollment, claimant binding and environment policy are trust boundaries.
#[tokio::test]
async fn funding_rejects_forged_authority_wrong_claimant_receiver_pair_and_history() {
    let f = Fixture::new("evidence").await;
    for case in 0..8 {
        let mut command = f.funding(34, 50);
        if let LedgerCommand::IssueCredit {
            claim,
            source,
            inventory,
        } = &mut command
        {
            match case {
                0 => {
                    let outsider = SigningKey::generate(&mut OsRng);
                    source.signature = outsider
                        .sign(&source.facts.signing_bytes().unwrap())
                        .to_bytes();
                }
                1 => claim.claimant = [92; 32],
                2 => {
                    source.facts.receiver = [93; 43];
                    source.signature = f
                        .source_key
                        .sign(&source.facts.signing_bytes().unwrap())
                        .to_bytes();
                }
                3 => {
                    source.facts.domain.pair = [94; 32];
                    source.signature = f
                        .source_key
                        .sign(&source.facts.signing_bytes().unwrap())
                        .to_bytes();
                }
                4 => {
                    source.facts.effect = SourceEffect::HistoryGap;
                    source.signature = f
                        .source_key
                        .sign(&source.facts.signing_bytes().unwrap())
                        .to_bytes();
                }
                5 => {
                    source.facts.provenance = ObservationEnvironment::Network;
                    source.signature = f
                        .source_key
                        .sign(&source.facts.signing_bytes().unwrap())
                        .to_bytes();
                }
                6 => {
                    inventory.facts.condition = InventoryCondition::Unknown;
                    inventory.signature = f
                        .inventory_key
                        .sign(&inventory.facts.signing_bytes().unwrap())
                        .to_bytes();
                }
                7 => {
                    inventory.facts.scope = f.policy.sponsor_scope;
                    inventory.signature = f
                        .inventory_key
                        .sign(&inventory.facts.signing_bytes().unwrap())
                        .to_bytes();
                }
                _ => unreachable!(),
            }
        }
        let op = f.operation(
            [51; 32],
            [0; 32],
            [51; 32],
            0,
            Transition::IssueCredit,
            &command,
        );
        let error = f.ledger.prepare_decision(op, command).await.unwrap_err();
        assert!(matches!(
            error,
            LedgerError::InvalidEvidence | LedgerError::InvalidAuthorization
        ));
        let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
        assert_eq!(
            (
                snapshot.available_credit,
                snapshot.usable_inventory,
                snapshot.sequence
            ),
            (0, 0, 0)
        );
    }
    f.remove().await;
}

// Signed but unclaimed, reorged, unknown or change facts cannot become deposit credit.
#[tokio::test]
async fn change_and_quarantined_source_facts_never_mint_credit() {
    let f = Fixture::new("quarantine").await;
    for effect in [
        SourceEffect::Unclaimed,
        SourceEffect::Reorged,
        SourceEffect::Unknown,
        SourceEffect::Change {
            parent_intent: [99; 32],
        },
    ] {
        let mut command = f.funding(34, 50);
        if let LedgerCommand::IssueCredit {
            claim,
            source,
            inventory,
        } = &mut command
        {
            source.facts.effect = effect;
            source.signature = f
                .source_key
                .sign(&source.facts.signing_bytes().unwrap())
                .to_bytes();
            claim.evidence_digest = source.facts.digest().unwrap();
            claim.authorization = f.claimant.sign(&claim.signing_bytes().unwrap()).to_bytes();
            if matches!(effect, SourceEffect::Change { .. }) {
                inventory.facts.origin = InventoryOrigin::Change {
                    parent_intent: [99; 32],
                };
                inventory.signature = f
                    .inventory_key
                    .sign(&inventory.facts.signing_bytes().unwrap())
                    .to_bytes();
            }
        }
        let op = f.operation(
            [51; 32],
            [0; 32],
            [51; 32],
            0,
            Transition::IssueCredit,
            &command,
        );
        assert_eq!(
            f.ledger.prepare_decision(op, command).await,
            Err(LedgerError::InvalidEvidence)
        );
    }
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .available_credit,
        0
    );
    f.remove().await;
}

// BIGINT narrowing or missing SQL numeric bounds would corrupt this boundary.
#[tokio::test]
async fn full_u64_roundtrips_and_database_rejects_negative_and_overflow() {
    let f = Fixture::new("maxu").await;
    let credit = f.issue(u64::MAX, 50).await;
    assert_eq!(
        f.ledger
            .credit(f.policy.domain.pair, credit)
            .await
            .unwrap()
            .amount,
        u64::MAX
    );
    let (op, command) = f.prepare(credit, [60; 32], u64::MAX);
    f.apply(op, command).await;
    assert_eq!(
        f.ledger
            .hold(f.policy.domain.pair, [60; 32])
            .await
            .unwrap()
            .amount,
        u64::MAX
    );
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .prepared,
        u128::from(u64::MAX)
    );
    let mut sql = f.db.connection().await;
    for invalid in ["-1", "18446744073709551616"] {
        let result = sqlx::query(
            "UPDATE ledger_credits SET amount = $1::text::numeric WHERE pair = $2 AND credit = $3",
        )
        .bind(invalid)
        .bind(f.policy.domain.pair.as_slice())
        .bind(credit.as_slice())
        .execute(&mut sql)
        .await;
        assert!(result.is_err(), "database accepted invalid u64 {invalid}");
    }
    sql.close().await.unwrap();
    assert_eq!(
        f.ledger
            .credit(f.policy.domain.pair, credit)
            .await
            .unwrap()
            .amount,
        u64::MAX
    );
    f.remove().await;
}

// Wrong CAS, writer generation, or body must not consume/refund the same entity.
#[tokio::test]
async fn exact_bytes_versions_and_writer_generation_fence_mutations() {
    let mut f = Fixture::new("fences").await;
    let credit = f.issue(34, 50).await;
    let (op, command) = f.prepare(credit, [60; 32], 34);
    let decision = f.apply(op, command.clone()).await;
    assert_eq!(
        f.ledger
            .prepare_decision(op, command.clone())
            .await
            .unwrap(),
        decision
    );
    let mut altered = command;
    if let LedgerCommand::PrepareHold {
        refund_receiver, ..
    } = &mut altered
    {
        *refund_receiver = [41; 43];
    }
    let changed = f.operation(
        [60; 32],
        [0; 32],
        [60; 32],
        0,
        Transition::PrepareHold,
        &altered,
    );
    assert_eq!(
        f.ledger.prepare_decision(changed, altered).await,
        Err(LedgerError::Conflict)
    );
    let stale = f.fence;
    f.fence = f
        .ledger
        .claim_writer(f.policy.domain.pair, stale.generation)
        .await
        .unwrap();
    let (mut op, command) = f.prepare(credit, [61; 32], 1);
    op.generation = stale.generation;
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::StaleWriter)
    );
    let mut auth = f.authorization(
        ([60; 32], [0; 32]),
        Transition::CommitEpoch,
        3,
        [62; 32],
        [64; 32].to_vec(),
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .target_head,
    );
    auth.decision.operation.generation = 2;
    auth.decision = Decision::new(auth.decision.operation, auth.decision.predecessor).unwrap();
    let command = LedgerCommand::AuthorizeTarget(auth);
    let op = f.operation(
        [60; 32],
        [0; 32],
        [63; 32],
        0,
        Transition::PrepareFill,
        &command,
    );
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::VersionConflict)
    );
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

// Expiry/restart/accepted and partial FINAL never release unused9 from held34.
#[tokio::test]
async fn prepared_accepted_and_partial_final_cannot_refund_or_release() {
    let f = Fixture::new("partial").await;
    let (_, hold) = f.held().await;
    let (op, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::NotReturnable)
    );
    let plan = f.allocated(hold).await;
    f.chunk(&plan, 0, 3).await;
    let mut payload = plan.allocation.to_vec();
    payload.extend_from_slice(&[73; 32]);
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let mut auth = f.authorization(
        (hold, [0; 32]),
        Transition::ActivateAllocation,
        5,
        [85; 32],
        payload,
        snapshot.target_head,
    );
    auth.decision.operation.generation = snapshot.target_generation.checked_add(1).unwrap();
    auth.decision = Decision::new(auth.decision.operation, snapshot.target_head).unwrap();
    let command = LedgerCommand::AuthorizeTarget(auth);
    let version = f
        .ledger
        .hold(f.policy.domain.pair, hold)
        .await
        .unwrap()
        .version;
    let op = f.operation(
        hold,
        [0; 32],
        [86; 32],
        version,
        Transition::PrepareFill,
        &command,
    );
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::IncompleteAllocation)
    );
    let (op, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::NotReturnable)
    );
    let command = LedgerCommand::PrepareFirstLeg {
        hold,
        portion: [65; 32],
    };
    let op = f.operation(
        hold,
        [65; 32],
        [95; 32],
        0,
        Transition::PrepareFill,
        &command,
    );
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::IncompleteAllocation)
    );
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.available_credit,
            snapshot.encumbered,
            snapshot.buyer_unused_outstanding
        ),
        (0, 34, 0)
    );
    f.remove().await;
}

// Distinct active portions may progress, but native unknowns cannot free backing.
#[tokio::test]
async fn full_activation_partitions_twenty_five_and_nine_without_double_disposal() {
    let f = Fixture::new("portions").await;
    let (_, hold, _) = f.active().await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.seller_outstanding,
            snapshot.buyer_unused_outstanding,
            snapshot.encumbered
        ),
        (25, 9, 0)
    );
    let (op, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(op, command).await;
    let command = LedgerCommand::PrepareFirstLeg {
        hold,
        portion: [65; 32],
    };
    let op = f.operation(
        hold,
        [65; 32],
        [95; 32],
        0,
        Transition::PrepareFill,
        &command,
    );
    f.apply(op, command).await;
    let (op, command) = f.refund(hold, [68; 32], [52; 32], 110).await;
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::CompetingIntent)
    );
    let command = LedgerCommand::NativeUnknown {
        intent: [100; 32],
        transaction: [105; 32],
    };
    let op = f.operation(
        [100; 32],
        [0; 32],
        [120; 32],
        1,
        Transition::ObserveNative,
        &command,
    );
    f.apply(op, command).await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.seller_outstanding,
            snapshot.buyer_unused_outstanding,
            snapshot.locked_inventory
        ),
        (25, 9, 34)
    );
    assert_eq!(
        f.ledger
            .intent(f.policy.domain.pair, [100; 32])
            .await
            .unwrap()
            .state,
        IntentStatus::Unknown
    );
    f.remove().await;
}

// Consume once: original input is replaced by recipient+provisional change, not duplicated.
#[tokio::test]
async fn observed_consumption_replaces_backing_and_pending_change_is_unspendable() {
    let f = Fixture::new("inventory").await;
    let (_, hold, _) = f.active().await;
    let (op, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(op, command).await;
    let facts = NativeFacts {
        domain: f.policy.domain,
        provenance: ObservationEnvironment::LocalFixture,
        intent: [100; 32],
        transaction: [105; 32],
        inputs: vec![[52; 32]],
        recipient: [40; 43],
        amount: 9,
        change: vec![ChangeOutput {
            note: [101; 32],
            action_index: 1,
            note_commitment: [106; 32],
            nullifier: [107; 32],
            receiver: f.policy.receiver,
            value: 25,
        }],
        block: [130; 32],
        height: 200,
        confirmations: 0,
        history_anchor: f.policy.history_anchor,
    };
    let signed = SignedNativeFacts {
        signature: f
            .inventory_key
            .sign(&facts.signing_bytes().unwrap())
            .to_bytes(),
        facts: facts.clone(),
    };
    let command = LedgerCommand::ObserveNative(signed);
    let op = f.operation(
        [100; 32],
        [0; 32],
        [131; 32],
        1,
        Transition::ObserveNative,
        &command,
    );
    let consumed = f.apply(op, command.clone()).await;
    assert_eq!(
        f.ledger.prepare_decision(op, command).await.unwrap(),
        consumed
    );
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.usable_inventory,
            snapshot.locked_inventory,
            snapshot.provisional_change,
            snapshot.pending_recipient
        ),
        (0, 0, 25, 9)
    );
    assert_eq!(
        (
            snapshot.seller_outstanding,
            snapshot.buyer_unused_outstanding,
            snapshot.final_refund
        ),
        (25, 9, 0)
    );
    let command = LedgerCommand::ReserveInputs {
        inputs: vec![[101; 32]],
        scope: f.policy.inventory_scope,
    };
    let op = f.operation(
        [132; 32],
        [0; 32],
        [132; 32],
        0,
        Transition::ReserveInputs,
        &command,
    );
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::InventoryUnavailable)
    );
    let mut confirmed = facts;
    confirmed.confirmations = 12;
    let signed = SignedNativeFacts {
        signature: f
            .inventory_key
            .sign(&confirmed.signing_bytes().unwrap())
            .to_bytes(),
        facts: confirmed,
    };
    let command = LedgerCommand::ObserveNative(signed);
    let op = f.operation(
        [100; 32],
        [0; 32],
        [133; 32],
        2,
        Transition::ObserveNative,
        &command,
    );
    f.apply(op, command).await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.usable_inventory,
            snapshot.provisional_change,
            snapshot.pending_recipient,
            snapshot.final_refund
        ),
        (25, 0, 0, 9)
    );
    assert_eq!(
        (snapshot.available_credit, snapshot.seller_outstanding),
        (0, 25)
    );
    f.remove().await;
}

// Sponsor stock is not buyer credit; impairment keeps existing liabilities intact.
#[tokio::test]
async fn sponsor_inventory_isolated_and_impairment_stops_new_sends() {
    let f = Fixture::new("impairment").await;
    let (_, hold, _) = f.active().await;
    let facts = InventoryFacts {
        domain: f.policy.domain,
        provenance: ObservationEnvironment::LocalFixture,
        note: [150; 32],
        occurrence: SourceOccurrence {
            network: SOURCE_NETWORK_TESTNET,
            pool: SOURCE_POOL_IRONWOOD,
            txid: [151; 32],
            action_index: 0,
        },
        note_commitment: [152; 32],
        nullifier: [153; 32],
        receiver: f.policy.receiver,
        value: 10,
        scope: f.policy.sponsor_scope,
        control: f.policy.inventory_producer,
        origin: InventoryOrigin::Sponsor,
        condition: InventoryCondition::Spendable,
        history_anchor: f.policy.history_anchor,
    };
    let command = LedgerCommand::RegisterSponsor {
        inventory: SignedInventoryFacts {
            signature: f
                .inventory_key
                .sign(&facts.signing_bytes().unwrap())
                .to_bytes(),
            facts,
        },
    };
    let op = f.operation(
        [150; 32],
        [0; 32],
        [152; 32],
        0,
        Transition::ReserveInputs,
        &command,
    );
    f.apply(op, command).await;
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .sponsor_inventory,
        10
    );
    let (op, mut command) = f.refund(hold, [68; 32], [150; 32], 100).await;
    if let LedgerCommand::PrepareNative(plan) = &mut command {
        plan.change[0].value = 1;
    }
    let mut op = op;
    op.effects = command.operation_effects(&op).unwrap();
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::InventoryUnavailable)
    );
    let mut facts = match f.funding(34, 50) {
        LedgerCommand::IssueCredit { inventory, .. } => inventory.facts,
        _ => unreachable!(),
    };
    facts.condition = InventoryCondition::Reorged;
    let command = LedgerCommand::ImpairInventory {
        inventory: SignedInventoryFacts {
            signature: f
                .inventory_key
                .sign(&facts.signing_bytes().unwrap())
                .to_bytes(),
            facts,
        },
    };
    let op = f.operation(
        [52; 32],
        [0; 32],
        [153; 32],
        0,
        Transition::ObserveNative,
        &command,
    );
    f.apply(op, command).await;
    let (op, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::InventoryImpaired)
    );
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert!(snapshot.impaired);
    assert_eq!(
        (
            snapshot.seller_outstanding,
            snapshot.buyer_unused_outstanding
        ),
        (25, 9)
    );
    f.remove().await;
}

// Caller-selected finality or forged observer cannot mutate the accepted hold.
#[tokio::test]
async fn target_observations_require_enrolled_authority_exact_context_and_finality() {
    let f = Fixture::new("target").await;
    let (_, hold) = f.held().await;
    for case in 0..4 {
        let mut target = f
            .target(
                (hold, [0; 32]),
                Transition::CommitEpoch,
                [61; 32],
                1,
                0,
                [62; 32],
            )
            .await;
        match case {
            0 => {
                let outsider = SigningKey::generate(&mut OsRng);
                target.signature = outsider
                    .sign(&target.facts.signing_bytes().unwrap())
                    .to_bytes();
            }
            1 => {
                target.facts.observation.environment = ObservationEnvironment::Network;
                target.signature = f
                    .target_key
                    .sign(&target.facts.signing_bytes().unwrap())
                    .to_bytes();
            }
            2 => {
                target.facts.observation.commitment = ChainCommitment::Confirmed;
                target.signature = f
                    .target_key
                    .sign(&target.facts.signing_bytes().unwrap())
                    .to_bytes();
            }
            3 => {
                target.facts.observation.effects = [99; 32];
                target.signature = f
                    .target_key
                    .sign(&target.facts.signing_bytes().unwrap())
                    .to_bytes();
            }
            _ => unreachable!(),
        }
        let epoch = target.facts.decision.operation.entity;
        let command = LedgerCommand::ObserveEpoch { target };
        let op = f.operation(
            epoch,
            [0; 32],
            [63; 32],
            1,
            Transition::CommitEpoch,
            &command,
        );
        assert!(matches!(
            f.ledger.prepare_decision(op, command).await,
            Err(LedgerError::InvalidEvidence | LedgerError::InvalidAuthorization)
        ));
    }
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
async fn physical_inventory_migration_rejects_legacy_history_without_backfill_or_rewrite() {
    let f = Fixture::new("freshphysicalschema").await;
    f.issue(34, 50).await;
    let legacy = TestDatabase::create("legacyphysicalschema").await;
    // Obtain the production handle while the authorized schema is absent.
    // A legacy-shaped schema constructed below must never be adopted by it.
    let ledger = Ledger::connect(&legacy.config).await.unwrap();
    let mut connection = legacy.connection().await;
    sqlx::raw_sql(&format!("CREATE SCHEMA {}", legacy.config.schema))
        .execute(&mut connection).await.unwrap();
    let mut migrations = sqlx::migrate::Migrator::new(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/market"
    )))
    .await
    .unwrap();
    migrations
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 7);
    migrations.run(&mut connection).await.unwrap();
    sqlx::query("INSERT INTO ledger_pairs(pair,policy,head,target_head) VALUES($1,$2,$3,$3)")
        .bind(f.policy.domain.pair.as_slice()).bind(f.policy.canonical_bytes().unwrap())
        .bind([0_u8;32].as_slice()).execute(&mut connection).await.unwrap();
    sqlx::query("INSERT INTO ledger_inventory(pair,note,scope,receiver,amount,origin,status,facts) VALUES ($1,$2,$1,$3,34,1,1,$4)")
        .bind(f.policy.domain.pair.as_slice()).bind([52_u8; 32].as_slice()).bind(f.policy.receiver.as_slice())
        .bind(b"retained-legacy-signed-inventory".as_slice()).execute(&mut connection).await.unwrap();
    sqlx::query("INSERT INTO ledger_journal(pair,operation,sequence,predecessor,next_head,writer_generation,body) VALUES ($1,$2,1,$3,$2,1,$4)")
        .bind(f.policy.domain.pair.as_slice()).bind([60_u8; 32].as_slice()).bind([0_u8; 32].as_slice())
        .bind(b"retained-legacy-signed-journal".as_slice()).execute(&mut connection).await.unwrap();
    let inventory_before =
        sqlx::query_scalar::<_, String>("SELECT row_to_json(i)::text FROM ledger_inventory i")
            .fetch_one(&mut connection)
            .await
            .unwrap();
    let journal_before =
        sqlx::query_scalar::<_, String>("SELECT row_to_json(j)::text FROM ledger_journal j")
            .fetch_one(&mut connection)
            .await
            .unwrap();
    let policy_before =
        sqlx::query_scalar::<_, String>("SELECT row_to_json(p)::text FROM ledger_pairs p")
            .fetch_one(&mut connection)
            .await
            .unwrap();
    assert_eq!(ledger.migrate().await, Err(LedgerError::Database));
    // Preserve the original migration's own non-adoption guard independently
    // of the stricter runtime identity preflight.
    let mut attempt = connection.begin().await.unwrap();
    let error = sqlx::raw_sql(include_str!("../migrations/market/0008_physical_inventory.sql"))
        .execute(&mut *attempt).await.unwrap_err();
    assert_eq!(error.as_database_error().and_then(|e| e.code()).as_deref(),Some("23514"));
    attempt.rollback().await.unwrap();
    let inventory_after =
        sqlx::query_scalar::<_, String>("SELECT row_to_json(i)::text FROM ledger_inventory i")
            .fetch_one(&mut connection)
            .await
            .unwrap();
    let journal_after =
        sqlx::query_scalar::<_, String>("SELECT row_to_json(j)::text FROM ledger_journal j")
            .fetch_one(&mut connection)
            .await
            .unwrap();
    let policy_after =
        sqlx::query_scalar::<_, String>("SELECT row_to_json(p)::text FROM ledger_pairs p")
            .fetch_one(&mut connection)
            .await
            .unwrap();
    assert!(
        inventory_before == inventory_after
            && journal_before == journal_after
            && policy_before == policy_after,
        "failed migration changed private legacy rows"
    );
    assert!(!sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=$1 AND table_name='ledger_inventory' AND column_name='note_commitment') OR pg_catalog.to_regclass($2) IS NOT NULL")
        .bind(&legacy.config.schema).bind(format!("{}.ledger_physical_claims", legacy.config.schema))
        .fetch_one(&mut connection).await.unwrap());
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=8)"
        )
        .fetch_one(&mut connection)
        .await
        .unwrap()
    );
    // This fixture intentionally created an unrecognized legacy schema. Generic
    // cleanup refuses it; only this exact CREATE's connection drops its own scope.
    sqlx::raw_sql(&format!("DROP SCHEMA {} CASCADE", legacy.config.schema))
        .execute(&mut connection).await.unwrap();
    connection.close().await.unwrap();
    ledger.close().await;
    f.remove().await;
}
