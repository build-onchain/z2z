#![cfg(feature = "postgres-tests")]
#[path = "market_support/ledger.rs"]
mod support;
use ed25519_dalek::Signer;
use ziquid_runtime::market::ledger::*;
use ziquid_protocol::market::*;
use support::*;

fn forged_journal(
    snapshot: &PairSnapshot,
    operation: Operation,
    command: &LedgerCommand,
) -> JournalDecision {
    use sha2::{Digest, Sha256};
    let mut body = b"KERBJH02".to_vec();
    let mut encoded = [0; OPERATION_LEN];
    operation.encode_into(&mut encoded).unwrap();
    body.extend_from_slice(&encoded);
    body.extend_from_slice(&snapshot.head);
    body.extend_from_slice(&(snapshot.sequence + 1).to_le_bytes());
    let encoded_command = command.canonical_bytes().unwrap();
    body.extend_from_slice(&(encoded_command.len() as u32).to_le_bytes());
    body.extend_from_slice(&encoded_command);
    body.push(0);
    let next_head: Id = Sha256::digest(&body).into();
    body.extend_from_slice(&next_head);
    JournalDecision::decode(&body).unwrap()
}

async fn assert_refused_before_ack(
    f: &Fixture,
    operation: Operation,
    command: LedgerCommand,
    error: LedgerError,
) {
    let pair = operation.domain.pair;
    let before = f.ledger.snapshot(pair).await.unwrap();
    assert_eq!(
        f.ledger.prepare_decision(operation, command.clone()).await,
        Err(error)
    );
    assert_eq!(f.ledger.pending_decision(pair).await.unwrap(), None);
    assert_eq!(f.ledger.snapshot(pair).await.unwrap(), before);
    let forged = forged_journal(&before, operation, &command);
    let challenge = RecoveryChallenge {
        pair,
        nonce: [230; 32],
    };
    for ((replica, key), db) in f.replicas.iter().zip(&f.keys).zip(&f.replica_dbs) {
        let state = Ledger::connect(&db.config).await.unwrap();
        let before = state.snapshot(pair).await.unwrap();
        let retained = replica.retained_head(&challenge, key).await.unwrap();
        assert_eq!(replica.acknowledge(&forged, key).await, Err(error));
        assert_eq!(
            replica.retained_head(&challenge, key).await.unwrap(),
            retained
        );
        assert_eq!(state.snapshot(pair).await.unwrap(), before);
        state.close().await;
    }
}

fn final_facts(f: &Fixture, tx: Id) -> NativeFacts {
    NativeFacts {
        domain: f.policy.domain,
        provenance: f.policy.environment,
        intent: [100; 32],
        transaction: tx,
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
        block: [150; 32],
        height: 200,
        confirmations: 12,
        history_anchor: f.policy.history_anchor,
    }
}
async fn observe(f: &Fixture, facts: NativeFacts, tag: u8) {
    let command = LedgerCommand::ObserveNative(SignedNativeFacts {
        signature: f
            .inventory_key
            .sign(&facts.signing_bytes().unwrap())
            .to_bytes(),
        facts,
    });
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, [100; 32], [0; 32])
        .await
        .unwrap();
    let op = f.operation(
        [100; 32],
        [0; 32],
        [tag; 32],
        version,
        Transition::ObserveNative,
        &command,
    );
    f.apply(op, command).await;
}
#[tokio::test]
async fn authenticated_incompatible_final_history_disputes_and_quarantines_existing_change() {
    let f = Fixture::new("finaldispute").await;
    let (_, hold, _) = f.active().await;
    let (op, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(op, command).await;
    observe(&f, final_facts(&f, [105; 32]), 151).await;
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .final_refund,
        9
    );
    observe(&f, final_facts(&f, [152; 32]), 153).await;
    let state = f
        .ledger
        .intent(f.policy.domain.pair, [100; 32])
        .await
        .unwrap();
    assert_eq!(state.state, IntentStatus::Disputed);
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert!(snapshot.impaired);
    assert_eq!(
        (
            snapshot.usable_inventory,
            snapshot.final_refund,
            snapshot.buyer_unused_outstanding
        ),
        (0, 0, 9)
    );
    f.remove().await;
}
#[tokio::test]
async fn planned_change_identifiers_are_exclusive_before_any_observation() {
    let f = Fixture::new("futurechange").await;
    let facts = InventoryFacts {
        domain: f.policy.domain,
        provenance: f.policy.environment,
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
    let facts = InventoryFacts {
        domain: f.policy.domain,
        provenance: f.policy.environment,
        note: [153; 32],
        occurrence: SourceOccurrence {
            network: SOURCE_NETWORK_TESTNET,
            pool: SOURCE_POOL_IRONWOOD,
            txid: [154; 32],
            action_index: 0,
        },
        note_commitment: [155; 32],
        nullifier: [156; 32],
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
        [153; 32],
        [0; 32],
        [155; 32],
        0,
        Transition::ReserveInputs,
        &command,
    );
    f.apply(op, command).await;
    for (tag, note) in [(160_u8, [150; 32]), (170, [153; 32])] {
        let command = LedgerCommand::PrepareNative(NativePlan {
            hold: [tag; 32],
            portion: [tag + 1; 32],
            kind: NativeIntentKind::SponsorFee,
            recipient: [50; 43],
            amount: 1,
            inventory_scope: f.policy.sponsor_scope,
            inputs: vec![note],
            fee_inputs: vec![],
            change: vec![ChangeOutput {
                note: [200; 32],
                action_index: 1,
                note_commitment: [tag + 6; 32],
                nullifier: [tag + 7; 32],
                receiver: f.policy.receiver,
                value: 9,
            }],
            fee: 0,
            nonce: [tag + 2; 32],
            pczt_digest: [tag + 3; 32],
            sighash: [tag + 4; 32],
            transaction: [tag + 5; 32],
        });
        let op = f.operation(
            [tag; 32],
            [tag + 1; 32],
            [tag; 32],
            0,
            Transition::PrepareNative,
            &command,
        );
        if tag == 160 {
            f.apply(op, command).await;
        } else {
            assert_eq!(
                f.ledger.prepare_decision(op, command).await,
                Err(LedgerError::Conflict)
            );
        }
    }
    f.remove().await;
}

async fn assert_admission_cannot_take_reserved_change(
    f: &Fixture,
    credit: Id,
    operation: Operation,
    command: LedgerCommand,
) {
    let pair = f.policy.domain.pair;
    let before = f.ledger.snapshot(pair).await.unwrap();
    let credit_before = f.ledger.credit(pair, credit).await.unwrap();
    let intent_before = f.ledger.intent(pair, [100; 32]).await.unwrap();
    assert_eq!(intent_before.state, IntentStatus::Prepared);
    assert_eq!(
        (
            before.available_credit,
            before.locked_inventory,
            before.usable_inventory,
            before.seller_outstanding,
            before.buyer_unused_outstanding,
            before.final_refund,
        ),
        (0, 34, 0, 25, 9, 0)
    );
    assert_eq!(
        f.ledger.inventory_input(pair, [101; 32]).await,
        Err(LedgerError::MissingEntity)
    );
    assert_eq!(
        f.ledger.prepare_decision(operation, command.clone()).await,
        Err(LedgerError::Conflict),
        "external admission must reject the reserved change before any ACK"
    );
    assert_eq!(f.ledger.pending_decision(pair).await.unwrap(), None);
    assert_eq!(f.ledger.snapshot(pair).await.unwrap(), before);
    assert_eq!(f.ledger.credit(pair, credit).await.unwrap(), credit_before);
    assert_eq!(
        f.ledger.intent(pair, [100; 32]).await.unwrap(),
        intent_before
    );
    assert_eq!(
        f.ledger.credit(pair, [161; 32]).await,
        Err(LedgerError::MissingEntity)
    );

    // Bypass coordinator admission with the existing canonical journal forge pattern.
    let forged = forged_journal(&before, operation, &command);
    let challenge = RecoveryChallenge {
        pair,
        nonce: [200; 32],
    };
    for ((replica, key), db) in f.replicas.iter().zip(&f.keys).zip(&f.replica_dbs) {
        let state = Ledger::connect(&db.config).await.unwrap();
        let replica_before = state.snapshot(pair).await.unwrap();
        let retained_before = replica.retained_head(&challenge, key).await.unwrap();
        assert_eq!(replica_before.head, before.head);
        assert_eq!(replica_before.sequence, before.sequence);
        assert_eq!(
            replica.acknowledge(&forged, key).await,
            Err(LedgerError::Conflict),
            "each independent replica must refuse to sign the admission"
        );
        assert_eq!(
            replica.retained_head(&challenge, key).await.unwrap(),
            retained_before
        );
        assert_eq!(state.snapshot(pair).await.unwrap(), replica_before);
        assert_eq!(state.credit(pair, credit).await.unwrap(), credit_before);
        assert_eq!(state.intent(pair, [100; 32]).await.unwrap(), intent_before);
        assert_eq!(
            state.credit(pair, [161; 32]).await,
            Err(LedgerError::MissingEntity)
        );
        assert_eq!(
            state.inventory_input(pair, [101; 32]).await,
            Err(LedgerError::MissingEntity)
        );
        state.close().await;
    }

    let facts = final_facts(f, [105; 32]);
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
        [151; 32],
        f.ledger
            .entity_version(pair, [100; 32], [0; 32])
            .await
            .unwrap(),
        Transition::ObserveNative,
        &command,
    );
    let observed = f.apply(operation, command.clone()).await;
    let after = f.ledger.snapshot(pair).await.unwrap();
    assert_eq!(
        (
            after.available_credit,
            after.locked_inventory,
            after.usable_inventory,
            after.seller_outstanding,
            after.buyer_unused_outstanding,
            after.final_refund,
            after.pending_recipient,
            after.provisional_change,
            after.sponsor_inventory,
            after.impaired,
        ),
        (0, 0, 25, 25, 0, 9, 0, 0, 0, false)
    );
    assert_eq!(after.usable_inventory + after.final_refund, 34);
    assert_eq!(f.ledger.credit(pair, credit).await.unwrap(), credit_before);
    assert_eq!(
        f.ledger.credit(pair, [161; 32]).await,
        Err(LedgerError::MissingEntity)
    );
    assert_eq!(
        f.ledger.inventory_input(pair, [101; 32]).await.unwrap(),
        InventoryInput {
            note: [101; 32],
            occurrence: SourceOccurrence {
                network: SOURCE_NETWORK_TESTNET,
                pool: SOURCE_POOL_IRONWOOD,
                txid: [105; 32],
                action_index: 1,
            },
            note_commitment: [106; 32],
            nullifier: [107; 32],
            value: 25,
            scope: f.policy.inventory_scope,
        }
    );
    assert_eq!(
        f.ledger.intent(pair, [100; 32]).await.unwrap().state,
        IntentStatus::Finalized
    );
    assert_eq!(
        f.ledger.prepare_decision(operation, command).await.unwrap(),
        observed
    );
    let acknowledgements = f.acknowledge(&observed).await;
    f.ledger
        .commit_decision(&observed, &acknowledgements)
        .await
        .unwrap();
    assert_eq!(f.ledger.snapshot(pair).await.unwrap(), after);
    for db in &f.replica_dbs {
        let state = Ledger::connect(&db.config).await.unwrap();
        let replica_after = state.snapshot(pair).await.unwrap();
        assert_eq!(replica_after.head, after.head);
        assert_eq!(replica_after.sequence, after.sequence);
        assert_eq!(
            (
                replica_after.available_credit,
                replica_after.locked_inventory,
                replica_after.usable_inventory,
                replica_after.final_refund,
                replica_after.sponsor_inventory,
            ),
            (0, 0, 25, 9, 0)
        );
        assert_eq!(state.credit(pair, credit).await.unwrap(), credit_before);
        assert_eq!(
            state.credit(pair, [161; 32]).await,
            Err(LedgerError::MissingEntity)
        );
        assert_eq!(
            state.inventory_input(pair, [101; 32]).await.unwrap(),
            InventoryInput {
                note: [101; 32],
                occurrence: SourceOccurrence {
                    network: SOURCE_NETWORK_TESTNET,
                    pool: SOURCE_POOL_IRONWOOD,
                    txid: [105; 32],
                    action_index: 1,
                },
                note_commitment: [106; 32],
                nullifier: [107; 32],
                value: 25,
                scope: f.policy.inventory_scope,
            }
        );
        assert_eq!(
            state.intent(pair, [100; 32]).await.unwrap().state,
            IntentStatus::Finalized
        );
        state.close().await;
    }
}

#[tokio::test]
async fn issue_credit_cannot_admit_reserved_native_change_before_ack() {
    let f = Fixture::new("creditreservedchange").await;
    let (credit, hold, _) = f.active().await;
    let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(operation, command).await;
    let mut command = f.funding(25, 160);
    if let LedgerCommand::IssueCredit {
        claim, inventory, ..
    } = &mut command
    {
        claim.inventory_note = [101; 32];
        claim.authorization = f.claimant.sign(&claim.signing_bytes().unwrap()).to_bytes();
        inventory.facts.note = [101; 32];
        inventory.signature = f
            .inventory_key
            .sign(&inventory.facts.signing_bytes().unwrap())
            .to_bytes();
    }
    let operation = f.operation(
        [161; 32],
        [0; 32],
        [161; 32],
        0,
        Transition::IssueCredit,
        &command,
    );
    assert_admission_cannot_take_reserved_change(&f, credit, operation, command).await;
    f.remove().await;
}

#[tokio::test]
async fn register_sponsor_cannot_admit_reserved_native_change_before_ack() {
    let f = Fixture::new("sponsorreservedchange").await;
    let (credit, hold, _) = f.active().await;
    let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(operation, command).await;
    let facts = InventoryFacts {
        domain: f.policy.domain,
        provenance: f.policy.environment,
        note: [101; 32],
        occurrence: SourceOccurrence {
            network: f.policy.domain.source_network,
            pool: f.policy.domain.source_pool,
            txid: [160; 32],
            action_index: 0,
        },
        note_commitment: [161; 32],
        nullifier: [162; 32],
        receiver: f.policy.receiver,
        value: 25,
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
    let operation = f.operation(
        [101; 32],
        [0; 32],
        [162; 32],
        0,
        Transition::ReserveInputs,
        &command,
    );
    assert_admission_cannot_take_reserved_change(&f, credit, operation, command).await;
    f.remove().await;
}

#[tokio::test]
async fn final_matching_observation_cannot_downgrade_finality_or_double_count_backing() {
    let f = Fixture::new("finalmonotonic").await;
    let (_, hold, _) = f.active().await;
    let (op, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(op, command).await;
    observe(&f, final_facts(&f, [105; 32]), 151).await;
    observe(&f, final_facts(&f, [105; 32]), 152).await;
    let mut delayed = final_facts(&f, [105; 32]);
    delayed.confirmations = 0;
    observe(&f, delayed, 153).await;
    assert_eq!(
        f.ledger
            .intent(f.policy.domain.pair, [100; 32])
            .await
            .unwrap()
            .state,
        IntentStatus::Finalized
    );
    let s = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (s.usable_inventory, s.final_refund, s.pending_recipient),
        (25, 9, 0)
    );
    assert!(!s.impaired);
    f.remove().await;
}

#[tokio::test]
async fn unauthenticated_conflict_cannot_impair_and_disputed_history_cannot_auto_reset() {
    let f = Fixture::new("conflictauth").await;
    let (_, hold, _) = f.active().await;
    let (op, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(op, command).await;
    observe(&f, final_facts(&f, [105; 32]), 151).await;
    let command = LedgerCommand::ObserveNative(SignedNativeFacts {
        facts: final_facts(&f, [152; 32]),
        signature: [0; 64],
    });
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, [100; 32], [0; 32])
        .await
        .unwrap();
    let op = f.operation(
        [100; 32],
        [0; 32],
        [153; 32],
        version,
        Transition::ObserveNative,
        &command,
    );
    assert_eq!(
        f.ledger.prepare_decision(op, command).await,
        Err(LedgerError::InvalidAuthorization)
    );
    assert!(
        !f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .impaired
    );
    observe(&f, final_facts(&f, [152; 32]), 154).await;
    observe(&f, final_facts(&f, [105; 32]), 155).await;
    assert_eq!(
        f.ledger
            .intent(f.policy.domain.pair, [100; 32])
            .await
            .unwrap()
            .state,
        IntentStatus::Disputed
    );
    let s = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            s.usable_inventory,
            s.final_refund,
            s.buyer_unused_outstanding
        ),
        (0, 0, 9)
    );
    assert!(s.impaired);
    f.remove().await;
}

#[tokio::test]
async fn finalized_conflicting_subset_input_consumption_disputes_without_releasing_other_inputs() {
    let f = Fixture::new("subsetconflict").await;
    let (_, hold, _) = f.active().await;
    let facts = InventoryFacts {
        domain: f.policy.domain,
        provenance: f.policy.environment,
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
        value: 10_000,
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
    let (op, mut command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    if let LedgerCommand::PrepareNative(plan) = &mut command {
        plan.fee = 10_000;
        plan.fee_inputs = vec![[150; 32]];
    }
    f.apply(op, command).await;
    let mut conflict = final_facts(&f, [153; 32]);
    conflict.inputs = vec![[52; 32]];
    observe(&f, conflict, 154).await;
    assert_eq!(
        f.ledger
            .intent(f.policy.domain.pair, [100; 32])
            .await
            .unwrap()
            .state,
        IntentStatus::Disputed
    );
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert!(snapshot.impaired);
    assert_eq!(
        (
            snapshot.available_credit,
            snapshot.final_refund,
            snapshot.buyer_unused_outstanding,
            snapshot.usable_inventory,
            snapshot.sponsor_inventory
        ),
        (0, 0, 9, 0, 0)
    );
    assert_eq!(
        f.ledger
            .inventory_input(f.policy.domain.pair, [150; 32])
            .await
            .unwrap()
            .value,
        10_000
    );
    f.remove().await;
}

#[tokio::test]
async fn inventory_physical_identity_requires_nonzero_authenticated_fields_before_ack() {
    let f = Fixture::new("physicalauth").await;
    for case in 0..5 {
        let mut command = f.funding(34, 50);
        let LedgerCommand::IssueCredit { inventory, .. } = &mut command else {
            unreachable!()
        };
        match case {
            0 => inventory.facts.note_commitment = [200; 32],
            1 => inventory.facts.nullifier = [201; 32],
            2 => inventory.facts.note_commitment = [0; 32],
            3 => inventory.facts.nullifier = [0; 32],
            4 => {
                let mut signing = inventory.facts.signing_bytes().unwrap();
                let old_role = b"KERB_INVENTORY_PRODUCER_V1";
                signing[..32].fill(0);
                signing[..old_role.len()].copy_from_slice(old_role);
                inventory.signature = f.inventory_key.sign(&signing).to_bytes();
            }
            _ => unreachable!(),
        }
        let error = if matches!(case, 2 | 3) {
            inventory.signature = f
                .inventory_key
                .sign(&inventory.facts.signing_bytes().unwrap())
                .to_bytes();
            LedgerError::InvalidEvidence
        } else {
            LedgerError::InvalidAuthorization
        };
        let operation = f.operation(
            [51; 32],
            [0; 32],
            [51; 32],
            0,
            Transition::IssueCredit,
            &command,
        );
        assert_refused_before_ack(&f, operation, command, error).await;
    }
    let credit = f.issue(34, 50).await;
    assert_eq!(
        f.ledger
            .credit(f.policy.domain.pair, credit)
            .await
            .unwrap()
            .available,
        34
    );
    assert_eq!(
        f.ledger
            .inventory_input(f.policy.domain.pair, [52; 32])
            .await
            .unwrap(),
        InventoryInput {
            note: [52; 32],
            occurrence: SourceOccurrence {
                network: SOURCE_NETWORK_TESTNET,
                pool: SOURCE_POOL_IRONWOOD,
                txid: [50; 32],
                action_index: 0
            },
            note_commitment: [53; 32],
            nullifier: [54; 32],
            value: 34,
            scope: f.policy.inventory_scope,
        }
    );
    f.remove().await;
}

#[tokio::test]
async fn admitted_note_cannot_alias_value_scope_or_logical_id_under_either_physical_key() {
    let f = Fixture::new("physicalalias").await;
    f.issue(34, 50).await;
    for sponsor in [false, true] {
        for component in 0..3 {
            let mut command = f.funding(17, 160);
            let LedgerCommand::IssueCredit { inventory, .. } = &mut command else {
                unreachable!()
            };
            match component {
                0 => inventory.facts.note_commitment = [53; 32],
                1 => inventory.facts.nullifier = [54; 32],
                2 if sponsor => inventory.facts.occurrence.txid = [50; 32],
                2 => continue,
                _ => unreachable!(),
            }
            let (entity, transition) = if sponsor {
                inventory.facts.origin = InventoryOrigin::Sponsor;
                inventory.facts.scope = f.policy.sponsor_scope;
                ([162; 32], Transition::ReserveInputs)
            } else {
                ([161; 32], Transition::IssueCredit)
            };
            inventory.signature = f
                .inventory_key
                .sign(&inventory.facts.signing_bytes().unwrap())
                .to_bytes();
            if sponsor {
                command = LedgerCommand::RegisterSponsor {
                    inventory: inventory.clone(),
                };
            }
            let operation = f.operation(entity, [0; 32], entity, 0, transition, &command);
            assert_refused_before_ack(&f, operation, command, LedgerError::Conflict).await;
        }
    }
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.available_credit,
            snapshot.usable_inventory,
            snapshot.sponsor_inventory
        ),
        (34, 34, 0)
    );
    f.remove().await;
}

#[tokio::test]
async fn future_change_physical_identity_is_exclusive_across_admission_namespaces_before_ack() {
    for sponsor in [false, true] {
        for component in 0..3 {
            let f = Fixture::new("physicalchangealias").await;
            let (credit, hold, _) = f.active().await;
            let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
            f.apply(operation, command).await;
            let mut command = f.funding(25, 160);
            let LedgerCommand::IssueCredit {
                claim,
                source,
                inventory,
            } = &mut command
            else {
                unreachable!()
            };
            match component {
                0 => inventory.facts.note_commitment = [106; 32],
                1 => inventory.facts.nullifier = [107; 32],
                2 => {
                    let occurrence = SourceOccurrence {
                        network: SOURCE_NETWORK_TESTNET,
                        pool: SOURCE_POOL_IRONWOOD,
                        txid: [105; 32],
                        action_index: 1,
                    };
                    claim.occurrence = occurrence;
                    source.facts.occurrence = occurrence;
                    inventory.facts.occurrence = occurrence;
                    source.signature = f
                        .source_key
                        .sign(&source.facts.signing_bytes().unwrap())
                        .to_bytes();
                    claim.evidence_digest = source.facts.digest().unwrap();
                    claim.authorization =
                        f.claimant.sign(&claim.signing_bytes().unwrap()).to_bytes();
                }
                _ => unreachable!(),
            }
            let (entity, transition) = if sponsor {
                inventory.facts.origin = InventoryOrigin::Sponsor;
                inventory.facts.scope = f.policy.sponsor_scope;
                ([162; 32], Transition::ReserveInputs)
            } else {
                ([161; 32], Transition::IssueCredit)
            };
            inventory.signature = f
                .inventory_key
                .sign(&inventory.facts.signing_bytes().unwrap())
                .to_bytes();
            if sponsor {
                command = LedgerCommand::RegisterSponsor {
                    inventory: inventory.clone(),
                };
            }
            let operation = f.operation(entity, [0; 32], entity, 0, transition, &command);
            assert_admission_cannot_take_reserved_change(&f, credit, operation, command).await;
            f.remove().await;
        }
    }
}

#[tokio::test]
async fn native_change_cannot_reuse_input_identity_or_duplicate_output_identity_before_ack() {
    let f = Fixture::new("physicalplan").await;
    let (_, hold, _) = f.active().await;
    for case in 0..7 {
        let (operation, mut command) = f.refund(hold, [68; 32], [52; 32], 100).await;
        let LedgerCommand::PrepareNative(plan) = &mut command else {
            unreachable!()
        };
        match case {
            0 => plan.change[0].note_commitment = [53; 32],
            1 => plan.change[0].nullifier = [54; 32],
            2 => plan.change[0].note_commitment = [0; 32],
            3 => plan.change[0].nullifier = [0; 32],
            4..=6 => {
                plan.change[0].value = 20;
                let mut second = ChangeOutput {
                    note: [201; 32],
                    action_index: 2,
                    note_commitment: [202; 32],
                    nullifier: [203; 32],
                    receiver: f.policy.receiver,
                    value: 5,
                };
                match case {
                    4 => second.note_commitment = plan.change[0].note_commitment,
                    5 => second.nullifier = plan.change[0].nullifier,
                    6 => second.action_index = plan.change[0].action_index,
                    _ => unreachable!(),
                }
                plan.change.push(second);
            }
            _ => unreachable!(),
        }
        let error = if case < 2 {
            LedgerError::Conflict
        } else {
            LedgerError::InvalidEvidence
        };
        assert_refused_before_ack(&f, operation, command, error).await;
    }
    let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(operation, command).await;
    observe(&f, final_facts(&f, [105; 32]), 150).await;
    assert_eq!(
        f.ledger
            .intent(f.policy.domain.pair, [100; 32])
            .await
            .unwrap()
            .state,
        IntentStatus::Finalized
    );
    f.remove().await;
}

#[tokio::test]
async fn impairment_cannot_change_retained_physical_identity_amount_scope_or_origin() {
    let f = Fixture::new("physicalimpair").await;
    f.issue(34, 50).await;
    for case in 0..8 {
        let LedgerCommand::IssueCredit { inventory, .. } = f.funding(34, 50) else {
            unreachable!()
        };
        let mut facts = inventory.facts;
        facts.condition = InventoryCondition::Reorged;
        match case {
            0 => facts.note_commitment = [200; 32],
            1 => facts.nullifier = [201; 32],
            2 => facts.occurrence.txid = [202; 32],
            3 => facts.occurrence.action_index = 1,
            4 => facts.value = 17,
            5 => facts.scope = f.policy.sponsor_scope,
            6 => {
                facts.origin = InventoryOrigin::Change {
                    parent_intent: [203; 32],
                }
            }
            7 => facts.domain.source_genesis = [204; 32],
            _ => unreachable!(),
        }
        let command = LedgerCommand::ImpairInventory {
            inventory: SignedInventoryFacts {
                signature: f
                    .inventory_key
                    .sign(&facts.signing_bytes().unwrap())
                    .to_bytes(),
                facts,
            },
        };
        let operation = f.operation(
            [52; 32],
            [0; 32],
            [205; 32],
            0,
            Transition::ObserveNative,
            &command,
        );
        assert_refused_before_ack(&f, operation, command, LedgerError::InvalidEvidence).await;
    }
    let LedgerCommand::IssueCredit { inventory, .. } = f.funding(34, 50) else {
        unreachable!()
    };
    let mut facts = inventory.facts;
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
    let operation = f.operation(
        [52; 32],
        [0; 32],
        [206; 32],
        0,
        Transition::ObserveNative,
        &command,
    );
    f.apply(operation, command).await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert!(snapshot.impaired);
    assert_eq!(
        (snapshot.available_credit, snapshot.usable_inventory),
        (34, 0)
    );
    f.remove().await;
}

#[tokio::test]
async fn signed_change_identity_mismatch_disputes_without_releasing_claims_or_locks() {
    for component in 0..3 {
        let f = Fixture::new("physicaldispute").await;
        let (_, hold, _) = f.active().await;
        let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
        f.apply(operation, command).await;
        let mut facts = final_facts(&f, [105; 32]);
        match component {
            0 => facts.change[0].note_commitment = [200; 32],
            1 => facts.change[0].nullifier = [201; 32],
            2 => facts.change[0].action_index = 2,
            _ => unreachable!(),
        }
        observe(&f, facts, 150).await;
        let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
        assert!(snapshot.impaired);
        assert_eq!(
            (
                snapshot.locked_inventory,
                snapshot.usable_inventory,
                snapshot.final_refund,
                snapshot.buyer_unused_outstanding
            ),
            (34, 0, 0, 9)
        );
        assert_eq!(
            f.ledger
                .intent(f.policy.domain.pair, [100; 32])
                .await
                .unwrap()
                .state,
            IntentStatus::Disputed
        );
        assert_eq!(
            f.ledger
                .inventory_input(f.policy.domain.pair, [101; 32])
                .await,
            Err(LedgerError::MissingEntity)
        );
        let mut command = f.funding(25, 160);
        let LedgerCommand::IssueCredit { inventory, .. } = &mut command else {
            unreachable!()
        };
        inventory.facts.note_commitment = [106; 32];
        inventory.signature = f
            .inventory_key
            .sign(&inventory.facts.signing_bytes().unwrap())
            .to_bytes();
        let operation = f.operation(
            [161; 32],
            [0; 32],
            [161; 32],
            0,
            Transition::IssueCredit,
            &command,
        );
        assert_refused_before_ack(&f, operation, command, LedgerError::Conflict).await;
        observe(&f, final_facts(&f, [105; 32]), 151).await;
        assert_eq!(
            f.ledger
                .intent(f.policy.domain.pair, [100; 32])
                .await
                .unwrap()
                .state,
            IntentStatus::Disputed
        );
        f.remove().await;
    }
}

#[tokio::test]
async fn finalized_change_retains_physical_identity_for_next_send_and_prevents_consumed_resurrection()
 {
    let f = Fixture::new("physicalcontinuation").await;
    let (_, hold, _) = f.active().await;
    let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(operation, command).await;
    observe(&f, final_facts(&f, [105; 32]), 150).await;
    let mut command = f.funding(34, 160);
    let LedgerCommand::IssueCredit { inventory, .. } = &mut command else {
        unreachable!()
    };
    inventory.facts.nullifier = [54; 32];
    inventory.signature = f
        .inventory_key
        .sign(&inventory.facts.signing_bytes().unwrap())
        .to_bytes();
    let operation = f.operation(
        [161; 32],
        [0; 32],
        [161; 32],
        0,
        Transition::IssueCredit,
        &command,
    );
    assert_refused_before_ack(&f, operation, command, LedgerError::Conflict).await;
    let retained = f
        .ledger
        .inventory_input(f.policy.domain.pair, [101; 32])
        .await
        .unwrap();
    assert_eq!(retained.occurrence.txid, [105; 32]);
    assert_eq!(
        (
            retained.occurrence.action_index,
            retained.note_commitment,
            retained.nullifier
        ),
        (1, [106; 32], [107; 32])
    );
    let command = LedgerCommand::ReserveInputs {
        inputs: vec![[101; 32]],
        scope: f.policy.inventory_scope,
    };
    let operation = f.operation(
        [210; 32],
        [0; 32],
        [210; 32],
        0,
        Transition::ReserveInputs,
        &command,
    );
    f.apply(operation, command).await;
    let snapshot = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.locked_inventory,
            snapshot.usable_inventory,
            snapshot.final_refund,
            snapshot.seller_outstanding
        ),
        (25, 0, 9, 25)
    );
    f.remove().await;
}

#[tokio::test]
async fn physical_claims_exclude_cross_pair_aliases_but_not_different_source_genesis() {
    let f = Fixture::new("physicalcrosspair").await;
    let (_, hold, _) = f.active().await;
    let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(operation, command).await;
    let mut policy = f.policy.clone();
    policy.domain.pair = [220; 32];
    policy.inventory_scope = policy.domain.pair;
    f.ledger.enroll_pair(&policy).await.unwrap();
    for replica in &f.replicas {
        replica.enroll_pair(&policy).await.unwrap();
    }
    let fence = f.ledger.claim_writer(policy.domain.pair, 0).await.unwrap();
    for component in 0..4 {
        let mut command = f.funding(25, 160);
        let LedgerCommand::IssueCredit {
            claim,
            source,
            inventory,
        } = &mut command
        else {
            unreachable!()
        };
        claim.domain = policy.domain;
        source.facts.domain = policy.domain;
        inventory.facts.domain = policy.domain;
        inventory.facts.scope = policy.inventory_scope;
        match component {
            0 => inventory.facts.note_commitment = [53; 32],
            1 => inventory.facts.nullifier = [54; 32],
            2 => inventory.facts.note_commitment = [106; 32],
            3 => inventory.facts.nullifier = [107; 32],
            _ => unreachable!(),
        }
        source.signature = f
            .source_key
            .sign(&source.facts.signing_bytes().unwrap())
            .to_bytes();
        claim.evidence_digest = source.facts.digest().unwrap();
        claim.authorization = f.claimant.sign(&claim.signing_bytes().unwrap()).to_bytes();
        inventory.signature = f
            .inventory_key
            .sign(&inventory.facts.signing_bytes().unwrap())
            .to_bytes();
        let mut operation = f.operation(
            [161; 32],
            [0; 32],
            [161; 32],
            0,
            Transition::IssueCredit,
            &command,
        );
        operation.domain = policy.domain;
        operation.generation = fence.generation;
        operation.effects = command.operation_effects(&operation).unwrap();
        assert_refused_before_ack(&f, operation, command, LedgerError::Conflict).await;
    }
    policy.domain.pair = [221; 32];
    policy.domain.source_genesis = [222; 32];
    policy.inventory_scope = policy.domain.pair;
    f.ledger.enroll_pair(&policy).await.unwrap();
    for replica in &f.replicas {
        replica.enroll_pair(&policy).await.unwrap();
    }
    let fence = f.ledger.claim_writer(policy.domain.pair, 0).await.unwrap();
    let mut command = f.funding(34, 50);
    let LedgerCommand::IssueCredit {
        claim,
        source,
        inventory,
    } = &mut command
    else {
        unreachable!()
    };
    claim.domain = policy.domain;
    source.facts.domain = policy.domain;
    inventory.facts.domain = policy.domain;
    inventory.facts.scope = policy.inventory_scope;
    source.signature = f
        .source_key
        .sign(&source.facts.signing_bytes().unwrap())
        .to_bytes();
    claim.evidence_digest = source.facts.digest().unwrap();
    claim.authorization = f.claimant.sign(&claim.signing_bytes().unwrap()).to_bytes();
    inventory.signature = f
        .inventory_key
        .sign(&inventory.facts.signing_bytes().unwrap())
        .to_bytes();
    let mut operation = f.operation(
        [51; 32],
        [0; 32],
        [51; 32],
        0,
        Transition::IssueCredit,
        &command,
    );
    operation.domain = policy.domain;
    operation.generation = fence.generation;
    operation.effects = command.operation_effects(&operation).unwrap();
    let prepared = f.ledger.prepare_decision(operation, command).await.unwrap();
    let acknowledgements = f.acknowledge(&prepared).await;
    f.ledger
        .commit_decision(&prepared, &acknowledgements)
        .await
        .unwrap();
    let snapshot = f.ledger.snapshot(policy.domain.pair).await.unwrap();
    assert_eq!(
        (
            snapshot.available_credit,
            snapshot.usable_inventory,
            snapshot.sequence
        ),
        (34, 34, 1)
    );
    observe(&f, final_facts(&f, [105; 32]), 150).await;
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .final_refund,
        9
    );
    f.remove().await;
}

#[tokio::test]
async fn prepared_native_plan_identity_cannot_equivocate_before_ack() {
    let f = Fixture::new("physicalwire").await;
    let (_, hold, _) = f.active().await;
    let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    let prepared = f
        .ledger
        .prepare_decision(operation, command.clone())
        .await
        .unwrap();
    for component in 0..3 {
        let mut altered = command.clone();
        let LedgerCommand::PrepareNative(plan) = &mut altered else {
            unreachable!()
        };
        match component {
            0 => plan.change[0].note_commitment = [200; 32],
            1 => plan.change[0].nullifier = [201; 32],
            2 => plan.change[0].action_index = 2,
            _ => unreachable!(),
        }
        assert_eq!(
            f.ledger.prepare_decision(operation, altered).await,
            Err(LedgerError::Conflict)
        );
    }
    let acknowledgements = f.acknowledge(&prepared).await;
    f.ledger
        .commit_decision(&prepared, &acknowledgements)
        .await
        .unwrap();
    observe(&f, final_facts(&f, [105; 32]), 150).await;
    assert_eq!(
        f.ledger
            .snapshot(f.policy.domain.pair)
            .await
            .unwrap()
            .final_refund,
        9
    );
    f.remove().await;
}

#[tokio::test]
async fn concurrent_cross_pair_admission_reserves_one_physical_note_before_any_ack() {
    let f = Fixture::new("physicalconcurrent").await;
    let mut commands = [f.funding(34, 50), f.funding(34, 50)];
    let mut operations = [f.operation(
        [51; 32],
        [0; 32],
        [51; 32],
        0,
        Transition::IssueCredit,
        &commands[0],
    ); 2];
    let mut policies = [f.policy.clone(), f.policy.clone()];
    for index in 0..2 {
        let policy = &mut policies[index];
        policy.domain.pair = [220 + index as u8; 32];
        policy.inventory_scope = policy.domain.pair;
        f.ledger.enroll_pair(policy).await.unwrap();
        for replica in &f.replicas {
            replica.enroll_pair(policy).await.unwrap();
        }
        let fence = f.ledger.claim_writer(policy.domain.pair, 0).await.unwrap();
        let LedgerCommand::IssueCredit {
            claim,
            source,
            inventory,
        } = &mut commands[index]
        else {
            unreachable!()
        };
        claim.domain = policy.domain;
        source.facts.domain = policy.domain;
        inventory.facts.domain = policy.domain;
        inventory.facts.scope = policy.inventory_scope;
        source.signature = f
            .source_key
            .sign(&source.facts.signing_bytes().unwrap())
            .to_bytes();
        claim.evidence_digest = source.facts.digest().unwrap();
        claim.authorization = f.claimant.sign(&claim.signing_bytes().unwrap()).to_bytes();
        inventory.signature = f
            .inventory_key
            .sign(&inventory.facts.signing_bytes().unwrap())
            .to_bytes();
        operations[index].domain = policy.domain;
        operations[index].generation = fence.generation;
        operations[index].effects = commands[index]
            .operation_effects(&operations[index])
            .unwrap();
    }
    let (first, second) = tokio::join!(
        f.ledger
            .prepare_decision(operations[0], commands[0].clone()),
        f.ledger
            .prepare_decision(operations[1], commands[1].clone())
    );
    assert!(matches!(
        (&first, &second),
        (Ok(_), Err(_)) | (Err(_), Ok(_))
    ));
    let (winner, loser) = if first.is_ok() { (0, 1) } else { (1, 0) };
    let prepared = first.or(second).unwrap();
    let acknowledgements = f.acknowledge(&prepared).await;
    f.ledger
        .commit_decision(&prepared, &acknowledgements)
        .await
        .unwrap();
    let snapshot = f
        .ledger
        .snapshot(policies[winner].domain.pair)
        .await
        .unwrap();
    assert_eq!(
        (
            snapshot.available_credit,
            snapshot.usable_inventory,
            snapshot.sequence
        ),
        (34, 34, 1)
    );
    let snapshot = f
        .ledger
        .snapshot(policies[loser].domain.pair)
        .await
        .unwrap();
    assert_eq!(
        (
            snapshot.available_credit,
            snapshot.usable_inventory,
            snapshot.sequence
        ),
        (0, 0, 0)
    );
    assert_refused_before_ack(
        &f,
        operations[loser],
        commands[loser].clone(),
        LedgerError::DuplicateOccurrence,
    )
    .await;
    f.remove().await;
}

async fn retained_native_claim_rows(db: &TestDatabase) -> Vec<String> {
    let mut connection = db.connection().await;
    sqlx::query_scalar::<_, String>(
        "SELECT 'claim:' || row_to_json(c)::text FROM ledger_physical_claims c
         UNION ALL SELECT 'reservation:' || row_to_json(r)::text FROM ledger_change_reservations r
         UNION ALL SELECT 'inventory:' || row_to_json(i)::text FROM ledger_inventory i
         UNION ALL SELECT 'consumption:' || row_to_json(c)::text FROM ledger_consumptions c
         ORDER BY 1",
    )
    .fetch_all(&mut connection)
    .await
    .unwrap()
}

async fn enroll_native_sponsor(f: &Fixture) -> InventoryFacts {
    let facts = InventoryFacts {
        domain: f.policy.domain,
        provenance: f.policy.environment,
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
        value: 10_000,
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
            facts: facts.clone(),
        },
    };
    let operation = f.operation(
        [150; 32],
        [0; 32],
        [152; 32],
        0,
        Transition::ReserveInputs,
        &command,
    );
    f.apply(operation, command).await;
    facts
}

async fn assert_native_facts_refused(f: &Fixture, facts: NativeFacts, authenticated: bool) {
    let pair = f.policy.domain.pair;
    let before_intent = f.ledger.intent(pair, [100; 32]).await.unwrap();
    let databases: Vec<_> = std::iter::once(&f.db).chain(&f.replica_dbs).collect();
    let mut before_rows = Vec::new();
    for db in &databases {
        before_rows.push(retained_native_claim_rows(db).await);
    }
    let signature = if authenticated {
        f.inventory_key
            .sign(&facts.signing_bytes().unwrap())
            .to_bytes()
    } else {
        [0; 64]
    };
    let command = LedgerCommand::ObserveNative(SignedNativeFacts { facts, signature });
    let version = f
        .ledger
        .entity_version(pair, [100; 32], [0; 32])
        .await
        .unwrap();
    let operation = f.operation(
        [100; 32],
        [0; 32],
        [210; 32],
        version,
        Transition::ObserveNative,
        &command,
    );
    let error = if authenticated {
        LedgerError::InvalidEvidence
    } else {
        LedgerError::InvalidAuthorization
    };
    assert_refused_before_ack(f, operation, command, error).await;
    for (db, rows) in databases.iter().zip(before_rows) {
        assert_eq!(retained_native_claim_rows(db).await, rows);
        let state = Ledger::connect(&db.config).await.unwrap();
        assert_eq!(state.intent(pair, [100; 32]).await.unwrap(), before_intent);
        state.close().await;
    }
}

#[tokio::test]
async fn different_final_transaction_with_reserved_and_unknown_inputs_disputes_and_retains_claims()
{
    for sponsor in [false, true] {
        let f = Fixture::new("overlapunknown").await;
        let (_, hold, _) = f.active().await;
        if sponsor {
            enroll_native_sponsor(&f).await;
        }
        let (operation, mut command) = f.refund(hold, [68; 32], [52; 32], 100).await;
        if sponsor {
            let LedgerCommand::PrepareNative(plan) = &mut command else {
                unreachable!()
            };
            plan.fee = 10_000;
            plan.fee_inputs = vec![[150; 32]];
        }
        f.apply(operation, command).await;
        let databases: Vec<_> = std::iter::once(&f.db).chain(&f.replica_dbs).collect();
        let mut before_rows = Vec::new();
        for db in &databases {
            before_rows.push(retained_native_claim_rows(db).await);
        }
        let mut conflict = final_facts(&f, [200; 32]);
        conflict.inputs = vec![[52; 32], [201; 32]];
        conflict.change[0].note = [202; 32];
        conflict.change[0].note_commitment = [203; 32];
        conflict.change[0].nullifier = [204; 32];
        observe(&f, conflict, 205).await;
        let pair = f.policy.domain.pair;
        let snapshot = f.ledger.snapshot(pair).await.unwrap();
        assert!(snapshot.impaired);
        assert_eq!(
            (
                snapshot.locked_inventory,
                snapshot.usable_inventory,
                snapshot.sponsor_inventory,
                snapshot.final_refund,
                snapshot.buyer_unused_outstanding
            ),
            (34, 0, 0, 0, 9)
        );
        for (db, rows) in databases.iter().zip(before_rows) {
            assert_eq!(retained_native_claim_rows(db).await, rows);
            let state = Ledger::connect(&db.config).await.unwrap();
            assert_eq!(state.snapshot(pair).await.unwrap(), snapshot);
            let intent = state.intent(pair, [100; 32]).await.unwrap();
            assert_eq!(intent.state, IntentStatus::Disputed);
            assert_eq!(intent.transaction, [105; 32]);
            assert_eq!(intent.nonce, [102; 32]);
            for note in [[101; 32], [201; 32], [202; 32]] {
                assert_eq!(
                    state.inventory_input(pair, note).await,
                    Err(LedgerError::MissingEntity)
                );
            }
            if sponsor {
                let retained = state.inventory_input(pair, [150; 32]).await.unwrap();
                assert_eq!(retained.value, 10_000);
                assert_eq!(retained.scope, f.policy.sponsor_scope);
            }
            state.close().await;
        }
        f.remove().await;
    }
}

#[tokio::test]
async fn wholly_unrelated_final_transaction_is_rejected_before_ack_without_impairment() {
    let f = Fixture::new("unrelatednative").await;
    let (_, hold, _) = f.active().await;
    let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(operation, command).await;
    let mut facts = final_facts(&f, [200; 32]);
    facts.inputs = vec![[201; 32], [202; 32]];
    assert_native_facts_refused(&f, facts, true).await;
    f.remove().await;
}

#[tokio::test]
async fn same_transaction_requires_exact_full_inputs_before_ack() {
    let f = Fixture::new("exactnativeinputs").await;
    let (_, hold, _) = f.active().await;
    enroll_native_sponsor(&f).await;
    let (operation, mut command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    let LedgerCommand::PrepareNative(plan) = &mut command else {
        unreachable!()
    };
    plan.fee = 10_000;
    plan.fee_inputs = vec![[150; 32]];
    f.apply(operation, command).await;
    for inputs in [
        vec![[52; 32], [150; 32], [201; 32]],
        vec![[52; 32]],
        vec![[150; 32], [52; 32]],
    ] {
        let mut facts = final_facts(&f, [105; 32]);
        facts.inputs = inputs;
        assert_native_facts_refused(&f, facts, true).await;
    }
    let mut facts = final_facts(&f, [105; 32]);
    facts.inputs = vec![[52; 32], [150; 32]];
    observe(&f, facts, 211).await;
    assert_eq!(
        f.ledger
            .intent(f.policy.domain.pair, [100; 32])
            .await
            .unwrap()
            .state,
        IntentStatus::Finalized
    );
    f.remove().await;
}

#[tokio::test]
async fn conflicting_overlap_still_requires_distinct_final_authenticated_context_before_ack() {
    let f = Fixture::new("overlapvalidation").await;
    let (_, hold, _) = f.active().await;
    let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
    f.apply(operation, command).await;
    for case in 0..9 {
        let mut facts = final_facts(&f, [200; 32]);
        facts.inputs = vec![[52; 32], [201; 32]];
        match case {
            0 => facts.inputs = vec![[52; 32], [201; 32], [201; 32]],
            1 => facts.inputs.clear(),
            2 => facts.transaction = [0; 32],
            3 => facts.confirmations = f.policy.minimum_confirmations - 1,
            4 => facts.domain.source_genesis = [202; 32],
            5 => facts.provenance = ObservationEnvironment::Network,
            6 => facts.history_anchor = [203; 32],
            7 => facts.block = [0; 32],
            8 => {}
            _ => unreachable!(),
        }
        assert_native_facts_refused(&f, facts, case != 8).await;
    }
    f.remove().await;
}

#[tokio::test]
async fn authenticated_sponsor_impairment_quarantines_fee_inventory_and_preserves_native_locks() {
    for condition in [InventoryCondition::Reorged, InventoryCondition::Unknown] {
        let f = Fixture::new("sponsorimpair").await;
        let (_, hold, _) = f.active().await;
        let original = enroll_native_sponsor(&f).await;
        let (operation, command) = f.refund(hold, [68; 32], [52; 32], 100).await;
        f.apply(operation, command).await;
        let pair = f.policy.domain.pair;
        let databases: Vec<_> = std::iter::once(&f.db).chain(&f.replica_dbs).collect();
        let before_intent = f.ledger.intent(pair, [100; 32]).await.unwrap();
        let before_sponsor = f.ledger.inventory_input(pair, original.note).await.unwrap();
        let mut before_rows = Vec::new();
        for db in &databases {
            before_rows.push(retained_native_claim_rows(db).await);
        }
        for case in 0..7 {
            let mut facts = original.clone();
            facts.condition = condition;
            match case {
                0 => facts.scope = [200; 32],
                1 => facts.origin = InventoryOrigin::Deposit,
                2 => facts.note_commitment = [201; 32],
                3 => facts.nullifier = [202; 32],
                4 => facts.occurrence.txid = [203; 32],
                5 => facts.scope = f.policy.inventory_scope,
                6 => facts.condition = InventoryCondition::Spendable,
                _ => unreachable!(),
            }
            let command = LedgerCommand::ImpairInventory {
                inventory: SignedInventoryFacts {
                    signature: f
                        .inventory_key
                        .sign(&facts.signing_bytes().unwrap())
                        .to_bytes(),
                    facts,
                },
            };
            let operation = f.operation(
                original.note,
                [0; 32],
                [204; 32],
                0,
                Transition::ObserveNative,
                &command,
            );
            assert_refused_before_ack(&f, operation, command, LedgerError::InvalidEvidence).await;
            for (db, rows) in databases.iter().zip(&before_rows) {
                assert_eq!(&retained_native_claim_rows(db).await, rows);
            }
        }
        let mut facts = original.clone();
        facts.condition = condition;
        let command = LedgerCommand::ImpairInventory {
            inventory: SignedInventoryFacts {
                signature: f
                    .inventory_key
                    .sign(&facts.signing_bytes().unwrap())
                    .to_bytes(),
                facts,
            },
        };
        let operation = f.operation(
            original.note,
            [0; 32],
            [205; 32],
            0,
            Transition::ObserveNative,
            &command,
        );
        f.apply(operation, command).await;
        let snapshot = f.ledger.snapshot(pair).await.unwrap();
        assert!(snapshot.impaired);
        assert_eq!(
            (
                snapshot.locked_inventory,
                snapshot.sponsor_inventory,
                snapshot.available_credit,
                snapshot.final_refund,
                snapshot.buyer_unused_outstanding
            ),
            (34, 0, 0, 0, 9)
        );
        for (db, rows) in databases.iter().zip(before_rows) {
            let state = Ledger::connect(&db.config).await.unwrap();
            assert_eq!(state.snapshot(pair).await.unwrap(), snapshot);
            assert_eq!(state.intent(pair, [100; 32]).await.unwrap(), before_intent);
            assert_eq!(
                state.inventory_input(pair, original.note).await.unwrap(),
                before_sponsor
            );
            state.close().await;
            let mut connection = db.connection().await;
            let locks = sqlx::query_as::<_, (Vec<u8>, i16, Option<Vec<u8>>)>(
                "SELECT note,status,live_intent FROM ledger_inventory ORDER BY note",
            )
            .fetch_all(&mut connection)
            .await
            .unwrap();
            assert_eq!(
                locks,
                vec![
                    (vec![52; 32], 2, Some(vec![100; 32])),
                    (vec![150; 32], 5, None)
                ]
            );
            let after_rows = retained_native_claim_rows(db).await;
            let before_without_sponsor: Vec<_> = rows
                .iter()
                .filter(|row| !row.starts_with("inventory:"))
                .collect();
            let after_without_sponsor: Vec<_> = after_rows
                .iter()
                .filter(|row| !row.starts_with("inventory:"))
                .collect();
            assert_eq!(after_without_sponsor, before_without_sponsor);
        }
        let command = LedgerCommand::PrepareNative(NativePlan {
            hold: [210; 32],
            portion: [211; 32],
            kind: NativeIntentKind::SponsorFee,
            recipient: [50; 43],
            amount: 10_000,
            inventory_scope: f.policy.sponsor_scope,
            inputs: vec![original.note],
            fee_inputs: vec![],
            change: vec![],
            fee: 0,
            nonce: [212; 32],
            pczt_digest: [213; 32],
            sighash: [214; 32],
            transaction: [215; 32],
        });
        let operation = f.operation(
            [210; 32],
            [211; 32],
            [216; 32],
            0,
            Transition::PrepareNative,
            &command,
        );
        assert_refused_before_ack(&f, operation, command, LedgerError::InventoryImpaired).await;
        f.remove().await;
    }
}
