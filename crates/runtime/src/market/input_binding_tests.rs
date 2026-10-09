use crate::market::{
    Error,
    coordinator::Coordinator,
    facts,
    fixture::FixtureNative,
    native::{self, NativePolicy},
    process::ReplicaProcess,
};
use ed25519_dalek::Signer;
use crate::market::ledger::*;
use ziquid_protocol::market::*;

use crate::market_ledger_test_support as ledger_support;
#[path = "../../tests/market_support/runtime.rs"]
mod runtime_support;

async fn fixture(receiver: [u8; 43]) -> ledger_support::Fixture {
    use ledger_support::{Fixture, TestDatabase};
    let db = TestDatabase::create("inputroles").await;
    let ledger = Ledger::connect(&db.config).await.unwrap();
    ledger.migrate().await.unwrap();
    let keys = [
        facts::key().unwrap(),
        facts::key().unwrap(),
        facts::key().unwrap(),
    ];
    let source_key = facts::key().unwrap();
    let inventory_key = facts::key().unwrap();
    let target_key = facts::key().unwrap();
    let claimant = facts::key().unwrap();
    let domain = ledger_support::domain();
    let policy = PairPolicy {
        domain,
        environment: ObservationEnvironment::LocalFixture,
        source_policy: [20; 32],
        history_anchor: [21; 32],
        minimum_confirmations: 10,
        receiver,
        inventory_scope: domain.pair,
        sponsor_scope: [24; 32],
        source_producer: source_key.verifying_key().to_bytes(),
        inventory_producer: inventory_key.verifying_key().to_bytes(),
        target_observer: target_key.verifying_key().to_bytes(),
        target_admin: [25; 32],
        roster: keys.each_ref().map(|key| key.verifying_key().to_bytes()),
    };
    ledger.enroll_pair(&policy).await.unwrap();
    let fence = ledger.claim_writer(domain.pair, 0).await.unwrap();
    let replica_dbs = [
        TestDatabase::create("replica").await,
        TestDatabase::create("replica").await,
        TestDatabase::create("replica").await,
    ];
    let replicas = [
        Replica::connect(&replica_dbs[0].config)
            .await
            .unwrap(),
        Replica::connect(&replica_dbs[1].config)
            .await
            .unwrap(),
        Replica::connect(&replica_dbs[2].config)
            .await
            .unwrap(),
    ];
    for replica in &replicas {
        replica.migrate().await.unwrap();
        replica.enroll_pair(&policy).await.unwrap();
    }
    Fixture {
        db,
        ledger,
        policy,
        fence,
        keys,
        source_key,
        inventory_key,
        target_key,
        claimant,
        replica_dbs,
        replicas,
    }
}

async fn released(
    f: &ledger_support::Fixture,
    input: &ziquid_zcash::custody::ReservedNativeInput,
    native_recipient: [u8; 43],
    refund_recipient: [u8; 43],
) -> (Id, Id) {
    let credit = [51; 32];
    let command = facts::funding(
        &f.policy,
        (&f.source_key, &f.inventory_key),
        &f.claimant,
        input,
        credit,
    )
    .unwrap();
    f.apply(
        f.operation(
            credit,
            [0; 32],
            credit,
            0,
            Transition::IssueCredit,
            &command,
        ),
        command,
    )
    .await;
    let hold = [60; 32];
    let portion = [65; 32];
    let mut command = LedgerCommand::PrepareHold {
        credit,
        amount: 34,
        refund_receiver: refund_recipient,
        target: f.target_binding(hold),
        authorization: [0; 64],
    };
    let operation = f.operation(hold, [0; 32], hold, 0, Transition::PrepareHold, &command);
    if let LedgerCommand::PrepareHold { authorization, .. } = &mut command {
        *authorization = f
            .claimant
            .sign(&operation.signing_bytes(SignatureRole::Application).unwrap())
            .to_bytes();
    }
    f.apply(operation, command).await;
    f.accepted(hold).await;
    let mut allocation = AllocationPlan {
        hold,
        allocation: [64; 32],
        portions: vec![
            PortionSpec {
                portion,
                offset: 0,
                amount: 25,
                kind: AllocationKind::SellerLiability,
                native_recipient,
                spl_recipient: [67; 32],
                target_base_offset: 0,
                target_base_amount: 5,
                fill_fence: [72; 32],
            },
            PortionSpec {
                portion: [68; 32],
                offset: 25,
                amount: 9,
                kind: AllocationKind::BuyerUnused,
                native_recipient: refund_recipient,
                spl_recipient: [28; 32],
                target_base_offset: 5,
                target_base_amount: 2,
                fill_fence: [0; 32],
            },
        ],
        chunks: vec![],
    };
    for p in &allocation.portions {
        let mut payload = p.portion.to_vec();
        payload.extend_from_slice(&p.target_base_offset.to_le_bytes());
        payload.extend_from_slice(&p.target_base_amount.to_le_bytes());
        payload.push(p.kind as u8);
        payload.extend_from_slice(&allocation.allocation);
        allocation.chunks.push(
            f.authorization(
                (hold, p.portion),
                Transition::RecordAllocation,
                2,
                [70; 32],
                payload,
                [0; 32],
            )
            .decision
            .operation
            .effects,
        );
    }
    let command = LedgerCommand::PrepareAllocation(allocation.clone());
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, [0; 32])
        .await
        .unwrap();
    f.apply(
        f.operation(
            hold,
            [0; 32],
            [69; 32],
            version,
            Transition::RecordAllocation,
            &command,
        ),
        command,
    )
    .await;
    f.chunk(&allocation, 0, 0).await;
    f.chunk(&allocation, 1, 0).await;
    f.activate(&allocation, 0).await;
    let prepared = f
        .authorize(
            (hold, portion),
            Transition::PrepareFill,
            1,
            [95; 32],
            ziquid_solana_interface::PrepareFillEffects {
                amount: 5,
                journal: [73; 32],
                fence: [72; 32],
            }
            .encode()
            .to_vec(),
            [96; 32],
        )
        .await;
    let entity = prepared.facts.decision.operation.id().unwrap();
    let command = LedgerCommand::ObserveTarget(prepared);
    f.apply(
        f.operation(
            entity,
            [0; 32],
            [97; 32],
            0,
            Transition::ObserveNative,
            &command,
        ),
        command,
    )
    .await;
    let target = f
        .authorize(
            (hold, portion),
            Transition::ReleaseSpl,
            2,
            [95; 32],
            ziquid_solana_interface::ReleaseEffects {
                amount: 5,
                result: [64; 32],
                fence: [72; 32],
            }
            .encode()
            .to_vec(),
            [98; 32],
        )
        .await;
    let command = LedgerCommand::ObserveSplRelease {
        hold,
        portion,
        recipient: [67; 32],
        target_base_amount: 5,
        target,
    };
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, portion)
        .await
        .unwrap();
    f.apply(
        f.operation(
            hold,
            portion,
            [99; 32],
            version,
            Transition::ReleaseSpl,
            &command,
        ),
        command,
    )
    .await;
    (hold, portion)
}

fn checked_change(checked: &ziquid_zcash::custody::UnsignedNativeInspection<'_>, note: Id) -> ChangeOutput {
    let expected_change = checked
        .expected_outputs()
        .iter()
        .find(|output| output.kind == ziquid_zcash::custody::NativeOutputKind::Change)
        .unwrap();
    let mut changes = checked.outputs().iter().filter(|output| {
        output.recipient() == &expected_change.recipient && output.value() == expected_change.value
    });
    let change = changes.next().unwrap();
    assert!(changes.next().is_none());
    ChangeOutput {
        note,
        receiver: change.recipient().to_raw_address_bytes(),
        value: change.value(),
        action_index: change.action_index(),
        note_commitment: *change.note_commitment(),
        nullifier: *change.nullifier().unwrap(),
    }
}
async fn coordinator(f: &ledger_support::Fixture, files: &runtime_support::Files) -> Coordinator {
    let mut processes = Vec::new();
    let executable = runtime_support::binary();
    for i in 0..3 {
        let path = files.json(
            &format!("replica{i}.json"),
            &serde_json::json!({"schema_version":1,"database": &f.replica_dbs[i].config,
                "policy":f.policy.canonical_bytes().unwrap(),
                "expected_signer":f.policy.roster[i]}),
        );
        processes.push(
            ReplicaProcess::launch(&executable, &path, &f.keys[i], &f.policy)
                .await
                .unwrap(),
        );
    }
    Coordinator {
        ledger: f.ledger.clone(),
        policy: f.policy.clone(),
        replicas: processes,
    }
}

async fn retained_heads(coordinator: &mut Coordinator) -> Vec<RetainedHead> {
    let challenge = coordinator
        .ledger
        .begin_reconciliation(coordinator.policy.domain.pair)
        .await
        .unwrap();
    let mut heads = Vec::new();
    for replica in &mut coordinator.replicas {
        heads.push(replica.retained(&challenge).await.unwrap());
    }
    coordinator
        .ledger
        .reconcile_heads(&challenge, &heads)
        .await
        .unwrap();
    heads
}

fn assert_same_heads(before: &[RetainedHead], after: &[RetainedHead]) {
    assert_eq!(before.len(), 3);
    assert_eq!(after.len(), 3);
    for (before, after) in before.iter().zip(after) {
        assert!(after.domain == before.domain);
        assert!(after.pair == before.pair);
        assert!(after.signer == before.signer);
        assert!(after.head == before.head);
        assert!(after.target_head == before.target_head);
        assert_eq!(after.sequence, before.sequence);
        assert_eq!(after.generation, before.generation);
    }
}

async fn reservations(f: &ledger_support::Fixture) -> (i64, i64, i64, i64, i64, i64, i64) {
    use sqlx::Connection;
    let mut sql = f.db.connection().await;
    let result = sqlx::query_as("SELECT \
        (SELECT count(*) FROM ledger_inventory WHERE pair=$1 AND (status=2 OR live_intent IS NOT NULL)), \
        (SELECT count(*) FROM ledger_versions WHERE pair=$1 AND reservation IS NOT NULL), \
        (SELECT count(*) FROM ledger_portions WHERE pair=$1 AND live_intent IS NOT NULL), \
        (SELECT count(*) FROM ledger_intent_records WHERE pair=$1), \
        (SELECT count(*) FROM ledger_nonce_tombstones WHERE pair=$1), \
        (SELECT count(*) FROM ledger_change_reservations WHERE pair=$1), \
        (SELECT count(*) FROM ledger_physical_claims WHERE pair=$1)")
        .bind(f.policy.domain.pair.as_slice())
        .fetch_one(&mut sql)
        .await
        .unwrap();
    sql.close().await.unwrap();
    result
}

async fn sponsor(
    f: &ledger_support::Fixture,
    input: &ziquid_zcash::custody::ReservedNativeInput,
    intent: Id,
) {
    let inventory = facts::inventory(
        &f.policy,
        &f.inventory_key,
        input,
        InventoryOrigin::Sponsor,
        f.policy.sponsor_scope,
    )
    .unwrap();
    let command = LedgerCommand::RegisterSponsor { inventory };
    f.apply(
        f.operation(
            input.inventory_note,
            [0; 32],
            intent,
            0,
            Transition::ReserveInputs,
            &command,
        ),
        command,
    )
    .await;
}

#[tokio::test]
async fn inspected_native_user_and_sponsor_values_match_retained_roles_before_any_ack_or_reservation()
 {
    let root = runtime_support::fixture_dir();
    let context = crate::market::config::read::<NativePolicy>(&root.join("policy.json"))
        .unwrap()
        .context()
        .unwrap();
    let recipient = context
        .outputs
        .iter()
        .find(|output| output.kind == ziquid_zcash::custody::NativeOutputKind::Recipient)
        .unwrap()
        .recipient;
    let change = context
        .outputs
        .iter()
        .find(|output| output.kind == ziquid_zcash::custody::NativeOutputKind::Change)
        .unwrap()
        .recipient;
    let f = fixture(change.to_raw_address_bytes()).await;
    let sponsor = [150; 32];
    let mut pczt = FixtureNative::payout(
        f.policy.domain,
        context.inputs[0].trusted_fvk.clone(),
        recipient,
        change,
    )
    .unwrap();
    pczt.context.inputs[0].inventory_note = [52; 32];
    pczt.context.inputs[1].inventory_note = sponsor;
    let (hold, portion) = released(
        &f,
        &pczt.context.inputs[0],
        recipient.to_raw_address_bytes(),
        change.to_raw_address_bytes(),
    )
    .await;
    let inventory = facts::inventory(
        &f.policy,
        &f.inventory_key,
        &pczt.context.inputs[1],
        InventoryOrigin::Sponsor,
        f.policy.sponsor_scope,
    )
    .unwrap();
    let command = LedgerCommand::RegisterSponsor { inventory };
    f.apply(
        f.operation(
            sponsor,
            [0; 32],
            [152; 32],
            0,
            Transition::ReserveInputs,
            &command,
        ),
        command,
    )
    .await;
    let checked = ziquid_zcash::custody::inspect_pczt(&pczt.bytes, &pczt.context.expected()).unwrap();
    let plan = NativePlan {
        hold,
        portion,
        kind: NativeIntentKind::SellerPayout,
        recipient: recipient.to_raw_address_bytes(),
        amount: 25,
        inventory_scope: f.policy.inventory_scope,
        inputs: vec![[52; 32]],
        fee_inputs: vec![sponsor],
        change: vec![checked_change(&checked, [153; 32])],
        fee: 10_000,
        nonce: [154; 32],
        pczt_digest: *checked.exact_pczt_digest(),
        sighash: *checked.shielded_sighash(),
        transaction: *checked.txid(),
    };
    let mut wrong_context = native::NativeContext {
        domain: pczt.context.domain,
        environment: pczt.context.environment,
        lock_time: pczt.context.lock_time,
        expiry_height: pczt.context.expiry_height,
        fee: pczt.context.fee,
        inputs: pczt.context.inputs.clone(),
        outputs: pczt.context.outputs.clone(),
    };
    wrong_context.inputs[0].inventory_note = sponsor;
    wrong_context.inputs[1].inventory_note = [52; 32];
    let wrong_checked = ziquid_zcash::custody::inspect_pczt(&pczt.bytes, &wrong_context.expected()).unwrap();
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, portion)
        .await
        .unwrap();
    let command = LedgerCommand::PrepareNative(plan.clone());
    let operation = f.operation(
        hold,
        portion,
        [155; 32],
        version,
        Transition::PrepareNative,
        &command,
    );
    native::bind_plan(&operation, &plan, &wrong_checked).unwrap();
    let files = runtime_support::Files::new();
    let mut coordinator = coordinator(&f, &files).await;
    let before = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let result = coordinator
        .prepare_native(operation, plan.clone(), &wrong_checked)
        .await;
    let after = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let pending = f
        .ledger
        .pending_decision(f.policy.domain.pair)
        .await
        .unwrap();
    let challenge = f
        .ledger
        .begin_reconciliation(f.policy.domain.pair)
        .await
        .unwrap();
    let mut heads = Vec::new();
    for replica in &mut coordinator.replicas {
        heads.push(replica.retained(&challenge).await.unwrap());
    }
    let no_export = heads
        .iter()
        .all(|head| head.head == before.head && head.sequence == before.sequence);
    let no_intent = f
        .ledger
        .native_plan(f.policy.domain.pair, operation.intent)
        .await
        == Err(LedgerError::MissingEntity);
    f.ledger.reconcile_heads(&challenge, &heads).await.unwrap();
    let accepted = coordinator
        .prepare_native(operation, plan.clone(), &checked)
        .await;
    let correct_stored = f
        .ledger
        .native_plan(f.policy.domain.pair, operation.intent)
        .await;
    coordinator.shutdown().await.unwrap();
    f.remove().await;
    assert!(
        matches!(result, Err(Error::NativePlanMismatch)),
        "swapped actual34/10000 native input role values must reject before prepare/ACK"
    );
    assert_eq!(after, before);
    assert!(pending.is_none());
    assert!(no_export);
    assert!(no_intent);
    assert!(accepted.is_ok());
    assert!(correct_stored == Ok(plan));
}

#[tokio::test]
async fn equal_value_distinct_native_note_cannot_reuse_authenticated_inventory_label_before_ack() {
    let root = runtime_support::fixture_dir();
    let context = crate::market::config::read::<NativePolicy>(&root.join("policy.json"))
        .unwrap()
        .context()
        .unwrap();
    let recipient = context
        .outputs
        .iter()
        .find(|output| output.kind == ziquid_zcash::custody::NativeOutputKind::Recipient)
        .unwrap()
        .recipient;
    let change = context
        .outputs
        .iter()
        .find(|output| output.kind == ziquid_zcash::custody::NativeOutputKind::Change)
        .unwrap()
        .recipient;
    let f = fixture(change.to_raw_address_bytes()).await;
    let user = [52; 32];
    let sponsor = [150; 32];
    let mut a = FixtureNative::payout(
        f.policy.domain,
        context.inputs[0].trusted_fvk.clone(),
        recipient,
        change,
    )
    .unwrap();
    let mut b = FixtureNative::payout(
        f.policy.domain,
        context.inputs[0].trusted_fvk.clone(),
        recipient,
        change,
    )
    .unwrap();
    a.context.inputs[0].inventory_note = user;
    a.context.inputs[1].inventory_note = sponsor;
    // Enroll A's genuine physical identities under U/S before presenting B.
    let inventory_a = a.context.inputs.clone();
    b.context.inputs[0].inventory_note = user;
    b.context.inputs[1].inventory_note = sponsor;
    for ((input_a, input_b), (label, value)) in inventory_a
        .iter()
        .zip(&b.context.inputs)
        .zip([(user, 34), (sponsor, 10_000)])
    {
        assert!(input_a.inventory_note == label);
        assert!(input_b.inventory_note == label);
        assert_eq!(input_a.value, value);
        assert_eq!(input_b.value, value);
        assert!(input_a.trusted_fvk == input_b.trusted_fvk);
        assert!(input_a.note_commitment != input_b.note_commitment);
        assert!(input_a.nullifier != input_b.nullifier);
    }
    let checked_a = ziquid_zcash::custody::inspect_pczt(&a.bytes, &a.context.expected()).unwrap();
    // Only B's business labels were changed. Its independently generated native
    // bytes, commitments, nullifiers, values and public FVK remain B's exact ones.
    let checked_b = ziquid_zcash::custody::inspect_pczt(&b.bytes, &b.context.expected()).unwrap();
    let (hold, portion) = released(
        &f,
        &inventory_a[0],
        recipient.to_raw_address_bytes(),
        change.to_raw_address_bytes(),
    )
    .await;
    let inventory = facts::inventory(
        &f.policy,
        &f.inventory_key,
        &inventory_a[1],
        InventoryOrigin::Sponsor,
        f.policy.sponsor_scope,
    )
    .unwrap();
    let command = LedgerCommand::RegisterSponsor { inventory };
    f.apply(
        f.operation(
            sponsor,
            [0; 32],
            [152; 32],
            0,
            Transition::ReserveInputs,
            &command,
        ),
        command,
    )
    .await;
    for (input_a, scope) in inventory_a
        .iter()
        .zip([f.policy.inventory_scope, f.policy.sponsor_scope])
    {
        assert!(
            f.ledger
                .inventory_input(f.policy.domain.pair, input_a.inventory_note)
                .await
                .unwrap()
                == InventoryInput {
                    note: input_a.inventory_note,
                    occurrence: input_a.source_occurrence,
                    note_commitment: input_a.note_commitment,
                    nullifier: input_a.nullifier,
                    value: input_a.value,
                    scope,
                }
        );
    }
    let plan = NativePlan {
        hold,
        portion,
        kind: NativeIntentKind::SellerPayout,
        recipient: recipient.to_raw_address_bytes(),
        amount: 25,
        inventory_scope: f.policy.inventory_scope,
        inputs: vec![user],
        fee_inputs: vec![sponsor],
        change: vec![checked_change(&checked_b, [153; 32])],
        fee: 10_000,
        nonce: [154; 32],
        pczt_digest: *checked_b.exact_pczt_digest(),
        sighash: *checked_b.shielded_sighash(),
        transaction: *checked_b.txid(),
    };
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, portion)
        .await
        .unwrap();
    let command = LedgerCommand::PrepareNative(plan.clone());
    let operation = f.operation(
        hold,
        portion,
        [155; 32],
        version,
        Transition::PrepareNative,
        &command,
    );
    native::bind_plan(&operation, &plan, &checked_b).unwrap();
    let files = runtime_support::Files::new();
    let mut coordinator = coordinator(&f, &files).await;
    let before_heads = retained_heads(&mut coordinator).await;
    let before = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let before_reservations = reservations(&f).await;
    let mut correct_plan = plan.clone();
    correct_plan.change = vec![checked_change(&checked_a, [153; 32])];
    correct_plan.pczt_digest = *checked_a.exact_pczt_digest();
    correct_plan.sighash = *checked_a.shielded_sighash();
    correct_plan.transaction = *checked_a.txid();
    let correct_command = LedgerCommand::PrepareNative(correct_plan.clone());
    let correct_operation = f.operation(
        hold,
        portion,
        operation.intent,
        version,
        Transition::PrepareNative,
        &correct_command,
    );
    let result = coordinator
        .prepare_native(operation, plan.clone(), &checked_b)
        .await;
    let mutations: [fn(&mut SourceOccurrence); 2] = [
        |occurrence| occurrence.txid[0] ^= 1,
        |occurrence| occurrence.action_index += 1,
    ];
    let mut occurrence_results = Vec::new();
    for input_index in 0..2 {
        for mutate in mutations {
            let mut wrong_context = native::NativeContext {
                domain: a.context.domain,
                environment: a.context.environment,
                lock_time: a.context.lock_time,
                expiry_height: a.context.expiry_height,
                fee: a.context.fee,
                inputs: a.context.inputs.clone(),
                outputs: a.context.outputs.clone(),
            };
            mutate(&mut wrong_context.inputs[input_index].source_occurrence);
            let checked = ziquid_zcash::custody::inspect_pczt(&a.bytes, &wrong_context.expected()).unwrap();
            native::bind_plan(&correct_operation, &correct_plan, &checked).unwrap();
            occurrence_results.push(
                coordinator
                    .prepare_native(correct_operation, correct_plan.clone(), &checked)
                    .await,
            );
        }
    }
    let after = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let after_reservations = reservations(&f).await;
    let after_version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, portion)
        .await
        .unwrap();
    let pending = f
        .ledger
        .pending_decision(f.policy.domain.pair)
        .await
        .unwrap();
    let stored = f
        .ledger
        .native_plan(f.policy.domain.pair, operation.intent)
        .await;
    let after_heads = retained_heads(&mut coordinator).await;
    let accepted = coordinator
        .prepare_native(correct_operation, correct_plan.clone(), &checked_a)
        .await;
    let correct_stored = f
        .ledger
        .native_plan(f.policy.domain.pair, correct_operation.intent)
        .await;
    coordinator.shutdown().await.unwrap();
    f.remove().await;
    assert!(
        matches!(&result, Err(Error::NativePlanMismatch)),
        "distinct genuine 34/10000 notes relabeled as A must reject before reservation/ACK"
    );
    assert_eq!(after, before);
    assert_eq!(after_version, version);
    assert!(pending.is_none());
    assert!(stored == Err(LedgerError::MissingEntity));
    assert_eq!(before_reservations, (0, 0, 0, 0, 0, 0, 2));
    assert_eq!(after_reservations, before_reservations);
    assert_same_heads(&before_heads, &after_heads);
    assert!(accepted.is_ok());
    assert!(
        occurrence_results
            .iter()
            .all(|result| matches!(result, Err(Error::NativePlanMismatch)))
    );
    assert!(correct_stored == Ok(correct_plan));
}

#[tokio::test]
async fn equal_value_distinct_native_change_cannot_reuse_confirmed_inventory_label_before_ack() {
    let root = runtime_support::fixture_dir();
    let context = crate::market::config::read::<NativePolicy>(&root.join("policy.json"))
        .unwrap()
        .context()
        .unwrap();
    let recipient = context
        .outputs
        .iter()
        .find(|output| output.kind == ziquid_zcash::custody::NativeOutputKind::Recipient)
        .unwrap()
        .recipient;
    let change = context
        .outputs
        .iter()
        .find(|output| output.kind == ziquid_zcash::custody::NativeOutputKind::Change)
        .unwrap()
        .recipient;
    let f = fixture(change.to_raw_address_bytes()).await;
    let mut payout_a = FixtureNative::payout(
        f.policy.domain,
        context.inputs[0].trusted_fvk.clone(),
        recipient,
        change,
    )
    .unwrap();
    let payout_b = FixtureNative::payout(
        f.policy.domain,
        context.inputs[0].trusted_fvk.clone(),
        recipient,
        change,
    )
    .unwrap();
    payout_a.context.inputs[0].inventory_note = [52; 32];
    payout_a.context.inputs[1].inventory_note = [150; 32];
    let checked_a =
        ziquid_zcash::custody::inspect_pczt(&payout_a.bytes, &payout_a.context.expected()).unwrap();
    let checked_b =
        ziquid_zcash::custody::inspect_pczt(&payout_b.bytes, &payout_b.context.expected()).unwrap();
    let change_a = checked_change(&checked_a, crate::market::fixture::CHANGE_NOTE);
    let change_b = checked_change(&checked_b, crate::market::fixture::CHANGE_NOTE);
    assert_eq!(change_a.value, 9);
    assert_eq!(change_b.value, 9);
    assert!(change_a.note_commitment != change_b.note_commitment);
    assert!(change_a.nullifier != change_b.nullifier);
    let occurrence_a = SourceOccurrence {
        network: f.policy.domain.source_network,
        pool: f.policy.domain.source_pool,
        txid: *checked_a.txid(),
        action_index: change_a.action_index,
    };
    let occurrence_b = SourceOccurrence {
        network: f.policy.domain.source_network,
        pool: f.policy.domain.source_pool,
        txid: *checked_b.txid(),
        action_index: change_b.action_index,
    };
    let refund_a = FixtureNative::refund(
        f.policy.domain,
        context.inputs[0].trusted_fvk.clone(),
        payout_a.change_note.unwrap(),
        occurrence_a,
        change,
    )
    .unwrap();
    let mut refund_b = FixtureNative::refund(
        f.policy.domain,
        context.inputs[0].trusted_fvk.clone(),
        payout_b.change_note.unwrap(),
        occurrence_b,
        change,
    )
    .unwrap();
    // The independent fixture sponsor has its own LocalFixture occurrence and
    // label. Enroll its genuine cmx/nf so only B's substituted change is wrong.
    refund_b.context.inputs[1].inventory_note = [160; 32];
    refund_b.context.inputs[1].source_occurrence.txid = [34; 32];
    let (hold, portion) = released(
        &f,
        &payout_a.context.inputs[0],
        recipient.to_raw_address_bytes(),
        change.to_raw_address_bytes(),
    )
    .await;
    sponsor(&f, &payout_a.context.inputs[1], [152; 32]).await;
    sponsor(&f, &refund_a.context.inputs[1], [161; 32]).await;
    sponsor(&f, &refund_b.context.inputs[1], [162; 32]).await;
    let payout_plan = NativePlan {
        hold,
        portion,
        kind: NativeIntentKind::SellerPayout,
        recipient: recipient.to_raw_address_bytes(),
        amount: 25,
        inventory_scope: f.policy.inventory_scope,
        inputs: vec![payout_a.context.inputs[0].inventory_note],
        fee_inputs: vec![payout_a.context.inputs[1].inventory_note],
        change: vec![change_a],
        fee: checked_a.fee(),
        nonce: [154; 32],
        pczt_digest: *checked_a.exact_pczt_digest(),
        sighash: *checked_a.shielded_sighash(),
        transaction: *checked_a.txid(),
    };
    let payout_operation = f.operation(
        hold,
        portion,
        [155; 32],
        f.ledger
            .entity_version(f.policy.domain.pair, hold, portion)
            .await
            .unwrap(),
        Transition::PrepareNative,
        &LedgerCommand::PrepareNative(payout_plan.clone()),
    );
    let files = runtime_support::Files::new();
    let mut coordinator = coordinator(&f, &files).await;
    coordinator
        .prepare_native(payout_operation, payout_plan.clone(), &checked_a)
        .await
        .unwrap();
    // Fixture producer testimony materializes the exact checked payout change;
    // this does not claim a native signature, mined transaction or source proof.
    let observation = facts::observe_native(
        &f.policy,
        &f.inventory_key,
        payout_operation.intent,
        &payout_plan,
    )
    .unwrap();
    let observe_command = LedgerCommand::ObserveNative(observation);
    let observe_operation = f.operation(
        payout_operation.intent,
        [0; 32],
        [156; 32],
        f.ledger
            .entity_version(f.policy.domain.pair, payout_operation.intent, [0; 32])
            .await
            .unwrap(),
        Transition::ObserveNative,
        &observe_command,
    );
    coordinator
        .apply(observe_operation, observe_command)
        .await
        .unwrap();
    let retained_change = f
        .ledger
        .inventory_input(f.policy.domain.pair, change_a.note)
        .await
        .unwrap();
    let checked_refund_b =
        ziquid_zcash::custody::inspect_pczt(&refund_b.bytes, &refund_b.context.expected()).unwrap();
    let refund_plan_b = NativePlan {
        hold,
        portion: [68; 32],
        kind: NativeIntentKind::BuyerRefund,
        recipient: change.to_raw_address_bytes(),
        amount: 9,
        inventory_scope: f.policy.inventory_scope,
        inputs: vec![change_a.note],
        fee_inputs: vec![refund_b.context.inputs[1].inventory_note],
        change: vec![],
        fee: checked_refund_b.fee(),
        nonce: [164; 32],
        pczt_digest: *checked_refund_b.exact_pczt_digest(),
        sighash: *checked_refund_b.shielded_sighash(),
        transaction: *checked_refund_b.txid(),
    };
    let version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, [68; 32])
        .await
        .unwrap();
    let refund_operation_b = f.operation(
        hold,
        [68; 32],
        [165; 32],
        version,
        Transition::PrepareNative,
        &LedgerCommand::PrepareNative(refund_plan_b.clone()),
    );
    native::bind_plan(&refund_operation_b, &refund_plan_b, &checked_refund_b).unwrap();
    let before_heads = retained_heads(&mut coordinator).await;
    let before = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let before_reservations = reservations(&f).await;
    let result = coordinator
        .prepare_native(refund_operation_b, refund_plan_b, &checked_refund_b)
        .await;
    let after = f.ledger.snapshot(f.policy.domain.pair).await.unwrap();
    let after_reservations = reservations(&f).await;
    let after_version = f
        .ledger
        .entity_version(f.policy.domain.pair, hold, [68; 32])
        .await
        .unwrap();
    let pending = f
        .ledger
        .pending_decision(f.policy.domain.pair)
        .await
        .unwrap();
    let stored = f
        .ledger
        .native_plan(f.policy.domain.pair, refund_operation_b.intent)
        .await;
    let after_heads = retained_heads(&mut coordinator).await;
    let checked_refund_a =
        ziquid_zcash::custody::inspect_pczt(&refund_a.bytes, &refund_a.context.expected()).unwrap();
    let refund_plan_a = NativePlan {
        hold,
        portion: [68; 32],
        kind: NativeIntentKind::BuyerRefund,
        recipient: change.to_raw_address_bytes(),
        amount: 9,
        inventory_scope: f.policy.inventory_scope,
        inputs: vec![change_a.note],
        fee_inputs: vec![refund_a.context.inputs[1].inventory_note],
        change: vec![],
        fee: checked_refund_a.fee(),
        nonce: [164; 32],
        pczt_digest: *checked_refund_a.exact_pczt_digest(),
        sighash: *checked_refund_a.shielded_sighash(),
        transaction: *checked_refund_a.txid(),
    };
    let refund_operation_a = f.operation(
        hold,
        [68; 32],
        refund_operation_b.intent,
        version,
        Transition::PrepareNative,
        &LedgerCommand::PrepareNative(refund_plan_a.clone()),
    );
    let accepted = coordinator
        .prepare_native(refund_operation_a, refund_plan_a.clone(), &checked_refund_a)
        .await;
    let correct_stored = f
        .ledger
        .native_plan(f.policy.domain.pair, refund_operation_a.intent)
        .await;
    let inventory_scope = f.policy.inventory_scope;
    coordinator.shutdown().await.unwrap();
    f.remove().await;
    assert!(
        retained_change
            == InventoryInput {
                note: change_a.note,
                occurrence: occurrence_a,
                note_commitment: change_a.note_commitment,
                nullifier: change_a.nullifier,
                value: 9,
                scope: inventory_scope,
            }
    );
    assert!(refund_a.context.inputs[0].source_occurrence == occurrence_a);
    assert!(refund_a.context.inputs[0].note_commitment == change_a.note_commitment);
    assert!(refund_a.context.inputs[0].nullifier == change_a.nullifier);
    assert!(matches!(result, Err(Error::NativePlanMismatch)));
    assert_eq!(after, before);
    assert_eq!(after_version, version);
    assert_eq!(after_reservations, before_reservations);
    assert!(pending.is_none());
    assert!(stored == Err(LedgerError::MissingEntity));
    assert_same_heads(&before_heads, &after_heads);
    assert!(accepted.is_ok());
    assert!(correct_stored == Ok(refund_plan_a));
}
