use ziquid_zcash::custody::inspect_pczt;
use ziquid_runtime::market::ledger::{ChangeOutput, LedgerCommand, NativePlan};
use ziquid_protocol::market::{NativeIntentKind, Operation, Transition};
use ziquid_runtime::market::{
    Error, config,
    native::{self, NativePolicy},
};

#[test]
fn checked_pczt_rejects_substituted_domain_inputs_fee_and_exact_native_plan_bytes() {
    let root = std::env::var_os("Z2Z_TEST_NATIVE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/market"));
    let policy: NativePolicy = config::read(&root.join("policy.json")).unwrap();
    let context = policy.context().unwrap();
    let bytes = config::read_bytes(&root.join("unsigned.pczt"), 16 * 1024 * 1024).unwrap();
    let checked = inspect_pczt(&bytes, &context.expected()).unwrap();
    let recipient = checked
        .expected_outputs()
        .iter()
        .find(|out| out.kind == ziquid_zcash::custody::NativeOutputKind::Recipient)
        .unwrap();
    let expected_change = checked
        .expected_outputs()
        .iter()
        .find(|out| out.kind == ziquid_zcash::custody::NativeOutputKind::Change)
        .unwrap();
    let mut changes = checked.outputs().iter().filter(|out| {
        out.recipient() == &expected_change.recipient && out.value() == expected_change.value
    });
    let change = changes.next().unwrap();
    assert!(changes.next().is_none());
    let plan = NativePlan {
        hold: [60; 32],
        portion: [61; 32],
        kind: NativeIntentKind::SellerPayout,
        recipient: recipient.recipient.to_raw_address_bytes(),
        amount: recipient.value,
        inventory_scope: context.domain.pair,
        inputs: checked
            .inputs()
            .map(|input| *input.inventory_note())
            .collect(),
        fee_inputs: vec![],
        change: vec![ChangeOutput {
            note: [62; 32],
            receiver: change.recipient().to_raw_address_bytes(),
            value: change.value(),
            action_index: change.action_index(),
            note_commitment: *change.note_commitment(),
            nullifier: *change.nullifier().unwrap(),
        }],
        fee: checked.fee(),
        nonce: [63; 32],
        pczt_digest: *checked.exact_pczt_digest(),
        sighash: *checked.shielded_sighash(),
        transaction: *checked.txid(),
    };
    let mut operation = Operation {
        domain: context.domain,
        entity: plan.hold,
        portion: plan.portion,
        intent: [64; 32],
        generation: 1,
        prior_version: 0,
        transition: Transition::PrepareNative,
        effects: [0; 32],
    };
    operation.effects = LedgerCommand::PrepareNative(plan.clone())
        .operation_effects(&operation)
        .unwrap();
    native::bind_plan(&operation, &plan, &checked).unwrap();
    let mutations: [fn(&mut NativePlan); 11] = [
        |plan| plan.pczt_digest[0] ^= 1,
        |plan| plan.transaction[0] ^= 1,
        |plan| plan.sighash[0] ^= 1,
        |plan| plan.fee += 1,
        |plan| plan.inputs[0] = [65; 32],
        |plan| plan.fee_inputs.push(plan.inputs[0]),
        |plan| plan.change[0].value -= 1,
        |plan| plan.change[0].receiver[0] ^= 1,
        |plan| plan.change[0].action_index ^= 1,
        |plan| plan.change[0].note_commitment[0] ^= 1,
        |plan| plan.change[0].nullifier[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = plan.clone();
        mutate(&mut changed);
        assert!(matches!(
            native::bind_plan(&operation, &changed, &checked),
            Err(Error::NativePlanMismatch)
        ));
    }
    let mut wrong_domain = operation;
    wrong_domain.domain.source_genesis = [66; 32];
    wrong_domain.effects = LedgerCommand::PrepareNative(plan.clone())
        .operation_effects(&wrong_domain)
        .unwrap();
    assert!(matches!(
        native::bind_plan(&wrong_domain, &plan, &checked),
        Err(Error::NativePlanMismatch)
    ));
}

#[test]
fn native_policy_requires_complete_structured_source_occurrence() {
    let policy: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/market/policy.json")).unwrap();
    let mut legacy = policy.clone();
    legacy["inputs"][0]["source_occurrence"] =
        policy["inputs"][0]["source_occurrence"]["txid"].clone();
    assert!(serde_json::from_value::<NativePolicy>(legacy).is_err());
    for missing in ["network", "pool", "txid", "action_index"] {
        let mut incomplete = policy.clone();
        incomplete["inputs"][0]["source_occurrence"]
            .as_object_mut()
            .unwrap()
            .remove(missing);
        assert!(serde_json::from_value::<NativePolicy>(incomplete).is_err());
    }
}
