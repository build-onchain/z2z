use std::sync::LazyLock;

use incrementalmerkletree::{Hashable, Level};
use orchard::{
    Anchor, Note,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    primitives::redpallas,
};
use pczt::{
    Pczt,
    roles::{tx_extractor::TransactionExtractor, verifier::Verifier},
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    memo::MemoBytes,
    value::Zatoshis,
};
use zeroize::Zeroizing;
use ziquid_protocol::{
    NativeAmount, PreparationBinding, SolverCapsule, StatementContext, ValidatedContext,
    input_commitment, note_consumption_tag, payment_commitment, preparation_consent_digest,
    preparation_packet_binding, solver_capsule_commitment,
};
use ziquid_zcash::{
    AuthoringError, ExecutableSelfSpend, IronwoodTransaction, OutputPlan, OwnedInput,
    PreparationIntent, PreparedPair, SourceParameters, prepare,
};

// Entirely generated local witness: not a note acquired from a valid chain,
// not evidence that this anchor is admissible, and never sent to a node.
fn input_fixture() -> (OwnedInput, SpendAuthorizingKey, FullViewingKey) {
    let mut rng = ChaCha20Rng::from_seed([71; 32]);
    let sk = loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes)) {
            break sk;
        }
    };
    let fvk = FullViewingKey::from(&sk);
    let rho = Rho::from_bytes(&[8; 32]).unwrap();
    let note = loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(seed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(bytes, &rho))
            && let Some(note) = Option::<Note>::from(Note::from_parts(
                fvk.address_at(0u32, Scope::External),
                NoteValue::from_raw(100_000),
                rho,
                seed,
                NoteVersion::V3,
            ))
        {
            break note;
        }
    };
    // The note is the only occupied leaf, at position zero in a depth-32 tree.
    let siblings = std::array::from_fn(|i| MerkleHashOrchard::empty_root(Level::from(i as u8)));
    let path = MerklePath::from_parts(0, siblings);
    let anchor = path.root(note.commitment().into());
    let input = OwnedInput::new(note, fvk.clone(), path, anchor).unwrap();
    (input, SpendAuthorizingKey::from(&sk), fvk)
}

fn source_parameters() -> SourceParameters {
    SourceParameters {
        network: Network::TestNetwork,
        target_height: BlockHeight::from(4_134_000),
        expiry_height: BlockHeight::from(4_134_040),
        consensus_branch: BranchId::Nu6_3,
        fee_rule: zip317::FeeRule::standard(),
    }
}

fn output(address: orchard::Address, value: u64) -> OutputPlan {
    OutputPlan::new(
        address,
        Zatoshis::from_u64(value).unwrap(),
        MemoBytes::empty(),
    )
}

fn output_plans(fvk: &FullViewingKey) -> (Vec<OutputPlan>, Vec<OutputPlan>) {
    let solver_sk = SpendingKey::from_bytes([91; 32]).unwrap();
    let solver_fvk = FullViewingKey::from(&solver_sk);
    (
        vec![
            output(solver_fvk.address_at(0u32, Scope::External), 60_000),
            output(fvk.address_at(1u32, Scope::Internal), 30_000),
        ],
        vec![output(fvk.address_at(2u32, Scope::Internal), 90_000)],
    )
}
const INPUT_BLIND: [u8; 32] = [14; 32];
const PAYMENT_BLIND: [u8; 32] = [15; 32];
const PREPARATION_BLIND: [u8; 32] = [16; 32];
const CAPSULE_BLIND: [u8; 32] = [18; 32];
const CONSENT_PAYMENT_MEMO: &[u8] = b"synthetic private preparation payment";
const CONSENT_RECOVERY_MEMO: &[u8] = b"synthetic private preparation recovery";

struct ConsentFixture {
    input: OwnedInput,
    ask: SpendAuthorizingKey,
    pair: PreparedPair,
    q: ExecutableSelfSpend,
    context: ValidatedContext,
    receivers: [[u8; 43]; 2],
    rng_seed: u8,
}

static CONSENT: LazyLock<ConsentFixture> = LazyLock::new(|| {
    let (input, ask, fvk) = input_fixture();
    let solver = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
    let addresses = [
        solver.address_at(0u32, Scope::External),
        solver.address_at(1u32, Scope::External),
    ];
    let payment = [
        OutputPlan::new(
            addresses[0],
            Zatoshis::from_u64(25_000).unwrap(),
            MemoBytes::from_bytes(CONSENT_PAYMENT_MEMO).unwrap(),
        ),
        output(addresses[1], 35_000),
        output(fvk.address_at(1u32, Scope::Internal), 25_000),
    ];
    let recovery = [OutputPlan::new(
        fvk.address_at(2u32, Scope::Internal),
        Zatoshis::from_u64(90_000).unwrap(),
        MemoBytes::from_bytes(CONSENT_RECOVERY_MEMO).unwrap(),
    )];
    let mut source = source_parameters();
    source.target_height = BlockHeight::from(4_134_001);
    // Exercise a genuine padded Q whose real spend is NOT at action zero.
    let (rng_seed, pair) = (1..=64)
        .find_map(|seed| {
            let pair = prepare(
                &source,
                &input,
                &payment,
                &recovery,
                &mut ChaCha20Rng::from_seed([seed; 32]),
            )
            .unwrap();
            let private_q = Pczt::parse(&pair.private_recovery_pczt_bytes().unwrap()).unwrap();
            (private_q.ironwood().actions()[0].spend().nullifier()
                != &input.nullifier().to_bytes())
                .then_some((seed, pair))
        })
        .expect("deterministic fixture must place the real spend after padding");
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let q = pair.finish_recovery(&ask, &pk, &vk).unwrap();
    let mut receivers = addresses.map(|address| address.to_raw_address_bytes());
    receivers.sort_unstable();
    let mut terms = StatementContext {
        schema_version: 1,
        source_network: *b"testnet",
        source_pool: *b"ironwood",
        transaction_version: 6,
        consensus_branch: BranchId::Nu6_3.into(),
        source_policy_id: [1; 32],
        preparation_program: [2; 32],
        settlement_program: [3; 32],
        order_id: [4; 32],
        consumption_tag: [5; 32],
        source_payment_commitment: [6; 32],
        real_input_commitment: [7; 32],
        source_quoted_amount: 60_000,
        source_fee_cap: 15_000,
        source_expiry: 4_134_040,
        evm_chain_id: 31_337,
        escrow: [8; 20],
        escrow_code_hash: [9; 32],
        verifier: [10; 20],
        verifier_code_hash: [11; 32],
        u_payee: [12; 20],
        s_refund: [13; 20],
        native_amount: NativeAmount::from_be_bytes([1; 32]),
    };
    let note = input.note();
    terms.real_input_commitment = input_commitment(
        &INPUT_BLIND,
        &terms.source_network,
        &terms.source_pool,
        &note.recipient().to_raw_address_bytes(),
        note.value().inner(),
        &note.rho().to_bytes(),
        note.rseed().as_bytes(),
        &ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
        &input.nullifier().to_bytes(),
    )
    .unwrap();
    terms.source_payment_commitment = payment_commitment(
        &PAYMENT_BLIND,
        &terms.source_network,
        &terms.source_pool,
        &pair.unsigned_payment().effect_id(),
        &receivers,
        terms.source_quoted_amount,
    )
    .unwrap();
    let fvk_bytes = Zeroizing::new(fvk.to_bytes());
    terms.consumption_tag = note_consumption_tag(
        &terms.source_network,
        &terms.source_pool,
        terms.evm_chain_id,
        &terms.escrow,
        fvk_bytes[32..64].try_into().unwrap(),
        &input.nullifier().to_bytes(),
    )
    .unwrap();
    ConsentFixture {
        input,
        ask,
        pair,
        q,
        context: terms.validate().unwrap(),
        receivers,
        rng_seed,
    }
});

fn consent_intent<'a>(
    fixture: &'a ConsentFixture,
    context: &'a ValidatedContext,
) -> PreparationIntent<'a> {
    PreparationIntent {
        context,
        input_blind: &INPUT_BLIND,
        payment_blind: &PAYMENT_BLIND,
        receivers: &fixture.receivers,
        preparation_blind: &PREPARATION_BLIND,
        capsule_blind: &CAPSULE_BLIND,
    }
}

fn consent_binding(
    fixture: &ConsentFixture,
    context: &ValidatedContext,
    height: u32,
) -> [u8; 32] {
    let input = &fixture.input;
    let recipient = Zeroizing::new(input.note().recipient().to_raw_address_bytes());
    let rho = Zeroizing::new(input.note().rho().to_bytes());
    let fvk = Zeroizing::new(input.full_viewing_key().to_bytes());
    let siblings = Zeroizing::new(input.merkle_path().auth_path().map(|node| node.to_bytes()));
    let anchor = Zeroizing::new(input.anchor().to_bytes());
    preparation_packet_binding(PreparationBinding {
        context,
        preparation_blind: &PREPARATION_BLIND,
        redacted_payment: fixture.pair.unsigned_payment().pczt_bytes(),
        recovery_transaction: fixture.q.transaction_bytes(),
        note_recipient: &recipient,
        note_value: input.note().value().inner(),
        note_rho: &rho,
        note_rseed: input.note().rseed().as_bytes(),
        full_viewing_key: &fvk,
        merkle_position: input.merkle_path().position(),
        merkle_siblings: &siblings,
        anchor: &anchor,
        source_target_height: height,
    })
    .unwrap()
}

fn consent_capsule(
    fixture: &ConsentFixture,
    context: &ValidatedContext,
    binding: &[u8; 32],
    blind: &[u8; 32],
) -> [u8; 32] {
    solver_capsule_commitment(SolverCapsule {
        context,
        private_packet_binding: binding,
        capsule_blind: blind,
        redacted_payment: fixture.pair.unsigned_payment().pczt_bytes(),
        recovery_transaction: fixture.q.transaction_bytes(),
    })
    .unwrap()
}

fn consent_message(
    fixture: &ConsentFixture,
    context: &ValidatedContext,
    height: u32,
) -> [u8; 32] {
    let binding = consent_binding(fixture, context, height);
    let capsule = consent_capsule(fixture, context, &binding, &CAPSULE_BLIND);
    preparation_consent_digest(context, &binding, &capsule).unwrap()
}


#[test]
fn unsigned_payment_has_exact_ciphertexts_but_no_completion_or_viewing_material() {
    let (input, _, fvk) = input_fixture();
    let (payment, recovery) = output_plans(&fvk);
    let pair = prepare(
        &source_parameters(),
        &input,
        &payment,
        &recovery,
        &mut ChaCha20Rng::from_seed([11; 32]),
    )
    .unwrap();
    let pczt = Pczt::parse(pair.unsigned_payment().pczt_bytes()).unwrap();
    assert_eq!(pczt.ironwood().actions().len(), 2);
    assert!(pczt.ironwood().zkproof().is_none());
    for action in pczt.ironwood().actions() {
        assert!(action.spend().spend_auth_sig().is_none());
        assert!(action.spend().dummy_sk().is_none());
        assert!(action.spend().witness().is_none());
        assert!(action.output().rseed().is_none());
        assert!(action.output().recipient().is_none());
    }
    // These private fields are exposed only by the supported typed Verifier role.
    Verifier::new(pczt.clone())
        .with_ironwood(|bundle| {
            assert!(bundle.bsk().is_none());
            for action in bundle.actions() {
                assert!(action.spend().fvk().is_none());
                assert!(action.spend().alpha().is_none());
            }
            Ok::<_, pczt::roles::verifier::OrchardError<()>>(())
        })
        .unwrap();
    assert!(TransactionExtractor::new(pczt.clone()).extract().is_err());
    let solver_sk = SpendingKey::from_bytes([91; 32]).unwrap();
    let solver_address = FullViewingKey::from(&solver_sk).address_at(0u32, Scope::External);
    // Real full AEAD sender recovery, without the solver's IVK or any FVK.
    let recovered = pair
        .payout_witness()
        .recover_pczt_output(pair.unsigned_payment().pczt_bytes(), 0)
        .unwrap();
    assert_eq!(recovered.recipient(), solver_address);
    assert_eq!(recovered.value(), 60_000);
    assert_eq!(recovered.memo(), MemoBytes::empty().as_array());
    let effects = pczt.into_effects().unwrap();
    assert!(
        effects
            .ironwood_bundle()
            .unwrap()
            .actions()
            .iter()
            .any(|action| action.nullifier() == &input.nullifier())
    );
    assert_eq!(pair.payment_fee(), Zatoshis::from_u64(10_000).unwrap());
    assert_eq!(pair.recovery_fee(), Zatoshis::from_u64(10_000).unwrap());
}

#[test]
fn generated_owned_note_proves_signs_every_action_and_extracts_complete_q() {
    let (input, ask, fvk) = input_fixture();
    let (payment, recovery) = output_plans(&fvk);
    let pair = prepare(
        &source_parameters(),
        &input,
        &payment,
        &recovery,
        &mut ChaCha20Rng::from_seed([12; 32]),
    )
    .unwrap();
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let q = pair.finish_recovery(&ask, &pk, &vk).unwrap();
    let parsed = IronwoodTransaction::parse(q.transaction_bytes(), BranchId::Nu6_3).unwrap();
    assert_eq!(parsed.serialize().unwrap(), q.transaction_bytes());
    assert_eq!(parsed.effect_id(), q.effect_id());
    assert_eq!(
        parsed.transaction().expiry_height(),
        BlockHeight::from(4_134_040)
    );
    let bundle = parsed.transaction().ironwood_bundle().unwrap();
    // One real note is NOT one action: normal padding is completed too.
    assert_eq!(bundle.actions().len(), 2);
    assert!(
        bundle
            .actions()
            .iter()
            .any(|a| a.nullifier() == &input.nullifier())
    );
    assert_eq!(i64::from(*bundle.value_balance()), 10_000);
    let returned = bundle
        .decrypt_outputs_with_keys(&[fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)]);
    assert_eq!(
        returned
            .iter()
            .map(|(_, _, note, _, _)| note.value().inner())
            .sum::<u64>(),
        90_000
    );
    parsed
        .verify_authorization(&vk, &mut ChaCha20Rng::from_seed([21; 32]))
        .unwrap();
    assert!(parsed.transaction().transparent_bundle().is_none());
    assert!(parsed.transaction().sapling_bundle().is_none());
    assert!(parsed.transaction().orchard_bundle().is_none());
    // No proof/private PCZT is transferred to S, only final consensus bytes.
    let mut trailing = q.transaction_bytes().to_vec();
    trailing.push(0);
    assert!(IronwoodTransaction::parse(&trailing, BranchId::Nu6_3).is_err());
    assert!(IronwoodTransaction::parse(q.transaction_bytes(), BranchId::Nu6_2).is_err());
    assert!(IronwoodTransaction::parse(&q.transaction_bytes()[..30], BranchId::Nu6_3).is_err());
    // Every SpendAuth, including padding, and the binding signature are required.
    // Published v6 serialization ends with one 64-byte signature per action,
    // followed by the 64-byte binding signature.
    for signature in 0..=bundle.actions().len() {
        let mut damaged = q.transaction_bytes().to_vec();
        let offset = damaged.len() - 64 * (bundle.actions().len() + 1) + 64 * signature;
        damaged[offset..offset + 64].fill(0);
        let changed_auth = IronwoodTransaction::parse(&damaged, BranchId::Nu6_3).unwrap();
        assert_eq!(changed_auth.effect_id(), parsed.effect_id());
        assert_ne!(changed_auth.authorization_id(), parsed.authorization_id());
        assert!(
            changed_auth
                .verify_authorization(&vk, &mut ChaCha20Rng::from_seed([22; 32]))
                .is_err()
        );
    }
}

#[test]
fn wrong_owner_pool_anchor_branch_or_expiry_is_rejected_locally() {
    let (input, _, fvk) = input_fixture();
    let note = *input.note();
    let wrong_fvk = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
    assert!(matches!(
        OwnedInput::new(note, wrong_fvk, input.merkle_path().clone(), input.anchor()),
        Err(AuthoringError::InputNotOwned)
    ));
    assert!(matches!(
        OwnedInput::new(
            note,
            fvk.clone(),
            input.merkle_path().clone(),
            Anchor::empty_tree()
        ),
        Err(AuthoringError::AnchorMismatch)
    ));
    let old_note = Note::from_parts(
        note.recipient(),
        note.value(),
        note.rho(),
        *note.rseed(),
        NoteVersion::V2,
    )
    .unwrap();
    assert!(matches!(
        OwnedInput::new(
            old_note,
            fvk.clone(),
            input.merkle_path().clone(),
            input.anchor()
        ),
        Err(AuthoringError::WrongNoteVersion)
    ));
    let (payment, recovery) = output_plans(&fvk);
    let mut params = source_parameters();
    params.consensus_branch = BranchId::Nu6_2;
    assert!(matches!(
        prepare(
            &params,
            &input,
            &payment,
            &recovery,
            &mut ChaCha20Rng::from_seed([31; 32])
        ),
        Err(AuthoringError::WrongBranch)
    ));
    params = source_parameters();
    params.expiry_height = BlockHeight::from(0);
    assert!(matches!(
        prepare(
            &params,
            &input,
            &payment,
            &recovery,
            &mut ChaCha20Rng::from_seed([32; 32])
        ),
        Err(AuthoringError::InvalidHeight)
    ));
    params = source_parameters();
    params.target_height = BlockHeight::from(0);
    assert!(matches!(
        prepare(
            &params,
            &input,
            &payment,
            &recovery,
            &mut ChaCha20Rng::from_seed([33; 32])
        ),
        Err(AuthoringError::InvalidHeight)
    ));
}

#[test]
fn no_hidden_topup_or_unowned_q_output_is_added() {
    let (input, _, fvk) = input_fixture();
    let (payment, recovery) = output_plans(&fvk);
    let unbalanced = vec![output(fvk.address_at(1u32, Scope::Internal), 90_001)];
    assert!(matches!(
        prepare(
            &source_parameters(),
            &input,
            &payment,
            &unbalanced,
            &mut ChaCha20Rng::from_seed([41; 32])
        ),
        Err(AuthoringError::UnbalancedOutputs)
    ));
    let unowned = vec![output(
        FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap())
            .address_at(0u32, Scope::External),
        90_000,
    )];
    assert!(matches!(
        prepare(
            &source_parameters(),
            &input,
            &payment,
            &unowned,
            &mut ChaCha20Rng::from_seed([42; 32])
        ),
        Err(AuthoringError::RecoveryOutputNotOwned)
    ));
    let payment_short = vec![output(fvk.address_at(1u32, Scope::Internal), 89_999)];
    assert!(matches!(
        prepare(
            &source_parameters(),
            &input,
            &payment_short,
            &recovery,
            &mut ChaCha20Rng::from_seed([43; 32])
        ),
        Err(AuthoringError::UnbalancedOutputs)
    ));
}

#[test]
fn published_nu7_testnet_boundary_cannot_author_new_nu63_packets() {
    let (input, _, fvk) = input_fixture();
    let (payment, recovery) = output_plans(&fvk);
    for (target, expiry) in [(4_465_025u32, 4_465_026u32), (4_465_026, 4_465_026)] {
        let mut params = source_parameters();
        params.target_height = target.into();
        params.expiry_height = expiry.into();
        assert!(matches!(prepare(&params, &input, &payment, &recovery,
            &mut ChaCha20Rng::from_seed([17; 32])), Err(AuthoringError::WrongBranch)));
    }
}

#[test]
fn last_nu63_testnet_height_prepares_exact_outputs_and_fees() {
    let (input, _, fvk) = input_fixture();
    let (payment, recovery) = output_plans(&fvk);
    let mut params = source_parameters();
    params.target_height = BlockHeight::from(4_465_025);
    params.expiry_height = params.target_height;
    let pair = prepare(
        &params,
        &input,
        &payment,
        &recovery,
        &mut ChaCha20Rng::from_seed([18; 32]),
    )
    .unwrap();
    assert_eq!(pair.payment_fee(), Zatoshis::from_u64(10_000).unwrap());
    assert_eq!(pair.recovery_fee(), Zatoshis::from_u64(10_000).unwrap());
    for (index, planned) in payment.iter().enumerate() {
        let recovered = pair
            .payout_witness()
            .recover_pczt_output(pair.unsigned_payment().pczt_bytes(), index)
            .unwrap();
        assert_eq!(recovered.recipient(), planned.recipient());
        assert_eq!(recovered.value(), u64::from(planned.value()));
    }
    for bytes in [
        pair.unsigned_payment().pczt_bytes().to_vec(),
        pair.private_recovery_pczt_bytes().unwrap(),
    ] {
        let effects = Pczt::parse(&bytes).unwrap().into_effects().unwrap();
        assert_eq!(effects.expiry_height(), params.expiry_height);
        assert_eq!(effects.consensus_branch_id(), BranchId::Nu6_3);
    }
}

#[test]
fn out_of_era_source_is_rejected_before_outputs_or_rng_are_used() {
    let (input, _, _) = input_fixture();
    for (target, expiry) in [
        (4_133_999u32, 4_134_000u32),
        (4_465_025, 4_465_026),
        (4_465_026, 4_465_026),
    ] {
        let mut params = source_parameters();
        params.target_height = target.into();
        params.expiry_height = expiry.into();
        let mut rng = ChaCha20Rng::from_seed([19; 32]);
        let mut untouched_rng = rng.clone();
        assert!(matches!(
            prepare(&params, &input, &[], &[], &mut rng),
            Err(AuthoringError::WrongBranch)
        ));
        assert_eq!(rng.next_u64(), untouched_rng.next_u64());
    }
}

#[test]
fn testnet_cutoff_does_not_change_mainnet_source_preflight() {
    let (input, _, _) = input_fixture();
    for height in [3_428_143u32, 4_465_026] {
        let mut params = source_parameters();
        params.network = Network::MainNetwork;
        params.target_height = height.into();
        params.expiry_height = height.into();
        assert!(matches!(
            prepare(
                &params,
                &input,
                &[],
                &[],
                &mut ChaCha20Rng::from_seed([20; 32])
            ),
            Err(AuthoringError::MissingOutputs)
        ));
    }
}

#[test]
fn private_owner_intent_is_checked_before_signing_opaque_terms() {
    let fixture = &*CONSENT;
    let mut opaque = *fixture.context.context();
    opaque.consumption_tag = [5; 32];
    opaque.source_payment_commitment = [6; 32];
    opaque.real_input_commitment = [7; 32];
    let context = opaque.validate().unwrap();
    let mut rng = ChaCha20Rng::from_seed([17; 32]);
    let mut untouched_rng = rng.clone();
    // Shape-valid opaque commitments are not permission to sign destination terms.
    assert!(matches!(
        fixture.pair.authorize_preparation(
            &fixture.input,
            &fixture.q,
            consent_intent(fixture, &context),
            &fixture.ask,
            &mut rng,
        ),
        Err(AuthoringError::InvalidPreparationIntent)
    ));
    assert_eq!(rng.next_u64(), untouched_rng.next_u64());
}

#[test]
fn owner_consent_verifies_under_real_nonzero_q_action_and_exact_retained_height() {
    let fixture = &*CONSENT;
    let before_p = fixture.pair.payout_witness().private_pczt_bytes();
    let before_q = Zeroizing::new(fixture.pair.private_recovery_pczt_bytes().unwrap());
    let payment_output = fixture.pair.payout_witness()
        .recover_pczt_output(fixture.pair.unsigned_payment().pczt_bytes(), 0).unwrap();
    assert_eq!(payment_output.memo(),
        MemoBytes::from_bytes(CONSENT_PAYMENT_MEMO).unwrap().as_array());
    let signature = fixture
        .pair
        .authorize_preparation(
            &fixture.input,
            &fixture.q,
            consent_intent(fixture, &fixture.context),
            &fixture.ask,
            &mut ChaCha20Rng::from_seed([18; 32]),
        )
        .unwrap();
    assert_eq!(fixture.pair.source_target_height(), 4_134_001);
    let parsed = IronwoodTransaction::parse(fixture.q.transaction_bytes(), BranchId::Nu6_3).unwrap();
    let actions = parsed.transaction().ironwood_bundle().unwrap().actions();
    let fvk = fixture.input.full_viewing_key();
    let returned = parsed.transaction().ironwood_bundle().unwrap()
        .decrypt_outputs_with_keys(&[fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)]);
    let (_, _, _, _, memo) = returned.iter()
        .find(|(_, _, note, _, _)| note.value().inner() == 90_000).unwrap();
    assert_eq!(memo, MemoBytes::from_bytes(CONSENT_RECOVERY_MEMO).unwrap().as_array());
    let real_index = actions
        .iter()
        .position(|action| action.nullifier() == &fixture.input.nullifier())
        .unwrap();
    assert_ne!(real_index, 0);
    let signature = redpallas::Signature::<redpallas::SpendAuth>::from(signature);
    let message = consent_message(fixture, &fixture.context, 4_134_001);
    actions[real_index].rk().verify(&message, &signature).unwrap();
    assert!(actions[0].rk().verify(&message, &signature).is_err());
    assert!(actions[real_index].rk().verify(&fixture.q.effect_id(), &signature).is_err());
    assert!(actions[real_index]
        .rk()
        .verify(&consent_message(fixture, &fixture.context, 4_134_000), &signature)
        .is_err());
    assert_eq!(fixture.pair.payout_witness().private_pczt_bytes(), before_p);
    let after_q = Zeroizing::new(fixture.pair.private_recovery_pczt_bytes().unwrap());
    assert_eq!(after_q.as_slice(), before_q.as_slice());
    assert!(Pczt::parse(fixture.pair.unsigned_payment().pczt_bytes())
        .unwrap()
        .ironwood()
        .actions()
        .iter()
        .all(|action| action.spend().spend_auth_sig().is_none()));
}

#[test]
fn owner_consent_rejects_wrong_ask_mispaired_q_and_changed_owned_input() {
    let fixture = &*CONSENT;
    let wrong_ask = SpendAuthorizingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
    let mut rng = ChaCha20Rng::from_seed([19; 32]);
    let mut untouched_rng = rng.clone();
    assert!(matches!(
        fixture.pair.authorize_preparation(
            &fixture.input,
            &fixture.q,
            consent_intent(fixture, &fixture.context),
            &wrong_ask,
            &mut rng,
        ),
        Err(AuthoringError::SigningFailed)
    ));
    assert_eq!(rng.next_u64(), untouched_rng.next_u64());
    let fvk = fixture.input.full_viewing_key();
    let (payment, recovery) = output_plans(fvk);
    let other_pair = prepare(
        &source_parameters(),
        &fixture.input,
        &payment,
        &recovery,
        &mut ChaCha20Rng::from_seed([20; 32]),
    )
    .unwrap();
    let mut rng = ChaCha20Rng::from_seed([21; 32]);
    let mut untouched_rng = rng.clone();
    assert!(matches!(
        other_pair.authorize_preparation(
            &fixture.input,
            &fixture.q,
            consent_intent(fixture, &fixture.context),
            &fixture.ask,
            &mut rng,
        ),
        Err(AuthoringError::EffectsMismatch)
    ));
    assert_eq!(rng.next_u64(), untouched_rng.next_u64());
    let note = fixture.input.note();
    let changed_note = Option::<Note>::from(Note::from_parts(
        note.recipient(),
        NoteValue::from_raw(90_000),
        note.rho(),
        *note.rseed(),
        NoteVersion::V3,
    ))
    .unwrap();
    let path = fixture.input.merkle_path().clone();
    let changed = OwnedInput::new(
        changed_note,
        fvk.clone(),
        path.clone(),
        path.root(changed_note.commitment().into()),
    )
    .unwrap();
    let mut rng = ChaCha20Rng::from_seed([22; 32]);
    let mut untouched_rng = rng.clone();
    assert!(matches!(
        fixture.pair.authorize_preparation(
            &changed,
            &fixture.q,
            consent_intent(fixture, &fixture.context),
            &fixture.ask,
            &mut rng,
        ),
        Err(AuthoringError::InvalidInputRelation)
    ));
    assert_eq!(rng.next_u64(), untouched_rng.next_u64());
}

#[test]
fn owner_consent_rejects_same_effect_q_with_a_different_anchor() {
    let fixture = &*CONSENT;
    let note = *fixture.input.note();
    let path = MerklePath::from_parts(1, fixture.input.merkle_path().auth_path());
    let input = OwnedInput::new(
        note,
        fixture.input.full_viewing_key().clone(),
        path.clone(),
        path.root(note.commitment().into()),
    ).unwrap();
    let solver = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
    let fvk = input.full_viewing_key();
    let payment = [
        OutputPlan::new(
            solver.address_at(0u32, Scope::External),
            Zatoshis::from_u64(25_000).unwrap(),
            MemoBytes::from_bytes(CONSENT_PAYMENT_MEMO).unwrap(),
        ),
        output(solver.address_at(1u32, Scope::External), 35_000),
        output(fvk.address_at(1u32, Scope::Internal), 25_000),
    ];
    let recovery = [OutputPlan::new(
        fvk.address_at(2u32, Scope::Internal),
        Zatoshis::from_u64(90_000).unwrap(),
        MemoBytes::from_bytes(CONSENT_RECOVERY_MEMO).unwrap(),
    )];
    let mut source = source_parameters();
    source.target_height = BlockHeight::from(4_134_001);
    let pair = prepare(
        &source, &input, &payment, &recovery,
        &mut ChaCha20Rng::from_seed([fixture.rng_seed; 32]),
    ).unwrap();
    // v6 does not include the anchor in its effect ID. Same RNG/plan/note makes
    // this a real same-txid counterexample to an ID-only correspondence check.
    let effects = Pczt::parse(&pair.private_recovery_pczt_bytes().unwrap())
        .unwrap().into_effects().unwrap();
    let parsed_q = IronwoodTransaction::parse(fixture.q.transaction_bytes(), BranchId::Nu6_3).unwrap();
    assert_ne!(effects.ironwood_bundle().unwrap().anchor(),
        parsed_q.transaction().ironwood_bundle().unwrap().anchor());
    assert_eq!(effects.ironwood_bundle().unwrap().actions().len(), 2);
    let effect_id: [u8; 32] = zcash_primitives::transaction::txid::to_txid(
        effects.version(), effects.consensus_branch_id(),
        &effects.digest(zcash_primitives::transaction::txid::TxIdDigester),
    ).into();
    assert_eq!(effect_id, fixture.q.effect_id());
    // Give the second pair its genuine semantic input opening, so rejection is
    // specifically complete-Q/anchor correspondence, not an opaque commitment.
    let mut terms = *fixture.context.context();
    terms.real_input_commitment = input_commitment(
        &INPUT_BLIND, &terms.source_network, &terms.source_pool,
        &input.note().recipient().to_raw_address_bytes(), input.note().value().inner(),
        &input.note().rho().to_bytes(), input.note().rseed().as_bytes(),
        &ExtractedNoteCommitment::from(input.note().commitment()).to_bytes(),
        &input.nullifier().to_bytes(),
    ).unwrap();
    let context = terms.validate().unwrap();
    let mut rng = ChaCha20Rng::from_seed([25; 32]);
    let mut untouched_rng = rng.clone();
    assert!(matches!(pair.authorize_preparation(
        &input, &fixture.q, consent_intent(fixture, &context), &fixture.ask,
        &mut rng,
    ), Err(AuthoringError::EffectsMismatch)));
    assert_eq!(rng.next_u64(), untouched_rng.next_u64());
}

#[test]
fn owner_consent_rejects_changed_openings_quote_fee_expiry_branch_and_self_payment() {
    let fixture = &*CONSENT;
    let authorize = |context: &ValidatedContext, intent: PreparationIntent<'_>| {
        let mut rng = ChaCha20Rng::from_seed([23; 32]);
        let mut untouched_rng = rng.clone();
        assert!(matches!(
            fixture.pair.authorize_preparation(
                &fixture.input,
                &fixture.q,
                PreparationIntent { context, ..intent },
                &fixture.ask,
                &mut rng,
            ),
            Err(AuthoringError::InvalidPreparationIntent)
        ));
        assert_eq!(rng.next_u64(), untouched_rng.next_u64());
    };
    for field in 0..9 {
        let mut terms = *fixture.context.context();
        match field {
            0 => terms.real_input_commitment[0] ^= 1,
            1 => terms.source_payment_commitment[0] ^= 1,
            2 => terms.consumption_tag[0] ^= 1,
            3 => {
                terms.source_quoted_amount += 1;
                terms.source_payment_commitment = payment_commitment(
                    &PAYMENT_BLIND,
                    &terms.source_network,
                    &terms.source_pool,
                    &fixture.pair.unsigned_payment().effect_id(),
                    &fixture.receivers,
                    terms.source_quoted_amount,
                ).unwrap();
            }
            4 => terms.source_fee_cap = 10_000,
            5 => terms.source_expiry += 1,
            6 => terms.consensus_branch = BranchId::Nu6_2.into(),
            7 => terms.evm_chain_id += 1,
            _ => terms.escrow[0] ^= 1,
        }
        let context = terms.validate().unwrap();
        authorize(&context, consent_intent(fixture, &context));
    }
    authorize(
        &fixture.context,
        PreparationIntent { input_blind: &[17; 32], ..consent_intent(fixture, &fixture.context) },
    );
    authorize(
        &fixture.context,
        PreparationIntent { payment_blind: &INPUT_BLIND, ..consent_intent(fixture, &fixture.context) },
    );
    for intent in [
        PreparationIntent { input_blind: &[0; 32], ..consent_intent(fixture, &fixture.context) },
        PreparationIntent { payment_blind: &[0; 32], ..consent_intent(fixture, &fixture.context) },
        PreparationIntent { preparation_blind: &[0; 32], ..consent_intent(fixture, &fixture.context) },
    ] {
        authorize(&fixture.context, intent);
    }
    let incomplete_receivers = &fixture.receivers[..1];
    let mut incomplete_terms = *fixture.context.context();
    incomplete_terms.source_payment_commitment = payment_commitment(
        &PAYMENT_BLIND,
        &incomplete_terms.source_network,
        &incomplete_terms.source_pool,
        &fixture.pair.unsigned_payment().effect_id(),
        incomplete_receivers,
        incomplete_terms.source_quoted_amount,
    ).unwrap();
    let context = incomplete_terms.validate().unwrap();
    authorize(
        &context,
        PreparationIntent { receivers: incomplete_receivers, ..consent_intent(fixture, &context) },
    );
    let self_receiver = [fixture.input.full_viewing_key().address_at(1u32, Scope::Internal)
        .to_raw_address_bytes()];
    let mut self_terms = *fixture.context.context();
    self_terms.source_quoted_amount = 25_000;
    self_terms.source_payment_commitment = payment_commitment(
        &PAYMENT_BLIND,
        &self_terms.source_network,
        &self_terms.source_pool,
        &fixture.pair.unsigned_payment().effect_id(),
        &self_receiver,
        25_000,
    )
    .unwrap();
    let context = self_terms.validate().unwrap();
    authorize(
        &context,
        PreparationIntent { receivers: &self_receiver, ..consent_intent(fixture, &context) },
    );
    let mut reversed = fixture.receivers;
    reversed.reverse();
    authorize(
        &fixture.context,
        PreparationIntent { receivers: &reversed, ..consent_intent(fixture, &fixture.context) },
    );
    authorize(
        &fixture.context,
        PreparationIntent { receivers: &[[0; 43]], ..consent_intent(fixture, &fixture.context) },
    );
    let duplicates = [fixture.receivers[0]; 2];
    authorize(
        &fixture.context,
        PreparationIntent { receivers: &duplicates, ..consent_intent(fixture, &fixture.context) },
    );
    let over_limit = [fixture.receivers[0]; 65];
    authorize(
        &fixture.context,
        PreparationIntent { receivers: &over_limit, ..consent_intent(fixture, &fixture.context) },
    );
}

#[test]
fn owner_consent_does_not_authorize_mutated_opaque_destination_terms() {
    let fixture = &*CONSENT;
    let signature = fixture.pair.authorize_preparation(
        &fixture.input,
        &fixture.q,
        consent_intent(fixture, &fixture.context),
        &fixture.ask,
        &mut ChaCha20Rng::from_seed([24; 32]),
    )
    .unwrap();
    let signature = redpallas::Signature::<redpallas::SpendAuth>::from(signature);
    let parsed = IronwoodTransaction::parse(fixture.q.transaction_bytes(), BranchId::Nu6_3).unwrap();
    let real = parsed.transaction().ironwood_bundle().unwrap().actions().iter()
        .find(|action| action.nullifier() == &fixture.input.nullifier()).unwrap();
    for field in 0..10 {
        let mut terms = *fixture.context.context();
        match field {
            0 => terms.source_policy_id[0] ^= 1,
            1 => terms.preparation_program[0] ^= 1,
            2 => terms.settlement_program[0] ^= 1,
            3 => terms.order_id[0] ^= 1,
            4 => terms.escrow_code_hash[0] ^= 1,
            5 => terms.verifier[0] ^= 1,
            6 => terms.verifier_code_hash[0] ^= 1,
            7 => terms.u_payee[0] ^= 1,
            8 => terms.s_refund[0] ^= 1,
            _ => terms.native_amount = NativeAmount::from_be_bytes([2; 32]),
        }
        let context = terms.validate().unwrap();
        assert!(real.rk()
            .verify(&consent_message(fixture, &context, 4_134_001), &signature)
            .is_err());
    }
    assert_eq!(
        format!("{:?}", consent_intent(fixture, &fixture.context)),
        "PreparationIntent([redacted])",
    );
}

#[test]
fn capsule_only_reblinding_keeps_private_binding_and_tag_but_requires_fresh_consent() {
    let fixture = &*CONSENT;
    let height = fixture.pair.source_target_height();
    let binding = consent_binding(fixture, &fixture.context, height);
    let capsule = consent_capsule(fixture, &fixture.context, &binding, &CAPSULE_BLIND);
    let reblind = [19; 32];
    let rebound = consent_capsule(fixture, &fixture.context, &binding, &reblind);
    assert_ne!(capsule, rebound);
    let message = preparation_consent_digest(&fixture.context, &binding, &capsule).unwrap();
    let rebound_message = preparation_consent_digest(&fixture.context, &binding, &rebound).unwrap();
    assert_ne!(message, rebound_message);
    let before_tag = fixture.context.context().consumption_tag;
    let signature = fixture.pair.authorize_preparation(
        &fixture.input, &fixture.q, consent_intent(fixture, &fixture.context),
        &fixture.ask, &mut ChaCha20Rng::from_seed([26; 32]),
    ).unwrap();
    let rebound_signature = fixture.pair.authorize_preparation(
        &fixture.input, &fixture.q,
        PreparationIntent { capsule_blind: &reblind, ..consent_intent(fixture, &fixture.context) },
        &fixture.ask, &mut ChaCha20Rng::from_seed([26; 32]),
    ).unwrap();
    assert_eq!(binding, consent_binding(fixture, &fixture.context, height));
    assert_eq!(before_tag, fixture.context.context().consumption_tag);
    assert_ne!(signature, rebound_signature);
    let signature = redpallas::Signature::<redpallas::SpendAuth>::from(signature);
    let rebound_signature = redpallas::Signature::<redpallas::SpendAuth>::from(rebound_signature);
    let q = IronwoodTransaction::parse(fixture.q.transaction_bytes(), BranchId::Nu6_3).unwrap();
    let real = q.transaction().ironwood_bundle().unwrap().actions().iter()
        .find(|action| action.nullifier() == &fixture.input.nullifier()).unwrap();
    real.rk().verify(&message, &signature).unwrap();
    real.rk().verify(&rebound_message, &rebound_signature).unwrap();
    assert!(real.rk().verify(&rebound_message, &signature).is_err());
    assert!(real.rk().verify(&message, &rebound_signature).is_err());
}

#[test]
fn zero_or_reused_capsule_blind_is_rejected_before_signature_rng_is_used() {
    let fixture = &*CONSENT;
    for blind in [&[0; 32], &PREPARATION_BLIND, &INPUT_BLIND, &PAYMENT_BLIND] {
        let mut rng = ChaCha20Rng::from_seed([27; 32]);
        let mut untouched_rng = rng.clone();
        assert!(matches!(fixture.pair.authorize_preparation(
            &fixture.input, &fixture.q,
            PreparationIntent { capsule_blind: blind, ..consent_intent(fixture, &fixture.context) },
            &fixture.ask, &mut rng,
        ), Err(AuthoringError::InvalidPreparationIntent)));
        assert_eq!(rng.next_u64(), untouched_rng.next_u64());
    }
}

#[test]
fn owner_consent_binds_exact_capsule_domain_and_exported_p_q_bytes() {
    let fixture = &*CONSENT;
    let binding = consent_binding(fixture, &fixture.context, fixture.pair.source_target_height());
    let capsule = consent_capsule(fixture, &fixture.context, &binding, &CAPSULE_BLIND);
    let signature = fixture.pair.authorize_preparation(
        &fixture.input, &fixture.q, consent_intent(fixture, &fixture.context),
        &fixture.ask, &mut ChaCha20Rng::from_seed([28; 32]),
    ).unwrap();
    let signature = redpallas::Signature::<redpallas::SpendAuth>::from(signature);
    let q = IronwoodTransaction::parse(fixture.q.transaction_bytes(), BranchId::Nu6_3).unwrap();
    let real = q.transaction().ironwood_bundle().unwrap().actions().iter()
        .find(|action| action.nullifier() == &fixture.input.nullifier()).unwrap();
    // Independently frame the capsule too: the wallet must bind exact final bytes.
    let mut hash = Sha256::new();
    hash.update(b"ziquid.preparation.solver-capsule.v1");
    hash.update(fixture.context.digest());
    hash.update(binding);
    hash.update(CAPSULE_BLIND);
    for blob in [fixture.pair.unsigned_payment().pczt_bytes(), fixture.q.transaction_bytes()] {
        hash.update(u32::try_from(blob.len()).unwrap().to_le_bytes());
        hash.update(blob);
    }
    let expected_capsule: [u8; 32] = hash.finalize().into();
    assert_eq!(capsule, expected_capsule);
    // The expected transcript is independent of the protocol's consent helper.
    let mut hash = Sha256::new();
    hash.update(b"ziquid.semantic.owner-consent.v2");
    hash.update(fixture.context.digest());
    hash.update(binding);
    hash.update(capsule);
    let message: [u8; 32] = hash.finalize().into();
    real.rk().verify(&message, &signature).unwrap();
    for include_capsule in [false, true] {
        let mut hash = Sha256::new();
        hash.update(b"ziquid.semantic.owner-consent.v1");
        hash.update(fixture.context.digest());
        hash.update(binding);
        if include_capsule {
            hash.update(capsule);
        }
        let old_domain: [u8; 32] = hash.finalize().into();
        assert!(real.rk().verify(&old_domain, &signature).is_err());
    }
    let mut swapped_p = Zeroizing::new(fixture.pair.unsigned_payment().pczt_bytes().to_vec());
    let mut swapped_q = Zeroizing::new(fixture.q.transaction_bytes().to_vec());
    swapped_p[0] ^= 1;
    swapped_q[0] ^= 1;
    for (p, q) in [
        (swapped_p.as_slice(), fixture.q.transaction_bytes()),
        (fixture.pair.unsigned_payment().pczt_bytes(), swapped_q.as_slice()),
    ] {
        let changed = solver_capsule_commitment(SolverCapsule {
            context: &fixture.context,
            private_packet_binding: &binding,
            capsule_blind: &CAPSULE_BLIND,
            redacted_payment: p,
            recovery_transaction: q,
        }).unwrap();
        assert_ne!(changed, capsule);
        let changed_message = preparation_consent_digest(&fixture.context, &binding, &changed).unwrap();
        assert!(real.rk().verify(&changed_message, &signature).is_err());
    }
}
