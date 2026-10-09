use std::sync::LazyLock;

use ff::PrimeField;
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    Anchor, Note,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{NoteVersion, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
    pczt::{Action, Output, Spend},
    tree::{MerkleHashOrchard, MerklePath},
    primitives::redpallas::VerificationKey,
    value::{NoteValue, ValueCommitment},
};
use pczt::{
    Pczt,
    roles::{creator::Creator, redactor::Redactor, updater::Updater, verifier::Verifier},
};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use zcash_note_encryption::Domain;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317,
    txid::{TxIdDigester, to_txid},
};
use zeroize::Zeroizing;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    memo::MemoBytes,
    value::Zatoshis,
};
use ziquid_proofs::preparation::{
    JOURNAL_DOMAIN, JOURNAL_LEN, PreparationError, PreparationJournal, PreparationWitness,
    verify_preparation,
};
use ziquid_protocol::{
    MAX_QUOTED_RECEIVERS, NativeAmount, SolverCapsule, StatementContext, ValidatedContext,
    input_commitment, note_consumption_tag, payment_commitment, preparation_consent_digest,
};
use ziquid_zcash::{
    ExecutableSelfSpend, IronwoodTransaction, OutputPlan, OwnedInput, PreparationIntent,
    PreparedPair, SourceParameters, prepare,
};

const TARGET: u32 = 4_134_000;
const EXPIRY: u32 = 4_134_040;

// Generated local notes/trees only: not acquired notes, accepted history,
// admissible anchors or deployed program identities. Never sent to a node.
fn input_fixture() -> (OwnedInput, SpendAuthorizingKey) {
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
    let path = MerklePath::from_parts(
        0,
        std::array::from_fn(|i| MerkleHashOrchard::empty_root(Level::from(i as u8))),
    );
    let anchor = path.root(note.commitment().into());
    (
        OwnedInput::new(note, fvk, path, anchor).unwrap(),
        SpendAuthorizingKey::from(&sk),
    )
}

fn source() -> SourceParameters {
    SourceParameters {
        network: Network::TestNetwork,
        target_height: BlockHeight::from(TARGET),
        expiry_height: BlockHeight::from(EXPIRY),
        consensus_branch: BranchId::Nu6_3,
        fee_rule: zip317::FeeRule::standard(),
    }
}

fn context(fee_cap: u64) -> ValidatedContext {
    let mut fields = context_fields(fee_cap);
    let witness = fixture();
    let original = ValidatedContext::decode(&witness.context_bytes).unwrap();
    fields.real_input_commitment = original.context().real_input_commitment;
    fields.source_payment_commitment = original.context().source_payment_commitment;
    fields.consumption_tag = original.context().consumption_tag;
    fields.validate().unwrap()
}

fn context_fields(fee_cap: u64) -> StatementContext {
    StatementContext {
        schema_version: 1,
        source_network: *b"testnet",
        source_pool: *b"ironwood",
        transaction_version: 6,
        consensus_branch: BranchId::Nu6_3.into(),
        source_policy_id: [0x11; 32],
        preparation_program: [0x22; 32],
        settlement_program: [0x33; 32],
        order_id: [0x44; 32],
        consumption_tag: [0x55; 32],
        source_payment_commitment: [0x66; 32],
        real_input_commitment: [0x77; 32],
        source_quoted_amount: 60_000,
        source_fee_cap: fee_cap,
        source_expiry: EXPIRY,
        evm_chain_id: 31_337,
        escrow: [0x88; 20],
        escrow_code_hash: [0x99; 32],
        verifier: [0xaa; 20],
        verifier_code_hash: [0xbb; 32],
        u_payee: [0xcc; 20],
        s_refund: [0xdd; 20],
        native_amount: NativeAmount::from_be_bytes([1; 32]),
    }
}

fn output(address: orchard::Address, value: u64) -> OutputPlan {
    OutputPlan::new(
        address,
        Zatoshis::from_u64(value).unwrap(),
        MemoBytes::empty(),
    )
}

struct PreparedFixture {
    input: OwnedInput,
    ask: SpendAuthorizingKey,
    pair: PreparedPair,
    q: ExecutableSelfSpend,
    witness: PreparationWitness,
}

impl PreparedFixture {
    fn authorize(&self, witness: &mut PreparationWitness) {
        let context = ValidatedContext::decode(&witness.context_bytes).unwrap();
        witness.owner_intent_signature = self.pair.authorize_preparation(
            &self.input, &self.q, PreparationIntent {
                context: &context,
                input_blind: &witness.input_blind,
                payment_blind: &witness.payment_blind,
                receivers: &witness.quoted_receivers,
                preparation_blind: &witness.secret_blind,
                capsule_blind: &witness.capsule_blind,
            }, &self.ask, &mut OsRng,
        ).unwrap();
    }
}

fn make_fixture(three_actions: bool) -> PreparedFixture {
    make_seeded_fixture(three_actions, 12)
}

fn make_seeded_fixture(three_actions: bool, seed: u8) -> PreparedFixture {
    let (input, ask) = input_fixture();
    let fvk = input.full_viewing_key();
    let solver = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
    let payment = if three_actions {
        vec![
            output(solver.address_at(0u32, Scope::External), 60_000),
            output(fvk.address_at(1u32, Scope::Internal), 15_000),
            output(fvk.address_at(2u32, Scope::Internal), 10_000),
        ]
    } else {
        vec![
            output(solver.address_at(0u32, Scope::External), 60_000),
            output(fvk.address_at(1u32, Scope::Internal), 30_000),
        ]
    };
    let recovery = if three_actions {
        vec![
            output(fvk.address_at(3u32, Scope::Internal), 40_000),
            output(fvk.address_at(4u32, Scope::Internal), 30_000),
            output(fvk.address_at(5u32, Scope::Internal), 15_000),
        ]
    } else {
        vec![output(fvk.address_at(2u32, Scope::Internal), 90_000)]
    };
    let pair = prepare(
        &source(),
        &input,
        &payment,
        &recovery,
        &mut ChaCha20Rng::from_seed([seed; 32]),
    )
    .unwrap();
    finish_fixture(input, ask, pair,
        vec![solver.address_at(0u32, Scope::External).to_raw_address_bytes()],
        60_000, if three_actions { 15_000 } else { 10_000 })
}

fn finish_fixture(input: OwnedInput, ask: SpendAuthorizingKey, pair: PreparedPair,
    quoted_receivers: Vec<[u8; 43]>, quoted: u64, fee_cap: u64) -> PreparedFixture
{
    // Genuine Halo2 proof, every dummy/real SpendAuth and binding signature;
    // LazyLock shares this expensive genuine proof across hostile-byte cases.
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let q = pair.finish_recovery(&ask, &pk, &vk).unwrap();
    IronwoodTransaction::parse(q.transaction_bytes(), BranchId::Nu6_3)
        .unwrap()
        .verify_authorization(&vk, &mut ChaCha20Rng::from_seed([21; 32]))
        .unwrap();
    let blind = fresh_blind();
    let capsule_blind = fresh_blind();
    let input_blind = fresh_blind();
    let payment_blind = fresh_blind();
    let mut terms = context_fields(fee_cap);
    terms.source_quoted_amount = quoted;
    open_context(&mut terms, &input, pair.unsigned_payment().effect_id(),
        &input_blind, &payment_blind, &quoted_receivers);
    let mut witness = PreparationWitness {
        context_bytes: terms.validate().unwrap().canonical_bytes(),
        source_target_height: pair.source_target_height(),
        note_recipient: input.note().recipient().to_raw_address_bytes(),
        note_value: input.note().value().inner(),
        note_rho: input.note().rho().to_bytes(),
        note_rseed: *input.note().rseed().as_bytes(),
        full_viewing_key: input.full_viewing_key().to_bytes(),
        merkle_position: input.merkle_path().position(),
        merkle_siblings: input.merkle_path().auth_path().map(|s| s.to_bytes()),
        anchor: input.anchor().to_bytes(),
        private_p_pczt: pair.payout_witness().private_pczt_bytes().to_vec(),
        redacted_p_pczt: pair.unsigned_payment().pczt_bytes().to_vec(),
        private_q_pczt: pair.private_recovery_pczt_bytes().unwrap(),
        q_transaction: q.transaction_bytes().to_vec(),
        secret_blind: blind,
        capsule_blind,
        input_blind,
        payment_blind,
        quoted_receivers,
        owner_intent_signature: [0; 64],
    };
    witness.owner_intent_signature = pair.authorize_preparation(&input, &q,
        PreparationIntent {
            context: &terms.validate().unwrap(),
            input_blind: &witness.input_blind,
            payment_blind: &witness.payment_blind,
            receivers: &witness.quoted_receivers,
            preparation_blind: &witness.secret_blind,
            capsule_blind: &witness.capsule_blind,
        }, &ask, &mut OsRng,
    ).unwrap();
    PreparedFixture { input, ask, pair, q, witness }
}

fn fresh_blind() -> [u8; 32] {
    let mut blind = [0; 32];
    while blind == [0; 32] { OsRng.fill_bytes(&mut blind); }
    blind
}

fn open_context(terms: &mut StatementContext, input: &OwnedInput, effect: [u8; 32],
    input_blind: &[u8; 32], payment_blind: &[u8; 32], receivers: &[[u8; 43]])
{
    let note = input.note();
    let nf = Zeroizing::new(note.nullifier(input.full_viewing_key()).to_bytes());
    let cmx = Zeroizing::new(orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes());
    let fvk = Zeroizing::new(input.full_viewing_key().to_bytes());
    terms.real_input_commitment = input_commitment(input_blind,
        &terms.source_network, &terms.source_pool, &note.recipient().to_raw_address_bytes(),
        note.value().inner(), &note.rho().to_bytes(), note.rseed().as_bytes(), &cmx, &nf).unwrap();
    terms.source_payment_commitment = payment_commitment(payment_blind, &terms.source_network,
        &terms.source_pool, &effect, receivers, terms.source_quoted_amount).unwrap();
    terms.consumption_tag = note_consumption_tag(&terms.source_network, &terms.source_pool,
        terms.evm_chain_id, &terms.escrow, fvk[32..64].try_into().unwrap(), &nf).unwrap();
}

fn make_aggregate_fixture() -> PreparedFixture {
    let (input, ask) = input_fixture();
    let solver = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
    let other = FullViewingKey::from(&SpendingKey::from_bytes([92; 32]).unwrap());
    let first = solver.address_at(0u32, Scope::External);
    let second = other.address_at(1u32, Scope::External);
    let payment = [output(first, 20_000), output(second, 15_000), output(first, 25_000),
        output(input.full_viewing_key().address_at(1u32, Scope::Internal), 20_000)];
    let recovery = [output(input.full_viewing_key().address_at(2u32, Scope::Internal), 90_000)];
    // Select a genuine randomized authoring with a dummy in action zero, rather
    // than mutating/shuffling finished effects or assuming the real spend index.
    let pair = (0..=u8::MAX).find_map(|seed| {
        let pair = prepare(&source(), &input, &payment, &recovery,
            &mut ChaCha20Rng::from_seed([seed; 32])).unwrap();
        let q = Pczt::parse(&pair.private_recovery_pczt_bytes().unwrap()).unwrap();
        let mut dummy_first = false;
        Verifier::new(q).with_ironwood::<(), _>(|bundle| {
            dummy_first = bundle.actions()[0].spend().value().as_ref().unwrap().inner() == 0;
            Ok(())
        }).unwrap().finish();
        dummy_first.then_some(pair)
    }).expect("synthetic authoring must include a dummy-first Q candidate");
    let mut receivers = vec![first.to_raw_address_bytes(), second.to_raw_address_bytes()];
    receivers.sort_unstable();
    finish_fixture(input, ask, pair, receivers, 60_000, 20_000)
}

// Test-only hostile caller: sign exact modified bytes/terms with the actual
// synthetic Q randomized owner key. Production must use checked wallet intent.
fn sign_synthetic_packet(witness: &mut PreparationWitness) {
    let (_, ask) = input_fixture();
    let context = ValidatedContext::decode(&witness.context_bytes).unwrap();
    let message = Zeroizing::new(preparation_consent_digest(&context,
        &witness.preparation_binding().unwrap(), &witness.solver_capsule_commitment().unwrap()).unwrap());
    let mut signature = Zeroizing::new([0; 64]);
    Verifier::new(Pczt::parse(&witness.private_q_pczt).unwrap())
        .with_ironwood::<(), _>(|bundle| {
            let mut real = bundle.actions().iter().filter(|action|
                action.spend().value().as_ref().unwrap().inner() != 0);
            let spend = real.next().unwrap().spend();
            assert!(real.next().is_none());
            let key = ask.randomize(spend.alpha().as_ref().unwrap());
            assert_eq!(&VerificationKey::from(&key), spend.rk());
            let signed = key.sign(OsRng, &*message);
            signature.copy_from_slice(&<[u8; 64]>::from(&signed));
            Ok(())
        }).unwrap().finish();
    witness.owner_intent_signature = *signature;
}

static FIXTURE: LazyLock<PreparedFixture> = LazyLock::new(|| make_fixture(false));

fn fixture() -> &'static PreparationWitness {
    &FIXTURE.witness
}

#[test]
fn genuine_padded_authoring_and_completed_q_bind_the_exact_context_privately() {
    let witness = fixture();
    let journal = verify_preparation(witness).unwrap();
    let encoded = journal.encode();
    assert_eq!(&encoded[..JOURNAL_DOMAIN.len()], b"ziquid.preparation.v3");
    assert_eq!(
        &encoded[JOURNAL_DOMAIN.len()..JOURNAL_DOMAIN.len() + 32],
        &ValidatedContext::decode(&witness.context_bytes).unwrap().digest()
    );
    let wire = witness.encode_private().unwrap();
    let decoded = PreparationWitness::decode_private(&wire).unwrap();
    assert_eq!(verify_preparation(&decoded).unwrap(), journal);
    let mut changed = witness.clone();
    changed.secret_blind = fresh_blind();
    assert_eq!(verify_preparation(&changed), Err(PreparationError::OwnerConsent));
    FIXTURE.authorize(&mut changed);
    let changed_journal = verify_preparation(&changed).unwrap();
    assert_ne!(changed_journal, journal);
    assert_eq!(changed_journal.consumption_tag(), journal.consumption_tag());
}

#[test]
fn capsule_only_reblinding_keeps_private_binding_and_tag_but_requires_fresh_consent() {
    let mut witness = fixture().clone();
    let original = verify_preparation(&witness).unwrap();
    let context = ValidatedContext::decode(&witness.context_bytes).unwrap();
    let old_consent = preparation_consent_digest(&context, &original.packet_binding(),
        &original.solver_capsule_commitment()).unwrap();
    witness.capsule_blind = fresh_blind();
    assert_eq!(witness.preparation_binding().unwrap(), original.packet_binding());
    let capsule = witness.solver_capsule_commitment().unwrap();
    assert_ne!(capsule, original.solver_capsule_commitment());
    assert_ne!(preparation_consent_digest(&context, &original.packet_binding(), &capsule).unwrap(), old_consent);
    assert_eq!(verify_preparation(&witness), Err(PreparationError::OwnerConsent));
    FIXTURE.authorize(&mut witness);
    let journal = verify_preparation(&witness).unwrap();
    assert_eq!(journal.context_digest(), original.context_digest());
    assert_eq!(journal.packet_binding(), original.packet_binding());
    assert_eq!(journal.consumption_tag(), original.consumption_tag());
    assert_eq!(journal.solver_capsule_commitment(), capsule);
    let binding = journal.packet_binding();
    assert_eq!(original.check_solver_capsule(SolverCapsule {
        context: &context, private_packet_binding: &binding, capsule_blind: &witness.capsule_blind,
        redacted_payment: &witness.redacted_p_pczt, recovery_transaction: &witness.q_transaction,
    }), Err(PreparationError::SolverCapsule));
    assert_eq!(verify_preparation(&PreparationWitness::decode_private(&witness.encode_private().unwrap()).unwrap()).unwrap(), journal);
}


#[test]
fn actual_three_action_authoring_uses_the_actual_zip317_fee() {
    static THREE: LazyLock<PreparedFixture> = LazyLock::new(|| make_fixture(true));
    let witness = &THREE.witness;
    assert_eq!(
        Pczt::parse(&witness.private_p_pczt)
            .unwrap()
            .ironwood()
            .actions()
            .len(),
        3
    );
    assert!(verify_preparation(witness).is_ok());
    let mut underfunded_cap = witness.clone();
    let mut terms = *ValidatedContext::decode(&witness.context_bytes).unwrap().context();
    terms.source_fee_cap = 10_000;
    underfunded_cap.context_bytes = terms.validate().unwrap().canonical_bytes();
    sign_synthetic_packet(&mut underfunded_cap);
    assert!(verify_preparation(&underfunded_cap).is_err());
}

#[test]
fn hostile_note_owner_path_and_anchor_cannot_replace_the_private_input() {
    let original = fixture();
    let mut changed = original.clone();
    changed.full_viewing_key =
        FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap()).to_bytes();
    assert!(verify_preparation(&changed).is_err());
    changed = original.clone();
    changed.note_value += 1;
    assert!(verify_preparation(&changed).is_err());
    changed = original.clone();
    changed.note_rseed[0] ^= 1;
    assert!(verify_preparation(&changed).is_err());
    changed = original.clone();
    changed.merkle_position ^= 1;
    assert!(verify_preparation(&changed).is_err());
    changed = original.clone();
    changed.merkle_siblings[0] = [0; 32];
    assert!(verify_preparation(&changed).is_err());
    changed = original.clone();
    changed.anchor = Anchor::empty_tree().to_bytes();
    assert!(verify_preparation(&changed).is_err());
}

#[test]
fn missing_raw_anchors_and_positive_spend_paths_are_not_typed_placeholders() {
    for select in 0..3 {
        let mut changed = fixture().clone();
        let bytes = match select {
            0 => &mut changed.private_p_pczt,
            1 => &mut changed.redacted_p_pczt,
            _ => &mut changed.private_q_pczt,
        };
        *bytes = Redactor::new(Pczt::parse(bytes).unwrap())
            .redact_ironwood_with(|mut bundle| bundle.clear_anchor())
            .finish()
            .serialize()
            .unwrap();
        assert!(verify_preparation(&changed).is_err());
    }
    let mut changed = fixture().clone();
    changed.private_p_pczt = Redactor::new(Pczt::parse(&changed.private_p_pczt).unwrap())
        .redact_ironwood_with(|mut bundle| {
            bundle.redact_actions(|mut action| action.clear_spend_witness());
        })
        .finish()
        .serialize()
        .unwrap();
    assert!(verify_preparation(&changed).is_err());
    let mut changed = fixture().clone();
    let wrong = MerklePath::from_parts(
        1,
        std::array::from_fn(|i| MerkleHashOrchard::empty_root(Level::from(i as u8))),
    );
    changed.private_q_pczt = Updater::new(Pczt::parse(&changed.private_q_pczt).unwrap())
        .set_ironwood_spend_witnesses([(0, wrong.clone()), (1, wrong)])
        .unwrap()
        .finish()
        .serialize()
        .unwrap();
    assert!(verify_preparation(&changed).is_err());
}

#[test]
fn canonical_private_and_packet_encodings_reject_truncation_and_suffixes() {
    let encoded = fixture().encode_private().unwrap();
    assert!(PreparationWitness::decode_private(&encoded[..encoded.len() - 1]).is_err());
    let mut suffix = Zeroizing::new(Vec::with_capacity(encoded.len() + 1));
    suffix.extend_from_slice(&encoded);
    suffix.push(0);
    assert!(PreparationWitness::decode_private(&suffix).is_err());
    let mut oversized = encoded;
    let length_at = oversized.len() - fixture().q_transaction.len() - 4;
    oversized[length_at..length_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(PreparationWitness::decode_private(&oversized).is_err());
    for select in 0..4 {
        let mut changed = fixture().clone();
        let bytes = match select {
            0 => &mut changed.private_p_pczt,
            1 => &mut changed.redacted_p_pczt,
            2 => &mut changed.private_q_pczt,
            _ => &mut changed.q_transaction,
        };
        bytes.push(0);
        assert!(verify_preparation(&changed).is_err());
    }
}

#[test]
fn source_policy_shape_branch_height_expiry_fee_and_blind_are_enforced() {
    let mut changed = fixture().clone();
    changed.context_bytes = context(9_999).canonical_bytes();
    assert!(verify_preparation(&changed).is_err());
    let mut fields = *context(10_000).context();
    fields.consensus_branch = BranchId::Nu6_2.into();
    changed.context_bytes = fields.validate().unwrap().canonical_bytes();
    assert!(verify_preparation(&changed).is_err());
    fields = *context(10_000).context();
    fields.source_expiry += 1;
    changed.context_bytes = fields.validate().unwrap().canonical_bytes();
    assert!(verify_preparation(&changed).is_err());
    changed = fixture().clone();
    changed.source_target_height = 1;
    assert!(verify_preparation(&changed).is_err());
    changed.source_target_height = EXPIRY + 1;
    assert!(verify_preparation(&changed).is_err());
    changed = fixture().clone();
    changed.context_bytes[23] ^= 1; // testnet byte, not a digest-only context
    assert!(verify_preparation(&changed).is_err());
    changed = fixture().clone();
    changed.secret_blind = [0; 32];
    assert!(verify_preparation(&changed).is_err());
    for height in [0, 4_133_999, 4_465_026, 500_000_000, u32::MAX] {
        let mut invalid = fixture().clone();
        invalid.source_target_height = height;
        assert_eq!(verify_preparation(&invalid), Err(PreparationError::Source));
        assert!(invalid.encode_private().is_err());
    }
    for expiry in [0, TARGET - 1, 4_465_026, 499_999_999, 500_000_000, u32::MAX] {
        let mut invalid = fixture().clone();
        let mut bytes = invalid.context_bytes;
        const EXPIRY_AT: usize = 21 + 2 + 7 + 8 + 4 + 4 + 7 * 32 + 8 + 8;
        bytes[EXPIRY_AT..EXPIRY_AT + 4].copy_from_slice(&expiry.to_be_bytes());
        invalid.context_bytes = bytes;
        assert!(verify_preparation(&invalid).is_err());
        assert!(invalid.encode_private().is_err());
    }
}

#[test]
fn every_final_q_spendauth_and_binding_signature_is_required() {
    let actions = Pczt::parse(&fixture().private_q_pczt)
        .unwrap()
        .ironwood()
        .actions()
        .len();
    for signature in 0..=actions {
        let mut changed = fixture().clone();
        let at = changed.q_transaction.len() - 64 * (actions + 1) + 64 * signature;
        changed.q_transaction[at..at + 64].fill(0);
        sign_synthetic_packet(&mut changed);
        assert_eq!(verify_preparation(&changed), Err(PreparationError::Signature));
    }
}

// Mutate actual upstream typed builder parts, never a fake PCZT or fake Q.
fn changed_private_p(change: impl FnOnce(&mut orchard::pczt::Bundle)) -> Vec<u8> {
    let (input, _) = input_fixture();
    changed_private_p_outputs(&[output(input.full_viewing_key().address_at(2u32, Scope::Internal), 90_000)], change)
}

fn changed_private_p_outputs(outputs: &[OutputPlan], change: impl FnOnce(&mut orchard::pczt::Bundle)) -> Vec<u8> {
    let (input, _) = input_fixture();
    let mut builder = Builder::new(
        Network::TestNetwork,
        BlockHeight::from(TARGET),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(input.anchor()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    .with_expiry_height(BlockHeight::from(EXPIRY));
    builder
        .add_ironwood_spend::<zip317::FeeError>(
            input.full_viewing_key().clone(),
            *input.note(),
            input.merkle_path().clone(),
        )
        .unwrap();
    for output in outputs {
        builder.add_ironwood_output::<zip317::FeeError>(
            None, output.recipient(), output.value(), output.memo().clone(),
        ).unwrap();
    }
    let mut built = builder
        .build_for_pczt(
            ChaCha20Rng::from_seed([57; 32]),
            &zip317::FeeRule::standard(),
        )
        .unwrap();
    change(built.pczt_parts.ironwood.as_mut().unwrap());
    Creator::build_from_parts(built.pczt_parts)
        .unwrap()
        .serialize()
        .unwrap()
}

fn redacted(bytes: &[u8]) -> Vec<u8> {
    Redactor::new(Pczt::parse(bytes).unwrap())
        .redact_ironwood_with(|mut bundle| {
            bundle.clear_bsk();
            bundle.clear_zkproof();
            bundle.redact_actions(|mut action| {
                action.clear_spend_auth_sig();
                action.clear_spend_recipient();
                action.clear_spend_value();
                action.clear_spend_rho();
                action.clear_spend_rseed();
                action.clear_spend_fvk();
                action.clear_spend_witness();
                action.clear_spend_alpha();
                action.clear_spend_dummy_sk();
                action.clear_rcv();
                action.clear_output_recipient();
                action.clear_output_value();
                action.clear_output_rseed();
                action.clear_output_ock();
            });
        })
        .finish()
        .serialize()
        .unwrap()
}

fn copy_spend(spend: &Spend, value: u64, nf: [u8; 32]) -> Spend {
    Spend::parse(
        nf,
        spend.rk().into(),
        spend.spend_auth_sig().as_ref().map(|s| s.into()),
        spend.recipient().as_ref().map(|r| r.to_raw_address_bytes()),
        Some(value),
        spend.rho().as_ref().map(|r| r.to_bytes()),
        spend.rseed().as_ref().map(|r| *r.as_bytes()),
        spend.fvk().as_ref().map(|f| f.to_bytes()),
        spend
            .witness()
            .as_ref()
            .map(|p| (p.position(), p.auth_path().map(|s| s.to_bytes()))),
        spend.alpha().as_ref().map(|a| a.to_repr()),
        None,
        spend.dummy_sk().as_ref().map(|s| *s.to_bytes()),
        *spend.note_version(),
        Default::default(),
    )
    .unwrap()
}

fn copy_output(
    action: &Action,
    nf: orchard::note::Nullifier,
    cmx: [u8; 32],
    epk: [u8; 32],
    ciphertext: Vec<u8>,
) -> Output {
    let output = action.output();
    Output::parse(
        nf,
        cmx,
        epk,
        ciphertext,
        output.encrypted_note().out_ciphertext.to_vec(),
        output
            .recipient()
            .as_ref()
            .map(|r| r.to_raw_address_bytes()),
        output.value().as_ref().map(|v| v.inner()),
        output.rseed().as_ref().map(|r| *r.as_bytes()),
        None,
        None,
        None,
        NoteVersion::V3,
        Default::default(),
    )
    .unwrap()
}

#[test]
fn matching_export_still_rejects_second_action_recipient_ciphertext_corruption() {
    let (input, _) = input_fixture();
    let solver = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
    let outputs = [output(solver.address_at(0u32, Scope::External), 60_000),
        output(input.full_viewing_key().address_at(1u32, Scope::Internal), 30_000)];
    let rebind = |witness: &mut PreparationWitness| {
        witness.redacted_p_pczt = redacted(&witness.private_p_pczt);
        let effects = Pczt::parse(&witness.private_p_pczt).unwrap().into_effects().unwrap();
        let effect = to_txid(effects.version(), effects.consensus_branch_id(),
            &effects.digest(TxIdDigester)).into();
        let mut terms = *ValidatedContext::decode(&witness.context_bytes).unwrap().context();
        open_context(&mut terms, &input, effect, &witness.input_blind,
            &witness.payment_blind, &witness.quoted_receivers);
        witness.context_bytes = terms.validate().unwrap().canonical_bytes();
        sign_synthetic_packet(witness);
    };
    let mut changed = fixture().clone();
    changed.private_p_pczt = changed_private_p_outputs(&outputs, |_| {});
    rebind(&mut changed);
    verify_preparation(&changed).unwrap();
    changed.private_p_pczt = changed_private_p_outputs(&outputs, |bundle| {
        let action = &bundle.actions()[1];
        let mut ciphertext = action.output().encrypted_note().enc_ciphertext.to_vec();
        ciphertext[579] ^= 1;
        let output = copy_output(
            action,
            *action.spend().nullifier(),
            action.output().cmx().to_bytes(),
            action.output().encrypted_note().epk_bytes,
            ciphertext,
        );
        let replacement = Action::parse(
            action.cv_net().to_bytes(),
            copy_spend(
                action.spend(),
                action.spend().value().unwrap().inner(),
                action.spend().nullifier().to_bytes(),
            ),
            output,
            action.rcv().as_ref().map(|r| r.to_bytes()),
        )
        .unwrap();
        bundle.actions_mut()[1] = replacement;
    });
    rebind(&mut changed);
    assert_eq!(verify_preparation(&changed), Err(PreparationError::Ciphertext));
}

#[test]
fn valid_openings_cannot_turn_a_dummy_marker_into_a_second_positive_input() {
    let mut changed = fixture().clone();
    changed.private_p_pczt = changed_private_p(|bundle| {
        let index = bundle
            .actions()
            .iter()
            .position(|a| a.spend().value().unwrap().inner() == 0)
            .unwrap();
        let action = &bundle.actions()[index];
        let spend = action.spend();
        let note = Note::from_parts(
            spend.recipient().unwrap(),
            NoteValue::from_raw(1),
            spend.rho().unwrap(),
            spend.rseed().unwrap(),
            NoteVersion::V3,
        )
        .unwrap();
        let nf = note.nullifier(spend.fvk().as_ref().unwrap());
        let old = action.output();
        let output_note = Note::from_parts(
            old.recipient().unwrap(),
            old.value().unwrap(),
            Rho::from_bytes(&nf.to_bytes()).unwrap(),
            old.rseed().unwrap(),
            NoteVersion::V3,
        )
        .unwrap();
        let encryption =
            IronwoodNoteEncryption::new(None, output_note, *MemoBytes::empty().as_array());
        let output = copy_output(
            action,
            nf,
            orchard::note::ExtractedNoteCommitment::from(output_note.commitment()).to_bytes(),
            IronwoodDomain::epk_bytes(encryption.epk()).0,
            encryption.encrypt_note_plaintext().to_vec(),
        );
        let rcv = action.rcv().as_ref().unwrap();
        let cv =
            ValueCommitment::derive(NoteValue::from_raw(1) - old.value().unwrap(), rcv.clone());
        let replacement = Action::parse(
            cv.to_bytes(),
            copy_spend(spend, 1, nf.to_bytes()),
            output,
            Some(rcv.to_bytes()),
        )
        .unwrap();
        replacement.verify_cv_net().unwrap();
        replacement.spend().verify_nullifier(None).unwrap();
        replacement.spend().verify_rk(None).unwrap();
        replacement
            .output()
            .verify_note_commitment(replacement.spend())
            .unwrap();
        bundle.actions_mut()[index] = replacement;
    });
    changed.redacted_p_pczt = redacted(&changed.private_p_pczt);
    assert!(verify_preparation(&changed).is_err());
}

#[test]
fn exact_p_export_and_private_q_cannot_be_swapped_for_other_effects() {
    let alternate = Zeroizing::new(changed_private_p(|_| {}));
    let mut changed = fixture().clone();
    changed.private_p_pczt = alternate.to_vec();
    assert!(verify_preparation(&changed).is_err());
    changed = fixture().clone();
    changed.redacted_p_pczt = redacted(&alternate);
    assert!(verify_preparation(&changed).is_err());
    changed = fixture().clone();
    changed.private_q_pczt = alternate.to_vec();
    assert!(verify_preparation(&changed).is_err());
}

#[test]
fn private_preparation_rejects_fabricated_input_payment_and_consumption_bindings() {
    for field in 0..4 {
        let mut witness = fixture().clone();
        let mut context = *ValidatedContext::decode(&witness.context_bytes).unwrap().context();
        match field {
            0 => context.real_input_commitment[0] ^= 1,
            1 => context.source_payment_commitment[0] ^= 1,
            2 => context.consumption_tag[0] ^= 1,
            _ => context.source_quoted_amount += 1,
        }
        witness.context_bytes = context.validate().unwrap().canonical_bytes();
        assert!(verify_preparation(&witness).is_err(), "fabricated semantic binding {field}");
        sign_synthetic_packet(&mut witness);
        let expected = match field {
            0 => PreparationError::InputCommitment,
            1 | 3 => PreparationError::PaymentCommitment,
            _ => PreparationError::ConsumptionTag,
        };
        assert_eq!(verify_preparation(&witness), Err(expected),
            "fresh real consent must not excuse fabricated semantic binding {field}");
    }
}

#[test]
fn unsigned_bootstrap_is_pure_but_complete_relation_requires_distinct_owner_consent() {
    let mut witness = fixture().clone();
    let binding = witness.preparation_binding().unwrap();
    let capsule = witness.solver_capsule_commitment().unwrap();
    witness.owner_intent_signature = [0; 64];
    assert_eq!(witness.preparation_binding().unwrap(), binding);
    assert_eq!(witness.solver_capsule_commitment().unwrap(), capsule);
    let encoded = witness.encode_private().unwrap();
    let decoded = PreparationWitness::decode_private(&encoded).unwrap();
    assert_eq!(decoded.preparation_binding().unwrap(), binding);
    assert_eq!(decoded.solver_capsule_commitment().unwrap(), capsule);
    assert_eq!(verify_preparation(&decoded), Err(PreparationError::OwnerConsent));
    FIXTURE.authorize(&mut witness);
    let journal = verify_preparation(&witness).unwrap();
    assert_eq!(journal.packet_binding(), binding);
    assert_eq!(journal.solver_capsule_commitment(), capsule);
    assert_eq!(journal.context_digest(), ValidatedContext::decode(&witness.context_bytes).unwrap().digest());

    let q = IronwoodTransaction::parse(&witness.q_transaction, BranchId::Nu6_3).unwrap();
    let real_nf = FIXTURE.input.note().nullifier(FIXTURE.input.full_viewing_key());
    let real = q.transaction().ironwood_bundle().unwrap().actions().iter()
        .find(|action| action.nullifier() == &real_nf).unwrap();
    witness.owner_intent_signature = real.authorization().into();
    assert_eq!(verify_preparation(&witness), Err(PreparationError::OwnerConsent));
    witness.owner_intent_signature = fixture().owner_intent_signature;
    witness.owner_intent_signature[63] ^= 1;
    assert_eq!(verify_preparation(&witness), Err(PreparationError::OwnerConsent));
}

#[test]
fn owner_term_changes_need_fresh_real_consent_but_do_not_rekey_note_consumption() {
    let original = verify_preparation(fixture()).unwrap();
    for field in 0..10 {
        let mut witness = fixture().clone();
        let mut terms = *ValidatedContext::decode(&witness.context_bytes).unwrap().context();
        match field {
            0 => terms.order_id[0] ^= 1,
            1 => terms.native_amount = NativeAmount::from_be_bytes([2; 32]),
            2 => terms.u_payee[0] ^= 1,
            3 => terms.s_refund[0] ^= 1,
            4 => terms.preparation_program[0] ^= 1,
            5 => terms.settlement_program[0] ^= 1,
            6 => terms.source_policy_id[0] ^= 1,
            7 => terms.escrow_code_hash[0] ^= 1,
            8 => terms.verifier[0] ^= 1,
            _ => terms.verifier_code_hash[0] ^= 1,
        }
        witness.context_bytes = terms.validate().unwrap().canonical_bytes();
        assert_eq!(verify_preparation(&witness), Err(PreparationError::OwnerConsent));
        FIXTURE.authorize(&mut witness);
        let journal = verify_preparation(&witness).unwrap();
        assert_ne!(journal.context_digest(), original.context_digest());
        assert_ne!(journal.packet_binding(), original.packet_binding());
        assert_eq!(journal.consumption_tag(), original.consumption_tag());
    }
    for field in 0..2 {
        let mut witness = fixture().clone();
        let mut terms = *ValidatedContext::decode(&witness.context_bytes).unwrap().context();
        if field == 0 { terms.evm_chain_id += 1; } else { terms.escrow[0] ^= 1; }
        open_context(&mut terms, &FIXTURE.input, FIXTURE.pair.unsigned_payment().effect_id(),
            &witness.input_blind, &witness.payment_blind, &witness.quoted_receivers);
        witness.context_bytes = terms.validate().unwrap().canonical_bytes();
        assert_eq!(verify_preparation(&witness), Err(PreparationError::OwnerConsent));
        FIXTURE.authorize(&mut witness);
        assert_ne!(verify_preparation(&witness).unwrap().consumption_tag(), original.consumption_tag());
    }
    let mut witness = fixture().clone();
    witness.input_blind = fresh_blind();
    witness.payment_blind = fresh_blind();
    witness.secret_blind = fresh_blind();
    let mut terms = *ValidatedContext::decode(&witness.context_bytes).unwrap().context();
    open_context(&mut terms, &FIXTURE.input, FIXTURE.pair.unsigned_payment().effect_id(),
        &witness.input_blind, &witness.payment_blind, &witness.quoted_receivers);
    witness.context_bytes = terms.validate().unwrap().canonical_bytes();
    assert_eq!(verify_preparation(&witness), Err(PreparationError::OwnerConsent));
    FIXTURE.authorize(&mut witness);
    assert_eq!(verify_preparation(&witness).unwrap().consumption_tag(), original.consumption_tag());
}

#[test]
fn a_real_signature_under_padding_dummy_rk_cannot_authorize_owner_intent() {
    let mut witness = fixture().clone();
    let context = ValidatedContext::decode(&witness.context_bytes).unwrap();
    let message = Zeroizing::new(preparation_consent_digest(&context,
        &witness.preparation_binding().unwrap(), &witness.solver_capsule_commitment().unwrap()).unwrap());
    let mut signature = Zeroizing::new([0; 64]);
    Verifier::new(Pczt::parse(&witness.private_q_pczt).unwrap())
        .with_ironwood::<(), _>(|bundle| {
            let spend = bundle.actions().iter().find(|action|
                action.spend().value().as_ref().unwrap().inner() == 0).unwrap().spend();
            let ask = SpendAuthorizingKey::from(spend.dummy_sk().as_ref().unwrap());
            let key = ask.randomize(spend.alpha().as_ref().unwrap());
            let rk = VerificationKey::from(&key);
            assert_eq!(&rk, spend.rk());
            let signed = key.sign(OsRng, &*message);
            rk.verify(&*message, &signed).unwrap();
            signature.copy_from_slice(&<[u8; 64]>::from(&signed));
            Ok(())
        }).unwrap().finish();
    witness.owner_intent_signature = *signature;
    assert_eq!(verify_preparation(&witness), Err(PreparationError::OwnerConsent));
}

#[test]
fn bounded_journal_exposes_only_four_digests_and_private_diagnostics_are_redacted() {
    let witness = fixture();
    let journal = verify_preparation(witness).unwrap();
    let wire = journal.encode();
    assert_eq!(wire.len(), JOURNAL_LEN);
    assert_eq!(wire.len(), 149);
    assert_eq!(&wire[JOURNAL_DOMAIN.len()..JOURNAL_DOMAIN.len() + 32], &journal.context_digest());
    assert_eq!(&wire[JOURNAL_DOMAIN.len() + 32..JOURNAL_DOMAIN.len() + 64], &journal.packet_binding());
    assert_eq!(&wire[JOURNAL_DOMAIN.len() + 64..JOURNAL_DOMAIN.len() + 96], &journal.consumption_tag());
    assert_eq!(&wire[JOURNAL_DOMAIN.len() + 96..], &journal.solver_capsule_commitment());
    let nf = FIXTURE.input.note().nullifier(FIXTURE.input.full_viewing_key()).to_bytes();
    for private in [&nf[..], &witness.note_recipient[..], &witness.full_viewing_key[..],
        &witness.owner_intent_signature[..], &witness.secret_blind[..], &witness.capsule_blind[..],
        &witness.input_blind[..], &witness.payment_blind[..]] {
        assert!(!wire.windows(private.len()).any(|bytes| bytes == private));
    }
    let q = IronwoodTransaction::parse(&witness.q_transaction, BranchId::Nu6_3).unwrap();
    for action in q.transaction().ironwood_bundle().unwrap().actions().iter() {
        let rk: [u8; 32] = action.rk().into();
        assert!(!wire.windows(32).any(|bytes| bytes == rk));
    }
    for receiver in &witness.quoted_receivers {
        assert!(!wire.windows(43).any(|bytes| bytes == receiver));
    }
    let diagnostic = format!("{witness:?}");
    assert!(!diagnostic.contains("60000") && !diagnostic.contains("100000"));
    assert!(diagnostic.len() < witness.note_recipient.len());
    for error in [PreparationError::Blind, PreparationError::ReceiverSet,
        PreparationError::InputCommitment, PreparationError::PaymentCommitment,
        PreparationError::ConsumptionTag, PreparationError::OwnerConsent,
        PreparationError::PacketBinding, PreparationError::SolverCapsule] {
        let message = error.to_string();
        for private in ["60000", "100000", "[8, 8", "[91, 91"] {
            assert!(!message.contains(private));
        }
    }
}

#[test]
fn every_receiver_output_is_counted_with_duplicates_in_effects_and_dummy_first_q() {
    static AGGREGATE: LazyLock<PreparedFixture> = LazyLock::new(make_aggregate_fixture);
    let original = verify_preparation(&AGGREGATE.witness).unwrap();
    assert_eq!(Pczt::parse(&AGGREGATE.witness.private_p_pczt).unwrap().ironwood().actions().len(), 4);
    Verifier::new(Pczt::parse(&AGGREGATE.witness.private_q_pczt).unwrap())
        .with_ironwood::<(), _>(|bundle| {
            assert_eq!(bundle.actions()[0].spend().value().as_ref().unwrap().inner(), 0);
            Ok(())
        }).unwrap().finish();
    assert_eq!(original.consumption_tag(), verify_preparation(fixture()).unwrap().consumption_tag());

    // Same authentic input but fresh P/Q shuffle/padding/rk/proof/packet cannot
    // choose a fresh consumption identity. Both fixtures have complete consent.
    assert_ne!(AGGREGATE.witness.redacted_p_pczt, fixture().redacted_p_pczt);
    let solver = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
    for receiver in &AGGREGATE.witness.quoted_receivers {
        let total = if *receiver == solver.address_at(0u32, Scope::External).to_raw_address_bytes() { 45_000 } else { 15_000 };
        let mut witness = AGGREGATE.witness.clone();
        witness.quoted_receivers = vec![*receiver];
        witness.payment_blind = fresh_blind();
        let mut terms = *ValidatedContext::decode(&witness.context_bytes).unwrap().context();
        terms.source_quoted_amount = total;
        open_context(&mut terms, &AGGREGATE.input, AGGREGATE.pair.unsigned_payment().effect_id(),
            &witness.input_blind, &witness.payment_blind, &witness.quoted_receivers);
        witness.context_bytes = terms.validate().unwrap().canonical_bytes();
        assert_eq!(verify_preparation(&witness), Err(PreparationError::OwnerConsent));
        AGGREGATE.authorize(&mut witness);
        assert_eq!(verify_preparation(&witness).unwrap().consumption_tag(), original.consumption_tag());
        terms.source_quoted_amount = total + 1;
        open_context(&mut terms, &AGGREGATE.input, AGGREGATE.pair.unsigned_payment().effect_id(),
            &witness.input_blind, &witness.payment_blind, &witness.quoted_receivers);
        witness.context_bytes = terms.validate().unwrap().canonical_bytes();
        sign_synthetic_packet(&mut witness);
        assert_eq!(verify_preparation(&witness), Err(PreparationError::PaymentCommitment));
    }
}

#[test]
fn private_receivers_and_blinds_reject_noncanonical_invalid_or_owner_known_destinations() {
    let original = fixture();
    for case in 0..6 {
        let mut witness = original.clone();
        match case {
            0 => witness.quoted_receivers.clear(),
            1 => witness.quoted_receivers.push(witness.quoted_receivers[0]),
            2 => witness.quoted_receivers = vec![[0xff; 43]],
            3 => witness.quoted_receivers = vec![witness.quoted_receivers[0]; MAX_QUOTED_RECEIVERS + 1],
            4 => {
                let solver = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
                witness.quoted_receivers = (0u32..2).map(|i| solver.address_at(i, Scope::External)
                    .to_raw_address_bytes()).collect();
                witness.quoted_receivers.sort_unstable();
                witness.quoted_receivers.reverse();
            },
            _ => witness.input_blind = witness.payment_blind,
        }
        let expected = if case == 5 { PreparationError::Blind } else { PreparationError::ReceiverSet };
        assert_eq!(verify_preparation(&witness), Err(expected));
        assert!(matches!(witness.encode_private(), Err(error) if error == expected));
    }
    for select in 0..4 {
        let mut witness = original.clone();
        match select { 0 => witness.input_blind = [0; 32], 1 => witness.payment_blind = [0; 32],
            2 => witness.secret_blind = [0; 32], _ => witness.capsule_blind = [0; 32] }
        assert_eq!(verify_preparation(&witness), Err(PreparationError::Blind));
    }
    let mut witness = original.clone();
    witness.quoted_receivers = vec![FIXTURE.input.full_viewing_key().address_at(1u32, Scope::Internal)
        .to_raw_address_bytes()];
    let mut terms = *ValidatedContext::decode(&witness.context_bytes).unwrap().context();
    terms.source_quoted_amount = 30_000;
    open_context(&mut terms, &FIXTURE.input, FIXTURE.pair.unsigned_payment().effect_id(),
        &witness.input_blind, &witness.payment_blind, &witness.quoted_receivers);
    witness.context_bytes = terms.validate().unwrap().canonical_bytes();
    sign_synthetic_packet(&mut witness);
    assert_eq!(verify_preparation(&witness), Err(PreparationError::Ownership));
}

#[test]
fn private_capsule_blind_rejects_zero_or_any_reused_user_blind() {
    let original = fixture();
    let encoded = original.encode_private().unwrap();
    // Literal v3 offset is independently specified, not derived by the codec.
    const CAPSULE_AT: usize = 1810;
    for blind in [[0; 32], original.secret_blind, original.input_blind, original.payment_blind] {
        let mut witness = original.clone();
        witness.capsule_blind = blind;
        assert_eq!(verify_preparation(&witness), Err(PreparationError::Blind));
        assert_eq!(witness.solver_capsule_commitment(), Err(PreparationError::Blind));
        assert_eq!(witness.encode_private().unwrap_err(), PreparationError::Blind);
        let mut wire = encoded.clone();
        wire[CAPSULE_AT..CAPSULE_AT + 32].copy_from_slice(&blind);
        assert_eq!(PreparationWitness::decode_private(&wire).unwrap_err(), PreparationError::Blind);
    }
}


#[test]
fn v3_private_codec_checks_all_receivers_fixed_fields_and_full_exhaustion() {
    const FIXED_AT_RECEIVERS: usize = b"ziquid.preparation.private.v3".len()
        + ziquid_protocol::CONTEXT_ENCODED_LEN + 4 + 43 + 8 + 32 + 32 + 96 + 4
        + 32 * 32 + 32 + 32 + 32 + 32 + 32 + 64;
    let original = fixture().encode_private().unwrap();
    assert_eq!(&original[1810..1842], &fixture().capsule_blind);
    assert_eq!(&original[1842..1874], &fixture().input_blind);
    assert_eq!(&original[1874..1906], &fixture().payment_blind);
    assert_eq!(&original[1906..1970], &fixture().owner_intent_signature);
    for count in [0u16, 65, u16::MAX] {
        let mut wire = original.clone();
        wire[FIXED_AT_RECEIVERS..FIXED_AT_RECEIVERS + 2].copy_from_slice(&count.to_le_bytes());
        assert_eq!(PreparationWitness::decode_private(&wire).unwrap_err(), PreparationError::ReceiverSet);
    }
    let mut invalid = original.clone();
    invalid[FIXED_AT_RECEIVERS + 2..FIXED_AT_RECEIVERS + 2 + 43].fill(0xff);
    assert_eq!(PreparationWitness::decode_private(&invalid).unwrap_err(), PreparationError::ReceiverSet);
    for end in [FIXED_AT_RECEIVERS - 64, FIXED_AT_RECEIVERS - 1, FIXED_AT_RECEIVERS,
        FIXED_AT_RECEIVERS + 2, FIXED_AT_RECEIVERS + 44, original.len() - 1] {
        assert!(PreparationWitness::decode_private(&original[..end]).is_err());
    }
    for version in *b"124" {
        let mut unsupported = original.clone();
        unsupported[b"ziquid.preparation.private.v".len()] = version;
        assert_eq!(PreparationWitness::decode_private(&unsupported).unwrap_err(), PreparationError::Encoding);
    }
    // Bound the list before copying it, and reject duplicates/unordered valid
    // addresses even when all four blob frames are otherwise complete.
    let solver = FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap());
    let mut receivers: Vec<_> = (0u32..64).map(|i| solver.address_at(i, Scope::External)
        .to_raw_address_bytes()).collect();
    receivers.sort_unstable();
    let mut expanded = fixture().clone();
    expanded.quoted_receivers = receivers;
    let expanded = expanded.encode_private().unwrap();
    assert_eq!(PreparationWitness::decode_private(&expanded).unwrap().quoted_receivers.len(), 64);
    let mut duplicate = expanded.clone();
    let first = Zeroizing::new(<[u8; 43]>::try_from(&duplicate[FIXED_AT_RECEIVERS + 2..FIXED_AT_RECEIVERS + 45]).unwrap());
    duplicate[FIXED_AT_RECEIVERS + 45..FIXED_AT_RECEIVERS + 88].copy_from_slice(&*first);
    assert_eq!(PreparationWitness::decode_private(&duplicate).unwrap_err(), PreparationError::ReceiverSet);
    let mut unordered = expanded;
    let at = FIXED_AT_RECEIVERS + 2;
    for index in 0..43 { unordered.swap(at + index, at + 43 + index); }
    assert_eq!(PreparationWitness::decode_private(&unordered).unwrap_err(), PreparationError::ReceiverSet);
}


#[test]
fn solver_receives_strict_public_journal_not_user_private_openings() {
    let journal = verify_preparation(fixture()).unwrap();
    let wire = journal.encode();
    assert_eq!(PreparationJournal::decode(&wire).unwrap(), journal);
    for end in 0..wire.len() {
        assert_eq!(PreparationJournal::decode(&wire[..end]), Err(PreparationError::Encoding));
    }
    let mut suffixed = wire.to_vec();
    suffixed.push(0);
    assert_eq!(PreparationJournal::decode(&suffixed), Err(PreparationError::Encoding));
    for version in *b"124" {
        let mut unsupported = wire;
        unsupported[JOURNAL_DOMAIN.len() - 1] = version;
        assert_eq!(PreparationJournal::decode(&unsupported), Err(PreparationError::Encoding));
    }
    let mut wrong_domain = wire;
    wrong_domain[0] ^= 1;
    assert_eq!(PreparationJournal::decode(&wrong_domain), Err(PreparationError::Encoding));
    for field in 0..4 {
        let mut zero = wire;
        let at = JOURNAL_DOMAIN.len() + 32 * field;
        zero[at..at + 32].fill(0);
        assert_eq!(PreparationJournal::decode(&zero), Err(PreparationError::Encoding));
    }
    let mut sparse = [0; 149];
    sparse[..JOURNAL_DOMAIN.len()].copy_from_slice(JOURNAL_DOMAIN);
    for field in 0..4 { sparse[JOURNAL_DOMAIN.len() + 32 * field + 31] = 1; }
    assert_eq!(PreparationJournal::decode(&sparse).unwrap().encode(), sparse);
    // A public decoder does not authenticate a wrapped program proof: arbitrary
    // nonzero public digests remain shape-valid but cannot match the real export.
    let mut forged = [1; 149];
    forged[..JOURNAL_DOMAIN.len()].copy_from_slice(JOURNAL_DOMAIN);
    let decoded = PreparationJournal::decode(&forged).unwrap();
    let witness = fixture();
    let context = ValidatedContext::decode(&witness.context_bytes).unwrap();
    let binding = witness.preparation_binding().unwrap();
    assert_eq!(decoded.check_solver_capsule(SolverCapsule {
        context: &context, private_packet_binding: &binding, capsule_blind: &witness.capsule_blind,
        redacted_payment: &witness.redacted_p_pczt, recovery_transaction: &witness.q_transaction,
    }), Err(PreparationError::Context));
}

// Actual S-local consumer: only the bounded exported fields/public journal and
// independently pinned Q circuit key enter. No U note/FVK/path, opening blinds,
// preparation blind/private PCZTs or owner-consent signature are available here.
// Success is correspondence + complete Q authorization, NOT certificate/history
// verification or any solver acceptance/funding capability.
fn check_solver_export(
    export: SolverCapsule<'_>,
    public_journal: &[u8],
    q_key: &VerifyingKey,
) -> Result<(), PreparationError> {
    let q = IronwoodTransaction::parse(export.recovery_transaction, BranchId::Nu6_3)
        .map_err(|_| PreparationError::Transaction)?;
    q.verify_authorization(q_key, &mut ChaCha20Rng::from_seed([97; 32]))
        .map_err(|_| PreparationError::Signature)?;
    PreparationJournal::decode(public_journal)?.check_solver_capsule(export)
}

#[test]
fn solver_only_export_checks_actual_q_and_rejects_independently_valid_other_q() {
    // U prepares these exports; the S-local consumer below receives only the
    // five safe fields. The native-produced journal remains unwrapped/untrusted.
    let (public_journal, context, binding, capsule_blind, redacted_p, final_q) = {
        let owner = fixture();
        let journal = verify_preparation(owner).unwrap();
        (journal.encode(), ValidatedContext::decode(&owner.context_bytes).unwrap(),
            journal.packet_binding(), Zeroizing::new(owner.capsule_blind),
            Zeroizing::new(owner.redacted_p_pczt.clone()), Zeroizing::new(owner.q_transaction.clone()))
    };
    let export = || SolverCapsule {
        context: &context, private_packet_binding: &binding, capsule_blind: &capsule_blind,
        redacted_payment: &redacted_p, recovery_transaction: &final_q,
    };
    let q_key = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    check_solver_export(export(), &public_journal, &q_key).unwrap();
    assert_eq!(format!("{:?}", export()), "SolverCapsule([REDACTED])");
    let payment = Pczt::parse(&redacted_p).unwrap();
    assert!(payment.global().proprietary().is_empty());
    Verifier::new(payment).with_ironwood::<(), _>(|bundle| {
        assert!(bundle.bsk().is_none() && bundle.zkproof().is_none());
        for action in bundle.actions() {
            let spend = action.spend();
            let output = action.output();
            assert!(action.rcv().is_none() && spend.spend_auth_sig().is_none()
                && spend.recipient().is_none() && spend.value().is_none() && spend.rho().is_none()
                && spend.rseed().is_none() && spend.fvk().is_none() && spend.witness().is_none()
                && spend.alpha().is_none() && spend.dummy_sk().is_none()
                && spend.zip32_derivation().is_none() && spend.proprietary().is_empty()
                && output.recipient().is_none() && output.value().is_none()
                && output.rseed().is_none() && output.ock().is_none()
                && output.zip32_derivation().is_none() && output.user_address().is_none()
                && output.proprietary().is_empty());
        }
        Ok(())
    }).unwrap().finish();

    // Genuine independent builder execution creates a different actual P/Q
    // action/effect/proof/signature set, not a mutated or placeholder transaction.
    static ALTERNATE: LazyLock<PreparedFixture> = LazyLock::new(|| make_seeded_fixture(false, 13));
    let alternative_q = ALTERNATE.q.transaction_bytes();
    assert_ne!(alternative_q, final_q.as_slice());
    IronwoodTransaction::parse(alternative_q, BranchId::Nu6_3).unwrap()
        .verify_authorization(&q_key, &mut ChaCha20Rng::from_seed([98; 32])).unwrap();
    let mut changed = export();
    changed.recovery_transaction = alternative_q;
    // The same consumer runs full Q authorization BEFORE journal matching. This
    // exact error establishes that an actually valid OTHER Q is not this capsule.
    assert_eq!(check_solver_export(changed, &public_journal, &q_key), Err(PreparationError::SolverCapsule));
}

#[test]
fn correspondence_rejects_every_export_field_and_public_digest_substitution() {
    let owner = fixture();
    let journal = verify_preparation(owner).unwrap();
    let context = ValidatedContext::decode(&owner.context_bytes).unwrap();
    let binding = journal.packet_binding();
    let export = || SolverCapsule {
        context: &context, private_packet_binding: &binding, capsule_blind: &owner.capsule_blind,
        redacted_payment: &owner.redacted_p_pczt, recovery_transaction: &owner.q_transaction,
    };
    journal.check_solver_capsule(export()).unwrap();
    let mut changed_context = *context.context();
    changed_context.order_id[31] ^= 1;
    let changed_context = changed_context.validate().unwrap();
    let mut changed_binding = binding;
    changed_binding[31] ^= 1;
    let mut changed_blind = Zeroizing::new(owner.capsule_blind);
    changed_blind[31] ^= 1;
    let mut changed_p = Zeroizing::new(owner.redacted_p_pczt.clone());
    changed_p[0] ^= 1;
    let mut changed_q = Zeroizing::new(owner.q_transaction.clone());
    changed_q[0] ^= 1;
    for field in 0..9 {
        let mut changed = export();
        let expected = match field {
            0 => { changed.context = &changed_context; PreparationError::Context },
            1 => { changed.private_packet_binding = &changed_binding; PreparationError::PacketBinding },
            2 => { changed.capsule_blind = &changed_blind; PreparationError::SolverCapsule },
            3 => { changed.redacted_payment = &changed_p; PreparationError::SolverCapsule },
            4 => { changed.recovery_transaction = &changed_q; PreparationError::SolverCapsule },
            5 => { changed.redacted_payment = &[]; PreparationError::SolverCapsule },
            6 => { changed.recovery_transaction = &[]; PreparationError::SolverCapsule },
            7 => { changed.capsule_blind = &[0; 32]; PreparationError::SolverCapsule },
            _ => { changed.private_packet_binding = &[0; 32]; PreparationError::PacketBinding },
        };
        assert_eq!(journal.check_solver_capsule(changed), Err(expected), "export field {field}");
    }
    for (field, expected) in [PreparationError::Context, PreparationError::PacketBinding,
        PreparationError::ConsumptionTag, PreparationError::SolverCapsule].into_iter().enumerate() {
        let mut changed = journal.encode();
        changed[JOURNAL_DOMAIN.len() + 32 * field + 31] ^= 1;
        let decoded = PreparationJournal::decode(&changed).unwrap();
        assert_eq!(decoded.check_solver_capsule(export()), Err(expected), "public digest {field}");
    }
}

