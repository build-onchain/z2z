#![cfg(target_os = "linux")]

use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier, LazyLock},
};

use incrementalmerkletree::{Hashable, Level};
use orchard::{
    Note,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::{Pczt, roles::redactor::Redactor};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    memo::MemoBytes,
    value::Zatoshis,
};
use ziquid_proofs::preparation::{MAX_PRIVATE_INPUT_BYTES, PreparationError, PreparationJournal, PreparationWitness, verify_preparation};
use ziquid_protocol::{NativeAmount, SolverCapsule, StatementContext, ValidatedContext, input_commitment, payment_commitment, note_consumption_tag};
use ziquid_runtime::custody::{
    CustodyError, PrivatePreparation, load_preparation, save_preparation,
};
use ziquid_zcash::{IronwoodTransaction, OutputPlan, OwnedInput, PayoutWitness, PreparationIntent, SourceParameters, prepare};

const TARGET: u32 = 4_134_000;
const EXPIRY: u32 = 4_134_040;
// Generated fixture capabilities only, never supplied by or requested from a wallet.
const KEY: [u8; 32] = [0x83; 32];
const NAMESPACE: [u8; 32] = [0x84; 32];
const MEMO: &[u8] = b"generated private payout memo";
// Independent public synthetic capsule blind, not wallet entropy or a secret capability.
const CAPSULE_BLIND: [u8; 32] = [0x97; 32];

fn private_directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn base_context() -> ValidatedContext {
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
        source_fee_cap: 15_000,
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
    .validate()
    .unwrap()
}

fn context() -> ValidatedContext {
    ValidatedContext::decode(&FIXTURE.witness.context_bytes).unwrap()
}

fn owned_input() -> (OwnedInput, SpendAuthorizingKey) {
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

fn solver_address() -> orchard::Address {
    FullViewingKey::from(&SpendingKey::from_bytes([91; 32]).unwrap())
        .address_at(0u32, Scope::External)
}

fn output(address: orchard::Address, value: u64, memo: MemoBytes) -> OutputPlan {
    OutputPlan::new(address, Zatoshis::from_u64(value).unwrap(), memo)
}

// Genuine generated local P/Q authoring and Halo2 Q, not chain-origin or arming evidence.
// One expensive proof is shared across hostile-file cases in this test process.
static FIXTURE: LazyLock<PrivatePreparation> = LazyLock::new(|| make_fixture([0x85; 32]));
static ALTERNATE: LazyLock<PrivatePreparation> = LazyLock::new(|| make_fixture([0x86; 32]));

fn make_fixture(preparation_blind: [u8; 32]) -> PrivatePreparation {
    let (input, ask) = owned_input();
    let fvk = input.full_viewing_key();
    let source = SourceParameters {
        network: Network::TestNetwork,
        target_height: BlockHeight::from(TARGET),
        expiry_height: BlockHeight::from(EXPIRY),
        consensus_branch: BranchId::Nu6_3,
        fee_rule: zip317::FeeRule::standard(),
    };
    let pair = prepare(
        &source,
        &input,
        &[
            output(solver_address(), 60_000, MemoBytes::from_bytes(MEMO).unwrap()),
            output(fvk.address_at(1u32, Scope::Internal), 25_000, MemoBytes::empty()),
            // Zero-valued requested outputs must not be mistaken for builder padding.
            output(fvk.address_at(2u32, Scope::Internal), 0, MemoBytes::from_bytes(b"zero requested").unwrap()),
        ],
        &[output(fvk.address_at(3u32, Scope::Internal), 90_000, MemoBytes::empty())],
        &mut ChaCha20Rng::from_seed([12; 32]),
    )
    .unwrap();
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let q = pair.finish_recovery(&ask, &pk, &vk).unwrap();
    let requested_output_actions = pair
        .payout_witness()
        .requested_output_actions()
        .iter()
        .map(|index| u32::try_from(*index).unwrap())
        .collect();
    let input_blind = [0x93; 32];
    let payment_blind = [0x94; 32];
    let receivers = [solver_address().to_raw_address_bytes()];
    let mut terms = *base_context().context();
    let note = input.note();
    let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes();
    let nf = input.nullifier().to_bytes();
    terms.real_input_commitment = input_commitment(&input_blind, &terms.source_network, &terms.source_pool,
        &note.recipient().to_raw_address_bytes(), note.value().inner(), &note.rho().to_bytes(),
        note.rseed().as_bytes(), &cmx, &nf).unwrap();
    terms.source_payment_commitment = payment_commitment(&payment_blind, &terms.source_network, &terms.source_pool,
        &pair.unsigned_payment().effect_id(), &receivers, terms.source_quoted_amount).unwrap();
    let fvk_bytes = fvk.to_bytes();
    terms.consumption_tag = note_consumption_tag(&terms.source_network, &terms.source_pool, terms.evm_chain_id,
        &terms.escrow, fvk_bytes[32..64].try_into().unwrap(), &nf).unwrap();
    let semantic_context = terms.validate().unwrap();
    let owner_intent_signature = pair.authorize_preparation(&input, &q, PreparationIntent {
        context: &semantic_context, input_blind: &input_blind, payment_blind: &payment_blind,
        receivers: &receivers, preparation_blind: &preparation_blind, capsule_blind: &CAPSULE_BLIND,
    }, &ask, &mut ChaCha20Rng::from_seed([0x95; 32])).unwrap();
    PrivatePreparation {
        witness: PreparationWitness {
            context_bytes: semantic_context.canonical_bytes(),
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
            secret_blind: preparation_blind,
            capsule_blind: CAPSULE_BLIND,
            input_blind,
            payment_blind,
            quoted_receivers: receivers.to_vec(),
            owner_intent_signature,
        },
        requested_output_actions,
    }
}

// Synthetic fixture capability only: intentionally authorize a changed Q proof
// so custody's independent Halo2 check, not stale consent, rejects it.
fn resign_fixture(artifact: &mut PrivatePreparation) {
    let (input, ask) = owned_input();
    let context = ValidatedContext::decode(&artifact.witness.context_bytes).unwrap();
    let message = ziquid_protocol::preparation_consent_digest(&context,
        &artifact.witness.preparation_binding().unwrap(),
        &artifact.witness.solver_capsule_commitment().unwrap()).unwrap();
    let mut signed = None;
    pczt::roles::verifier::Verifier::new(Pczt::parse(&artifact.witness.private_q_pczt).unwrap())
        .with_ironwood::<(), _>(|bundle| {
            let real = bundle.actions().iter().find(|action|
                action.spend().value().is_some_and(|value| value.inner() == input.note().value().inner())
                && action.spend().nullifier() == &input.nullifier()).unwrap();
            let rsk = ask.randomize(real.spend().alpha().as_ref().unwrap());
            assert_eq!(orchard::primitives::redpallas::VerificationKey::from(&rsk), *real.spend().rk());
            signed = Some(<[u8; 64]>::from(&rsk.sign(ChaCha20Rng::from_seed([0x96; 32]), &message)));
            Ok(())
        }).unwrap();
    artifact.witness.owner_intent_signature = signed.unwrap();
}

fn assert_recovery(artifact: &PrivatePreparation) {
    let payout = artifact.restore_payout().unwrap();
    let recovered = payout.recover_pczt_output(&artifact.witness.redacted_p_pczt, 0).unwrap();
    assert_eq!(recovered.recipient(), solver_address());
    assert_eq!(recovered.value(), 60_000);
    assert!(recovered.memo().starts_with(MEMO));
    let change = payout.recover_pczt_output(&artifact.witness.redacted_p_pczt, 1).unwrap();
    assert_eq!(change.value(), 25_000);
    let zero = payout.recover_pczt_output(&artifact.witness.redacted_p_pczt, 2).unwrap();
    assert_eq!(zero.value(), 0);
    assert!(zero.memo().starts_with(b"zero requested"));
    verify_preparation(&artifact.witness).unwrap();
    IronwoodTransaction::parse(&artifact.witness.q_transaction, BranchId::Nu6_3)
        .unwrap()
        .verify_authorization(
            &VerifyingKey::build(OrchardCircuitVersion::PostNu6_3),
            &mut ChaCha20Rng::from_seed([21; 32]),
        )
        .unwrap();
}

fn pending(path: &Path) -> PathBuf {
    path.with_file_name(format!(".{}.pending", path.file_name().unwrap().to_str().unwrap()))
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    File::open(path.parent().unwrap()).unwrap().sync_all().unwrap();
}

#[test]
fn encrypted_restart_retains_shuffled_sender_openings_and_complete_q() {
    let directory = private_directory();
    let path = directory.path().join("u/orders/artifact");
    let artifact = FIXTURE.clone();
    save_preparation(&path, &KEY, NAMESPACE, &artifact).unwrap();
    let encrypted = fs::read(&path).unwrap();
    assert!(!encrypted.windows(96).any(|bytes| bytes == artifact.witness.full_viewing_key));
    assert!(!encrypted.windows(MEMO.len()).any(|bytes| bytes == MEMO));
    assert!(!encrypted.windows(artifact.witness.private_p_pczt.len()).any(|bytes| bytes == artifact.witness.private_p_pczt));
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o7777, 0o700);
    assert!(!pending(&path).exists());
    drop(artifact);
    let restored = load_preparation(&path, &KEY, NAMESPACE, context().digest()).unwrap();
    assert_recovery(&restored);
    assert_eq!(restored.witness.private_q_pczt, FIXTURE.witness.private_q_pczt);
    assert_eq!(restored.witness.q_transaction, FIXTURE.witness.q_transaction);
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "custody_child", "--nocapture"])
        .env("ZIQUID_CUSTODY_CHILD", "recover")
        .env("ZIQUID_CUSTODY_DIRECTORY", directory.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let logs = [output.stdout, output.stderr].concat();
    assert!(!logs.windows(MEMO.len()).any(|bytes| bytes == MEMO));
    assert!(!logs.windows(96).any(|bytes| bytes == FIXTURE.witness.full_viewing_key));
}

#[test]
fn immutable_retries_compare_logical_artifacts_not_fresh_aead_ciphertexts() {
    let directory = private_directory();
    let path = directory.path().join("artifact");
    save_preparation(&path, &KEY, NAMESPACE, &FIXTURE).unwrap();
    let original = fs::read(&path).unwrap();
    save_preparation(&path, &KEY, NAMESPACE, &FIXTURE.clone()).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    let changed = ALTERNATE.clone();
    assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &changed), Err(CustodyError::Conflict)));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_recovery(&load_preparation(&path, &KEY, NAMESPACE, context().digest()).unwrap());
}

#[test]
fn capsule_only_reblind_requires_fresh_consent_and_survives_restart_without_replacing_original() {
    let directory = private_directory();
    let original_path = directory.path().join("original");
    save_preparation(&original_path, &KEY, NAMESPACE, &FIXTURE).unwrap();
    let original_bytes = fs::read(&original_path).unwrap();
    let original_journal = verify_preparation(&FIXTURE.witness).unwrap();
    let mut reblinded = FIXTURE.clone();
    reblinded.witness.capsule_blind = [0x98; 32];
    assert_eq!(reblinded.witness.preparation_binding().unwrap(), original_journal.packet_binding());
    assert_ne!(reblinded.witness.solver_capsule_commitment().unwrap(), original_journal.solver_capsule_commitment());
    assert_eq!(verify_preparation(&reblinded.witness), Err(PreparationError::OwnerConsent));
    let reblinded_path = directory.path().join("capsule-reblinded");
    assert!(matches!(save_preparation(&reblinded_path, &KEY, NAMESPACE, &reblinded), Err(CustodyError::Preparation)));
    assert!(!reblinded_path.exists());
    assert!(!pending(&reblinded_path).exists());
    resign_fixture(&mut reblinded);
    let reblinded_journal = verify_preparation(&reblinded.witness).unwrap();
    assert_eq!(reblinded_journal.context_digest(), original_journal.context_digest());
    assert_eq!(reblinded_journal.packet_binding(), original_journal.packet_binding());
    assert_eq!(reblinded_journal.consumption_tag(), original_journal.consumption_tag());
    assert_ne!(reblinded.witness.owner_intent_signature, FIXTURE.witness.owner_intent_signature);
    assert!(matches!(save_preparation(&original_path, &KEY, NAMESPACE, &reblinded), Err(CustodyError::Conflict)));
    assert_eq!(fs::read(&original_path).unwrap(), original_bytes);
    let stage_path = directory.path().join("staged-original");
    write_private(&pending(&stage_path), &original_bytes);
    assert!(matches!(save_preparation(&stage_path, &KEY, NAMESPACE, &reblinded), Err(CustodyError::Conflict)));
    assert_eq!(fs::read(pending(&stage_path)).unwrap(), original_bytes);
    assert!(!stage_path.exists());
    save_preparation(&reblinded_path, &KEY, NAMESPACE, &reblinded).unwrap();
    let restored = load_preparation(&reblinded_path, &KEY, NAMESPACE, context().digest()).unwrap();
    assert_eq!(restored.witness.capsule_blind, [0x98; 32]);
    assert_eq!(restored.witness.owner_intent_signature, reblinded.witness.owner_intent_signature);
    assert_eq!(verify_preparation(&restored.witness).unwrap(), reblinded_journal);
    assert_recovery(&restored);
    // Public expected journal, not a private opening: compare the actual restart
    // consumer against the parent's independently verified pre-restart record.
    write_private(&directory.path().join("capsule-reblinded-journal"), &reblinded_journal.encode());
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "custody_child", "--nocapture"])
        .env("ZIQUID_CUSTODY_CHILD", "capsule-reblind-recover")
        .env("ZIQUID_CUSTODY_DIRECTORY", directory.path())
        .output().unwrap();
    assert!(output.status.success());
    let logs = [output.stdout, output.stderr].concat();
    assert!(!logs.windows(MEMO.len()).any(|bytes| bytes == MEMO));
    assert!(!logs.windows(96).any(|bytes| bytes == FIXTURE.witness.full_viewing_key));
    assert_eq!(fs::read(&original_path).unwrap(), original_bytes);
}

#[test]
fn wrong_capabilities_or_expected_bindings_never_replace_custody() {
    let directory = private_directory();
    let path = directory.path().join("caller-a/artifact");
    save_preparation(&path, &KEY, NAMESPACE, &FIXTURE).unwrap();
    let original = fs::read(&path).unwrap();
    for (key, namespace, digest) in [
        ([0x90; 32], NAMESPACE, context().digest()),
        (KEY, [0x91; 32], context().digest()),
        (KEY, NAMESPACE, [0x92; 32]),
    ] {
        assert!(matches!(load_preparation(&path, &key, namespace, digest), Err(CustodyError::Authentication)));
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    assert!(matches!(save_preparation(&path, &[0x90; 32], NAMESPACE, &FIXTURE), Err(CustodyError::Authentication)));
    assert!(matches!(save_preparation(&path, &KEY, [0x91; 32], &FIXTURE), Err(CustodyError::Authentication)));
    let other_path = directory.path().join("caller-b/artifact");
    save_preparation(&other_path, &[0x90; 32], [0x91; 32], &FIXTURE).unwrap();
    assert!(load_preparation(&other_path, &KEY, NAMESPACE, context().digest()).is_err());
    assert_recovery(&load_preparation(&other_path, &[0x90; 32], [0x91; 32], context().digest()).unwrap());
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn staging_namespace_cannot_be_used_as_an_immutable_final_or_loaded_directly() {
    let directory = private_directory();
    for basename in [".order.pending", ".hidden", ".order"] {
        let parent = directory.path().join(format!("fresh-{basename}"));
        let path = parent.join(basename);
        assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsafePath)));
        assert!(matches!(load_preparation(&path, &KEY, NAMESPACE, context().digest()), Err(CustodyError::UnsafePath)));
        assert!(!parent.exists());
    }
    let committed = directory.path().join("order");
    save_preparation(&committed, &KEY, NAMESPACE, &FIXTURE).unwrap();
    let encrypted = fs::read(&committed).unwrap();
    let collision = pending(&committed);
    assert!(matches!(save_preparation(&collision, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsafePath)));
    assert!(!collision.exists());
    assert_eq!(fs::read(&committed).unwrap(), encrypted);
    let resumed = directory.path().join("next-order");
    write_private(&pending(&resumed), &encrypted);
    assert!(matches!(load_preparation(pending(&resumed), &KEY, NAMESPACE, context().digest()), Err(CustodyError::UnsafePath)));
    assert_eq!(fs::read(pending(&resumed)).unwrap(), encrypted);
    save_preparation(&resumed, &KEY, NAMESPACE, &FIXTURE).unwrap();
    assert_eq!(fs::read(&resumed).unwrap(), encrypted);
    assert!(!pending(&resumed).exists());
    assert_eq!(fs::read(&committed).unwrap(), encrypted);
    assert_recovery(&load_preparation(&committed, &KEY, NAMESPACE, context().digest()).unwrap());
}

#[test]
fn malformed_oversized_or_tampered_envelopes_are_rejected_without_repair() {
    let directory = private_directory();
    let source = directory.path().join("source");
    save_preparation(&source, &KEY, NAMESPACE, &FIXTURE).unwrap();
    let original = fs::read(&source).unwrap();
    let mut nonce_or_header = original.clone();
    nonce_or_header[30] ^= 1;
    let mut ciphertext = original.clone();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 1;
    let mut suffixed = original.clone();
    suffixed.push(0);
    for (index, bytes) in [nonce_or_header, ciphertext, original[..original.len() - 1].to_vec(), vec![0; 8], suffixed].into_iter().enumerate() {
        let path = directory.path().join(format!("invalid-{index}"));
        write_private(&path, &bytes);
        assert!(load_preparation(&path, &KEY, NAMESPACE, context().digest()).is_err());
        assert!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    let path = directory.path().join("oversized");
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
    let oversized = MAX_PRIVATE_INPUT_BYTES as u64 + 65_536;
    file.set_len(oversized).unwrap();
    assert!(matches!(load_preparation(&path, &KEY, NAMESPACE, context().digest()), Err(CustodyError::ResourceLimit)));
    assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::ResourceLimit)));
    assert_eq!(file.metadata().unwrap().len(), oversized);
}

#[test]
fn restore_rejects_noncanonical_redacted_or_unbound_private_p_and_invalid_mappings() {
    let (input, _) = owned_input();
    let actions = FIXTURE.requested_output_actions.iter().map(|i| *i as usize).collect::<Vec<_>>();
    let restored = PayoutWitness::restore(input.clone(), FIXTURE.witness.private_p_pczt.clone(), actions.clone()).unwrap();
    assert_eq!(restored.recover_pczt_output(&FIXTURE.witness.redacted_p_pczt, 0).unwrap().value(), 60_000);
    let mut suffix = FIXTURE.witness.private_p_pczt.clone();
    suffix.push(0);
    assert!(PayoutWitness::restore(input.clone(), suffix, actions.clone()).is_err());
    assert!(PayoutWitness::restore(input.clone(), FIXTURE.witness.redacted_p_pczt.clone(), actions.clone()).is_err());
    let no_anchor = Redactor::new(Pczt::parse(&FIXTURE.witness.private_p_pczt).unwrap())
        .redact_ironwood_with(|mut bundle| bundle.clear_anchor())
        .finish().serialize().unwrap();
    assert!(PayoutWitness::restore(input.clone(), no_anchor, actions.clone()).is_err());
    for invalid in [vec![usize::MAX], vec![actions[0], actions[0]], vec![actions[0]]] {
        assert!(PayoutWitness::restore(input.clone(), FIXTURE.witness.private_p_pczt.clone(), invalid).is_err());
    }
    let mut reversed = FIXTURE.clone();
    reversed.requested_output_actions.swap(0, 1);
    let payout = reversed.restore_payout().unwrap();
    assert_eq!(payout.recover_pczt_output(&reversed.witness.redacted_p_pczt, 0).unwrap().value(), 25_000);
    let wrong_path = MerklePath::from_parts(1, std::array::from_fn(|i| MerkleHashOrchard::empty_root(Level::from(i as u8))));
    let wrong_anchor = wrong_path.root(input.note().commitment().into());
    let other_input = OwnedInput::new(*input.note(), input.full_viewing_key().clone(), wrong_path, wrong_anchor).unwrap();
    assert!(PayoutWitness::restore(other_input, FIXTURE.witness.private_p_pczt.clone(), actions).is_err());
    let directory = private_directory();
    let mut invalid = FIXTURE.clone();
    invalid.requested_output_actions = vec![u32::MAX];
    let path = directory.path().join("invalid");
    assert!(save_preparation(&path, &KEY, NAMESPACE, &invalid).is_err());
    assert!(!path.exists());
    let mut invalid_q = FIXTURE.clone();
    assert_recovery(&invalid_q);
    let original_capsule = invalid_q.witness.solver_capsule_commitment().unwrap();
    let q = IronwoodTransaction::parse(&invalid_q.witness.q_transaction, BranchId::Nu6_3).unwrap();
    let proof = q.transaction().ironwood_bundle().unwrap().authorization().proof().as_ref();
    let proof_at = invalid_q.witness.q_transaction.windows(proof.len()).position(|bytes| bytes == proof).unwrap();
    invalid_q.witness.q_transaction[proof_at] ^= 1;
    assert_ne!(invalid_q.witness.solver_capsule_commitment().unwrap(), original_capsule);
    resign_fixture(&mut invalid_q);
    // The preparation relation explicitly does not verify Halo2: custody must do so.
    verify_preparation(&invalid_q.witness).unwrap();
    assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &invalid_q), Err(CustodyError::Preparation)));
    assert!(!path.exists());
}

#[test]
fn concurrent_publishers_share_one_immutable_logical_artifact() {
    for different in [false, true] {
        let directory = private_directory();
        let path = directory.path().join("u/new/artifact");
        let barrier = Arc::new(Barrier::new(2));
        let workers = [0u8, 1].map(|index| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let artifact = if different && index == 1 { ALTERNATE.clone() } else { FIXTURE.clone() };
            std::thread::spawn(move || {
                barrier.wait();
                save_preparation(&path, &KEY, NAMESPACE, &artifact)
            })
        });
        let results = workers.map(|worker| worker.join().unwrap());
        if different {
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
            assert_eq!(results.iter().filter(|r| matches!(r, Err(CustodyError::Conflict))).count(), 1);
        } else {
            assert!(results.iter().all(|r| r.is_ok()));
        }
        let loaded = load_preparation(&path, &KEY, NAMESPACE, context().digest()).unwrap();
        assert!(loaded.witness.secret_blind == [0x85; 32] || different && loaded.witness.secret_blind == [0x86; 32]);
        assert_recovery(&loaded);
        assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
        assert!(!pending(&path).exists());
    }
}

#[test]
fn interrupted_staging_reuses_complete_encryption_and_retries_partial_write() {
    let directory = private_directory();
    let source = directory.path().join("source");
    save_preparation(&source, &KEY, NAMESPACE, &FIXTURE).unwrap();
    let encrypted = fs::read(&source).unwrap();
    let path = directory.path().join("complete");
    write_private(&pending(&path), &encrypted);
    save_preparation(&path, &KEY, NAMESPACE, &FIXTURE).unwrap();
    assert_eq!(fs::read(&path).unwrap(), encrypted);
    assert!(!pending(&path).exists());
    let path = directory.path().join("partial");
    write_private(&pending(&path), &encrypted[..encrypted.len() / 2]);
    assert!(load_preparation(&path, &KEY, NAMESPACE, context().digest()).is_err());
    save_preparation(&path, &KEY, NAMESPACE, &FIXTURE).unwrap();
    assert_recovery(&load_preparation(&path, &KEY, NAMESPACE, context().digest()).unwrap());
    let path = directory.path().join("empty-stage");
    write_private(&pending(&path), b"");
    save_preparation(&path, &KEY, NAMESPACE, &FIXTURE).unwrap();
    assert!(!pending(&path).exists());
    assert_recovery(&load_preparation(&path, &KEY, NAMESPACE, context().digest()).unwrap());
    // Only the full distinguishing current domain is disposable; its shorter
    // prefixes overlap retained versions and are preserved by the old-domain gate.
    let path = directory.path().join("current-domain-only-stage");
    write_private(&pending(&path), b"ziquid.u.custody.v3");
    save_preparation(&path, &KEY, NAMESPACE, &FIXTURE).unwrap();
    assert!(!pending(&path).exists());
    assert_recovery(&load_preparation(&path, &KEY, NAMESPACE, context().digest()).unwrap());
    let path = directory.path().join("different");
    write_private(&pending(&path), &encrypted);
    let changed = ALTERNATE.clone();
    assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &changed), Err(CustodyError::Conflict)));
    assert!(!path.exists());
    assert_eq!(fs::read(pending(&path)).unwrap(), encrypted);
    let path = directory.path().join("wrong-capability");
    write_private(&pending(&path), &encrypted);
    assert!(matches!(save_preparation(&path, &[0x90; 32], NAMESPACE, &FIXTURE), Err(CustodyError::Authentication)));
    assert_eq!(fs::read(pending(&path)).unwrap(), encrypted);
    for (index, bytes) in [b"unrelated owner data".as_slice(), b"ziquid.u.custody.v4".as_slice()].into_iter().enumerate() {
        let path = directory.path().join(format!("unknown-staging-{index}"));
        write_private(&pending(&path), bytes);
        assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::Conflict)));
        assert_eq!(fs::read(pending(&path)).unwrap(), bytes);
        assert!(!path.exists());
    }
    let path = directory.path().join("tampered-staging");
    let mut tampered = encrypted.clone();
    *tampered.last_mut().unwrap() ^= 1;
    write_private(&pending(&path), &tampered);
    assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::Authentication)));
    assert_eq!(fs::read(pending(&path)).unwrap(), tampered);
    assert!(!path.exists());
    // Real kernel file-size failure terminates a subprocess during encrypted staging.
    // Only a generated-key fixture path crosses the process boundary, never a key or PCZT.
    let output = Command::new("/bin/sh")
        .args(["-c", "ulimit -f 1; exec \"$@\"", "custody-write"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "custody_child", "--nocapture"])
        .env("ZIQUID_CUSTODY_CHILD", "limited-write")
        .env("ZIQUID_CUSTODY_DIRECTORY", directory.path())
        .output().unwrap();
    assert!(!output.status.success());
    let path = directory.path().join("limited");
    assert!(!path.exists());
    assert!(pending(&path).exists());
    save_preparation(&path, &KEY, NAMESPACE, &FIXTURE).unwrap();
    assert_recovery(&load_preparation(&path, &KEY, NAMESPACE, context().digest()).unwrap());
    assert_eq!(fs::read(&source).unwrap(), encrypted);
}

#[test]
fn unsafe_files_directories_and_aliases_fail_without_mutating_other_data() {
    let directory = private_directory();
    let target = directory.path().join("unrelated");
    write_private(&target, b"unrelated owner data");
    let path = directory.path().join("symlink");
    symlink(&target, &path).unwrap();
    assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsafePath)));
    assert_eq!(fs::read(&target).unwrap(), b"unrelated owner data");
    let real = directory.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, Permissions::from_mode(0o700)).unwrap();
    let alias = directory.path().join("directory-link");
    symlink(&real, &alias).unwrap();
    assert!(matches!(save_preparation(alias.join("artifact"), &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsafePath)));
    assert!(!real.join("artifact").exists());
    let path = directory.path().join("artifact");
    save_preparation(&path, &KEY, NAMESPACE, &FIXTURE).unwrap();
    let original = fs::read(&path).unwrap();
    for mode in [0o644, 0o400, 0o2600] {
        fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
        assert!(matches!(load_preparation(&path, &KEY, NAMESPACE, context().digest()), Err(CustodyError::UnsafePath)));
        assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsafePath)));
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, mode);
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, directory.path().join("hardlink")).unwrap();
    assert!(matches!(load_preparation(&path, &KEY, NAMESPACE, context().digest()), Err(CustodyError::UnsafePath)));
    assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsafePath)));
    assert_eq!(fs::read(&path).unwrap(), original);
    for mode in [0o755, 0o770, 0o707, 0o777, 0o1770] {
        let ancestor = directory.path().join(format!("mode-{mode:o}"));
        fs::create_dir(&ancestor).unwrap();
        fs::set_permissions(&ancestor, Permissions::from_mode(mode)).unwrap();
        let path = ancestor.join("artifact");
        assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsafePath)));
        assert!(!path.exists());
        if mode != 0o755 {
            assert!(save_preparation(ancestor.join("private/artifact"), &KEY, NAMESPACE, &FIXTURE).is_err());
            assert!(!ancestor.join("private").exists());
        }
    }
    let parent = directory.path().join("stage-parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
    let path = parent.join("artifact");
    symlink(&target, pending(&path)).unwrap();
    assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsafePath)));
    assert_eq!(fs::read(&target).unwrap(), b"unrelated owner data");
    assert!(!path.exists());
    assert!(save_preparation(directory.path().join("real/../escape"), &KEY, NAMESPACE, &FIXTURE).is_err());
    assert!(!directory.path().join("escape").exists());
}

#[test]
fn filesystem_errors_are_sanitized_and_never_count_as_saved_custody() {
    let directory = private_directory();
    let missing = directory.path().join("missing/artifact");
    assert!(load_preparation(&missing, &KEY, NAMESPACE, context().digest()).is_err());
    assert!(!missing.parent().unwrap().exists());
    let blocker = directory.path().join("blocker");
    write_private(&blocker, b"not a directory");
    let error = save_preparation(blocker.join("private/artifact"), &KEY, NAMESPACE, &FIXTURE).unwrap_err();
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(directory.path().to_str().unwrap()));
    assert!(!rendered.contains("blocker"));
    assert_eq!(fs::read(&blocker).unwrap(), b"not a directory");
    let path = directory.path().join("directory-instead-of-file");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsafePath)));
    assert!(path.is_dir());
    // Ordinary DAC failure must not create custody beneath an unreadable ancestor.
    // Root bypasses these permissions, so this case is not exercised as root.
    if fs::metadata("/proc/self").unwrap().uid() != 0 {
        let ancestor = directory.path().join("unreadable");
        fs::create_dir(&ancestor).unwrap();
        fs::set_permissions(&ancestor, Permissions::from_mode(0o300)).unwrap();
        let path = ancestor.join("private/artifact");
        let result = save_preparation(&path, &KEY, NAMESPACE, &FIXTURE);
        fs::set_permissions(&ancestor, Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(result, Err(CustodyError::Io)));
        assert!(!path.exists());
        assert!(!ancestor.join("private").exists());
    }
}

#[test]
fn custody_child() {
    let Ok(mode) = std::env::var("ZIQUID_CUSTODY_CHILD") else { return; };
    let directory = PathBuf::from(std::env::var_os("ZIQUID_CUSTODY_DIRECTORY").unwrap());
    match mode.as_str() {
        "recover" => {
            let artifact = load_preparation(directory.join("u/orders/artifact"), &KEY, NAMESPACE, context().digest()).unwrap();
            assert_recovery(&artifact);
        }
        "capsule-reblind-recover" => {
            let artifact = load_preparation(directory.join("capsule-reblinded"), &KEY, NAMESPACE, context().digest()).unwrap();
            assert_eq!(artifact.witness.capsule_blind, [0x98; 32]);
            let original = load_preparation(directory.join("original"), &KEY, NAMESPACE, context().digest()).unwrap();
            assert_eq!(artifact.witness.secret_blind, original.witness.secret_blind);
            assert_eq!(artifact.witness.redacted_p_pczt, original.witness.redacted_p_pczt);
            assert_eq!(artifact.witness.q_transaction, original.witness.q_transaction);
            assert_ne!(artifact.witness.owner_intent_signature, original.witness.owner_intent_signature);
            assert_recovery(&artifact);
            let encoded = fs::read(directory.join("capsule-reblinded-journal")).unwrap();
            let journal = PreparationJournal::decode(&encoded).unwrap();
            assert_eq!(verify_preparation(&artifact.witness).unwrap(), journal);
            let ctx = ValidatedContext::decode(&original.witness.context_bytes).unwrap();
            let binding = original.witness.preparation_binding().unwrap();
            assert_eq!(journal.packet_binding(), binding);
            assert_eq!(journal.consumption_tag(), ctx.context().consumption_tag);
            journal.check_solver_capsule(SolverCapsule {
                context: &ctx, private_packet_binding: &binding,
                capsule_blind: &artifact.witness.capsule_blind,
                redacted_payment: &artifact.witness.redacted_p_pczt,
                recovery_transaction: &artifact.witness.q_transaction,
            }).unwrap();
            assert_eq!(journal.check_solver_capsule(SolverCapsule {
                context: &ctx, private_packet_binding: &binding, capsule_blind: &CAPSULE_BLIND,
                redacted_payment: &artifact.witness.redacted_p_pczt,
                recovery_transaction: &artifact.witness.q_transaction,
            }), Err(PreparationError::SolverCapsule));
        }
        "limited-write" => {
            let artifact = load_preparation(directory.join("source"), &KEY, NAMESPACE, context().digest()).unwrap();
            save_preparation(directory.join("limited"), &KEY, NAMESPACE, &artifact).unwrap();
        }
        _ => panic!("unknown generated-fixture child scenario"),
    }
}


#[test]
fn retained_v1_v2_final_and_pending_are_explicitly_unsupported_and_unchanged() {
    let directory = private_directory();
    // Opaque recognition fixtures, not encrypted old custody or restore evidence.
    for (version, old_domain) in [(1, b"ziquid.u.custody.v1"), (2, b"ziquid.u.custody.v2")] {
        let mut retained = old_domain.to_vec();
        retained.extend_from_slice(b"opaque retained bytes; no old decryption inference");
        for length in (1..=old_domain.len()).chain(std::iter::once(retained.len())) {
            let bytes = &retained[..length];
            let path = directory.path().join(format!("old-v{version}-final-{length}"));
            write_private(&path, bytes);
            assert!(matches!(load_preparation(&path, &KEY, NAMESPACE, context().digest()), Err(CustodyError::UnsupportedVersion)));
            assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsupportedVersion)));
            assert_eq!(fs::read(&path).unwrap(), bytes);
            let path = directory.path().join(format!("old-v{version}-stage-{length}"));
            let stage = pending(&path);
            write_private(&stage, bytes);
            assert!(matches!(save_preparation(&path, &KEY, NAMESPACE, &FIXTURE), Err(CustodyError::UnsupportedVersion)));
            assert_eq!(fs::read(&stage).unwrap(), bytes);
            assert!(!path.exists());
        }
    }
}

