#![cfg(target_os = "linux")]

//! Generated offline capabilities only: synthetic V3 J, fresh DKG and real v6
//! authorization. No wallet, source admission, funding, network or target facts.

use std::{
    fs::{self, File, OpenOptions, Permissions}, io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf}, process::Command, sync::LazyLock,
};

use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::{AeadInPlace, KeyInit}};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{
    Anchor, Note,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::{Pczt, roles::redactor::Redactor};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::{consensus::{BranchId, Network}, memo::MemoBytes, value::Zatoshis};
use zeroize::{Zeroize, Zeroizing};
use ziquid_runtime::custody::CustodyError;
use ziquid_runtime::native_recovery::{
    RecoveryError, RecoverySelection, RecoveryStage, joint_spend_terms_digest,
    load_finished, load_preauthorized, save_finished, save_preauthorized,
};
use ziquid_threshold::{
    Alpha, DkgSession, Participant, aggregate, check_action_rk, commit, sign_share,
};
use ziquid_zcash::{
    IronwoodTransaction, OutputPlan, SourceParameters,
    joint_spend::{JointSpendTerms, build_deferred_joint_spend, review_joint_spend},
};

const NAMESPACE: [u8; 32] = [0x81; 32];
static VERIFYING_KEY: LazyLock<VerifyingKey> =
    LazyLock::new(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3));
static FIXTURE: LazyLock<Fixture> = LazyLock::new(Fixture::new);
// One genuine Halo2 proof in this whole test process, reused by finished-stage
// cases and subprocess consumers. No child process generates another proof.
static FINISHED: LazyLock<FinishedFixture> = LazyLock::new(|| {
    let directory = private_directory();
    let key = generated_key();
    let selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let path = directory.path().join("completion-input");
    let terms = FIXTURE.terms();
    let digest = save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).unwrap();
    let restored = load_preauthorized(&path, &key, NAMESPACE, &selection, digest,
        &terms, &VERIFYING_KEY).unwrap();
    let (membership, anchor) = synthetic_membership(&FIXTURE.note);
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let transaction = restored.into_preauthorized().complete(
        membership, anchor, &pk, &VERIFYING_KEY, &mut OsRng,
    ).unwrap();
    assert_eq!(transaction.effect_id(), FIXTURE.sighash);
    let consensus = transaction.serialize().unwrap();
    FinishedFixture { anchor, consensus }
});

struct FinishedFixture {
    anchor: Anchor,
    consensus: Vec<u8>,
}

fn private_directory() -> tempfile::TempDir {
    tempfile::Builder::new().permissions(Permissions::from_mode(0o700)).tempdir().unwrap()
}

fn generated_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}

struct Fixture {
    source: SourceParameters,
    fvk: FullViewingKey,
    note: Note,
    payout: OutputPlan,
    group_ak: [u8; 32],
    early_r: Zeroizing<Vec<u8>>,
    alternate_r: Zeroizing<Vec<u8>>,
    sighash: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let (mut first, first_round1) = DkgSession::start(Participant::First, &mut OsRng).unwrap();
        let (mut second, second_round1) = DkgSession::start(Participant::Second, &mut OsRng).unwrap();
        let first_round2 = first.round2(&second_round1).unwrap();
        let second_round2 = second.round2(&first_round1).unwrap();
        let (first, group) = first.finalize(&second_round1, &second_round2).unwrap();
        let (second, second_group) = second.finalize(&first_round1, &first_round2).unwrap();
        assert_eq!(group.to_bytes(), second_group.to_bytes());
        let group_ak = group.verifying_key_bytes().unwrap();
        // Same experimental public byte-swap surrogate as the existing source
        // capability test; NOT production threshold-FVK construction evidence.
        let (source, fvk, note, payout) = fixture_terms(group_ak);
        let terms = JointSpendTerms {
            source: &source, note: &note, full_viewing_key: &fvk, group_ak,
            payout: &payout, fee: Zatoshis::from_u64(10_000).unwrap(),
        };
        let deferred = build_deferred_joint_spend(&terms, &mut ChaCha20Rng::from_seed([12; 32])).unwrap();
        let reviewed = review_joint_spend(deferred.private_pczt_bytes(), &terms).unwrap();
        let sighash = reviewed.shielded_sighash();
        let alpha = Alpha::from_bytes(&reviewed.alpha()).unwrap();
        check_action_rk(&group, &alpha, &reviewed.randomized_key()).unwrap();
        let (first_nonce, first_commitment) = commit(&first, &mut OsRng).unwrap();
        let (second_nonce, second_commitment) = commit(&second, &mut OsRng).unwrap();
        let commitments = [first_commitment, second_commitment];
        let first_signature = sign_share(&first, first_nonce, &sighash, &alpha, &commitments).unwrap();
        let second_signature = sign_share(&second, second_nonce, &sighash, &alpha, &commitments).unwrap();
        let signature = aggregate(&group, &sighash, &alpha, &commitments,
            &[first_signature, second_signature]).unwrap();
        let signed = reviewed.apply_external_signature(signature).unwrap();
        let early_r = Zeroizing::new(signed.private_pczt_bytes().to_vec());
        // Fresh nonces authorize the SAME reviewed effects a second time: both
        // capabilities are genuine, but immutable custody must not replace one
        // exact authorized PCZT with the other signature under the same binding.
        let (first_nonce, first_commitment) = commit(&first, &mut OsRng).unwrap();
        let (second_nonce, second_commitment) = commit(&second, &mut OsRng).unwrap();
        let commitments = [first_commitment, second_commitment];
        let first_signature = sign_share(&first, first_nonce, &sighash, &alpha, &commitments).unwrap();
        let second_signature = sign_share(&second, second_nonce, &sighash, &alpha, &commitments).unwrap();
        let signature = aggregate(&group, &sighash, &alpha, &commitments,
            &[first_signature, second_signature]).unwrap();
        let alternate = review_joint_spend(deferred.private_pczt_bytes(), &terms).unwrap()
            .apply_external_signature(signature).unwrap();
        let alternate_r = Zeroizing::new(alternate.private_pczt_bytes().to_vec());
        Self { source, fvk, note, payout, group_ak, early_r, alternate_r, sighash }
    }

    fn terms(&self) -> JointSpendTerms<'_> {
        JointSpendTerms {
            source: &self.source, note: &self.note, full_viewing_key: &self.fvk,
            group_ak: self.group_ak, payout: &self.payout, fee: Zatoshis::from_u64(10_000).unwrap(),
        }
    }

    fn selection(&self, stage: RecoveryStage) -> RecoverySelection {
        RecoverySelection {
            session_id: [0x82; 32], quote_id: [0x83; 32],
            terms_digest: joint_spend_terms_digest(&self.terms()),
            chain_context: [0x84; 32], deployment_context: [0x85; 32],
            shielded_sighash: self.sighash, stage,
        }
    }
}

#[test]
fn preauthorized_capsule_authenticates_readback_and_restores_exact_source_capability() {
    let directory = private_directory();
    let path = directory.path().join("session/preauthorized-r");
    let key = generated_key();
    let terms = FIXTURE.terms();
    let selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let digest = save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).unwrap();
    let ciphertext = fs::read(&path).unwrap();
    let restored = load_preauthorized(&path, &key, NAMESPACE, &selection, digest,
        &terms, &VERIFYING_KEY).unwrap();
    assert!(restored.private_pczt_bytes() == FIXTURE.early_r.as_slice());
    assert_eq!(restored.into_preauthorized().shielded_sighash(), FIXTURE.sighash);
    assert_eq!(save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).unwrap(), digest);
    assert_eq!(fs::read(&path).unwrap(), ciphertext);
    assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
}

fn fixture_terms(group_ak: [u8; 32]) -> (SourceParameters, FullViewingKey, Note, OutputPlan) {
    let mut fvk_bytes = Zeroizing::new(
        FullViewingKey::from(&SpendingKey::from_bytes([0x11; 32]).unwrap()).to_bytes(),
    );
    fvk_bytes[..32].copy_from_slice(&group_ak);
    let fvk = FullViewingKey::from_bytes(&fvk_bytes).unwrap();
    let mut rho_bytes = [0; 32];
    rho_bytes[0] = 21;
    let rho = Rho::from_bytes(&rho_bytes).unwrap();
    let mut rng = ChaCha20Rng::from_seed([21; 32]);
    let note = loop {
        let mut bytes = Zeroizing::new([0; 32]);
        rng.fill_bytes(&mut *bytes);
        if let Some(seed) = RandomSeed::from_bytes(*bytes, &rho).into_option()
            && let Some(note) = Note::from_parts(
                fvk.address_at(0u32, Scope::External), NoteValue::from_raw(50_000),
                rho, seed, NoteVersion::V3,
            ).into_option()
        {
            break note;
        }
    };
    let payout = OutputPlan::new(
        FullViewingKey::from(&SpendingKey::from_bytes([0x33; 32]).unwrap())
            .address_at(0u32, Scope::External),
        Zatoshis::from_u64(40_000).unwrap(), MemoBytes::from_bytes(b"synthetic early R").unwrap(),
    );
    let source = SourceParameters {
        network: Network::TestNetwork, target_height: 4_134_000.into(),
        expiry_height: 4_134_040.into(), consensus_branch: BranchId::Nu6_3,
        fee_rule: zip317::FeeRule::standard(),
    };
    (source, fvk, note, payout)
}

fn synthetic_membership(note: &Note) -> (MerklePath, Anchor) {
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    tree.append(MerkleHashOrchard::from_cmx(&cmx)).unwrap();
    let witness = IncrementalWitness::from_tree(tree).unwrap();
    let path: MerklePath = witness.path().unwrap().into();
    let anchor = path.root(cmx);
    (path, anchor)
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    File::open(path.parent().unwrap()).unwrap().sync_all().unwrap();
}

fn pending(path: &Path) -> PathBuf {
    path.with_file_name(format!(".{}.pending", path.file_name().unwrap().to_str().unwrap()))
}

#[test]
fn independent_selection_key_namespace_digest_and_terms_reject_without_changing_ciphertext() {
    let directory = private_directory();
    let key = generated_key();
    let path = directory.path().join("early-r");
    let terms = FIXTURE.terms();
    let selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let digest = save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).unwrap();
    let ciphertext = fs::read(&path).unwrap();
    for field in 0..7 {
        let mut wrong = selection;
        match field {
            0 => wrong.session_id[0] ^= 1,
            1 => wrong.quote_id[0] ^= 1,
            2 => wrong.terms_digest[0] ^= 1,
            3 => wrong.chain_context[0] ^= 1,
            4 => wrong.deployment_context[0] ^= 1,
            5 => wrong.shielded_sighash[0] ^= 1,
            6 => wrong.stage = RecoveryStage::Finished,
            _ => unreachable!(),
        }
        assert!(load_preauthorized(&path, &key, NAMESPACE, &wrong, digest,
            &terms, &VERIFYING_KEY).is_err());
        assert!(save_preauthorized(&path, &key, NAMESPACE, &wrong, &terms,
            &FIXTURE.early_r, &VERIFYING_KEY).is_err());
        assert_eq!(fs::read(&path).unwrap(), ciphertext);
    }
    let wrong_key = generated_key();
    assert!(load_preauthorized(&path, &wrong_key, NAMESPACE, &selection, digest,
        &terms, &VERIFYING_KEY).is_err());
    assert!(load_preauthorized(&path, &key, [0x99; 32], &selection, digest,
        &terms, &VERIFYING_KEY).is_err());
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert_eq!(load_preauthorized(&path, &key, NAMESPACE, &selection, wrong_digest,
        &terms, &VERIFYING_KEY).unwrap_err(), RecoveryError::Digest);
    for field in 0..7 {
        let mut zero = selection;
        let namespace = if field == 0 { [0; 32] } else { NAMESPACE };
        match field {
            0 => {},
            1 => zero.session_id = [0; 32],
            2 => zero.quote_id = [0; 32],
            3 => zero.chain_context = [0; 32],
            4 => zero.deployment_context = [0; 32],
            5 => zero.terms_digest = [0; 32],
            6 => zero.shielded_sighash = [0; 32],
            _ => unreachable!(),
        }
        let absent = directory.path().join(format!("zero-{field}/r"));
        assert_eq!(save_preauthorized(&absent, &key, namespace, &zero, &terms,
            &FIXTURE.early_r, &VERIFYING_KEY), Err(RecoveryError::Selection));
        assert!(!absent.parent().unwrap().exists());
    }
    let wrong_memo = OutputPlan::new(terms.payout.recipient(), terms.payout.value(), MemoBytes::empty());
    let wrong_terms = JointSpendTerms { payout: &wrong_memo, ..terms };
    assert_eq!(load_preauthorized(&path, &key, NAMESPACE, &selection, digest,
        &wrong_terms, &VERIFYING_KEY).unwrap_err(), RecoveryError::Terms);
    assert_eq!(fs::read(&path).unwrap(), ciphertext);
    assert_eq!(format!("{selection:?}"), "RecoverySelection { stage: Preauthorized, .. }");
    let restored = load_preauthorized(&path, &key, NAMESPACE, &selection, digest,
        &terms, &VERIFYING_KEY).unwrap();
    assert_eq!(format!("{restored:?}"), "RestoredRecovery([redacted])");
}

#[test]
fn equal_session_quote_ids_are_valid_local_selection_not_an_authentication_claim() {
    let directory = private_directory();
    let key = generated_key();
    let path = directory.path().join("equal-identities-r");
    let terms = FIXTURE.terms();
    let mut selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    selection.quote_id = selection.session_id;
    let digest = save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).unwrap();
    let restored = load_preauthorized(&path, &key, NAMESPACE, &selection, digest,
        &terms, &VERIFYING_KEY).unwrap();
    assert!(restored.private_pczt_bytes() == FIXTURE.early_r.as_slice());
}

#[test]
fn complete_explicit_terms_digest_and_semantic_review_reject_every_changed_term() {
    let directory = private_directory();
    let key = generated_key();
    let terms = FIXTURE.terms();
    let selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let mut sources = Vec::new();
    for field in 0..8 {
        let mut source = FIXTURE.source.clone();
        match field {
            0 => source.network = Network::MainNetwork,
            1 => source.target_height = 4_134_001.into(),
            2 => source.expiry_height = 4_134_041.into(),
            3 => source.consensus_branch = BranchId::Nu6_2,
            4..=7 => source.fee_rule = zip317::FeeRule::non_standard(
                Zatoshis::from_u64(if field == 4 { 5_001 } else { 5_000 }).unwrap(),
                if field == 5 { 3 } else { 2 }, if field == 6 { 149 } else { 150 },
                if field == 7 { 33 } else { 34 },
            ).unwrap(),
            _ => unreachable!(),
        }
        sources.push(source);
    }
    let note_recipient = Note::from_parts(
        FIXTURE.fvk.address_at(1u32, Scope::External), FIXTURE.note.value(),
        FIXTURE.note.rho(), *FIXTURE.note.rseed(), NoteVersion::V3,
    ).unwrap();
    let note_value = Note::from_parts(FIXTURE.note.recipient(), NoteValue::from_raw(50_001),
        FIXTURE.note.rho(), *FIXTURE.note.rseed(), NoteVersion::V3).unwrap();
    let note_version = Note::from_parts(FIXTURE.note.recipient(), FIXTURE.note.value(),
        FIXTURE.note.rho(), *FIXTURE.note.rseed(), NoteVersion::V2).unwrap();
    let note_seed = loop {
        let mut bytes = Zeroizing::new([0; 32]); OsRng.fill_bytes(&mut *bytes);
        if let Some(seed) = RandomSeed::from_bytes(*bytes, &FIXTURE.note.rho()).into_option()
            && let Some(note) = Note::from_parts(FIXTURE.note.recipient(), FIXTURE.note.value(),
                FIXTURE.note.rho(), seed, NoteVersion::V3).into_option()
        { break note; }
    };
    let rho = Rho::from_bytes(&[22; 32]).unwrap();
    let note_rho = loop {
        let mut bytes = Zeroizing::new([0; 32]); OsRng.fill_bytes(&mut *bytes);
        if let Some(seed) = RandomSeed::from_bytes(*bytes, &rho).into_option()
            && let Some(note) = Note::from_parts(FIXTURE.note.recipient(), FIXTURE.note.value(),
                rho, seed, NoteVersion::V3).into_option()
        { break note; }
    };
    let wrong_fvk = FullViewingKey::from(&SpendingKey::from_bytes([0x34; 32]).unwrap());
    let wrong_recipient = OutputPlan::new(FIXTURE.fvk.address_at(1u32, Scope::External),
        terms.payout.value(), terms.payout.memo().clone());
    let wrong_value = OutputPlan::new(terms.payout.recipient(), Zatoshis::from_u64(39_999).unwrap(),
        terms.payout.memo().clone());
    let mut memo = Zeroizing::new(*terms.payout.memo().as_array());
    memo[511] ^= 1;
    let wrong_memo = OutputPlan::new(terms.payout.recipient(), terms.payout.value(),
        MemoBytes::from_bytes(&*memo).unwrap());
    let mut group_ak = terms.group_ak; group_ak[0] ^= 1;
    let changes = sources.iter().map(|source| JointSpendTerms { source, ..terms }).chain([
        JointSpendTerms { note: &note_recipient, ..terms },
        JointSpendTerms { note: &note_value, ..terms },
        JointSpendTerms { note: &note_rho, ..terms },
        JointSpendTerms { note: &note_seed, ..terms },
        JointSpendTerms { note: &note_version, ..terms },
        JointSpendTerms { full_viewing_key: &wrong_fvk, ..terms },
        JointSpendTerms { group_ak, ..terms },
        JointSpendTerms { payout: &wrong_recipient, ..terms },
        JointSpendTerms { payout: &wrong_value, ..terms },
        JointSpendTerms { payout: &wrong_memo, ..terms },
        JointSpendTerms { fee: Zatoshis::from_u64(9_999).unwrap(), ..terms },
    ]);
    for (index, changed) in changes.enumerate() {
        assert_ne!(joint_spend_terms_digest(&changed), selection.terms_digest);
        let path = directory.path().join(format!("changed-{index}/r"));
        assert_eq!(save_preauthorized(&path, &key, NAMESPACE, &selection, &changed,
            &FIXTURE.early_r, &VERIFYING_KEY), Err(RecoveryError::Terms));
        assert!(!path.parent().unwrap().exists());
    }
    // Updating a caller hash does NOT make hostile PCZT semantics acceptable.
    let changed = JointSpendTerms { payout: &wrong_memo, ..terms };
    let updated = RecoverySelection { terms_digest: joint_spend_terms_digest(&changed), ..selection };
    let absent = directory.path().join("self-labeled/r");
    assert_eq!(save_preauthorized(&absent, &key, NAMESPACE, &updated, &changed,
        &FIXTURE.early_r, &VERIFYING_KEY), Err(RecoveryError::Capability));
    assert!(!absent.parent().unwrap().exists());
}

#[test]
fn unsigned_missing_padding_invalid_signature_preset_membership_and_trailing_pczt_never_publish() {
    let directory = private_directory();
    let key = generated_key();
    let terms = FIXTURE.terms();
    let selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let reviewed = review_joint_spend(&FIXTURE.early_r, &terms).unwrap();
    let real = reviewed.action_index();
    let padding = 1 - real;
    let mut variants = Vec::new();
    for index in [real, padding] {
        let pczt = Redactor::new(Pczt::parse(&FIXTURE.early_r).unwrap())
            .redact_ironwood_with(|mut bundle| {
                bundle.redact_action(index, |mut action| action.clear_spend_auth_sig());
            }).finish();
        variants.push(Zeroizing::new(pczt.serialize().unwrap()));
    }
    let mut trailing = Zeroizing::new(Vec::with_capacity(FIXTURE.early_r.len() + 1));
    trailing.extend_from_slice(&FIXTURE.early_r); trailing.push(0);
    variants.push(trailing);
    let pczt = Pczt::parse(&FIXTURE.early_r).unwrap();
    let signature = pczt.ironwood().actions()[real].spend().spend_auth_sig().as_ref().unwrap();
    let signature_at = FIXTURE.early_r.windows(signature.len()).position(|bytes| bytes == signature).unwrap();
    let mut bad_signature = Zeroizing::new(FIXTURE.early_r.to_vec());
    bad_signature[signature_at] ^= 1;
    variants.push(bad_signature);
    let (membership, anchor) = synthetic_membership(&FIXTURE.note);
    let attached = reviewed.attach_membership(membership, anchor).unwrap();
    variants.push(Zeroizing::new(attached.private_pczt_bytes().to_vec()));
    let wrong_vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let absent = directory.path().join("wrong-circuit/r");
    assert_eq!(save_preauthorized(&absent, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &wrong_vk), Err(RecoveryError::Capability));
    assert!(!absent.parent().unwrap().exists());
    for (index, early) in variants.iter().enumerate() {
        let absent = directory.path().join(format!("unsigned-{index}/r"));
        assert_eq!(save_preauthorized(&absent, &key, NAMESPACE, &selection, &terms,
            early, &VERIFYING_KEY), Err(RecoveryError::Capability));
        assert!(!absent.parent().unwrap().exists());
        // Even genuinely AEAD-authenticated hostile source material is reviewed
        // again on load. A valid envelope is not a source capability approval.
        let payload = canonical_payload(&selection, early, None);
        let ciphertext = encrypt_payload(&key, &selection, &payload);
        let path = directory.path().join(format!("authenticated-invalid-{index}"));
        write_private(&path, &ciphertext);
        assert_eq!(load_preauthorized(&path, &key, NAMESPACE, &selection,
            Sha256::digest(&ciphertext).into(), &terms, &VERIFYING_KEY).unwrap_err(),
            RecoveryError::Capability);
        assert_eq!(fs::read(path).unwrap(), ciphertext);
    }
    let path = directory.path().join("oversized/r");
    let oversized = Zeroizing::new(vec![0; 16 * 1024 * 1024 + 1]);
    assert_eq!(save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
        &oversized, &VERIFYING_KEY), Err(RecoveryError::ResourceLimit));
    assert!(!path.parent().unwrap().exists());
}

// Independent hostile-fixture encoder, never a production escape hatch. Native
// format fields are fixed literals here so parser tests do not mirror its codec.
const ENVELOPE: &[u8] = b"ziquid.nativeR.v1\0";
const PAYLOAD: &[u8] = b"ZIQUID_NATIVE_R_CAPSULE\0";
const SELECTED_BYTES: usize = 1 + 6 * 32;

fn independent_selected(selection: &RecoverySelection) -> Zeroizing<[u8; SELECTED_BYTES]> {
    let mut bytes = Zeroizing::new([0; SELECTED_BYTES]); bytes[0] = selection.stage as u8;
    for (index, field) in [&selection.session_id, &selection.quote_id, &selection.terms_digest,
        &selection.chain_context, &selection.deployment_context, &selection.shielded_sighash]
        .into_iter().enumerate()
    {
        bytes[1 + index * 32..1 + (index + 1) * 32].copy_from_slice(field);
    }
    bytes
}

fn canonical_payload(
    selection: &RecoverySelection, early: &[u8], finished: Option<(Anchor, &[u8])>,
) -> Zeroizing<Vec<u8>> {
    let length = PAYLOAD.len() + 2 + SELECTED_BYTES + 4 + early.len()
        + finished.map_or(0, |(_, bytes)| 32 + 4 + bytes.len());
    let mut payload = Zeroizing::new(Vec::with_capacity(length + 17));
    payload.extend_from_slice(PAYLOAD); payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(&*independent_selected(selection));
    payload.extend_from_slice(&(early.len() as u32).to_le_bytes()); payload.extend_from_slice(early);
    if let Some((anchor, consensus)) = finished {
        payload.extend_from_slice(&anchor.to_bytes());
        payload.extend_from_slice(&(consensus.len() as u32).to_le_bytes());
        payload.extend_from_slice(consensus);
    }
    payload
}

fn encrypt_payload(key: &[u8; 32], selection: &RecoverySelection, payload: &[u8]) -> Vec<u8> {
    let mut nonce = [0; 24]; OsRng.fill_bytes(&mut nonce);
    let mut header = ENVELOPE.to_vec();
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&((payload.len() + 16) as u32).to_le_bytes());
    let mut hash = Sha256::new(); hash.update(b"ZIQUID_NATIVE_R_SELECTION\0");
    hash.update(1u16.to_le_bytes()); hash.update(Sha256::digest(independent_selected(selection).as_slice()));
    let context: [u8; 32] = hash.finalize().into();
    let mut aad = header.clone(); aad.extend_from_slice(&NAMESPACE); aad.extend_from_slice(&context);
    let mut guarded = Zeroizing::new(payload.to_vec());
    let tag = XChaCha20Poly1305::new(key.into()).encrypt_in_place_detached(
        XNonce::from_slice(&nonce), &aad, &mut guarded,
    ).unwrap();
    let mut ciphertext = Vec::with_capacity(header.len() + guarded.len() + 16);
    ciphertext.extend_from_slice(&header); ciphertext.extend_from_slice(&guarded);
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

#[test]
fn authenticated_codec_rejects_unknown_version_stage_shape_lengths_selection_and_trailing() {
    let directory = private_directory();
    let key = generated_key();
    let terms = FIXTURE.terms();
    let selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let valid = canonical_payload(&selection, &FIXTURE.early_r, None);
    let selected_at = PAYLOAD.len() + 2;
    let length_at = selected_at + SELECTED_BYTES;
    let mut variants = Vec::new();
    for field in 0..9 {
        let mut bytes = valid.clone();
        match field {
            0 => bytes[0] ^= 1,
            1 => bytes[PAYLOAD.len()..PAYLOAD.len() + 2].copy_from_slice(&2u16.to_le_bytes()),
            2 => bytes[selected_at] = 2,
            3 => bytes[selected_at + 33] ^= 1,
            4 => bytes[length_at..length_at + 4].copy_from_slice(&0u32.to_le_bytes()),
            5 => bytes[length_at..length_at + 4].copy_from_slice(&(16u32 * 1024 * 1024 + 1).to_le_bytes()),
            6 => bytes[length_at..length_at + 4].copy_from_slice(&u32::MAX.to_le_bytes()),
            7 => { let last = bytes.len() - 1; bytes[last..].zeroize(); bytes.truncate(last); },
            8 => {
                let mut trailing = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
                trailing.extend_from_slice(&bytes); trailing.push(0); bytes = trailing;
            },
            _ => unreachable!(),
        }
        variants.push(bytes);
    }
    // A preauthorized frame cannot smuggle an anchor or finished fields.
    variants.push(canonical_payload(&selection, &FIXTURE.early_r,
        Some((synthetic_membership(&FIXTURE.note).1, b"not consensus"))));
    for (index, payload) in variants.iter().enumerate() {
        let ciphertext = encrypt_payload(&key, &selection, payload);
        let path = directory.path().join(format!("malformed-{index}"));
        write_private(&path, &ciphertext);
        assert!(load_preauthorized(&path, &key, NAMESPACE, &selection,
            Sha256::digest(&ciphertext).into(), &terms, &VERIFYING_KEY).is_err());
        assert_eq!(fs::read(path).unwrap(), ciphertext);
    }
    let ciphertext = encrypt_payload(&key, &selection, &valid);
    let path = directory.path().join("independently-encoded-valid");
    write_private(&path, &ciphertext);
    let restored = load_preauthorized(&path, &key, NAMESPACE, &selection,
        Sha256::digest(&ciphertext).into(), &terms, &VERIFYING_KEY).unwrap();
    assert!(restored.private_pczt_bytes() == FIXTURE.early_r.as_slice());
    let finished_selection = FIXTURE.selection(RecoveryStage::Finished);
    let missing_finished = canonical_payload(&finished_selection, &FIXTURE.early_r, None);
    let ciphertext = encrypt_payload(&key, &finished_selection, &missing_finished);
    let path = directory.path().join("finished-without-fields"); write_private(&path, &ciphertext);
    assert!(load_finished(&path, &key, NAMESPACE, &finished_selection,
        Sha256::digest(&ciphertext).into(), &terms, synthetic_membership(&FIXTURE.note).1,
        &VERIFYING_KEY, &mut OsRng).is_err());
}

#[test]
fn foreign_legacy_unknown_final_and_pending_bytes_are_preserved() {
    let directory = private_directory();
    let key = generated_key();
    let terms = FIXTURE.terms();
    let selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    for (format, domain) in [b"ziquid.u.custody.v1".as_slice(), b"ziquid.u.custody.v2".as_slice(),
        b"ziquid.u.custody.v3".as_slice(), b"ziquid.samechain.backup.v1".as_slice(),
        b"ziquid.samechain.release.v1".as_slice(), b"ziquid.nativeR.v2\0".as_slice(),
        b"unrecognized retained artifact".as_slice()].into_iter().enumerate()
    {
        for length in 1..=domain.len() {
            let bytes = &domain[..length];
            let path = directory.path().join(format!("foreign-{format}-{length}"));
            write_private(&path, bytes);
            assert!(load_preauthorized(&path, &key, NAMESPACE, &selection, [0x99; 32],
                &terms, &VERIFYING_KEY).is_err());
            assert!(save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
                &FIXTURE.early_r, &VERIFYING_KEY).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
            let resumed = directory.path().join(format!("pending-{format}-{length}"));
            let staging = pending(&resumed); write_private(&staging, bytes);
            assert!(save_preauthorized(&resumed, &key, NAMESPACE, &selection, &terms,
                &FIXTURE.early_r, &VERIFYING_KEY).is_err());
            assert_eq!(fs::read(&staging).unwrap(), bytes);
            assert!(!resumed.exists());
        }
    }
}

#[test]
fn strict_private_file_policy_tamper_trailing_and_reserved_stage_names_reject() {
    let directory = private_directory();
    let key = generated_key();
    let terms = FIXTURE.terms();
    let selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let path = directory.path().join("early-r");
    let digest = save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).unwrap();
    let ciphertext = fs::read(&path).unwrap();
    let fvk = Zeroizing::new(FIXTURE.fvk.to_bytes());
    assert!(!ciphertext.windows(fvk.len()).any(|bytes| bytes == fvk.as_slice()));
    assert!(!ciphertext.windows(FIXTURE.early_r.len()).any(|bytes| bytes == FIXTURE.early_r.as_slice()));
    assert!(!ciphertext.windows(b"synthetic early R".len()).any(|bytes| bytes == b"synthetic early R"));
    for mode in [0o640, 0o644] {
        fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
        assert_eq!(load_preauthorized(&path, &key, NAMESPACE, &selection, digest,
            &terms, &VERIFYING_KEY).unwrap_err(), RecoveryError::Custody(CustodyError::UnsafePath));
        assert_eq!(save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
            &FIXTURE.early_r, &VERIFYING_KEY), Err(RecoveryError::Custody(CustodyError::UnsafePath)));
        assert_eq!(fs::read(&path).unwrap(), ciphertext);
    }
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let hardlink = directory.path().join("hardlink"); fs::hard_link(&path, &hardlink).unwrap();
    assert!(load_preauthorized(&path, &key, NAMESPACE, &selection, digest, &terms, &VERIFYING_KEY).is_err());
    fs::remove_file(hardlink).unwrap();
    let link = directory.path().join("symlink"); symlink(&path, &link).unwrap();
    assert_eq!(load_preauthorized(&link, &key, NAMESPACE, &selection, digest,
        &terms, &VERIFYING_KEY).unwrap_err(), RecoveryError::Custody(CustodyError::UnsafePath));
    let reserved = directory.path().join(".caller-chosen.pending"); write_private(&reserved, &ciphertext);
    assert_eq!(load_preauthorized(&reserved, &key, NAMESPACE, &selection, digest,
        &terms, &VERIFYING_KEY).unwrap_err(), RecoveryError::Custody(CustodyError::UnsafePath));
    assert_eq!(save_preauthorized(&reserved, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY), Err(RecoveryError::Custody(CustodyError::UnsafePath)));
    assert_eq!(fs::read(&reserved).unwrap(), ciphertext);
    let hostile_directory = directory.path().join("hostile"); fs::create_dir(&hostile_directory).unwrap();
    fs::set_permissions(&hostile_directory, Permissions::from_mode(0o770)).unwrap();
    assert_eq!(save_preauthorized(hostile_directory.join("r"), &key, NAMESPACE, &selection,
        &terms, &FIXTURE.early_r, &VERIFYING_KEY), Err(RecoveryError::Custody(CustodyError::UnsafePath)));
    assert!(!hostile_directory.join("r").exists());
    for mutation in 0..2 {
        let mut changed = ciphertext.clone();
        if mutation == 0 { *changed.last_mut().unwrap() ^= 1; } else { changed.push(0); }
        let path = directory.path().join(format!("damaged-{mutation}")); write_private(&path, &changed);
        assert!(load_preauthorized(&path, &key, NAMESPACE, &selection,
            Sha256::digest(&changed).into(), &terms, &VERIFYING_KEY).is_err());
        assert!(save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
            &FIXTURE.early_r, &VERIFYING_KEY).is_err());
        assert_eq!(fs::read(&path).unwrap(), changed);
    }
    assert_eq!(load_preauthorized(directory.path().join("absent/early-r"), &key, NAMESPACE,
        &selection, digest, &terms, &VERIFYING_KEY).unwrap_err(), RecoveryError::Custody(CustodyError::NotFound));
    assert!(!directory.path().join("absent").exists());
}

#[test]
fn finished_capsule_reuses_restored_early_proof_and_independent_anchor_with_distinct_immutable_stage() {
    let directory = private_directory();
    let key = generated_key();
    let terms = FIXTURE.terms();
    let early_selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let selection = FIXTURE.selection(RecoveryStage::Finished);
    let early_path = directory.path().join("preauthorized-r");
    let early_digest = save_preauthorized(&early_path, &key, NAMESPACE, &early_selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).unwrap();
    let early_ciphertext = fs::read(&early_path).unwrap();
    let path = directory.path().join("finished-r");
    let digest = save_finished(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, FINISHED.anchor, &FINISHED.consensus, &VERIFYING_KEY, &mut OsRng).unwrap();
    let ciphertext = fs::read(&path).unwrap();
    let restored = load_finished(&path, &key, NAMESPACE, &selection, digest, &terms,
        FINISHED.anchor, &VERIFYING_KEY, &mut OsRng).unwrap();
    assert!(restored.private_pczt_bytes() == FIXTURE.early_r.as_slice());
    let checked = restored.finished_transaction().unwrap();
    assert_eq!(checked.effect_id(), FIXTURE.sighash);
    assert_eq!(checked.serialize().unwrap(), FINISHED.consensus);
    let owned = restored.into_finished().unwrap();
    assert_eq!(owned.serialize().unwrap(), FINISHED.consensus);
    assert_eq!(save_finished(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, FINISHED.anchor, &FINISHED.consensus, &VERIFYING_KEY, &mut OsRng).unwrap(), digest);
    assert_eq!(fs::read(&path).unwrap(), ciphertext);
    assert_eq!(fs::read(&early_path).unwrap(), early_ciphertext);
    assert!(load_preauthorized(&path, &key, NAMESPACE, &early_selection, digest,
        &terms, &VERIFYING_KEY).is_err());
    assert!(load_finished(&early_path, &key, NAMESPACE, &selection, early_digest, &terms,
        FINISHED.anchor, &VERIFYING_KEY, &mut OsRng).is_err());
    assert!(save_finished(&early_path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, FINISHED.anchor, &FINISHED.consensus, &VERIFYING_KEY, &mut OsRng).is_err());
    assert_eq!(fs::read(&early_path).unwrap(), early_ciphertext);

    let wrong_anchor = Anchor::empty_tree();
    assert!(wrong_anchor != FINISHED.anchor);
    assert_eq!(load_finished(&path, &key, NAMESPACE, &selection, digest, &terms,
        wrong_anchor, &VERIFYING_KEY, &mut OsRng).unwrap_err(), RecoveryError::Capability);
    let absent = directory.path().join("wrong-anchor/r");
    assert_eq!(save_finished(&absent, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, wrong_anchor, &FINISHED.consensus, &VERIFYING_KEY, &mut OsRng),
        Err(RecoveryError::Capability));
    assert!(!absent.parent().unwrap().exists());
    let mut wrong_digest = digest; wrong_digest[0] ^= 1;
    assert_eq!(load_finished(&path, &key, NAMESPACE, &selection, wrong_digest, &terms,
        FINISHED.anchor, &VERIFYING_KEY, &mut OsRng).unwrap_err(), RecoveryError::Digest);
    let wrong_key = generated_key();
    assert!(load_finished(&path, &wrong_key, NAMESPACE, &selection, digest, &terms,
        FINISHED.anchor, &VERIFYING_KEY, &mut OsRng).is_err());
    assert!(load_finished(&path, &key, [0x99; 32], &selection, digest, &terms,
        FINISHED.anchor, &VERIFYING_KEY, &mut OsRng).is_err());
    for field in 0..7 {
        let mut changed = selection;
        match field {
            0 => changed.session_id[0] ^= 1,
            1 => changed.quote_id[0] ^= 1,
            2 => changed.chain_context[0] ^= 1,
            3 => changed.deployment_context[0] ^= 1,
            4 => changed.terms_digest[0] ^= 1,
            5 => changed.shielded_sighash[0] ^= 1,
            6 => changed.stage = RecoveryStage::Preauthorized,
            _ => unreachable!(),
        }
        assert!(load_finished(&path, &key, NAMESPACE, &changed, digest, &terms,
            FINISHED.anchor, &VERIFYING_KEY, &mut OsRng).is_err());
        assert!(save_finished(&path, &key, NAMESPACE, &changed, &terms,
            &FIXTURE.early_r, FINISHED.anchor, &FINISHED.consensus, &VERIFYING_KEY, &mut OsRng).is_err());
        assert_eq!(fs::read(&path).unwrap(), ciphertext);
    }
    let wrong_memo = OutputPlan::new(terms.payout.recipient(), terms.payout.value(), MemoBytes::empty());
    let wrong_terms = JointSpendTerms { payout: &wrong_memo, ..terms };
    assert_eq!(load_finished(&path, &key, NAMESPACE, &selection, digest, &wrong_terms,
        FINISHED.anchor, &VERIFYING_KEY, &mut OsRng).unwrap_err(), RecoveryError::Terms);
    let wrong_vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    assert_eq!(load_finished(&path, &key, NAMESPACE, &selection, digest, &terms,
        FINISHED.anchor, &wrong_vk, &mut OsRng).unwrap_err(), RecoveryError::Capability);
    let action_count = IronwoodTransaction::parse(&FINISHED.consensus, BranchId::Nu6_3).unwrap()
        .transaction().ironwood_bundle().unwrap().actions().len();
    let signatures_at = FINISHED.consensus.len() - 64 * (action_count + 1);
    let mut variants = Vec::new();
    for index in 0..action_count {
        let mut invalid = FINISHED.consensus.clone();
        invalid[signatures_at + 64 * index..signatures_at + 64 * (index + 1)].fill(0);
        variants.push(invalid);
    }
    let mut binding = FINISHED.consensus.clone();
    binding[FINISHED.consensus.len() - 64..].fill(0); variants.push(binding);
    let mut proof = FINISHED.consensus.clone(); proof[signatures_at - 1] ^= 1; variants.push(proof);
    let mut trailing = FINISHED.consensus.clone(); trailing.push(0); variants.push(trailing);
    for (index, invalid) in variants.iter().enumerate() {
        let absent = directory.path().join(format!("invalid-finished-{index}/r"));
        assert_eq!(save_finished(&absent, &key, NAMESPACE, &selection, &terms,
            &FIXTURE.early_r, FINISHED.anchor, invalid, &VERIFYING_KEY, &mut OsRng),
            Err(RecoveryError::Capability));
        assert!(!absent.parent().unwrap().exists());
        let payload = canonical_payload(&selection, &FIXTURE.early_r, Some((FINISHED.anchor, invalid)));
        let ciphertext = encrypt_payload(&key, &selection, &payload);
        let path = directory.path().join(format!("authenticated-invalid-finished-{index}"));
        write_private(&path, &ciphertext);
        assert_eq!(load_finished(&path, &key, NAMESPACE, &selection,
            Sha256::digest(&ciphertext).into(), &terms, FINISHED.anchor, &VERIFYING_KEY, &mut OsRng).unwrap_err(),
            RecoveryError::Capability);
    }
    let absent = directory.path().join("oversized-finished/r");
    let oversized = vec![0; 2 * 1024 * 1024 + 1];
    assert_eq!(save_finished(&absent, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, FINISHED.anchor, &oversized, &VERIFYING_KEY, &mut OsRng),
        Err(RecoveryError::ResourceLimit));
    assert!(!absent.parent().unwrap().exists());
    let payload = canonical_payload(&selection, &FIXTURE.early_r,
        Some((FINISHED.anchor, &FINISHED.consensus)));
    let anchor_at = PAYLOAD.len() + 2 + SELECTED_BYTES + 4 + FIXTURE.early_r.len();
    for mutation in 0..5 {
        let mut changed = Zeroizing::new(Vec::with_capacity(payload.len() + 1));
        changed.extend_from_slice(&payload);
        match mutation {
            0 => changed[anchor_at..anchor_at + 32].copy_from_slice(&wrong_anchor.to_bytes()),
            1 => changed[anchor_at + 32..anchor_at + 36].copy_from_slice(&0u32.to_le_bytes()),
            2 => changed[anchor_at + 32..anchor_at + 36].copy_from_slice(&(2u32 * 1024 * 1024 + 1).to_le_bytes()),
            3 => changed[anchor_at + 32..anchor_at + 36].copy_from_slice(&u32::MAX.to_le_bytes()),
            4 => changed.push(0),
            _ => unreachable!(),
        }
        let ciphertext = encrypt_payload(&key, &selection, &changed);
        let path = directory.path().join(format!("finished-frame-{mutation}"));
        write_private(&path, &ciphertext);
        assert!(load_finished(&path, &key, NAMESPACE, &selection,
            Sha256::digest(&ciphertext).into(), &terms, FINISHED.anchor, &VERIFYING_KEY, &mut OsRng).is_err());
        assert_eq!(fs::read(path).unwrap(), ciphertext);
    }
}

#[test]
fn exact_logical_conflicts_and_authenticated_pending_resume_preserve_immutable_ciphertext() {
    let directory = private_directory();
    let key = generated_key();
    let terms = FIXTURE.terms();
    let selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let path = directory.path().join("original");
    let digest = save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).unwrap();
    let ciphertext = fs::read(&path).unwrap();
    assert!(FIXTURE.alternate_r.as_slice() != FIXTURE.early_r.as_slice());
    assert_eq!(save_preauthorized(&path, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.alternate_r, &VERIFYING_KEY), Err(RecoveryError::Custody(CustodyError::Conflict)));
    assert_eq!(fs::read(&path).unwrap(), ciphertext);
    let mut different_binding = selection; different_binding.quote_id[0] ^= 1;
    assert!(save_preauthorized(&path, &key, NAMESPACE, &different_binding, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).is_err());
    let resumed = directory.path().join("resumed");
    let stage = pending(&resumed); write_private(&stage, &ciphertext);
    assert_eq!(save_preauthorized(&resumed, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.alternate_r, &VERIFYING_KEY), Err(RecoveryError::Custody(CustodyError::Conflict)));
    assert_eq!(fs::read(&stage).unwrap(), ciphertext); assert!(!resumed.exists());
    assert!(save_preauthorized(&resumed, &key, NAMESPACE, &different_binding, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).is_err());
    assert_eq!(fs::read(&stage).unwrap(), ciphertext); assert!(!resumed.exists());
    assert_eq!(save_preauthorized(&resumed, &key, NAMESPACE, &selection, &terms,
        &FIXTURE.early_r, &VERIFYING_KEY).unwrap(), digest);
    assert!(!stage.exists()); assert_eq!(fs::read(&resumed).unwrap(), ciphertext);
    // Different positive output effects are a real source relation, but they
    // cannot be relabeled as this prior local sighash or replace its ciphertext.
    let alternate = build_deferred_joint_spend(&terms, &mut ChaCha20Rng::from_seed([37; 32])).unwrap();
    let alternate = review_joint_spend(alternate.private_pczt_bytes(), &terms).unwrap();
    assert_ne!(alternate.shielded_sighash(), selection.shielded_sighash);
    let altered = RecoverySelection { shielded_sighash: alternate.shielded_sighash(), ..selection };
    assert!(load_preauthorized(&path, &key, NAMESPACE, &altered, digest, &terms, &VERIFYING_KEY).is_err());
    assert_eq!(fs::read(&path).unwrap(), ciphertext);
}

// Controlled generated-fixture selection record, NOT another product custody
// format or a source of authority inferred from the encrypted capsule. Only
// generated encryption capability is read from a separate 0600 file; no keys or
// private opening bytes are put in argv/environment/logs. Fixed terms below are
// recomputed outside the capsule by both restart consumers.
const RESTART_RECORD_BYTES: usize = 32 + 32 + 32 + 32 + SELECTED_BYTES + 32;

fn restart_record(early_digest: [u8; 32], finished_digest: [u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(RESTART_RECORD_BYTES));
    bytes.extend_from_slice(&FIXTURE.group_ak);
    bytes.extend_from_slice(&FIXTURE.sighash);
    bytes.extend_from_slice(&early_digest);
    bytes.extend_from_slice(&finished_digest);
    bytes.extend_from_slice(&*independent_selected(&FIXTURE.selection(RecoveryStage::Preauthorized)));
    bytes.extend_from_slice(&FINISHED.anchor.to_bytes());
    assert_eq!(bytes.len(), RESTART_RECORD_BYTES);
    bytes
}

fn run_restart_child(directory: &Path, mode: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_recovery_child", "--nocapture"])
        .env("ZIQUID_NATIVE_R_CHILD", mode)
        .env("ZIQUID_NATIVE_R_DIRECTORY", directory)
        .output().unwrap();
    assert!(output.status.success(), "generated native R restart consumer failed");
    let logs = [output.stdout, output.stderr].concat();
    assert!(!logs.windows(b"synthetic early R".len()).any(|bytes| bytes == b"synthetic early R"));
    let fvk = Zeroizing::new(FIXTURE.fvk.to_bytes());
    assert!(!logs.windows(fvk.len()).any(|bytes| bytes == fvk.as_slice()));
    assert!(!logs.windows(FIXTURE.early_r.len()).any(|bytes| bytes == FIXTURE.early_r.as_slice()));
}

#[test]
fn actual_process_restart_restores_both_stages_from_independent_local_pins() {
    let directory = private_directory();
    let early_path = directory.path().join("preauthorized-r");
    let finished_path = directory.path().join("finished-r");
    let key = generated_key();
    let early_selection = FIXTURE.selection(RecoveryStage::Preauthorized);
    let finished_selection = FIXTURE.selection(RecoveryStage::Finished);
    let early_digest = save_preauthorized(&early_path, &key, NAMESPACE, &early_selection,
        &FIXTURE.terms(), &FIXTURE.early_r, &VERIFYING_KEY).unwrap();
    let finished_digest = save_finished(&finished_path, &key, NAMESPACE, &finished_selection,
        &FIXTURE.terms(), &FIXTURE.early_r, FINISHED.anchor, &FINISHED.consensus,
        &VERIFYING_KEY, &mut OsRng).unwrap();
    let early_ciphertext = fs::read(&early_path).unwrap();
    let finished_ciphertext = fs::read(&finished_path).unwrap();
    write_private(&directory.path().join("generated-capability"), &*key);
    write_private(&directory.path().join("independent-selection"), &restart_record(early_digest, finished_digest));
    // The parent keeps only ciphertext plus independent fixture records for
    // these subprocesses. Exec creates a new address space: no inherited DKG,
    // Nonces, reviewer artifact, private PCZT or proof builder serves either child.
    drop(key);
    run_restart_child(directory.path(), "preauthorized");
    run_restart_child(directory.path(), "finished");
    assert_eq!(fs::read(&early_path).unwrap(), early_ciphertext);
    assert_eq!(fs::read(&finished_path).unwrap(), finished_ciphertext);
}

#[test]
fn native_recovery_child() {
    let Ok(mode) = std::env::var("ZIQUID_NATIVE_R_CHILD") else { return; };
    let directory = PathBuf::from(std::env::var_os("ZIQUID_NATIVE_R_DIRECTORY").unwrap());
    let encoded_key = Zeroizing::new(fs::read(directory.join("generated-capability")).unwrap());
    let key: &[u8; 32] = encoded_key.as_slice().try_into().unwrap();
    let record = Zeroizing::new(fs::read(directory.join("independent-selection")).unwrap());
    assert_eq!(record.len(), RESTART_RECORD_BYTES);
    let group_ak = record[0..32].try_into().unwrap();
    let sighash: [u8; 32] = record[32..64].try_into().unwrap();
    let early_digest = record[64..96].try_into().unwrap();
    let finished_digest = record[96..128].try_into().unwrap();
    let selected = &record[128..128 + SELECTED_BYTES];
    assert_eq!(selected[0], 0);
    let selection = RecoverySelection {
        session_id: selected[1..33].try_into().unwrap(),
        quote_id: selected[33..65].try_into().unwrap(),
        terms_digest: selected[65..97].try_into().unwrap(),
        chain_context: selected[97..129].try_into().unwrap(),
        deployment_context: selected[129..161].try_into().unwrap(),
        shielded_sighash: selected[161..193].try_into().unwrap(),
        stage: RecoveryStage::Preauthorized,
    };
    let anchor = Anchor::from_bytes(record[128 + SELECTED_BYTES..].try_into().unwrap()).unwrap();
    let (source, fvk, note, payout) = fixture_terms(group_ak);
    let terms = JointSpendTerms {
        source: &source, full_viewing_key: &fvk, note: &note, group_ak, payout: &payout,
        fee: Zatoshis::from_u64(10_000).unwrap(),
    };
    assert_eq!(joint_spend_terms_digest(&terms), selection.terms_digest);
    assert_eq!(selection.shielded_sighash, sighash);
    match mode.as_str() {
        "preauthorized" => {
            let restored = load_preauthorized(directory.join("preauthorized-r"), key, NAMESPACE,
                &selection, early_digest, &terms, &VERIFYING_KEY).unwrap();
            assert!(restored.finished_transaction().is_none());
            let reviewed = restored.into_preauthorized();
            assert_eq!(reviewed.shielded_sighash(), sighash);
            let (membership, actual_anchor) = synthetic_membership(&note);
            assert!(actual_anchor == anchor);
            let attached = reviewed.attach_membership(membership, anchor).unwrap();
            assert_eq!(attached.shielded_sighash(), sighash);
            // Reuse the existing finished proof: no new proof construction in
            // this process. Its full reviewer takes output notes from restored
            // early local custody, not a received output-note list or wallet IVK.
            let finished_selection = RecoverySelection { stage: RecoveryStage::Finished, ..selection };
            let finished = load_finished(directory.join("finished-r"), key, NAMESPACE,
                &finished_selection, finished_digest, &terms, anchor, &VERIFYING_KEY, &mut OsRng).unwrap();
            assert_eq!(finished.finished_transaction().unwrap().effect_id(), sighash);
        },
        "finished" => {
            let selection = RecoverySelection { stage: RecoveryStage::Finished, ..selection };
            let restored = load_finished(directory.join("finished-r"), key, NAMESPACE,
                &selection, finished_digest, &terms, anchor, &VERIFYING_KEY, &mut OsRng).unwrap();
            let finished = restored.into_finished().unwrap();
            assert_eq!(finished.effect_id(), sighash);
            let consensus = finished.serialize().unwrap();
            let parsed = IronwoodTransaction::parse(&consensus, BranchId::Nu6_3).unwrap();
            assert_eq!(parsed.serialize().unwrap(), consensus);
        },
        _ => panic!("unknown generated native R restart fixture"),
    }
}
