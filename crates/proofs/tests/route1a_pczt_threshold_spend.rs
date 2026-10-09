//! Offline route-1a capabilities: fresh 2-of-2 DKG, exact builder-generated F→J,
//! early R BEFORE F authorization or J membership, independent semantic review,
//! and genuine PostNu6_3 Halo2/full consensus extraction.
//!
//! Synthetic keys/trees only. This does not establish funding, source admission,
//! finality, target arming, durable custody, fresh-J disclosure permission, ZIP312
//! alpha-generation qualification or exchange/release qualification.

use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{
    Address, Anchor, Note,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    primitives::redpallas::{self, SpendAuth},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::{
    Pczt,
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, redactor::Redactor,
        signer::Signer, tx_extractor::TransactionExtractor, updater::Updater,
    },
};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use serde_json::{Value, json};
use zcash_primitives::transaction::{
    builder::{BundlePadding, DeferredPcztBuilder},
    components::orchard::write_action_without_auth,
    fees::zip317,
    sighash::SignableInput,
    sighash_v6::v6_signature_hash,
    txid::TxIdDigester,
};
use zcash_protocol::{
    consensus::{BranchId, Network}, constants::MAX_BLOCK_BYTES, memo::MemoBytes, value::Zatoshis,
};
use zeroize::Zeroizing;
use ziquid_threshold::{
    Alpha, DkgSession, GroupPublicKey, KeyShare, Participant, aggregate, commit, sign_share,
    check_action_rk,
};
use ziquid_proofs::native_relation::{
    FundingFacts, JointSpendFacts, NativeOutputFacts, OwnedInputFacts, SourceFacts,
    verify_funding, verify_joint_consumer,
};
use ziquid_zcash::{
    AuthoringError, IronwoodTransaction, OutputPlan, OwnedInput, SourceParameters, ValidationError,
    custody::CustodyError,
    funding::{FundingError, prepare_joint_funding},
    joint_spend::{
        DeferredJointSpend, FinishedJointSpendExpectation, JointSpendError, JointSpendTerms,
        build_deferred_joint_spend, review_finished_joint_spend, review_joint_spend,
    },
};

struct Ceremony {
    first: KeyShare,
    second: KeyShare,
    group: GroupPublicKey,
}

fn run_dkg() -> Ceremony {
    let mut rng = OsRng;
    let (mut first, first_round1) = DkgSession::start(Participant::First, &mut rng).unwrap();
    let (mut second, second_round1) = DkgSession::start(Participant::Second, &mut rng).unwrap();
    let first_round2 = first.round2(&second_round1).unwrap();
    let second_round2 = second.round2(&first_round1).unwrap();
    let (first, group) = first.finalize(&second_round1, &second_round2).unwrap();
    let (second, second_group) = second.finalize(&first_round1, &first_round2).unwrap();
    assert_eq!(group.to_bytes(), second_group.to_bytes());
    Ceremony { first, second, group }
}

// Experimental public byte-swap surrogate, NOT a production threshold-FVK
// constructor or evidence that the installed cohort is audited for custody.
fn experimental_joint_fvk(group: &GroupPublicKey) -> FullViewingKey {
    let group_ak = group.verifying_key_bytes().unwrap();
    assert_eq!(group_ak[31] & 0x80, 0);
    let base_sk = Zeroizing::new([0x11; 32]);
    let mut fvk_bytes = Zeroizing::new(
        FullViewingKey::from(&SpendingKey::from_bytes(*base_sk).unwrap()).to_bytes(),
    );
    fvk_bytes[..32].copy_from_slice(&group_ak);
    FullViewingKey::from_bytes(&fvk_bytes).unwrap()
}

// Every attempt, including negatives, consumes fresh owned Nonces exactly once.
fn threshold_sign(ceremony: &Ceremony, message: &[u8; 32], alpha: &Alpha) -> [u8; 64] {
    let mut rng = OsRng;
    let (nonces_first, commitment_first) = commit(&ceremony.first, &mut rng).unwrap();
    let (nonces_second, commitment_second) = commit(&ceremony.second, &mut rng).unwrap();
    let commitments = [commitment_first, commitment_second];
    let first = sign_share(&ceremony.first, nonces_first, message, alpha, &commitments).unwrap();
    let second = sign_share(&ceremony.second, nonces_second, message, alpha, &commitments).unwrap();
    aggregate(&ceremony.group, message, alpha, &commitments, &[first, second]).unwrap()
}

fn synthetic_note(recipient: Address, value: u64, tag: u8, version: NoteVersion) -> Note {
    let mut rho_bytes = [0; 32];
    rho_bytes[0] = tag;
    let rho = Rho::from_bytes(&rho_bytes).unwrap();
    synthetic_note_with_rho(recipient, value, rho, tag, version)
}

fn synthetic_note_with_rho(
    recipient: Address, value: u64, rho: Rho, tag: u8, version: NoteVersion,
) -> Note {
    let mut rng = ChaCha20Rng::from_seed([tag; 32]);
    loop {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        if let Some(seed) = RandomSeed::from_bytes(seed, &rho).into_option()
            && let Some(note) = Note::from_parts(
                recipient, NoteValue::from_raw(value), rho, seed, version,
            ).into_option()
        {
            return note;
        }
    }
}

// Local generated input/J membership only, never a chain-admissible anchor.
fn synthetic_membership(note: &Note) -> (MerklePath, Anchor) {
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    tree.append(MerkleHashOrchard::from_cmx(&cmx)).unwrap();
    let witness = IncrementalWitness::from_tree(tree).unwrap();
    let path: MerklePath = witness.path().unwrap().into();
    let anchor = path.root(cmx);
    (path, anchor)
}

struct Fixture {
    ceremony: Ceremony,
    source: SourceParameters,
    fvk: FullViewingKey,
    note: Note,
    payout: OutputPlan,
}

impl Fixture {
    fn new() -> Self {
        let ceremony = run_dkg();
        let fvk = experimental_joint_fvk(&ceremony.group);
        let note = synthetic_note(fvk.address_at(0u32, Scope::External), 50_000, 21, NoteVersion::V3);
        let recipient_fvk = FullViewingKey::from(&SpendingKey::from_bytes([0x33; 32]).unwrap());
        let payout = OutputPlan::new(
            recipient_fvk.address_at(0u32, Scope::External),
            Zatoshis::from_u64(40_000).unwrap(), MemoBytes::from_bytes(b"synthetic early R").unwrap(),
        );
        let source = SourceParameters {
            network: Network::TestNetwork, target_height: 4_134_000.into(),
            expiry_height: 4_134_040.into(), consensus_branch: BranchId::Nu6_3,
            fee_rule: zip317::FeeRule::standard(),
        };
        Self { ceremony, source, fvk, note, payout }
    }

    fn terms(&self) -> JointSpendTerms<'_> {
        JointSpendTerms {
            source: &self.source, note: &self.note, full_viewing_key: &self.fvk,
            group_ak: self.ceremony.group.verifying_key_bytes().unwrap(),
            payout: &self.payout, fee: Zatoshis::from_u64(10_000).unwrap(),
        }
    }

    fn deferred(&self) -> DeferredJointSpend {
        build_deferred_joint_spend(&self.terms(), &mut ChaCha20Rng::from_seed([12; 32])).unwrap()
    }
}

fn source_facts(source: &SourceParameters) -> SourceFacts<'_> {
    SourceFacts { network: source.network, target_height: source.target_height,
        expiry_height: source.expiry_height, consensus_branch: source.consensus_branch,
        fee_rule: &source.fee_rule }
}

// Independent target shape vector only: its opaque commitments are NOT opened
// by the partial source-field checker or evidence of an authenticated quote.
fn statement_for_generated_joint(note: &Note, fvk: &FullViewingKey) -> ziquid_protocol::native::Statement {
    use ziquid_protocol::native::{Statement, stable_j_tag};
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../contracts/evm/test/fixtures/native-financial-vectors.json",
    )).unwrap();
    let encoded = vectors["statement"].as_str().unwrap().as_bytes().as_chunks::<2>().0.iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    let mut statement = Statement::decode(&encoded).unwrap();
    statement.a = 40_000;
    statement.joint_value = 50_000;
    statement.r_return = 40_000;
    statement.targets = [4_134_000; 3];
    statement.expiries = [4_134_020, 4_134_040, 4_134_040];
    statement.fees = [10_000; 3];
    statement.fee_caps = [12_000; 3];
    let fvk_bytes = Zeroizing::new(fvk.to_bytes());
    let nf = Zeroizing::new(note.nullifier(fvk).to_bytes());
    statement.stable_jtag = stable_j_tag(statement.target_chain_id, &statement.obligation,
        fvk_bytes[32..64].try_into().unwrap(), &nf).unwrap();
    statement.validate().unwrap();
    statement
}

// Real public upstream wire type serialization, not a second product parser.
fn mutate_pczt(bytes: &[u8], mutate: impl FnOnce(&mut Value)) -> Zeroizing<Vec<u8>> {
    let wire = pczt::v2::Pczt::try_from(Pczt::parse(bytes).unwrap()).unwrap();
    let mut fields = serde_json::to_value(wire).unwrap();
    mutate(&mut fields);
    let wire: pczt::v2::Pczt = serde_json::from_value(fields).unwrap();
    Zeroizing::new(wire.serialize())
}

#[test]
fn finished_joint_spend_rejects_empty_consensus_handoff() {
    let fixture = Fixture::new();
    let deferred = fixture.deferred();
    let terms = fixture.terms();
    let reviewed = review_joint_spend(deferred.private_pczt_bytes(), &terms).unwrap();
    let output_notes = reviewed.output_notes().unwrap();
    let (_, anchor) = synthetic_membership(&fixture.note);
    let expected = FinishedJointSpendExpectation {
        terms, shielded_sighash: reviewed.shielded_sighash(), anchor,
        output_notes: &output_notes,
    };
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    assert_eq!(review_finished_joint_spend(&[], &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Consensus(ValidationError::MalformedTransaction));
    let oversized = vec![0; MAX_BLOCK_BYTES + 1];
    assert_eq!(review_finished_joint_spend(&oversized, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Consensus(ValidationError::MalformedTransaction));
    assert_eq!(format!("{expected:?}"), "FinishedJointSpendExpectation([redacted])");
    assert_eq!(format!("{}", JointSpendError::Review(CustodyError::CiphertextMismatch)),
        "local joint spend rejected: Review(CiphertextMismatch)");
}

#[test]
fn deferred_joint_spend_review_binds_local_terms_before_membership() {
    let fixture = Fixture::new();
    let deferred = fixture.deferred();
    let terms = fixture.terms();
    let pczt = Pczt::parse(deferred.private_pczt_bytes()).unwrap();
    assert!(pczt.ironwood().anchor().is_none(), "no invented parent anchor");
    let reviewed = review_joint_spend(deferred.private_pczt_bytes(), &terms).unwrap();
    assert!(pczt.ironwood().actions()[reviewed.action_index()].spend().witness().is_none());
    assert_eq!(reviewed.shielded_sighash(), Signer::new(pczt.clone()).unwrap().shielded_sighash());
    let effects = pczt.into_effects().unwrap();
    let direct = v6_signature_hash(&effects, &SignableInput::Shielded, &effects.digest(TxIdDigester));
    assert_eq!(reviewed.shielded_sighash(), <[u8; 32]>::try_from(direct.as_ref()).unwrap());
    let alpha = Alpha::from_bytes(&reviewed.alpha()).unwrap();
    check_action_rk(&fixture.ceremony.group, &alpha, &reviewed.randomized_key()).unwrap();

    let wrong_payout = OutputPlan::new(
        fixture.fvk.address_at(1u32, Scope::External), terms.payout.value(), terms.payout.memo().clone(),
    );
    assert!(review_joint_spend(deferred.private_pczt_bytes(), &JointSpendTerms {
        payout: &wrong_payout, ..terms
    }).is_err());
    let wrong_value = OutputPlan::new(
        terms.payout.recipient(), Zatoshis::from_u64(39_999).unwrap(), terms.payout.memo().clone(),
    );
    assert!(review_joint_spend(deferred.private_pczt_bytes(), &JointSpendTerms {
        payout: &wrong_value, fee: Zatoshis::from_u64(10_001).unwrap(), ..terms
    }).is_err());
    let wrong_memo = OutputPlan::new(terms.payout.recipient(), terms.payout.value(), MemoBytes::empty());
    assert!(review_joint_spend(deferred.private_pczt_bytes(), &JointSpendTerms {
        payout: &wrong_memo, ..terms
    }).is_err());
    assert!(review_joint_spend(deferred.private_pczt_bytes(), &JointSpendTerms {
        fee: Zatoshis::from_u64(9_999).unwrap(), ..terms
    }).is_err());
    let mut wrong_group = terms.group_ak;
    wrong_group[0] ^= 1;
    assert_eq!(review_joint_spend(deferred.private_pczt_bytes(), &JointSpendTerms {
        group_ak: wrong_group, ..terms
    }).unwrap_err(), JointSpendError::GroupMismatch);
    let wrong_input = synthetic_note(fixture.note.recipient(), 50_000, 22, NoteVersion::V3);
    assert!(review_joint_spend(deferred.private_pczt_bytes(), &JointSpendTerms {
        note: &wrong_input, ..terms
    }).is_err());
    let wrong_owner = FullViewingKey::from(&SpendingKey::from_bytes([0x34; 32]).unwrap());
    assert!(review_joint_spend(deferred.private_pczt_bytes(), &JointSpendTerms {
        full_viewing_key: &wrong_owner, ..terms
    }).is_err());
    let mut wrong_source = fixture.source.clone();
    wrong_source.expiry_height = 4_134_041.into();
    assert!(review_joint_spend(deferred.private_pczt_bytes(), &JointSpendTerms {
        source: &wrong_source, ..terms
    }).is_err());
}

#[test]
fn received_joint_spend_rejects_missing_altered_and_unrelated_native_data() {
    let fixture = Fixture::new();
    let deferred = fixture.deferred();
    let bytes = deferred.private_pczt_bytes();
    let terms = fixture.terms();
    let reviewed = review_joint_spend(bytes, &terms).unwrap();
    let real = reviewed.action_index();
    let wire = pczt::v2::Pczt::try_from(Pczt::parse(bytes).unwrap()).unwrap();
    let fields = serde_json::to_value(wire).unwrap();
    let output = fields["ironwood"]["actions"].as_array().unwrap().iter()
        .position(|action| action["output"]["value"].as_u64() == Some(40_000)).unwrap();
    let padding = 1 - real;
    for field in 0..10 {
        let pczt = Redactor::new(Pczt::parse(bytes).unwrap())
            .redact_ironwood_with(|mut bundle| {
                bundle.redact_action(real, |mut action| match field {
                    0 => action.clear_spend_recipient(),
                    1 => action.clear_spend_value(),
                    2 => action.clear_spend_rho(),
                    3 => action.clear_spend_rseed(),
                    4 => action.clear_spend_alpha(),
                    5 => action.clear_spend_fvk(),
                    6 => action.clear_output_recipient(),
                    7 => action.clear_output_value(),
                    8 => action.clear_output_rseed(),
                    9 => action.clear_rcv(),
                    _ => unreachable!(),
                });
            }).finish();
        assert!(review_joint_spend(&pczt.serialize().unwrap(), &terms).is_err(), "field {field}");
    }
    let no_padding_auth = Redactor::new(Pczt::parse(bytes).unwrap())
        .redact_ironwood_with(|mut bundle| {
            bundle.redact_action(padding, |mut action| action.clear_spend_auth_sig());
        }).finish();
    assert!(review_joint_spend(&no_padding_auth.serialize().unwrap(), &terms).is_err());
    for (field, value) in [
        ("tx_version", json!(5)), ("version_group_id", json!(0)),
        ("consensus_branch_id", json!(u32::from(BranchId::Nu6_2))),
        ("coin_type", json!(133)), ("tx_modifiable", json!(128)),
        ("fallback_lock_time", json!(1)), ("fallback_lock_time", Value::Null),
        ("expiry_height", json!(4_134_041)), ("expiry_height", json!(0)),
    ] {
        let changed = mutate_pczt(bytes, |fields| fields["global"][field] = value);
        assert!(review_joint_spend(&changed, &terms).is_err(), "global {field}");
    }
    let bad_nullifier = mutate_pczt(bytes, |fields| {
        fields["ironwood"]["actions"][real]["spend"]["nullifier"] = json!(vec![0; 32]);
    });
    assert!(review_joint_spend(&bad_nullifier, &terms).is_err());
    let wrong_alpha = Alpha::random(&mut OsRng).to_bytes();
    let bad_alpha = mutate_pczt(bytes, |fields| {
        fields["ironwood"]["actions"][real]["spend"]["alpha"] = json!(wrong_alpha);
    });
    assert!(review_joint_spend(&bad_alpha, &terms).is_err());
    for action_index in [real, padding] {
        let altered = mutate_pczt(bytes, |fields| {
            fields["ironwood"]["actions"][action_index]["spend"]["value"] = json!(1);
        });
        assert!(review_joint_spend(&altered, &terms).is_err());
    }
    for action_index in [output, 1 - output] {
        let bad_ciphertext = mutate_pczt(bytes, |fields| {
            let ciphertext = fields["ironwood"]["actions"][action_index]["output"]["enc_ciphertext"]["Encrypted"]
                .as_array_mut().unwrap();
            ciphertext[70] = json!(ciphertext[70].as_u64().unwrap() ^ 1);
        });
        assert!(review_joint_spend(&bad_ciphertext, &terms).is_err(), "ciphertext {action_index}");
    }
    let bad_binding = mutate_pczt(bytes, |fields| fields["ironwood"]["bsk"] = json!(vec![0; 32]));
    assert!(review_joint_spend(&bad_binding, &terms).is_err());
    let other_pool = mutate_pczt(bytes, |fields| {
        let mut bundle = fields["ironwood"].clone();
        bundle["flags"] = json!(3);
        fields["orchard"] = bundle;
    });
    assert!(review_joint_spend(&other_pool, &terms).is_err());
    let unrelated_metadata = mutate_pczt(bytes, |fields| {
        fields["orchard"] = json!({
            "actions": [], "flags": 3, "value_sum": [0, false], "anchor": vec![0; 32],
            "note_version": "V2", "zkproof": null, "bsk": null,
        });
    });
    assert!(review_joint_spend(&unrelated_metadata, &terms).is_err());
    let mut trailing = Zeroizing::new(bytes.to_vec());
    trailing.push(0);
    assert!(review_joint_spend(&trailing, &terms).is_err());
    assert!(review_joint_spend(&[], &terms).is_err());
    assert!(review_joint_spend(&vec![0; 16 * 1024 * 1024 + 1], &terms).is_err());
}

#[test]
fn received_joint_spend_rejects_preset_membership_before_owner_attachment() {
    let fixture = Fixture::new();
    let deferred = fixture.deferred();
    let terms = fixture.terms();
    let reviewed = review_joint_spend(deferred.private_pczt_bytes(), &terms).unwrap();
    let real_index = reviewed.action_index();
    let message = reviewed.shielded_sighash();
    let alpha = Alpha::from_bytes(&reviewed.alpha()).unwrap();
    let aggregate = threshold_sign(&fixture.ceremony, &message, &alpha);
    let signed = reviewed.apply_external_signature(aggregate).unwrap();
    let before = signed.private_pczt_bytes();
    assert!(review_joint_spend(before, &terms).is_ok());

    let (path, actual_anchor) = synthetic_membership(&fixture.note);
    let (_, wrong_anchor) = synthetic_membership(&synthetic_note(
        fixture.note.recipient(), 50_000, 26, NoteVersion::V3,
    ));
    assert!(actual_anchor != wrong_anchor);
    let poisoned = Updater::new(Pczt::parse(before).unwrap())
        .set_ironwood_anchor(wrong_anchor).unwrap().finish();
    assert!(poisoned.ironwood().actions()[real_index].spend().witness().is_none());
    assert_eq!(Signer::new(poisoned.clone()).unwrap().shielded_sighash(), message);
    assert_eq!(poisoned.ironwood().actions()[real_index].spend().spend_auth_sig(), &Some(aggregate));
    assert!(review_joint_spend(&poisoned.serialize().unwrap(), &terms).is_err(),
        "received preset anchor must not pin pre-parent authorization");

    let witness_only = Updater::new(Pczt::parse(before).unwrap())
        .set_ironwood_spend_witnesses([(real_index, path.clone())]).unwrap().finish();
    assert!(review_joint_spend(&witness_only.serialize().unwrap(), &terms).is_err(),
        "received J witness is not owner-local membership enrollment");
    let preset_pair = Updater::new(Pczt::parse(before).unwrap())
        .set_ironwood_anchor(actual_anchor).unwrap()
        .set_ironwood_spend_witnesses([(real_index, path.clone())]).unwrap().finish();
    assert!(review_joint_spend(&preset_pair.serialize().unwrap(), &terms).is_err(),
        "matching received pair does not authenticate a parent anchor");
    let owner_attached = signed.attach_membership(path, actual_anchor).unwrap();
    assert_eq!(owner_attached.effect_id(), review_joint_spend(deferred.private_pczt_bytes(), &terms).unwrap().effect_id());
    assert_eq!(owner_attached.shielded_sighash(), message);
}

#[test]
fn independently_reviewed_terms_reject_extra_genuine_positive_output_or_spend() {
    let fixture = Fixture::new();
    for extra_spend in [false, true] {
        let mut builder = DeferredPcztBuilder::new::<zip317::FeeError>(
            fixture.source.network, fixture.source.target_height,
            BundlePadding::DEFAULT, BundlePadding::DEFAULT,
        ).unwrap().with_expiry_height(fixture.source.expiry_height);
        builder.add_ironwood_spend::<zip317::FeeError>(fixture.fvk.clone(), fixture.note).unwrap();
        if extra_spend {
            let extra_note = synthetic_note(fixture.note.recipient(), 1, 23, NoteVersion::V3);
            builder.add_ironwood_spend::<zip317::FeeError>(fixture.fvk.clone(), extra_note).unwrap();
            builder.add_ironwood_output::<zip317::FeeError>(
                None, fixture.payout.recipient(), Zatoshis::from_u64(40_001).unwrap(), fixture.payout.memo().clone(),
            ).unwrap();
        } else {
            builder.add_ironwood_output::<zip317::FeeError>(
                None, fixture.payout.recipient(), Zatoshis::from_u64(39_999).unwrap(), fixture.payout.memo().clone(),
            ).unwrap();
            builder.add_ironwood_output::<zip317::FeeError>(
                None, fixture.fvk.address_at(1u32, Scope::External), Zatoshis::from_u64(1).unwrap(), MemoBytes::empty(),
            ).unwrap();
        }
        let built = builder.build_for_pczt(ChaCha20Rng::from_seed([52; 32]), &fixture.source.fee_rule).unwrap();
        let pczt = IoFinalizer::new(Creator::build_from_parts(built.pczt_parts).unwrap()).finalize_io().unwrap();
        assert!(review_joint_spend(&pczt.serialize().unwrap(), &fixture.terms()).is_err());
    }
}

#[test]
fn route_terms_reject_unusable_source_context_v2_or_zero_notes_without_rewriting_terms() {
    let fixture = Fixture::new();
    let terms = fixture.terms();
    for (target, expiry) in [
        (4_133_999u32, 4_134_040u32), (4_134_000, 0), (4_134_040, 4_134_000),
        (4_134_000, 4_465_026), (4_465_026, 4_465_026), (4_134_000, 500_000_000),
    ] {
        let mut source = fixture.source.clone();
        source.target_height = target.into();
        source.expiry_height = expiry.into();
        assert!(build_deferred_joint_spend(&JointSpendTerms { source: &source, ..terms }, &mut OsRng).is_err());
    }
    let mut mainnet = fixture.source.clone();
    mainnet.network = Network::MainNetwork;
    mainnet.target_height = 3_428_144.into();
    mainnet.expiry_height = 3_428_184.into();
    assert!(build_deferred_joint_spend(&JointSpendTerms { source: &mainnet, ..terms }, &mut OsRng).is_err());
    for (value, version) in [(50_000, NoteVersion::V2), (0, NoteVersion::V3)] {
        let note = synthetic_note(fixture.note.recipient(), value, 24, version);
        assert!(build_deferred_joint_spend(&JointSpendTerms { note: &note, ..terms }, &mut OsRng).is_err());
    }
    let zero_payout = OutputPlan::new(fixture.payout.recipient(), Zatoshis::ZERO, MemoBytes::empty());
    assert!(build_deferred_joint_spend(&JointSpendTerms { payout: &zero_payout, ..terms }, &mut OsRng).is_err());
    let altered_fee = OutputPlan::new(fixture.payout.recipient(), Zatoshis::from_u64(39_999).unwrap(), MemoBytes::empty());
    assert_eq!(build_deferred_joint_spend(&JointSpendTerms {
        payout: &altered_fee, fee: Zatoshis::from_u64(10_001).unwrap(), ..terms
    }, &mut OsRng).unwrap_err(), JointSpendError::FeeMismatch);
}

#[test]
fn pczt_spend_of_threshold_keyed_note_is_authorized_by_the_frost_aggregate() {
    let fixture = Fixture::new();
    let terms = fixture.terms();
    // Deterministically exercise shuffle: the J action must not be assumed zero.
    let deferred = (1..=64).find_map(|seed| {
        let deferred = build_deferred_joint_spend(&terms, &mut ChaCha20Rng::from_seed([seed; 32])).unwrap();
        let reviewed = review_joint_spend(deferred.private_pczt_bytes(), &terms).unwrap();
        let output_notes = reviewed.output_notes().unwrap();
        (reviewed.action_index() != 0 && output_notes[0].value().inner() == 0).then_some(deferred)
    }).expect("fixture with J and payout shuffled away from zero");
    let bytes = deferred.private_pczt_bytes();
    let reviewed = review_joint_spend(bytes, &terms).unwrap();
    let real_index = reviewed.action_index();
    let message = reviewed.shielded_sighash();
    // Capture local private output openings BEFORE the reviewed artifact is consumed.
    let output_notes = reviewed.output_notes().unwrap();
    let effect_id = reviewed.effect_id();
    let alpha = Alpha::from_bytes(&reviewed.alpha()).unwrap();
    check_action_rk(&fixture.ceremony.group, &alpha, &reviewed.randomized_key()).unwrap();
    let before = Pczt::parse(bytes).unwrap();
    assert!(before.ironwood().anchor().is_none());
    assert!(before.ironwood().actions()[real_index].spend().witness().is_none());
    assert!(before.ironwood().actions().iter().all(|action| action.spend().dummy_sk().is_none()));
    assert!(TransactionExtractor::new(before).extract().is_err());
    let second_review = review_joint_spend(bytes, &terms).unwrap();
    assert_eq!(second_review.shielded_sighash(), message);
    assert_eq!(second_review.alpha(), reviewed.alpha());

    let wrong_alpha = Alpha::random(&mut OsRng);
    assert_eq!(review_joint_spend(bytes, &terms).unwrap().apply_external_signature(
        threshold_sign(&fixture.ceremony, &message, &wrong_alpha),
    ).unwrap_err(), JointSpendError::InvalidSignature);
    let mut wrong_message = message;
    wrong_message[0] ^= 1;
    assert_eq!(review_joint_spend(bytes, &terms).unwrap().apply_external_signature(
        threshold_sign(&fixture.ceremony, &wrong_message, &alpha),
    ).unwrap_err(), JointSpendError::InvalidSignature);
    assert_eq!(review_joint_spend(bytes, &terms).unwrap().apply_external_signature([0; 64])
        .unwrap_err(), JointSpendError::InvalidSignature);

    // PREAUTHORIZATION happens while the parent has no membership path/anchor.
    let aggregate = threshold_sign(&fixture.ceremony, &message, &alpha);
    let signed = reviewed.apply_external_signature(aggregate).unwrap();
    let early_r = Zeroizing::new(signed.private_pczt_bytes().to_vec());
    let signed_pczt = Pczt::parse(&early_r).unwrap();
    assert!(signed_pczt.ironwood().anchor().is_none());
    assert!(signed_pczt.ironwood().actions()[real_index].spend().witness().is_none());
    assert!(signed_pczt.ironwood().actions().iter().all(|action| action.spend().spend_auth_sig().is_some()));
    assert_eq!(signed_pczt.ironwood().actions()[real_index].spend().spend_auth_sig(), &Some(aggregate));
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(signed.randomized_key()).unwrap();
    rk.verify(&message, &redpallas::Signature::from(aggregate)).unwrap();
    assert_eq!(review_joint_spend(&early_r, &terms).unwrap().apply_external_signature(aggregate)
        .unwrap_err(), JointSpendError::InvalidSignature);

    // Only now construct synthetic parent membership. No source observation is fabricated.
    let (path, anchor) = synthetic_membership(&fixture.note);
    let (_, wrong_anchor) = synthetic_membership(&synthetic_note(fixture.note.recipient(), 50_000, 25, NoteVersion::V3));
    assert_eq!(review_joint_spend(&early_r, &terms).unwrap().attach_membership(path.clone(), wrong_anchor)
        .unwrap_err(), JointSpendError::InvalidMembership);
    assert_eq!(review_joint_spend(bytes, &terms).unwrap().attach_membership(path.clone(), anchor)
        .unwrap_err(), JointSpendError::MissingAuthorization);
    let signed = signed.attach_membership(path.clone(), anchor).unwrap();
    assert_eq!(signed.effect_id(), effect_id);
    assert_eq!(signed.shielded_sighash(), message);
    assert_eq!(Signer::new(Pczt::parse(signed.private_pczt_bytes()).unwrap()).unwrap().shielded_sighash(), message);

    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    assert_eq!(review_joint_spend(&early_r, &terms).unwrap().extract_consensus(&pk, &vk, &mut OsRng)
        .unwrap_err(), JointSpendError::InvalidMembership);
    // The reusable completion path supplies parent membership, proof and FULL consensus extraction.
    let complete = review_joint_spend(&early_r, &terms).unwrap()
        .complete(path, anchor, &pk, &vk, &mut OsRng).unwrap();
    let consensus = complete.serialize().unwrap();
    let parsed = IronwoodTransaction::parse(&consensus, BranchId::Nu6_3).unwrap();
    assert_eq!(parsed.serialize().unwrap(), consensus);
    assert_eq!(parsed.effect_id(), effect_id);
    assert_eq!(parsed.transaction().lock_time(), 0);
    assert_eq!(u32::from(parsed.transaction().expiry_height()), 4_134_040);
    let bundle = parsed.transaction().ironwood_bundle().unwrap();
    assert_eq!(bundle.bundle_version().circuit_version(), OrchardCircuitVersion::PostNu6_3);
    assert_eq!(bundle.actions().len(), 2, "genuine padding remains authorized");
    assert_eq!(i64::from(*bundle.value_balance()), 10_000);
    assert_eq!(bundle.actions()[real_index].nullifier(), &fixture.note.nullifier(&fixture.fvk));
    bundle.actions()[real_index].rk().verify(&message, &redpallas::Signature::from(aggregate)).unwrap();
    let payout_fvk = FullViewingKey::from(&SpendingKey::from_bytes([0x33; 32]).unwrap());
    let outputs = bundle.decrypt_outputs_with_keys(&[payout_fvk.to_ivk(Scope::External)]);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].2.value().inner(), 40_000);
    assert_eq!(outputs[0].3, fixture.payout.recipient());
    assert_eq!(&outputs[0].4, fixture.payout.memo().as_array());
    parsed.verify_authorization(&vk, &mut OsRng).unwrap();
    // Under this independently checked pure-shielded v6 profile the maintained
    // sighash equals effect txid; the pre/post-membership Signer oracle is above.
    assert_eq!(message, parsed.effect_id());

    // Maintained public Updater cannot change effects while adding deferred membership.
    let attached = Pczt::parse(signed.private_pczt_bytes()).unwrap();
    assert!(Updater::new(attached).set_ironwood_anchor(wrong_anchor).is_err());
    drop(signed);
    drop(signed_pczt);
    drop(second_review);
    drop(early_r);
    drop(deferred);
    drop(complete);

    // Independent finished handoff: no PCZT reaches this verifier boundary. The
    // digest is the prior local review's value, not the received transaction ID.
    let expected = FinishedJointSpendExpectation {
        terms, shielded_sighash: message, anchor, output_notes: &output_notes,
    };
    let accepted = review_finished_joint_spend(&consensus, &expected, &vk, &mut OsRng).unwrap();
    assert_eq!(accepted.serialize().unwrap(), consensus);
    assert_eq!(output_notes.len(), bundle.actions().len());
    let padding_output = output_notes.iter().position(|note| note.value().inner() == 0).unwrap();
    let payout_output = output_notes.iter().position(|note| note.value().inner() != 0).unwrap();
    assert!(output_notes[payout_output].recipient() == fixture.payout.recipient());
    assert_eq!(output_notes[payout_output].value().inner(), 40_000);
    for (action, note) in bundle.actions().iter().zip(&output_notes) {
        assert_eq!(note.version(), NoteVersion::V3);
        assert!(note.rho() == action.rho());
        assert!(ExtractedNoteCommitment::from(note.commitment()) == *action.cmx());
    }

    let wrong_note = synthetic_note(fixture.note.recipient(), 50_000, 27, NoteVersion::V3);
    let wrong_owner = FullViewingKey::from(&SpendingKey::from_bytes([0x34; 32]).unwrap());
    let wrong_recipient = OutputPlan::new(
        fixture.fvk.address_at(1u32, Scope::External), fixture.payout.value(), fixture.payout.memo().clone(),
    );
    let wrong_value = OutputPlan::new(
        fixture.payout.recipient(), Zatoshis::from_u64(39_999).unwrap(), fixture.payout.memo().clone(),
    );
    let wrong_memo = OutputPlan::new(fixture.payout.recipient(), fixture.payout.value(), MemoBytes::empty());
    let mut wrong_fee_rule = fixture.source.clone();
    wrong_fee_rule.fee_rule = zip317::FeeRule::non_standard(
        Zatoshis::from_u64(5_000).unwrap(), 3,
        zip317::P2PKH_STANDARD_INPUT_SIZE, zip317::P2PKH_STANDARD_OUTPUT_SIZE,
    ).unwrap();
    let mut wrong_source = fixture.source.clone();
    wrong_source.expiry_height = 4_134_041.into();
    let mut wrong_group = terms.group_ak;
    wrong_group[0] ^= 1;
    for (label, changed_terms) in [
        ("group", JointSpendTerms { group_ak: wrong_group, ..terms }),
        ("J note", JointSpendTerms { note: &wrong_note, ..terms }),
        ("J FVK", JointSpendTerms { full_viewing_key: &wrong_owner, ..terms }),
        ("recipient", JointSpendTerms { payout: &wrong_recipient, ..terms }),
        ("value", JointSpendTerms { payout: &wrong_value, fee: Zatoshis::from_u64(10_001).unwrap(), ..terms }),
        ("memo", JointSpendTerms { payout: &wrong_memo, ..terms }),
        ("fee", JointSpendTerms { fee: Zatoshis::from_u64(9_999).unwrap(), ..terms }),
        ("expiry", JointSpendTerms { source: &wrong_source, ..terms }),
        ("configured action fee", JointSpendTerms { source: &wrong_fee_rule, ..terms }),
    ] {
        assert!(review_finished_joint_spend(&consensus, &FinishedJointSpendExpectation {
            terms: changed_terms, ..expected
        }, &vk, &mut OsRng).is_err(), "independent {label} mismatch accepted");
    }
    assert_eq!(review_finished_joint_spend(&consensus, &FinishedJointSpendExpectation {
        shielded_sighash: wrong_message, ..expected
    }, &vk, &mut OsRng).unwrap_err(), JointSpendError::EffectsChanged);
    assert_eq!(review_finished_joint_spend(&consensus, &FinishedJointSpendExpectation {
        anchor: wrong_anchor, ..expected
    }, &vk, &mut OsRng).unwrap_err(), JointSpendError::InvalidMembership);

    for notes in [&output_notes[..0], &output_notes[..1]] {
        assert_eq!(review_finished_joint_spend(&consensus, &FinishedJointSpendExpectation {
            output_notes: notes, ..expected
        }, &vk, &mut OsRng).unwrap_err(), JointSpendError::Review(CustodyError::OutputMismatch));
    }
    let mut extra_notes = output_notes.clone();
    extra_notes.push(output_notes[padding_output]);
    assert!(review_finished_joint_spend(&consensus, &FinishedJointSpendExpectation {
        output_notes: &extra_notes, ..expected
    }, &vk, &mut OsRng).is_err());
    let mut reordered_notes = output_notes.clone();
    reordered_notes.swap(0, 1);
    assert_eq!(review_finished_joint_spend(&consensus, &FinishedJointSpendExpectation {
        output_notes: &reordered_notes, ..expected
    }, &vk, &mut OsRng).unwrap_err(), JointSpendError::Review(CustodyError::OutputMismatch));
    let padding_note = output_notes[padding_output];
    let mut altered_notes = output_notes.clone();
    altered_notes[padding_output] = synthetic_note_with_rho(
        padding_note.recipient(), 0, padding_note.rho(), 71, NoteVersion::V3,
    );
    assert!(altered_notes[padding_output].rseed().as_bytes() != padding_note.rseed().as_bytes());
    assert!(review_finished_joint_spend(&consensus, &FinishedJointSpendExpectation {
        output_notes: &altered_notes, ..expected
    }, &vk, &mut OsRng).is_err());
    altered_notes[padding_output] = synthetic_note_with_rho(
        padding_note.recipient(), 0, padding_note.rho(), 72, NoteVersion::V2,
    );
    assert!(review_finished_joint_spend(&consensus, &FinishedJointSpendExpectation {
        output_notes: &altered_notes, ..expected
    }, &vk, &mut OsRng).is_err());
    let payout_note = output_notes[payout_output];
    altered_notes = output_notes.clone();
    altered_notes[payout_output] = synthetic_note_with_rho(
        payout_note.recipient(), 40_000, payout_note.rho(), 73, NoteVersion::V3,
    );
    assert!(review_finished_joint_spend(&consensus, &FinishedJointSpendExpectation {
        output_notes: &altered_notes, ..expected
    }, &vk, &mut OsRng).is_err());

    let action_offsets: Vec<_> = bundle.actions().iter().map(|action| {
        let mut encoded = Vec::new();
        write_action_without_auth(&mut encoded, action).unwrap();
        consensus.windows(encoded.len()).position(|bytes| bytes == encoded).unwrap()
    }).collect();
    let padding_input = (0..bundle.actions().len()).find(|index| *index != real_index).unwrap();
    let mut duplicate_nf = consensus.clone();
    let nullifier_offset = action_offsets[padding_input] + 32;
    duplicate_nf[nullifier_offset..nullifier_offset + 32]
        .copy_from_slice(&fixture.note.nullifier(&fixture.fvk).to_bytes());
    assert_eq!(review_finished_joint_spend(&duplicate_nf, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Review(CustodyError::InputMismatch));
    let ciphertext = &bundle.actions()[padding_output].encrypted_note().enc_ciphertext;
    let ciphertext_offset = consensus.windows(ciphertext.len()).position(|bytes| bytes == ciphertext).unwrap();
    let mut damaged_padding = consensus.clone();
    damaged_padding[ciphertext_offset + ciphertext.len() - 1] ^= 1;
    assert_eq!(review_finished_joint_spend(&damaged_padding, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Review(CustodyError::CiphertextMismatch));
    let mut damaged_payout = consensus.clone();
    let payout_ciphertext = &bundle.actions()[payout_output].encrypted_note().enc_ciphertext;
    let payout_offset = consensus.windows(payout_ciphertext.len()).position(|bytes| bytes == payout_ciphertext).unwrap();
    damaged_payout[payout_offset] ^= 1;
    assert_eq!(review_finished_joint_spend(&damaged_payout, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Review(CustodyError::CiphertextMismatch));
    let outgoing = &bundle.actions()[padding_output].encrypted_note().out_ciphertext;
    let outgoing_offset = consensus.windows(outgoing.len()).position(|bytes| bytes == outgoing).unwrap();
    let mut damaged_outgoing = consensus.clone();
    damaged_outgoing[outgoing_offset] ^= 1;
    assert_eq!(review_finished_joint_spend(&damaged_outgoing, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::EffectsChanged);

    let mut header = Vec::new();
    parsed.transaction().write_v6_header(&mut header).unwrap();
    let empty_pools = header.len();
    assert_eq!(&consensus[empty_pools..empty_pools + 5], &[0, 0, 0, 0, 0]);
    let action_count = empty_pools + 5;
    assert_eq!(consensus[action_count], 2);
    let flag_offset = action_offsets.last().unwrap()
        + zcash_primitives::transaction::components::orchard::ACTION_SIZE;
    assert_eq!(consensus[flag_offset], 7);
    for balance in [0i64, -10_000, 9_999, 10_001] {
        let mut changed_balance = consensus.clone();
        changed_balance[flag_offset + 1..flag_offset + 9].copy_from_slice(&balance.to_le_bytes());
        assert_eq!(review_finished_joint_spend(&changed_balance, &expected, &vk, &mut OsRng).unwrap_err(),
            JointSpendError::Review(CustodyError::ValueBalanceMismatch));
    }
    let anchor_offset = flag_offset + 1 + 8;
    let mut changed_anchor = consensus.clone();
    changed_anchor[anchor_offset..anchor_offset + 32].copy_from_slice(&wrong_anchor.to_bytes());
    let changed = IronwoodTransaction::parse(&changed_anchor, BranchId::Nu6_3).unwrap();
    assert_eq!(changed.effect_id(), message, "v6 effects deliberately exclude the anchor");
    assert_eq!(review_finished_joint_spend(&changed_anchor, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::InvalidMembership);
    assert_eq!(review_finished_joint_spend(&changed_anchor, &FinishedJointSpendExpectation {
        anchor: wrong_anchor, ..expected
    }, &vk, &mut OsRng).unwrap_err(), JointSpendError::Consensus(ValidationError::InvalidAuthorization));

    let mut wrong_flags = consensus.clone();
    wrong_flags[flag_offset] = 3;
    assert_eq!(review_finished_joint_spend(&wrong_flags, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Review(CustodyError::GlobalMetadata));
    let mut reserved_flags = consensus.clone();
    reserved_flags[flag_offset] |= 0x80;
    assert!(review_finished_joint_spend(&reserved_flags, &expected, &vk, &mut OsRng).is_err());
    let mut orchard_only = consensus.clone();
    orchard_only.remove(empty_pools + 4);
    orchard_only[flag_offset - 1] = 3; // Valid Orchard-v3 flags, not Ironwood-v3.
    orchard_only.push(0); // Empty Ironwood slot after the relocated bundle.
    assert_eq!(review_finished_joint_spend(&orchard_only, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Consensus(ValidationError::UnsupportedComponents));

    let mut old_version = Vec::new();
    zcash_primitives::transaction::TxVersion::V5.write(&mut old_version).unwrap();
    let version_prefix = old_version.len();
    old_version.extend_from_slice(&consensus[version_prefix..]);
    assert_eq!(review_finished_joint_spend(&old_version, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Consensus(ValidationError::WrongVersion));
    let mut wrong_branch = consensus.clone();
    wrong_branch[8..12].copy_from_slice(&u32::from(BranchId::Nu6_2).to_le_bytes());
    assert!(review_finished_joint_spend(&wrong_branch, &expected, &vk, &mut OsRng).is_err());
    let mut lock_time = consensus.clone();
    lock_time[12..16].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(review_finished_joint_spend(&lock_time, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Review(CustodyError::GlobalMetadata));
    let mut wrong_expiry = consensus.clone();
    wrong_expiry[16..20].copy_from_slice(&4_134_041u32.to_le_bytes());
    assert_eq!(review_finished_joint_spend(&wrong_expiry, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Review(CustodyError::GlobalMetadata));
    assert!(review_finished_joint_spend(&consensus[..consensus.len() - 1], &expected, &vk, &mut OsRng).is_err());
    assert!(review_finished_joint_spend(&[0xff; 32], &expected, &vk, &mut OsRng).is_err());
    let mut trailing = consensus.clone();
    trailing.push(0);
    assert_eq!(review_finished_joint_spend(&trailing, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Consensus(ValidationError::NonCanonicalEncoding));
    let mut noncanonical_count = consensus.clone();
    noncanonical_count.splice(action_count..action_count + 1, [0xfd, 2, 0]);
    assert!(review_finished_joint_spend(&noncanonical_count, &expected, &vk, &mut OsRng).is_err());

    // All authorizing-data mutations retain the independently reviewed effects.
    let signatures = consensus.len() - 64 * (bundle.actions().len() + 1);
    for index in 0..bundle.actions().len() {
        let offset = signatures + 64 * index;
        let mut damaged = consensus.clone();
        damaged[offset..offset + 64].fill(0);
        assert_eq!(IronwoodTransaction::parse(&damaged, BranchId::Nu6_3).unwrap().effect_id(), message);
        assert_eq!(review_finished_joint_spend(&damaged, &expected, &vk, &mut OsRng).unwrap_err(),
            JointSpendError::Consensus(ValidationError::InvalidAuthorization), "real/padding signature {index}");
        let mut missing = consensus.clone();
        missing.drain(offset..offset + 64);
        assert!(review_finished_joint_spend(&missing, &expected, &vk, &mut OsRng).is_err());
    }
    let mut damaged_binding = consensus.clone();
    damaged_binding[consensus.len() - 64..].fill(0);
    assert_eq!(review_finished_joint_spend(&damaged_binding, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Consensus(ValidationError::InvalidAuthorization));
    let mut damaged_proof = consensus.clone();
    damaged_proof[signatures - 1] ^= 1;
    assert_eq!(review_finished_joint_spend(&damaged_proof, &expected, &vk, &mut OsRng).unwrap_err(),
        JointSpendError::Consensus(ValidationError::InvalidAuthorization));
    let wrong_key = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    assert_eq!(review_finished_joint_spend(&consensus, &expected, &wrong_key, &mut OsRng).unwrap_err(),
        JointSpendError::Consensus(ValidationError::WrongCircuitVersion));
}

#[test]
fn statement_source_fields_reject_mismatches_in_actual_generated_private_transactions() {
    use ziquid_proofs::native_relation::source::{
        ConsumerFacts, SourceRelationError, check_statement_source_fields,
    };
    let wallet_fvk = FullViewingKey::from(&SpendingKey::from_bytes([0x44; 32]).unwrap());
    let note = synthetic_note(wallet_fvk.address_at(0u32, Scope::External), 100_000, 81, NoteVersion::V3);
    let (path, anchor) = synthetic_membership(&note);
    let input = OwnedInput::new(note, wallet_fvk, path, anchor).unwrap();
    // Ordinary generated fixture key, not evidence of production 2-of-2 custody.
    let joint_fvk = FullViewingKey::from(&SpendingKey::from_bytes([73; 32]).unwrap());
    let group_ak: [u8; 32] = joint_fvk.to_bytes()[..32].try_into().unwrap();
    let source = SourceParameters {
        network: Network::TestNetwork, target_height: 4_134_000.into(),
        expiry_height: 4_134_020.into(), consensus_branch: BranchId::Nu6_3,
        fee_rule: zip317::FeeRule::standard(),
    };
    let outputs = [
        OutputPlan::new(joint_fvk.address_at(0u32, Scope::External), Zatoshis::from_u64(50_000).unwrap(),
            MemoBytes::from_bytes(b"generated J for statement source validation").unwrap()),
        OutputPlan::new(input.full_viewing_key().address_at(1u32, Scope::Internal),
            Zatoshis::from_u64(40_000).unwrap(), MemoBytes::from_bytes(b"actual U change").unwrap()),
    ];
    let funding = prepare_joint_funding(&source, &input, &outputs, 0, &joint_fvk, group_ak,
        &mut ChaCha20Rng::from_seed([74; 32])).unwrap();
    let child_source = SourceParameters { expiry_height: 4_134_040.into(), ..source.clone() };
    let solver_fvk = FullViewingKey::from(&SpendingKey::from_bytes([0x66; 32]).unwrap());
    let payout = OutputPlan::new(solver_fvk.address_at(0u32, Scope::External),
        Zatoshis::from_u64(40_000).unwrap(), MemoBytes::from_bytes(b"exact C payout").unwrap());
    let returned = OutputPlan::new(input.full_viewing_key().address_at(2u32, Scope::Internal),
        Zatoshis::from_u64(40_000).unwrap(), MemoBytes::from_bytes(b"exact R return").unwrap());
    let c_terms = JointSpendTerms {
        source: &child_source, note: funding.joint_note(), full_viewing_key: &joint_fvk,
        group_ak, payout: &payout, fee: Zatoshis::from_u64(10_000).unwrap(),
    };
    let r_terms = JointSpendTerms { payout: &returned, ..c_terms };
    let deferred_c = build_deferred_joint_spend(&c_terms, &mut ChaCha20Rng::from_seed([83; 32])).unwrap();
    let deferred_r = build_deferred_joint_spend(&r_terms, &mut ChaCha20Rng::from_seed([82; 32])).unwrap();
    let (_, joint_anchor) = synthetic_membership(funding.joint_note());
    let funding_facts = FundingFacts {
        source: source_facts(&source),
        input: OwnedInputFacts { note: input.note(), full_viewing_key: input.full_viewing_key(),
            merkle_path: input.merkle_path(), anchor: input.anchor() },
        private_pczt: funding.private_pczt_bytes(),
        requested_output_actions: funding.payout_witness().requested_output_actions(),
        joint_requested_index: 0, joint_full_viewing_key: &joint_fvk, group_ak, fee: 10_000,
    };
    let output_facts = || outputs.iter().map(|output| NativeOutputFacts {
        recipient: output.recipient(), value: u64::from(output.value()), memo: Some(output.memo().as_array()),
    });
    let completion = ConsumerFacts {
        private_pczt: deferred_c.private_pczt_bytes(), anchor: joint_anchor,
        terms: JointSpendFacts { source: source_facts(&child_source), note: funding.joint_note(),
            full_viewing_key: &joint_fvk, group_ak, fee: 10_000,
            payout: NativeOutputFacts { recipient: payout.recipient(), value: 40_000,
                memo: Some(payout.memo().as_array()) } },
    };
    let recovery = ConsumerFacts {
        private_pczt: deferred_r.private_pczt_bytes(),
        terms: JointSpendFacts { payout: NativeOutputFacts { recipient: returned.recipient(),
            value: 40_000, memo: Some(returned.memo().as_array()) }, ..completion.terms },
        ..completion
    };
    let statement = statement_for_generated_joint(funding.joint_note(), &joint_fvk);
    let check = |statement: &ziquid_protocol::native::Statement| {
        check_statement_source_fields(statement, &funding_facts, output_facts(), &completion, &recovery)
    };
    let checked = check(&statement).unwrap();
    assert_eq!((checked.input_debit, checked.owned_change, checked.joint_note.value().inner(), checked.fee),
        (100_000, 40_000, 50_000, 10_000));

    // Independently shape-valid financial scalars must match the original
    // generated F/C/R, not one another or a caller-rewritten expected field.
    for role in 0..3 {
        let mut changed = statement;
        changed.targets[role] += 1;
        changed.validate().unwrap();
        assert!(matches!(check(&changed), Err(SourceRelationError::StatementMismatch)));
        changed = statement;
        changed.expiries[role] += 1;
        changed.validate().unwrap();
        assert!(matches!(check(&changed), Err(SourceRelationError::StatementMismatch)));
        changed = statement;
        changed.fees[role] += 1;
        if role == 1 { changed.a -= 1; }
        if role == 2 { changed.r_return -= 1; }
        changed.validate().unwrap();
        assert!(matches!(check(&changed), Err(SourceRelationError::StatementMismatch)));
        changed = statement;
        changed.fee_caps[role] = 9_999;
        assert!(matches!(check(&changed), Err(SourceRelationError::StatementShape)));
    }
    let mut changed = statement;
    changed.joint_value += 1;
    changed.a += 1;
    changed.r_return += 1;
    changed.validate().unwrap();
    assert!(matches!(check(&changed), Err(SourceRelationError::StatementMismatch)));
    changed = statement;
    changed.stable_jtag[0] ^= 1;
    changed.validate().unwrap();
    assert!(matches!(check(&changed), Err(SourceRelationError::StableTagMismatch)));
    changed = statement;
    changed.target_chain_id += 1;
    changed.validate().unwrap();
    assert!(matches!(check(&changed), Err(SourceRelationError::StableTagMismatch)));
    changed = statement;
    changed.obligation[0] ^= 1;
    changed.validate().unwrap();
    assert!(matches!(check(&changed), Err(SourceRelationError::StableTagMismatch)));
    for (network, pool, version, branch) in [
        (0, 3, 6, 0x37a5_165b), (1, 2, 6, 0x37a5_165b),
        (1, 3, 5, 0x37a5_165b), (1, 3, 6, 0xc8e7_1055),
    ] {
        changed = statement;
        changed.source_network = network;
        changed.source_pool = pool;
        changed.transaction_version = version;
        changed.consensus_branch = branch;
        assert!(matches!(check(&changed), Err(SourceRelationError::StatementShape)));
    }

    let mut wrong_funding = funding_facts;
    wrong_funding.source.target_height = 4_134_001.into();
    assert!(matches!(check_statement_source_fields(&statement, &wrong_funding,
        output_facts(), &completion, &recovery), Err(SourceRelationError::StatementMismatch)));
    let changed_input_note = synthetic_note(input.note().recipient(), 99_999, 81, NoteVersion::V3);
    wrong_funding = funding_facts;
    wrong_funding.input.note = &changed_input_note;
    assert!(check_statement_source_fields(&statement, &wrong_funding,
        output_facts(), &completion, &recovery).is_err());
    let mut wrong_completion = completion;
    wrong_completion.terms.payout.recipient = returned.recipient();
    assert!(check_statement_source_fields(&statement, &funding_facts,
        output_facts(), &wrong_completion, &recovery).is_err());
    wrong_completion = completion;
    wrong_completion.terms.payout.memo = Some(returned.memo().as_array());
    assert!(check_statement_source_fields(&statement, &funding_facts,
        output_facts(), &wrong_completion, &recovery).is_err());
    let mut wrong_recovery = recovery;
    wrong_recovery.terms.group_ak[0] ^= 1;
    assert!(matches!(check_statement_source_fields(&statement, &funding_facts,
        output_facts(), &completion, &wrong_recovery), Err(SourceRelationError::Expectation)));

    // A semantically valid, actually generated R-to-S is not U recovery even
    // when its private expected terms are rewritten to agree with the packet.
    let redirected_plan = OutputPlan::new(payout.recipient(), returned.value(), returned.memo().clone());
    let redirected_terms = JointSpendTerms { payout: &redirected_plan, ..r_terms };
    let redirected = build_deferred_joint_spend(&redirected_terms,
        &mut ChaCha20Rng::from_seed([84; 32])).unwrap();
    review_joint_spend(redirected.private_pczt_bytes(), &redirected_terms).unwrap();
    let redirected_recovery = ConsumerFacts { private_pczt: redirected.private_pczt_bytes(),
        terms: JointSpendFacts { payout: NativeOutputFacts { recipient: redirected_plan.recipient(),
            value: 40_000, memo: Some(redirected_plan.memo().as_array()) }, ..recovery.terms },
        ..recovery };
    assert!(matches!(check_statement_source_fields(&statement, &funding_facts,
        output_facts(), &completion, &redirected_recovery), Err(SourceRelationError::RecoveryOwnership)));
}

#[test]
fn generated_funding_joint_note_is_preauthorized_for_early_r_before_funding_owner_signs() {
    let ceremony = run_dkg();
    let joint_fvk = experimental_joint_fvk(&ceremony.group);
    let group_ak = ceremony.group.verifying_key_bytes().unwrap();
    let wallet_sk = SpendingKey::from_bytes([0x44; 32]).unwrap();
    let wallet_fvk = FullViewingKey::from(&wallet_sk);
    let wallet_ask = SpendAuthorizingKey::from(&wallet_sk);
    let wallet_note = synthetic_note(
        wallet_fvk.address_at(0u32, Scope::External), 100_000, 81, NoteVersion::V3,
    );
    let (wallet_path, wallet_anchor) = synthetic_membership(&wallet_note);
    let input = OwnedInput::new(wallet_note, wallet_fvk.clone(), wallet_path, wallet_anchor).unwrap();
    let funding_source = SourceParameters {
        network: Network::TestNetwork, target_height: 4_134_000.into(),
        expiry_height: 4_134_020.into(), consensus_branch: BranchId::Nu6_3,
        fee_rule: zip317::FeeRule::standard(),
    };
    let joint_plan = OutputPlan::new(
        joint_fvk.address_at(0u32, Scope::External), Zatoshis::from_u64(50_000).unwrap(),
        MemoBytes::from_bytes(b"builder-generated exact J before F signature").unwrap(),
    );
    let change_plan = OutputPlan::new(
        wallet_fvk.address_at(1u32, Scope::Internal), Zatoshis::from_u64(40_000).unwrap(),
        MemoBytes::from_bytes(b"explicit wallet change").unwrap(),
    );
    let outputs = [joint_plan.clone(), change_plan.clone()];
    let (funding, funding_owner_index) = (1..=64).find_map(|seed| {
        let funding = prepare_joint_funding(&funding_source, &input, &outputs, 0, &joint_fvk,
            group_ak, &mut ChaCha20Rng::from_seed([seed; 32])).unwrap();
        let pczt = Pczt::parse(funding.private_pczt_bytes()).unwrap();
        let owner_index = pczt.ironwood().actions().iter()
            .position(|action| action.spend().nullifier() == &input.nullifier().to_bytes()).unwrap();
        (owner_index != 0 && funding.joint_action_index() != 0).then_some((funding, owner_index))
    }).expect("fixture must exercise both actual wallet input and J away from action zero");
    let exact_unsigned_f = Zeroizing::new(funding.private_pczt_bytes().to_vec());
    let funding_effect_id = funding.effect_id();
    let joint_note = *funding.joint_note();
    let joint_cmx = ExtractedNoteCommitment::from(joint_note.commitment());
    assert_eq!(funding.fee(), Zatoshis::from_u64(10_000).unwrap());
    assert_eq!(joint_note.version(), NoteVersion::V3);
    assert_eq!(joint_note.value().inner(), 50_000);
    assert!(joint_note.recipient() == joint_plan.recipient());
    assert_eq!(funding.joint_memo(), joint_plan.memo().as_array());
    let unsigned = Pczt::parse(&exact_unsigned_f).unwrap();
    assert!(unsigned.ironwood().zkproof().is_none());
    assert!(unsigned.ironwood().actions().iter().all(|action| action.spend().spend_auth_sig().is_none()));
    assert_eq!(unsigned.ironwood().actions()[funding.joint_action_index()].output().cmx(),
        &Some(joint_cmx.to_bytes()));
    assert_eq!(unsigned.ironwood().actions().len(), 2);
    assert_eq!(unsigned.ironwood().actions()[funding_owner_index].spend().nullifier(),
        &input.nullifier().to_bytes());
    assert!(TransactionExtractor::new(unsigned).extract().is_err());

    // Use the EXACT F-generated J, not a fabricated rho/rseed. The independent
    // child expiry is only a fixture choice, NOT a qualified W4/W5 safety margin.
    let recovery_source = SourceParameters { expiry_height: 4_134_040.into(), ..funding_source.clone() };
    let return_plan = OutputPlan::new(
        wallet_fvk.address_at(2u32, Scope::Internal), Zatoshis::from_u64(40_000).unwrap(),
        MemoBytes::from_bytes(b"early R for the exact generated J").unwrap(),
    );
    let terms = JointSpendTerms {
        source: &recovery_source, note: &joint_note, full_viewing_key: &joint_fvk,
        group_ak, payout: &return_plan, fee: Zatoshis::from_u64(10_000).unwrap(),
    };
    let deferred = build_deferred_joint_spend(&terms, &mut ChaCha20Rng::from_seed([82; 32])).unwrap();
    let reviewed = review_joint_spend(deferred.private_pczt_bytes(), &terms).unwrap();
    let recovery_owner_index = reviewed.action_index();
    let recovery_message = reviewed.shielded_sighash();
    let recovery_output_notes = reviewed.output_notes().unwrap();
    let alpha = Alpha::from_bytes(&reviewed.alpha()).unwrap();
    check_action_rk(&ceremony.group, &alpha, &reviewed.randomized_key()).unwrap();
    let aggregate = threshold_sign(&ceremony, &recovery_message, &alpha);
    let early_r = reviewed.apply_external_signature(aggregate).unwrap();
    let early_pczt = Pczt::parse(early_r.private_pczt_bytes()).unwrap();
    assert!(early_pczt.ironwood().anchor().is_none());
    assert!(early_pczt.ironwood().actions()[recovery_owner_index].spend().witness().is_none());
    assert!(early_pczt.ironwood().actions().iter().all(|action| action.spend().spend_auth_sig().is_some()));
    assert_eq!(early_pczt.ironwood().actions()[recovery_owner_index].spend().nullifier(),
        &joint_note.nullifier(&joint_fvk).to_bytes());
    assert_eq!(early_pczt.ironwood().actions()[recovery_owner_index].spend().spend_auth_sig(), &Some(aggregate));
    assert!(TransactionExtractor::new(early_pczt).extract().is_err(), "early R is not finished R");
    assert_eq!(funding.private_pczt_bytes(), exact_unsigned_f.as_slice());
    assert!(Pczt::parse(funding.private_pczt_bytes()).unwrap().ironwood().actions().iter()
        .all(|action| action.spend().spend_auth_sig().is_none()), "R exists before any F signature");

    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let wrong_wallet_ask = SpendAuthorizingKey::from(&SpendingKey::from_bytes([0x45; 32]).unwrap());
    assert_eq!(funding.complete_borrowed_owner(&wrong_wallet_ask, &pk, &vk, &mut OsRng).unwrap_err(),
        FundingError::Source(AuthoringError::SigningFailed));
    let wrong_vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    assert_eq!(funding.complete_borrowed_owner(&wallet_ask, &pk, &wrong_vk, &mut OsRng).unwrap_err(),
        FundingError::Source(AuthoringError::WrongCircuitVersion));
    assert_eq!(funding.private_pczt_bytes(), exact_unsigned_f.as_slice(), "failed completion never replaces F");
    // Only generated fixture authority is exercised, with the actual funding
    // wallet ask. No J ask is reconstructed, and no C-only arming token is used.
    let completed_f = funding.complete_borrowed_owner(&wallet_ask, &pk, &vk, &mut OsRng).unwrap();
    assert_eq!(completed_f.effect_id(), funding_effect_id);
    assert_eq!(completed_f.transaction().lock_time(), 0);
    assert_eq!(u32::from(completed_f.transaction().expiry_height()), 4_134_020);
    assert_eq!(funding.private_pczt_bytes(), exact_unsigned_f.as_slice());
    let consensus_f = completed_f.serialize().unwrap();
    let parsed_f = IronwoodTransaction::parse(&consensus_f, BranchId::Nu6_3).unwrap();
    parsed_f.verify_authorization(&vk, &mut OsRng).unwrap();
    let bundle_f = parsed_f.transaction().ironwood_bundle().unwrap();
    assert_eq!(bundle_f.actions().len(), 2);
    assert_eq!(bundle_f.anchor(), &wallet_anchor);
    assert_eq!(i64::from(*bundle_f.value_balance()), 10_000);
    assert_eq!(bundle_f.actions()[funding_owner_index].nullifier(), &input.nullifier());
    let recovered_j = funding.payout_witness().recover_transaction_output(&parsed_f, 0).unwrap();
    let recovered_change = funding.payout_witness().recover_transaction_output(&parsed_f, 1).unwrap();
    assert!(recovered_j.note() == &joint_note);
    assert_eq!(recovered_j.memo(), joint_plan.memo().as_array());
    assert_eq!(recovered_change.value(), 40_000);
    assert!(recovered_change.recipient() == change_plan.recipient());
    assert_eq!(recovered_change.memo(), change_plan.memo().as_array());
    let received_j = bundle_f.decrypt_outputs_with_keys(&[joint_fvk.to_ivk(Scope::External)]);
    assert_eq!(received_j.len(), 1);
    assert!(received_j[0].2 == joint_note);
    assert_eq!(&received_j[0].4, joint_plan.memo().as_array());

    // Mutated authorizations preserve F txid but the FULL verifier rejects each
    // real/padding SpendAuth, binding signature and Halo2 proof independently.
    let signatures = consensus_f.len() - 64 * (bundle_f.actions().len() + 1);
    for index in 0..bundle_f.actions().len() {
        let mut damaged = consensus_f.clone();
        damaged[signatures + 64 * index..signatures + 64 * (index + 1)].fill(0);
        let parsed = IronwoodTransaction::parse(&damaged, BranchId::Nu6_3).unwrap();
        assert_eq!(parsed.effect_id(), funding_effect_id);
        assert_eq!(parsed.verify_authorization(&vk, &mut OsRng).unwrap_err(), ValidationError::InvalidAuthorization);
        assert_eq!(funding.verify_transaction(&parsed).unwrap_err(), FundingError::Consensus(ValidationError::InvalidAuthorization));
    }
    let mut damaged_binding = consensus_f.clone();
    damaged_binding[consensus_f.len() - 64..].fill(0);
    assert_eq!(IronwoodTransaction::parse(&damaged_binding, BranchId::Nu6_3).unwrap()
        .verify_authorization(&vk, &mut OsRng).unwrap_err(), ValidationError::InvalidAuthorization);
    let mut damaged_proof = consensus_f.clone();
    damaged_proof[signatures - 1] ^= 1;
    assert_eq!(IronwoodTransaction::parse(&damaged_proof, BranchId::Nu6_3).unwrap()
        .verify_authorization(&vk, &mut OsRng).unwrap_err(), ValidationError::InvalidAuthorization);
    for damaged in [&damaged_binding, &damaged_proof] {
        let parsed = IronwoodTransaction::parse(damaged, BranchId::Nu6_3).unwrap();
        assert_eq!(funding.verify_transaction(&parsed).unwrap_err(), FundingError::Consensus(ValidationError::InvalidAuthorization));
    }

    // ONLY now construct synthetic J membership. Real admission/finality remains
    // separate. R's early aggregate survives unchanged F completion and membership.
    let (joint_path, joint_anchor) = synthetic_membership(&joint_note);
    let finished_r = early_r.complete(joint_path, joint_anchor, &pk, &vk, &mut OsRng).unwrap();
    assert_eq!(finished_r.effect_id(), recovery_message);
    let bundle_r = finished_r.transaction().ironwood_bundle().unwrap();
    assert_eq!(bundle_r.actions()[recovery_owner_index].nullifier(), &joint_note.nullifier(&joint_fvk));
    assert_eq!(<[u8; 64]>::from(bundle_r.actions()[recovery_owner_index].authorization()), aggregate);
    let consensus_r = finished_r.serialize().unwrap();
    let independently_reviewed_r = review_finished_joint_spend(&consensus_r, &FinishedJointSpendExpectation {
        terms, shielded_sighash: recovery_message, anchor: joint_anchor,
        output_notes: &recovery_output_notes,
    }, &vk, &mut OsRng).unwrap();
    assert_eq!(independently_reviewed_r.serialize().unwrap(), consensus_r);

    // The guest-safe relation reopens the ORIGINAL unsigned F and pre-parent R,
    // rather than trusting the host review digest or finished output list.
    let funding_facts = FundingFacts {
        source: source_facts(&funding_source),
        input: OwnedInputFacts {
            note: input.note(), full_viewing_key: input.full_viewing_key(),
            merkle_path: input.merkle_path(), anchor: input.anchor(),
        },
        private_pczt: funding.private_pczt_bytes(),
        requested_output_actions: funding.payout_witness().requested_output_actions(),
        joint_requested_index: 0, joint_full_viewing_key: &joint_fvk, group_ak,
        fee: 10_000,
    };
    let output_facts = || outputs.iter().map(|output| NativeOutputFacts {
        recipient: output.recipient(), value: u64::from(output.value()),
        memo: Some(output.memo().as_array()),
    });
    let checked_f = verify_funding(&funding_facts, output_facts(), Some(parsed_f.transaction())).unwrap();
    assert_eq!(checked_f.input_debit, 100_000);
    assert_eq!(checked_f.owned_change, 40_000);
    assert_eq!(checked_f.fee, 10_000);
    assert_eq!(checked_f.joint_note.value().inner(), 50_000);
    let recovery_facts = JointSpendFacts {
        source: source_facts(&recovery_source), note: &checked_f.joint_note,
        full_viewing_key: &joint_fvk, group_ak,
        payout: NativeOutputFacts {
            recipient: return_plan.recipient(), value: 40_000,
            memo: Some(return_plan.memo().as_array()),
        }, fee: 10_000,
    };
    let checked_r = verify_joint_consumer(
        deferred.private_pczt_bytes(), &recovery_facts, joint_anchor, finished_r.transaction(),
    ).unwrap();
    assert_eq!(checked_r.input_total, 50_000);
    assert_eq!(checked_r.output_total, 40_000);
    assert_eq!(checked_r.fee, 10_000);
    assert_eq!(checked_r.effect_id, recovery_message);
    let mut wrong_f_anchor = funding_facts;
    wrong_f_anchor.input.anchor = joint_anchor;
    assert!(verify_funding(&wrong_f_anchor, output_facts(), Some(parsed_f.transaction())).is_err());
    let mut wrong_r = recovery_facts;
    wrong_r.payout.memo = Some(joint_plan.memo().as_array());
    assert!(verify_joint_consumer(deferred.private_pczt_bytes(), &wrong_r, joint_anchor,
        finished_r.transaction()).is_err());

    // A genuine separate completion transaction pays S, not a C/R branch label
    // echo over the same R. Its effects, threshold message and ciphertext differ.
    let solver_fvk = FullViewingKey::from(&SpendingKey::from_bytes([0x66; 32]).unwrap());
    let completion_plan = OutputPlan::new(
        solver_fvk.address_at(0u32, Scope::External), Zatoshis::from_u64(40_000).unwrap(),
        MemoBytes::from_bytes(b"actual separate solver completion C").unwrap(),
    );
    let completion_terms = JointSpendTerms { payout: &completion_plan, ..terms };
    let deferred_c = build_deferred_joint_spend(&completion_terms,
        &mut ChaCha20Rng::from_seed([83; 32])).unwrap();
    let reviewed_c = review_joint_spend(deferred_c.private_pczt_bytes(), &completion_terms).unwrap();
    let c_message = reviewed_c.shielded_sighash();
    let c_alpha = Alpha::from_bytes(&reviewed_c.alpha()).unwrap();
    let c_signature = threshold_sign(&ceremony, &c_message, &c_alpha);
    let (c_path, c_anchor) = synthetic_membership(&joint_note);
    let finished_c = reviewed_c.apply_external_signature(c_signature).unwrap()
        .complete(c_path, c_anchor, &pk, &vk, &mut OsRng).unwrap();
    let completion_facts = JointSpendFacts {
        payout: NativeOutputFacts {
            recipient: completion_plan.recipient(), value: 40_000,
            memo: Some(completion_plan.memo().as_array()),
        }, ..recovery_facts
    };
    let checked_c = verify_joint_consumer(deferred_c.private_pczt_bytes(), &completion_facts,
        c_anchor, finished_c.transaction()).unwrap();
    assert_eq!(checked_c.input_total, 50_000);
    assert_eq!(checked_c.output_total, 40_000);
    assert_eq!(checked_c.fee, 10_000);
    assert_ne!(checked_c.effect_id, checked_r.effect_id);
    assert!(verify_joint_consumer(deferred.private_pczt_bytes(), &recovery_facts,
        joint_anchor, finished_c.transaction()).is_err());
    assert!(verify_joint_consumer(deferred_c.private_pczt_bytes(), &completion_facts,
        c_anchor, finished_r.transaction()).is_err());

    // Authentic genesis is not an origin certificate for synthetic U/J. The
    // actual one-loop composed consumer must exhaust it and return no accounting.
    use ziquid_proofs::{genesis::ShieldedPool,
        native_relation::source::{ConsumerFacts, SourceRelationError, check_statement_source_fields, verify_supplied_prefix},
        source_note::{SourceFundingLocator, SourceNoteError, SourceNoteSelection}};
    let origin_selection = SourceNoteSelection {
        pool: ShieldedPool::Ironwood,
        commitment: ExtractedNoteCommitment::from(input.note().commitment()).to_bytes(),
        nullifier: input.nullifier().to_bytes(),
        funding: SourceFundingLocator { block_height: 4_134_000, transaction_index: 1, action_index: 0,
            effect_id: [1; 32], auth_digest: [2; 32] },
    };
    let joint_selection = SourceNoteSelection {
        pool: ShieldedPool::Ironwood,
        commitment: ExtractedNoteCommitment::from(joint_note.commitment()).to_bytes(),
        nullifier: joint_note.nullifier(&joint_fvk).to_bytes(),
        funding: SourceFundingLocator { block_height: 4_134_001, transaction_index: 1,
            action_index: funding.joint_action_index() as u32, effect_id: funding.effect_id(),
            auth_digest: parsed_f.authorization_id() },
    };
    let genesis = include_bytes!("fixtures/testnet-genesis.bin");
    let mut history = 1u32.to_le_bytes().to_vec();
    history.extend_from_slice(&(genesis.len() as u32).to_le_bytes());
    history.extend_from_slice(genesis);
    let completion = ConsumerFacts { private_pczt: deferred_c.private_pczt_bytes(), terms: completion_facts, anchor: c_anchor };
    let recovery = ConsumerFacts { private_pczt: deferred.private_pczt_bytes(), terms: recovery_facts, anchor: joint_anchor };
    let statement = statement_for_generated_joint(&joint_note, &joint_fvk);
    check_statement_source_fields(&statement, &funding_facts, output_facts(), &completion, &recovery).unwrap();
    let mut reader = history.as_slice();
    assert_eq!(verify_supplied_prefix(&statement, &mut reader, 1, history.len() as u64,
        origin_selection, joint_selection, &funding_facts, output_facts(), &completion, &recovery).unwrap_err(),
        SourceRelationError::History(SourceNoteError::FundingNotFound));
    assert!(reader.is_empty());
    let mut wrong_statement = statement;
    wrong_statement.a += 1;
    wrong_statement.joint_value += 1;
    wrong_statement.r_return += 1;
    wrong_statement.validate().unwrap();
    let mut reader = history.as_slice();
    assert_eq!(verify_supplied_prefix(&wrong_statement, &mut reader, 1, history.len() as u64,
        origin_selection, joint_selection, &funding_facts, output_facts(), &completion, &recovery).unwrap_err(),
        SourceRelationError::StatementMismatch);
    assert_eq!(reader.len(), history.len(), "source mismatch rejects before history acquisition");

    #[cfg(feature = "native-relation-smoke")]
    for (_case, private, facts, anchor, raw) in [
        ("R", deferred.private_pczt_bytes(), recovery_facts, joint_anchor, consensus_r),
        ("C", deferred_c.private_pczt_bytes(), completion_facts, c_anchor, finished_c.serialize().unwrap()),
    ] {
        use ziquid_proofs::native_relation::smoke;
        let frame = smoke::encode(&funding_facts, output_facts(), &consensus_f,
            private, &facts, anchor, &raw).unwrap();
        smoke::verify(&frame).unwrap();
        let mut damaged = Zeroizing::new(frame.to_vec());
        *damaged.last_mut().unwrap() ^= 1; // Actual consumer binding signature.
        assert!(smoke::verify(&damaged).is_err());
        let mut trailing = Zeroizing::new(Vec::with_capacity(frame.len() + 1));
        trailing.extend_from_slice(&frame);
        trailing.push(0);
        assert!(smoke::verify(&trailing).is_err());
        #[cfg(feature = "sp1-execute")]
        if let Some(path) = std::env::var_os("ZIQUID_NATIVE_RELATION_ELF") {
            use sp1_primitives::Elf;
            use ziquid_proofs::artifacts::execution::execute_private;
            let elf: Elf = std::fs::read(path).unwrap().into();
            let result = execute_private(elf.clone(), &frame).expect("actual native relation guest failed");
            println!("native_relation_cpu_smoke case={_case} valid instructions={} exit={} journal_len={}",
                result.instructions, result.exit_code, result.journal.len());
            assert_eq!(result.exit_code, 0);
            assert!(result.instructions > 0);
            assert_eq!(result.journal, smoke::SUCCESS);
            let result = execute_private(elf, &damaged).expect("negative guest execution failed");
            println!("native_relation_cpu_smoke case={_case} damaged instructions={} exit={} journal_len={}",
                result.instructions, result.exit_code, result.journal.len());
            assert_ne!(result.exit_code, 0);
            assert!(result.journal.is_empty());
        }
    }
}
