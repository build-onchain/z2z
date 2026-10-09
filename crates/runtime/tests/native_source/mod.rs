//! Real generated capabilities and authentic genesis..10; no connected late
//! Ironwood archive is available. Isolated cryptographic checks do not construct
//! a public supplied-prefix result. No wallet, SQL, network or funds are used.

use super::*;
use std::{io, sync::LazyLock};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{
    Anchor, Note,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::{consensus::{BranchId, Network}, memo::MemoBytes, value::Zatoshis};
use ziquid_proofs::source_replay::SourceReplayError;
use ziquid_threshold::{
    Alpha, DkgSession, GroupPublicKey, KeyShare, Participant, aggregate, check_action_rk,
    commit, sign_share,
};
use ziquid_zcash::{
    OutputPlan, OwnedInput, SourceParameters,
    funding::prepare_joint_funding,
    joint_spend::{DeferredJointSpend, JointSpendTerms, build_deferred_joint_spend, review_joint_spend},
};

static VERIFYING_KEY: LazyLock<VerifyingKey> =
    LazyLock::new(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3));
static FIXTURE: LazyLock<Fixture> = LazyLock::new(Fixture::new);

struct Fixture {
    first: KeyShare,
    second: KeyShare,
    group: GroupPublicKey,
    funding: PreparedJointFunding,
    source: SourceParameters,
    c_payout: OutputPlan,
    r_payout: OutputPlan,
    r: DeferredJointSpend,
    c_sighash: [u8; 32],
    r_sighash: [u8; 32],
    c_notes: Vec<Note>,
    r_notes: Vec<Note>,
    anchor: Anchor,
    path: MerklePath,
}

fn generated_note(fvk: &FullViewingKey) -> Note {
    let rho = Rho::from_bytes(&[8; 32]).unwrap();
    let mut rng = ChaCha20Rng::from_seed([72; 32]);
    loop {
        let mut seed = Zeroizing::new([0; 32]);
        rng.fill_bytes(&mut *seed);
        if let Some(seed) = RandomSeed::from_bytes(*seed, &rho).into_option()
            && let Some(note) = Note::from_parts(
                fvk.address_at(0u32, Scope::External), NoteValue::from_raw(100_000),
                rho, seed, NoteVersion::V3,
            ).into_option()
        {
            return note;
        }
    }
}

fn isolated_membership(note: &Note) -> (MerklePath, Anchor) {
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    tree.append(MerkleHashOrchard::from_cmx(&cmx)).unwrap();
    let path: MerklePath = IncrementalWitness::from_tree(tree).unwrap().path().unwrap().into();
    let anchor = path.root(cmx);
    (path, anchor)
}

impl Fixture {
    fn new() -> Self {
        let (mut first, first_round1) = DkgSession::start(Participant::First, &mut OsRng).unwrap();
        let (mut second, second_round1) = DkgSession::start(Participant::Second, &mut OsRng).unwrap();
        let first_round2 = first.round2(&second_round1).unwrap();
        let second_round2 = second.round2(&first_round1).unwrap();
        let (first, group) = first.finalize(&second_round1, &second_round2).unwrap();
        let (second, second_group) = second.finalize(&first_round1, &first_round2).unwrap();
        assert!(group.to_bytes() == second_group.to_bytes());
        let group_ak = group.verifying_key_bytes().unwrap();
        // Same explicit experimental surrogate as route1a_pczt_threshold_spend:
        // genuine normalized DKG ak, NOT qualification of threshold-FVK custody.
        let mut fvk_bytes = Zeroizing::new(
            FullViewingKey::from(&SpendingKey::from_bytes([0x11; 32]).unwrap()).to_bytes(),
        );
        fvk_bytes[..32].copy_from_slice(&group_ak);
        let joint_fvk = FullViewingKey::from_bytes(&fvk_bytes).unwrap();
        let wallet_fvk = FullViewingKey::from(&SpendingKey::from_bytes([71; 32]).unwrap());
        let wallet_note = generated_note(&wallet_fvk);
        let (wallet_path, wallet_anchor) = isolated_membership(&wallet_note);
        let input = OwnedInput::new(wallet_note, wallet_fvk.clone(), wallet_path, wallet_anchor).unwrap();
        let source = SourceParameters {
            network: Network::TestNetwork, target_height: 4_134_000.into(),
            expiry_height: 4_134_040.into(), consensus_branch: BranchId::Nu6_3,
            fee_rule: zip317::FeeRule::standard(),
        };
        let outputs = [
            OutputPlan::new(joint_fvk.address_at(0u32, Scope::External),
                Zatoshis::from_u64(50_000).unwrap(), MemoBytes::from_bytes(b"generated exact J").unwrap()),
            OutputPlan::new(wallet_fvk.address_at(1u32, Scope::Internal),
                Zatoshis::from_u64(40_000).unwrap(), MemoBytes::from_bytes(b"explicit wallet change").unwrap()),
        ];
        let funding = (1..=64).find_map(|seed| {
            let funding = prepare_joint_funding(&source, &input, &outputs, 0, &joint_fvk,
                group_ak, &mut ChaCha20Rng::from_seed([seed; 32])).unwrap();
            (funding.joint_action_index() != 0).then_some(funding)
        }).expect("fixture exercises the actual shuffled J index");
        let c_fvk = FullViewingKey::from(&SpendingKey::from_bytes([73; 32]).unwrap());
        let c_payout = OutputPlan::new(c_fvk.address_at(0u32, Scope::External),
            Zatoshis::from_u64(40_000).unwrap(), MemoBytes::from_bytes(b"independent C payout").unwrap());
        let r_payout = OutputPlan::new(wallet_fvk.address_at(2u32, Scope::Internal),
            Zatoshis::from_u64(40_000).unwrap(), MemoBytes::from_bytes(b"independent R return").unwrap());
        let c_terms = JointSpendTerms {
            source: &source, note: funding.joint_note(), full_viewing_key: funding.joint_full_viewing_key(),
            group_ak, payout: &c_payout, fee: Zatoshis::from_u64(10_000).unwrap(),
        };
        let r_terms = JointSpendTerms { payout: &r_payout, ..c_terms };
        let c = build_deferred_joint_spend(&c_terms,
            &mut ChaCha20Rng::from_seed([74; 32])).unwrap();
        let r = build_deferred_joint_spend(&r_terms,
            &mut ChaCha20Rng::from_seed([75; 32])).unwrap();
        let reviewed_c = review_joint_spend(c.private_pczt_bytes(), &c_terms).unwrap();
        let reviewed_r = review_joint_spend(r.private_pczt_bytes(), &r_terms).unwrap();
        let c_sighash = reviewed_c.shielded_sighash();
        let r_sighash = reviewed_r.shielded_sighash();
        let c_notes = reviewed_c.output_notes().unwrap();
        let r_notes = reviewed_r.output_notes().unwrap();
        let (path, anchor) = isolated_membership(funding.joint_note());
        Self { first, second, group, funding, source, c_payout, r_payout,
            r, c_sighash, r_sighash, c_notes, r_notes, anchor, path }
    }

    fn terms<'a>(&'a self, payout: &'a OutputPlan) -> JointSpendTerms<'a> {
        JointSpendTerms {
            source: &self.source, note: self.funding.joint_note(),
            full_viewing_key: self.funding.joint_full_viewing_key(),
            group_ak: self.funding.group_ak(), payout, fee: Zatoshis::from_u64(10_000).unwrap(),
        }
    }

    fn expectations(&self) -> [FinishedJointSpendExpectation<'_>; 2] {
        [
            FinishedJointSpendExpectation { terms: self.terms(&self.c_payout),
                shielded_sighash: self.c_sighash, anchor: self.anchor, output_notes: &self.c_notes },
            FinishedJointSpendExpectation { terms: self.terms(&self.r_payout),
                shielded_sighash: self.r_sighash, anchor: self.anchor, output_notes: &self.r_notes },
        ]
    }

    fn selection(&self) -> SourceNoteSelection {
        SourceNoteSelection {
            pool: ShieldedPool::Ironwood,
            commitment: ExtractedNoteCommitment::from(self.funding.joint_note().commitment()).to_bytes(),
            nullifier: self.funding.joint_note().nullifier(self.funding.joint_full_viewing_key()).to_bytes(),
            funding: ziquid_proofs::source_note::SourceFundingLocator {
                block_height: 4_134_000, transaction_index: 1,
                action_index: self.funding.joint_action_index() as u32,
                effect_id: self.funding.effect_id(), auth_digest: [0x81; 32],
            },
        }
    }

    fn sign(&self, message: &[u8; 32], alpha: &Alpha) -> [u8; 64] {
        let (first_nonce, first_commitment) = commit(&self.first, &mut OsRng).unwrap();
        let (second_nonce, second_commitment) = commit(&self.second, &mut OsRng).unwrap();
        let commitments = [first_commitment, second_commitment];
        let first = sign_share(&self.first, first_nonce, message, alpha, &commitments).unwrap();
        let second = sign_share(&self.second, second_nonce, message, alpha, &commitments).unwrap();
        aggregate(&self.group, message, alpha, &commitments, &[first, second]).unwrap()
    }
}

struct UnreadHistory;
impl io::Read for UnreadHistory {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("invalid source linkage must reject before history acquisition")
    }
}

#[test]
fn arbitrary_selection_values_or_different_joint_terms_reject_before_reading_history() {
    let fixture = &*FIXTURE;
    let [c, r] = fixture.expectations();
    for field in 0..5 {
        let mut selection = fixture.selection();
        match field {
            0 => selection.pool = ShieldedPool::Orchard,
            1 => selection.commitment = [0; 32],
            2 => selection.nullifier = [0; 32],
            3 => selection.funding.effect_id[0] ^= 1,
            4 => selection.funding.action_index = 0,
            _ => unreachable!(),
        }
        assert_eq!(reconcile_source_testnet(&mut UnreadHistory, 11, 17_920, selection,
            &fixture.funding, &c, &r, &VERIFYING_KEY, &mut OsRng).unwrap_err(),
            NativeSourceError::Selection);
    }
    let mut wrong_group = r.terms.group_ak;
    wrong_group[0] ^= 1;
    let other_note = generated_note(fixture.funding.joint_full_viewing_key());
    let other_fvk = FullViewingKey::from(&SpendingKey::from_bytes([76; 32]).unwrap());
    for terms in [
        JointSpendTerms { group_ak: wrong_group, ..r.terms },
        JointSpendTerms { note: &other_note, ..r.terms },
        JointSpendTerms { full_viewing_key: &other_fvk, ..r.terms },
    ] {
        let changed = FinishedJointSpendExpectation { terms, ..r };
        assert_eq!(reconcile_source_testnet(&mut UnreadHistory, 11, 17_920, fixture.selection(),
            &fixture.funding, &c, &changed, &VERIFYING_KEY, &mut OsRng).unwrap_err(),
            NativeSourceError::Expectation);
    }
    assert_eq!(reconcile_source_testnet(&mut UnreadHistory, 11, 17_920, fixture.selection(),
        &fixture.funding, &c, &c, &VERIFYING_KEY, &mut OsRng).unwrap_err(),
        NativeSourceError::Expectation);
}

fn framed(blocks: &[&[u8]]) -> Vec<u8> {
    let mut bytes = (blocks.len() as u32).to_le_bytes().to_vec();
    for block in blocks {
        bytes.extend_from_slice(&(block.len() as u32).to_le_bytes());
        bytes.extend_from_slice(block);
    }
    bytes
}

const GENESIS: &[u8] = include_bytes!("../../../proofs/tests/fixtures/testnet-genesis.bin");

#[test]
fn authentic_connected_prefix_cannot_fabricate_generated_joint_funding_or_hide_bad_suffix() {
    let fixture = &*FIXTURE;
    let [c, r] = fixture.expectations();
    let blocks: [&[u8]; 11] = [
        GENESIS,
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-1.bin"),
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-2.bin"),
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-3.bin"),
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-4.bin"),
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-5.bin"),
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-6.bin"),
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-7.bin"),
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-8.bin"),
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-9.bin"),
        include_bytes!("../../../proofs/tests/fixtures/testnet-block-10.bin"),
    ];
    let bytes = framed(&blocks);
    assert_eq!(bytes.len(), 17_920);
    let run = |mut bytes: &[u8]| reconcile_source_testnet(&mut bytes, 11, 17_921,
        fixture.selection(), &fixture.funding, &c, &r, &VERIFYING_KEY, &mut OsRng).unwrap_err();
    assert_eq!(run(&bytes), NativeSourceError::History(SourceNoteError::FundingNotFound));
    let mut corrupt = bytes.clone();
    corrupt[bytes.len() - blocks[10].len() + 1488 + 50] ^= 1;
    assert_eq!(run(&corrupt), NativeSourceError::History(SourceNoteError::Replay(SourceReplayError::InvalidTransition)));
    struct FailedEof<'a>(&'a [u8]);
    impl io::Read for FailedEof<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() { return Err(io::Error::other("private reader sentinel")); }
            io::Read::read(&mut self.0, bytes)
        }
    }
    let error = reconcile_source_testnet(&mut FailedEof(&bytes), 11, 17_920,
        fixture.selection(), &fixture.funding, &c, &r, &VERIFYING_KEY, &mut OsRng).unwrap_err();
    assert_eq!(error, NativeSourceError::History(SourceNoteError::Replay(SourceReplayError::InputUnavailable)));
    assert!(!error.to_string().contains("private reader sentinel"));
    assert!(!format!("{error:?}").contains("private reader sentinel"));
    let mut suffix = bytes.clone(); suffix.push(0);
    assert_eq!(run(&suffix), NativeSourceError::History(SourceNoteError::Replay(SourceReplayError::TrailingBytes)));
    assert_eq!(run(&bytes[..bytes.len() - 1]),
        NativeSourceError::History(SourceNoteError::Replay(SourceReplayError::InvalidFraming)));
    let late = include_bytes!("../../../proofs/tests/fixtures/testnet-nu5-block-1842467.bin");
    assert_eq!(run(&framed(&[GENESIS, late])),
        NativeSourceError::History(SourceNoteError::Replay(SourceReplayError::InvalidTransition)));
}

#[test]
fn isolated_genuine_generated_f_and_r_use_independent_semantics_and_accept_new_authorization() {
    let fixture = &*FIXTURE;
    let [c, r] = fixture.expectations();
    let selection = checked_selection(fixture.selection(), &fixture.funding, &c, &r, &VERIFYING_KEY).unwrap();
    assert!(selection.commitment == ExtractedNoteCommitment::from(fixture.funding.joint_note().commitment()).to_bytes());
    assert!(selection.nullifier == fixture.funding.joint_note().nullifier(fixture.funding.joint_full_viewing_key()).to_bytes());
    assert_ne!(selection.funding.action_index, 0);

    // Exact genuine generated F, with only this isolated fixture's wallet ask.
    // It has a synthetic anchor and is NEVER inserted into public replay evidence.
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let wallet_ask = SpendAuthorizingKey::from(&SpendingKey::from_bytes([71; 32]).unwrap());
    let finished_f = fixture.funding.complete_borrowed_owner(&wallet_ask, &pk, &VERIFYING_KEY, &mut OsRng).unwrap();
    let f_bytes = Zeroizing::new(finished_f.serialize().unwrap());
    check_funding_bytes(&f_bytes, &fixture.funding).unwrap();
    drop(finished_f);

    let reviewed = review_joint_spend(fixture.r.private_pczt_bytes(), &r.terms).unwrap();
    let action_index = reviewed.action_index();
    let alpha = Alpha::from_bytes(&reviewed.alpha()).unwrap();
    check_action_rk(&fixture.group, &alpha, &reviewed.randomized_key()).unwrap();
    let signature = fixture.sign(&r.shielded_sighash, &alpha);
    let finished_r = reviewed.apply_external_signature(signature).unwrap()
        .complete(fixture.path.clone(), fixture.anchor, &pk, &VERIFYING_KEY, &mut OsRng).unwrap();
    let r_bytes = Zeroizing::new(finished_r.serialize().unwrap());
    let actions = finished_r.transaction().ironwood_bundle().unwrap().actions().len();
    let effect_id = finished_r.effect_id();
    let old_auth = finished_r.authorization_id();
    drop(finished_r);
    drop(pk);
    assert_eq!(check_funding_bytes(&r_bytes, &fixture.funding), Err(NativeSourceError::Funding));
    let classify = |bytes: Option<&[u8]>, c: &FinishedJointSpendExpectation<'_>, r: &FinishedJointSpendExpectation<'_>| {
        classify_consumption(bytes, c, r, &VERIFYING_KEY, &mut OsRng)
    };
    assert_eq!(classify(None, &c, &r), SuppliedPrefixOutcome::SuppliedPrefixUnspent);
    assert_eq!(classify(Some(&r_bytes), &c, &r), SuppliedPrefixOutcome::SuppliedPrefixR);

    let new_signature = fixture.sign(&r.shielded_sighash, &alpha);
    assert!(new_signature != signature);
    let signatures_at = r_bytes.len() - 64 * (actions + 1);
    let mut new_auth = Zeroizing::new(r_bytes.to_vec());
    new_auth[signatures_at + 64 * action_index..signatures_at + 64 * (action_index + 1)]
        .copy_from_slice(&new_signature);
    let parsed = IronwoodTransaction::parse(&new_auth, BranchId::Nu6_3).unwrap();
    assert!(parsed.effect_id() == effect_id);
    assert!(parsed.authorization_id() != old_auth);
    assert_eq!(classify(Some(&new_auth), &c, &r), SuppliedPrefixOutcome::SuppliedPrefixR);
    drop(parsed);

    let wrong_memo = OutputPlan::new(r.terms.payout.recipient(), r.terms.payout.value(), MemoBytes::empty());
    let wrong_amount = OutputPlan::new(r.terms.payout.recipient(), Zatoshis::from_u64(39_999).unwrap(),
        r.terms.payout.memo().clone());
    let wrong_recipient = OutputPlan::new(c.terms.payout.recipient(), r.terms.payout.value(),
        r.terms.payout.memo().clone());
    let wrong_source = SourceParameters { expiry_height: 4_134_041.into(), ..fixture.source.clone() };
    let other_network = SourceParameters { network: Network::MainNetwork, ..fixture.source.clone() };
    let wrong_height = SourceParameters { target_height: 4_133_999.into(), ..fixture.source.clone() };
    for terms in [
        JointSpendTerms { payout: &wrong_memo, ..r.terms },
        JointSpendTerms { payout: &wrong_amount, fee: Zatoshis::from_u64(10_001).unwrap(), ..r.terms },
        JointSpendTerms { payout: &wrong_recipient, ..r.terms },
        JointSpendTerms { source: &wrong_source, ..r.terms },
        JointSpendTerms { source: &other_network, ..r.terms },
        JointSpendTerms { source: &wrong_height, ..r.terms },
    ] {
        // This actual fully authorized J consumer is unknown under these
        // independent terms. Gross credit is NEVER promoted to refund/net value.
        let changed = FinishedJointSpendExpectation { terms, ..r };
        assert_eq!(classify(Some(&r_bytes), &c, &changed), SuppliedPrefixOutcome::SuppliedPrefixOther);
    }
    let mut wrong_sighash = r.shielded_sighash; wrong_sighash[0] ^= 1;
    let mut wrong_notes = fixture.r_notes.clone(); wrong_notes.swap(0, 1);
    for changed in [
        FinishedJointSpendExpectation { shielded_sighash: wrong_sighash, ..r },
        FinishedJointSpendExpectation { anchor: Anchor::empty_tree(), ..r },
        FinishedJointSpendExpectation { output_notes: &fixture.r_notes[..1], ..r },
        FinishedJointSpendExpectation { output_notes: &wrong_notes, ..r },
    ] {
        assert_eq!(classify(Some(&r_bytes), &c, &changed), SuppliedPrefixOutcome::SuppliedPrefixOther);
    }
    // Actual authorization is verified, not just effect/sighash equality.
    let mut corrupted = Zeroizing::new(r_bytes.to_vec());
    corrupted[signatures_at + 64 * action_index..signatures_at + 64 * (action_index + 1)].fill(0);
    assert_eq!(classify(Some(&corrupted), &c, &r), SuppliedPrefixOutcome::SuppliedPrefixOther);
}
