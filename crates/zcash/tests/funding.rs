//! Generated local wallet witnesses only: not mined funding or source admission.

use incrementalmerkletree::{Hashable, Level};
use orchard::{
    Note,
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::Pczt;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::{
    consensus::{BranchId, Network},
    memo::MemoBytes,
    value::Zatoshis,
};
use ziquid_zcash::{
    AuthoringError, OutputPlan, OwnedInput, SourceParameters,
    funding::{FundingError, prepare_joint_funding},
};

fn fixture() -> (OwnedInput, FullViewingKey, SourceParameters) {
    let wallet_sk = SpendingKey::from_bytes([71; 32]).unwrap();
    let wallet_fvk = FullViewingKey::from(&wallet_sk);
    let mut rng = ChaCha20Rng::from_seed([72; 32]);
    let rho = Rho::from_bytes(&[8; 32]).unwrap();
    let note = loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(seed) = RandomSeed::from_bytes(bytes, &rho).into_option()
            && let Some(note) = Note::from_parts(
                wallet_fvk.address_at(0u32, Scope::External),
                NoteValue::from_raw(100_000), rho, seed, NoteVersion::V3,
            ).into_option()
        {
            break note;
        }
    };
    let siblings = std::array::from_fn(|i| MerkleHashOrchard::empty_root(Level::from(i as u8)));
    let path = MerklePath::from_parts(0, siblings);
    let anchor = path.root(note.commitment().into());
    let input = OwnedInput::new(note, wallet_fvk, path, anchor).unwrap();
    let joint_fvk = FullViewingKey::from(&SpendingKey::from_bytes([73; 32]).unwrap());
    let source = SourceParameters {
        network: Network::TestNetwork, target_height: 4_134_000.into(),
        expiry_height: 4_134_020.into(), consensus_branch: BranchId::Nu6_3,
        fee_rule: zip317::FeeRule::standard(),
    };
    (input, joint_fvk, source)
}

fn group_ak(fvk: &FullViewingKey) -> [u8; 32] {
    fvk.to_bytes()[..32].try_into().unwrap()
}

fn output(recipient: orchard::Address, value: u64, memo: &[u8]) -> OutputPlan {
    OutputPlan::new(recipient, Zatoshis::from_u64(value).unwrap(), MemoBytes::from_bytes(memo).unwrap())
}

#[test]
fn funding_exposes_exact_generated_joint_opening_before_authorization() {
    let (input, joint_fvk, source) = fixture();
    let joint = output(joint_fvk.address_at(0u32, Scope::External), 35_000, b"exact generated J");
    let outputs = [
        joint.clone(), joint.clone(),
        output(input.full_viewing_key().address_at(1u32, Scope::Internal), 15_000, b"explicit change"),
    ];
    let prepared = prepare_joint_funding(
        &source, &input, &outputs, 1, &joint_fvk, group_ak(&joint_fvk),
        &mut ChaCha20Rng::from_seed([74; 32]),
    ).unwrap();
    assert_eq!(format!("{prepared:?}"), "PreparedJointFunding([redacted])");
    assert_eq!(prepared.fee(), Zatoshis::from_u64(15_000).unwrap());
    assert_eq!(prepared.joint_note().version(), NoteVersion::V3);
    assert!(prepared.joint_note().recipient() == joint.recipient());
    assert_eq!(prepared.joint_note().value().inner(), 35_000);
    assert_eq!(prepared.joint_memo(), joint.memo().as_array());
    let witness = prepared.payout_witness();
    assert_eq!(prepared.effect_id(), witness.effect_id());
    assert_eq!(prepared.joint_action_index(), witness.requested_output_actions()[1]);
    let duplicate = witness.recover_pczt_output(prepared.private_pczt_bytes(), 0).unwrap();
    let selected = witness.recover_pczt_output(prepared.private_pczt_bytes(), 1).unwrap();
    assert!(selected.note() == prepared.joint_note());
    assert_ne!(
        ExtractedNoteCommitment::from(duplicate.note().commitment()).to_bytes(),
        ExtractedNoteCommitment::from(selected.note().commitment()).to_bytes(),
        "identical requested plans must retain distinct generated openings",
    );
    let pczt = Pczt::parse(prepared.private_pczt_bytes()).unwrap();
    assert_eq!(pczt.ironwood().actions().len(), 3);
    assert!(pczt.ironwood().zkproof().is_none());
    assert!(pczt.ironwood().actions().iter().all(|action| action.spend().spend_auth_sig().is_none()));
    assert_eq!(*pczt.global().expiry_height(), 4_134_020);
}

#[test]
fn funding_rejects_unowned_zero_or_misbound_joint_terms_without_changing_amounts() {
    let (input, joint_fvk, source) = fixture();
    let outputs = [
        output(joint_fvk.address_at(0u32, Scope::External), 60_000, b"J"),
        output(input.full_viewing_key().address_at(1u32, Scope::Internal), 30_000, b"change"),
    ];
    let prepare = |source: &SourceParameters, outputs: &[OutputPlan], index, fvk: &FullViewingKey, group| {
        prepare_joint_funding(source, &input, outputs, index, fvk, group,
            &mut ChaCha20Rng::from_seed([75; 32]))
    };
    assert_eq!(prepare(&source, &[], 0, &joint_fvk, group_ak(&joint_fvk)).unwrap_err(),
        FundingError::Source(AuthoringError::MissingOutputs));
    assert_eq!(prepare(&source, &outputs, 2, &joint_fvk, group_ak(&joint_fvk)).unwrap_err(),
        FundingError::Source(AuthoringError::InvalidOutputIndex));
    let mut wrong_group = group_ak(&joint_fvk);
    wrong_group[0] ^= 1;
    assert_eq!(prepare(&source, &outputs, 0, &joint_fvk, wrong_group).unwrap_err(),
        FundingError::GroupMismatch);
    assert_eq!(prepare(&source, &outputs, 0, input.full_viewing_key(), group_ak(input.full_viewing_key())).unwrap_err(),
        FundingError::JointOutputNotOwned);
    assert_eq!(prepare(&source, &outputs, 1, &joint_fvk, group_ak(&joint_fvk)).unwrap_err(),
        FundingError::JointOutputNotOwned);
    let zero_joint = [
        output(joint_fvk.address_at(0u32, Scope::External), 0, b"zero is not J"),
        output(input.full_viewing_key().address_at(1u32, Scope::Internal), 90_000, b"change"),
    ];
    assert_eq!(prepare(&source, &zero_joint, 0, &joint_fvk, group_ak(&joint_fvk)).unwrap_err(),
        FundingError::InvalidJointOutput);
    for amount in [59_999, 60_001] {
        let unbalanced = [output(outputs[0].recipient(), amount, b"J"), outputs[1].clone()];
        assert_eq!(prepare(&source, &unbalanced, 0, &joint_fvk, group_ak(&joint_fvk)).unwrap_err(),
            FundingError::Source(AuthoringError::UnbalancedOutputs));
    }
    let mut custom_fee = source.clone();
    custom_fee.fee_rule = zip317::FeeRule::non_standard(
        Zatoshis::from_u64(6_000).unwrap(), 2,
        zip317::P2PKH_STANDARD_INPUT_SIZE, zip317::P2PKH_STANDARD_OUTPUT_SIZE,
    ).unwrap();
    assert_eq!(prepare(&custom_fee, &outputs, 0, &joint_fvk, group_ak(&joint_fvk)).unwrap_err(),
        FundingError::Source(AuthoringError::UnbalancedOutputs));
    let balanced_custom = [outputs[0].clone(), output(outputs[1].recipient(), 28_000, b"explicit custom-fee change")];
    assert_eq!(prepare(&custom_fee, &balanced_custom, 0, &joint_fvk, group_ak(&joint_fvk)).unwrap().fee(),
        Zatoshis::from_u64(12_000).unwrap());
}

#[test]
fn funding_retains_explicit_zero_output_and_actual_shuffled_joint_index() {
    let (input, joint_fvk, source) = fixture();
    let outputs = [
        output(joint_fvk.address_at(0u32, Scope::External), 60_000, b"J"),
        output(input.full_viewing_key().address_at(1u32, Scope::Internal), 25_000, b"change"),
        output(joint_fvk.address_at(1u32, Scope::External), 0, b"explicit zero memo"),
    ];
    let prepared = (1..=64).find_map(|seed| {
        let prepared = prepare_joint_funding(&source, &input, &outputs, 0, &joint_fvk, group_ak(&joint_fvk),
            &mut ChaCha20Rng::from_seed([seed; 32])).unwrap();
        (prepared.joint_action_index() != 0).then_some(prepared)
    }).expect("deterministic builder shuffle must place J after action zero");
    assert_ne!(prepared.joint_action_index(), 0);
    let zero = prepared.payout_witness().recover_pczt_output(prepared.private_pczt_bytes(), 2).unwrap();
    assert_eq!(zero.value(), 0);
    assert_eq!(zero.memo(), outputs[2].memo().as_array());
    assert_eq!(prepared.payout_witness().requested_output_actions().len(), 3);
    assert_eq!(prepared.fee(), Zatoshis::from_u64(15_000).unwrap());
    assert_eq!(prepared.source_parameters().target_height, source.target_height);
    assert_eq!(prepared.source_parameters().expiry_height, source.expiry_height);
    assert_eq!(prepared.joint_requested_index(), 0);
    assert_eq!(prepared.joint_full_viewing_key().to_bytes(), joint_fvk.to_bytes());
    assert_eq!(prepared.group_ak(), group_ak(&joint_fvk));
    let mapping = prepared.payout_witness().requested_output_actions();
    let facts = ziquid_proofs::native_relation::FundingFacts {
        source: ziquid_proofs::native_relation::SourceFacts { network: source.network,
            target_height: source.target_height, expiry_height: source.expiry_height,
            consensus_branch: source.consensus_branch, fee_rule: &source.fee_rule },
        input: ziquid_proofs::native_relation::OwnedInputFacts { note: input.note(),
            full_viewing_key: input.full_viewing_key(), merkle_path: input.merkle_path(), anchor: input.anchor() },
        private_pczt: prepared.private_pczt_bytes(), requested_output_actions: mapping,
        joint_requested_index: 0, joint_full_viewing_key: &joint_fvk, group_ak: group_ak(&joint_fvk), fee: 15_000,
    };
    let expected = || outputs.iter().map(|output| ziquid_proofs::native_relation::NativeOutputFacts {
        recipient: output.recipient(), value: u64::from(output.value()), memo: Some(output.memo().as_array()),
    });
    let checked = ziquid_proofs::native_relation::verify_funding(&facts, expected(), None).unwrap();
    assert_eq!(checked.input_debit, 100_000);
    assert_eq!(checked.owned_change, 25_000);
    assert_eq!(checked.outputs.len(), 3);
    let wrong_memo = MemoBytes::from_bytes(b"changed requested ZERO memo").unwrap();
    assert!(ziquid_proofs::native_relation::verify_funding(&facts,
        expected().enumerate().map(|(index, mut output)| {
            if index == 2 { output.memo = Some(wrong_memo.as_array()); }
            output
        }), None).is_err());
    assert!(ziquid_proofs::native_relation::verify_funding(&facts, expected().take(2), None).is_err());
}

#[test]
fn funding_refuses_mainnet_invalid_height_branch_and_the_testnet_upgrade_boundary() {
    let (input, joint_fvk, source) = fixture();
    let outputs = [output(joint_fvk.address_at(0u32, Scope::External), 90_000, b"J")];
    let check = |source: &SourceParameters| {
        prepare_joint_funding(source, &input, &outputs, 0, &joint_fvk, group_ak(&joint_fvk),
            &mut ChaCha20Rng::from_seed([76; 32])).unwrap_err()
    };
    let mut changed = source.clone();
    changed.network = Network::MainNetwork;
    assert_eq!(check(&changed), FundingError::TestnetRequired);
    for (target, expiry) in [(0u32, 4_134_020u32), (4_134_000, 0), (4_134_000, 4_133_999), (4_134_000, 500_000_000)] {
        changed = source.clone();
        changed.target_height = target.into();
        changed.expiry_height = expiry.into();
        assert_eq!(check(&changed), FundingError::Source(AuthoringError::InvalidHeight));
    }
    changed = source.clone();
    changed.consensus_branch = BranchId::Nu6_2;
    assert_eq!(check(&changed), FundingError::Source(AuthoringError::WrongBranch));
    changed = source.clone();
    changed.target_height = 4_133_999.into();
    assert_eq!(check(&changed), FundingError::Source(AuthoringError::WrongBranch));
    changed = source.clone();
    changed.expiry_height = 4_465_026.into();
    assert_eq!(check(&changed), FundingError::Source(AuthoringError::WrongBranch));
}
