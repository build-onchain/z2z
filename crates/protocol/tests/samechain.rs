use primitive_types::U256;
use sha2::{Digest, Sha256};
use ziquid_protocol::samechain::{
    Action, Asset, Deployment, FeePolicy, FeeRule, InputDescriptor, OrderPolicy, OutputDescriptor,
    OwnerJournal, PublicPacket, Role, SamechainError, SingleOwnerPacket, single_terms_commitment,
    validate_pair, validate_single,
};

fn deployment() -> Deployment {
    Deployment { chain_id: 31_337, authority: [1; 20], authority_code: [2; 32],
        verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 }
}

fn input(tag: u8, index: u32) -> InputDescriptor {
    InputDescriptor { commitment: [tag; 32], root: [19; 32], tree_id: 0, index,
        order_id: [tag + 2; 32], generation: 1, nullifier: [tag + 4; 32], owner_key: [tag + 6; 32] }
}

fn note(role: Role, tag: u8) -> OutputDescriptor {
    OutputDescriptor::Note { role, commitment: [tag; 32], recovery_key_commitment: [tag + 1; 32],
        ciphertext_version: 1, ciphertext: vec![tag, tag + 1, tag + 2] }
}

fn fee(role: Role, asset: Asset, recipient: u8, amount: U256) -> OutputDescriptor {
    OutputDescriptor::Fee { payer: role, asset, recipient: [recipient; 20], amount }
}

fn fee_policy(role: Role, asset: Asset, cap: U256) -> FeePolicy {
    FeePolicy { entries: vec![FeeRule { payer: role, asset, beneficiary: [9; 20], max_atoms: cap }] }
}

fn policy() -> OrderPolicy {
    OrderPolicy { sell_asset: Asset::Native, buy_asset: Asset::Token([7; 20]),
        min_buy_num: U256::from(1), min_sell_den: U256::from(3),
        fee_policy: fee_policy(Role::A, Asset::Token([7; 20]), U256::from(1)) }
}

// Opaque commitments are public shape fixtures, not authenticated leaf openings.
fn packet() -> PublicPacket {
    PublicPacket { deployment: deployment(), inputs: [input(30, 0), input(50, 1)],
        outputs: vec![note(Role::A, 80), note(Role::B, 90)], expiry: 100,
        terms_commitment: [201; 32] }
}

#[test]
fn exact_fee_policy_rejects_overcap_and_substituted_beneficiary() {
    let x = Asset::Native;
    let y = Asset::Token([7; 20]);
    let policy = fee_policy(Role::A, y, U256::from(1));
    policy.validate_for(Role::A, x, y).unwrap();
    assert!(policy.check_fee(Role::A, y, [9; 20], U256::from(1)).is_ok());
    for (role, asset, recipient, amount) in [
        (Role::A, y, [9; 20], U256::from(2)),
        (Role::A, y, [8; 20], U256::from(1)),
        (Role::B, y, [9; 20], U256::from(1)),
        (Role::A, x, [9; 20], U256::from(1)),
    ] { assert!(policy.check_fee(role, asset, recipient, amount).is_err()); }
}

#[test]
fn split_fee_is_aggregated_before_duplicate_payment_rejection() {
    let policy = fee_policy(Role::A, Asset::Native, U256::from(1));
    let outputs = vec![fee(Role::A, Asset::Native, 9, U256::from(1)),
        fee(Role::A, Asset::Native, 9, U256::from(1))];
    assert_eq!(policy.validate_fees(Role::A, &outputs), Err(SamechainError::FeeCapExceeded));
    let policy = fee_policy(Role::A, Asset::Native, U256::from(2));
    assert_eq!(policy.validate_fees(Role::A, &outputs), Err(SamechainError::DuplicateOutput));
}

#[test]
fn fee_aggregation_never_wraps_at_256_bits() {
    let policy = fee_policy(Role::A, Asset::Native, U256::MAX);
    let outputs = vec![fee(Role::A, Asset::Native, 9, U256::MAX),
        fee(Role::A, Asset::Native, 9, U256::from(1))];
    assert_eq!(policy.validate_fees(Role::A, &outputs), Err(SamechainError::FeeCapExceeded));
    policy.validate_fees(Role::A, &outputs[..1]).unwrap();
}

#[test]
fn fee_policy_is_an_opened_bounded_canonical_allowlist() {
    let mut policy = fee_policy(Role::A, Asset::Native, U256::from(1));
    assert_eq!(FeePolicy::decode(&policy.encode().unwrap()).unwrap(), policy);
    let original = policy.commitment().unwrap();
    policy.entries[0].beneficiary = [10; 20];
    assert_ne!(original, policy.commitment().unwrap());
    assert!(policy.check_fee(Role::A, Asset::Native, [9; 20], U256::from(1)).is_err());
    policy.entries.push(policy.entries[0]);
    assert_eq!(policy.validate(), Err(SamechainError::NonCanonical));
    policy.entries[1].beneficiary = [8; 20];
    assert_eq!(policy.validate(), Err(SamechainError::NonCanonical));
    policy.entries.clear();
    for recipient in 1..=4 {
        policy.entries.push(FeeRule { payer: Role::A, asset: Asset::Native,
            beneficiary: [recipient; 20], max_atoms: U256::MAX });
    }
    policy.validate_for(Role::A, Asset::Native, Asset::Token([7; 20])).unwrap();
    policy.entries.push(FeeRule { payer: Role::A, asset: Asset::Native,
        beneficiary: [5; 20], max_atoms: U256::MAX });
    assert_eq!(policy.validate(), Err(SamechainError::Oversize));
}

#[test]
fn fee_and_exit_cannot_count_the_same_external_payment_twice() {
    let mut packet = packet();
    packet.outputs.push(fee(Role::A, Asset::Token([7; 20]), 9, U256::from(1)));
    packet.outputs.push(OutputDescriptor::Exit { role: Role::A, asset: Asset::Token([7; 20]),
        recipient: [9; 20], amount: U256::from(2) });
    assert_eq!(packet.validate(), Err(SamechainError::DuplicateOutput));
}

#[test]
fn policies_require_distinct_assets_positive_limits_and_role_fee_allowlists() {
    let original = policy();
    original.validate_for(Role::A).unwrap();
    let mut changed = original.clone(); changed.min_buy_num = U256::zero();
    assert_eq!(changed.validate(), Err(SamechainError::InvalidPolicy));
    let mut changed = original.clone(); changed.min_sell_den = U256::zero();
    assert_eq!(changed.validate(), Err(SamechainError::InvalidPolicy));
    let mut changed = original.clone(); changed.buy_asset = changed.sell_asset;
    assert_eq!(changed.validate(), Err(SamechainError::InvalidPolicy));
    let mut changed = original.clone(); changed.fee_policy.entries[0].asset = Asset::Token([8; 20]);
    assert_eq!(changed.validate(), Err(SamechainError::InvalidPolicy));
    let mut changed = original; changed.fee_policy.entries[0].payer = Role::B;
    assert_eq!(changed.validate_for(Role::A), Err(SamechainError::InvalidFeePolicy));
}

#[test]
fn packets_reject_overlapping_inputs_but_allow_shared_membership_roots() {
    let packet = packet();
    packet.validate().unwrap();
    let mut attacks = Vec::new();
    let mut a = packet.clone(); a.inputs[1].commitment = a.inputs[0].commitment; attacks.push(a);
    let mut a = packet.clone(); a.inputs[1].nullifier = a.inputs[0].nullifier; attacks.push(a);
    let mut a = packet.clone(); a.inputs[1].owner_key = a.inputs[0].owner_key; attacks.push(a);
    let mut a = packet.clone(); a.inputs[1].order_id = a.inputs[0].order_id; attacks.push(a);
    let mut a = packet.clone(); a.inputs[1].index = a.inputs[0].index; attacks.push(a);
    for attack in attacks { assert_eq!(attack.validate(), Err(SamechainError::OverlappingInputs)); }
    let mut other_tree = packet;
    other_tree.inputs[1].tree_id = 1;
    other_tree.inputs[1].index = other_tree.inputs[0].index;
    other_tree.validate().unwrap();
}

#[test]
fn input_generation_root_owner_and_nullifier_are_required() {
    let base = input(30, 0);
    let mut attacks = Vec::new();
    let mut a = base; a.commitment = [0; 32]; attacks.push(a);
    let mut a = base; a.root = [0; 32]; attacks.push(a);
    let mut a = base; a.order_id = [0; 32]; attacks.push(a);
    let mut a = base; a.owner_key = [0; 32]; attacks.push(a);
    let mut a = base; a.nullifier = [0; 32]; attacks.push(a);
    let mut a = base; a.generation = 0; attacks.push(a);
    for attack in attacks { assert_eq!(attack.validate(), Err(SamechainError::InvalidInput)); }
    assert_eq!(InputDescriptor::decode(&base.encode().unwrap()).unwrap(), base);
}

#[test]
fn outputs_reject_reused_commitments_ciphertexts_and_input_commitments() {
    let mut p = packet(); p.outputs.push(p.outputs[0].clone());
    assert_eq!(p.validate(), Err(SamechainError::DuplicateOutput));
    let mut p = packet();
    if let OutputDescriptor::Note { commitment, .. } = &mut p.outputs[0] { *commitment = p.inputs[0].commitment; }
    assert_eq!(p.validate(), Err(SamechainError::DuplicateOutput));
    let mut p = packet();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut p.outputs[1] { *ciphertext = vec![80, 81, 82]; }
    assert_eq!(p.validate(), Err(SamechainError::DuplicateOutput));
}

#[test]
fn descriptors_and_manifests_are_bounded_before_encoding_or_allocation() {
    let mut p = packet();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut p.outputs[0] { *ciphertext = vec![1; 4096]; }
    p.validate().unwrap();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut p.outputs[0] { ciphertext.push(1); }
    assert_eq!(p.validate(), Err(SamechainError::Oversize));
    let mut p = packet();
    for tag in 100..106 { p.outputs.push(note(Role::A, tag)); }
    p.validate().unwrap();
    p.outputs.push(note(Role::B, 120));
    assert_eq!(p.validate(), Err(SamechainError::Oversize));
    assert_eq!(PublicPacket::decode(&vec![0; 65_537]), Err(SamechainError::Oversize));
    let mut encoded = note(Role::A, 80).encode().unwrap();
    let offset = b"Z2Z_SAMECHAIN_OUTPUT\0".len() + 2 + 1 + 1 + 32 + 32 + 2;
    encoded[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(OutputDescriptor::decode(&encoded), Err(SamechainError::Oversize));
}

#[test]
fn packet_digest_binds_ciphertext_version_recovery_key_owner_and_expiry() {
    let packet = packet();
    let digest = packet.digest().unwrap();
    let mut attacks = Vec::new();
    let mut a = packet.clone(); a.expiry += 1; attacks.push(a);
    let mut a = packet.clone(); a.inputs[0].owner_key = [111; 32]; attacks.push(a);
    let mut a = packet.clone(); a.terms_commitment = [112; 32]; attacks.push(a);
    let mut a = packet.clone(); a.outputs.swap(0, 1); attacks.push(a);
    let mut a = packet.clone();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut a.outputs[0] { ciphertext[0] ^= 1; }
    attacks.push(a);
    let mut a = packet.clone();
    if let OutputDescriptor::Note { ciphertext_version, .. } = &mut a.outputs[0] { *ciphertext_version = 2; }
    attacks.push(a);
    let mut a = packet.clone();
    if let OutputDescriptor::Note { recovery_key_commitment, .. } = &mut a.outputs[0] { *recovery_key_commitment = [113; 32]; }
    attacks.push(a);
    for attack in attacks { assert_ne!(digest, attack.digest().unwrap()); }
}

#[test]
fn packet_decode_rejects_trailing_unknown_role_asset_schema_and_truncation() {
    let packet = packet();
    let encoded = packet.encode().unwrap();
    assert_eq!(PublicPacket::decode(&encoded).unwrap(), packet);
    assert_eq!(packet.digest().unwrap(), <[u8; 32]>::from(Sha256::digest(&encoded)));
    for end in 0..encoded.len() { assert!(PublicPacket::decode(&encoded[..end]).is_err()); }
    let mut trailing = encoded.clone(); trailing.push(0);
    assert_eq!(PublicPacket::decode(&trailing), Err(SamechainError::TrailingBytes));
    let mut schema = encoded;
    let offset = b"Z2Z_SAMECHAIN_PUBLIC_PACKET\0".len();
    schema[offset..offset + 2].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(PublicPacket::decode(&schema), Err(SamechainError::UnsupportedSchema));
    let mut descriptor = note(Role::A, 80).encode().unwrap();
    let offset = b"Z2Z_SAMECHAIN_OUTPUT\0".len() + 2;
    descriptor[offset] = 3;
    assert_eq!(OutputDescriptor::decode(&descriptor), Err(SamechainError::InvalidOutput));
    descriptor[offset] = 0; descriptor[offset + 1] = 2;
    assert_eq!(OutputDescriptor::decode(&descriptor), Err(SamechainError::InvalidRole));
    let mut asset = Asset::Native.encode().unwrap();
    asset[b"Z2Z_SAMECHAIN_ASSET\0".len() + 2] = 2;
    assert_eq!(Asset::decode(&asset), Err(SamechainError::InvalidAsset));
    assert_eq!(Asset::Token([0; 20]).encode(), Err(SamechainError::InvalidAsset));
}

#[test]
fn pair_binds_complete_manifest_deployment_commitment_and_each_input_field() {
    let packet = packet();
    let a = OwnerJournal::from_packet(&packet, Role::A, Action::Fill).unwrap();
    let b = OwnerJournal::from_packet(&packet, Role::B, Action::Fill).unwrap();
    validate_pair(&packet, &a, &b).unwrap();
    assert_eq!(OwnerJournal::decode(&a.encode().unwrap()).unwrap(), a);
    assert!(validate_pair(&packet, &b, &a).is_err());
    assert!(validate_pair(&packet, &a, &a).is_err());
    let mut attacks = Vec::new();
    let mut j = a; j.deployment_digest = [2; 32]; attacks.push(j);
    let mut j = a; j.terms_commitment = [3; 32]; attacks.push(j);
    let mut j = a; j.packet_digest = [4; 32]; attacks.push(j);
    let mut j = a; j.input_nullifier = [5; 32]; attacks.push(j);
    let mut j = a; j.input_commitment = [6; 32]; attacks.push(j);
    let mut j = a; j.root = [7; 32]; attacks.push(j);
    let mut j = a; j.tree_id += 1; attacks.push(j);
    let mut j = a; j.index += 1; attacks.push(j);
    let mut j = a; j.order_id = [8; 32]; attacks.push(j);
    let mut j = a; j.generation += 1; attacks.push(j);
    let mut j = a; j.action = Action::Cancel; attacks.push(j);
    let mut j = a; j.relation_version = 1; attacks.push(j);
    for attack in attacks { assert!(validate_pair(&packet, &attack, &b).is_err()); }
    let mut replay = packet.clone(); replay.expiry += 1;
    assert!(validate_pair(&replay, &a, &b).is_err());
    let mut replay = packet.clone(); replay.outputs.swap(0, 1);
    assert!(validate_pair(&replay, &a, &b).is_err());
    let mut replay = packet; replay.deployment.verifier_code = [22; 32];
    assert!(validate_pair(&replay, &a, &b).is_err());
    let mut trailing = a.encode().unwrap(); trailing.push(0);
    assert_eq!(OwnerJournal::decode(&trailing), Err(SamechainError::TrailingBytes));
}

#[test]
fn single_owner_packet_has_one_real_input_and_a_separate_action_domain() {
    let pair = packet();
    let mut single = SingleOwnerPacket { deployment: pair.deployment, input: pair.inputs[0],
        outputs: vec![pair.outputs[0].clone()], expiry: pair.expiry, terms_commitment: pair.terms_commitment };
    single.validate_for(Role::A).unwrap();
    assert_eq!(SingleOwnerPacket::decode(&single.encode().unwrap()).unwrap(), single);
    assert!(PublicPacket::decode(&single.encode().unwrap()).is_err());
    assert!(SingleOwnerPacket::decode(&pair.encode().unwrap()).is_err());
    assert!(OwnerJournal::from_single_packet(&single, Role::A, Action::Fill).is_err());
    assert!(OwnerJournal::from_packet(&pair, Role::A, Action::Cancel).is_err());
    let cancel = OwnerJournal::from_single_packet(&single, Role::A, Action::Cancel).unwrap();
    let exit = OwnerJournal::from_single_packet(&single, Role::A, Action::Exit).unwrap();
    assert_eq!(cancel.input_nullifier, exit.input_nullifier);
    assert_ne!(cancel.encode().unwrap(), exit.encode().unwrap());
    validate_single(&single, &cancel, Role::A, Action::Cancel).unwrap();
    assert!(validate_single(&single, &cancel, Role::A, Action::Exit).is_err());
    assert!(validate_single(&single, &cancel, Role::B, Action::Cancel).is_err());
    single.outputs.push(note(Role::B, 90)); assert!(single.validate_for(Role::A).is_err());
    single.outputs.clear(); assert!(single.validate_for(Role::A).is_err());
}

#[test]
fn single_journal_cannot_replay_a_changed_recipient_or_generation() {
    let mut packet = SingleOwnerPacket { deployment: deployment(), input: input(30, 0),
        outputs: vec![OutputDescriptor::Exit { role: Role::A, asset: Asset::Native,
            recipient: [21; 20], amount: U256::from(10) }], expiry: 100, terms_commitment: [201; 32] };
    let journal = OwnerJournal::from_single_packet(&packet, Role::A, Action::Exit).unwrap();
    validate_single(&packet, &journal, Role::A, Action::Exit).unwrap();
    let mut recipient = packet.clone();
    if let OutputDescriptor::Exit { recipient, .. } = &mut recipient.outputs[0] { *recipient = [22; 20]; }
    assert!(validate_single(&recipient, &journal, Role::A, Action::Exit).is_err());
    packet.input.generation += 1;
    assert!(validate_single(&packet, &journal, Role::A, Action::Exit).is_err());
}

#[test]
fn deployment_codec_matches_independent_big_endian_frame() {
    let descriptor = deployment();
    let mut expected = b"Z2Z_SAMECHAIN_DEPLOYMENT\0\0\x01".to_vec();
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x7a, 0x69]);
    expected.extend_from_slice(&[1; 20]); expected.extend_from_slice(&[2; 32]);
    expected.extend_from_slice(&[3; 20]); expected.extend_from_slice(&[4; 32]);
    expected.extend_from_slice(&[5; 32]); expected.extend_from_slice(&[0, 1]);
    assert_eq!(descriptor.encode().unwrap(), expected);
    assert_eq!(Deployment::decode(&expected).unwrap(), descriptor);
    assert_eq!(descriptor.digest().unwrap(), <[u8; 32]>::from(Sha256::digest(&expected)));
    let mut wrong_identity = descriptor; wrong_identity.owner_program = [0; 32];
    assert!(wrong_identity.encode().is_err());
    let mut trailing = expected; trailing.push(0);
    assert_eq!(Deployment::decode(&trailing), Err(SamechainError::TrailingBytes));
}

#[test]
fn opened_policy_and_rule_codecs_reject_hash_only_or_trailing_inputs() {
    let policy = policy();
    let wire = policy.encode().unwrap();
    assert_eq!(OrderPolicy::decode(&wire).unwrap(), policy);
    let rule = policy.fee_policy.entries[0];
    let wire = rule.encode().unwrap();
    assert_eq!(FeeRule::decode(&wire).unwrap(), rule);
    let mut trailing = wire; trailing.push(0);
    assert_eq!(FeeRule::decode(&trailing), Err(SamechainError::TrailingBytes));
    assert!(FeePolicy::decode(&policy.fee_policy.commitment().unwrap()).is_err());
    let wire = policy.fee_policy.encode().unwrap();
    for len in 0..wire.len() { assert!(FeePolicy::decode(&wire[..len]).is_err()); }
}

#[test]
fn owner_private_policy_and_fee_caps_have_explicit_erasure() {
    use zeroize::Zeroize;
    let mut private = policy(); private.zeroize();
    assert_eq!(private.min_buy_num, U256::zero());
    assert_eq!(private.min_sell_den, U256::zero());
    for fee in &private.fee_policy.entries {
        assert_eq!(fee.max_atoms, U256::zero()); assert_eq!(fee.beneficiary, [0; 20]);
    }
}

#[test]
fn journal_canonical_decode_rejects_unknown_action_and_public_input_count() {
    let packet = packet();
    let journal = OwnerJournal::from_packet(&packet, Role::A, Action::Fill).unwrap();
    let mut wire = journal.encode().unwrap();
    wire[b"Z2Z_SAMECHAIN_OWNER_JOURNAL\0".len() + 2 + 2] = 3;
    assert_eq!(OwnerJournal::decode(&wire), Err(SamechainError::InvalidAction));
    let mut wire = packet.encode().unwrap();
    let offset = b"Z2Z_SAMECHAIN_PUBLIC_PACKET\0".len() + 2 + 146;
    wire[offset..offset + 4].copy_from_slice(&1_u32.to_be_bytes());
    assert_eq!(PublicPacket::decode(&wire), Err(SamechainError::InvalidLength));
}

#[test]
fn external_payments_are_canonically_sorted_without_reordering_notes() {
    let mut p = packet();
    for recipient in [21, 22] {
        p.outputs.push(OutputDescriptor::Exit { role: Role::A, asset: Asset::Native,
            recipient: [recipient; 20], amount: U256::from(1) });
    }
    p.validate().unwrap(); p.outputs.swap(0, 1); p.validate().unwrap();
    p.outputs.swap(2, 3); assert_eq!(p.validate(), Err(SamechainError::NonCanonical));
}

#[test]
fn single_terms_opening_commits_all_real_fields_without_hashing_itself() {
    let pair = packet();
    let mut packet = SingleOwnerPacket { deployment: pair.deployment, input: pair.inputs[0],
        outputs: vec![pair.outputs[0].clone()], expiry: pair.expiry, terms_commitment: [0; 32] };
    packet.terms_commitment = single_terms_commitment(&packet.deployment, &packet.input,
        &packet.outputs, packet.expiry, &[202; 32]).unwrap();
    packet.validate_commitment(&[202; 32]).unwrap();
    assert_eq!(packet.validate_commitment(&[203; 32]), Err(SamechainError::OpeningMismatch));
    assert_eq!(single_terms_commitment(&packet.deployment, &packet.input, &packet.outputs,
        packet.expiry, &[0; 32]), Err(SamechainError::InvalidBlind));
    let wire = packet.encode().unwrap();
    let body_start = b"Z2Z_SAMECHAIN_SINGLE_PACKET\0".len() + 2;
    let mut expected = Sha256::new();
    expected.update(b"Z2Z_SAMECHAIN_SINGLE_TERMS_COMMITMENT\0");
    expected.update(1_u16.to_be_bytes()); expected.update([202; 32]);
    expected.update(&wire[body_start..wire.len() - 32]);
    assert_eq!(packet.terms_commitment, <[u8; 32]>::from(expected.finalize()));
    packet.input.generation += 1;
    assert_eq!(packet.validate_commitment(&[202; 32]), Err(SamechainError::OpeningMismatch));
}
