#![cfg(feature = "native")]

use std::io::{self, Write};

use primitive_types::U256;
use sha2::{Digest, Sha256};
use ziquid_protocol::samechain::{
    Action, Asset, Deployment, FeePolicy, FeeRule, InputDescriptor, OrderPolicy, OutputDescriptor,
    OwnerJournal, PublicPacket, Role, SamechainError, SingleOwnerPacket, owner_relation_version,
    validate_pair, validate_single,
    fill::{
        FILL_RELATION_VERSION, FillExecution, aggregate_commitment, owner_leaf, validate_commitment,
    },
};

// Public shape fixtures only: opaque notes do not establish ownership or backing.
fn packet() -> PublicPacket {
    PublicPacket {
        deployment: Deployment {
            chain_id: 31_337,
            authority: [1; 20],
            authority_code: [2; 32],
            verifier: [3; 20],
            verifier_code: [4; 32],
            owner_program: [5; 32],
            schema: 1,
        },
        inputs: [input(30, 0), input(50, 1)],
        outputs: vec![
            note(Role::A, 80),
            note(Role::B, 90),
            OutputDescriptor::Fee {
                payer: Role::A,
                asset: Asset::Token([7; 20]),
                recipient: [9; 20],
                amount: U256::from(1),
            },
            OutputDescriptor::Exit {
                role: Role::B,
                asset: Asset::Native,
                recipient: [21; 20],
                amount: U256::from(2),
            },
        ],
        expiry: 100,
        terms_commitment: [0; 32],
    }
}

fn input(tag: u8, index: u32) -> InputDescriptor {
    InputDescriptor {
        commitment: [tag; 32],
        root: [19; 32],
        tree_id: 0,
        index,
        order_id: [tag + 2; 32],
        generation: 1,
        nullifier: [tag + 4; 32],
        owner_key: [tag + 6; 32],
    }
}

fn note(role: Role, tag: u8) -> OutputDescriptor {
    OutputDescriptor::Note {
        role,
        commitment: [tag; 32],
        recovery_key_commitment: [tag + 1; 32],
        ciphertext_version: 1,
        ciphertext: vec![tag, tag + 1, tag + 2],
    }
}

fn execution() -> FillExecution {
    FillExecution {
        asset_a: Asset::Native,
        asset_b: Asset::Token([7; 20]),
        sell_a: (U256::from(1) << 255) + U256::from(10),
        sell_b: U256::MAX - U256::from(1),
    }
}

fn policy(role: Role) -> OrderPolicy {
    let (sell_asset, buy_asset) = match role {
        Role::A => (Asset::Native, Asset::Token([7; 20])),
        Role::B => (Asset::Token([7; 20]), Asset::Native),
    };
    OrderPolicy {
        sell_asset,
        buy_asset,
        min_buy_num: U256::from(1),
        min_sell_den: U256::from(3),
        fee_policy: FeePolicy {
            entries: if role == Role::A {
                vec![FeeRule {
                    payer: Role::A,
                    asset: Asset::Token([7; 20]),
                    beneficiary: [9; 20],
                    max_atoms: U256::from(1),
                }]
            } else {
                vec![]
            },
        },
    }
}

fn small_atoms(value: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[31] = value;
    bytes
}

// These oracles never call a production encoder, digest, or commitment helper.
fn manual_execution_body() -> Vec<u8> {
    let mut body = vec![0, 1];
    body.extend_from_slice(&[7; 20]);
    let mut a = [0; 32];
    a[0] = 0x80;
    a[31] = 10;
    body.extend_from_slice(&a);
    let mut b = [0xff; 32];
    b[31] = 0xfe;
    body.extend_from_slice(&b);
    body
}

fn manual_packet_body_without_commitment() -> Vec<u8> {
    let mut body = vec![0, 0, 0, 0, 0, 0, 0x7a, 0x69];
    body.extend_from_slice(&[1; 20]);
    body.extend_from_slice(&[2; 32]);
    body.extend_from_slice(&[3; 20]);
    body.extend_from_slice(&[4; 32]);
    body.extend_from_slice(&[5; 32]);
    body.extend_from_slice(&[0, 1]);
    body.extend_from_slice(&[0, 0, 0, 2]);
    for (tag, index) in [(30, 0), (50, 1)] {
        body.extend_from_slice(&[tag; 32]);
        body.extend_from_slice(&[19; 32]);
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&[0, 0, 0, index]);
        body.extend_from_slice(&[tag + 2; 32]);
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        body.extend_from_slice(&[tag + 4; 32]);
        body.extend_from_slice(&[tag + 6; 32]);
    }
    body.extend_from_slice(&[0, 0, 0, 4]);
    for (role, tag) in [(0, 80), (1, 90)] {
        body.extend_from_slice(&[0, role]);
        body.extend_from_slice(&[tag; 32]);
        body.extend_from_slice(&[tag + 1; 32]);
        body.extend_from_slice(&[0, 1, 0, 0, 0, 3, tag, tag + 1, tag + 2]);
    }
    body.extend_from_slice(&[2, 0, 1]);
    body.extend_from_slice(&[7; 20]);
    body.extend_from_slice(&[9; 20]);
    body.extend_from_slice(&small_atoms(1));
    body.extend_from_slice(&[1, 1, 0]);
    body.extend_from_slice(&[21; 20]);
    body.extend_from_slice(&small_atoms(2));
    body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 100]);
    body
}

fn manual_policy_frame(role: Role) -> Vec<u8> {
    let mut frame = b"Z2Z_SAMECHAIN_ORDER_POLICY\0\0\x01".to_vec();
    match role {
        Role::A => {
            frame.extend_from_slice(&[0, 1]);
            frame.extend_from_slice(&[7; 20]);
        }
        Role::B => {
            frame.push(1);
            frame.extend_from_slice(&[7; 20]);
            frame.push(0);
        }
    }
    frame.extend_from_slice(&small_atoms(1));
    frame.extend_from_slice(&small_atoms(3));
    match role {
        Role::A => {
            frame.extend_from_slice(&[0, 0, 0, 1, 0, 1]);
            frame.extend_from_slice(&[7; 20]);
            frame.extend_from_slice(&[9; 20]);
            frame.extend_from_slice(&small_atoms(1));
        }
        Role::B => frame.extend_from_slice(&[0; 4]),
    }
    frame
}

fn manual_context() -> [u8; 32] {
    let body = manual_packet_body_without_commitment();
    let mut preimage = b"Z2Z_SAMECHAIN_FILL_CONTEXT\0\0\x02\0\x01".to_vec();
    preimage.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    preimage.extend_from_slice(&body);
    preimage.extend_from_slice(&manual_execution_body());
    Sha256::digest(preimage).into()
}

fn manual_leaf(role: Role, salt: &[u8; 32]) -> [u8; 32] {
    let policy = manual_policy_frame(role);
    let mut preimage = b"Z2Z_SAMECHAIN_FILL_OWNER_LEAF\0\0\x02".to_vec();
    preimage.push(role as u8);
    preimage.extend_from_slice(salt);
    preimage.extend_from_slice(&manual_context());
    preimage.extend_from_slice(&u32::try_from(policy.len()).unwrap().to_be_bytes());
    preimage.extend_from_slice(&policy);
    Sha256::digest(preimage).into()
}

fn manual_aggregate(leaves: &[[u8; 32]; 2]) -> [u8; 32] {
    let mut preimage = b"Z2Z_SAMECHAIN_FILL_AGGREGATE\0\0\x02".to_vec();
    preimage.extend_from_slice(&manual_context());
    preimage.extend_from_slice(&leaves[0]);
    preimage.extend_from_slice(&leaves[1]);
    Sha256::digest(preimage).into()
}

fn committed_packet() -> (PublicPacket, [[u8; 32]; 2]) {
    let mut packet = packet();
    let leaves = [manual_leaf(Role::A, &[201; 32]), manual_leaf(Role::B, &[202; 32])];
    packet.terms_commitment = manual_aggregate(&leaves);
    (packet, leaves)
}

#[test]
fn fill2_execution_has_exact_version2_frame_and_full_width_body() {
    let execution = execution();
    let mut expected = b"Z2Z_SAMECHAIN_FILL_EXECUTION\0\0\x02".to_vec();
    expected.extend_from_slice(&manual_execution_body());
    assert_eq!(execution.encode().unwrap(), expected);
    assert_eq!(execution.encoded_len().unwrap(), expected.len());
    let mut streamed = Vec::new();
    execution.encode_into(&mut streamed).unwrap();
    assert_eq!(streamed, expected);
    assert_eq!(FillExecution::decode(&expected).unwrap(), execution);
}

#[test]
fn fill2_execution_rejects_legacy_version_domain_truncation_and_trailing_bytes() {
    let encoded = execution().encode().unwrap();
    for end in 0..encoded.len() {
        assert_eq!(FillExecution::decode(&encoded[..end]), Err(SamechainError::InvalidLength));
    }
    let mut changed = encoded.clone();
    changed[0] ^= 1;
    assert_eq!(FillExecution::decode(&changed), Err(SamechainError::WrongDomain));
    for version in [0_u16, 1, 3] {
        let mut changed = encoded.clone();
        let start = b"Z2Z_SAMECHAIN_FILL_EXECUTION\0".len();
        changed[start..start + 2].copy_from_slice(&version.to_be_bytes());
        assert_eq!(FillExecution::decode(&changed), Err(SamechainError::UnsupportedSchema));
    }
    let mut changed = encoded.clone();
    changed.push(0);
    assert_eq!(FillExecution::decode(&changed), Err(SamechainError::TrailingBytes));
    let mut changed = encoded;
    changed[b"Z2Z_SAMECHAIN_FILL_EXECUTION\0".len() + 2] = 2;
    assert_eq!(FillExecution::decode(&changed), Err(SamechainError::InvalidAsset));
    assert_eq!(FillExecution::decode(&vec![0; 65_537]), Err(SamechainError::Oversize));
}

#[test]
fn fill2_execution_rejects_zero_quantities_and_invalid_or_equal_assets() {
    for role in [Role::A, Role::B] {
        let mut changed = execution();
        match role {
            Role::A => changed.sell_a = U256::zero(),
            Role::B => changed.sell_b = U256::zero(),
        }
        assert_eq!(changed.validate(), Err(SamechainError::InvalidTerms));
        assert_eq!(changed.encode(), Err(SamechainError::InvalidTerms));
        assert_eq!(changed.context_digest(&packet()), Err(SamechainError::InvalidTerms));
    }
    let mut changed = execution();
    changed.asset_b = changed.asset_a;
    assert_eq!(changed.validate(), Err(SamechainError::InvalidTerms));
    for role in [Role::A, Role::B] {
        let mut changed = execution();
        match role {
            Role::A => changed.asset_a = Asset::Token([0; 20]),
            Role::B => changed.asset_b = Asset::Token([0; 20]),
        }
        assert_eq!(changed.validate(), Err(SamechainError::InvalidAsset));
    }
}

#[test]
fn fill2_context_leaf_and_aggregate_match_independent_sha256_preimages() {
    let packet = packet();
    let execution = execution();
    assert_eq!(execution.context_digest(&packet).unwrap(), manual_context());
    let mut leaves = [[0; 32]; 2];
    for (role, salt) in [(Role::A, [201; 32]), (Role::B, [202; 32])] {
        let own_policy = policy(role);
        assert_eq!(own_policy.encode().unwrap(), manual_policy_frame(role));
        leaves[role.index()] = owner_leaf(&packet, &execution, role, &own_policy, &salt).unwrap();
        assert_eq!(leaves[role.index()], manual_leaf(role, &salt));
    }
    assert_ne!(leaves[0], leaves[1]);
    assert_eq!(aggregate_commitment(&packet, &execution, &leaves).unwrap(), manual_aggregate(&leaves));
    assert_eq!(FILL_RELATION_VERSION, owner_relation_version(Action::Fill));
}

#[test]
fn fill2_context_excludes_only_commitment_while_packet_frame_and_digest_include_it() {
    let (packet, leaves) = committed_packet();
    let execution = execution();
    packet.validate().unwrap();
    validate_commitment(&packet, &execution, &leaves).unwrap();
    let mut expected = b"Z2Z_SAMECHAIN_PUBLIC_PACKET\0\0\x01".to_vec();
    expected.extend_from_slice(&manual_packet_body_without_commitment());
    expected.extend_from_slice(&manual_aggregate(&leaves));
    assert_eq!(packet.encode().unwrap(), expected);
    assert_eq!(packet.encoded_len().unwrap(), expected.len());
    let mut streamed = Vec::new();
    packet.encode_into(&mut streamed).unwrap();
    assert_eq!(streamed, expected);
    assert_eq!(PublicPacket::decode(&expected).unwrap(), packet);
    assert_eq!(packet.digest().unwrap(), <[u8; 32]>::from(Sha256::digest(&expected)));
    let mut substituted = packet.clone();
    substituted.terms_commitment = [77; 32];
    assert_eq!(execution.context_digest(&substituted).unwrap(), manual_context());
    assert_ne!(substituted.digest().unwrap(), packet.digest().unwrap());
    assert_eq!(validate_commitment(&substituted, &execution, &leaves), Err(SamechainError::OpeningMismatch));
    substituted.terms_commitment = [0; 32];
    assert_eq!(execution.context_digest(&substituted).unwrap(), manual_context());
    assert_eq!(substituted.validate(), Err(SamechainError::InvalidTerms));
    assert_eq!(validate_commitment(&substituted, &execution, &leaves), Err(SamechainError::InvalidTerms));
}

#[test]
fn fill2_aggregate_is_role_ordered_and_rejects_zero_or_substituted_leaves() {
    let (packet, leaves) = committed_packet();
    let execution = execution();
    let swapped = [leaves[1], leaves[0]];
    assert_ne!(aggregate_commitment(&packet, &execution, &swapped).unwrap(), packet.terms_commitment);
    assert_eq!(validate_commitment(&packet, &execution, &swapped), Err(SamechainError::OpeningMismatch));
    for index in 0..2 {
        let mut changed = leaves;
        changed[index][0] ^= 1;
        assert_eq!(validate_commitment(&packet, &execution, &changed), Err(SamechainError::OpeningMismatch));
        changed[index] = [0; 32];
        assert_eq!(aggregate_commitment(&packet, &execution, &changed), Err(SamechainError::InvalidTerms));
        assert_eq!(validate_commitment(&packet, &execution, &changed), Err(SamechainError::InvalidTerms));
    }
}

#[test]
fn fill2_owner_leaf_binds_only_own_role_policy_and_independent_nonzero_salt() {
    let packet = packet();
    let execution = execution();
    let original = owner_leaf(&packet, &execution, Role::A, &policy(Role::A), &[201; 32]).unwrap();
    assert_eq!(owner_leaf(&packet, &execution, Role::A, &policy(Role::A), &[0; 32]), Err(SamechainError::InvalidBlind));
    assert_ne!(original, owner_leaf(&packet, &execution, Role::A, &policy(Role::A), &[202; 32]).unwrap());
    let mut own_policy = policy(Role::A);
    own_policy.min_buy_num += U256::from(1);
    assert_ne!(original, owner_leaf(&packet, &execution, Role::A, &own_policy, &[201; 32]).unwrap());
    own_policy = policy(Role::A);
    own_policy.fee_policy.entries[0].beneficiary = [10; 20];
    assert_ne!(original, owner_leaf(&packet, &execution, Role::A, &own_policy, &[201; 32]).unwrap());
    assert_eq!(owner_leaf(&packet, &execution, Role::B, &policy(Role::A), &[201; 32]), Err(SamechainError::InvalidFeePolicy));
    own_policy = policy(Role::A);
    own_policy.sell_asset = Asset::Token([8; 20]);
    assert_eq!(owner_leaf(&packet, &execution, Role::A, &own_policy, &[201; 32]), Err(SamechainError::InvalidPolicy));
    own_policy = policy(Role::A);
    own_policy.min_sell_den = U256::zero();
    assert_eq!(owner_leaf(&packet, &execution, Role::A, &own_policy, &[201; 32]), Err(SamechainError::InvalidPolicy));
    let b_with_same_salt = owner_leaf(&packet, &execution, Role::B, &policy(Role::B), &[201; 32]).unwrap();
    assert_ne!(original, b_with_same_salt);
}

#[test]
fn fill2_commitment_rejects_quantity_asset_and_valid_public_body_substitutions() {
    let (packet, leaves) = committed_packet();
    let execution = execution();
    for mutate in [
        (|e: &mut FillExecution| e.sell_a += U256::from(1)) as fn(&mut FillExecution),
        |e| e.sell_b -= U256::from(1),
        |e| e.asset_a = Asset::Token([8; 20]),
        |e| e.asset_b = Asset::Token([8; 20]),
    ] {
        let mut changed = execution;
        mutate(&mut changed);
        changed.validate().unwrap();
        assert_ne!(changed.context_digest(&packet).unwrap(), manual_context());
        assert_eq!(validate_commitment(&packet, &changed, &leaves), Err(SamechainError::OpeningMismatch));
    }
    for mutate in [
        (|p: &mut PublicPacket| p.deployment.verifier_code = [22; 32]) as fn(&mut PublicPacket),
        |p| p.expiry += 1,
        |p| p.inputs.swap(0, 1),
        |p| p.inputs[0].owner_key = [111; 32],
        |p| p.inputs[1].nullifier = [112; 32],
        |p| p.outputs.swap(0, 1),
        |p| if let OutputDescriptor::Note { ciphertext, .. } = &mut p.outputs[0] { ciphertext[0] ^= 1; },
        |p| if let OutputDescriptor::Note { recovery_key_commitment, .. } = &mut p.outputs[0] { *recovery_key_commitment = [113; 32]; },
        |p| if let OutputDescriptor::Note { ciphertext_version, .. } = &mut p.outputs[0] { *ciphertext_version = 2; },
        |p| if let OutputDescriptor::Fee { amount, .. } = &mut p.outputs[2] { *amount += U256::from(1); },
        |p| if let OutputDescriptor::Exit { recipient, .. } = &mut p.outputs[3] { *recipient = [22; 20]; },
    ] {
        let mut changed = packet.clone();
        mutate(&mut changed);
        changed.validate().unwrap();
        assert_ne!(execution.context_digest(&changed).unwrap(), manual_context());
        assert_eq!(validate_commitment(&changed, &execution, &leaves), Err(SamechainError::OpeningMismatch));
    }
}

#[test]
fn fill2_initial_body_validation_preserves_all_public_shape_guards() {
    type PacketMutation = fn(&mut PublicPacket);
    let mutations: &[(PacketMutation, SamechainError)] = &[
        (|p| p.deployment.schema = 2, SamechainError::UnsupportedSchema),
        (|p| p.deployment.authority = [0; 20], SamechainError::InvalidDeployment),
        (|p| p.expiry = 0, SamechainError::InvalidTerms),
        (|p| p.inputs[0].nullifier = [0; 32], SamechainError::InvalidInput),
        (|p| p.inputs[1].commitment = p.inputs[0].commitment, SamechainError::OverlappingInputs),
        (|p| p.inputs[1].nullifier = p.inputs[0].nullifier, SamechainError::OverlappingInputs),
        (|p| p.inputs[1].owner_key = p.inputs[0].owner_key, SamechainError::OverlappingInputs),
        (|p| p.inputs[1].order_id = p.inputs[0].order_id, SamechainError::OverlappingInputs),
        (|p| p.inputs[1].index = p.inputs[0].index, SamechainError::OverlappingInputs),
        (|p| p.outputs.clear(), SamechainError::InvalidOutput),
        (|p| p.outputs.retain(|o| o.role() == Role::A), SamechainError::InvalidOutput),
        (|p| p.outputs.retain(|o| o.role() == Role::B), SamechainError::InvalidOutput),
        (|p| p.outputs[1] = p.outputs[0].clone(), SamechainError::DuplicateOutput),
        (|p| if let OutputDescriptor::Note { commitment, .. } = &mut p.outputs[0] { *commitment = p.inputs[0].commitment; }, SamechainError::DuplicateOutput),
        (|p| if let OutputDescriptor::Note { ciphertext, .. } = &mut p.outputs[0] { *ciphertext = vec![90, 91, 92]; }, SamechainError::DuplicateOutput),
        (|p| if let OutputDescriptor::Note { ciphertext, .. } = &mut p.outputs[0] { ciphertext.clear(); }, SamechainError::InvalidOutput),
        (|p| if let OutputDescriptor::Note { ciphertext, .. } = &mut p.outputs[0] { *ciphertext = vec![1; 4097]; }, SamechainError::Oversize),
        (|p| p.outputs.swap(2, 3), SamechainError::NonCanonical),
        (|p| p.outputs.push(OutputDescriptor::Fee { payer: Role::B, asset: Asset::Native, recipient: [21; 20], amount: U256::from(3) }), SamechainError::DuplicateOutput),
    ];
    let execution = execution();
    let leaves = [manual_leaf(Role::A, &[201; 32]), manual_leaf(Role::B, &[202; 32])];
    for (mutate, expected) in mutations {
        let mut changed = packet();
        mutate(&mut changed);
        assert_eq!(execution.context_digest(&changed), Err(*expected));
        assert_eq!(aggregate_commitment(&changed, &execution, &leaves), Err(*expected));
        assert_eq!(owner_leaf(&changed, &execution, Role::A, &policy(Role::A), &[201; 32]), Err(*expected));
    }
    let mut bounded = packet();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut bounded.outputs[0] {
        *ciphertext = vec![1; 4096];
    }
    for tag in 100..104 { bounded.outputs.push(note(Role::A, tag)); }
    execution.context_digest(&bounded).unwrap();
    bounded.outputs.push(note(Role::B, 104));
    assert_eq!(execution.context_digest(&bounded), Err(SamechainError::Oversize));
}

#[test]
fn fill2_context_length_prefix_prevents_ciphertext_partition_collisions() {
    let execution = execution();
    let mut first = packet();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut first.outputs[0] { *ciphertext = vec![1]; }
    if let OutputDescriptor::Note { ciphertext, .. } = &mut first.outputs[1] { *ciphertext = vec![2, 3]; }
    let mut second = first.clone();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut second.outputs[0] { *ciphertext = vec![1, 2]; }
    if let OutputDescriptor::Note { ciphertext, .. } = &mut second.outputs[1] { *ciphertext = vec![3]; }
    assert_ne!(execution.context_digest(&first).unwrap(), execution.context_digest(&second).unwrap());
    assert_ne!(owner_leaf(&first, &execution, Role::A, &policy(Role::A), &[201; 32]).unwrap(),
        owner_leaf(&second, &execution, Role::A, &policy(Role::A), &[201; 32]).unwrap());
}

#[test]
fn fill2_journals_use_relation2_but_preserve_outer_frame1_and_single_relation1() {
    let (packet, _) = committed_packet();
    let a = OwnerJournal::from_packet(&packet, Role::A, Action::Fill).unwrap();
    let b = OwnerJournal::from_packet(&packet, Role::B, Action::Fill).unwrap();
    validate_pair(&packet, &a, &b).unwrap();
    for journal in [a, b] {
        assert_eq!(journal.relation_version, 2);
        let encoded = journal.encode().unwrap();
        let header = b"Z2Z_SAMECHAIN_OWNER_JOURNAL\0\0\x01";
        assert_eq!(&encoded[..header.len()], header);
        assert_eq!(&encoded[header.len()..header.len() + 2], &[0, 2]);
        assert_eq!(encoded.len(), header.len() + 244);
        assert_eq!(OwnerJournal::decode(&encoded).unwrap(), journal);
        let mut old_relation = encoded;
        old_relation[header.len()..header.len() + 2].copy_from_slice(&[0, 1]);
        assert_eq!(OwnerJournal::decode(&old_relation), Err(SamechainError::UnsupportedSchema));
    }
    let mut old_a = a;
    old_a.relation_version = 1;
    assert_eq!(validate_pair(&packet, &old_a, &b), Err(SamechainError::UnsupportedSchema));
    assert_eq!(validate_pair(&packet, &b, &a), Err(SamechainError::JournalMismatch));
    let single = SingleOwnerPacket {
        deployment: packet.deployment,
        input: packet.inputs[0],
        outputs: vec![packet.outputs[0].clone()],
        expiry: packet.expiry,
        terms_commitment: [203; 32],
    };
    for action in [Action::Cancel, Action::Exit] {
        assert_eq!(owner_relation_version(action), 1);
        let journal = OwnerJournal::from_single_packet(&single, Role::A, action).unwrap();
        assert_eq!(journal.relation_version, 1);
        validate_single(&single, &journal, Role::A, action).unwrap();
        let encoded = journal.encode().unwrap();
        let start = b"Z2Z_SAMECHAIN_OWNER_JOURNAL\0".len();
        assert_eq!(&encoded[start..start + 4], &[0, 1, 0, 1]);
        assert_eq!(OwnerJournal::decode(&encoded).unwrap(), journal);
        let mut wrong_relation = journal;
        wrong_relation.relation_version = 2;
        assert_eq!(wrong_relation.validate(), Err(SamechainError::UnsupportedSchema));
        assert_eq!(validate_single(&single, &wrong_relation, Role::A, action), Err(SamechainError::UnsupportedSchema));
    }
}

#[test]
fn fill2_borrowed_writers_validate_before_writing_and_propagate_io_errors() {
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::Error::other("test sink")) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let (packet, _) = committed_packet();
    assert_eq!(packet.encode_into(&mut FailingWriter), Err(SamechainError::Encoding));
    assert_eq!(execution().encode_into(&mut FailingWriter), Err(SamechainError::Encoding));
    let mut invalid = packet;
    invalid.terms_commitment = [0; 32];
    let mut bytes = Vec::new();
    assert_eq!(invalid.encoded_len(), Err(SamechainError::InvalidTerms));
    assert_eq!(invalid.encode_into(&mut bytes), Err(SamechainError::InvalidTerms));
    assert!(bytes.is_empty());
    let mut invalid = execution();
    invalid.sell_a = U256::zero();
    assert_eq!(invalid.encoded_len(), Err(SamechainError::InvalidTerms));
    assert_eq!(invalid.encode_into(&mut bytes), Err(SamechainError::InvalidTerms));
    assert!(bytes.is_empty());
}
