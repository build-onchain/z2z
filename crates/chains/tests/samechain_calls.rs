use primitive_types::U256;
use serde_json::Value;
use ziquid_chains::samechain::{
    build_creation_call, build_fill_call, build_single_call, build_withdrawal_call,
    CallBuildError, UnsignedCall,
};
use ziquid_protocol::samechain::{
    creation::NoteCreationPacket, withdrawal::NoteWithdrawalPacket, Action, Asset,
    Deployment, OutputDescriptor, PublicPacket, Role, SingleOwnerPacket,
    MAX_CIPHERTEXT_BYTES,
};

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value.as_bytes().as_chunks::<2>().0.iter().map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

fn vectors() -> Vec<Value> {
    let value: Value = serde_json::from_str(include_str!(
        "../../../contracts/evm/test/fixtures/samechain-native-vectors.json"
    )).unwrap();
    let fill2: Value = serde_json::from_str(include_str!(
        "../../../contracts/evm/test/fixtures/samechain-fill2-vectors.json"
    )).unwrap();
    let mut packets = value["packets"].as_array().unwrap().clone();
    for replacement in fill2["packets"].as_array().unwrap() {
        assert_eq!(replacement["kind"], "Fill");
        let original = packets.iter_mut().find(|packet| packet["name"] == replacement["name"]).unwrap();
        assert_eq!(original["kind"], "Fill");
        *original = replacement.clone();
    }
    packets
}

#[test]
fn generated_fill2_overlay_binds_execution_leaves_and_preserves_public_body() {
    use ziquid_protocol::samechain::{OwnerJournal, fill::{FillExecution, validate_commitment}};
    let value = vector("known_pair");
    let raw = field(&value, "packethex");
    let packet = PublicPacket::decode(&raw).unwrap();
    let execution = FillExecution::decode(&field(&value, "executionhex")).unwrap();
    let leaves = [field(&value, "leafhexA").try_into().unwrap(),
        field(&value, "leafhexB").try_into().unwrap()];
    validate_commitment(&packet, &execution, &leaves).unwrap();
    let old: Value = serde_json::from_str(include_str!(
        "../../../contracts/evm/test/fixtures/samechain-native-vectors.json"
    )).unwrap();
    let old = old["packets"].as_array().unwrap().iter()
        .find(|record| record["name"] == "known_pair").unwrap();
    let old_raw = field(old, "packethex");
    assert_eq!(&raw[..raw.len() - 32], &old_raw[..old_raw.len() - 32]);
    assert_ne!(&raw[raw.len() - 32..], &old_raw[old_raw.len() - 32..]);
    for key in ["journalhexA", "journalhexB"] {
        let journal = field(&value, key);
        assert_eq!(journal.len(), 274);
        assert_eq!(&journal[28..32], &[0, 1, 0, 2]);
        assert_eq!(OwnerJournal::decode(&journal).unwrap().relation_version, 2);
    }
    for name in ["single_cancel", "single_exit"] {
        let journal = field(&vector(name), "journalhex");
        assert_eq!(&journal[28..32], &[0, 1, 0, 1]);
        assert_eq!(OwnerJournal::decode(&journal).unwrap().relation_version, 1);
    }
}

fn vector(name: &str) -> Value {
    vectors().into_iter().find(|value| value["name"] == name).unwrap()
}

fn field(value: &Value, name: &str) -> Vec<u8> {
    hex(value[name].as_str().unwrap())
}

// Correct public framing, deliberately invalid infinite pairing points. This
// test input is NOT a certificate or a successful financial execution fixture.
fn unverified_frame() -> Vec<u8> {
    let mut frame = vec![0; 356];
    frame[..4].copy_from_slice(&hex("4388a21c"));
    frame[36..68].copy_from_slice(&hex(
        "002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352"
    ));
    frame
}

fn word(value: usize) -> Vec<u8> {
    let mut result = vec![0; 32];
    result[24..].copy_from_slice(&(value as u64).to_be_bytes());
    result
}

// Independent ABI oracle: materialize each separate tail, then combine the
// literal compiler selector and complete heads. Production streams one buffer.
fn abi(selector: &str, args: &[Option<&[u8]>], role_action: Option<(u8, u8)>) -> Vec<u8> {
    let tails: Vec<Vec<u8>> = args.iter().filter_map(|arg| arg.map(|bytes| {
        let mut tail = word(bytes.len());
        tail.extend_from_slice(bytes);
        while !tail.len().is_multiple_of(32) { tail.push(0); }
        tail
    })).collect();
    let mut result = hex(selector);
    let mut offset = args.len() * 32;
    let mut tail_index = 0;
    for (index, arg) in args.iter().enumerate() {
        if arg.is_some() {
            result.extend(word(offset));
            offset += tails[tail_index].len();
            tail_index += 1;
        } else {
            let (role, action) = role_action.unwrap();
            result.extend(word(if index == 1 { role } else { action } as usize));
        }
    }
    for tail in tails { result.extend(tail); }
    result
}

fn assert_error(result: Result<UnsignedCall, CallBuildError>, expected: CallBuildError) {
    assert_eq!(result.unwrap_err(), expected);
}

#[test]
fn all_actual_public_vectors_bind_full_journals_and_independent_abi_bytes() {
    let proof = unverified_frame();
    let sender = [0x42; 20];
    for value in vectors() {
        let raw = field(&value, "packethex");
        let deployment = Deployment::decode(&field(&value, "deploymenthex")).unwrap();
        let kind = value["kind"].as_str().unwrap();
        let (call, expected_data, expected_outputs) = match kind {
            "Creation" => {
                let packet = NoteCreationPacket::decode(&raw).unwrap();
                let call = build_creation_call(&deployment, packet.token, &packet, &proof).unwrap();
                assert_eq!(call.from(), packet.payer);
                assert_eq!(call.value(), if packet.asset == Asset::Native { packet.amount } else { U256::zero() });
                (call, abi("94184ba9", &[Some(&raw), Some(&proof)], None), vec![packet.output])
            }
            "Fill" => {
                let packet = PublicPacket::decode(&raw).unwrap();
                let call = build_fill_call(&deployment, &packet, sender, &proof, &proof).unwrap();
                assert_eq!(call.expected_journals(), &[
                    field(&value, "journalhexA"), field(&value, "journalhexB")
                ]);
                (call, abi("d316bd1a", &[Some(&raw), Some(&proof), Some(&proof)], None), packet.outputs)
            }
            "SingleCancel" | "SingleExit" => {
                let packet = SingleOwnerPacket::decode(&raw).unwrap();
                let role = packet.outputs[0].role();
                let action = if kind == "SingleCancel" { Action::Cancel } else { Action::Exit };
                let call = build_single_call(&deployment, &packet, sender, role, action, &proof).unwrap();
                (call, abi("f6146f41", &[Some(&raw), None, None, Some(&proof)], Some((role as u8, action as u8))), packet.outputs)
            }
            "Withdrawal" => {
                let packet = NoteWithdrawalPacket::decode(&raw).unwrap();
                let call = build_withdrawal_call(&deployment, &packet, sender, &proof).unwrap();
                (call, abi("50fbe2d9", &[Some(&raw), Some(&proof)], None), packet.outputs)
            }
            _ => panic!("unexpected actual vector kind"),
        };
        if kind != "Creation" {
            assert_eq!(call.from(), sender);
            assert_eq!(call.value(), U256::zero());
        }
        if kind != "Fill" {
            assert_eq!(call.expected_journals(), &[field(&value, "journalhex")]);
        }
        assert_eq!(call.to(), deployment.authority);
        assert_eq!(call.deployment(), &deployment);
        assert_eq!(call.packet_digest().as_slice(), field(&value, "digesthex"));
        assert_eq!(call.outputs(), expected_outputs);
        assert_eq!(call.data(), expected_data);
        assert!(call.data().len() <= 70 * 1024);
    }
}

#[test]
fn every_independently_supplied_deployment_field_is_checked_for_each_operation() {
    let creation = NoteCreationPacket::decode(&field(&vector("ordinary_native"), "packethex")).unwrap();
    let fill = PublicPacket::decode(&field(&vector("known_pair"), "packethex")).unwrap();
    let single = SingleOwnerPacket::decode(&field(&vector("single_cancel"), "packethex")).unwrap();
    let withdrawal = NoteWithdrawalPacket::decode(&field(&vector("received_native_full"), "packethex")).unwrap();
    let proof = unverified_frame();
    for index in 0..7 {
        let mut expected = creation.deployment;
        match index {
            0 => expected.chain_id += 1,
            1 => expected.authority[0] ^= 1,
            2 => expected.authority_code[0] ^= 1,
            3 => expected.verifier[0] ^= 1,
            4 => expected.verifier_code[0] ^= 1,
            5 => expected.owner_program[0] ^= 1,
            6 => expected.schema += 1,
            _ => unreachable!(),
        }
        assert_error(build_creation_call(&expected, creation.token, &creation, &proof), CallBuildError::WrongDeployment);
        assert_error(build_fill_call(&expected, &fill, [1; 20], &proof, &proof), CallBuildError::WrongDeployment);
        assert_error(build_single_call(&expected, &single, [1; 20], Role::A, Action::Cancel, &proof), CallBuildError::WrongDeployment);
        assert_error(build_withdrawal_call(&expected, &withdrawal, [1; 20], &proof), CallBuildError::WrongDeployment);
    }
    let mut expected = creation.deployment;
    expected.chain_id = 0;
    assert_error(build_creation_call(&expected, creation.token, &creation, &proof), CallBuildError::WrongDeployment);
    let mut invalid = creation.clone();
    invalid.deployment = expected;
    assert_error(build_creation_call(&expected, invalid.token, &invalid, &proof), CallBuildError::WrongDeployment);
}

#[test]
fn sender_token_role_and_action_fail_before_any_unsigned_call_is_returned() {
    let mut creation = NoteCreationPacket::decode(&field(&vector("ordinary_token"), "packethex")).unwrap();
    let fill = PublicPacket::decode(&field(&vector("known_pair"), "packethex")).unwrap();
    let single = SingleOwnerPacket::decode(&field(&vector("single_cancel"), "packethex")).unwrap();
    let withdrawal = NoteWithdrawalPacket::decode(&field(&vector("received_native_full"), "packethex")).unwrap();
    let proof = unverified_frame();
    assert_error(build_creation_call(&creation.deployment, [0; 20], &creation, &proof), CallBuildError::WrongToken);
    assert_error(build_creation_call(&creation.deployment, [0x88; 20], &creation, &proof), CallBuildError::WrongToken);
    creation.asset = Asset::Token([0x99; 20]);
    assert_error(build_creation_call(&creation.deployment, creation.token, &creation, &proof), CallBuildError::InvalidPacket);
    creation.asset = Asset::Token(creation.token);
    creation.payer = [0; 20];
    assert_error(build_creation_call(&creation.deployment, creation.token, &creation, &proof), CallBuildError::InvalidSender);
    assert_error(build_fill_call(&fill.deployment, &fill, [0; 20], &proof, &proof), CallBuildError::InvalidSender);
    assert_error(build_single_call(&single.deployment, &single, [0; 20], Role::A, Action::Cancel, &proof), CallBuildError::InvalidSender);
    assert_error(build_withdrawal_call(&withdrawal.deployment, &withdrawal, [0; 20], &proof), CallBuildError::InvalidSender);
    assert_error(build_single_call(&single.deployment, &single, [1; 20], Role::A, Action::Fill, &proof), CallBuildError::InvalidRoleAction);
    assert_error(build_single_call(&single.deployment, &single, [1; 20], Role::B, Action::Exit, &proof), CallBuildError::InvalidRoleAction);
}

#[test]
fn complete_proof_framing_rejects_lengths_selector_exit_and_root_for_all_calls() {
    let creation = NoteCreationPacket::decode(&field(&vector("ordinary_native"), "packethex")).unwrap();
    let fill = PublicPacket::decode(&field(&vector("known_pair"), "packethex")).unwrap();
    let single = SingleOwnerPacket::decode(&field(&vector("single_cancel"), "packethex")).unwrap();
    let withdrawal = NoteWithdrawalPacket::decode(&field(&vector("received_native_full"), "packethex")).unwrap();
    let good = unverified_frame();
    let mut invalid = vec![vec![], good[..355].to_vec(), [good.as_slice(), &[0]].concat(), vec![0; 70 * 1024]];
    for index in [0, 3, 4, 35, 36, 67] {
        let mut proof = good.clone();
        proof[index] ^= 1;
        invalid.push(proof);
    }
    for proof in invalid {
        assert_error(build_creation_call(&creation.deployment, creation.token, &creation, &proof), CallBuildError::InvalidProofFrame);
        assert_error(build_fill_call(&fill.deployment, &fill, [1; 20], &proof, &good), CallBuildError::InvalidProofFrame);
        assert_error(build_fill_call(&fill.deployment, &fill, [1; 20], &good, &proof), CallBuildError::InvalidProofFrame);
        assert_error(build_single_call(&single.deployment, &single, [1; 20], Role::A, Action::Cancel, &proof), CallBuildError::InvalidProofFrame);
        assert_error(build_withdrawal_call(&withdrawal.deployment, &withdrawal, [1; 20], &proof), CallBuildError::InvalidProofFrame);
    }
}

#[test]
fn proof_payload_is_preserved_not_misrepresented_as_cryptographically_checked() {
    let packet = PublicPacket::decode(&field(&vector("known_pair"), "packethex")).unwrap();
    let original = unverified_frame();
    let first = build_fill_call(&packet.deployment, &packet, [1; 20], &original, &original).unwrap();
    for index in [68, 99, 100, 355] {
        let mut mutated = original.clone();
        mutated[index] = 0xff;
        let call = build_fill_call(&packet.deployment, &packet, [1; 20], &original, &mutated).unwrap();
        assert_ne!(call.data(), first.data());
        assert_eq!(call.expected_journals(), first.expected_journals());
        assert_eq!(call.data(), abi("d316bd1a", &[Some(&packet.encode().unwrap()), Some(&original), Some(&mutated)], None));
    }
}

#[test]
fn native_maximum_value_and_dynamic_padding_remain_exact_without_rounding() {
    let mut packet = NoteCreationPacket::decode(&field(&vector("ordinary_native"), "packethex")).unwrap();
    let proof = unverified_frame();
    packet.amount = U256::MAX;
    for length in [1, 31, 32, 33, MAX_CIPHERTEXT_BYTES] {
        let OutputDescriptor::Note { ciphertext, .. } = &mut packet.output else { unreachable!() };
        *ciphertext = vec![0xa5; length];
        let call = build_creation_call(&packet.deployment, packet.token, &packet, &proof).unwrap();
        assert_eq!(call.value(), U256::MAX);
        assert_eq!(call.data(), abi("94184ba9", &[Some(&packet.encode().unwrap()), Some(&proof)], None));
        // The 356-byte proof has exactly 28 zero ABI padding bytes.
        assert_eq!(&call.data()[call.data().len() - 28..], &[0; 28]);
    }
    let OutputDescriptor::Note { ciphertext, .. } = &mut packet.output else { unreachable!() };
    ciphertext.push(0);
    assert_error(build_creation_call(&packet.deployment, packet.token, &packet, &proof), CallBuildError::InputBounds);
    let mut invalid = PublicPacket::decode(&field(&vector("known_pair"), "packethex")).unwrap();
    invalid.terms_commitment = [0; 32];
    assert_error(build_fill_call(&invalid.deployment, &invalid, [1; 20], &proof, &proof), CallBuildError::InvalidPacket);
}

#[test]
fn both_single_roles_and_modes_use_canonical_static_words() {
    let mut packet = SingleOwnerPacket::decode(&field(&vector("single_cancel"), "packethex")).unwrap();
    let proof = unverified_frame();
    for role in [Role::A, Role::B] {
        for output in &mut packet.outputs {
            match output {
                OutputDescriptor::Note { role: output_role, .. }
                | OutputDescriptor::Exit { role: output_role, .. } => *output_role = role,
                OutputDescriptor::Fee { payer, .. } => *payer = role,
            }
        }
        for action in [Action::Cancel, Action::Exit] {
            let call = build_single_call(&packet.deployment, &packet, [2; 20], role, action, &proof).unwrap();
            assert_eq!(&call.data()[36..68], word(role as usize));
            assert_eq!(&call.data()[68..100], word(action as usize));
            assert_eq!(call.data(), abi("f6146f41", &[Some(&packet.encode().unwrap()), None, None, Some(&proof)], Some((role as u8, action as u8))));
        }
    }
}

#[test]
fn maximum_public_manifest_is_bounded_and_oversized_notes_fail_in_each_builder() {
    let proof = unverified_frame();
    let mut fill = PublicPacket::decode(&field(&vector("known_pair"), "packethex")).unwrap();
    fill.outputs = (0..8).map(|index| OutputDescriptor::Note {
        role: if index < 4 { Role::A } else { Role::B },
        commitment: [0x80 + index; 32],
        recovery_key_commitment: [0x90 + index; 32],
        ciphertext_version: 1,
        ciphertext: vec![0xab + index; MAX_CIPHERTEXT_BYTES],
    }).collect();
    let call = build_fill_call(&fill.deployment, &fill, [1; 20], &proof, &proof).unwrap();
    assert_eq!(call.data(), abi("d316bd1a", &[Some(&fill.encode().unwrap()), Some(&proof), Some(&proof)], None));
    assert!(call.data().len() < 70 * 1024);
    let OutputDescriptor::Note { ciphertext, .. } = &mut fill.outputs[0] else { unreachable!() };
    ciphertext.push(0);
    assert_error(build_fill_call(&fill.deployment, &fill, [1; 20], &proof, &proof), CallBuildError::InputBounds);
    let mut single = SingleOwnerPacket::decode(&field(&vector("single_cancel"), "packethex")).unwrap();
    let mut withdrawal = NoteWithdrawalPacket::decode(&field(&vector("received_token_partial"), "packethex")).unwrap();
    for outputs in [&mut single.outputs, &mut withdrawal.outputs] {
        let output = outputs.iter_mut().find(|output| matches!(output, OutputDescriptor::Note { .. })).unwrap();
        let OutputDescriptor::Note { ciphertext, .. } = output else { unreachable!() };
        *ciphertext = vec![0; MAX_CIPHERTEXT_BYTES + 1];
    }
    assert_error(build_single_call(&single.deployment, &single, [1; 20], Role::A, Action::Cancel, &proof), CallBuildError::InputBounds);
    assert_error(build_withdrawal_call(&withdrawal.deployment, &withdrawal, [1; 20], &proof), CallBuildError::InputBounds);
}
