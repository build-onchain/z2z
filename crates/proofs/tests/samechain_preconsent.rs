use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use ziquid_proofs::samechain::{
    CancelExitWitness, OwnerWitness, RelationError, fill_consent_message, prepare_output,
    review_owner_fill, single_consent_message, verify_cancel_exit_relation, verify_owner_relation,
};
use ziquid_protocol::samechain::{
    Action, Deployment, OutputDescriptor, PublicPacket, Role, SamechainError,
    single_terms_commitment, validate_pair,
};
use ziquid_protocol::samechain::fill::FillExecution;

#[path = "support/samechain.rs"]
#[allow(dead_code)]
mod support;

#[test]
fn rejects_wrong_partial_successor_before_returning_owner_consent_material() {
    let fill = support::known_fill();
    let mut owner = fill.a;
    let expected_deployment = owner.packet.deployment;
    let expected_order = owner.input.order.as_ref().unwrap().id;
    owner.owned_outputs[0].note.order.as_mut().unwrap().remaining_sell = U256::from(61);
    support::replace_note(&mut owner, 0);
    let packet = unsigned_rebind(&mut owner);
    owner.consent = [0;64];
    // A raw signature-message codec accepts this packet; semantic review must not.
    fill_consent_message(&packet, Role::A).unwrap();
    assert_eq!(review_owner_fill(&packet, &owner, &expected_deployment, expected_order, Role::A,
        &approved_execution()),
        Err(RelationError::Successor));
}

fn approved_execution() -> FillExecution {
    FillExecution { asset_a: ziquid_protocol::samechain::Asset::Native,
        asset_b: ziquid_protocol::samechain::Asset::Token([7; 20]),
        sell_a: U256::from(40), sell_b: U256::from(50) }
}

fn review(packet: &PublicPacket, owner: &OwnerWitness)
    -> Result<[u8; ziquid_proofs::samechain::CONSENT_MESSAGE_BYTES], RelationError>
{
    review_owner_fill(packet, owner, &support::deployment(),
        if owner.role == Role::A { [11; 32] } else { [12; 32] }, owner.role, &approved_execution())
}

fn unsigned_rebind(owner: &mut OwnerWitness) -> PublicPacket {
    let packet = support::rebind(owner);
    owner.consent = [0; 64];
    packet
}

#[test]
fn independent_owners_review_without_consent_then_sign_and_verify_exact_pair() {
    let mut fill = support::known_fill();
    assert_ne!(fill.a.input.owner_key, fill.b.input.owner_key);
    for owner in [&mut fill.a, &mut fill.b] {
        owner.consent = [0; 64];
        let reviewed = review(&fill.packet, owner).unwrap();
        assert_eq!(reviewed, fill_consent_message(&fill.packet, owner.role).unwrap());
        assert_eq!(owner.consent, [0; 64]);
        assert_eq!(verify_owner_relation(&fill.packet, owner), Err(RelationError::Signature));
        owner.consent = [44; 64];
        assert_eq!(review(&fill.packet, owner).unwrap(), reviewed);
        assert_eq!(owner.consent, [44; 64]);
        owner.consent = SigningKey::from_bytes(&owner.owner_seed).sign(&reviewed).to_bytes();
    }
    let a = verify_owner_relation(&fill.packet, &fill.a).unwrap();
    let b = verify_owner_relation(&fill.packet, &fill.b).unwrap();
    validate_pair(&fill.packet, &a, &b).unwrap();
}

#[test]
fn review_ignores_genuine_stale_consent_but_signed_verification_rechecks_it() {
    let fill = support::known_fill();
    let mut owner = fill.a;
    owner.packet.expiry += 1;
    let old_consent = owner.consent;
    let packet = support::rebind(&mut owner);
    owner.consent = old_consent;
    let reviewed = review(&packet, &owner).unwrap();
    assert_eq!(owner.consent, old_consent);
    assert_eq!(verify_owner_relation(&packet, &owner), Err(RelationError::Signature));
    owner.consent = SigningKey::from_bytes(&owner.owner_seed).sign(&reviewed).to_bytes();
    verify_owner_relation(&packet, &owner).unwrap();
}

#[test]
fn rejects_every_wrong_caller_selected_deployment_field_order_and_role() {
    let mut fill = support::known_fill();
    fill.a.consent = [0; 64];
    review(&fill.packet, &fill.a).unwrap();
    for change in 0..7 {
        let mut expected: Deployment = support::deployment();
        match change {
            0 => expected.chain_id += 1,
            1 => expected.authority[0] ^= 1,
            2 => expected.authority_code[0] ^= 1,
            3 => expected.verifier[0] ^= 1,
            4 => expected.verifier_code[0] ^= 1,
            5 => expected.owner_program[0] ^= 1,
            _ => expected.schema += 1,
        }
        assert_eq!(review_owner_fill(&fill.packet, &fill.a, &expected, [11; 32], Role::A,
            &approved_execution()),
            Err(RelationError::Protocol(SamechainError::InvalidDeployment)));
    }
    for order in [[0; 32], [12; 32], [99; 32]] {
        assert_eq!(review_owner_fill(&fill.packet, &fill.a, &support::deployment(), order, Role::A,
            &approved_execution()),
            Err(RelationError::Input));
    }
    assert_eq!(review_owner_fill(&fill.packet, &fill.a, &support::deployment(), [11; 32], Role::B,
        &approved_execution()),
        Err(RelationError::Protocol(SamechainError::InvalidRole)));
    let mut wrong_input = fill.a.clone();
    wrong_input.input.order.as_mut().unwrap().id = [99; 32];
    assert_eq!(review(&fill.packet, &wrong_input), Err(RelationError::Input));
    let mut wrong_descriptor = fill.a.clone();
    wrong_descriptor.packet.inputs[0].order_id = [99; 32];
    let packet = unsigned_rebind(&mut wrong_descriptor);
    assert_eq!(review(&packet, &wrong_descriptor), Err(RelationError::Input));
}

#[test]
fn independent_execution_selection_is_required_even_for_a_fresh_valid_other_execution() {
    let fill = support::known_fill();
    for role in [Role::A, Role::B] {
        let owner = if role == Role::A { &fill.a } else { &fill.b };
        for mutation in 0..4 {
            let mut selected = approved_execution();
            match mutation {
                0 => selected.sell_a += U256::one(),
                1 => selected.sell_b += U256::one(),
                2 => selected.asset_a = ziquid_protocol::samechain::Asset::Token([9; 20]),
                _ => selected.asset_b = ziquid_protocol::samechain::Asset::Token([9; 20]),
            }
            assert_eq!(review_owner_fill(&fill.packet, owner, &support::deployment(),
                owner.input.order.as_ref().unwrap().id, role, &selected),
                Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
        }
    }
    let mut different = fill.a.clone();
    different.execution.sell_b = U256::from(51);
    different.owned_outputs[1].note.value = U256::from(50);
    support::replace_note(&mut different, 1);
    let packet = support::rebind(&mut different);
    verify_owner_relation(&packet, &different).unwrap();
    assert_eq!(review(&packet, &different),
        Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
    different.consent = [0; 64];
    review_owner_fill(&packet, &different, &support::deployment(), [11; 32], Role::A,
        &different.execution).unwrap();
    let mut supplied = fill.packet.clone();
    supplied.expiry += 1;
    assert_eq!(review(&supplied, &fill.a),
        Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
}

#[test]
fn requires_authentic_seed_and_ordinary_owner_key_before_consent_bytes() {
    let fill = support::known_fill();
    review(&fill.packet, &fill.a).unwrap();
    for seed in [[0; 32], fill.b.owner_seed] {
        let mut wrong = fill.a.clone();
        wrong.owner_seed = seed;
        let packet = unsigned_rebind(&mut wrong);
        assert_eq!(review(&packet, &wrong), Err(RelationError::Key));
    }
    let mut wrong = fill.a.clone();
    wrong.input.owner_key = fill.b.input.owner_key;
    let packet = unsigned_rebind(&mut wrong);
    assert_eq!(review(&packet, &wrong), Err(RelationError::Key));
    for key in [[0; 32], { let mut identity = [0; 32]; identity[0] = 1; identity }] {
        let mut wrong = fill.a.clone();
        wrong.input.owner_key = key;
        let packet = unsigned_rebind(&mut wrong);
        assert_eq!(review(&packet, &wrong), Err(RelationError::Key));
    }
}

#[test]
fn rejects_input_membership_policy_and_owner_leaf_mutations_without_consent() {
    let fill = support::known_fill();
    for (change, expected) in [
        (0, RelationError::Input), (1, RelationError::Input),
        (2, RelationError::Membership), (3, RelationError::Input),
    ] {
        let mut wrong = fill.a.clone();
        match change {
            0 => wrong.packet.inputs[0].nullifier[0] ^= 1,
            1 => wrong.input.nf_key[0] ^= 1,
            2 => wrong.packet.inputs[0].root[0] ^= 1,
            _ => wrong.input.order.as_mut().unwrap().policy.min_sell_den = U256::from(2),
        }
        let packet = unsigned_rebind(&mut wrong);
        assert_eq!(review(&packet, &wrong), Err(expected));
    }
    let mut wrong = fill.a.clone();
    wrong.consent = [0; 64];
    wrong.own_salt[0] ^= 1;
    assert_eq!(review(&fill.packet, &wrong),
        Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
}

#[test]
fn recipient_key_ciphertext_opening_and_owner_are_reviewed_after_exact_rebind() {
    let fill = support::known_fill();
    review(&fill.packet, &fill.a).unwrap();
    for change in 0..5 {
        let mut wrong = fill.a.clone();
        match change {
            0 => wrong.owned_outputs[0].recovery_key[0] ^= 1,
            1 => if let OutputDescriptor::Note { ciphertext, .. } = &mut wrong.packet.outputs[0] {
                ciphertext[24] ^= 1;
            },
            2 => if let OutputDescriptor::Note { recovery_key_commitment, .. } = &mut wrong.packet.outputs[0] {
                recovery_key_commitment[0] ^= 1;
            },
            3 => wrong.owned_outputs[0].note.value += U256::one(),
            _ => {
                wrong.owned_outputs[0].note.owner_key = fill.b.input.owner_key;
                support::replace_note(&mut wrong, 0);
            }
        }
        let packet = unsigned_rebind(&mut wrong);
        assert_eq!(review(&packet, &wrong), Err(if change < 3 {
            RelationError::Ciphertext
        } else { RelationError::Output }));
    }
    let mut missing = fill.a.clone();
    missing.owned_outputs.pop();
    let packet = unsigned_rebind(&mut missing);
    assert_eq!(review(&packet, &missing), Err(RelationError::Manifest));
}

#[test]
fn fee_beneficiary_aggregate_cap_and_net_limit_reject_exact_fresh_signed_hostile_packets() {
    let fill = support::known_fill();
    review(&fill.packet, &fill.a).unwrap();
    for (change, expected) in [
        (0, SamechainError::UnlistedFee), (1, SamechainError::FeeCapExceeded),
        (2, SamechainError::LimitNotMet),
    ] {
        let mut wrong = fill.a.clone();
        match change {
            0 => if let OutputDescriptor::Fee { recipient, .. } = &mut wrong.packet.outputs[2] {
                *recipient = [9; 20];
            },
            1 => if let OutputDescriptor::Fee { amount, .. } = &mut wrong.packet.outputs[2] {
                *amount = U256::from(2);
            },
            _ => {
                // Gross 50*4 = 40*5; actual net 49*4 < 40*5.
                let policy = &mut wrong.input.order.as_mut().unwrap().policy;
                policy.min_buy_num = U256::from(5);
                policy.min_sell_den = U256::from(4);
                wrong.owned_outputs[0].note.order.as_mut().unwrap().policy = policy.clone();
                support::replace_note(&mut wrong, 0);
                wrong.packet.inputs[0] = support::descriptor(&wrong.input, &wrong.membership);
            }
        }
        let packet = support::rebind(&mut wrong);
        assert_eq!(verify_owner_relation(&packet, &wrong), Err(RelationError::Protocol(expected)),
            "fresh authentic policy, leaf, aggregate and signature reach the intended economics");
        wrong.consent = [0; 64];
        assert_eq!(review(&packet, &wrong), Err(RelationError::Protocol(expected)));
    }
}

#[test]
fn per_asset_conservation_and_successor_policy_are_required_before_consent() {
    let fill = support::known_fill();
    for change in 0..6 {
        let mut wrong = fill.a.clone();
        match change {
            0 => wrong.owned_outputs[1].note.value += U256::one(),
            1 => {
                wrong.owned_outputs[0].note.value += U256::one();
                wrong.owned_outputs[1].note.value -= U256::one();
                support::replace_note(&mut wrong, 0);
            }
            2 => wrong.owned_outputs[0].note.order.as_mut().unwrap().policy.min_sell_den = U256::from(2),
            3 => wrong.owned_outputs[0].note.order.as_mut().unwrap().generation += 1,
            4 => wrong.owned_outputs[0].note.order.as_mut().unwrap().id = [99; 32],
            _ => wrong.owned_outputs[0].note.order = None,
        }
        support::replace_note(&mut wrong, if change < 2 { 1 } else { 0 });
        let packet = unsigned_rebind(&mut wrong);
        assert_eq!(review(&packet, &wrong), Err(if change < 2 {
            RelationError::Conservation
        } else { RelationError::Successor }));
    }
}

fn cancel_review(witness: &CancelExitWitness)
    -> Result<[u8; ziquid_proofs::samechain::CONSENT_MESSAGE_BYTES], RelationError>
{
    ziquid_proofs::samechain::review_owner_cancel_exit(&witness.packet, witness,
        &support::deployment(), if witness.role == Role::A { [11; 32] } else { [12; 32] },
        witness.role, witness.action)
}

fn restored_cancel_exit(role: Role, action: Action) -> CancelExitWitness {
    let fill = support::known_fill();
    let owner = if role == Role::A { fill.a } else { fill.b };
    support::cancel_exit_from_note(owner.owned_outputs[0].note.clone(),
        owner.membership.clone(), role, owner.owner_seed, action)
}

fn rebind_single(witness: &mut CancelExitWitness) {
    witness.packet.terms_commitment = single_terms_commitment(&witness.packet.deployment,
        &witness.packet.input, &witness.packet.outputs, witness.packet.expiry, &witness.blind).unwrap();
    witness.consent = SigningKey::from_bytes(&witness.owner_seed).sign(
        &single_consent_message(&witness.packet, witness.role, witness.action).unwrap()).to_bytes();
}

fn replace_single_note(witness: &mut CancelExitWitness, index: usize) {
    let opening = &witness.owned_outputs[index];
    witness.packet.outputs[opening.manifest_index as usize] = prepare_output(&opening.note,
        witness.role, &opening.recovery_key, [201 + index as u8; 24]).unwrap();
}

fn rejected_single_semantics(mut witness: CancelExitWitness, expected: RelationError) {
    rebind_single(&mut witness);
    assert_eq!(verify_cancel_exit_relation(&witness), Err(expected), "fresh signed baseline");
    witness.consent = [0; 64];
    assert_eq!(cancel_review(&witness), Err(expected), "unsigned semantic review");
}

#[test]
fn cancel_exit_unsigned_review_ignores_only_consent_for_both_restored_owners() {
    for role in [Role::A, Role::B] {
        for action in [Action::Cancel, Action::Exit] {
            let mut witness = restored_cancel_exit(role, action);
            verify_cancel_exit_relation(&witness).unwrap();
            let expected = single_consent_message(&witness.packet, role, action).unwrap();
            for consent in [[0; 64], [44; 64]] {
                witness.consent = consent;
                assert_eq!(cancel_review(&witness).unwrap(), expected);
                assert_eq!(witness.consent, consent);
                assert_eq!(verify_cancel_exit_relation(&witness), Err(RelationError::Signature));
            }
            witness.consent = SigningKey::from_bytes(&witness.owner_seed).sign(&expected).to_bytes();
            verify_cancel_exit_relation(&witness).unwrap();
        }
    }
    let mut legacy = support::cancel_exit(&support::known_fill(), Action::Cancel);
    legacy.consent = [0; 64];
    cancel_review(&legacy).unwrap();
}

#[test]
fn cancel_exit_stale_consent_and_action_replay_never_repair_signed_verification() {
    let mut witness = restored_cancel_exit(Role::A, Action::Cancel);
    let cancel = cancel_review(&witness).unwrap();
    witness.action = Action::Exit;
    let exit = cancel_review(&witness).unwrap();
    assert_ne!(cancel, exit);
    assert_eq!(verify_cancel_exit_relation(&witness), Err(RelationError::Signature));
    witness.consent = SigningKey::from_bytes(&witness.owner_seed).sign(&exit).to_bytes();
    verify_cancel_exit_relation(&witness).unwrap();
    let stale = witness.consent;
    witness.packet.expiry += 1;
    witness.packet.terms_commitment = single_terms_commitment(&witness.packet.deployment,
        &witness.packet.input, &witness.packet.outputs, witness.packet.expiry, &witness.blind).unwrap();
    cancel_review(&witness).unwrap();
    assert_eq!(witness.consent, stale);
    assert_eq!(verify_cancel_exit_relation(&witness), Err(RelationError::Signature));
}

#[test]
fn cancel_exit_review_requires_independent_packet_deployment_order_role_and_action() {
    let mut witness = restored_cancel_exit(Role::A, Action::Cancel);
    witness.consent = [0; 64];
    let review = |packet: &_, deployment: &_, order, role, action| {
        ziquid_proofs::samechain::review_owner_cancel_exit(packet, &witness,
            deployment, order, role, action)
    };
    for change in 0..7 {
        let mut deployment = support::deployment();
        match change {
            0 => deployment.chain_id += 1,
            1 => deployment.authority[0] ^= 1,
            2 => deployment.authority_code[0] ^= 1,
            3 => deployment.verifier[0] ^= 1,
            4 => deployment.verifier_code[0] ^= 1,
            5 => deployment.owner_program[0] ^= 1,
            _ => deployment.schema += 1,
        }
        assert_eq!(review(&witness.packet, &deployment, [11; 32], Role::A, Action::Cancel),
            Err(RelationError::Protocol(SamechainError::InvalidDeployment)));
    }
    for order in [[0; 32], [12; 32], [99; 32]] {
        assert_eq!(review(&witness.packet, &support::deployment(), order, Role::A, Action::Cancel),
            Err(RelationError::Input));
    }
    assert_eq!(review(&witness.packet, &support::deployment(), [11; 32], Role::B, Action::Cancel),
        Err(RelationError::Protocol(SamechainError::InvalidRole)));
    for action in [Action::Fill, Action::Exit] {
        assert_eq!(review(&witness.packet, &support::deployment(), [11; 32], Role::A, action),
            Err(RelationError::Action));
    }
    let mut packet = witness.packet.clone();
    packet.expiry += 1;
    assert_eq!(review(&packet, &support::deployment(), [11; 32], Role::A, Action::Cancel),
        Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
    witness.blind[0] ^= 1;
    assert_eq!(cancel_review(&witness), Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
    witness.blind[0] ^= 1;
    witness.input.order.as_mut().unwrap().id = [99; 32];
    assert_eq!(cancel_review(&witness), Err(RelationError::Input));
}

#[test]
fn cancel_exit_review_requires_authentic_owner_input_and_membership() {
    for role in [Role::A, Role::B] {
        let baseline = restored_cancel_exit(role, Action::Cancel);
        for seed in [[0; 32], [23; 32]] {
            let mut wrong = baseline.clone();
            wrong.owner_seed = seed;
            assert_eq!(cancel_review(&wrong), Err(RelationError::Key));
        }
        for key in [[0; 32], SigningKey::from_bytes(&[23; 32]).verifying_key().to_bytes()] {
            let mut wrong = baseline.clone();
            wrong.input.owner_key = key;
            assert_eq!(cancel_review(&wrong), Err(RelationError::Key));
        }
        for change in 0..5 {
            let mut wrong = baseline.clone();
            match change {
                0 => wrong.packet.input.nullifier[0] ^= 1,
                1 => wrong.input.nf_key[0] ^= 1,
                2 => wrong.packet.input.root[0] ^= 1,
                3 => wrong.membership.index ^= 1,
                _ => wrong.membership.siblings[0][0] ^= 1,
            }
            rejected_single_semantics(wrong, if change < 2 { RelationError::Input }
                else { RelationError::Membership });
        }
    }
}

#[test]
fn cancel_exit_review_checks_recipient_crypto_manifest_and_private_opening() {
    for role in [Role::A, Role::B] {
        let baseline = restored_cancel_exit(role, Action::Cancel);
        for change in 0..7 {
            let mut wrong = baseline.clone();
            match change {
                0 => wrong.owned_outputs[0].recovery_key[0] ^= 1,
                1 => if let OutputDescriptor::Note { ciphertext, .. } = &mut wrong.packet.outputs[0] {
                    ciphertext[24] ^= 1;
                },
                2 => if let OutputDescriptor::Note { recovery_key_commitment, .. } = &mut wrong.packet.outputs[0] {
                    recovery_key_commitment[0] ^= 1;
                },
                3 => wrong.owned_outputs[0].note.value += U256::one(),
                4 => {
                    wrong.owned_outputs[0].note.owner_key = SigningKey::from_bytes(&[23; 32]).verifying_key().to_bytes();
                    replace_single_note(&mut wrong, 0);
                }
                5 => { wrong.owned_outputs.clear(); }
                _ => { wrong.owned_outputs.push(wrong.owned_outputs[0].clone()); }
            }
            rejected_single_semantics(wrong, match change {
                0..=2 => RelationError::Ciphertext,
                3..=4 => RelationError::Output,
                _ => RelationError::Manifest,
            });
        }
    }
}

#[test]
fn cancel_exit_review_prohibits_successors_reused_nullifiers_and_inflated_outputs() {
    for role in [Role::A, Role::B] {
        let baseline = restored_cancel_exit(role, Action::Cancel);
        for change in 0..4 {
            let mut wrong = baseline.clone();
            match change {
                0 => wrong.owned_outputs[0].note.order = wrong.input.order.clone(),
                1 => {
                    wrong.owned_outputs[0].note.nf_key = wrong.input.nf_key;
                    wrong.owned_outputs[0].note.nonce = wrong.input.nonce;
                }
                2 => wrong.owned_outputs[0].note.value += U256::one(),
                _ => wrong.owned_outputs[0].note.asset = wrong.input.order.as_ref().unwrap().policy.buy_asset,
            }
            replace_single_note(&mut wrong, 0);
            rejected_single_semantics(wrong, match change {
                0 => RelationError::Successor, 1 => RelationError::Output,
                _ => RelationError::Conservation,
            });
        }
        let mut exit = restored_cancel_exit(role, Action::Exit);
        if let OutputDescriptor::Exit { amount, .. } = &mut exit.packet.outputs[0] { *amount += U256::one(); }
        rejected_single_semantics(exit, RelationError::Conservation);
        let mut duplicate = baseline.clone();
        duplicate.owned_outputs[0].note.value -= U256::one();
        replace_single_note(&mut duplicate, 0);
        let mut extra = duplicate.owned_outputs[0].clone();
        extra.manifest_index = 1;
        extra.note.value = U256::one();
        extra.note.salt[0] ^= 1;
        duplicate.packet.outputs.push(prepare_output(&extra.note, role,
            &extra.recovery_key, [203; 24]).unwrap());
        duplicate.owned_outputs.push(extra);
        rejected_single_semantics(duplicate, RelationError::Output);
    }
}

#[test]
fn cancel_exit_fee_allowlist_and_aggregate_cap_are_checked_before_unsigned_consent() {
    let mut baseline = restored_cancel_exit(Role::A, Action::Cancel);
    let policy = &mut baseline.input.order.as_mut().unwrap().policy;
    policy.fee_policy.entries[0].asset = policy.sell_asset;
    baseline.packet.input = support::descriptor(&baseline.input, &baseline.membership);
    baseline.owned_outputs[0].note.value -= U256::one();
    replace_single_note(&mut baseline, 0);
    baseline.packet.outputs.push(OutputDescriptor::Fee { payer: Role::A, asset: baseline.input.asset,
        recipient: [8; 20], amount: U256::one() });
    rebind_single(&mut baseline);
    verify_cancel_exit_relation(&baseline).unwrap();
    cancel_review(&baseline).unwrap();
    for change in 0..2 {
        let mut wrong = baseline.clone();
        if let OutputDescriptor::Fee { recipient, amount, .. } = &mut wrong.packet.outputs[1] {
            if change == 0 { *recipient = [9; 20]; } else { *amount = U256::from(2); }
        }
        rejected_single_semantics(wrong, RelationError::Protocol(if change == 0 {
            SamechainError::UnlistedFee
        } else { SamechainError::FeeCapExceeded }));
    }
}

#[test]
fn signed_cancel_exit_still_checks_bad_consent_before_output_errors() {
    let mut witness = restored_cancel_exit(Role::A, Action::Cancel);
    witness.owned_outputs[0].recovery_key[0] ^= 1;
    witness.consent = [0; 64];
    assert_eq!(verify_cancel_exit_relation(&witness), Err(RelationError::Signature));
    assert_eq!(cancel_review(&witness), Err(RelationError::Ciphertext));
    witness.membership.siblings[0][0] ^= 1;
    assert_eq!(verify_cancel_exit_relation(&witness), Err(RelationError::Membership));
    assert_eq!(cancel_review(&witness), Err(RelationError::Membership));
}

#[test]
fn signed_fill_checks_fresh_packet_consent_before_fee_or_output_semantics() {
    let fill = support::known_fill();
    for mutation in 0..2 {
        let mut owner = fill.a.clone();
        let expected = if mutation == 0 {
            if let OutputDescriptor::Fee { amount, .. } = &mut owner.packet.outputs[2] {
                *amount = U256::from(2);
            }
            RelationError::Protocol(SamechainError::FeeCapExceeded)
        } else {
            owner.owned_outputs[0].recovery_key[0] ^= 1;
            RelationError::Ciphertext
        };
        let packet = support::rebind(&mut owner);
        assert_eq!(verify_owner_relation(&packet, &owner), Err(expected));
        owner.consent = [0; 64];
        assert_eq!(verify_owner_relation(&packet, &owner), Err(RelationError::Signature));
        assert_eq!(review(&packet, &owner), Err(expected));
    }
}
