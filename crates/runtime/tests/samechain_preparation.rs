//! Controlled shared fixture regressions; each witness opens only its own policy/salt.
//! Output preparation is not bilateral approval, backup or funded admission.
use primitive_types::U256;
use std::io::Write;
use std::process::{Command, Stdio};
use ziquid_proofs::samechain::{
    MerkleMembership, NoteOpening, OwnerWitness, RelationError, decrypt_output,
    fill_consent_message, review_owner_fill, verify_owner_relation,
};
use ziquid_protocol::samechain::{Action, Asset, FeeRule, OutputDescriptor, PublicPacket, Role, SamechainError};
use ziquid_protocol::samechain::fill::FillExecution;
use ziquid_protocol::samechain::tree::NoteTree;
use ziquid_runtime::samechain::preparation::{PreparedFillOutputs, prepare_fill_outputs};

#[allow(dead_code)]
#[path = "../../proofs/tests/support/samechain.rs"]
mod support;


fn assert_prepared_notes(
    prepared: &PreparedFillOutputs, input: &NoteOpening, role: Role,
    expected: &[(Asset, u64, Option<u64>)],
) {
    assert_eq!(prepared.descriptors.len(), expected.len());
    assert_eq!(prepared.openings.len(), expected.len());
    for (index, (opening, &(asset, value, remaining))) in
        prepared.openings.iter().zip(expected).enumerate()
    {
        assert_eq!(opening.manifest_index, index as u32);
        let descriptor = &prepared.descriptors[index];
        let OutputDescriptor::Note { role: actual_role, ciphertext, .. } = descriptor else {
            panic!("preparation must return recipient notes only");
        };
        assert_eq!(*actual_role, role);
        assert_eq!(opening.note.asset, asset);
        assert_eq!(opening.note.value, U256::from(value));
        assert_eq!(opening.note.deployment_digest, input.deployment_digest);
        assert_eq!(opening.note.owner_key, input.owner_key);
        let recovered = decrypt_output(descriptor, &opening.recovery_key,
            &input.deployment_digest, &input.owner_key).unwrap();
        assert_eq!(recovered, opening.note);
        match remaining {
            Some(remaining) => {
                let source = input.order.as_ref().unwrap();
                let successor = recovered.order.as_ref().expect("missing backed successor");
                assert_eq!(successor.id, source.id);
                assert_eq!(successor.generation, source.generation + 1);
                assert_eq!(successor.remaining_sell, U256::from(remaining));
                assert_eq!(successor.policy, source.policy);
            }
            None => assert!(recovered.order.is_none()),
        }
        assert_ne!(opening.note.nf_key, [0; 32]);
        assert_ne!(opening.note.nonce, [0; 32]);
        assert_ne!(opening.note.salt, [0; 32]);
        assert_ne!(opening.recovery_key, [0; 32]);
        assert!(ciphertext[..24].iter().any(|byte| *byte != 0));
        assert_ne!(opening.note.nullifier().unwrap(), input.nullifier().unwrap());
        for previous in &prepared.openings[..index] {
            assert_ne!(opening.note.nullifier().unwrap(), previous.note.nullifier().unwrap());
        }
    }
}

fn review_in_process(packet: &PublicPacket, owner: &OwnerWitness, expected_execution: &FillExecution) {
    assert_eq!(owner.consent, [0; 64]);
    let order_id = owner.input.order.as_ref().unwrap().id;
    let message = review_owner_fill(packet, owner, &support::deployment(), order_id,
        owner.role, expected_execution).unwrap();
    assert_eq!(message, fill_consent_message(packet, owner.role).unwrap());
    assert_eq!(verify_owner_relation(packet, owner), Err(RelationError::Signature));
}

fn review_in_cli(packet_file: &tempfile::NamedTempFile, execution_file: &tempfile::NamedTempFile,
    packet: &PublicPacket, owner: &OwnerWitness)
{
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .args(["samechain", "review-fill", "--packet", packet_file.path().to_str().unwrap(),
            "--execution", execution_file.path().to_str().unwrap(),
            "--role", if owner.role == Role::A { "a" } else { "b" }, "--witness-stdin"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    // Only independently selected public packet/execution are on disk. Private
    // openings/keys stay in the erasing witness buffer and explicit private stdin.
    let witness = owner.encode().unwrap();
    child.stdin.take().unwrap().write_all(&witness).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "prepared owner review failed");
    assert!(output.stderr.is_empty(), "review emitted an unexpected diagnostic");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut fields: Vec<_> = json.as_object().unwrap().keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(fields, [
        "action", "asset_backing", "consent_message", "evidence", "financial_execution",
        "global_unspentness", "kind", "packet", "packet_digest", "proof_certificate",
        "role", "root_eligibility", "strict_matching_privacy",
    ]);
    assert_eq!(json["kind"], "review_fill");
    assert_eq!(json["role"], owner.role as u8);
    assert_eq!(json["action"], Action::Fill as u8);
    assert_eq!(json["evidence"], "native_owner_preconsent_review");
    for field in ["asset_backing", "global_unspentness", "root_eligibility"] {
        assert_eq!(json[field], "UNVERIFIED");
    }
    for field in ["financial_execution", "proof_certificate", "strict_matching_privacy"] {
        assert_eq!(json[field], false);
    }
    for (field, expected) in [
        ("packet", packet.encode().unwrap()),
        ("packet_digest", packet.digest().unwrap().to_vec()),
        ("consent_message", fill_consent_message(packet, owner.role).unwrap().to_vec()),
    ] {
        let bytes: Vec<u8> = serde_json::from_value(json[field].clone()).unwrap();
        assert_eq!(bytes, expected);
    }
}

#[test]
fn prepared_partial_fill_outputs_review_exact_packet_for_both_owners_and_cli() {
    let mut fill = support::known_fill();
    let deployment = support::deployment();
    // This is an independent local approval, frozen before output preparation.
    let approved = FillExecution { asset_a: Asset::Native, asset_b: Asset::Token([7; 20]),
        sell_a: U256::from(40), sell_b: U256::from(50) };
    approved.validate().unwrap();
    let mut tree = NoteTree::new(deployment.digest().unwrap(), 9).unwrap();
    // Genuine accumulator insertion paths, not the fixture's arbitrary siblings.
    // Historical roots are mathematical membership only, never root admission.
    for owner in [&mut fill.a, &mut fill.b] {
        let insertion = tree.append(owner.input.commitment().unwrap()).unwrap();
        owner.membership = MerkleMembership { tree_id: insertion.tree_id,
            index: insertion.index, siblings: insertion.siblings };
        assert_eq!(owner.membership.root(&owner.input.deployment_digest,
            &owner.input.commitment().unwrap()), insertion.root);
    }
    // Explicit accepted fee-only slice; do not feed a full bilateral manifest
    // and rely on the preparer silently discarding Notes/Exits/other-owner fees.
    let fees = vec![fill.packet.outputs[2].clone()];
    assert_eq!(fees, [OutputDescriptor::Fee { payer: Role::A, asset: Asset::Token([7; 20]),
        recipient: [8; 20], amount: U256::one() }]);
    let mut a_prepared = prepare_fill_outputs(&fill.a.input, &deployment, [11; 32], Role::A,
        approved.sell_a, approved.sell_b, &fees).unwrap();
    let mut b_prepared = prepare_fill_outputs(&fill.b.input, &deployment, [12; 32], Role::B,
        approved.sell_b, approved.sell_a, &[]).unwrap();
    assert_prepared_notes(&a_prepared, &fill.a.input, Role::A, &[
        (Asset::Native, 65, Some(60)), (Asset::Token([7; 20]), 49, None),
    ]);
    assert_prepared_notes(&b_prepared, &fill.b.input, Role::B, &[
        (Asset::Token([7; 20]), 50, Some(50)), (Asset::Native, 40, None),
    ]);
    // All fresh output NFs differ from both consumed inputs and their siblings.
    let mut nullifiers = vec![fill.a.input.nullifier().unwrap(), fill.b.input.nullifier().unwrap()];
    for opening in a_prepared.openings.iter().chain(&b_prepared.openings) {
        let nullifier = opening.note.nullifier().unwrap();
        assert!(!nullifiers.contains(&nullifier));
        nullifiers.push(nullifier);
    }
    let mut outputs = std::mem::take(&mut a_prepared.descriptors);
    outputs.extend(fees);
    let b_offset = outputs.len() as u32;
    outputs.append(&mut b_prepared.descriptors);
    for opening in &mut b_prepared.openings { opening.manifest_index += b_offset; }
    fill.packet = PublicPacket { deployment,
        inputs: [support::descriptor(&fill.a.input, &fill.a.membership),
            support::descriptor(&fill.b.input, &fill.b.membership)],
        outputs, expiry: 500, terms_commitment: [0; 32] };
    // Controlled paired mutations use the proof-owned binding helper; no
    // complete private terms or common salt are installed in either witness.
    fill.a.execution = approved;
    fill.b.execution = approved;
    fill.a.owned_outputs = std::mem::take(&mut a_prepared.openings);
    fill.b.owned_outputs = std::mem::take(&mut b_prepared.openings);
    support::bind_pair(&mut fill);
    assert_eq!(fill.a.packet, fill.packet);
    assert_eq!(fill.b.packet, fill.packet);
    assert_ne!(fill.a.own_salt, fill.b.own_salt);
    fill.a.consent = [0; 64];
    fill.b.consent = [0; 64];
    assert_eq!(fill.a.owned_outputs.iter().map(|output| output.manifest_index).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(fill.b.owned_outputs.iter().map(|output| output.manifest_index).collect::<Vec<_>>(), [3, 4]);
    review_in_process(&fill.packet, &fill.a, &approved);
    review_in_process(&fill.packet, &fill.b, &approved);
    let mut packet_file = tempfile::NamedTempFile::new().unwrap();
    packet_file.write_all(&fill.packet.encode().unwrap()).unwrap();
    let mut execution_file = tempfile::NamedTempFile::new().unwrap();
    execution_file.write_all(&approved.encode().unwrap()).unwrap();
    // CLI regression only: the shared controlled fixture is not independence evidence.
    review_in_cli(&packet_file, &execution_file, &fill.packet, &fill.a);
    review_in_cli(&packet_file, &execution_file, &fill.packet, &fill.b);

    // Continue from the actually prepared, decrypted successor openings, not
    // freshly reset fixture backing. A's five-atom surplus must survive again.
    let a_successor = fill.a.owned_outputs[0].note.clone();
    let b_successor = fill.b.owned_outputs[0].note.clone();
    fill.a.input = a_successor;
    fill.b.input = b_successor;
    for owner in [&mut fill.a, &mut fill.b] {
        let insertion = tree.append(owner.input.commitment().unwrap()).unwrap();
        owner.membership = MerkleMembership { tree_id: insertion.tree_id,
            index: insertion.index, siblings: insertion.siblings };
        assert_eq!(owner.membership.root(&owner.input.deployment_digest,
            &owner.input.commitment().unwrap()), insertion.root);
    }
    let mut next_a = prepare_fill_outputs(&fill.a.input, &deployment, [11; 32], Role::A,
        approved.sell_a, approved.sell_b, &[]).unwrap();
    let mut next_b = prepare_fill_outputs(&fill.b.input, &deployment, [12; 32], Role::B,
        approved.sell_b, approved.sell_a, &[]).unwrap();
    assert_prepared_notes(&next_a, &fill.a.input, Role::A, &[
        (Asset::Native, 25, Some(20)), (Asset::Token([7; 20]), 50, None),
    ]);
    assert_prepared_notes(&next_b, &fill.b.input, Role::B, &[(Asset::Native, 40, None)]);
    assert_eq!(next_a.openings[0].note.order.as_ref().unwrap().generation, 9);
    let mut next_nullifiers = vec![fill.a.input.nullifier().unwrap(), fill.b.input.nullifier().unwrap()];
    for opening in next_a.openings.iter().chain(&next_b.openings) {
        let nullifier = opening.note.nullifier().unwrap();
        assert!(!next_nullifiers.contains(&nullifier));
        next_nullifiers.push(nullifier);
    }
    let mut next_outputs = std::mem::take(&mut next_a.descriptors);
    let next_b_offset = next_outputs.len() as u32;
    next_outputs.append(&mut next_b.descriptors);
    for opening in &mut next_b.openings { opening.manifest_index += next_b_offset; }
    fill.packet = PublicPacket { deployment,
        inputs: [support::descriptor(&fill.a.input, &fill.a.membership),
            support::descriptor(&fill.b.input, &fill.b.membership)],
        outputs: next_outputs, expiry: 501, terms_commitment: [0; 32] };
    fill.a.owned_outputs = std::mem::take(&mut next_a.openings);
    fill.b.owned_outputs = std::mem::take(&mut next_b.openings);
    support::bind_pair(&mut fill);
    fill.a.consent = [0; 64];
    fill.b.consent = [0; 64];
    assert_eq!(fill.a.owned_outputs.iter().map(|output| output.manifest_index).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(fill.b.owned_outputs[0].manifest_index, 2);
    review_in_process(&fill.packet, &fill.a, &approved);
    review_in_process(&fill.packet, &fill.b, &approved);
}

#[test]
fn repeated_preparation_generates_fresh_recipient_material_without_changing_input() {
    let fill = support::known_fill();
    let original = fill.a.input.clone();
    let fees = &fill.packet.outputs[2..3];
    let first = prepare_fill_outputs(&fill.a.input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(50), fees).unwrap();
    let second = prepare_fill_outputs(&fill.a.input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(50), fees).unwrap();
    assert_eq!(fill.a.input, original);
    assert_ne!(first.descriptors, second.descriptors);
    for (left, right) in first.openings.iter().zip(&second.openings) {
        assert_ne!(left.note.nullifier().unwrap(), right.note.nullifier().unwrap());
    }
}

#[test]
fn preparation_accepts_full_close_at_max_generation_and_full_width_amounts() {
    let fill = support::known_fill();
    let mut input = fill.a.input.clone();
    input.order.as_mut().unwrap().generation = u64::MAX;
    let closed = prepare_fill_outputs(&input, &support::deployment(), [11; 32], Role::A,
        U256::from(100), U256::from(101), &fill.packet.outputs[2..3]).unwrap();
    assert_prepared_notes(&closed, &input, Role::A, &[
        (Asset::Native, 5, None), (Asset::Token([7; 20]), 100, None),
    ]);
    let wide = support::wide_fill();
    for owner in [&wide.a, &wide.b] {
        let id = owner.input.order.as_ref().unwrap().id;
        let prepared = prepare_fill_outputs(&owner.input, &support::deployment(), id, owner.role,
            U256::MAX, U256::MAX, &[]).unwrap();
        assert_eq!(prepared.descriptors.len(), 1);
        assert_eq!(prepared.openings.len(), 1);
        let opening = &prepared.openings[0];
        assert_eq!(opening.manifest_index, 0);
        assert_eq!(opening.note.value, U256::MAX);
        assert_eq!(opening.note.asset, owner.input.order.as_ref().unwrap().policy.buy_asset);
        assert!(opening.note.order.is_none());
        assert_eq!(decrypt_output(&prepared.descriptors[0], &opening.recovery_key,
            &owner.input.deployment_digest, &owner.input.owner_key).unwrap(), opening.note);
    }
}

#[test]
fn preparation_rejects_full_manifests_and_other_owner_fee_slices() {
    let fill = support::known_fill();
    for fees in [fill.packet.outputs.clone(), vec![OutputDescriptor::Fee {
        payer: Role::B, asset: Asset::Native, recipient: [8; 20], amount: U256::one(),
    }], vec![OutputDescriptor::Exit {
        role: Role::A, asset: Asset::Native, recipient: [8; 20], amount: U256::one(),
    }]] {
        assert_eq!(prepare_fill_outputs(&fill.a.input, &support::deployment(), [11; 32], Role::A,
            U256::from(40), U256::from(50), &fees).unwrap_err(), RelationError::Output);
    }
}

#[test]
fn preparation_rejects_wrong_scope_and_zero_or_excess_sold_quantities() {
    let fill = support::known_fill();
    let prepare = |input: &NoteOpening, deployment: &ziquid_protocol::samechain::Deployment,
        id, role, sold, credit| {
        prepare_fill_outputs(input, deployment, id, role, sold, credit, &[]).unwrap_err()
    };
    let deployment = support::deployment();
    for id in [[0; 32], [12; 32]] {
        assert_eq!(prepare(&fill.a.input, &deployment, id, Role::A,
            U256::from(40), U256::from(50)), RelationError::Input);
    }
    let mut wrong_deployment = deployment;
    wrong_deployment.chain_id += 1;
    assert_eq!(prepare(&fill.a.input, &wrong_deployment, [11; 32], Role::A,
        U256::from(40), U256::from(50)), RelationError::Input);
    let mut ordinary = fill.a.input.clone();
    ordinary.order = None;
    assert_eq!(prepare(&ordinary, &deployment, [11; 32], Role::A,
        U256::from(40), U256::from(50)), RelationError::Input);
    assert_eq!(prepare(&fill.a.input, &deployment, [11; 32], Role::B,
        U256::from(40), U256::from(50)),
        RelationError::Protocol(SamechainError::InvalidFeePolicy));
    for (sold, credit) in [(U256::zero(), U256::from(50)), (U256::from(40), U256::zero())] {
        assert_eq!(prepare(&fill.a.input, &deployment, [11; 32], Role::A, sold, credit),
            RelationError::Protocol(SamechainError::InvalidTerms));
    }
    assert_eq!(prepare(&fill.a.input, &deployment, [11; 32], Role::A,
        U256::from(101), U256::from(200)), RelationError::Successor);
    let mut invalid = fill.a.input.clone();
    invalid.nf_key = [0; 32];
    assert_eq!(prepare(&invalid, &deployment, [11; 32], Role::A,
        U256::from(40), U256::from(50)), RelationError::Note);
}

#[test]
fn preparation_rejects_unlisted_overcap_duplicate_and_noncanonical_fees() {
    let fill = support::known_fill();
    let allowed = fill.packet.outputs[2].clone();
    let mut unlisted = allowed.clone();
    if let OutputDescriptor::Fee { recipient, .. } = &mut unlisted { *recipient = [9; 20]; }
    let mut overcap = allowed.clone();
    if let OutputDescriptor::Fee { amount, .. } = &mut overcap { *amount = U256::from(2); }
    for (fees, expected) in [
        (vec![unlisted], SamechainError::UnlistedFee),
        (vec![overcap], SamechainError::FeeCapExceeded),
        // Aggregate first: duplicate 1+1 under cap 1 is also over-cap.
        (vec![allowed.clone(), allowed.clone()], SamechainError::FeeCapExceeded),
    ] {
        assert_eq!(prepare_fill_outputs(&fill.a.input, &support::deployment(), [11; 32], Role::A,
            U256::from(40), U256::from(50), &fees).unwrap_err(), RelationError::Protocol(expected));
    }
    assert_eq!(prepare_fill_outputs(&fill.a.input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(50),
        &vec![allowed.clone(); ziquid_protocol::samechain::MAX_OUTPUTS + 1]).unwrap_err(),
        RelationError::ResourceLimit);
    let mut input = fill.a.input.clone();
    input.order.as_mut().unwrap().policy.fee_policy.entries[0].max_atoms = U256::from(2);
    assert_eq!(prepare_fill_outputs(&input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(50), &[allowed.clone(), allowed.clone()]).unwrap_err(),
        RelationError::Protocol(SamechainError::DuplicateOutput));
    input.order.as_mut().unwrap().policy.fee_policy.entries.push(FeeRule {
        payer: Role::A, asset: Asset::Token([7; 20]), beneficiary: [9; 20], max_atoms: U256::one(),
    });
    let second = OutputDescriptor::Fee { payer: Role::A, asset: Asset::Token([7; 20]),
        recipient: [9; 20], amount: U256::one() };
    assert_eq!(prepare_fill_outputs(&input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(50), &[second, allowed]).unwrap_err(),
        RelationError::Protocol(SamechainError::NonCanonical));
}

#[test]
fn preparation_checks_net_buy_limit_and_partial_generation_overflow() {
    let fill = support::known_fill();
    // Gross 40 for 40 meets 1:1, but the explicit token fee leaves net 39.
    assert_eq!(prepare_fill_outputs(&fill.a.input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(40), &fill.packet.outputs[2..3]).unwrap_err(),
        RelationError::Protocol(SamechainError::LimitNotMet));
    let mut input = fill.a.input.clone();
    input.order.as_mut().unwrap().generation = u64::MAX;
    assert_eq!(prepare_fill_outputs(&input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(50), &[]).unwrap_err(), RelationError::Successor);
}

#[test]
fn sell_fees_use_only_surplus_without_changing_the_price_denominator() {
    let fill = support::known_fill();
    let mut input = fill.a.input.clone();
    input.order.as_mut().unwrap().policy.fee_policy.entries.insert(0, FeeRule {
        payer: Role::A, asset: Asset::Native, beneficiary: [8; 20], max_atoms: U256::from(6),
    });
    let fee = |amount| OutputDescriptor::Fee { payer: Role::A, asset: Asset::Native,
        recipient: [8; 20], amount: U256::from(amount) };
    // Net 40 for sold 40 meets 1:1. The separately paid sell fee consumes the
    // five-atom surplus, not another five atoms of authorized order quantity.
    let prepared = prepare_fill_outputs(&input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(40), &[fee(5u64)]).unwrap();
    assert_prepared_notes(&prepared, &input, Role::A, &[
        (Asset::Native, 60, Some(60)), (Asset::Token([7; 20]), 40, None),
    ]);
    // Still nonnegative, but 59 cannot back the mandatory remaining 60.
    assert_eq!(prepare_fill_outputs(&input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(50), &[fee(6u64)]).unwrap_err(), RelationError::Successor);
    // Full close: 105 - 100 - 6 cannot be represented as a residual.
    assert_eq!(prepare_fill_outputs(&input, &support::deployment(), [11; 32], Role::A,
        U256::from(100), U256::from(200), &[fee(6u64)]).unwrap_err(), RelationError::Conservation);
}

#[test]
fn preparation_rejects_buy_fee_underflow_and_full_width_fee_sum_without_wrapping() {
    let fill = support::known_fill();
    let mut input = fill.a.input.clone();
    input.order.as_mut().unwrap().policy.fee_policy.entries[0].max_atoms = U256::from(51);
    let fee = OutputDescriptor::Fee { payer: Role::A, asset: Asset::Token([7; 20]),
        recipient: [8; 20], amount: U256::from(51) };
    assert_eq!(prepare_fill_outputs(&input, &support::deployment(), [11; 32], Role::A,
        U256::from(40), U256::from(50), &[fee]).unwrap_err(), RelationError::Conservation);
    let wide = support::wide_fill();
    let mut input = wide.a.input.clone();
    input.order.as_mut().unwrap().policy.fee_policy.entries = [8u8, 9].map(|tag| FeeRule {
        payer: Role::A, asset: Asset::Token([7; 20]), beneficiary: [tag; 20], max_atoms: U256::MAX,
    }).to_vec();
    let fees = [8u8, 9].map(|tag| OutputDescriptor::Fee {
        payer: Role::A, asset: Asset::Token([7; 20]), recipient: [tag; 20], amount: U256::MAX,
    });
    // Two individually allowed U256::MAX fees exceed a U256::MAX credit.
    assert_eq!(prepare_fill_outputs(&input, &support::deployment(), [11; 32], Role::A,
        U256::MAX, U256::MAX, &fees).unwrap_err(), RelationError::Conservation);
}
