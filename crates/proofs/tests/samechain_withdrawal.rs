use zeroize::Zeroizing;
use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use ziquid_protocol::samechain::{Action, Asset, OutputDescriptor, Role, SamechainError};
use ziquid_proofs::samechain::{
    MAX_PRIVATE_INPUT_BYTES, PreparedOutputOpening, RelationError, fill_consent_message,
    prepare_output,
};
use ziquid_proofs::samechain::withdrawal::{
    NoteWithdrawalWitness, note_withdrawal_consent_message, review_note_withdrawal,
    verify_note_withdrawal_relation,
};
#[path = "support/ordinary_withdrawal.rs"]
#[allow(dead_code)]
mod support;
#[path = "support/samechain.rs"]
#[allow(dead_code)]
mod fill_support;

fn review(witness: &NoteWithdrawalWitness) -> Result<Vec<u8>, RelationError> {
    review_note_withdrawal(&witness.packet, witness, &witness.packet.deployment,
        witness.packet.input.commitment).map(|message| message.to_vec())
}

fn reject_both(witness: &NoteWithdrawalWitness, error: RelationError) {
    assert_eq!(review(witness).unwrap_err(), error);
    assert_eq!(verify_note_withdrawal_relation(witness).unwrap_err(), error);
}

#[test]
fn independently_framed_withdrawal_consent_authorizes_exact_public_scope() {
    let mut witness = support::received_token_partial();
    let mut message = b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_CONSENT\0".to_vec();
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&witness.packet.deployment.digest().unwrap());
    message.extend_from_slice(&witness.packet.terms_commitment);
    message.extend_from_slice(&witness.packet.digest().unwrap());
    message.extend_from_slice(&[0, 2]); // fixed Role A, Action Exit
    assert_eq!(review(&witness).unwrap(), message);
    witness.consent = SigningKey::from_bytes(&witness.owner_seed).sign(&message).to_bytes();
    verify_note_withdrawal_relation(&witness).unwrap();
}

#[test]
fn recovered_receipts_and_cancel_return_support_exact_withdrawal_and_recoverable_change() {
    for (witness, input_value, change_value) in [
        (support::received_token_partial(), 49, Some(8)),
        (support::received_native_full(), 40, None),
        (support::cancelled_native_partial(), 100, Some(30)),
    ] {
        assert!(witness.input.order.is_none());
        assert_eq!(witness.input.value, U256::from(input_value));
        let journal = verify_note_withdrawal_relation(&witness).unwrap();
        assert_eq!(journal.input_commitment, witness.input.commitment().unwrap());
        assert_eq!(journal.input_nullifier, witness.input.nullifier().unwrap());
        let mut unsigned = witness.clone();
        unsigned.consent = [0; 64];
        assert_eq!(review(&unsigned).unwrap(), note_withdrawal_consent_message(&witness.packet).unwrap());
        assert_eq!(verify_note_withdrawal_relation(&unsigned).unwrap_err(), RelationError::Signature);
        if let Some(value) = change_value {
            let next = support::change_withdrawal(&witness);
            assert_eq!(next.input.value, U256::from(value));
            assert!(next.input.order.is_none());
            assert_eq!(next.packet.input.nullifier, witness.owned_outputs[0].note.nullifier().unwrap());
            assert_ne!(next.packet.input.nullifier, journal.input_nullifier);
            review(&next).unwrap();
            verify_note_withdrawal_relation(&next).unwrap();
        }
    }
}

#[test]
fn full_u256_max_is_not_narrowed_and_one_extra_atom_is_rejected() {
    let mut witness = support::max_withdrawal();
    review(&witness).unwrap();
    verify_note_withdrawal_relation(&witness).unwrap();
    witness.packet.outputs.push(OutputDescriptor::Fee { payer: Role::A, asset: Asset::Native,
        recipient: [10; 20], amount: U256::one() });
    support::rebind(&mut witness);
    reject_both(&witness, RelationError::Conservation);
}

#[test]
fn changed_blind_and_arbitrary_terms_labels_fail_even_with_fresh_exact_consent() {
    for change_blind in [true, false] {
        let mut witness = support::received_token_partial();
        if change_blind { witness.blind = [133; 32]; }
        else { witness.packet.terms_commitment = [134; 32]; }
        support::resign(&mut witness);
        reject_both(&witness, RelationError::Protocol(SamechainError::OpeningMismatch));
        // Private transport remains shape-only, including semantic-invalid packets.
        let transported = NoteWithdrawalWitness::decode(&witness.encode().unwrap()).unwrap();
        reject_both(&transported, RelationError::Protocol(SamechainError::OpeningMismatch));
    }
}

#[test]
fn review_requires_independently_selected_deployment_input_and_exact_packet() {
    let witness = support::received_token_partial();
    let mut deployment = witness.packet.deployment;
    deployment.chain_id += 1;
    assert!(review_note_withdrawal(&witness.packet, &witness, &deployment,
        witness.packet.input.commitment).is_err());
    for commitment in [[0; 32], [135; 32]] {
        assert_eq!(review_note_withdrawal(&witness.packet, &witness, &witness.packet.deployment,
            commitment).unwrap_err(), RelationError::Input);
    }
    let mut different = witness.packet.clone();
    different.expiry += 1;
    assert!(review_note_withdrawal(&different, &witness, &witness.packet.deployment,
        witness.packet.input.commitment).is_err());
}

#[test]
fn ordinary_withdrawal_rejects_order_input_after_honest_rebinding() {
    let mut witness = support::received_token_partial();
    let fill = fill_support::known_fill();
    witness.input = fill.a.input.clone();
    witness.membership = fill.a.membership.clone();
    witness.packet.outputs = vec![OutputDescriptor::Exit { role: Role::A,
        asset: witness.input.asset, recipient: [9; 20], amount: witness.input.value }];
    witness.owned_outputs.clear();
    support::replace_input(&mut witness);
    support::rebind(&mut witness);
    reject_both(&witness, RelationError::Input);
}

#[test]
fn every_public_effect_and_change_must_use_the_input_asset_and_exact_value() {
    for fee in [false, true] {
        let mut witness = support::received_token_partial();
        match &mut witness.packet.outputs[if fee { 2 } else { 0 }] {
            OutputDescriptor::Exit { asset, .. } | OutputDescriptor::Fee { asset, .. } =>
                *asset = if fee { Asset::Token([11; 20]) } else { Asset::Native },
            _ => unreachable!(),
        }
        support::rebind(&mut witness);
        reject_both(&witness, RelationError::Output);
    }
    let mut witness = support::received_token_partial();
    witness.owned_outputs[0].note.asset = Asset::Native;
    support::replace_change(&mut witness, 0);
    support::rebind(&mut witness);
    reject_both(&witness, RelationError::Output);
    let mut witness = support::received_token_partial();
    witness.owned_outputs[0].note.value += U256::one();
    support::replace_change(&mut witness, 0);
    support::rebind(&mut witness);
    reject_both(&witness, RelationError::Conservation);
}

#[test]
fn ordinary_change_cannot_carry_order_metadata_or_reuse_input_or_sibling_nullifiers() {
    let mut witness = support::cancelled_native_partial();
    witness.owned_outputs[0].note.order = fill_support::known_fill().a.input.order.clone();
    witness.owned_outputs[0].note.order.as_mut().unwrap().remaining_sell = U256::from(30);
    support::replace_change(&mut witness, 0);
    support::rebind(&mut witness);
    reject_both(&witness, RelationError::Output);
    let mut witness = support::received_token_partial();
    witness.owned_outputs[0].note.nf_key = witness.input.nf_key;
    witness.owned_outputs[0].note.nonce = witness.input.nonce;
    support::replace_change(&mut witness, 0);
    support::rebind(&mut witness);
    reject_both(&witness, RelationError::Output);
    let mut witness = support::received_token_partial();
    witness.owned_outputs[0].note.value = U256::from(4);
    support::replace_change(&mut witness, 0);
    let mut note = witness.owned_outputs[0].note.clone();
    note.salt = [219; 32];
    let recovery_key = [220; 32];
    witness.packet.outputs.push(prepare_output(&note, Role::A, &recovery_key, [221; 24]).unwrap());
    witness.owned_outputs.push(PreparedOutputOpening { manifest_index: 3, note, recovery_key });
    // First prove a genuinely fresh sibling with the same total is admissible.
    witness.owned_outputs[1].note.nf_key = [222; 32];
    support::replace_change(&mut witness, 1);
    support::rebind(&mut witness);
    review(&witness).unwrap();
    verify_note_withdrawal_relation(&witness).unwrap();
    witness.owned_outputs[1].note.nf_key = witness.owned_outputs[0].note.nf_key;
    support::replace_change(&mut witness, 1);
    support::rebind(&mut witness);
    reject_both(&witness, RelationError::Output);
}

#[test]
fn recovery_openings_are_complete_ordered_authenticated_and_owner_bound() {
    for mutation in 0..6 {
        let mut witness = support::received_token_partial();
        match mutation {
            0 => { witness.owned_outputs.clear(); }
            1 => { witness.owned_outputs[0].manifest_index = 2; }
            2 => { witness.owned_outputs.push(witness.owned_outputs[0].clone()); }
            3 => { witness.owned_outputs[0].recovery_key = [223; 32]; }
            4 => { witness.owned_outputs[0].note.salt = [224; 32]; }
            5 => {
                if let OutputDescriptor::Note { ciphertext, .. } = &mut witness.packet.outputs[1] {
                    ciphertext[30] ^= 1;
                }
            }
            _ => unreachable!(),
        }
        support::rebind(&mut witness);
        let error = match mutation {
            0..=2 => RelationError::Manifest,
            3 | 5 => RelationError::Ciphertext,
            _ => RelationError::Output,
        };
        reject_both(&witness, error);
    }
    for foreign_deployment in [false, true] {
        let mut witness = support::received_token_partial();
        if foreign_deployment { witness.owned_outputs[0].note.deployment_digest = [225; 32]; }
        else { witness.owned_outputs[0].note.owner_key = fill_support::known_fill().b.input.owner_key; }
        support::replace_change(&mut witness, 0);
        support::rebind(&mut witness);
        reject_both(&witness, RelationError::Output);
    }
}

#[test]
fn input_crypto_and_path_are_rechecked_without_replacing_the_nullifier_identity() {
    for mutation in 0..7 {
        let mut witness = support::received_token_partial();
        match mutation {
            0 => witness.owner_seed = [226; 32],
            1 => witness.input.nf_key = [227; 32],
            2 => witness.packet.input.nullifier = [228; 32],
            3 => witness.membership.index += 1,
            4 => witness.membership.tree_id += 1,
            5 => witness.membership.siblings[0][0] ^= 1,
            6 => witness.input.deployment_digest = [229; 32],
            _ => unreachable!(),
        }
        support::rebind(&mut witness);
        let error = match mutation { 0 => RelationError::Key, 3..=5 => RelationError::Membership,
            _ => RelationError::Input };
        reject_both(&witness, error);
    }
}

#[test]
fn signed_relation_rechecks_exact_consent_and_rejects_old_fill_domain() {
    let mut witness = support::received_token_partial();
    witness.consent[0] ^= 1;
    review(&witness).unwrap();
    assert_eq!(verify_note_withdrawal_relation(&witness).unwrap_err(), RelationError::Signature);
    let fill = fill_support::known_fill();
    assert_ne!(note_withdrawal_consent_message(&witness.packet).unwrap().as_slice(),
        fill_consent_message(&fill.packet, Role::A).unwrap().as_slice());
    witness.consent = fill.a.consent;
    assert_eq!(verify_note_withdrawal_relation(&witness).unwrap_err(), RelationError::Signature);
    witness.consent = fill_support::cancel_exit(&fill, Action::Cancel).consent;
    assert_eq!(verify_note_withdrawal_relation(&witness).unwrap_err(), RelationError::Signature);
    let mut witness = support::received_token_partial();
    witness.packet.expiry += 1;
    witness.packet.terms_commitment = ziquid_protocol::samechain::withdrawal::note_withdrawal_terms_commitment(
        &witness.packet.deployment, &witness.packet.input, &witness.packet.outputs,
        witness.packet.expiry, &witness.blind).unwrap();
    review(&witness).unwrap();
    assert_eq!(verify_note_withdrawal_relation(&witness).unwrap_err(), RelationError::Signature);
}

#[test]
fn guarded_private_codec_has_exact_exhaustion_bound_and_redacted_diagnostics() {
    let witness = support::received_token_partial();
    let bytes = witness.encode().unwrap();
    assert_eq!(NoteWithdrawalWitness::decode(&bytes).unwrap(), witness);
    let debug = format!("{witness:?}");
    for secret in [format!("{:?}", witness.owner_seed), format!("{:?}", witness.blind),
        format!("{:?}", witness.input.nf_key), format!("{:?}", witness.owned_outputs[0].recovery_key)]
    { assert!(!debug.contains(&secret)); }
    for end in 0..bytes.len() { assert!(NoteWithdrawalWitness::decode(&bytes[..end]).is_err()); }
    let mut trailing = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
    trailing.extend_from_slice(&bytes); trailing.push(0);
    assert_eq!(NoteWithdrawalWitness::decode(&trailing).unwrap_err(), RelationError::Encoding);
    assert_eq!(NoteWithdrawalWitness::decode(&vec![0; MAX_PRIVATE_INPUT_BYTES + 1]).unwrap_err(),
        RelationError::ResourceLimit);
    let mut wrong_domain = Zeroizing::new(Vec::with_capacity(bytes.len()));
    wrong_domain.extend_from_slice(&bytes); wrong_domain[0] ^= 1;
    assert_eq!(NoteWithdrawalWitness::decode(&wrong_domain).unwrap_err(), RelationError::Encoding);
    let mut wrong_length = Zeroizing::new(Vec::with_capacity(bytes.len()));
    wrong_length.extend_from_slice(&bytes);
    let offset = b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_WITNESS\0".len() + 2;
    wrong_length[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(NoteWithdrawalWitness::decode(&wrong_length).unwrap_err(), RelationError::ResourceLimit);
    let mut wrong_owned_count = Zeroizing::new(Vec::with_capacity(bytes.len()));
    wrong_owned_count.extend_from_slice(&bytes);
    let owned_offset = offset + 4 + witness.packet.encode().unwrap().len() + 64
        + 4 + witness.input.encode().unwrap().len() + 8 + 32 * 32 + 64;
    wrong_owned_count[owned_offset..owned_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(NoteWithdrawalWitness::decode(&wrong_owned_count).unwrap_err(), RelationError::ResourceLimit);
}
