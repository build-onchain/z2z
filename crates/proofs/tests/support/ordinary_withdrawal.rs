//! Deterministic synthetic authorization and supplied paths; never backing or root admission.
use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use ziquid_protocol::samechain::{Action, Asset, OutputDescriptor, Role};
use ziquid_protocol::samechain::withdrawal::{
    NoteInputDescriptor, NoteWithdrawalPacket, note_withdrawal_terms_commitment,
};
use ziquid_proofs::samechain::{
    MerkleMembership, NoteOpening, PreparedOutputOpening, decrypt_output, prepare_output,
    verify_cancel_exit_relation, verify_owner_relation,
};
use ziquid_proofs::samechain::withdrawal::{
    NoteWithdrawalWitness, note_withdrawal_consent_message,
};
use crate::fill_support as source;

pub fn replace_input(witness: &mut NoteWithdrawalWitness) {
    let commitment = witness.input.commitment().unwrap();
    witness.packet.input = NoteInputDescriptor {
        commitment,
        root: witness.membership.root(&witness.input.deployment_digest, &commitment),
        tree_id: witness.membership.tree_id,
        index: witness.membership.index,
        nullifier: witness.input.nullifier().unwrap(),
        owner_key: witness.input.owner_key,
    };
}

/// Sign the exact packet without fixing an intentionally invalid opening.
pub fn resign(witness: &mut NoteWithdrawalWitness) {
    witness.consent = SigningKey::from_bytes(&witness.owner_seed)
        .sign(&note_withdrawal_consent_message(&witness.packet).unwrap()).to_bytes();
}

/// Freshly open and authorize changed synthetic effects, not stale-signature negatives.
pub fn rebind(witness: &mut NoteWithdrawalWitness) {
    witness.packet.terms_commitment = note_withdrawal_terms_commitment(
        &witness.packet.deployment, &witness.packet.input, &witness.packet.outputs,
        witness.packet.expiry, &witness.blind,
    ).unwrap();
    resign(witness);
}

pub fn replace_change(witness: &mut NoteWithdrawalWitness, owned_index: usize) {
    let entry = &witness.owned_outputs[owned_index];
    witness.packet.outputs[entry.manifest_index as usize] = prepare_output(
        &entry.note, Role::A, &entry.recovery_key, [210 + owned_index as u8; 24],
    ).unwrap();
}

pub fn from_note(input: NoteOpening, owner_seed: [u8; 32], exit: U256,
    change: U256, fee: U256) -> NoteWithdrawalWitness
{
    // This path only supplies a native relation witness; no accepted tree is simulated.
    let membership = MerkleMembership { tree_id: 10, index: 0,
        siblings: std::array::from_fn(|level| [130 + level as u8; 32]) };
    let commitment = input.commitment().unwrap();
    let descriptor = NoteInputDescriptor { commitment,
        root: membership.root(&input.deployment_digest, &commitment),
        tree_id: membership.tree_id, index: membership.index,
        nullifier: input.nullifier().unwrap(), owner_key: input.owner_key };
    let mut outputs = vec![OutputDescriptor::Exit { role: Role::A,
        asset: input.asset, recipient: [9; 20], amount: exit }];
    let mut owned_outputs = vec![];
    if !change.is_zero() {
        let mut note = input.clone();
        note.value = change;
        note.order = None;
        note.nf_key = [201; 32]; note.nonce = [202; 32]; note.salt = [203; 32];
        let recovery_key = [204; 32];
        outputs.push(prepare_output(&note, Role::A, &recovery_key, [205; 24]).unwrap());
        owned_outputs.push(PreparedOutputOpening { manifest_index: 1, note, recovery_key });
    }
    if !fee.is_zero() {
        outputs.push(OutputDescriptor::Fee { payer: Role::A, asset: input.asset,
            recipient: [10; 20], amount: fee });
    }
    let mut witness = NoteWithdrawalWitness {
        packet: NoteWithdrawalPacket { deployment: source::deployment(), input: descriptor,
            outputs, expiry: 600, terms_commitment: [1; 32] },
        blind: [132; 32], owner_seed, input, membership, consent: [0; 64], owned_outputs,
    };
    rebind(&mut witness);
    witness
}

/// Actual decrypted A proceeds: 49 token = 40 exit + 8 ordinary change + 1 fee.
pub fn received_token_partial() -> NoteWithdrawalWitness {
    let fill = source::known_fill();
    verify_owner_relation(&fill.packet, &fill.a).unwrap();
    verify_owner_relation(&fill.packet, &fill.b).unwrap();
    let received = &fill.a.owned_outputs[1];
    let note = decrypt_output(&fill.packet.outputs[received.manifest_index as usize],
        &received.recovery_key, &fill.a.input.deployment_digest, &fill.a.input.owner_key).unwrap();
    assert!(note.order.is_none());
    assert_eq!(note.asset, Asset::Token([7; 20]));
    assert_eq!(note.value, U256::from(49));
    from_note(note, fill.a.owner_seed, U256::from(40), U256::from(8), U256::one())
}

/// A note decrypted from a Role B fill leg is not permanently role-bound.
pub fn received_native_full() -> NoteWithdrawalWitness {
    let fill = source::known_fill();
    verify_owner_relation(&fill.packet, &fill.b).unwrap();
    let received = &fill.b.owned_outputs[1];
    let note = decrypt_output(&fill.packet.outputs[received.manifest_index as usize],
        &received.recovery_key, &fill.b.input.deployment_digest, &fill.b.input.owner_key).unwrap();
    assert!(note.order.is_none());
    assert_eq!(note.asset, Asset::Native);
    assert_eq!(note.value, U256::from(40));
    from_note(note, fill.b.owner_seed, U256::from(40), U256::zero(), U256::zero())
}

pub fn cancelled_native_partial() -> NoteWithdrawalWitness {
    let fill = source::known_fill();
    let cancel = source::cancel_exit(&fill, Action::Cancel);
    verify_cancel_exit_relation(&cancel).unwrap();
    let received = &cancel.owned_outputs[0];
    let note = decrypt_output(&cancel.packet.outputs[received.manifest_index as usize],
        &received.recovery_key, &cancel.input.deployment_digest, &cancel.input.owner_key).unwrap();
    assert!(note.order.is_none());
    assert_eq!(note.asset, Asset::Native);
    assert_eq!(note.value, U256::from(100));
    from_note(note, cancel.owner_seed, U256::from(70), U256::from(30), U256::zero())
}

pub fn max_withdrawal() -> NoteWithdrawalWitness {
    from_note(source::note(Role::A, 181, Asset::Native, U256::MAX, None),
        [21; 32], U256::MAX, U256::zero(), U256::zero())
}

pub fn change_withdrawal(witness: &NoteWithdrawalWitness) -> NoteWithdrawalWitness {
    let entry = &witness.owned_outputs[0];
    let note = decrypt_output(&witness.packet.outputs[entry.manifest_index as usize],
        &entry.recovery_key, &witness.input.deployment_digest, &witness.input.owner_key).unwrap();
    let value = note.value;
    from_note(note, witness.owner_seed, value, U256::zero(), U256::zero())
}
