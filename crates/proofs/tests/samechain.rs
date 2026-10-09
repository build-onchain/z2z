use primitive_types::U256;
use ziquid_protocol::samechain::{Asset, FeePolicy, OrderPolicy};
use ziquid_proofs::samechain::{NoteOpening, OrderState};

#[path = "support/samechain.rs"]
#[allow(dead_code)]
mod support;

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use ziquid_protocol::samechain::{
    Action, OutputDescriptor, OwnerJournal, Role, SamechainError, validate_pair, validate_single,
};
use ziquid_protocol::samechain::fill::{aggregate_commitment, owner_leaf};
use ziquid_proofs::samechain::{
    CancelExitWitness, OwnerWitness, RelationError, decrypt_output, fill_consent_message,
    prepare_output, single_consent_message, verify_cancel_exit_relation, verify_owner_relation,
    MAX_PRIVATE_INPUT_BYTES,
};
use support::{cancel_exit, known_fill, rebind, replace_note, wide_fill};

#[test]
fn input_commitment_binds_nullifier_key_while_actions_do_not_change_nullifier() {
    let note=NoteOpening { deployment_digest:[1;32], owner_key:SigningKey::from_bytes(&[2;32]).verifying_key().to_bytes(), nf_key:[3;32], nonce:[4;32], salt:[5;32], asset:Asset::Native, value:U256::from(100), order:Some(OrderState { id:[6;32], generation:1, remaining_sell:U256::from(100), policy:OrderPolicy { sell_asset:Asset::Native, buy_asset:Asset::Token([7;20]), min_buy_num:U256::from(1), min_sell_den:U256::from(1), fee_policy:FeePolicy { entries:vec![] } } }) };
    let mut changed=note.clone();changed.nf_key=[9;32];
    assert_ne!(note.commitment().unwrap(),changed.commitment().unwrap());
    assert_ne!(note.nullifier().unwrap(),changed.nullifier().unwrap());
    let mut other_salt=note.clone();other_salt.salt=[10;32];
    assert_ne!(note.commitment().unwrap(),other_salt.commitment().unwrap());
    assert_eq!(note.nullifier().unwrap(),other_salt.nullifier().unwrap());
    // Independently constructed preimage: no owner seed, salt, role or action.
    let mut preimage = b"Z2Z_SAMECHAIN_NOTE_NULLIFIER\0".to_vec();
    preimage.extend_from_slice(&1_u16.to_be_bytes());
    preimage.extend_from_slice(&[1; 32]);
    preimage.extend_from_slice(&[3; 32]);
    preimage.extend_from_slice(&[4; 32]);
    assert_eq!(note.nullifier().unwrap(), <[u8; 32]>::from(Sha256::digest(preimage)));
    let mut changed_nonce = note.clone(); changed_nonce.nonce[0] ^= 1;
    assert_ne!(note.nullifier().unwrap(), changed_nonce.nullifier().unwrap());
    let mut changed_owner = note.clone();
    changed_owner.owner_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    assert_eq!(note.nullifier().unwrap(), changed_owner.nullifier().unwrap());
}

#[test]
fn two_independent_owners_verify_actual_partial_fill_and_pair_journals() {
    let fill = known_fill();
    let a = verify_owner_relation(&fill.packet, &fill.a).unwrap();
    let b = verify_owner_relation(&fill.packet, &fill.b).unwrap();
    assert_eq!(a.action, Action::Fill);
    assert_eq!(a.role, Role::A);
    assert_eq!(b.role, Role::B);
    assert_eq!(a.generation, 7);
    assert_eq!(a.input_nullifier, fill.a.input.nullifier().unwrap());
    assert_ne!(a.input_nullifier, b.input_nullifier);
    validate_pair(&fill.packet, &a, &b).unwrap();
    assert!(validate_pair(&fill.packet, &b, &a).is_err());
    assert_eq!(OwnerJournal::decode(&a.encode().unwrap()).unwrap(), a);
    for witness in [&fill.a, &fill.b] {
        let decoded = OwnerWitness::decode(&witness.encode().unwrap()).unwrap();
        assert_eq!(&decoded, witness);
        assert_eq!(verify_owner_relation(&fill.packet, &decoded).unwrap().role, witness.role);
        for output in &witness.owned_outputs {
            assert_eq!(decrypt_output(&fill.packet.outputs[output.manifest_index as usize],
                &output.recovery_key, &witness.input.deployment_digest, &witness.input.owner_key).unwrap(),
                output.note);
        }
    }
}

#[test]
fn independent_owner_frames_contain_only_their_local_policy_and_salt() {
    let fill = known_fill();
    assert_ne!(fill.a.own_salt, fill.b.own_salt);
    assert_ne!(fill.a.input.order.as_ref().unwrap().policy, fill.b.input.order.as_ref().unwrap().policy);
    for (owner, other) in [(&fill.a, &fill.b), (&fill.b, &fill.a)] {
        let frame = owner.encode().unwrap();
        assert_eq!(owner.packet, fill.packet);
        assert_eq!(owner.execution, other.execution);
        assert_eq!(owner.leaves, other.leaves);
        let own_policy = owner.input.order.as_ref().unwrap().policy.encode().unwrap();
        let other_policy = other.input.order.as_ref().unwrap().policy.encode().unwrap();
        assert!(frame.windows(own_policy.len()).any(|bytes| bytes == own_policy));
        assert!(!frame.windows(other_policy.len()).any(|bytes| bytes == other_policy));
        assert!(frame.windows(32).any(|bytes| bytes == owner.own_salt));
        assert!(!frame.windows(32).any(|bytes| bytes == other.own_salt));
        assert_eq!(verify_owner_relation(&fill.packet, &OwnerWitness::decode(&frame).unwrap()).unwrap().role,
            owner.role);
    }
}

#[test]
fn ordered_leaves_execution_salt_and_exact_inner_packet_are_authorization_bindings() {
    let fill = known_fill();
    for role in [Role::A, Role::B] {
        let owner = if role == Role::A { &fill.a } else { &fill.b };
        for mutation in 0..5 {
            let mut wrong = owner.clone();
            match mutation {
                0 => wrong.leaves[role.index()][0] ^= 1,
                1 => wrong.leaves[1 - role.index()][0] ^= 1,
                2 => wrong.leaves.swap(0, 1),
                3 => wrong.own_salt[0] ^= 1,
                _ => wrong.execution.sell_a += U256::one(),
            }
            assert_eq!(verify_owner_relation(&fill.packet, &wrong),
                Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
        }
        let mut own_leaf = owner.clone();
        own_leaf.leaves[role.index()][0] ^= 1;
        own_leaf.packet.terms_commitment = aggregate_commitment(&own_leaf.packet,
            &own_leaf.execution, &own_leaf.leaves).unwrap();
        own_leaf.consent = SigningKey::from_bytes(&own_leaf.owner_seed).sign(
            &fill_consent_message(&own_leaf.packet, role).unwrap()).to_bytes();
        assert_eq!(verify_owner_relation(&own_leaf.packet, &own_leaf),
            Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
        let mut zero = owner.clone();
        zero.leaves[1 - role.index()] = [0; 32];
        assert_eq!(verify_owner_relation(&zero.packet, &zero),
            Err(RelationError::Protocol(SamechainError::InvalidTerms)));
        let mut zero_salt = owner.clone();
        zero_salt.own_salt = [0; 32];
        assert_eq!(verify_owner_relation(&zero_salt.packet, &zero_salt),
            Err(RelationError::Protocol(SamechainError::InvalidBlind)));
        let mut supplied = fill.packet.clone();
        supplied.expiry += 1;
        assert_eq!(verify_owner_relation(&supplied, owner),
            Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
    }
}

#[test]
fn shared_changes_need_both_independent_owner_leaves_before_a_valid_pair() {
    let mut fill = known_fill();
    let original_a = fill.a.leaves[0];
    let original_b = fill.b.leaves[1];
    fill.a.packet.expiry += 1;
    let packet = rebind(&mut fill.a);
    assert_ne!(fill.a.leaves[0], original_a);
    assert_eq!(fill.a.leaves[1], original_b);
    verify_owner_relation(&packet, &fill.a).unwrap();
    fill.b.packet = packet.clone();
    fill.b.leaves = fill.a.leaves;
    fill.b.consent = SigningKey::from_bytes(&fill.b.owner_seed)
        .sign(&fill_consent_message(&packet, Role::B).unwrap()).to_bytes();
    assert_eq!(verify_owner_relation(&packet, &fill.b),
        Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
    fill.packet = packet;
    support::bind_pair(&mut fill);
    assert_ne!(fill.b.leaves[1], original_b);
    assert_eq!(fill.a.leaves[0], owner_leaf(&fill.packet, &fill.a.execution, Role::A,
        &fill.a.input.order.as_ref().unwrap().policy, &fill.a.own_salt).unwrap());
    validate_pair(&fill.packet, &verify_owner_relation(&fill.packet, &fill.a).unwrap(),
        &verify_owner_relation(&fill.packet, &fill.b).unwrap()).unwrap();
}

#[test]
fn local_recipient_rejects_wrong_key_ciphertext_ad_version_and_opening() {
    let fill = known_fill();
    let entry = &fill.a.owned_outputs[0];
    let output = &fill.packet.outputs[0];
    let dep = &fill.a.input.deployment_digest;
    let owner = &fill.a.input.owner_key;
    assert!(decrypt_output(output, &[1; 32], dep, owner).is_err());
    assert!(decrypt_output(output, &entry.recovery_key, &[1; 32], owner).is_err());
    assert!(decrypt_output(output, &entry.recovery_key, dep, &fill.b.input.owner_key).is_err());
    for change in 0..5 {
        let mut damaged = output.clone();
        if let OutputDescriptor::Note { commitment, recovery_key_commitment, ciphertext_version,
            ciphertext, .. } = &mut damaged
        {
            match change {
                0 => ciphertext[24] ^= 1,
                1 => { let last = ciphertext.len() - 1; ciphertext[last] ^= 1; },
                2 => *ciphertext_version = 2,
                3 => commitment[0] ^= 1,
                _ => recovery_key_commitment[0] ^= 1,
            }
        }
        assert!(decrypt_output(&damaged, &entry.recovery_key, dep, owner).is_err());
    }
    assert!(prepare_output(&entry.note, Role::A, &[0; 32], [1; 24]).is_err());
    assert!(prepare_output(&entry.note, Role::A, &entry.recovery_key, [0; 24]).is_err());
    // Valid AEAD under the original commitment/AD, but plaintext opens a
    // different amount. This must reach recomputation, not just tag rejection.
    use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
    let mut different = entry.note.clone(); different.value += U256::one();
    let mut plaintext = different.encode().unwrap();
    let (commitment, recovery_key_commitment) = match output {
        OutputDescriptor::Note { commitment, recovery_key_commitment, .. } =>
            (*commitment, *recovery_key_commitment), _ => unreachable!(),
    };
    let mut ad = b"Z2Z_SAMECHAIN_RECIPIENT_AD\0".to_vec();
    ad.extend_from_slice(&1_u16.to_be_bytes());
    ad.extend_from_slice(&1_u16.to_be_bytes());
    ad.push(Role::A as u8);
    ad.extend_from_slice(dep); ad.extend_from_slice(owner);
    ad.extend_from_slice(&commitment); ad.extend_from_slice(&recovery_key_commitment);
    let nonce = [151; 24];
    let tag = XChaCha20Poly1305::new((&entry.recovery_key).into())
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &ad, &mut plaintext).unwrap();
    let mut ciphertext = nonce.to_vec();
    ciphertext.extend_from_slice(&plaintext); ciphertext.extend_from_slice(&tag);
    let forged = OutputDescriptor::Note { role: Role::A, commitment, recovery_key_commitment,
        ciphertext_version: 1, ciphertext };
    assert_eq!(decrypt_output(&forged, &entry.recovery_key, dep, owner), Err(RelationError::Output));
}

#[test]
fn every_own_manifest_note_requires_exactly_one_owned_opening_and_key() {
    let fill = known_fill();
    let mut missing = fill.a.clone(); missing.owned_outputs.pop();
    assert_eq!(verify_owner_relation(&fill.packet, &missing), Err(RelationError::Manifest));
    let mut duplicate = fill.a.clone(); duplicate.owned_outputs.push(duplicate.owned_outputs[0].clone());
    assert_eq!(verify_owner_relation(&fill.packet, &duplicate), Err(RelationError::Manifest));
    let mut wrong_role = fill.a.clone();
    wrong_role.owned_outputs.push(fill.b.owned_outputs[0].clone());
    assert_eq!(verify_owner_relation(&fill.packet, &wrong_role), Err(RelationError::Manifest));
    let mut wrong_key = fill.a.clone(); wrong_key.owned_outputs[0].recovery_key = [1; 32];
    assert!(verify_owner_relation(&fill.packet, &wrong_key).is_err());
    let mut wrong_note = fill.a.clone(); wrong_note.owned_outputs[0].note.value += U256::one();
    assert_eq!(verify_owner_relation(&fill.packet, &wrong_note), Err(RelationError::Output));
    let mut swapped = fill.a.clone(); swapped.owned_outputs.swap(0, 1);
    // Canonical private list order is the manifest order, not an unordered bag.
    assert_eq!(verify_owner_relation(&fill.packet, &swapped), Err(RelationError::Manifest));
}

#[test]
fn new_owned_notes_never_reuse_consumed_or_sibling_nullifiers() {
    let fill = known_fill();
    for source in [&fill.a.input, &fill.b.input, &fill.a.owned_outputs[1].note] {
        let mut wrong = fill.a.clone();
        wrong.owned_outputs[0].note.nf_key = source.nf_key;
        wrong.owned_outputs[0].note.nonce = source.nonce;
        replace_note(&mut wrong, 0);
        let packet = rebind(&mut wrong);
        assert!(verify_owner_relation(&packet, &wrong).is_err(),
            "new successor reused a consumed or sibling note nullifier");
    }
    let mut cancelled = cancel_exit(&fill, Action::Cancel);
    cancelled.owned_outputs[0].note.nf_key = cancelled.input.nf_key;
    cancelled.owned_outputs[0].note.nonce = cancelled.input.nonce;
    cancelled.packet.outputs[0] = prepare_output(&cancelled.owned_outputs[0].note,
        Role::A, &cancelled.owned_outputs[0].recovery_key, [152; 24]).unwrap();
    cancelled.packet.terms_commitment = ziquid_protocol::samechain::single_terms_commitment(
        &cancelled.packet.deployment, &cancelled.packet.input, &cancelled.packet.outputs,
        cancelled.packet.expiry, &cancelled.blind).unwrap();
    cancelled.consent = SigningKey::from_bytes(&cancelled.owner_seed).sign(
        &single_consent_message(&cancelled.packet, Role::A, Action::Cancel).unwrap()).to_bytes();
    assert!(verify_cancel_exit_relation(&cancelled).is_err(),
        "cancel returned a note carrying the consumed nullifier");
}

#[test]
fn input_requires_owned_seed_committed_policy_stable_nullifier_and_ordered_membership() {
    let fill = known_fill();
    for change in 0..8 {
        let mut wrong = fill.a.clone();
        match change {
            0 => wrong.owner_seed = fill.b.owner_seed,
            1 => wrong.input.nf_key[0] ^= 1,
            2 => wrong.input.salt[0] ^= 1,
            3 => wrong.input.nonce[0] ^= 1,
            4 => wrong.membership.siblings[31][0] ^= 1,
            5 => wrong.membership.index ^= 1,
            6 => wrong.membership.tree_id += 1,
            _ => wrong.input.order.as_mut().unwrap().generation += 1,
        }
        assert!(verify_owner_relation(&fill.packet, &wrong).is_err());
    }
    let mut wrong = fill.a.clone();
    wrong.input.order.as_mut().unwrap().policy.min_sell_den = U256::from(2);
    // There is no duplicate witness policy: the authenticated input policy must
    // open the owner's leaf, even when an attacker retains all public bindings.
    assert_eq!(verify_owner_relation(&fill.packet, &wrong),
        Err(RelationError::Protocol(SamechainError::OpeningMismatch)));
    let mut nullifier = fill.a.clone(); nullifier.packet.inputs[0].nullifier[0] ^= 1;
    let packet = rebind(&mut nullifier);
    assert_eq!(verify_owner_relation(&packet, &nullifier), Err(RelationError::Input));
    let mut root = fill.a.clone(); root.packet.inputs[0].root[0] ^= 1;
    let packet = rebind(&mut root);
    assert_eq!(verify_owner_relation(&packet, &root), Err(RelationError::Membership));
}

#[test]
fn owner_checks_note_owner_asset_and_per_asset_conservation_even_with_valid_consent() {
    let fill = known_fill();
    for change in 0..4 {
        let mut bad = fill.a.clone();
        match change {
            0 => bad.owned_outputs[1].note.value += U256::one(),
            1 => bad.owned_outputs[1].note.value -= U256::one(),
            2 => bad.owned_outputs[1].note.asset = Asset::Token([9; 20]),
            _ => bad.owned_outputs[1].note.owner_key = fill.b.input.owner_key,
        }
        replace_note(&mut bad, 1);
        let packet = rebind(&mut bad);
        assert!(verify_owner_relation(&packet, &bad).is_err());
    }
    // A value surplus in one asset cannot cover a shortage in another.
    let mut bad = fill.a.clone();
    bad.owned_outputs[0].note.value += U256::one();
    bad.owned_outputs[1].note.value -= U256::one();
    replace_note(&mut bad, 0); replace_note(&mut bad, 1);
    let packet = rebind(&mut bad);
    assert_eq!(verify_owner_relation(&packet, &bad), Err(RelationError::Conservation));
}

#[test]
fn partial_successor_preserves_exact_capacity_generation_and_immutable_policy() {
    let fill = known_fill();
    for change in 0..5 {
        let mut bad = fill.a.clone();
        let successor = &mut bad.owned_outputs[0].note;
        match change {
            0 => successor.order.as_mut().unwrap().remaining_sell += U256::one(),
            1 => successor.order.as_mut().unwrap().generation += 1,
            2 => successor.order.as_mut().unwrap().id[0] ^= 1,
            3 => successor.order.as_mut().unwrap().policy.min_sell_den = U256::from(2),
            _ => successor.order = None,
        }
        replace_note(&mut bad, 0);
        let packet = rebind(&mut bad);
        assert_eq!(verify_owner_relation(&packet, &bad), Err(RelationError::Successor));
    }
    let mut bad = fill.a.clone();
    let order = bad.input.order.as_mut().unwrap(); order.generation = u64::MAX;
    bad.packet.inputs[0] = support::descriptor(&bad.input, &bad.membership);
    let packet = rebind(&mut bad);
    assert_eq!(verify_owner_relation(&packet, &bad), Err(RelationError::Successor));
    let mut too_small = fill.a.owned_outputs[0].note.clone();
    too_small.value = U256::from(59);
    assert_eq!(too_small.commitment(), Err(RelationError::Note));
    let mut zero_capacity = fill.a.owned_outputs[0].note.clone();
    zero_capacity.order.as_mut().unwrap().remaining_sell = U256::zero();
    assert_eq!(zero_capacity.commitment(), Err(RelationError::Note));
}

#[test]
fn net_limit_and_explicit_aggregate_fee_caps_are_not_optional_signature_checks() {
    let fill = known_fill();
    let mut limit = fill.a.clone();
    let policy = &mut limit.input.order.as_mut().unwrap().policy;
    policy.min_buy_num = U256::from(5);
    policy.min_sell_den = U256::from(4);
    limit.owned_outputs[0].note.order.as_mut().unwrap().policy = policy.clone();
    limit.packet.inputs[0] = support::descriptor(&limit.input, &limit.membership);
    replace_note(&mut limit, 0);
    let packet = rebind(&mut limit);
    // Gross 50*4 = 40*5, but net 49*4 < 40*5. All bindings and consent are fresh.
    assert_eq!(verify_owner_relation(&packet, &limit),
        Err(RelationError::Protocol(SamechainError::LimitNotMet)));
    let mut fee = fill.a.clone();
    if let OutputDescriptor::Fee { amount, .. } = &mut fee.packet.outputs[2] { *amount = U256::from(2); }
    let packet = rebind(&mut fee);
    assert_eq!(verify_owner_relation(&packet, &fee),
        Err(RelationError::Protocol(SamechainError::FeeCapExceeded)));
    let mut split = fill.a.clone(); split.packet.outputs.push(split.packet.outputs[2].clone());
    // Common shape rejects duplicate payments before any signature. The actual
    // authenticated fee validator separately proves split sums cannot evade caps.
    assert_eq!(split.input.order.as_ref().unwrap().policy.fee_policy
        .validate_fees(Role::A, &split.packet.outputs), Err(SamechainError::FeeCapExceeded));
    assert_eq!(verify_owner_relation(&split.packet, &split),
        Err(RelationError::Protocol(SamechainError::DuplicateOutput)));
    let mut beneficiary = fill.a.clone();
    if let OutputDescriptor::Fee { recipient, .. } = &mut beneficiary.packet.outputs[2] { *recipient = [9; 20]; }
    let packet = rebind(&mut beneficiary);
    assert_eq!(verify_owner_relation(&packet, &beneficiary),
        Err(RelationError::Protocol(SamechainError::UnlistedFee)));
}

#[test]
fn full_width_products_and_sums_close_orders_without_u256_wraparound() {
    let fill = wide_fill();
    let a = verify_owner_relation(&fill.packet, &fill.a).unwrap();
    let b = verify_owner_relation(&fill.packet, &fill.b).unwrap();
    validate_pair(&fill.packet, &a, &b).unwrap();
    let mut excessive = fill.a.clone();
    let extra = support::note(Role::A, 151, Asset::Token([7; 20]), U256::one(), None);
    let index = excessive.packet.outputs.len() as u32;
    excessive.packet.outputs.push(prepare_output(&extra, Role::A, &[152; 32], [153; 24]).unwrap());
    excessive.owned_outputs.push(ziquid_proofs::samechain::PreparedOutputOpening {
        manifest_index: index, note: extra, recovery_key: [152; 32],
    });
    let packet = rebind(&mut excessive);
    assert_eq!(verify_owner_relation(&packet, &excessive), Err(RelationError::Conservation));
    let mut wrong_limit = fill.a.clone();
    wrong_limit.input.order.as_mut().unwrap().policy.min_sell_den = U256::MAX - U256::one();
    wrong_limit.packet.inputs[0] = support::descriptor(&wrong_limit.input, &wrong_limit.membership);
    let packet = rebind(&mut wrong_limit);
    assert_eq!(verify_owner_relation(&packet, &wrong_limit),
        Err(RelationError::Protocol(SamechainError::LimitNotMet)));
    let mut reopened = fill.a.clone();
    reopened.owned_outputs[0].note.order = Some(OrderState {
        id: reopened.input.order.as_ref().unwrap().id, generation: 8, remaining_sell: U256::one(),
        policy: reopened.input.order.as_ref().unwrap().policy.clone(),
    });
    reopened.owned_outputs[0].note.asset = Asset::Native;
    replace_note(&mut reopened, 0);
    let packet = rebind(&mut reopened);
    assert_eq!(verify_owner_relation(&packet, &reopened), Err(RelationError::Successor));
}

#[test]
fn exact_common_packet_and_strict_signature_bind_every_public_effect_and_role() {
    let fill = known_fill();
    let mut bad = fill.a.clone(); bad.consent[0] ^= 1;
    assert_eq!(verify_owner_relation(&fill.packet, &bad), Err(RelationError::Signature));
    let mut high_s = fill.a.clone(); high_s.consent[63] |= 0x80;
    assert_eq!(verify_owner_relation(&fill.packet, &high_s), Err(RelationError::Signature));
    let mut wrong_role = fill.a.clone(); wrong_role.role = Role::B;
    assert!(verify_owner_relation(&fill.packet, &wrong_role).is_err());
    for change in 0..5 {
        let mut bad = fill.a.clone();
        match change {
            0 => bad.packet.expiry += 1,
            1 => if let OutputDescriptor::Note { ciphertext, .. } = &mut bad.packet.outputs[4] { ciphertext[24] ^= 1; },
            2 => bad.packet.deployment.authority_code[0] ^= 1,
            3 => bad.packet.inputs[1].owner_key = SigningKey::from_bytes(&[24; 32]).verifying_key().to_bytes(),
            _ => bad.own_salt[0] ^= 1,
        }
        assert!(verify_owner_relation(&fill.packet, &bad).is_err());
        let old_consent = bad.consent;
        let packet = rebind(&mut bad);
        bad.consent = old_consent;
        assert_eq!(verify_owner_relation(&packet, &bad), Err(RelationError::Signature));
    }
    let mut packet = fill.packet.clone(); packet.outputs.swap(0, 1);
    assert!(verify_owner_relation(&packet, &fill.a).is_err());
    // An owner can validate its leg without possessing the other owner's seed,
    // keys or openings, but an altered whole-manifest journal cannot be paired.
    let mut changed = fill.a.clone();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut changed.packet.outputs[4] { ciphertext[24] ^= 1; }
    let changed_packet = rebind(&mut changed);
    let changed_a = verify_owner_relation(&changed_packet, &changed).unwrap();
    let original_b = verify_owner_relation(&fill.packet, &fill.b).unwrap();
    assert!(validate_pair(&changed_packet, &changed_a, &original_b).is_err());
}

#[test]
fn cancellation_uses_the_real_input_same_fill_nullifier_and_separate_exit_domain() {
    let fill = known_fill();
    let fill_journal = verify_owner_relation(&fill.packet, &fill.a).unwrap();
    for action in [Action::Cancel, Action::Exit] {
        let witness = cancel_exit(&fill, action);
        let journal = verify_cancel_exit_relation(&witness).unwrap();
        assert_eq!(journal.input_nullifier, fill_journal.input_nullifier);
        assert_eq!(journal.generation, fill_journal.generation);
        assert_eq!(journal.action, action);
        validate_single(&witness.packet, &journal, Role::A, action).unwrap();
        assert_eq!(CancelExitWitness::decode(&witness.encode().unwrap()).unwrap(), witness);
        let mut replay = witness.clone();
        replay.action = if action == Action::Cancel { Action::Exit } else { Action::Cancel };
        assert_eq!(verify_cancel_exit_relation(&replay), Err(RelationError::Signature));
        let mut fill_signature = witness.clone(); fill_signature.consent = fill.a.consent;
        assert_eq!(verify_cancel_exit_relation(&fill_signature), Err(RelationError::Signature));
        let mut wrong_head = witness.clone(); wrong_head.packet.input.generation += 1;
        assert!(verify_cancel_exit_relation(&wrong_head).is_err());
    }
}

#[test]
fn cancellation_returns_ordinary_notes_conserves_only_real_assets_and_enforces_policy() {
    let fill = known_fill();
    for change in 0..5 {
        let mut witness = cancel_exit(&fill, Action::Cancel);
        match change {
            0 => witness.owned_outputs[0].note.value += U256::one(),
            1 => witness.owned_outputs[0].note.order = witness.input.order.clone(),
            2 => witness.owned_outputs[0].note.asset = Asset::Token([7; 20]),
            3 => witness.owned_outputs[0].note.owner_key = fill.b.input.owner_key,
            _ => {
                witness.packet.outputs.push(OutputDescriptor::Fee { payer: Role::A,
                    asset: Asset::Native, recipient: [10; 20], amount: U256::one() });
            },
        }
        if change < 4 {
            witness.packet.outputs[0] = prepare_output(&witness.owned_outputs[0].note, Role::A,
                &witness.owned_outputs[0].recovery_key, [154; 24]).unwrap();
        }
        witness.packet.terms_commitment = ziquid_protocol::samechain::single_terms_commitment(
            &witness.packet.deployment, &witness.packet.input, &witness.packet.outputs,
            witness.packet.expiry, &witness.blind).unwrap();
        witness.consent = SigningKey::from_bytes(&witness.owner_seed)
            .sign(&single_consent_message(&witness.packet, witness.role, witness.action).unwrap()).to_bytes();
        assert!(verify_cancel_exit_relation(&witness).is_err());
    }
    let mut missing = cancel_exit(&fill, Action::Cancel); missing.owned_outputs.clear();
    assert_eq!(verify_cancel_exit_relation(&missing), Err(RelationError::Manifest));
    let mut fill_action = cancel_exit(&fill, Action::Cancel); fill_action.action = Action::Fill;
    assert_eq!(verify_cancel_exit_relation(&fill_action), Err(RelationError::Action));
}

#[test]
fn private_canonical_codecs_are_bounded_full_consuming_and_redacted() {
    let fill = known_fill();
    let encoded = fill.a.encode().unwrap();
    assert!(encoded.len() < MAX_PRIVATE_INPUT_BYTES);
    assert_eq!(format!("{:?}", fill.a), "OwnerWitness([REDACTED])");
    assert_eq!(format!("{:?}", fill.a.input), "NoteOpening([REDACTED])");
    assert_eq!(format!("{:?}", fill.a.owned_outputs[0]), "PreparedOutputOpening([REDACTED])");
    for length in [0, 1, 20, encoded.len() - 1] {
        assert!(OwnerWitness::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.to_vec(); trailing.push(0);
    assert_eq!(OwnerWitness::decode(&trailing), Err(RelationError::Encoding));
    let mut wrong_domain = encoded.to_vec(); wrong_domain[0] ^= 1;
    assert_eq!(OwnerWitness::decode(&wrong_domain), Err(RelationError::Encoding));
    let mut wrong_version = encoded.to_vec();
    wrong_version[b"Z2Z_SAMECHAIN_OWNER_WITNESS\0".len() + 1] = 1;
    assert_eq!(OwnerWitness::decode(&wrong_version), Err(RelationError::Encoding));
    let mut excessive_packet = encoded.to_vec();
    let offset = b"Z2Z_SAMECHAIN_OWNER_WITNESS\0".len() + 2;
    excessive_packet[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(OwnerWitness::decode(&excessive_packet), Err(RelationError::ResourceLimit));
    let packet_len = u32::from_be_bytes(encoded[offset..offset + 4].try_into().unwrap()) as usize;
    let execution_offset = offset + 4 + packet_len;
    let mut excessive_execution = encoded.to_vec();
    excessive_execution[execution_offset..execution_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(OwnerWitness::decode(&excessive_execution), Err(RelationError::ResourceLimit));
    let mut legacy_execution = encoded.to_vec();
    legacy_execution[execution_offset + 4 + b"Z2Z_SAMECHAIN_FILL_EXECUTION\0".len() + 1] = 1;
    assert_eq!(OwnerWitness::decode(&legacy_execution),
        Err(RelationError::Protocol(SamechainError::UnsupportedSchema)));
    let mut old_packet = encoded.to_vec();
    old_packet[offset + 4 + b"Z2Z_SAMECHAIN_PUBLIC_PACKET\0".len() + 1] = 2;
    assert_eq!(OwnerWitness::decode(&old_packet),
        Err(RelationError::Protocol(SamechainError::UnsupportedSchema)));
    assert_eq!(OwnerWitness::decode(&vec![0; MAX_PRIVATE_INPUT_BYTES + 1]),
        Err(RelationError::ResourceLimit));
    let note = &fill.a.input;
    assert_eq!(NoteOpening::decode(&note.encode().unwrap()).unwrap(), *note);
    let mut note_trailing = note.encode().unwrap(); note_trailing.push(0);
    assert_eq!(NoteOpening::decode(&note_trailing), Err(RelationError::Encoding));
    let single = cancel_exit(&fill, Action::Cancel);
    assert!(OwnerWitness::decode(&single.encode().unwrap()).is_err());
    assert!(CancelExitWitness::decode(&encoded).is_err());
}

#[test]
fn membership_uses_all_32_ordered_levels_and_exact_tree_leaf_context() {
    let fill = known_fill();
    let membership = &fill.a.membership;
    let dep = &fill.a.input.deployment_digest;
    let commitment = fill.a.input.commitment().unwrap();
    let mut leaf = b"Z2Z_SAMECHAIN_MERKLE_LEAF\0".to_vec();
    leaf.extend_from_slice(&1_u16.to_be_bytes()); leaf.extend_from_slice(dep);
    leaf.extend_from_slice(&membership.tree_id.to_be_bytes());
    leaf.extend_from_slice(&membership.index.to_be_bytes()); leaf.extend_from_slice(&commitment);
    let mut current: [u8; 32] = Sha256::digest(leaf).into();
    for (depth, sibling) in membership.siblings.iter().enumerate() {
        let mut node = b"Z2Z_SAMECHAIN_MERKLE_NODE\0".to_vec();
        node.extend_from_slice(&1_u16.to_be_bytes());
        let (left, right) = if (membership.index >> depth) & 1 == 0 {
            (&current, sibling)
        } else { (sibling, &current) };
        node.extend_from_slice(left); node.extend_from_slice(right);
        current = Sha256::digest(node).into();
    }
    assert_eq!(membership.root(dep, &commitment), current);
    assert_eq!(fill.packet.inputs[0].root, current);
    let mut changed = membership.clone(); changed.index ^= 1 << 31;
    assert_ne!(changed.root(dep, &commitment), current);
    let mut changed = membership.clone(); changed.siblings.swap(0, 31);
    assert_ne!(changed.root(dep, &commitment), current);
}

#[test]
fn exact_note_consent_and_journal_bytes_are_independently_consumable() {
    let fill = known_fill();
    let note = &fill.a.owned_outputs[1].note;
    let mut body = vec![];
    for bytes in [&note.salt, &note.deployment_digest, &note.owner_key, &note.nf_key, &note.nonce] {
        body.extend_from_slice(bytes);
    }
    body.push(1); body.extend_from_slice(&[7; 20]);
    body.extend_from_slice(&[0; 31]); body.push(49); body.push(0);
    let mut frame = b"Z2Z_SAMECHAIN_NOTE_OPENING\0".to_vec();
    frame.extend_from_slice(&1_u16.to_be_bytes()); frame.extend_from_slice(&body);
    assert_eq!(note.encode().unwrap().as_slice(), frame);
    let mut committed = b"Z2Z_SAMECHAIN_NOTE_COMMITMENT\0".to_vec();
    committed.extend_from_slice(&1_u16.to_be_bytes()); committed.extend_from_slice(&body);
    assert_eq!(note.commitment().unwrap(), <[u8; 32]>::from(Sha256::digest(committed)));
    let mut consent = b"Z2Z_SAMECHAIN_OWNER_CONSENT\0".to_vec();
    consent.extend_from_slice(&1_u16.to_be_bytes());
    consent.extend_from_slice(&2_u16.to_be_bytes()); consent.extend_from_slice(&[0, 0]);
    consent.extend_from_slice(&fill.packet.deployment.digest().unwrap());
    consent.extend_from_slice(&fill.packet.terms_commitment);
    consent.extend_from_slice(&<[u8; 32]>::from(Sha256::digest(fill.packet.encode().unwrap())));
    assert_eq!(fill_consent_message(&fill.packet, Role::A).unwrap().as_slice(), consent);
    let journal = verify_owner_relation(&fill.packet, &fill.a).unwrap();
    let input = &fill.packet.inputs[0];
    let mut public = b"Z2Z_SAMECHAIN_OWNER_JOURNAL\0".to_vec();
    public.extend_from_slice(&1_u16.to_be_bytes());
    public.extend_from_slice(&2_u16.to_be_bytes()); public.extend_from_slice(&[0, 0]);
    public.extend_from_slice(&journal.deployment_digest);
    public.extend_from_slice(&fill.packet.terms_commitment);
    public.extend_from_slice(&journal.packet_digest);
    public.extend_from_slice(&input.nullifier); public.extend_from_slice(&input.commitment);
    public.extend_from_slice(&input.root); public.extend_from_slice(&9_u32.to_be_bytes());
    public.extend_from_slice(&0_u32.to_be_bytes()); public.extend_from_slice(&[11; 32]);
    public.extend_from_slice(&7_u64.to_be_bytes());
    assert_eq!(journal.encode().unwrap(), public);
}

#[test]
fn private_codec_rejects_unknown_tags_oversize_counts_and_noncanonical_order_policy() {
    let fill = known_fill();
    let frame = fill.a.encode().unwrap();
    let header_len = b"Z2Z_SAMECHAIN_OWNER_WITNESS\0".len() + 2;
    let packet_len = u32::from_be_bytes(frame[header_len..header_len + 4].try_into().unwrap()) as usize;
    let execution_offset = header_len + 4 + packet_len;
    let execution_len = u32::from_be_bytes(frame[execution_offset..execution_offset + 4].try_into().unwrap()) as usize;
    let role_offset = execution_offset + 4 + execution_len + 64 + 32;
    let mut wrong_role = frame.to_vec(); wrong_role[role_offset] = 2;
    assert_eq!(OwnerWitness::decode(&wrong_role), Err(RelationError::Encoding));
    let input_len_offset = role_offset + 1 + 32;
    let input_len = u32::from_be_bytes(frame[input_len_offset..input_len_offset + 4].try_into().unwrap()) as usize;
    let outputs_count = input_len_offset + 4 + input_len + 8 + 1024 + 64;
    let mut too_many = frame.to_vec();
    too_many[outputs_count..outputs_count + 4].copy_from_slice(&9_u32.to_be_bytes());
    assert_eq!(OwnerWitness::decode(&too_many), Err(RelationError::ResourceLimit));
    let mut too_many_with_bad_note = too_many.clone();
    too_many_with_bad_note[input_len_offset + 4] ^= 1;
    // Resource/EOF shape checks happen before decoding the secret note buffers.
    assert_eq!(OwnerWitness::decode(&too_many_with_bad_note), Err(RelationError::ResourceLimit));
    let mut trailing_with_bad_note = frame.to_vec();
    trailing_with_bad_note[input_len_offset + 4] ^= 1;
    trailing_with_bad_note.push(0);
    assert_eq!(OwnerWitness::decode(&trailing_with_bad_note), Err(RelationError::Encoding));
    let mut note = fill.a.input.encode().unwrap();
    let asset_offset = b"Z2Z_SAMECHAIN_NOTE_OPENING\0".len() + 2 + 160;
    note[asset_offset] = 2;
    assert_eq!(NoteOpening::decode(&note), Err(RelationError::Encoding));
    let mut note = fill.a.input.encode().unwrap();
    note[asset_offset + 1 + 32] = 2;
    assert_eq!(NoteOpening::decode(&note), Err(RelationError::Encoding));
    let order = fill.a.input.order.as_ref().unwrap();
    assert_eq!(OrderState::decode(&order.encode().unwrap()).unwrap(), *order);
    let mut changed = order.clone(); changed.policy.fee_policy.entries.push(changed.policy.fee_policy.entries[0]);
    assert!(changed.encode().is_err());
    let mut weak = fill.a.input.clone();
    weak.owner_key = [0; 32]; weak.owner_key[0] = 1;
    assert_eq!(weak.commitment(), Err(RelationError::Key));
    let mut zero = fill.a.input.clone(); zero.nf_key = [0; 32];
    assert_eq!(zero.commitment(), Err(RelationError::Note));
    let single = cancel_exit(&fill, Action::Cancel);
    let mut single_wire = single.encode().unwrap();
    let head = b"Z2Z_SAMECHAIN_CANCEL_EXIT_WITNESS\0".len() + 2;
    let len = u32::from_be_bytes(single_wire[head..head + 4].try_into().unwrap()) as usize;
    single_wire[head + 4 + len + 32 + 1] = 3;
    assert_eq!(CancelExitWitness::decode(&single_wire), Err(RelationError::Encoding));
}

#[test]
fn sell_asset_fees_are_conserved_and_capacity_cannot_be_reset() {
    let fill = known_fill();
    let mut paid = fill.a.clone();
    paid.input.order.as_mut().unwrap().policy.fee_policy.entries.insert(0,
        ziquid_protocol::samechain::FeeRule { payer: Role::A, asset: Asset::Native,
            beneficiary: [6; 20], max_atoms: U256::from(2) });
    let policy = paid.input.order.as_ref().unwrap().policy.clone();
    paid.packet.inputs[0] = support::descriptor(&paid.input, &paid.membership);
    paid.owned_outputs[0].note.order.as_mut().unwrap().policy = policy;
    paid.owned_outputs[0].note.value -= U256::from(2);
    replace_note(&mut paid, 0);
    paid.packet.outputs.insert(2, OutputDescriptor::Fee { payer: Role::A,
        asset: Asset::Native, recipient: [6; 20], amount: U256::from(2) });
    let packet = rebind(&mut paid);
    verify_owner_relation(&packet, &paid).unwrap();
    paid.owned_outputs[0].note.value += U256::from(2);
    replace_note(&mut paid, 0);
    let packet = rebind(&mut paid);
    assert_eq!(verify_owner_relation(&packet, &paid), Err(RelationError::Conservation));
    let mut overdraft = fill.a.clone();
    overdraft.input.order.as_mut().unwrap().remaining_sell = U256::from(39);
    overdraft.packet.inputs[0] = support::descriptor(&overdraft.input, &overdraft.membership);
    let packet = rebind(&mut overdraft);
    assert_eq!(verify_owner_relation(&packet, &overdraft), Err(RelationError::Successor));
    let mut extra_order = fill.a.clone();
    // A second same-asset order note with one atom, plus 64 in the real
    // successor, conserves money but would create duplicate backing capacity.
    let second = support::note(Role::A, 161, Asset::Native, U256::one(), Some(OrderState {
        id: extra_order.input.order.as_ref().unwrap().id, generation: 8,
        remaining_sell: U256::one(), policy: extra_order.input.order.as_ref().unwrap().policy.clone(),
    }));
    extra_order.owned_outputs[0].note.value -= U256::one();
    replace_note(&mut extra_order, 0);
    let manifest_index = extra_order.packet.outputs.len() as u32;
    extra_order.packet.outputs.push(prepare_output(&second, Role::A, &[162; 32], [163; 24]).unwrap());
    extra_order.owned_outputs.push(ziquid_proofs::samechain::PreparedOutputOpening {
        manifest_index, note: second, recovery_key: [162; 32],
    });
    let packet = rebind(&mut extra_order);
    assert_eq!(verify_owner_relation(&packet, &extra_order), Err(RelationError::Successor));
}

#[test]
fn authenticated_empty_and_zero_fee_caps_allow_no_fee_but_never_authorize_positive_payments() {
    let fill = wide_fill();
    for role in [Role::A, Role::B] {
        let mut owner = if role == Role::A { fill.a.clone() } else { fill.b.clone() };
        verify_owner_relation(&owner.packet, &owner).unwrap();
        let buy_asset = owner.input.order.as_ref().unwrap().policy.buy_asset;
        owner.input.order.as_mut().unwrap().policy.fee_policy.entries.push(
            ziquid_protocol::samechain::FeeRule { payer: role, asset: buy_asset,
                beneficiary: [8; 20], max_atoms: U256::zero() });
        owner.packet.inputs[role.index()] = support::descriptor(&owner.input, &owner.membership);
        let packet = rebind(&mut owner);
        verify_owner_relation(&packet, &owner).unwrap();
        owner.packet.outputs.push(OutputDescriptor::Fee { payer: role, asset: buy_asset,
            recipient: [8; 20], amount: U256::one() });
        let packet = rebind(&mut owner);
        assert_eq!(verify_owner_relation(&packet, &owner),
            Err(RelationError::Protocol(SamechainError::FeeCapExceeded)));
        owner.input.order.as_mut().unwrap().policy.fee_policy.entries.clear();
        owner.packet.inputs[role.index()] = support::descriptor(&owner.input, &owner.membership);
        let packet = rebind(&mut owner);
        assert_eq!(verify_owner_relation(&packet, &owner),
            Err(RelationError::Protocol(SamechainError::UnlistedFee)));
    }
}

#[test]
fn full_width_buy_fee_sums_and_checked_net_subtraction_never_wrap_or_narrow() {
    let fill = wide_fill();
    let mut owner = fill.a.clone();
    let policy = &mut owner.input.order.as_mut().unwrap().policy;
    policy.min_buy_num = U256::one();
    policy.min_sell_den = U256::MAX;
    policy.fee_policy.entries = vec![
        ziquid_protocol::samechain::FeeRule { payer: Role::A, asset: Asset::Token([7; 20]),
            beneficiary: [8; 20], max_atoms: U256::MAX },
        ziquid_protocol::samechain::FeeRule { payer: Role::A, asset: Asset::Token([7; 20]),
            beneficiary: [9; 20], max_atoms: U256::MAX },
    ];
    owner.packet.inputs[0] = support::descriptor(&owner.input, &owner.membership);
    owner.owned_outputs[0].note.value = U256::one();
    replace_note(&mut owner, 0);
    owner.packet.outputs.push(OutputDescriptor::Fee { payer: Role::A, asset: Asset::Token([7; 20]),
        recipient: [8; 20], amount: U256::MAX - U256::one() });
    let packet = rebind(&mut owner);
    // MAX credit minus (MAX-1) fee is one atom, and 1*MAX >= MAX*1 exactly.
    verify_owner_relation(&packet, &owner).unwrap();
    if let OutputDescriptor::Fee { amount, .. } = &mut owner.packet.outputs[2] {
        *amount = U256::MAX;
    }
    owner.packet.outputs.push(OutputDescriptor::Fee { payer: Role::A, asset: Asset::Token([7; 20]),
        recipient: [9; 20], amount: U256::one() });
    let packet = rebind(&mut owner);
    // Each listed key is within its cap, but the U512 sum exceeds MAX credit.
    assert_eq!(verify_owner_relation(&packet, &owner),
        Err(RelationError::Protocol(SamechainError::LimitNotMet)));
}

#[test]
fn owner_exit_asset_allowlist_and_both_role_buy_fees_use_the_authentic_policy() {
    let fill = known_fill();
    let mut buy_exit = fill.a.clone();
    buy_exit.owned_outputs[1].note.value -= U256::one();
    replace_note(&mut buy_exit, 1);
    buy_exit.packet.outputs.push(OutputDescriptor::Exit { role: Role::A, asset: Asset::Token([7; 20]),
        recipient: [9; 20], amount: U256::one() });
    let packet = rebind(&mut buy_exit);
    verify_owner_relation(&packet, &buy_exit).unwrap();
    let mut wrong = fill.a.clone();
    wrong.packet.outputs.push(OutputDescriptor::Exit { role: Role::A, asset: Asset::Token([9; 20]),
        recipient: [9; 20], amount: U256::one() });
    let packet = rebind(&mut wrong);
    assert_eq!(verify_owner_relation(&packet, &wrong),
        Err(RelationError::Protocol(SamechainError::InvalidOutput)));
    let mut b_fee = fill.b.clone();
    b_fee.owned_outputs[1].note.value -= U256::one();
    replace_note(&mut b_fee, 1);
    b_fee.packet.outputs.push(OutputDescriptor::Fee { payer: Role::B, asset: Asset::Native,
        recipient: [8; 20], amount: U256::one() });
    let packet = rebind(&mut b_fee);
    verify_owner_relation(&packet, &b_fee).unwrap();
    if let OutputDescriptor::Fee { amount, .. } = b_fee.packet.outputs.last_mut().unwrap() {
        *amount = U256::from(2);
    }
    let packet = rebind(&mut b_fee);
    assert_eq!(verify_owner_relation(&packet, &b_fee),
        Err(RelationError::Protocol(SamechainError::FeeCapExceeded)));
}

#[test]
fn exact_execution_assets_cannot_replace_the_committed_owner_assets_even_with_fresh_consent() {
    let fill = known_fill();
    for mut owner in [fill.a.clone(), fill.b.clone()] {
        owner.execution.asset_a = Asset::Token([9; 20]);
        owner.packet.terms_commitment = aggregate_commitment(&owner.packet,
            &owner.execution, &owner.leaves).unwrap();
        owner.consent = SigningKey::from_bytes(&owner.owner_seed)
            .sign(&fill_consent_message(&owner.packet, owner.role).unwrap()).to_bytes();
        assert_eq!(verify_owner_relation(&owner.packet, &owner),
            Err(RelationError::Protocol(SamechainError::InvalidPolicy)));
    }
}

#[test]
fn generation_max_is_valid_for_exhausted_orders_and_never_wraps_partial_successors() {
    let mut fill = wide_fill();
    for owner in [&mut fill.a, &mut fill.b] {
        owner.input.order.as_mut().unwrap().generation = u64::MAX;
        fill.packet.inputs[owner.role.index()] = support::descriptor(&owner.input, &owner.membership);
    }
    support::bind_pair(&mut fill);
    let a = verify_owner_relation(&fill.packet, &fill.a).unwrap();
    let b = verify_owner_relation(&fill.packet, &fill.b).unwrap();
    assert_eq!(a.generation, u64::MAX);
    assert_eq!(b.generation, u64::MAX);
    validate_pair(&fill.packet, &a, &b).unwrap();
    let mut partial = known_fill().a;
    partial.input.order.as_mut().unwrap().generation = u64::MAX;
    partial.packet.inputs[0] = support::descriptor(&partial.input, &partial.membership);
    let packet = rebind(&mut partial);
    assert_eq!(verify_owner_relation(&packet, &partial), Err(RelationError::Successor));
}

#[test]
fn fill_frame_field_order_is_independently_consumable_with_all_nonfill_frames_still_version_one() {
    let fill = known_fill();
    for owner in [&fill.a, &fill.b] {
        let packet = owner.packet.encode().unwrap();
        let execution = owner.execution.encode().unwrap();
        let input = owner.input.encode().unwrap();
        let mut expected = b"Z2Z_SAMECHAIN_OWNER_WITNESS\0".to_vec();
        expected.extend_from_slice(&2_u16.to_be_bytes());
        expected.extend_from_slice(&(packet.len() as u32).to_be_bytes());
        expected.extend_from_slice(&packet);
        expected.extend_from_slice(&(execution.len() as u32).to_be_bytes());
        expected.extend_from_slice(&execution);
        expected.extend_from_slice(&owner.leaves[0]);
        expected.extend_from_slice(&owner.leaves[1]);
        expected.extend_from_slice(&owner.own_salt);
        expected.push(owner.role as u8);
        expected.extend_from_slice(&owner.owner_seed);
        expected.extend_from_slice(&(input.len() as u32).to_be_bytes());
        expected.extend_from_slice(&input);
        expected.extend_from_slice(&owner.membership.tree_id.to_be_bytes());
        expected.extend_from_slice(&owner.membership.index.to_be_bytes());
        for sibling in owner.membership.siblings { expected.extend_from_slice(&sibling); }
        expected.extend_from_slice(&owner.consent);
        expected.extend_from_slice(&(owner.owned_outputs.len() as u32).to_be_bytes());
        for output in &owner.owned_outputs {
            let note = output.note.encode().unwrap();
            expected.extend_from_slice(&output.manifest_index.to_be_bytes());
            expected.extend_from_slice(&(note.len() as u32).to_be_bytes());
            expected.extend_from_slice(&note);
            expected.extend_from_slice(&output.recovery_key);
        }
        assert_eq!(owner.encode().unwrap().as_slice(), expected.as_slice());
        let note_header = b"Z2Z_SAMECHAIN_NOTE_OPENING\0".len();
        assert_eq!(&input[note_header..note_header + 2], &[0, 1]);
        let packet_header = b"Z2Z_SAMECHAIN_PUBLIC_PACKET\0".len();
        assert_eq!(&packet[packet_header..packet_header + 2], &[0, 1]);
        let execution_header = b"Z2Z_SAMECHAIN_FILL_EXECUTION\0".len();
        assert_eq!(&execution[execution_header..execution_header + 2], &[0, 2]);
        let policy = owner.input.order.as_ref().unwrap().policy.encode().unwrap();
        let policy_header = b"Z2Z_SAMECHAIN_ORDER_POLICY\0".len();
        assert_eq!(&policy[policy_header..policy_header + 2], &[0, 1]);
        let order = owner.input.order.as_ref().unwrap().encode().unwrap();
        let order_header = b"Z2Z_SAMECHAIN_ORDER_STATE\0".len();
        assert_eq!(&order[order_header..order_header + 2], &[0, 1]);
    }
    for action in [Action::Cancel, Action::Exit] {
        let owner = cancel_exit(&fill, action);
        let frame = owner.encode().unwrap();
        let header = b"Z2Z_SAMECHAIN_CANCEL_EXIT_WITNESS\0".len();
        assert_eq!(&frame[header..header + 2], &[0, 1]);
        let consent = single_consent_message(&owner.packet, owner.role, action).unwrap();
        let consent_header = b"Z2Z_SAMECHAIN_OWNER_CONSENT\0".len();
        assert_eq!(&consent[consent_header..consent_header + 4], &[0, 1, 0, 1]);
        let journal = verify_cancel_exit_relation(&owner).unwrap().encode().unwrap();
        let journal_header = b"Z2Z_SAMECHAIN_OWNER_JOURNAL\0".len();
        assert_eq!(&journal[journal_header..journal_header + 4], &[0, 1, 0, 1]);
    }
}
