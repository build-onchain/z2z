//! Public deterministic fixtures, actual signatures/AEAD and the frozen guest ABI.
//! No proving/setup or genuine wrapped-certificate qualification occurs here.
use ed25519_dalek::{Signer, SigningKey};
use primitive_types::U256;
use zeroize::Zeroizing;
use ziquid_protocol::samechain::{
    Action, OutputDescriptor, SamechainError, single_terms_commitment,
};
use ziquid_proofs::artifacts::owner::OwnerInput;
use ziquid_proofs::samechain::{
    CancelExitWitness, OwnerWitness, RelationError, single_consent_message,
    verify_cancel_exit_relation, verify_owner_relation,
};
use ziquid_proofs::samechain::creation::{
    NoteCreationWitness, verify_note_creation_relation,
};
use ziquid_proofs::samechain::withdrawal::{
    NoteWithdrawalWitness, verify_note_withdrawal_relation,
};

#[path = "support/samechain.rs"]
#[allow(dead_code)]
mod fill_support;
#[path = "support/ordinary_withdrawal.rs"]
#[allow(dead_code)]
mod withdrawal_support;
#[path = "support/note_creation.rs"]
#[allow(dead_code)]
mod creation_support;

// Consume the real outer ABI with the actual full-consuming codecs and signed
// predicates. A wrong mode, duplicate public prefix or added stdin wrapper breaks
// this consumer; it does not echo the adapter's expected journal.
fn consume_frame(frame: &[u8]) -> Result<Vec<u8>, RelationError> {
    if frame.len() > 1 + ziquid_proofs::samechain::MAX_PRIVATE_INPUT_BYTES {
        return Err(RelationError::ResourceLimit);
    }
    let (mode, body) = frame.split_first().ok_or(RelationError::Encoding)?;
    match mode {
        0 => {
            let witness = OwnerWitness::decode(body)?;
            Ok(verify_owner_relation(&witness.packet, &witness)?.encode()?)
        }
        1 => Ok(verify_cancel_exit_relation(&CancelExitWitness::decode(body)?)?.encode()?),
        2 => Ok(verify_note_withdrawal_relation(&NoteWithdrawalWitness::decode(body)?)?.encode()?),
        3 => Ok(verify_note_creation_relation(&NoteCreationWitness::decode(body)?)?.encode()?),
        _ => Err(RelationError::Encoding),
    }
}

fn accepted(input: &OwnerInput<'_>, mode: u8, expected: Vec<u8>) {
    let frame: Zeroizing<Vec<u8>> = input.encode_private().unwrap();
    assert_eq!(frame[0], mode);
    if mode != 0 {
        let domain: &[u8] = match mode {
            1 => b"Z2Z_SAMECHAIN_CANCEL_EXIT_WITNESS\0",
            2 => b"Z2Z_SAMECHAIN_NOTE_WITHDRAWAL_WITNESS\0",
            3 => b"Z2Z_SAMECHAIN_NOTE_CREATION_WITNESS\0",
            _ => unreachable!(),
        };
        assert_eq!(&frame[1..1 + domain.len()], domain);
        assert_eq!(&frame[1 + domain.len()..1 + domain.len() + 2], &[0, 1]);
    }
    assert_eq!(input.expected_journal().unwrap(), expected);
    assert_eq!(consume_frame(&frame).unwrap(), expected);
    assert_eq!(input.deployment(), &fill_support::deployment());
    // No trailing bytes may silently fall outside the signed guest relation.
    let mut trailing = Zeroizing::new(Vec::with_capacity(frame.len() + 1));
    trailing.extend_from_slice(&frame);
    trailing.push(0);
    assert_eq!(consume_frame(&trailing), Err(RelationError::Encoding));
}

fn rejected_but_transportable(input: &OwnerInput<'_>, error: RelationError) {
    assert_eq!(input.expected_journal(), Err(error));
    // CPU guest-negative callers must be able to bypass host semantic preflight
    // using this shape-only frame, then call execute_private on the actual ELF.
    let frame: Zeroizing<Vec<u8>> = input.encode_private().unwrap();
    assert_eq!(consume_frame(&frame), Err(error));
}

#[test]
fn all_owner_modes_feed_the_exact_guest_abi_and_actual_signed_relations() {
    let fill = fill_support::known_fill();
    for witness in [&fill.a, &fill.b] {
        accepted(&OwnerInput::Fill(witness), 0,
            verify_owner_relation(&fill.packet, witness).unwrap().encode().unwrap());
    }
    for action in [Action::Cancel, Action::Exit] {
        let witness = fill_support::cancel_exit(&fill, action);
        accepted(&OwnerInput::CancelExit(&witness), 1,
            verify_cancel_exit_relation(&witness).unwrap().encode().unwrap());
    }
    let partial = withdrawal_support::received_token_partial();
    let change = withdrawal_support::change_withdrawal(&partial);
    for witness in [partial, change, withdrawal_support::received_native_full(),
        withdrawal_support::cancelled_native_partial()]
    {
        accepted(&OwnerInput::Withdrawal(&witness), 2,
            verify_note_withdrawal_relation(&witness).unwrap().encode().unwrap());
    }
    for witness in [creation_support::ordinary_native(), creation_support::ordinary_token(),
        creation_support::initial_order_a(), creation_support::initial_order_b()]
    {
        accepted(&OwnerInput::Creation(&witness), 3,
            verify_note_creation_relation(&witness).unwrap().encode().unwrap());
    }
}

#[test]
fn fill_mode_is_one_witness_copy_and_rejects_legacy_prefix_or_version_one() {
    let fill = fill_support::known_fill();
    for owner in [&fill.a, &fill.b] {
        let witness = owner.encode().unwrap();
        let frame = OwnerInput::Fill(owner).encode_private().unwrap();
        assert_eq!(frame.len(), 1 + witness.len());
        assert_eq!(&frame[1..], witness.as_slice());
        assert_eq!(&witness[..b"Z2Z_SAMECHAIN_OWNER_WITNESS\0".len()],
            b"Z2Z_SAMECHAIN_OWNER_WITNESS\0");
        let header = b"Z2Z_SAMECHAIN_OWNER_WITNESS\0".len();
        assert_eq!(&witness[header..header + 2], &[0, 2]);
        let packet_offset = header + 2;
        let packet_len = u32::from_be_bytes(witness[packet_offset..packet_offset + 4]
            .try_into().unwrap()) as usize;
        assert_eq!(&witness[packet_offset + 4..packet_offset + 4 + packet_len],
            owner.packet.encode().unwrap());
        let execution_offset = packet_offset + 4 + packet_len;
        let execution_len = u32::from_be_bytes(witness[execution_offset..execution_offset + 4]
            .try_into().unwrap()) as usize;
        assert_eq!(&witness[execution_offset + 4..execution_offset + 4 + execution_len],
            owner.execution.encode().unwrap());
        let mut old_version = frame.to_vec();
        old_version[1 + header + 1] = 1;
        assert_eq!(consume_frame(&old_version), Err(RelationError::Encoding));
        let packet = owner.packet.encode().unwrap();
        let mut old_prefix = vec![0];
        old_prefix.extend_from_slice(&(packet.len() as u32).to_be_bytes());
        old_prefix.extend_from_slice(&packet);
        old_prefix.extend_from_slice(&witness);
        assert_eq!(consume_frame(&old_prefix), Err(RelationError::Encoding));
    }
    assert_eq!(consume_frame(&vec![0; 2 + ziquid_proofs::samechain::MAX_PRIVATE_INPUT_BYTES]),
        Err(RelationError::ResourceLimit));
}

#[test]
fn freshly_bound_fee_caps_allowlists_and_net_limits_are_guest_predicates_not_encoder_checks() {
    let fill = fill_support::known_fill();
    for mutation in 0..3 {
        let mut owner = fill.a.clone();
        let expected = match mutation {
            0 => {
                if let OutputDescriptor::Fee { amount, .. } = &mut owner.packet.outputs[2] {
                    *amount = U256::from(2);
                }
                SamechainError::FeeCapExceeded
            }
            1 => {
                if let OutputDescriptor::Fee { recipient, .. } = &mut owner.packet.outputs[2] {
                    *recipient = [9; 20];
                }
                SamechainError::UnlistedFee
            }
            _ => {
                let policy = &mut owner.input.order.as_mut().unwrap().policy;
                policy.min_buy_num = U256::from(5);
                policy.min_sell_den = U256::from(4);
                owner.owned_outputs[0].note.order.as_mut().unwrap().policy = policy.clone();
                owner.packet.inputs[0] = fill_support::descriptor(&owner.input, &owner.membership);
                fill_support::replace_note(&mut owner, 0);
                SamechainError::LimitNotMet
            }
        };
        fill_support::rebind(&mut owner);
        rejected_but_transportable(&OwnerInput::Fill(&owner), RelationError::Protocol(expected));
    }
}

#[test]
fn every_native_mode_checks_actual_consent_without_blocking_shape_transport() {
    let mut fill = fill_support::known_fill();
    let mut cancel = fill_support::cancel_exit(&fill, Action::Cancel);
    let mut withdrawal = withdrawal_support::received_token_partial();
    let mut creation = creation_support::ordinary_native();
    for input in [OwnerInput::Fill(&fill.a),
        OwnerInput::CancelExit(&cancel), OwnerInput::Withdrawal(&withdrawal),
        OwnerInput::Creation(&creation)]
    {
        input.expected_journal().unwrap();
    }
    fill.a.consent[0] ^= 1;
    cancel.consent[0] ^= 1;
    withdrawal.consent[0] ^= 1;
    creation.consent[0] ^= 1;
    for input in [OwnerInput::Fill(&fill.a),
        OwnerInput::CancelExit(&cancel), OwnerInput::Withdrawal(&withdrawal),
        OwnerInput::Creation(&creation)]
    {
        rejected_but_transportable(&input, RelationError::Signature);
    }
}

#[test]
fn fresh_correct_consent_does_not_approve_ciphertext_inflation_or_wrong_openings() {
    let mut fill = fill_support::known_fill();
    OwnerInput::Fill(&fill.a).expected_journal().unwrap();
    if let OutputDescriptor::Note { ciphertext, .. } = &mut fill.a.packet.outputs[0] {
        ciphertext[30] ^= 1;
    } else { unreachable!(); }
    fill_support::rebind(&mut fill.a);
    rejected_but_transportable(&OwnerInput::Fill(&fill.a), RelationError::Ciphertext);

    let fill = fill_support::known_fill();
    let mut cancel = fill_support::cancel_exit(&fill, Action::Exit);
    OwnerInput::CancelExit(&cancel).expected_journal().unwrap();
    if let OutputDescriptor::Exit { amount, .. } = &mut cancel.packet.outputs[1] {
        *amount += U256::one();
    } else { unreachable!(); }
    cancel.packet.terms_commitment = single_terms_commitment(
        &cancel.packet.deployment, &cancel.packet.input, &cancel.packet.outputs,
        cancel.packet.expiry, &cancel.blind,
    ).unwrap();
    cancel.consent = SigningKey::from_bytes(&cancel.owner_seed).sign(
        &single_consent_message(&cancel.packet, cancel.role, cancel.action).unwrap(),
    ).to_bytes();
    rejected_but_transportable(&OwnerInput::CancelExit(&cancel), RelationError::Conservation);

    let mut withdrawal = withdrawal_support::received_token_partial();
    OwnerInput::Withdrawal(&withdrawal).expected_journal().unwrap();
    withdrawal.owned_outputs[0].note.value += U256::one();
    withdrawal_support::replace_change(&mut withdrawal, 0);
    withdrawal_support::rebind(&mut withdrawal);
    rejected_but_transportable(&OwnerInput::Withdrawal(&withdrawal), RelationError::Conservation);
    withdrawal = withdrawal_support::received_token_partial();
    withdrawal.blind = [133; 32];
    withdrawal_support::resign(&mut withdrawal);
    rejected_but_transportable(&OwnerInput::Withdrawal(&withdrawal),
        RelationError::Protocol(SamechainError::OpeningMismatch));

    let mut creation = creation_support::ordinary_native();
    OwnerInput::Creation(&creation).expected_journal().unwrap();
    creation.packet.amount = U256::one(); // actual note still holds 100 atoms
    creation_support::rebind(&mut creation);
    rejected_but_transportable(&OwnerInput::Creation(&creation), RelationError::Note);
}

#[test]
fn restored_partial_remainder_cancel_consumes_generation_eight_not_original_input() {
    use ziquid_protocol::samechain::tree::NoteTree;
    use ziquid_proofs::samechain::{MerkleMembership, decrypt_output};

    let fill = fill_support::known_fill();
    let deployment = fill.packet.deployment.digest().unwrap();
    let mut tree = NoteTree::new(deployment, 9).unwrap();
    tree.append(fill.a.input.commitment().unwrap()).unwrap();
    tree.append(fill.b.input.commitment().unwrap()).unwrap();
    let descriptor = fill.packet.outputs[0].clone();
    let key = Zeroizing::new(fill.a.owned_outputs[0].recovery_key);
    let owner = fill.a.input.owner_key;
    let commitment = match &descriptor {
        OutputDescriptor::Note { commitment, .. } => *commitment,
        _ => unreachable!(),
    };
    let insertion = tree.append(commitment).unwrap();
    // Drop the original typed successor before reconstructing from retained bytes.
    drop(fill);
    let restored = decrypt_output(&descriptor, &key, &deployment, &owner).unwrap();
    let membership = MerkleMembership { tree_id: insertion.tree_id,
        index: insertion.index, siblings: insertion.siblings };
    assert_eq!(restored.order.as_ref().unwrap().generation, 8);
    assert_eq!(restored.value, U256::from(65));
    assert_eq!(membership.root(&deployment, &commitment), insertion.root);
    let cancel = fill_support::cancel_exit_from_note(restored, membership,
        ziquid_protocol::samechain::Role::A, [21; 32], Action::Cancel);
    assert_eq!(cancel.packet.input.commitment, commitment);
    assert_eq!(cancel.packet.input.generation, 8);
    assert_eq!(cancel.packet.input.root, insertion.root);
    accepted(&OwnerInput::CancelExit(&cancel), 1,
        verify_cancel_exit_relation(&cancel).unwrap().encode().unwrap());
}

// MATHEMATICAL_NOT_ADMITTED: deterministic fixture history, never authority state.
fn mathematical_membership(insertion: &ziquid_protocol::samechain::tree::NoteInsertion)
    -> ziquid_proofs::samechain::MerkleMembership
{
    ziquid_proofs::samechain::MerkleMembership { tree_id: insertion.tree_id,
        index: insertion.index, siblings: insertion.siblings }
}

type AppendTranscript = Vec<(OutputDescriptor, ziquid_protocol::samechain::tree::NoteInsertion)>;

fn append_public_notes(tree: &mut ziquid_protocol::samechain::tree::NoteTree,
    transcript: &mut AppendTranscript, outputs: &[OutputDescriptor])
{
    for output in outputs {
        if let OutputDescriptor::Note { commitment, .. } = output {
            let bytes = output.encode().unwrap();
            let retained = OutputDescriptor::decode(&bytes).unwrap();
            assert_eq!(retained.encode().unwrap(), bytes);
            transcript.push((retained, tree.append(*commitment).unwrap()));
        }
    }
}

fn replay_mathematical_transcript(transcript: &AppendTranscript, count: u64,
    root: [u8; 32]) -> Result<Vec<ziquid_protocol::samechain::tree::NoteInsertion>, RelationError>
{
    use ziquid_protocol::samechain::tree::NoteTree;
    let mut tree = NoteTree::new(fill_support::deployment().digest().unwrap(), 9).unwrap();
    let mut paths = Vec::with_capacity(transcript.len());
    for (output, expected) in transcript {
        let OutputDescriptor::Note { commitment, .. } = output else {
            return Err(RelationError::Output);
        };
        let actual = tree.append(*commitment).map_err(|_| RelationError::Membership)?;
        if actual != *expected { return Err(RelationError::Membership); }
        paths.push(actual);
    }
    if tree.count() != count || tree.root() != root { return Err(RelationError::Membership); }
    Ok(paths)
}

#[test]
fn controlled_mathematical_restore_links_both_owners_remainders_proceeds_and_change() {
    use ziquid_protocol::samechain::{Asset, Role, validate_pair};
    use ziquid_protocol::samechain::tree::NoteTree;
    use ziquid_proofs::samechain::decrypt_output;

    let mut fill = fill_support::known_fill();
    let a_creation = creation_support::initial_order_a();
    let mut b_creation = creation_support::initial_order_b();
    // Retain the existing exact 40-for-50 partial economics, but link genuine
    // controlled generation-one creation openings to generation-two successors.
    b_creation.note.order.as_mut().unwrap().policy =
        fill.b.input.order.as_ref().unwrap().policy.clone();
    b_creation.packet.creation_nonce = [156; 32];
    creation_support::replace_output(&mut b_creation);
    for creation in [&a_creation, &b_creation] {
        accepted(&OwnerInput::Creation(creation), 3,
            verify_note_creation_relation(creation).unwrap().encode().unwrap());
    }
    fill.a.input = a_creation.note.clone();
    fill.b.input = b_creation.note.clone();
    let deployment = fill.packet.deployment.digest().unwrap();
    let mut tree = NoteTree::new(deployment, 9).unwrap();
    let mut transcript = vec![];
    append_public_notes(&mut tree, &mut transcript, &[a_creation.packet.output.clone(),
        b_creation.packet.output.clone()]);
    for (owner, insertion) in [&mut fill.a, &mut fill.b].into_iter()
        .zip(transcript.iter().map(|entry| entry.1))
    {
        owner.membership = mathematical_membership(&insertion);
        owner.packet.inputs[owner.role.index()] = fill_support::descriptor(
            &owner.input, &owner.membership);
        owner.owned_outputs[0].note.order.as_mut().unwrap().generation = 2;
        fill_support::replace_note(owner, 0);
    }
    fill.packet.inputs = [fill.a.packet.inputs[0], fill.b.packet.inputs[1]];
    fill.packet.outputs[0] = fill.a.packet.outputs[0].clone();
    fill.packet.outputs[3] = fill.b.packet.outputs[3].clone();
    fill_support::bind_pair(&mut fill);
    let a_journal = verify_owner_relation(&fill.packet, &fill.a).unwrap();
    let b_journal = verify_owner_relation(&fill.packet, &fill.b).unwrap();
    validate_pair(&fill.packet, &a_journal, &b_journal).unwrap();
    for owner in [&fill.a, &fill.b] {
        accepted(&OwnerInput::Fill(owner), 0,
            verify_owner_relation(&fill.packet, owner).unwrap().encode().unwrap());
    }
    // Independently hand-checked conservation: the five-atom backing surplus
    // survives A's partial fill; net buy proceeds exclude the one-token fee.
    assert_eq!(fill.a.input.value, U256::from(105));
    assert_eq!(fill.b.input.value, U256::from(100));
    assert_eq!(fill.a.owned_outputs[0].note.value, U256::from(65));
    assert_eq!(fill.a.owned_outputs[1].note.value, U256::from(49));
    assert_eq!(fill.b.owned_outputs[0].note.value, U256::from(50));
    assert_eq!(fill.b.owned_outputs[1].note.value, U256::from(40));
    assert_eq!(fill.a.owned_outputs[0].note.value + fill.a.execution.sell_a, U256::from(105));
    let OutputDescriptor::Fee { amount: fill_fee, .. } = &fill.packet.outputs[2] else { unreachable!() };
    assert_eq!(fill.a.owned_outputs[1].note.value + *fill_fee, U256::from(50));
    assert_eq!(fill.b.owned_outputs[0].note.value + fill.b.execution.sell_b, U256::from(100));
    for owner in [&fill.a, &fill.b] {
        assert_eq!(owner.packet.inputs[owner.role.index()].root,
            transcript[owner.role.index()].1.root);
        assert_eq!(owner.input.order.as_ref().unwrap().generation, 1);
        for output in &owner.owned_outputs {
            assert_eq!(output.note.order.as_ref().map(|order| order.generation),
                if output.manifest_index == owner.owned_outputs[0].manifest_index { Some(2) } else { None });
            assert_ne!(output.note.nullifier().unwrap(), fill.packet.inputs[0].nullifier);
            assert_ne!(output.note.nullifier().unwrap(), fill.packet.inputs[1].nullifier);
        }
    }

    // A freshly encrypted/signed wrong successor reaches Successor, not a stale
    // signature, commitment mismatch, or corrupted AEAD tag.
    let mut wrong_successor = fill.a.clone();
    wrong_successor.owned_outputs[0].note.order.as_mut().unwrap().generation = 3;
    fill_support::replace_note(&mut wrong_successor, 0);
    fill_support::rebind(&mut wrong_successor);
    rejected_but_transportable(&OwnerInput::Fill(&wrong_successor), RelationError::Successor);
    drop(wrong_successor);

    append_public_notes(&mut tree, &mut transcript, &fill.packet.outputs);
    // Capabilities are owner-separated: no shared recovery-key bag or plaintext
    // note inventory. Only public complete descriptors go into the transcript.
    let capabilities = [&fill.a, &fill.b].map(|owner| (
        owner.role, Zeroizing::new(owner.owner_seed), owner.input.owner_key,
        owner.owned_outputs.iter().map(|entry|
            (entry.manifest_index as usize, Zeroizing::new(entry.recovery_key)))
            .collect::<Vec<_>>(),
    ));
    let public_packet = fill.packet.clone();
    drop(fill);
    drop(a_creation);
    drop(b_creation);
    let paths = replay_mathematical_transcript(&transcript, tree.count(), tree.root()).unwrap();
    let mut incomplete = transcript.clone();
    incomplete.remove(0);
    assert_eq!(replay_mathematical_transcript(&incomplete, tree.count(), tree.root()),
        Err(RelationError::Membership));
    let mut reordered = transcript.clone();
    reordered.swap(2, 3);
    assert_eq!(replay_mathematical_transcript(&reordered, tree.count(), tree.root()),
        Err(RelationError::Membership));
    let mut missing_suffix = transcript.clone();
    missing_suffix.pop();
    assert_eq!(replay_mathematical_transcript(&missing_suffix, tree.count(), tree.root()),
        Err(RelationError::Membership));

    for (role, seed, owner, keys) in capabilities {
        let [(remainder_index, remainder_key), (proceeds_index, proceeds_key)] =
            keys.as_slice() else { unreachable!() };
        let remainder_output = &public_packet.outputs[*remainder_index];
        // Missing capability cannot be recovered from public ciphertext alone.
        assert_eq!(decrypt_output(remainder_output, &[0; 32], &deployment, &owner),
            Err(RelationError::Key));
        assert_eq!(decrypt_output(remainder_output, &[250; 32], &deployment, &owner),
            Err(RelationError::Ciphertext));
        assert_eq!(decrypt_output(remainder_output, remainder_key, &[251; 32], &owner),
            Err(RelationError::Ciphertext));
        let other_owner = SigningKey::from_bytes(&[250; 32]).verifying_key().to_bytes();
        assert_eq!(decrypt_output(remainder_output, remainder_key, &deployment, &other_owner),
            Err(RelationError::Ciphertext));
        for mutation in 0..3 {
            let mut modified = remainder_output.clone();
            if let OutputDescriptor::Note { ciphertext, ciphertext_version, commitment, .. } =
                &mut modified
            {
                match mutation {
                    0 => ciphertext[30] ^= 1,
                    1 => *ciphertext_version = 2,
                    _ => commitment[0] ^= 1,
                }
            }
            assert_eq!(decrypt_output(&modified, remainder_key, &deployment, &owner),
                Err(RelationError::Ciphertext));
        }
        let remainder = decrypt_output(remainder_output, remainder_key, &deployment, &owner).unwrap();
        let proceeds = decrypt_output(&public_packet.outputs[*proceeds_index], proceeds_key,
            &deployment, &owner).unwrap();
        let (remainder_path_index, proceeds_path_index, remainder_atoms, proceeds_atoms,
            remaining, asset, buy_asset) = match role {
            Role::A => (2, 3, 65_u64, 49_u64, 60_u64, Asset::Native, Asset::Token([7; 20])),
            Role::B => (4, 5, 50_u64, 40_u64, 50_u64, Asset::Token([7; 20]), Asset::Native),
        };
        assert_eq!(remainder.value, U256::from(remainder_atoms));
        assert_eq!(remainder.asset, asset);
        assert_eq!(remainder.order.as_ref().unwrap().generation, 2);
        assert_eq!(remainder.order.as_ref().unwrap().remaining_sell, U256::from(remaining));
        assert_eq!(proceeds.value, U256::from(proceeds_atoms));
        assert_eq!(proceeds.asset, buy_asset);
        assert!(proceeds.order.is_none());
        assert_ne!(remainder.nullifier().unwrap(), public_packet.inputs[role.index()].nullifier);
        assert_ne!(proceeds.nullifier().unwrap(), public_packet.inputs[role.index()].nullifier);
        assert_ne!(remainder.nullifier().unwrap(), proceeds.nullifier().unwrap());
        for action in [Action::Cancel, Action::Exit] {
            let cancel = fill_support::cancel_exit_from_note(remainder.clone(),
                mathematical_membership(&paths[remainder_path_index]), role, *seed, action);
            assert_eq!(cancel.packet.input.generation, 2);
            assert_eq!(cancel.packet.input.index, remainder_path_index as u32);
            assert_eq!(cancel.packet.input.root, paths[remainder_path_index].root);
            assert_eq!(cancel.packet.input.nullifier, remainder.nullifier().unwrap());
            match action {
                Action::Cancel => {
                    assert_eq!(cancel.owned_outputs[0].note.value, U256::from(remainder_atoms));
                    assert!(cancel.owned_outputs[0].note.order.is_none());
                    assert_ne!(cancel.owned_outputs[0].note.nullifier().unwrap(), cancel.packet.input.nullifier);
                }
                Action::Exit => {
                    assert_eq!(cancel.packet.outputs, vec![OutputDescriptor::Exit {
                        role, asset, recipient: [9; 20], amount: U256::from(remainder_atoms) }]);
                }
                Action::Fill => unreachable!(),
            }
            accepted(&OwnerInput::CancelExit(&cancel), 1,
                verify_cancel_exit_relation(&cancel).unwrap().encode().unwrap());
            let mut wrong_path = cancel.clone();
            wrong_path.membership.index ^= 1;
            rejected_but_transportable(&OwnerInput::CancelExit(&wrong_path), RelationError::Membership);
            let mut wrong_root = cancel.clone();
            wrong_root.membership.siblings[0][0] ^= 1;
            rejected_but_transportable(&OwnerInput::CancelExit(&wrong_root), RelationError::Membership);
            let mut stale = cancel.clone();
            stale.action = if action == Action::Cancel { Action::Exit } else { Action::Cancel };
            rejected_but_transportable(&OwnerInput::CancelExit(&stale), RelationError::Signature);
        }
        // Cancel and Exit above are alternative native witnesses, not sequential
        // history. Only the independent proceeds/change branch appends below.
        let (exit, change, fee) = match role {
            Role::A => (40_u64, 8_u64, 1_u64), Role::B => (30_u64, 10_u64, 0_u64) };
        assert_eq!(exit + change + fee, proceeds_atoms);
        let mut withdrawal = withdrawal_support::from_note(proceeds, *seed,
            U256::from(exit), U256::from(change), U256::from(fee));
        // The shared old withdrawal fixture uses one fixed change identity.
        // A linked two-owner corpus must not create globally colliding NFs.
        withdrawal.owned_outputs[0].note.nf_key = [211 + role as u8; 32];
        withdrawal.owned_outputs[0].note.nonce = [213 + role as u8; 32];
        withdrawal.owned_outputs[0].note.salt = [215 + role as u8; 32];
        withdrawal_support::replace_change(&mut withdrawal, 0);
        withdrawal.membership = mathematical_membership(&paths[proceeds_path_index]);
        withdrawal_support::replace_input(&mut withdrawal);
        withdrawal_support::rebind(&mut withdrawal);
        accepted(&OwnerInput::Withdrawal(&withdrawal), 2,
            verify_note_withdrawal_relation(&withdrawal).unwrap().encode().unwrap());
        assert_eq!(withdrawal.packet.outputs[0], OutputDescriptor::Exit {
            role: Role::A, asset: buy_asset, recipient: [9; 20], amount: U256::from(exit) });
        assert_eq!(withdrawal.owned_outputs[0].note.value, U256::from(change));
        assert_eq!(withdrawal.input.value, U256::from(exit + change + fee));
        let proceeds_nullifier = withdrawal.packet.input.nullifier;
        let change_output = withdrawal.packet.outputs[1].clone();
        let change_key = Zeroizing::new(withdrawal.owned_outputs[0].recovery_key);
        append_public_notes(&mut tree, &mut transcript, &withdrawal.packet.outputs);
        drop(withdrawal); // no original change opening survives restoration
        let replay = replay_mathematical_transcript(&transcript, tree.count(), tree.root()).unwrap();
        let change_note = decrypt_output(&change_output, &change_key, &deployment, &owner).unwrap();
        assert!(change_note.order.is_none());
        assert_eq!(change_note.value, U256::from(change));
        assert_ne!(change_note.nullifier().unwrap(), public_packet.inputs[role.index()].nullifier);
        assert_ne!(change_note.nullifier().unwrap(), proceeds_nullifier);
        let mut final_withdrawal = withdrawal_support::from_note(change_note, *seed,
            U256::from(change), U256::zero(), U256::zero());
        final_withdrawal.membership = mathematical_membership(replay.last().unwrap());
        withdrawal_support::replace_input(&mut final_withdrawal);
        withdrawal_support::rebind(&mut final_withdrawal);
        accepted(&OwnerInput::Withdrawal(&final_withdrawal), 2,
            verify_note_withdrawal_relation(&final_withdrawal).unwrap().encode().unwrap());
    }
    assert_eq!(tree.count(), 8); // two inputs, four fill notes, two ordinary changes
}

#[cfg(feature = "sp1-local")]
mod local {
    use super::*;
    use sha2::{Digest, Sha256};
    use sp1_sdk::Elf;
    use std::io;
    use ziquid_proofs::artifacts::local::{
        GROTH16_VK_SHA256, OwnerCertificate, prove_owner, verify_owner_certificate,
    };

    #[tokio::test]
    async fn public_program_pin_rejections_precede_light_setup() {
        let elf = b"public invalid ELF sentinel never parsed on pin rejection";
        for pin in [[0; 32], [9; 32]] {
            assert_eq!(error_kind(ziquid_proofs::artifacts::local::owner_program(
                Elf::Static(elf), &pin,
            ).await), io::ErrorKind::InvalidInput);
        }
    }

    // Frozen Solidity scalar field bound; native pairing must not reduce n >= R.
    const SCALAR_R: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
        0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
    ];
    fn error_kind<T>(result: Result<T, Box<dyn std::error::Error + Send + Sync>>) -> io::ErrorKind {
        match result {
            Ok(_) => panic!("invalid owner certificate input accepted"),
            Err(error) => error.downcast_ref::<io::Error>().expect("categorical I/O error").kind(),
        }
    }

    #[test]
    fn on_curve_generator_proof_reaches_pairing_and_rejects_exact_release_statement() {
        use sp1_verifier::{Groth16Error, Groth16Verifier};
        use ziquid_protocol::samechain::{Action, OwnerJournal, Role};
        let deployment = fill_support::deployment();
        let journal = OwnerJournal { relation_version: 2, action: Action::Fill, role: Role::A,
            deployment_digest: deployment.digest().unwrap(), terms_commitment: [0x16; 32],
            packet_digest: [0x12; 32], input_nullifier: [0x14; 32], input_commitment: [0x17; 32],
            root: [0x18; 32], tree_id: 9, index: 1, order_id: [0x19; 32], generation: 1 }
            .encode().unwrap();
        let mut proof = [0; 256];
        proof[31] = 1; proof[63] = 2; proof[223] = 1; proof[255] = 2;
        // Pinned BN254 G2 generator, imaginary-before-real Gnark wire order.
        for (index, coordinate) in [
            "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
            "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
            "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
            "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
        ].into_iter().enumerate() {
            for (byte, pair) in coordinate.as_bytes().as_chunks::<2>().0.iter().enumerate() {
                proof[64 + index * 32 + byte] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
            }
        }
        let result = Groth16Verifier::verify_gnark_proof(&proof,
            &[[5; 32], sp1_verifier::hash_public_inputs(&journal), [0; 32],
                *sp1_verifier::VK_ROOT_BYTES, [0; 32]], *sp1_verifier::GROTH16_VK_BYTES);
        assert!(matches!(result, Err(Groth16Error::ProofVerificationFailed)), "{result:?}");
    }

    #[test]
    fn owner_certificate_requires_independent_context_and_exact_evm_header_before_pairing() {
        let witness = creation_support::ordinary_native();
        let journal = OwnerInput::Creation(&witness).expected_journal().unwrap();
        let program = witness.packet.deployment.owner_program;
        let mut bytes = vec![0; 356];
        bytes[..4].copy_from_slice(&GROTH16_VK_SHA256[..4]);
        bytes[36..68].copy_from_slice(&*sp1_verifier::VK_ROOT_BYTES);
        bytes[68..100].copy_from_slice(&[6; 32]);
        let mut certificate = OwnerCertificate { program_vkey: program,
            journal: journal.clone(), proof_bytes: bytes };
        // All-zero raw proof is deliberately INVALID. Other is generic verifier
        // rejection, not evidence that point decoding reached the pairing.
        assert_eq!(error_kind(verify_owner_certificate(&certificate, &program, &journal)),
            io::ErrorKind::Other);
        assert_eq!(error_kind(verify_owner_certificate(&certificate, &[0; 32], &journal)),
            io::ErrorKind::InvalidInput);
        assert_eq!(error_kind(verify_owner_certificate(&certificate, &[9; 32], &journal)),
            io::ErrorKind::InvalidInput);
        certificate.program_vkey = [0; 32];
        assert_eq!(error_kind(verify_owner_certificate(&certificate, &[0; 32], &journal)),
            io::ErrorKind::InvalidInput);
        for pin in [SCALAR_R, [0xff; 32]] {
            certificate.program_vkey = pin;
            assert_eq!(error_kind(verify_owner_certificate(&certificate, &pin, &journal)),
                io::ErrorKind::InvalidInput);
        }
        let mut largest_scalar = SCALAR_R;
        largest_scalar[31] -= 1;
        certificate.program_vkey = largest_scalar;
        assert_eq!(error_kind(verify_owner_certificate(&certificate, &largest_scalar, &journal)),
            io::ErrorKind::Other);
        certificate.program_vkey = program;
        certificate.journal[0] ^= 1;
        assert_eq!(error_kind(verify_owner_certificate(&certificate, &program, &journal)),
            io::ErrorKind::InvalidInput);
        certificate.journal[0] ^= 1;
        let mut different_journal = journal.clone();
        different_journal[1] ^= 1;
        assert_eq!(error_kind(verify_owner_certificate(&certificate, &program, &different_journal)),
            io::ErrorKind::InvalidInput);
        for offset in [0, 4, 35, 36, 67] {
            certificate.proof_bytes[offset] ^= 1;
            assert_eq!(error_kind(verify_owner_certificate(&certificate, &program, &journal)),
                io::ErrorKind::InvalidData);
            certificate.proof_bytes[offset] ^= 1;
        }
        for length in [0, 3, 100, 355, 357] {
            let mut malformed = certificate.proof_bytes.clone();
            malformed.resize(length, 0);
            let original = std::mem::replace(&mut certificate.proof_bytes, malformed);
            assert_eq!(error_kind(verify_owner_certificate(&certificate, &program, &journal)),
                io::ErrorKind::InvalidData);
            certificate.proof_bytes = original;
        }
        for nonce in [SCALAR_R, [0xff; 32]] {
            certificate.proof_bytes[68..100].copy_from_slice(&nonce);
            assert_eq!(error_kind(verify_owner_certificate(&certificate, &program, &journal)),
                io::ErrorKind::InvalidData);
        }
        certificate.proof_bytes[68..100].copy_from_slice(&largest_scalar);
        assert_eq!(error_kind(verify_owner_certificate(&certificate, &program, &journal)),
            io::ErrorKind::Other);
        certificate.proof_bytes[68..100].copy_from_slice(&[6; 32]);
        // A nonce is a public field, not an extra zero-header constraint.
        // Its correct pairing binding needs a genuine proof, absent here.
        certificate.proof_bytes[68] ^= 1;
        assert_eq!(error_kind(verify_owner_certificate(&certificate, &program, &journal)),
            io::ErrorKind::Other);
    }

    // Parent must inspect production preflight ordering before running this test.
    // Every case must reject before artifact lookup, ProverClient or setup.
    #[tokio::test]
    async fn owner_producer_rejects_unpinned_or_mismatched_inputs_before_heavy_setup() {
        let witness = creation_support::ordinary_native();
        let input = OwnerInput::Creation(&witness);
        let elf_bytes = b"not an SP1 ELF".to_vec();
        let elf_hash: [u8; 32] = Sha256::digest(&elf_bytes).into();
        let program = witness.packet.deployment.owner_program;
        let mut wrong_hash = elf_hash;
        wrong_hash[0] ^= 1;
        for (hash, pin) in [([0; 32], program), (elf_hash, [0; 32]),
            (elf_hash, [9; 32]), (wrong_hash, program)]
        {
            assert_eq!(error_kind(prove_owner(Elf::from(elf_bytes.clone()), &input,
                &hash, &pin).await), io::ErrorKind::InvalidInput);
        }
        // Match the packet to the noncanonical pin, so a mere mismatch guard
        // cannot hide accidental modular reduction of an independently pinned VK.
        let mut noncanonical = creation_support::ordinary_native();
        noncanonical.packet.deployment.owner_program = SCALAR_R;
        noncanonical.note.deployment_digest = noncanonical.packet.deployment.digest().unwrap();
        creation_support::replace_output(&mut noncanonical);
        let input = OwnerInput::Creation(&noncanonical);
        input.expected_journal().unwrap();
        assert_eq!(error_kind(prove_owner(Elf::from(elf_bytes), &input,
            &elf_hash, &SCALAR_R).await), io::ErrorKind::InvalidInput);
    }
}
