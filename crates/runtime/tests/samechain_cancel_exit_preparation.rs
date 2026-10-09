//! Fresh unsigned owner-local Cancel/Exit preparation, not consent or financial execution.
use primitive_types::U256;
use zeroize::Zeroizing;
use ziquid_proofs::samechain::{
    CancelExitWitness, MerkleMembership, NoteOpening, RelationError, decrypt_output,
    review_owner_cancel_exit, single_consent_message, verify_cancel_exit_relation,
};
use ziquid_protocol::samechain::{
    Action, Asset, Deployment, FeePolicy, FeeRule, InputDescriptor, OrderPolicy,
    OutputDescriptor, Role, SamechainError, tree::NoteTree,
};
use ziquid_runtime::samechain::preparation::{
    CancelExitRequest, CreationRequest, InitialOrderRequest, prepare_cancel_exit, prepare_note_creation,
};

type Candidate = (CancelExitRequest, NoteOpening, MerkleMembership, Zeroizing<[u8; 32]>);
type InputMutation = fn(&mut InputDescriptor);

fn creation(role: Role, asset: Asset, value: U256) -> CreationRequest {
    CreationRequest {
        deployment: Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
            verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 },
        token: [7; 20], payer: [8; 20], role, asset, amount: value, expiry: 700,
        order: Some(InitialOrderRequest { remaining_sell: value.min(U256::from(100)),
            policy: OrderPolicy { sell_asset: asset,
                buy_asset: if asset == Asset::Native { Asset::Token([7; 20]) } else { Asset::Native },
                min_buy_num: U256::one(), min_sell_den: U256::one(),
                fee_policy: FeePolicy { entries: vec![
                    FeeRule { payer: role, asset, beneficiary: [9; 20], max_atoms: value },
                    FeeRule { payer: role, asset, beneficiary: [10; 20], max_atoms: value },
                ] } } }),
    }
}

fn exit(role: Role, asset: Asset, amount: U256, recipient: u8) -> OutputDescriptor {
    OutputDescriptor::Exit { role, asset, recipient: [recipient; 20], amount }
}

fn fee(role: Role, asset: Asset, amount: U256, recipient: u8) -> OutputDescriptor {
    OutputDescriptor::Fee { payer: role, asset, recipient: [recipient; 20], amount }
}

fn candidate(role: Role, action: Action, asset: Asset, value: U256,
    effects: Vec<OutputDescriptor>) -> Candidate
{
    let created = prepare_note_creation(&creation(role, asset, value)).unwrap();
    let mut tree = NoteTree::new(created.note.deployment_digest, 0).unwrap();
    tree.append([0x66; 32]).unwrap();
    let commitment = created.note.commitment().unwrap();
    let insertion = tree.append(commitment).unwrap();
    // Select the insertion independently, before later unrelated appends.
    tree.append([0x67; 32]).unwrap();
    assert_ne!(insertion.root, tree.root());
    let order = created.note.order.as_ref().unwrap();
    let expected_input = InputDescriptor { commitment, root: insertion.root,
        tree_id: insertion.tree_id, index: insertion.index, order_id: order.id,
        generation: order.generation, nullifier: created.note.nullifier().unwrap(),
        owner_key: created.note.owner_key };
    let membership = MerkleMembership { tree_id: insertion.tree_id, index: insertion.index,
        siblings: insertion.siblings };
    (CancelExitRequest { deployment: created.packet.deployment, expected_input, role, action,
        expiry: 701, effects }, created.note.clone(), membership, Zeroizing::new(created.owner_seed))
}

fn prepare((request, input, membership, seed): Candidate) -> Result<CancelExitWitness, RelationError> {
    prepare_cancel_exit(request, input, membership, seed)
}

fn assert_unsigned(witness: &CancelExitWitness, expected: &InputDescriptor,
    role: Role, action: Action, effects: &[OutputDescriptor], residual: U256)
{
    assert_eq!(&witness.packet.input, expected);
    assert_eq!((witness.role, witness.action), (role, action));
    assert_eq!(&witness.packet.outputs[..effects.len()], effects);
    assert_eq!(witness.consent, [0; 64]);
    witness.packet.validate_commitment(&witness.blind).unwrap();
    let message = review_owner_cancel_exit(&witness.packet, witness, &witness.packet.deployment,
        expected.order_id, role, action).unwrap();
    assert_eq!(message, single_consent_message(&witness.packet, role, action).unwrap());
    assert_eq!(verify_cancel_exit_relation(witness), Err(RelationError::Signature));
    if residual.is_zero() {
        assert!(witness.owned_outputs.is_empty());
        assert_eq!(witness.packet.outputs.len(), effects.len());
    } else {
        assert_eq!(witness.packet.outputs.len(), effects.len() + 1);
        assert_eq!(witness.owned_outputs.len(), 1);
        let opening = &witness.owned_outputs[0];
        assert_eq!(opening.manifest_index as usize, effects.len());
        let recovered = decrypt_output(&witness.packet.outputs[effects.len()], &opening.recovery_key,
            &witness.input.deployment_digest, &expected.owner_key).unwrap();
        assert_eq!(recovered, opening.note);
        assert_eq!(recovered.value, residual);
        assert_eq!(recovered.asset, witness.input.asset);
        assert_eq!(recovered.deployment_digest, witness.input.deployment_digest);
        assert_eq!(recovered.owner_key, expected.owner_key);
        assert!(recovered.order.is_none());
        assert_ne!(recovered.nullifier().unwrap(), expected.nullifier);
        for secret in [&opening.recovery_key, &opening.note.nf_key,
            &opening.note.nonce, &opening.note.salt] { assert_ne!(*secret, [0; 32]); }
        assert!(matches!(&witness.packet.outputs[effects.len()],
            OutputDescriptor::Note { role: selected, .. } if *selected == role));
    }
}

#[test]
fn both_roles_assets_and_actions_allow_full_external_ordinary_mixed_and_fee_only_returns() {
    for role in [Role::A, Role::B] {
        for asset in [Asset::Native, Asset::Token([7; 20])] {
            for action in [Action::Cancel, Action::Exit] {
                let cases = [
                    (vec![], 105),
                    (vec![exit(role, asset, U256::from(105), 8)], 0),
                    (vec![exit(role, asset, U256::from(90), 8), fee(role, asset, U256::one(), 9)], 14),
                    (vec![fee(role, asset, U256::from(105), 9)], 0),
                ];
                for (effects, residual) in cases {
                    let candidate = candidate(role, action, asset, U256::from(105), effects.clone());
                    assert_eq!(candidate.1.order.as_ref().unwrap().remaining_sell, U256::from(100));
                    let expected = candidate.0.expected_input;
                    let witness = prepare(candidate).unwrap();
                    assert_unsigned(&witness, &expected, role, action, &effects, U256::from(residual));
                }
            }
        }
    }
}

#[test]
fn exact_authenticated_fee_allowlist_cap_and_payer_cannot_be_bypassed() {
    for role in [Role::A, Role::B] {
        for action in [Action::Cancel, Action::Exit] {
            let asset = Asset::Native;
            let mut capped = creation(role, asset, U256::from(105));
            capped.order.as_mut().unwrap().policy.fee_policy.entries[0].max_atoms = U256::from(4);
            let created = prepare_note_creation(&capped).unwrap();
            let mut tree = NoteTree::new(created.note.deployment_digest, 0).unwrap();
            let insertion = tree.append(created.note.commitment().unwrap()).unwrap();
            let order = created.note.order.as_ref().unwrap();
            let expected_input = InputDescriptor { commitment: created.note.commitment().unwrap(),
                root: insertion.root, tree_id: insertion.tree_id, index: insertion.index,
                order_id: order.id, generation: order.generation,
                nullifier: created.note.nullifier().unwrap(), owner_key: created.note.owner_key };
            for (effects, error) in [
                (vec![fee(role, asset, U256::from(5), 9)], SamechainError::FeeCapExceeded),
                (vec![fee(role, asset, U256::one(), 11)], SamechainError::UnlistedFee),
                (vec![fee(if role == Role::A { Role::B } else { Role::A }, asset,
                    U256::one(), 9)], SamechainError::InvalidRole),
            ] {
                assert_eq!(prepare_cancel_exit(CancelExitRequest { deployment: capped.deployment,
                    expected_input, role, action, expiry: 701, effects }, created.note.clone(),
                    MerkleMembership { tree_id: insertion.tree_id, index: insertion.index,
                        siblings: insertion.siblings }, Zeroizing::new(created.owner_seed)),
                    Err(RelationError::Protocol(error)));
            }
            let effects = vec![fee(role, asset, U256::from(4), 9)];
            let witness = prepare_cancel_exit(CancelExitRequest { deployment: capped.deployment,
                expected_input, role, action, expiry: 701, effects: effects.clone() }, created.note.clone(),
                MerkleMembership { tree_id: insertion.tree_id, index: insertion.index,
                    siblings: insertion.siblings }, Zeroizing::new(created.owner_seed)).unwrap();
            assert_unsigned(&witness, &expected_input, role, action, &effects, U256::from(101));
        }
    }
}

#[test]
fn all_eight_independently_selected_descriptor_fields_and_private_paths_are_bound() {
    let mutations: [(InputMutation, RelationError); 8] = [
        (|input| input.commitment[0] ^= 1, RelationError::Input),
        (|input| input.nullifier[0] ^= 1, RelationError::Input),
        (|input| input.owner_key[0] ^= 1, RelationError::Input),
        (|input| input.order_id[0] ^= 1, RelationError::Input),
        (|input| input.generation += 1, RelationError::Input),
        (|input| input.root[0] ^= 1, RelationError::Membership),
        (|input| input.tree_id += 1, RelationError::Membership),
        (|input| input.index += 1, RelationError::Membership),
    ];
    for (mutate, error) in mutations {
        let mut candidate = candidate(Role::A, Action::Cancel, Asset::Native, U256::from(105), vec![]);
        mutate(&mut candidate.0.expected_input);
        assert_eq!(prepare(candidate), Err(error));
    }
    for mutate in [
        (|path: &mut MerkleMembership| path.siblings[0][0] ^= 1) as fn(&mut MerkleMembership),
        |path| path.tree_id += 1, |path| path.index += 1,
    ] {
        let mut candidate = candidate(Role::B, Action::Exit, Asset::Token([7; 20]), U256::from(105), vec![]);
        mutate(&mut candidate.2);
        assert_eq!(prepare(candidate), Err(RelationError::Membership));
    }
}

#[test]
fn ordinary_input_foreign_deployment_wrong_seed_role_fill_and_invalid_opening_are_rejected() {
    for mutation in 0..7 {
        let mut candidate = candidate(Role::A, Action::Cancel, Asset::Native, U256::from(105), vec![]);
        let error = match mutation {
            0 => { candidate.1.order = None; RelationError::Input }
            1 => { candidate.0.deployment.chain_id += 1; RelationError::Input }
            2 => { candidate.3[0] ^= 1; RelationError::Key }
            3 => { *candidate.3 = [0; 32]; RelationError::Key }
            4 => { candidate.0.role = Role::B; RelationError::Protocol(SamechainError::InvalidFeePolicy) }
            5 => { candidate.0.action = Action::Fill; RelationError::Action }
            6 => { candidate.1.value = U256::zero(); RelationError::Note }
            _ => unreachable!(),
        };
        assert_eq!(prepare(candidate), Err(error));
    }
}

#[test]
fn exact_effects_reject_notes_foreign_asset_noncanonical_duplicate_zero_and_wrong_role() {
    let role = Role::A;
    let asset = Asset::Native;
    let cases = [
        (vec![exit(role, Asset::Token([7; 20]), U256::one(), 8)], RelationError::Output),
        (vec![fee(role, Asset::Token([7; 20]), U256::one(), 9)], RelationError::Output),
        (vec![exit(Role::B, asset, U256::one(), 8)], RelationError::Protocol(SamechainError::InvalidRole)),
        (vec![exit(role, asset, U256::zero(), 8)], RelationError::Protocol(SamechainError::InvalidOutput)),
        (vec![fee(role, asset, U256::zero(), 9)], RelationError::Protocol(SamechainError::InvalidOutput)),
        (vec![exit(role, asset, U256::one(), 0)], RelationError::Protocol(SamechainError::InvalidOutput)),
        (vec![exit(role, asset, U256::one(), 10), fee(role, asset, U256::one(), 9)],
            RelationError::Protocol(SamechainError::NonCanonical)),
        (vec![exit(role, asset, U256::one(), 9), fee(role, asset, U256::one(), 9)],
            RelationError::Protocol(SamechainError::DuplicateOutput)),
        (vec![OutputDescriptor::Note { role, commitment: [1; 32], recovery_key_commitment: [2; 32],
            ciphertext_version: 1, ciphertext: vec![3] }], RelationError::Output),
    ];
    for (effects, error) in cases {
        assert_eq!(prepare(candidate(role, Action::Cancel, asset, U256::from(105), effects)), Err(error));
    }
    let mut expired = candidate(role, Action::Exit, asset, U256::from(105), vec![]);
    expired.0.expiry = 0;
    assert_eq!(prepare(expired), Err(RelationError::Protocol(SamechainError::InvalidTerms)));
}

#[test]
fn eight_full_effects_are_valid_but_partial_eight_and_overlong_effects_reject() {
    for action in [Action::Cancel, Action::Exit] {
        let effects = (1..=8).map(|recipient| exit(Role::B, Asset::Token([7; 20]),
            U256::one(), recipient)).collect::<Vec<_>>();
        let full = candidate(Role::B, action, Asset::Token([7; 20]), U256::from(8), effects.clone());
        let expected = full.0.expected_input;
        assert_unsigned(&prepare(full).unwrap(), &expected, Role::B, action, &effects, U256::zero());
        assert_eq!(prepare(candidate(Role::B, action, Asset::Token([7; 20]), U256::from(9), effects.clone())),
            Err(RelationError::ResourceLimit));
        let mut overlong = effects;
        overlong.push(exit(Role::B, Asset::Token([7; 20]), U256::one(), 9));
        assert_eq!(prepare(candidate(Role::B, action, Asset::Token([7; 20]), U256::from(9), overlong)),
            Err(RelationError::ResourceLimit));
    }
}

#[test]
fn u256_max_conservation_and_u512_effect_overrun_are_not_narrowed() {
    for action in [Action::Cancel, Action::Exit] {
        let effects = vec![exit(Role::A, Asset::Native, U256::MAX - U256::one(), 8),
            fee(Role::A, Asset::Native, U256::one(), 9)];
        let full = candidate(Role::A, action, Asset::Native, U256::MAX, effects.clone());
        let expected = full.0.expected_input;
        assert_unsigned(&prepare(full).unwrap(), &expected, Role::A, action, &effects, U256::zero());
        let effects = vec![exit(Role::A, Asset::Native, U256::one(), 8),
            fee(Role::A, Asset::Native, U256::MAX, 9), fee(Role::A, Asset::Native, U256::MAX, 10)];
        assert_eq!(prepare(candidate(Role::A, action, Asset::Native, U256::MAX, effects)),
            Err(RelationError::Conservation));
    }
}

#[test]
fn repeated_return_preparation_retains_selection_and_policy_but_refreshes_all_secrets() {
    let (request, input, path, seed) = candidate(Role::B, Action::Cancel, Asset::Token([7; 20]),
        U256::from(105), vec![]);
    let expected = request.expected_input;
    let second_request = CancelExitRequest { deployment: request.deployment, expected_input: expected,
        role: request.role, action: request.action, expiry: request.expiry, effects: vec![] };
    let first = prepare_cancel_exit(request, input.clone(), path.clone(), Zeroizing::new(*seed)).unwrap();
    let second = prepare_cancel_exit(second_request, input, path, seed).unwrap();
    for witness in [&first, &second] {
        assert_unsigned(witness, &expected, Role::B, Action::Cancel, &[], U256::from(105));
    }
    assert_eq!(first.input.order, second.input.order);
    assert_ne!(first.blind, second.blind);
    assert_ne!(first.packet.terms_commitment, second.packet.terms_commitment);
    assert_ne!(first.packet.outputs[0], second.packet.outputs[0]);
    let a = &first.owned_outputs[0];
    let b = &second.owned_outputs[0];
    assert_ne!(a.recovery_key, b.recovery_key);
    assert_ne!(a.note.nf_key, b.note.nf_key);
    assert_ne!(a.note.nonce, b.note.nonce);
    assert_ne!(a.note.salt, b.note.salt);
    assert_ne!(a.note.nullifier().unwrap(), b.note.nullifier().unwrap());
}
