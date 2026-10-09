//! Fresh owner-local unsigned construction, real AEAD and actual private-stdin CLI review.
//! Supplied mathematical paths are not root admission, backing or global unspentness.
use primitive_types::U256;
use std::{io::Write, process::{Command, Stdio}};
use zeroize::Zeroizing;
use ziquid_proofs::samechain::{MerkleMembership, NoteOpening, RelationError, decrypt_output};
use ziquid_proofs::samechain::withdrawal::{
    NoteWithdrawalWitness, note_withdrawal_consent_message, review_note_withdrawal,
    verify_note_withdrawal_relation,
};
use ziquid_protocol::samechain::{
    Asset, Deployment, FeePolicy, OrderPolicy, OutputDescriptor, Role, SamechainError,
    tree::NoteTree, withdrawal::NoteInputDescriptor,
};
use ziquid_runtime::samechain::preparation::{
    CreationRequest, InitialOrderRequest, WithdrawalRequest, prepare_note_creation,
    prepare_note_withdrawal,
};

type Candidate = (WithdrawalRequest, NoteOpening, MerkleMembership, Zeroizing<[u8; 32]>);
type InputMutation = fn(&mut NoteInputDescriptor);

fn creation(asset: Asset, value: U256, backed: bool) -> CreationRequest {
    CreationRequest {
        deployment: Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
            verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 },
        token: [7; 20], payer: [8; 20], role: Role::B, asset, amount: value, expiry: 700,
        order: backed.then(|| InitialOrderRequest { remaining_sell: value,
            policy: OrderPolicy { sell_asset: asset,
                buy_asset: if asset == Asset::Native { Asset::Token([7; 20]) } else { Asset::Native },
                min_buy_num: U256::one(), min_sell_den: U256::one(),
                fee_policy: FeePolicy { entries: vec![] } } }),
    }
}

fn exit(asset: Asset, amount: U256, recipient: u8) -> OutputDescriptor {
    OutputDescriptor::Exit { role: Role::A, asset, recipient: [recipient; 20], amount }
}

fn fee(asset: Asset, amount: U256, recipient: u8) -> OutputDescriptor {
    OutputDescriptor::Fee { payer: Role::A, asset, recipient: [recipient; 20], amount }
}

fn candidate(asset: Asset, value: U256, effects: Vec<OutputDescriptor>, backed: bool) -> Candidate {
    let created = prepare_note_creation(&creation(asset, value, backed)).unwrap();
    // Derive the selected descriptor from a real append, independently of the preparer.
    let mut tree = NoteTree::new(created.note.deployment_digest, 0).unwrap();
    tree.append([0x66; 32]).unwrap();
    let commitment = created.note.commitment().unwrap();
    let insertion = tree.append(commitment).unwrap();
    let membership = MerkleMembership { tree_id: insertion.tree_id, index: insertion.index,
        siblings: insertion.siblings };
    let expected_input = NoteInputDescriptor { commitment, root: insertion.root,
        tree_id: insertion.tree_id, index: insertion.index,
        nullifier: created.note.nullifier().unwrap(), owner_key: created.note.owner_key };
    (WithdrawalRequest { deployment: created.packet.deployment, expected_input, expiry: 701, effects },
        created.note.clone(), membership, Zeroizing::new(created.owner_seed))
}

fn prepare((request, input, membership, seed): Candidate) -> Result<NoteWithdrawalWitness, RelationError> {
    prepare_note_withdrawal(request, input, membership, seed)
}

fn assert_unsigned(witness: &NoteWithdrawalWitness, expected: &NoteInputDescriptor,
    effects: &[OutputDescriptor], residual: U256)
{
    assert_eq!(&witness.packet.input, expected);
    assert_eq!(&witness.packet.outputs[..effects.len()], effects);
    assert_eq!(witness.consent, [0; 64]);
    witness.packet.validate_commitment(&witness.blind).unwrap();
    let message = review_note_withdrawal(&witness.packet, witness,
        &witness.packet.deployment, expected.commitment).unwrap();
    assert_eq!(message, note_withdrawal_consent_message(&witness.packet).unwrap());
    assert_eq!(verify_note_withdrawal_relation(witness), Err(RelationError::Signature));
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
        assert!(matches!(witness.packet.outputs[effects.len()], OutputDescriptor::Note { role: Role::A, .. }));
    }
}

fn private_absent(stream: &[u8], private: &[u8]) {
    assert!(!stream.windows(private.len()).any(|bytes| bytes == private), "private bytes disclosed");
    let mut array = Zeroizing::new(Vec::with_capacity(private.len() * 4 + 2));
    serde_json::to_writer(&mut *array, private).unwrap();
    assert!(!stream.windows(array.len()).any(|bytes| bytes == &array[..]), "private array disclosed");
    if private.len() == 32 {
        use std::fmt::Write as _;
        let mut text = Zeroizing::new(String::with_capacity(64));
        for byte in private { write!(&mut *text, "{byte:02x}").unwrap(); }
        assert!(!stream.windows(text.len()).any(|bytes| bytes.eq_ignore_ascii_case(text.as_bytes())),
            "private hex disclosed");
    }
}

fn review_in_cli(witness: &NoteWithdrawalWitness) {
    let public = witness.packet.encode().unwrap();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&public).unwrap();
    let private = witness.encode().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .args(["samechain", "review-note-withdrawal", "--packet"])
        .arg(file.path()).arg("--witness-stdin").stdin(Stdio::piped())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(&private).unwrap();
    let output = child.wait_with_output().unwrap();
    for stream in [&output.stdout, &output.stderr] {
        private_absent(stream, &private);
        private_absent(stream, &witness.input.encode().unwrap());
        for secret in [&witness.owner_seed, &witness.blind, &witness.input.nf_key,
            &witness.input.nonce, &witness.input.salt] { private_absent(stream, secret); }
        for opening in &witness.owned_outputs {
            private_absent(stream, &opening.note.encode().unwrap());
            for secret in [&opening.recovery_key, &opening.note.nf_key,
                &opening.note.nonce, &opening.note.salt] { private_absent(stream, secret); }
        }
    }
    assert!(output.status.success(), "unsigned withdrawal CLI review rejected");
    assert!(output.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "review_note_withdrawal");
    assert_eq!(json["role"], Role::A as u8);
    assert_eq!(json["evidence"], "native_owner_preconsent_review");
    for field in ["asset_backing", "global_unspentness", "root_eligibility"] {
        assert_eq!(json[field], "UNVERIFIED");
    }
    for field in ["proof_certificate", "financial_execution", "strict_matching_privacy"] {
        assert_eq!(json[field], false);
    }
    for field in ["journal", "signature", "witness", "owner_seed", "recovery_key"] {
        assert!(json.get(field).is_none(), "private or invented export field");
    }
    for (field, expected) in [("packet", public),
        ("packet_digest", witness.packet.digest().unwrap().to_vec()),
        ("consent_message", note_withdrawal_consent_message(&witness.packet).unwrap().to_vec())]
    {
        assert_eq!(serde_json::from_value::<Vec<u8>>(json[field].clone()).unwrap(), expected);
    }
}

#[test]
fn fresh_native_token_full_partial_decrypt_and_actual_unsigned_cli_review() {
    for asset in [Asset::Native, Asset::Token([7; 20])] {
        for (exit_value, residual) in [(104u64, 0u64), (90, 14)] {
            let effects = vec![exit(asset, U256::from(exit_value), 8), fee(asset, U256::one(), 9)];
            let candidate = candidate(asset, U256::from(105), effects.clone(), false);
            let expected = candidate.0.expected_input;
            let witness = prepare(candidate).unwrap();
            assert_unsigned(&witness, &expected, &effects, U256::from(residual));
            review_in_cli(&witness);
        }
    }
}

#[test]
fn full_u256_and_wide_fee_overrun_never_wrap_or_narrow() {
    for asset in [Asset::Native, Asset::Token([7; 20])] {
        let effects = vec![exit(asset, U256::MAX - U256::one(), 8), fee(asset, U256::one(), 9)];
        let full = candidate(asset, U256::MAX, effects.clone(), false);
        let expected = full.0.expected_input;
        assert_unsigned(&prepare(full).unwrap(), &expected, &effects, U256::zero());
        let effects = vec![exit(asset, U256::one(), 8), fee(asset, U256::MAX, 9),
            fee(asset, U256::MAX, 10)];
        assert_eq!(prepare(candidate(asset, U256::MAX, effects, false)), Err(RelationError::Conservation));
    }
}

#[test]
fn eight_full_effects_allowed_but_partial_change_requires_remaining_slot() {
    let effects = (1..=8).map(|recipient| exit(Asset::Native, U256::one(), recipient)).collect::<Vec<_>>();
    let full = candidate(Asset::Native, U256::from(8), effects.clone(), false);
    let expected = full.0.expected_input;
    assert_unsigned(&prepare(full).unwrap(), &expected, &effects, U256::zero());
    assert_eq!(prepare(candidate(Asset::Native, U256::from(9), effects.clone(), false)),
        Err(RelationError::ResourceLimit));
    let mut overlong = effects;
    overlong.push(exit(Asset::Native, U256::one(), 9));
    assert_eq!(prepare(candidate(Asset::Native, U256::from(9), overlong, false)),
        Err(RelationError::ResourceLimit));
}

#[test]
fn independent_complete_input_selection_rejects_each_identity_and_membership_mutation() {
    let mutations: [(InputMutation, RelationError); 6] = [
        (|input| input.commitment[0] ^= 1, RelationError::Input),
        (|input| input.nullifier[0] ^= 1, RelationError::Input),
        (|input| input.owner_key[0] ^= 1, RelationError::Input),
        (|input| input.root[0] ^= 1, RelationError::Membership),
        (|input| input.tree_id += 1, RelationError::Membership),
        (|input| input.index += 1, RelationError::Membership),
    ];
    for (mutate, expected) in mutations {
        let mut candidate = candidate(Asset::Native, U256::from(105),
            vec![exit(Asset::Native, U256::from(105), 8)], false);
        mutate(&mut candidate.0.expected_input);
        assert_eq!(prepare(candidate), Err(expected));
    }
    for mutate in [
        (|path: &mut MerkleMembership| path.siblings[0][0] ^= 1) as fn(&mut MerkleMembership),
        |path| path.tree_id += 1, |path| path.index += 1,
    ] {
        let mut candidate = candidate(Asset::Native, U256::from(105),
            vec![exit(Asset::Native, U256::from(105), 8)], false);
        mutate(&mut candidate.2);
        assert_eq!(prepare(candidate), Err(RelationError::Membership));
    }
}

#[test]
fn backed_input_wrong_owner_seed_and_deployment_never_prepare_withdrawal() {
    assert_eq!(prepare(candidate(Asset::Native, U256::from(105),
        vec![exit(Asset::Native, U256::from(105), 8)], true)), Err(RelationError::Input));
    let mut wrong_seed = candidate(Asset::Native, U256::from(105),
        vec![exit(Asset::Native, U256::from(105), 8)], false);
    wrong_seed.3[0] ^= 1;
    assert_eq!(prepare(wrong_seed), Err(RelationError::Key));
    let mut foreign = candidate(Asset::Native, U256::from(105),
        vec![exit(Asset::Native, U256::from(105), 8)], false);
    foreign.0.deployment.chain_id += 1;
    assert_eq!(prepare(foreign), Err(RelationError::Input));
}

#[test]
fn exact_effects_reject_wrong_asset_role_missing_exit_zero_and_noncanonical_payments() {
    let asset = Asset::Native;
    let cases = [
        (vec![exit(Asset::Token([7; 20]), U256::one(), 8)], RelationError::Output),
        (vec![OutputDescriptor::Exit { role: Role::B, asset, recipient: [8; 20], amount: U256::one() }],
            RelationError::Protocol(SamechainError::InvalidRole)),
        (vec![exit(asset, U256::one(), 8), OutputDescriptor::Fee { payer: Role::B, asset,
            recipient: [9; 20], amount: U256::one() }], RelationError::Protocol(SamechainError::InvalidRole)),
        (vec![fee(asset, U256::one(), 9)], RelationError::Protocol(SamechainError::InvalidOutput)),
        (vec![], RelationError::Protocol(SamechainError::InvalidOutput)),
        (vec![exit(asset, U256::zero(), 8)], RelationError::Protocol(SamechainError::InvalidOutput)),
        (vec![exit(asset, U256::one(), 8), fee(asset, U256::zero(), 9)],
            RelationError::Protocol(SamechainError::InvalidOutput)),
        (vec![exit(asset, U256::one(), 0)], RelationError::Protocol(SamechainError::InvalidOutput)),
        (vec![exit(asset, U256::one(), 9), fee(asset, U256::one(), 8)],
            RelationError::Protocol(SamechainError::NonCanonical)),
        (vec![exit(asset, U256::one(), 8), fee(asset, U256::one(), 8)],
            RelationError::Protocol(SamechainError::DuplicateOutput)),
        (vec![OutputDescriptor::Note { role: Role::A, commitment: [1; 32],
            recovery_key_commitment: [2; 32], ciphertext_version: 1, ciphertext: vec![3] },
            exit(asset, U256::one(), 8)], RelationError::Output),
    ];
    for (effects, expected) in cases {
        assert_eq!(prepare(candidate(asset, U256::from(105), effects, false)), Err(expected));
    }
    let mut expired = candidate(asset, U256::from(105), vec![exit(asset, U256::one(), 8)], false);
    expired.0.expiry = 0;
    assert_eq!(prepare(expired), Err(RelationError::Protocol(SamechainError::InvalidTerms)));
}

#[test]
fn repeated_partial_withdrawal_retains_input_and_exact_effects_but_fresh_change_and_blind() {
    let effects = vec![exit(Asset::Native, U256::from(90), 8), fee(Asset::Native, U256::one(), 9)];
    let (request, input, path, seed) = candidate(Asset::Native, U256::from(105), effects.clone(), false);
    let expected = request.expected_input;
    let second_request = WithdrawalRequest { deployment: request.deployment, expected_input: expected,
        expiry: request.expiry, effects: effects.clone() };
    let first = prepare_note_withdrawal(request, input.clone(), path.clone(), Zeroizing::new(*seed)).unwrap();
    let second = prepare_note_withdrawal(second_request, input, path, seed).unwrap();
    for witness in [&first, &second] { assert_unsigned(witness, &expected, &effects, U256::from(14)); }
    assert_ne!(first.blind, second.blind);
    assert_ne!(first.packet.terms_commitment, second.packet.terms_commitment);
    assert_ne!(first.packet.outputs[2], second.packet.outputs[2]);
    let a = &first.owned_outputs[0];
    let b = &second.owned_outputs[0];
    assert_ne!(a.recovery_key, b.recovery_key);
    assert_ne!(a.note.nf_key, b.note.nf_key);
    assert_ne!(a.note.nonce, b.note.nonce);
    assert_ne!(a.note.salt, b.note.salt);
    assert_ne!(a.note.nullifier().unwrap(), b.note.nullifier().unwrap());
}
