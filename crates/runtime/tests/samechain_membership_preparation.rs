//! Generated owner crypto + parser-acquired provider history + actual unsigned CLI review.
//! Provider initial-boundary/log-completeness TRUST remains; no admitted root, backing,
//! authenticated global unspentness, signing, proof, submission or recovery scanner.
use primitive_types::U256;
use serde_json::Value;
use std::{io::Write, process::{Command, Stdio}};
use zeroize::Zeroizing;
use ziquid_chains::samechain::{
    history::PublicHistory,
    inspection::{InspectionScope, SamechainInspectionClient},
};
use ziquid_proofs::samechain::{
    CancelExitWitness, MerkleMembership, NoteOpening, OwnerWitness, RelationError, decrypt_output,
    review_owner_cancel_exit, review_owner_fill, single_consent_message, verify_cancel_exit_relation,
};
use ziquid_proofs::samechain::creation::NoteCreationWitness;
use ziquid_proofs::samechain::withdrawal::{
    NoteWithdrawalWitness, note_withdrawal_consent_message, review_note_withdrawal,
    verify_note_withdrawal_relation,
};
use ziquid_protocol::samechain::{
    Action, Asset, FeePolicy, FeeRule, InputDescriptor, OrderPolicy, OutputDescriptor,
    PublicPacket, Role, SamechainError,
    fill::{FillExecution, aggregate_commitment, owner_leaf}, tree::{NoteInsertion, NoteTree},
};
use ziquid_protocol::samechain::withdrawal::NoteInputDescriptor;
use ziquid_runtime::samechain::preparation::{
    CancelExitRequest, CreationRequest, InitialOrderRequest, WithdrawalRequest, prepare_cancel_exit,
    prepare_fill_outputs, prepare_note_creation, prepare_note_membership, prepare_note_withdrawal,
};

#[path = "../../chains/tests/support/samechain_inspection.rs"]
mod support;
#[path = "../../chains/tests/support/samechain_history.rs"]
mod history_support;
use history_support::{ExpectedNote, append, block_hash, consume, empty_block, hash_label};
use support::{Fixture, HistoryBlockFixture, hex, uint_word};

struct Generated {
    owners: [NoteCreationWitness; 2],
    blocks: Vec<HistoryBlockFixture>,
    notes: [ExpectedNote; 2],
}

fn request(role: Role) -> CreationRequest {
    let scope = support::scope();
    let (asset, buy_asset, amount): (Asset, Asset, u64) = match role {
        Role::A => (Asset::Native, Asset::Token(scope.token), 105),
        Role::B => (Asset::Token(scope.token), Asset::Native, 100),
    };
    CreationRequest {
        deployment: scope.expected, token: scope.token, payer: [8; 20], role,
        asset, amount: U256::from(amount), expiry: 700,
        order: Some(InitialOrderRequest {
            remaining_sell: U256::from(100),
            policy: OrderPolicy {
                sell_asset: asset, buy_asset,
                min_buy_num: U256::one(), min_sell_den: U256::from(2),
                fee_policy: FeePolicy { entries: vec![FeeRule {
                    payer: role, asset: buy_asset, beneficiary: [9; 20],
                    max_atoms: U256::from(4),
                }] },
            },
        }),
    }
}

// Reuse the complete real event layout; replace only the fixture's dummy public
// descriptor words with actual generated AEAD descriptor and packet bindings.
fn append_descriptor(block: &mut HistoryBlockFixture, tree: &mut NoteTree,
    output: &OutputDescriptor, packet_digest: [u8; 32], transaction: [u8; 32],
    positions: (u64, u64, u32)) -> ExpectedNote
{
    let OutputDescriptor::Note { role, commitment, recovery_key_commitment,
        ciphertext_version, ciphertext } = output else { panic!("expected recipient note"); };
    let expected = append(block, tree, *commitment, transaction, positions, *role, ciphertext.clone());
    let mut data = [
        packet_digest, uint_word(u64::from(positions.2)), uint_word(*role as u64),
        uint_word(u64::from(expected.insertion.tree_id)),
        uint_word(u64::from(expected.insertion.index)), uint_word(expected.insertion.count),
        expected.insertion.root, *commitment, *recovery_key_commitment,
        uint_word(u64::from(*ciphertext_version)), uint_word(352),
        uint_word(ciphertext.len() as u64),
    ].concat();
    data.extend_from_slice(ciphertext);
    data.resize(data.len() + (32 - ciphertext.len() % 32) % 32, 0);
    block.appended_logs.last_mut().unwrap()["data"] = Value::String(hex(&data));
    expected
}

fn next_block(number: u64, tree: &NoteTree, previous: &HistoryBlockFixture) -> HistoryBlockFixture {
    let mut block = empty_block(number, tree);
    block.root_counts = previous.root_counts.clone();
    block.spent = previous.spent.clone();
    block
}

impl Generated {
    fn new() -> Self {
        let owners = [prepare_note_creation(&request(Role::A)).unwrap(),
            prepare_note_creation(&request(Role::B)).unwrap()];
        let mut tree = NoteTree::new(support::scope().expected.digest().unwrap(), 0).unwrap();
        let origin = empty_block(42, &tree);
        let mut first = next_block(43, &tree, &origin);
        let a = append_descriptor(&mut first, &mut tree, &owners[0].packet.output,
            owners[0].packet.digest().unwrap(), hash_label(43), (0, 0, 0));
        let mut later = next_block(44, &tree, &first);
        let b = append_descriptor(&mut later, &mut tree, &owners[1].packet.output,
            owners[1].packet.digest().unwrap(), hash_label(44), (0, 0, 0));
        let suffix = next_block(45, &tree, &later);
        Self { owners, blocks: vec![origin, first, later, suffix], notes: [a, b] }
    }

    fn tree(&self) -> NoteTree {
        let mut tree = NoteTree::new(support::scope().expected.digest().unwrap(), 0).unwrap();
        for note in &self.notes { tree.append(note.commitment).unwrap(); }
        tree
    }
}

async fn acquire(blocks: &[HistoryBlockFixture]) -> PublicHistory {
    let fixture = Fixture::with_history(blocks.to_vec());
    let client = SamechainInspectionClient::new(fixture.endpoint(), true).unwrap();
    let mut history = PublicHistory::new(blocks[0].scope, blocks[0].number).unwrap();
    for block in blocks {
        let observation = client.inspect(&block.scope, None).await.unwrap();
        history.ingest(block.scope.block_hash, observation).unwrap();
    }
    history
}

fn retained_descriptor(history: &PublicHistory, commitment: &[u8; 32]) -> OutputDescriptor {
    let event = &history.note(commitment).unwrap().note;
    OutputDescriptor::Note { role: event.role, commitment: event.commitment,
        recovery_key_commitment: event.recovery_key_commitment,
        ciphertext_version: event.ciphertext_version, ciphertext: event.ciphertext.clone() }
}

fn assert_insertion(path: &MerkleMembership, expected: &NoteInsertion, note: &NoteOpening) {
    assert_eq!((path.tree_id, path.index), (expected.tree_id, expected.index));
    assert_eq!(path.siblings, expected.siblings);
    assert_eq!(path.root(&note.deployment_digest, &note.commitment().unwrap()), expected.root);
}

fn selected_order_input(history: &PublicHistory, input: &NoteOpening) -> InputDescriptor {
    let commitment = input.commitment().unwrap();
    let retained = history.note(&commitment).unwrap();
    let insertion = &retained.insertion;
    let order = input.order.as_ref().unwrap();
    InputDescriptor { commitment: retained.note.commitment, root: insertion.root,
        tree_id: insertion.tree_id, index: insertion.index, order_id: order.id,
        generation: order.generation, nullifier: input.nullifier().unwrap(), owner_key: input.owner_key }
}

fn unsigned_cancel_exit(history: &PublicHistory, input: NoteOpening, membership: MerkleMembership,
    role: Role, action: Action, effects: Vec<OutputDescriptor>, owner_seed: [u8; 32]) -> CancelExitWitness
{
    let expected_input = selected_order_input(history, &input);
    let witness = prepare_cancel_exit(CancelExitRequest { deployment: support::scope().expected,
        expected_input, role, action, expiry: 702, effects }, input, membership,
        Zeroizing::new(owner_seed)).unwrap();
    assert_eq!(witness.packet.input, expected_input);
    witness
}

fn assert_private_absent(stream: &[u8], private: &[u8]) {
    assert!(!private.is_empty());
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

fn review_cancel_exit_in_cli(witness: &CancelExitWitness) {
    let order_id = witness.packet.input.order_id;
    let message = review_owner_cancel_exit(&witness.packet, witness,
        &support::scope().expected, order_id, witness.role, witness.action).unwrap();
    assert_eq!(message, single_consent_message(&witness.packet, witness.role, witness.action).unwrap());
    assert_eq!(witness.consent, [0; 64]);
    assert_eq!(verify_cancel_exit_relation(witness), Err(RelationError::Signature));
    // Only public packet and independently selected deployment go to disk/args.
    // This actual command is also runnable from the built consumer harness by
    // the parent; generated owner capability bytes travel solely via stdin.
    let public = witness.packet.encode().unwrap();
    let mut packet_file = tempfile::NamedTempFile::new().unwrap();
    packet_file.write_all(&public).unwrap();
    let mut deployment_file = tempfile::NamedTempFile::new().unwrap();
    deployment_file.write_all(&support::scope().expected.encode().unwrap()).unwrap();
    let private = witness.encode().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .args(["samechain", "review-cancel-exit", "--packet"])
        .arg(packet_file.path()).arg("--deployment").arg(deployment_file.path())
        .args(["--order-id", &hex(&order_id), "--role",
            if witness.role == Role::A { "a" } else { "b" }, "--action",
            if witness.action == Action::Cancel { "cancel" } else { "exit" }, "--witness-stdin"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(&private).unwrap();
    let output = child.wait_with_output().unwrap();
    for stream in [&output.stdout, &output.stderr] {
        assert_private_absent(stream, &private);
        assert_private_absent(stream, &witness.input.encode().unwrap());
        for secret in [&witness.owner_seed, &witness.blind, &witness.input.nf_key,
            &witness.input.nonce, &witness.input.salt] { assert_private_absent(stream, secret); }
        assert_private_absent(stream, &witness.input.order.as_ref().unwrap().encode().unwrap());
        for opening in &witness.owned_outputs {
            assert_private_absent(stream, &opening.note.encode().unwrap());
            for secret in [&opening.recovery_key, &opening.note.nf_key,
                &opening.note.nonce, &opening.note.salt] { assert_private_absent(stream, secret); }
        }
    }
    assert!(output.status.success(), "acquired historical membership unsigned review rejected");
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "review_cancel_exit");
    assert_eq!(json["role"], witness.role as u8);
    assert_eq!(json["action"], witness.action as u8);
    assert_eq!(json["evidence"], "native_owner_preconsent_review");
    for field in ["asset_backing", "global_unspentness", "root_eligibility"] {
        assert_eq!(json[field], "UNVERIFIED");
    }
    for field in ["signing", "financial_execution", "proof_certificate", "strict_matching_privacy"] {
        assert_eq!(json[field], false);
    }
    for field in ["journal", "signature", "witness", "owner_seed", "recovery_key"] {
        assert!(json.get(field).is_none(), "private or invented export field");
    }
    for (field, expected) in [("packet", public),
        ("packet_digest", witness.packet.digest().unwrap().to_vec()),
        ("consent_message", message.to_vec())]
    {
        assert_eq!(serde_json::from_value::<Vec<u8>>(json[field].clone()).unwrap(), expected);
    }
}

fn review_withdrawal_in_cli(witness: &NoteWithdrawalWitness) {
    let message = review_note_withdrawal(&witness.packet, witness,
        &support::scope().expected, witness.packet.input.commitment).unwrap();
    assert_eq!(message, note_withdrawal_consent_message(&witness.packet).unwrap());
    assert_eq!(witness.consent, [0; 64]);
    assert_eq!(verify_note_withdrawal_relation(witness), Err(RelationError::Signature));
    let public = witness.packet.encode().unwrap();
    let mut packet_file = tempfile::NamedTempFile::new().unwrap();
    packet_file.write_all(&public).unwrap();
    let private = witness.encode().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
        .args(["samechain", "review-note-withdrawal", "--packet"])
        .arg(packet_file.path()).arg("--witness-stdin")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(&private).unwrap();
    let output = child.wait_with_output().unwrap();
    for stream in [&output.stdout, &output.stderr] {
        assert_private_absent(stream, &private);
        assert_private_absent(stream, &witness.input.encode().unwrap());
        for secret in [&witness.owner_seed, &witness.blind, &witness.input.nf_key,
            &witness.input.nonce, &witness.input.salt] { assert_private_absent(stream, secret); }
        for opening in &witness.owned_outputs {
            assert_private_absent(stream, &opening.note.encode().unwrap());
            for secret in [&opening.recovery_key, &opening.note.nf_key,
                &opening.note.nonce, &opening.note.salt] { assert_private_absent(stream, secret); }
        }
    }
    assert!(output.status.success(), "acquired ordinary proceeds withdrawal review rejected");
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "review_note_withdrawal");
    assert_eq!(json["role"], Role::A as u8);
    assert_eq!(json["action"], Action::Exit as u8);
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
        ("consent_message", message.to_vec())]
    {
        assert_eq!(serde_json::from_value::<Vec<u8>>(json[field].clone()).unwrap(), expected);
    }
}

fn selected_note_input(note: &NoteOpening, expected: &ExpectedNote) -> NoteInputDescriptor {
    let insertion = &expected.insertion;
    NoteInputDescriptor { commitment: expected.commitment, root: insertion.root,
        tree_id: insertion.tree_id, index: insertion.index,
        nullifier: note.nullifier().unwrap(), owner_key: note.owner_key }
}

#[tokio::test]
async fn acquired_historical_paths_review_fresh_unsigned_a_b_exits_in_actual_cli() {
    let generated = Generated::new();
    let history = acquire(&generated.blocks).await;
    let final_block = generated.blocks.last().unwrap();
    assert_eq!(history.origin_scope(), generated.blocks[0].scope);
    assert_ne!(history.origin_scope().block_hash, final_block.scope.block_hash);
    assert_eq!(history.block_count(), 4); // Includes the independently pinned empty suffix.
    for (owner, expected) in generated.owners.iter().zip(&generated.notes) {
        let descriptor = retained_descriptor(&history, &expected.commitment);
        assert_eq!(descriptor, owner.packet.output);
        let restored = decrypt_output(&descriptor, &owner.recovery_key,
            &final_block.scope.expected.digest().unwrap(), &owner.packet.owner_key).unwrap();
        assert_eq!(restored, owner.note);
        let path = prepare_note_membership(&history, &final_block.scope, final_block.number, &restored).unwrap();
        assert_insertion(&path, &expected.insertion, &restored);
        assert_eq!(history.root_count(path.tree_id, expected.insertion.root), expected.insertion.count);
        assert!(!history.observed_spent(&restored.nullifier().unwrap())); // NOT OBSERVED, not proven unspent.
        let effects = vec![OutputDescriptor::Exit { role: owner.packet.role, asset: restored.asset,
            recipient: [9; 20], amount: restored.value }];
        let witness = unsigned_cancel_exit(&history, restored, path, owner.packet.role,
            Action::Exit, effects, owner.owner_seed);
        assert_eq!(witness.packet.input.root, expected.insertion.root);
        review_cancel_exit_in_cli(&witness);
        let mut wrong_path = witness.clone();
        wrong_path.membership.siblings[0][0] ^= 1;
        assert_eq!(review_owner_cancel_exit(&wrong_path.packet, &wrong_path,
            &final_block.scope.expected, witness.packet.input.order_id,
            witness.role, Action::Exit), Err(RelationError::Membership));
    }
    assert_ne!(generated.notes[0].insertion.root, history.tree_state().2);
}

#[tokio::test]
async fn rejects_unaccepted_wrong_scope_exact_horizon_unknown_and_invalid_openings() {
    let generated = Generated::new();
    let history = acquire(&generated.blocks).await;
    let final_block = generated.blocks.last().unwrap();
    let note = &generated.owners[0].note;
    assert!(prepare_note_membership(&history, &final_block.scope, final_block.number, note).is_ok());
    let unaccepted = PublicHistory::new(generated.blocks[0].scope, generated.blocks[0].number).unwrap();
    assert_eq!(prepare_note_membership(&unaccepted, &final_block.scope, final_block.number, note),
        Err(RelationError::Input));
    for number in [final_block.number - U256::one(), final_block.number + U256::one(), U256::MAX] {
        assert_eq!(prepare_note_membership(&history, &final_block.scope, number, note), Err(RelationError::Input));
    }
    let prefix = acquire(&generated.blocks[..3]).await;
    assert_eq!(prefix.tree_state(), history.tree_state());
    assert_eq!(prepare_note_membership(&prefix, &final_block.scope, final_block.number, note), Err(RelationError::Input));
    let prior = &generated.blocks[2];
    assert_eq!(prepare_note_membership(&history, &prior.scope, prior.number, note), Err(RelationError::Input));
    // Valid but different pins cannot fall through to a mathematically valid path.
    for mutation in 0..11 {
        let mut wrong: InspectionScope = final_block.scope;
        match mutation {
            0 => wrong.block_hash = block_hash(99),
            1 => wrong.token[0] ^= 1,
            2 => wrong.token_code[0] ^= 1,
            3 => wrong.policy_id[0] ^= 1,
            4 => wrong.expected.chain_id += 1,
            5 => wrong.expected.authority[0] ^= 1,
            6 => wrong.expected.authority_code[0] ^= 1,
            7 => wrong.expected.verifier[0] ^= 1,
            8 => wrong.expected.verifier_code[0] ^= 1,
            9 => wrong.expected.owner_program[0] ^= 1,
            10 => wrong.block_hash = [0; 32],
            _ => unreachable!(),
        }
        assert_eq!(prepare_note_membership(&history, &wrong, final_block.number, note), Err(RelationError::Input));
    }
    let unknown = prepare_note_creation(&request(Role::A)).unwrap();
    unknown.note.validate().unwrap();
    assert_eq!(prepare_note_membership(&history, &final_block.scope, final_block.number, &unknown.note), Err(RelationError::Input));
    let mut foreign_request = request(Role::A);
    foreign_request.deployment.chain_id += 1;
    let foreign = prepare_note_creation(&foreign_request).unwrap();
    foreign.note.validate().unwrap();
    assert_eq!(prepare_note_membership(&history, &final_block.scope, final_block.number, &foreign.note), Err(RelationError::Input));
    let mut invalid = note.clone();
    invalid.value = U256::zero();
    assert_eq!(prepare_note_membership(&history, &final_block.scope, final_block.number, &invalid), Err(RelationError::Note));
}

#[tokio::test]
async fn nf_only_spend_rejects_unchanged_tree_but_omitted_unqueried_log_remains_provider_trust() {
    let generated = Generated::new();
    let before = acquire(&generated.blocks).await;
    let mut blocks = generated.blocks.clone();
    let mut spend = next_block(46, &generated.tree(), blocks.last().unwrap());
    let nf = generated.owners[0].note.nullifier().unwrap();
    consume(&mut spend, nf, hash_label(46), 0, 0);
    blocks.push(spend);
    let history = acquire(&blocks).await;
    let final_block = blocks.last().unwrap();
    assert_eq!(history.tree_state(), before.tree_state());
    assert!(history.observed_spent(&nf));
    assert_eq!(prepare_note_membership(&history, &final_block.scope, final_block.number,
        &generated.owners[0].note), Err(RelationError::Input));
    let other = prepare_note_membership(&history, &final_block.scope, final_block.number,
        &generated.owners[1].note).unwrap();
    assert_insertion(&other, &generated.notes[1].insertion, &generated.owners[1].note);
    // Deliberately coherent dishonest provider: there was no queried getter.
    // Omitting this NF-only transaction cannot be detected by append coherence.
    let mut omitted = blocks;
    omitted.last_mut().unwrap().nullifier_logs.clear();
    omitted.last_mut().unwrap().spent.remove(&nf);
    let incomplete = acquire(&omitted).await;
    let endpoint = omitted.last().unwrap();
    assert_eq!(incomplete.tree_state(), history.tree_state());
    assert!(!incomplete.observed_spent(&nf));
    assert!(prepare_note_membership(&incomplete, &endpoint.scope, endpoint.number,
        &generated.owners[0].note).is_ok());
    assert_eq!(incomplete.log_completeness_trust(), "TRUSTED_PROVIDER_LOG_COMPLETENESS");
}

#[tokio::test]
async fn retained_event_role_must_match_private_order_fee_policy() {
    let generated = Generated::new();
    let baseline = acquire(&generated.blocks).await;
    let endpoint = generated.blocks.last().unwrap();
    assert!(prepare_note_membership(&baseline, &endpoint.scope, endpoint.number,
        &generated.owners[0].note).is_ok());
    let mut blocks = generated.blocks.clone();
    let mut tree = NoteTree::new(endpoint.scope.expected.digest().unwrap(), 0).unwrap();
    let mut wrong_output = generated.owners[0].packet.output.clone();
    let OutputDescriptor::Note { role, .. } = &mut wrong_output else { unreachable!() };
    *role = Role::B;
    blocks[1].appended_logs.clear();
    append_descriptor(&mut blocks[1], &mut tree, &wrong_output,
        generated.owners[0].packet.digest().unwrap(), hash_label(43), (0, 0, 0));
    let history = acquire(&blocks).await;
    generated.owners[0].note.validate().unwrap(); // General validation alone allows this mismatch.
    assert_eq!(prepare_note_membership(&history, &endpoint.scope, endpoint.number,
        &generated.owners[0].note), Err(RelationError::Protocol(SamechainError::InvalidFeePolicy)));
}

#[tokio::test]
async fn acquired_partial_successors_and_ordinary_proceeds_restore_after_discarding_typed_outputs() {
    let generated = Generated::new();
    let approved = FillExecution { asset_a: Asset::Native, asset_b: Asset::Token(support::scope().token),
        sell_a: U256::from(40), sell_b: U256::from(50) };
    approved.validate().unwrap();
    let mut tree = generated.tree();
    let mut blocks = generated.blocks.clone();
    let mut fill_block = next_block(46, &tree, blocks.last().unwrap());
    for (index, owner) in generated.owners.iter().enumerate() {
        consume(&mut fill_block, owner.note.nullifier().unwrap(), hash_label(46), 0, index as u64);
    }
    let mut prepared_owners = generated.owners.iter().enumerate().map(|(index, owner)| {
        let (sold, credit) = if index == 0 { (approved.sell_a, approved.sell_b) }
            else { (approved.sell_b, approved.sell_a) };
        prepare_fill_outputs(&owner.note, &support::scope().expected,
            owner.note.order.as_ref().unwrap().id, owner.packet.role, sold, credit, &[]).unwrap()
    }).collect::<Vec<_>>();
    let initial_history = acquire(&generated.blocks).await;
    let initial_endpoint = generated.blocks.last().unwrap();
    let memberships = generated.owners.iter().map(|owner| prepare_note_membership(
        &initial_history, &initial_endpoint.scope, initial_endpoint.number, &owner.note).unwrap())
        .collect::<Vec<_>>();
    let inputs = std::array::from_fn(|index| {
        let owner = &generated.owners[index];
        let note = &owner.note;
        let order = note.order.as_ref().unwrap();
        InputDescriptor { commitment: generated.notes[index].commitment,
            root: generated.notes[index].insertion.root,
            tree_id: memberships[index].tree_id, index: memberships[index].index,
            order_id: order.id, generation: order.generation,
            nullifier: note.nullifier().unwrap(), owner_key: note.owner_key }
    });
    let mut outputs = Vec::new();
    for prepared in &mut prepared_owners {
        assert_eq!(prepared.descriptors.len(), 2);
        let offset = outputs.len() as u32;
        for opening in &mut prepared.openings { opening.manifest_index += offset; }
        outputs.append(&mut prepared.descriptors);
    }
    let mut packet = PublicPacket { deployment: support::scope().expected, inputs,
        outputs, expiry: 701, terms_commitment: [0; 32] };
    let salts = Zeroizing::new([[0x81; 32], [0x82; 32]]);
    let leaves = std::array::from_fn(|index| owner_leaf(&packet, &approved,
        generated.owners[index].packet.role,
        &generated.owners[index].note.order.as_ref().unwrap().policy, &salts[index]).unwrap());
    packet.terms_commitment = aggregate_commitment(&packet, &approved, &leaves).unwrap();
    let digest = packet.digest().unwrap();
    let mut candidates = Vec::new();
    for (index, prepared) in prepared_owners.iter_mut().enumerate() {
        let owner = &generated.owners[index];
        let witness = OwnerWitness { packet: packet.clone(), execution: approved, leaves,
            own_salt: salts[index], role: owner.packet.role, owner_seed: owner.owner_seed,
            input: owner.note.clone(), membership: memberships[index].clone(),
            consent: [0; 64], owned_outputs: std::mem::take(&mut prepared.openings) };
        review_owner_fill(&packet, &witness, &packet.deployment,
            owner.note.order.as_ref().unwrap().id, owner.packet.role, &approved).unwrap();
        for opening in &witness.owned_outputs {
            let manifest_index = opening.manifest_index;
            let expected = append_descriptor(&mut fill_block, &mut tree,
                &packet.outputs[manifest_index as usize], digest, hash_label(46),
                (0, u64::from(manifest_index) + 2, manifest_index));
            candidates.push((index, expected, Zeroizing::new(opening.recovery_key)));
        }
        // Drop all typed successor/proceeds before decrypting retained ciphertext.
        drop(witness);
    }
    drop(prepared_owners);
    drop(packet);
    blocks.push(fill_block);
    blocks.push(next_block(47, &tree, blocks.last().unwrap()));
    let history = acquire(&blocks).await;
    let endpoint = blocks.last().unwrap();
    assert_eq!(history.note_count(), 6);
    assert_eq!(history.nullifier_count(), 2);
    for owner in &generated.owners {
        assert_eq!(prepare_note_membership(&history, &endpoint.scope, endpoint.number,
            &owner.note), Err(RelationError::Input));
    }
    let mut nfs = vec![generated.owners[0].note.nullifier().unwrap(),
        generated.owners[1].note.nullifier().unwrap()];
    for (position, (owner_index, expected, key)) in candidates.into_iter().enumerate() {
        let owner = &generated.owners[owner_index];
        let output = retained_descriptor(&history, &expected.commitment);
        let restored = decrypt_output(&output, &key, &endpoint.scope.expected.digest().unwrap(),
            &owner.packet.owner_key).unwrap();
        let path = prepare_note_membership(&history, &endpoint.scope, endpoint.number, &restored).unwrap();
        assert_insertion(&path, &expected.insertion, &restored);
        let nf = restored.nullifier().unwrap();
        assert!(!nfs.contains(&nf));
        assert!(!history.observed_spent(&nf)); // Only an absence in retained provider coverage.
        nfs.push(nf);
        if position % 2 == 0 {
            let order = restored.order.as_ref().unwrap();
            assert_eq!(order.id, owner.note.order.as_ref().unwrap().id);
            assert_eq!(order.generation, 2);
            assert_eq!(order.policy, owner.note.order.as_ref().unwrap().policy);
            assert_eq!(order.remaining_sell, U256::from(if owner_index == 0 { 60 } else { 50 }));
            assert_eq!(restored.value, U256::from(if owner_index == 0 { 65 } else { 50 }));
            assert_eq!(restored.asset, owner.note.asset);
            let selected = selected_order_input(&history, &restored);
            assert_eq!(selected.root, expected.insertion.root);
            if owner_index == 0 { assert_ne!(selected.root, history.tree_state().2); }
            let mut selected_cancel = None;
            let mut selected_exit = None;
            // Mutually exclusive alternatives are only prepared/reviewed, not executed.
            for action in [Action::Cancel, Action::Exit] {
                for (kind, effects) in [
                    (0, vec![]),
                    (1, vec![OutputDescriptor::Exit { role: owner.packet.role, asset: restored.asset,
                        recipient: [8; 20], amount: restored.value }]),
                    (2, vec![OutputDescriptor::Exit { role: owner.packet.role, asset: restored.asset,
                        recipient: [8; 20], amount: restored.value - U256::from(3) }]),
                ] {
                    let witness = unsigned_cancel_exit(&history, restored.clone(), path.clone(),
                        owner.packet.role, action, effects, owner.owner_seed);
                    assert_eq!(witness.packet.input, selected);
                    review_cancel_exit_in_cli(&witness);
                    if action == Action::Cancel && kind == 0 { selected_cancel = Some(witness); }
                    else if action == Action::Exit && kind == 1 { selected_exit = Some(witness); }
                }
            }
            let cancel = selected_cancel.unwrap();
            assert_eq!(cancel.owned_outputs.len(), 1);
            let return_key = Zeroizing::new(cancel.owned_outputs[0].recovery_key);
            let return_output = cancel.packet.outputs[0].clone();
            let cancel_digest = cancel.packet.digest().unwrap();
            let mut cancel_tree = tree.clone();
            let mut cancel_blocks = blocks.clone();
            let mut cancel_block = next_block(48, &cancel_tree, cancel_blocks.last().unwrap());
            consume(&mut cancel_block, selected.nullifier, hash_label(48), 0, 0);
            let return_expected = append_descriptor(&mut cancel_block, &mut cancel_tree,
                &return_output, cancel_digest, hash_label(48), (0, 1, 0));
            // Only retained public ciphertext and the owner recovery capability survive.
            drop(cancel);
            drop(return_output);
            cancel_blocks.push(cancel_block);
            cancel_blocks.push(next_block(49, &cancel_tree, cancel_blocks.last().unwrap()));
            let cancel_history = acquire(&cancel_blocks).await;
            let cancel_endpoint = cancel_blocks.last().unwrap();
            assert!(cancel_history.observed_spent(&selected.nullifier));
            assert_eq!(prepare_note_membership(&cancel_history, &cancel_endpoint.scope,
                cancel_endpoint.number, &restored), Err(RelationError::Input));
            let retained_return = retained_descriptor(&cancel_history, &return_expected.commitment);
            let ordinary = decrypt_output(&retained_return, &return_key,
                &cancel_endpoint.scope.expected.digest().unwrap(), &owner.packet.owner_key).unwrap();
            assert_eq!(ordinary.value, U256::from(if owner_index == 0 { 65 } else { 50 }));
            assert_eq!(ordinary.asset, restored.asset);
            assert_eq!(ordinary.owner_key, restored.owner_key);
            assert!(ordinary.order.is_none());
            assert_ne!(ordinary.nullifier().unwrap(), selected.nullifier);
            let return_path = prepare_note_membership(&cancel_history, &cancel_endpoint.scope,
                cancel_endpoint.number, &ordinary).unwrap();
            assert_insertion(&return_path, &return_expected.insertion, &ordinary);
            let expected_return = selected_note_input(&ordinary, &return_expected);
            // Ordinary withdrawal uses its own role-A relation even for a canceled B order.
            let withdrawal_effects = vec![OutputDescriptor::Exit { role: Role::A, asset: ordinary.asset,
                recipient: [8; 20], amount: ordinary.value - U256::one() },
                OutputDescriptor::Fee { payer: Role::A, asset: ordinary.asset,
                    recipient: [9; 20], amount: U256::one() }];
            let withdrawal = prepare_note_withdrawal(WithdrawalRequest {
                deployment: cancel_endpoint.scope.expected, expected_input: expected_return,
                expiry: 704, effects: withdrawal_effects,
            }, ordinary, return_path, Zeroizing::new(owner.owner_seed)).unwrap();
            assert_eq!(withdrawal.packet.input, expected_return);
            assert!(withdrawal.owned_outputs.is_empty());
            review_withdrawal_in_cli(&withdrawal);

            // Separate modeled Exit-only alternative consumes the same NF with no append.
            let exit = selected_exit.unwrap();
            assert!(exit.owned_outputs.is_empty());
            assert_eq!(exit.packet.outputs.len(), 1);
            let mut exit_blocks = blocks.clone();
            let mut exit_block = next_block(48, &tree, exit_blocks.last().unwrap());
            consume(&mut exit_block, selected.nullifier, hash_label(48), 0, 0);
            drop(exit);
            exit_blocks.push(exit_block);
            exit_blocks.push(next_block(49, &tree, exit_blocks.last().unwrap()));
            let exit_history = acquire(&exit_blocks).await;
            let exit_endpoint = exit_blocks.last().unwrap();
            assert_eq!(exit_history.tree_state(), history.tree_state());
            assert_eq!(exit_history.note_count(), history.note_count());
            assert!(exit_history.observed_spent(&selected.nullifier));
            assert_eq!(prepare_note_membership(&exit_history, &exit_endpoint.scope,
                exit_endpoint.number, &restored), Err(RelationError::Input));
        } else {
            assert!(restored.order.is_none());
            assert_eq!(restored.asset, owner.note.order.as_ref().unwrap().policy.buy_asset);
            assert_eq!(restored.value, U256::from(if owner_index == 0 { 50 } else { 40 }));
            // Independently select the complete retained insertion descriptor; a
            // corrupted supplied path cannot choose a new root for self-review.
            let expected_input = selected_note_input(&restored, &expected);
            let effects = vec![OutputDescriptor::Exit { role: Role::A, asset: restored.asset,
                recipient: [8; 20], amount: restored.value - U256::from(3) },
                OutputDescriptor::Fee { payer: Role::A, asset: restored.asset,
                    recipient: [9; 20], amount: U256::one() }];
            let chosen_effects = effects.clone();
            let withdrawal = prepare_note_withdrawal(WithdrawalRequest {
                deployment: endpoint.scope.expected, expected_input, expiry: 703, effects,
            }, restored, path, Zeroizing::new(owner.owner_seed)).unwrap();
            assert_eq!(withdrawal.packet.input, expected_input);
            assert_eq!(&withdrawal.packet.outputs[..2], &chosen_effects);
            review_withdrawal_in_cli(&withdrawal);
            assert_eq!(withdrawal.owned_outputs.len(), 1);
            let change_key = Zeroizing::new(withdrawal.owned_outputs[0].recovery_key);
            let change_output = withdrawal.packet.outputs[2].clone();
            let change_digest = withdrawal.packet.digest().unwrap();
            let mut change_tree = tree.clone();
            let mut change_blocks = blocks.clone();
            let mut change_block = next_block(48, &change_tree, change_blocks.last().unwrap());
            consume(&mut change_block, expected_input.nullifier, hash_label(48), 0, 0);
            let change_expected = append_descriptor(&mut change_block, &mut change_tree,
                &change_output, change_digest, hash_label(48), (0, 1, 2));
            // Retain only ciphertext/recovery capability, not the typed change.
            drop(withdrawal);
            drop(change_output);
            change_blocks.push(change_block);
            change_blocks.push(next_block(49, &change_tree, change_blocks.last().unwrap()));
            let change_history = acquire(&change_blocks).await;
            let change_endpoint = change_blocks.last().unwrap();
            assert!(change_history.observed_spent(&expected_input.nullifier));
            let retained = retained_descriptor(&change_history, &change_expected.commitment);
            let change = decrypt_output(&retained, &change_key,
                &change_endpoint.scope.expected.digest().unwrap(), &owner.packet.owner_key).unwrap();
            assert_eq!(change.value, U256::from(2));
            assert_eq!(change.asset, owner.note.order.as_ref().unwrap().policy.buy_asset);
            assert_eq!(change.owner_key, owner.packet.owner_key);
            assert!(change.order.is_none());
            assert_ne!(change.nullifier().unwrap(), expected_input.nullifier);
            let change_path = prepare_note_membership(&change_history, &change_endpoint.scope,
                change_endpoint.number, &change).unwrap();
            assert_insertion(&change_path, &change_expected.insertion, &change);
            let expected_change = selected_note_input(&change, &change_expected);
            let second = prepare_note_withdrawal(WithdrawalRequest {
                deployment: change_endpoint.scope.expected, expected_input: expected_change,
                expiry: 704, effects: vec![OutputDescriptor::Exit { role: Role::A,
                    asset: change.asset, recipient: [8; 20], amount: U256::from(2) }],
            }, change, change_path, Zeroizing::new(owner.owner_seed)).unwrap();
            assert_eq!(second.packet.input, expected_change);
            assert!(second.owned_outputs.is_empty());
            assert_eq!(second.packet.outputs.len(), 1);
            review_withdrawal_in_cli(&second);
        }
    }
}
