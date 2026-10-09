//! Generated zero-consent capability custody only: no admission, backing, proving or funds.
//! The clean restorer never calls the producer or regenerates an original opening.
#![cfg(target_os = "linux")]

use chacha20poly1305::{AeadInPlace, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Barrier},
};
use zeroize::Zeroizing;
use ziquid_proofs::samechain::{
    MerkleMembership, NoteOpening, OwnerWitness, PreparedOutputOpening, decrypt_output,
    fill_consent_message, review_owner_cancel_exit, review_owner_fill, single_consent_message,
    creation::{NoteCreationWitness, note_creation_consent_message, review_note_creation},
    withdrawal::{note_withdrawal_consent_message, review_note_withdrawal},
};
use ziquid_protocol::samechain::{
    Action, Asset, Deployment, FeePolicy, InputDescriptor, OrderPolicy, OutputDescriptor,
    PublicPacket, Role, SingleOwnerPacket,
    creation::NoteCreationPacket,
    fill::{FillExecution, aggregate_commitment, owner_leaf},
    tree::NoteTree,
    withdrawal::{NoteInputDescriptor, NoteWithdrawalPacket},
};
use ziquid_runtime::{
    custody::load_preparation,
    samechain::{
        OwnedOwnerInput,
        backup::{HistoryPin, SnapshotOperation, SnapshotScope, SnapshotSelection,
            load_snapshot, save_snapshot},
        preparation::{CancelExitRequest, CreationRequest, InitialOrderRequest, WithdrawalRequest,
            prepare_cancel_exit, prepare_fill_outputs, prepare_note_creation, prepare_note_withdrawal},
    },
};

const DOMAIN: &[u8] = b"ziquid.samechain.backup.v1";
const PAYLOAD_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_PRIVATE_SNAPSHOT\0";
const CONTEXT_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_PRIVATE_SNAPSHOT_CONTEXT\0";
const NAMESPACE: [u8; 32] = [0x84; 32];
const TOKEN: [u8; 20] = [7; 20];
const CHILD_MODE: &str = "Z2Z_SNAPSHOT_TEST_MODE";
const CHILD_DIR: &str = "Z2Z_SNAPSHOT_TEST_DIRECTORY";
const REPORT_MARKER: &[u8] = b"SNAPSHOT_PUBLIC=";
const NAMES: [&str; 6] = ["creation", "fill-a", "fill-b", "cancel", "exit", "withdrawal"];

fn directory() -> tempfile::TempDir {
    tempfile::Builder::new().permissions(Permissions::from_mode(0o700)).tempdir().unwrap()
}

fn backup_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(&mut key[..]).unwrap();
    assert!(key.iter().any(|byte| *byte != 0));
    key
}

fn deployment() -> Deployment {
    Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
        verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 }
}

fn execution() -> FillExecution {
    FillExecution { asset_a: Asset::Native, asset_b: Asset::Token(TOKEN),
        sell_a: U256::from(40), sell_b: U256::from(50) }
}

fn creation(role: Role, ordered: bool, token: [u8; 20]) -> NoteCreationWitness {
    let asset = if role == Role::A { Asset::Native } else { Asset::Token(token) };
    prepare_note_creation(&CreationRequest {
        deployment: deployment(), token, payer: [8; 20], role, asset,
        amount: U256::from(105), expiry: 700,
        order: ordered.then(|| InitialOrderRequest { remaining_sell: U256::from(100),
            policy: OrderPolicy { sell_asset: asset,
                buy_asset: if role == Role::A { Asset::Token(token) } else { Asset::Native },
                min_buy_num: U256::one(), min_sell_den: U256::from(2),
                fee_policy: FeePolicy { entries: vec![] } } }),
    }).unwrap()
}

// Select from a real independent accumulator append, never membership.root().
fn insertion(note: &NoteOpening) -> (MerkleMembership, NoteInputDescriptor) {
    let tree_id = if note.asset == Asset::Native { 9 } else { 10 };
    let mut tree = NoteTree::new(note.deployment_digest, tree_id).unwrap();
    tree.append([0x66; 32]).unwrap();
    let commitment = note.commitment().unwrap();
    let selected = tree.append(commitment).unwrap();
    tree.append([0x67; 32]).unwrap();
    assert_ne!(selected.root, tree.root());
    (MerkleMembership { tree_id: selected.tree_id, index: selected.index, siblings: selected.siblings },
        NoteInputDescriptor { commitment, root: selected.root, tree_id: selected.tree_id,
            index: selected.index, nullifier: note.nullifier().unwrap(), owner_key: note.owner_key })
}

fn order_descriptor(note: &NoteOpening, input: NoteInputDescriptor) -> InputDescriptor {
    let order = note.order.as_ref().unwrap();
    InputDescriptor { commitment: input.commitment, root: input.root, tree_id: input.tree_id,
        index: input.index, nullifier: input.nullifier, owner_key: input.owner_key,
        order_id: order.id, generation: order.generation }
}

fn fill_pair() -> [OwnedOwnerInput; 2] {
    let a = creation(Role::A, true, TOKEN);
    let b = creation(Role::B, true, TOKEN);
    let approved = execution();
    let (a_path, a_input) = insertion(&a.note);
    let (b_path, b_input) = insertion(&b.note);
    let mut a_outputs = prepare_fill_outputs(&a.note, &deployment(), a.note.order.as_ref().unwrap().id,
        Role::A, approved.sell_a, approved.sell_b, &[]).unwrap();
    let mut b_outputs = prepare_fill_outputs(&b.note, &deployment(), b.note.order.as_ref().unwrap().id,
        Role::B, approved.sell_b, approved.sell_a, &[]).unwrap();
    let mut outputs = std::mem::take(&mut a_outputs.descriptors);
    let offset = outputs.len() as u32;
    outputs.append(&mut b_outputs.descriptors);
    for opening in &mut b_outputs.openings { opening.manifest_index += offset; }
    let mut packet = PublicPacket { deployment: deployment(),
        inputs: [order_descriptor(&a.note, a_input), order_descriptor(&b.note, b_input)],
        outputs, expiry: 701, terms_commitment: [0; 32] };
    let mut salts = Zeroizing::new([[0; 32]; 2]);
    getrandom::fill(&mut salts[0]).unwrap();
    getrandom::fill(&mut salts[1]).unwrap();
    let leaves = [(&a, Role::A), (&b, Role::B)].map(|(owner, role)|
        owner_leaf(&packet, &approved, role, &owner.note.order.as_ref().unwrap().policy,
            &salts[role.index()]).unwrap());
    packet.terms_commitment = aggregate_commitment(&packet, &approved, &leaves).unwrap();
    [OwnedOwnerInput::Fill(OwnerWitness { packet: packet.clone(), execution: approved, leaves,
        own_salt: salts[0], role: Role::A, owner_seed: a.owner_seed, input: a.note.clone(),
        membership: a_path, consent: [0; 64], owned_outputs: std::mem::take(&mut a_outputs.openings) }),
        OwnedOwnerInput::Fill(OwnerWitness { packet, execution: approved, leaves,
            own_salt: salts[1], role: Role::B, owner_seed: b.owner_seed, input: b.note.clone(),
            membership: b_path, consent: [0; 64], owned_outputs: std::mem::take(&mut b_outputs.openings) })]
}

fn cancel_exit(action: Action) -> OwnedOwnerInput {
    let source = creation(Role::B, true, TOKEN);
    let (membership, selected) = insertion(&source.note);
    let expected_input = order_descriptor(&source.note, selected);
    OwnedOwnerInput::CancelExit(prepare_cancel_exit(CancelExitRequest {
        deployment: deployment(), expected_input, role: Role::B, action, expiry: 702,
        effects: vec![OutputDescriptor::Exit { role: Role::B, asset: Asset::Token(TOKEN),
            recipient: [9; 20], amount: U256::from(5) }],
    }, source.note.clone(), membership, Zeroizing::new(source.owner_seed)).unwrap())
}

fn withdrawal() -> OwnedOwnerInput {
    let source = creation(Role::B, false, TOKEN);
    let (membership, expected_input) = insertion(&source.note);
    OwnedOwnerInput::Withdrawal(prepare_note_withdrawal(WithdrawalRequest {
        deployment: deployment(), expected_input, expiry: 703,
        effects: vec![OutputDescriptor::Exit { role: Role::A, asset: Asset::Token(TOKEN),
            recipient: [9; 20], amount: U256::from(5) }],
    }, source.note.clone(), membership, Zeroizing::new(source.owner_seed)).unwrap())
}

fn materials() -> Vec<OwnedOwnerInput> {
    let [a, b] = fill_pair();
    vec![OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN)), a, b,
        cancel_exit(Action::Cancel), cancel_exit(Action::Exit), withdrawal()]
}

fn encode_material(material: &OwnedOwnerInput) -> Zeroizing<Vec<u8>> {
    match material {
        OwnedOwnerInput::Creation(witness) => witness.encode().unwrap(),
        OwnedOwnerInput::Fill(witness) => witness.encode().unwrap(),
        OwnedOwnerInput::CancelExit(witness) => witness.encode().unwrap(),
        OwnedOwnerInput::Withdrawal(witness) => witness.encode().unwrap(),
    }
}

#[derive(Serialize, Deserialize)]
struct PublicReport { packets: Vec<Vec<u8>> }

fn public_packet(material: &OwnedOwnerInput) -> Vec<u8> {
    match material {
        OwnedOwnerInput::Creation(witness) => witness.packet.encode().unwrap(),
        OwnedOwnerInput::Fill(witness) => witness.packet.encode().unwrap(),
        OwnedOwnerInput::CancelExit(witness) => witness.packet.encode().unwrap(),
        OwnedOwnerInput::Withdrawal(witness) => witness.packet.encode().unwrap(),
    }
}

// Public pins are selected by the supervisor/restorer, not decoded from a backup.
fn selection(index: usize, bytes: &[u8]) -> SnapshotSelection {
    let (operation, role, digest) = match index {
        0 => { let packet = NoteCreationPacket::decode(bytes).unwrap();
            assert_eq!(packet.deployment, deployment());
            assert_eq!((packet.token, packet.role, packet.asset, packet.amount, packet.payer),
                (TOKEN, Role::A, Asset::Native, U256::from(105), [8; 20]));
            (SnapshotOperation::Creation, Role::A, packet.digest().unwrap()) }
        1 | 2 => { let packet = PublicPacket::decode(bytes).unwrap();
            assert_eq!(packet.deployment, deployment());
            (SnapshotOperation::Fill, if index == 1 { Role::A } else { Role::B }, packet.digest().unwrap()) }
        3 | 4 => { let packet = SingleOwnerPacket::decode(bytes).unwrap();
            assert_eq!(packet.deployment, deployment());
            (if index == 3 { SnapshotOperation::Cancel } else { SnapshotOperation::Exit },
                Role::B, packet.digest().unwrap()) }
        5 => { let packet = NoteWithdrawalPacket::decode(bytes).unwrap();
            assert_eq!(packet.deployment, deployment());
            (SnapshotOperation::Withdrawal, Role::A, packet.digest().unwrap()) }
        _ => panic!("invalid public slot"),
    };
    SnapshotSelection { scope: SnapshotScope::ControlledGenerated, deployment: deployment(),
        token: TOKEN, token_code: [0x91; 32], policy_id: [0x92; 32], operation, role,
        packet_digest: digest, execution: (index == 1 || index == 2).then(execution),
        history: (index != 0).then(|| HistoryPin { block_hash: [0x93; 32],
            block_number: (U256::one() << 200) + U256::from(17) }),
        elf_sha256: [0x94; 32], kit_manifest_digest: [0x95; 32] }
}

fn unsigned_message(material: &OwnedOwnerInput, expected: &SnapshotSelection) -> Vec<u8> {
    match material {
        OwnedOwnerInput::Creation(w) => { assert!(w.consent == [0; 64]);
            review_note_creation(&w.packet, w, &expected.deployment, [8; 20],
                w.packet.creation_nonce).unwrap().to_vec() }
        OwnedOwnerInput::Fill(w) => { assert!(w.consent == [0; 64]);
            review_owner_fill(&w.packet, w, &expected.deployment,
                w.packet.inputs[expected.role.index()].order_id, expected.role,
                expected.execution.as_ref().unwrap()).unwrap().to_vec() }
        OwnedOwnerInput::CancelExit(w) => { assert!(w.consent == [0; 64]);
            let action = if matches!(expected.operation, SnapshotOperation::Cancel) { Action::Cancel } else { Action::Exit };
            review_owner_cancel_exit(&w.packet, w, &expected.deployment, w.packet.input.order_id,
                expected.role, action).unwrap().to_vec() }
        OwnedOwnerInput::Withdrawal(w) => { assert!(w.consent == [0; 64]);
            review_note_withdrawal(&w.packet, w, &expected.deployment,
                w.packet.input.commitment).unwrap().to_vec() }
    }
}

fn selected_message(index: usize, bytes: &[u8]) -> Vec<u8> {
    match index {
        0 => note_creation_consent_message(&NoteCreationPacket::decode(bytes).unwrap()).unwrap().to_vec(),
        1 | 2 => fill_consent_message(&PublicPacket::decode(bytes).unwrap(),
            if index == 1 { Role::A } else { Role::B }).unwrap().to_vec(),
        3 | 4 => single_consent_message(&SingleOwnerPacket::decode(bytes).unwrap(), Role::B,
            if index == 3 { Action::Cancel } else { Action::Exit }).unwrap().to_vec(),
        5 => note_withdrawal_consent_message(&NoteWithdrawalPacket::decode(bytes).unwrap()).unwrap().to_vec(),
        _ => panic!("invalid public slot"),
    }
}

fn reuse_note(note: NoteOpening, seed: Zeroizing<[u8; 32]>, role: Role) {
    let (membership, selected) = insertion(&note);
    if note.order.is_some() {
        let expected_input = order_descriptor(&note, selected);
        let sold = U256::one();
        let prepared = prepare_fill_outputs(&note, &deployment(), expected_input.order_id,
            role, sold, U256::from(2), &[]).unwrap();
        assert!(!prepared.openings.is_empty());
        for opening in &prepared.openings {
            let recovered = decrypt_output(&prepared.descriptors[opening.manifest_index as usize],
                &opening.recovery_key, &note.deployment_digest, &note.owner_key).unwrap();
            assert!(recovered == opening.note);
        }
        let next = prepare_cancel_exit(CancelExitRequest { deployment: deployment(), expected_input,
            role, action: Action::Cancel, expiry: 800, effects: vec![] }, note, membership, seed).unwrap();
        assert!(next.consent == [0; 64]);
        review_owner_cancel_exit(&next.packet, &next, &deployment(), expected_input.order_id,
            role, Action::Cancel).unwrap();
    } else {
        let asset = note.asset;
        let next = prepare_note_withdrawal(WithdrawalRequest { deployment: deployment(),
            expected_input: selected, expiry: 800,
            effects: vec![OutputDescriptor::Exit { role: Role::A, asset,
                recipient: [10; 20], amount: U256::one() }] }, note, membership, seed).unwrap();
        assert!(next.consent == [0; 64]);
        review_note_withdrawal(&next.packet, &next, &deployment(), selected.commitment).unwrap();
        assert!(!next.owned_outputs.is_empty());
    }
}

fn reuse_outputs(outputs: &[OutputDescriptor], owned: &[PreparedOutputOpening],
    input: &NoteOpening, seed: &[u8; 32], role: Role)
{
    assert!(!owned.is_empty());
    for opening in owned {
        let recovered = decrypt_output(&outputs[opening.manifest_index as usize], &opening.recovery_key,
            &input.deployment_digest, &input.owner_key).unwrap();
        assert!(recovered == opening.note, "restored AEAD capability differs");
        reuse_note(recovered, Zeroizing::new(*seed), role);
    }
}

fn recover_capabilities(material: &OwnedOwnerInput) {
    match material {
        OwnedOwnerInput::Creation(w) => {
            let note = decrypt_output(&w.packet.output, &w.recovery_key,
                &w.note.deployment_digest, &w.packet.owner_key).unwrap();
            assert!(note == w.note);
            reuse_note(note, Zeroizing::new(w.owner_seed), w.packet.role);
        }
        OwnedOwnerInput::Fill(w) => reuse_outputs(&w.packet.outputs, &w.owned_outputs,
            &w.input, &w.owner_seed, w.role),
        OwnedOwnerInput::CancelExit(w) => reuse_outputs(&w.packet.outputs, &w.owned_outputs,
            &w.input, &w.owner_seed, w.role),
        OwnedOwnerInput::Withdrawal(w) => reuse_outputs(&w.packet.outputs, &w.owned_outputs,
            &w.input, &w.owner_seed, Role::A),
    }
}

#[test]
fn all_operations_restore_exact_complete_witness_and_reusable_unsigned_capabilities() {
    let root = directory();
    let key = backup_key();
    for (index, material) in materials().iter().enumerate() {
        let packet = public_packet(material);
        let expected = selection(index, &packet);
        let path = root.path().join(NAMES[index]);
        save_snapshot(&path, &key, NAMESPACE, &expected, material).unwrap();
        let restored = load_snapshot(&path, &key, NAMESPACE, &expected).unwrap();
        assert!(encode_material(&restored)[..] == encode_material(material)[..], "complete witness changed");
        assert_eq!(public_packet(&restored), packet);
        assert_eq!(unsigned_message(&restored, &expected), selected_message(index, &packet));
        recover_capabilities(&restored);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
    }
}

// Every spawned process has an owner that kills/reaps on error. Secrets travel
// solely over piped stdin; the child receives no witness, seed, key argv or file.
struct Process(Option<Child>);
impl Process {
    fn spawn(mode: &str, root: &Path) -> Self {
        Self(Some(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "snapshot_process", "--ignored", "--nocapture", "--test-threads=1"])
            .env_clear().env(CHILD_MODE, mode).env(CHILD_DIR, root)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()))
    }
    fn exchange(mut self, key: &[u8; 32], public: Option<&PublicReport>) -> Output {
        let child = self.0.as_mut().unwrap();
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(key).unwrap();
        if let Some(public) = public {
            let bytes = serde_json::to_vec(public).unwrap();
            pipe.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
            pipe.write_all(&bytes).unwrap();
        }
        drop(pipe);
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 { let _ = child.kill(); let _ = child.wait(); }
    }
}

#[test]
#[ignore = "private subprocess entry, launched by clean_process_snapshot_restore"]
fn snapshot_process() {
    let mode = std::env::var(CHILD_MODE).expect("missing public process mode");
    let root = PathBuf::from(std::env::var_os(CHILD_DIR).expect("missing public snapshot directory"));
    let mut stdin = std::io::stdin().lock();
    let mut key = Zeroizing::new([0; 32]);
    stdin.read_exact(&mut key[..]).unwrap();
    match mode.as_str() {
        "produce" => {
            let material = materials();
            let public = PublicReport { packets: material.iter().map(public_packet).collect() };
            for (index, material) in material.iter().enumerate() {
                let expected = selection(index, &public.packets[index]);
                assert_eq!(unsigned_message(material, &expected), selected_message(index, &public.packets[index]));
                save_snapshot(root.join(NAMES[index]), &key, NAMESPACE, &expected, material).unwrap();
            }
            // Only complete public packets are returned. No original witness is
            // encoded on stdout or retained in the supervisor.
            print!("SNAPSHOT_PUBLIC=");
            serde_json::to_writer(std::io::stdout().lock(), &public).unwrap();
            println!();
        }
        "restore" => {
            let mut length = [0; 4];
            stdin.read_exact(&mut length).unwrap();
            let length = u32::from_be_bytes(length) as usize;
            assert!(length <= 6 * 64 * 1024 * 4);
            let mut bytes = vec![0; length];
            stdin.read_exact(&mut bytes).unwrap();
            let public: PublicReport = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(public.packets.len(), NAMES.len());
            let mut eof = [0; 1];
            assert_eq!(stdin.read(&mut eof).unwrap(), 0);
            for (index, packet) in public.packets.iter().enumerate() {
                let expected = selection(index, packet);
                let restored = load_snapshot(root.join(NAMES[index]), &key, NAMESPACE, &expected).unwrap();
                assert_eq!(public_packet(&restored), *packet);
                assert_eq!(unsigned_message(&restored, &expected), selected_message(index, packet));
                recover_capabilities(&restored);
                save_snapshot(root.join(NAMES[index]), &key, NAMESPACE, &expected, &restored).unwrap();
            }
        }
        _ => panic!("invalid public process mode"),
    }
}

#[test]
fn clean_process_snapshot_restore() {
    let root = directory();
    let key = backup_key();
    // exchange waits and reaps before any restorer can be created.
    let produced = Process::spawn("produce", root.path()).exchange(&key, None);
    assert!(produced.status.success(), "generated snapshot producer failed");
    assert!(produced.stderr.is_empty(), "producer emitted a diagnostic");
    let start = produced.stdout.windows(REPORT_MARKER.len()).position(|bytes| bytes == REPORT_MARKER)
        .expect("public producer report absent") + REPORT_MARKER.len();
    let end = produced.stdout[start..].iter().position(|byte| *byte == b'\n').unwrap() + start;
    let public: PublicReport = serde_json::from_slice(&produced.stdout[start..end]).unwrap();
    assert_eq!(public.packets.len(), NAMES.len());
    // Independent descriptor validation happens after producer death, outside it.
    for (index, packet) in public.packets.iter().enumerate() { let _ = selection(index, packet); }
    let original: Vec<_> = NAMES.iter().map(|name| fs::read(root.path().join(name)).unwrap()).collect();
    let restored = Process::spawn("restore", root.path()).exchange(&key, Some(&public));
    assert!(restored.status.success(), "fresh snapshot restore/reuse failed");
    assert!(restored.stderr.is_empty(), "restorer emitted a diagnostic");
    for (name, original) in NAMES.iter().zip(original) {
        assert_eq!(fs::read(root.path().join(name)).unwrap(), original, "restore retry replaced retained bytes");
    }
    for stream in [&produced.stdout, &produced.stderr, &restored.stdout, &restored.stderr] {
        assert!(!stream.windows(32).any(|bytes| bytes == &key[..]), "backup key disclosed");
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), NAMES.len(), "non-ciphertext artifact left behind");
}

fn pending(path: &Path) -> PathBuf {
    path.with_file_name(format!(".{}.pending", path.file_name().unwrap().to_str().unwrap()))
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn every_independent_context_pin_and_private_capability_is_revalidated() {
    let root = directory();
    let key = backup_key();
    let [material, _] = fill_pair();
    let packet = public_packet(&material);
    let expected = selection(1, &packet);
    let path = root.path().join("retained");
    save_snapshot(&path, &key, NAMESPACE, &expected, &material).unwrap();
    let original = fs::read(&path).unwrap();
    let changes: &[fn(&mut SnapshotSelection)] = &[
        |s| s.scope = SnapshotScope::IndependentlySelected,
        |s| s.deployment.chain_id += 1,
        |s| s.deployment.authority[0] ^= 1,
        |s| s.deployment.authority_code[0] ^= 1,
        |s| s.deployment.verifier[0] ^= 1,
        |s| s.deployment.verifier_code[0] ^= 1,
        |s| s.deployment.owner_program[0] ^= 1,
        |s| s.deployment.schema += 1,
        |s| s.token[0] ^= 1,
        |s| s.token_code[0] ^= 1,
        |s| s.policy_id[0] ^= 1,
        |s| s.operation = SnapshotOperation::Cancel,
        |s| s.role = Role::B,
        |s| s.packet_digest[0] ^= 1,
        |s| s.execution.as_mut().unwrap().sell_a += U256::one(),
        |s| s.execution.as_mut().unwrap().sell_b += U256::one(),
        |s| s.execution.as_mut().unwrap().asset_a = Asset::Token([10; 20]),
        |s| s.execution = None,
        |s| s.history.as_mut().unwrap().block_hash[0] ^= 1,
        |s| s.history.as_mut().unwrap().block_number += U256::one(),
        |s| s.history.as_mut().unwrap().block_number ^= U256::one() << 200,
        |s| s.history = None,
        |s| s.elf_sha256[0] ^= 1,
        |s| s.kit_manifest_digest[0] ^= 1,
    ];
    for change in changes {
        let mut wrong = selection(1, &packet);
        change(&mut wrong);
        assert!(load_snapshot(&path, &key, NAMESPACE, &wrong).is_err(), "context pin was ignored");
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    assert!(load_snapshot(&path, &[0x66; 32], NAMESPACE, &expected).is_err());
    assert!(load_snapshot(&path, &key, [0x67; 32], &expected).is_err());
    assert!(save_snapshot(&path, &[0x66; 32], NAMESPACE, &expected, &material).is_err());
    assert!(save_snapshot(&path, &key, [0x67; 32], &expected, &material).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);

    let mutations: &[fn(&mut OwnerWitness)] = &[
        |w| w.owner_seed[0] ^= 1,
        |w| w.membership.siblings[0][0] ^= 1,
        |w| w.input.value += U256::one(),
        |w| w.input.nf_key[0] ^= 1,
        |w| w.own_salt[0] ^= 1,
        |w| w.leaves[w.role.index()][0] ^= 1,
        |w| w.owned_outputs[0].recovery_key[0] ^= 1,
        |w| w.owned_outputs[0].note.value += U256::one(),
        |w| w.owned_outputs[0].manifest_index += 1,
        |w| w.owned_outputs.clear(),
        |w| w.consent[0] = 1,
    ];
    let encoded = encode_material(&material);
    for (index, mutate) in mutations.iter().enumerate() {
        let mut witness = OwnerWitness::decode(&encoded).unwrap();
        mutate(&mut witness);
        let invalid = OwnedOwnerInput::Fill(witness);
        let target = root.path().join(format!("invalid-{index}"));
        assert!(save_snapshot(&target, &key, NAMESPACE, &expected, &invalid).is_err());
        assert!(!target.exists());
        assert!(save_snapshot(&path, &key, NAMESPACE, &expected, &invalid).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn selection_shape_fixed_token_and_nonzero_consent_reject_before_publication() {
    let root = directory();
    let key = backup_key();
    for (index, material) in materials().into_iter().enumerate() {
        let packet = public_packet(&material);
        let changes: &[fn(&mut SnapshotSelection)] = &[
            |s| s.token = [0; 20], |s| s.token_code = [0; 32],
            |s| s.policy_id = [0; 32], |s| s.packet_digest = [0; 32],
            |s| s.elf_sha256 = [0; 32], |s| s.kit_manifest_digest = [0; 32],
            |s| s.deployment.authority = [0; 20], |s| s.token = [10; 20],
        ];
        for (case, change) in changes.iter().enumerate() {
            let mut expected = selection(index, &packet);
            change(&mut expected);
            let path = root.path().join(format!("shape-{index}-{case}"));
            assert!(save_snapshot(&path, &key, NAMESPACE, &expected, &material).is_err());
            assert!(!path.exists());
        }
        let expected = selection(index, &packet);
        assert!(save_snapshot(root.path().join(format!("namespace-{index}")), &key,
            [0; 32], &expected, &material).is_err());
        let mut wrong = selection(index, &packet);
        if index == 0 {
            wrong.history = Some(HistoryPin { block_hash: [1; 32], block_number: U256::one() });
        } else {
            wrong.history.as_mut().unwrap().block_hash = [0; 32];
        }
        assert!(save_snapshot(root.path().join(format!("history-{index}")), &key,
            NAMESPACE, &wrong, &material).is_err());
        if index != 1 && index != 2 {
            let mut wrong = selection(index, &packet);
            wrong.execution = Some(execution());
            assert!(save_snapshot(root.path().join(format!("execution-{index}")), &key,
                NAMESPACE, &wrong, &material).is_err());
        }
        if index == 5 {
            let mut wrong = selection(index, &packet);
            wrong.role = Role::B;
            assert!(save_snapshot(root.path().join("withdrawal-role"), &key,
                NAMESPACE, &wrong, &material).is_err());
        }
        let mut invalid = material;
        match &mut invalid {
            OwnedOwnerInput::Creation(w) => w.consent[0] = 1,
            OwnedOwnerInput::Fill(w) => w.consent[0] = 1,
            OwnedOwnerInput::CancelExit(w) => w.consent[0] = 1,
            OwnedOwnerInput::Withdrawal(w) => w.consent[0] = 1,
        }
        assert!(save_snapshot(root.path().join(format!("partial-consent-{index}")), &key,
            NAMESPACE, &expected, &invalid).is_err());
    }
    // A semantically valid foreign-token creation first works under its actual
    // token pin. Contradictory fixed-token metadata must then be rejected.
    let foreign = OwnedOwnerInput::Creation(creation(Role::B, true, [10; 20]));
    let packet = public_packet(&foreign);
    let parsed = NoteCreationPacket::decode(&packet).unwrap();
    let mut expected = selection(0, &public_packet(&OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN))));
    expected.token = [10; 20];
    expected.role = Role::B;
    expected.packet_digest = parsed.digest().unwrap();
    let path = root.path().join("valid-foreign");
    save_snapshot(&path, &key, NAMESPACE, &expected, &foreign).unwrap();
    assert!(load_snapshot(&path, &key, NAMESPACE, &expected).is_ok());
    expected.token = TOKEN;
    assert!(save_snapshot(root.path().join("mislabelled-foreign"), &key,
        NAMESPACE, &expected, &foreign).is_err());
}

// Independent spec encoding, intentionally not a production codec/test hook.
fn selection_frame(s: &SnapshotSelection) -> Vec<u8> {
    let mut bytes = vec![match s.scope {
        SnapshotScope::ControlledGenerated => 0, SnapshotScope::IndependentlySelected => 1 }];
    let deployment = s.deployment.encode().unwrap();
    bytes.extend_from_slice(&(deployment.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&deployment);
    bytes.extend_from_slice(&s.token);
    bytes.extend_from_slice(&s.token_code);
    bytes.extend_from_slice(&s.policy_id);
    bytes.push(match s.operation { SnapshotOperation::Fill => 0, SnapshotOperation::Cancel => 1,
        SnapshotOperation::Exit => 2, SnapshotOperation::Withdrawal => 3, SnapshotOperation::Creation => 4 });
    bytes.push(s.role as u8);
    bytes.extend_from_slice(&s.packet_digest);
    bytes.push(u8::from(s.execution.is_some()));
    if let Some(execution) = &s.execution {
        let frame = execution.encode().unwrap();
        bytes.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&frame);
    }
    bytes.push(u8::from(s.history.is_some()));
    if let Some(history) = &s.history {
        bytes.extend_from_slice(&history.block_hash);
        let mut number = [0; 32];
        history.block_number.to_big_endian(&mut number);
        bytes.extend_from_slice(&number);
    }
    bytes.extend_from_slice(&s.elf_sha256);
    bytes.extend_from_slice(&s.kit_manifest_digest);
    bytes
}

fn context(s: &SnapshotSelection) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CONTEXT_DOMAIN);
    hash.update(1u16.to_be_bytes());
    hash.update(selection_frame(s));
    hash.finalize().into()
}

fn decrypt_envelope(bytes: &[u8], key: &[u8; 32], s: &SnapshotSelection) -> Zeroizing<Vec<u8>> {
    let header_len = DOMAIN.len() + 24 + 4;
    assert_eq!(&bytes[..DOMAIN.len()], DOMAIN);
    let length = u32::from_le_bytes(bytes[header_len - 4..header_len].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), header_len + length);
    let mut aad = bytes[..header_len].to_vec();
    aad.extend_from_slice(&NAMESPACE);
    aad.extend_from_slice(&context(s));
    let mut plain = Zeroizing::new(bytes[header_len..bytes.len() - 16].to_vec());
    XChaCha20Poly1305::new(key.into()).decrypt_in_place_detached(
        XNonce::from_slice(&bytes[DOMAIN.len()..DOMAIN.len() + 24]), &aad, &mut plain,
        Tag::from_slice(&bytes[bytes.len() - 16..])).unwrap();
    plain
}

fn authenticate_payload(mut plain: Zeroizing<Vec<u8>>, key: &[u8; 32],
    s: &SnapshotSelection) -> Vec<u8>
{
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).unwrap();
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&((plain.len() + 16) as u32).to_le_bytes());
    let mut aad = bytes.clone();
    aad.extend_from_slice(&NAMESPACE);
    aad.extend_from_slice(&context(s));
    let tag = XChaCha20Poly1305::new(key.into()).encrypt_in_place_detached(
        XNonce::from_slice(&nonce), &aad, &mut plain).unwrap();
    bytes.extend_from_slice(&plain);
    bytes.extend_from_slice(&tag);
    bytes
}

#[test]
fn actual_envelopes_use_exact_spec_context_framing_and_guest_modes() {
    let root = directory();
    let key = backup_key();
    for (index, material) in materials().iter().enumerate() {
        let s = selection(index, &public_packet(material));
        let path = root.path().join(NAMES[index]);
        save_snapshot(&path, &key, NAMESPACE, &s, material).unwrap();
        let plain = decrypt_envelope(&fs::read(&path).unwrap(), &key, &s);
        assert_eq!(&plain[..PAYLOAD_DOMAIN.len()], PAYLOAD_DOMAIN);
        assert_eq!(&plain[PAYLOAD_DOMAIN.len()..PAYLOAD_DOMAIN.len() + 2], &1u16.to_be_bytes());
        let length_at = PAYLOAD_DOMAIN.len() + 2;
        let selection_len = u32::from_be_bytes(plain[length_at..length_at + 4].try_into().unwrap()) as usize;
        let mode_at = length_at + 4 + selection_len;
        assert_eq!(&plain[length_at + 4..mode_at], selection_frame(&s));
        assert_eq!(plain[mode_at], [3, 0, 0, 1, 1, 2][index], "snapshot code used as guest mode");
        let witness_len = u32::from_be_bytes(plain[mode_at + 1..mode_at + 5].try_into().unwrap()) as usize;
        assert_eq!(plain.len(), mode_at + 5 + witness_len);
        assert!(plain[mode_at + 5..] == encode_material(material)[..]);
    }
}

#[test]
fn authenticated_noncanonical_frames_and_invalid_witnesses_reject_on_actual_load() {
    let root = directory();
    let key = backup_key();
    let material = OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN));
    let s = selection(0, &public_packet(&material));
    let path = root.path().join("source");
    save_snapshot(&path, &key, NAMESPACE, &s, &material).unwrap();
    let original = fs::read(&path).unwrap();
    let plain = decrypt_envelope(&original, &key, &s);
    let length_at = PAYLOAD_DOMAIN.len() + 2;
    let selection_at = length_at + 4;
    let selection_len = selection_frame(&s).len();
    let mode_at = selection_at + selection_len;
    let deployment_length = s.deployment.encode().unwrap().len();
    let operation_at = selection_at + 1 + 4 + deployment_length + 20 + 32 + 32;
    let execution_at = operation_at + 2 + 32;
    type PayloadMutation = fn(&mut Vec<u8>, usize, usize, usize, usize, usize);
    let mutations: &[PayloadMutation] = &[
        |p, _, _, _, _, _| p[0] ^= 1,
        |p, _, _, _, _, _| p[PAYLOAD_DOMAIN.len() + 1] = 2,
        |p, _, s, _, _, _| p[s] = 2,
        |p, _, s, _, _, _| p[s + 1..s + 5].copy_from_slice(&u32::MAX.to_be_bytes()),
        |p, _, s, _, _, _| p[s + 5] ^= 1,
        |p, _, _, _, o, _| p[o] = 5,
        |p, _, _, _, o, _| p[o + 1] = 2,
        |p, _, _, _, _, e| p[e] = 2,
        |p, _, _, _, _, e| p[e + 1] = 2,
        |p, _, _, m, _, _| p[m] = 4,
        |p, _, _, m, _, _| p[m] = 0,
        |p, l, _, _, _, _| p[l..l + 4].copy_from_slice(&u32::MAX.to_be_bytes()),
        |p, _, _, m, _, _| p[m + 1..m + 5].copy_from_slice(&u32::MAX.to_be_bytes()),
        |p, _, _, m, _, _| p[m + 5] ^= 1,
        |p, _, _, _, _, _| { p.pop(); },
        |p, _, _, _, _, _| p.push(0),
    ];
    for (case, mutation) in mutations.iter().enumerate() {
        // Capacity is complete before copying a secret buffer, including suffix.
        let mut invalid = Zeroizing::new(Vec::with_capacity(plain.len() + 1));
        invalid.extend_from_slice(&plain);
        mutation(&mut invalid, length_at, selection_at, mode_at, operation_at, execution_at);
        let bytes = authenticate_payload(invalid, &key, &s);
        let target = root.path().join(format!("frame-{case}"));
        write_private(&target, &bytes);
        assert!(load_snapshot(&target, &key, NAMESPACE, &s).is_err(), "authenticated invalid frame accepted");
        assert_eq!(fs::read(&target).unwrap(), bytes);
    }
    // Validly framed, correctly authenticated, but private AEAD/owner/consent
    // semantics corrupted: load must review, not merely parse/authenticate.
    for case in 0..3 {
        let OwnedOwnerInput::Creation(w) = &material else { unreachable!() };
        let mut bad = NoteCreationWitness::decode(&w.encode().unwrap()).unwrap();
        match case { 0 => bad.owner_seed[0] ^= 1, 1 => bad.recovery_key[0] ^= 1,
            2 => bad.consent[0] = 1, _ => unreachable!() }
        let witness = bad.encode().unwrap();
        let mut payload = Zeroizing::new(Vec::with_capacity(mode_at + 5 + witness.len()));
        payload.extend_from_slice(&plain[..mode_at + 1]);
        payload.extend_from_slice(&(witness.len() as u32).to_be_bytes());
        payload.extend_from_slice(&witness);
        let bytes = authenticate_payload(payload, &key, &s);
        let target = root.path().join(format!("semantic-{case}"));
        write_private(&target, &bytes);
        assert!(load_snapshot(&target, &key, NAMESPACE, &s).is_err());
        assert_eq!(fs::read(&target).unwrap(), bytes);
    }
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn immutable_retry_interrupted_staging_and_older_snapshots_preserve_exact_bytes() {
    let root = directory();
    let key = backup_key();
    let material = OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN));
    let expected = selection(0, &public_packet(&material));
    let path = root.path().join("older");
    save_snapshot(&path, &key, NAMESPACE, &expected, &material).unwrap();
    let original = fs::read(&path).unwrap();
    save_snapshot(&path, &key, NAMESPACE, &expected, &material).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    let newer = OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN));
    let newer_selection = selection(0, &public_packet(&newer));
    assert!(save_snapshot(&path, &key, NAMESPACE, &newer_selection, &newer).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    save_snapshot(root.path().join("newer"), &key, NAMESPACE, &newer_selection, &newer).unwrap();
    assert!(encode_material(&load_snapshot(&path, &key, NAMESPACE, &expected).unwrap())[..]
        == encode_material(&material)[..]);
    let complete = root.path().join("complete-stage");
    write_private(&pending(&complete), &original);
    save_snapshot(&complete, &key, NAMESPACE, &expected, &material).unwrap();
    assert_eq!(fs::read(&complete).unwrap(), original);
    assert!(!pending(&complete).exists());
    for (index, bytes) in [Vec::new(), DOMAIN.to_vec(), original[..original.len() / 2].to_vec()]
        .into_iter().enumerate()
    {
        let target = root.path().join(format!("interrupted-{index}"));
        write_private(&pending(&target), &bytes);
        assert!(load_snapshot(&target, &key, NAMESPACE, &expected).is_err());
        save_snapshot(&target, &key, NAMESPACE, &expected, &material).unwrap();
        assert!(load_snapshot(&target, &key, NAMESPACE, &expected).is_ok());
        assert!(!pending(&target).exists());
    }
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let target = root.path().join("unauthenticated-stage");
    write_private(&pending(&target), &tampered);
    assert!(save_snapshot(&target, &key, NAMESPACE, &expected, &material).is_err());
    assert_eq!(fs::read(pending(&target)).unwrap(), tampered);
    assert!(!target.exists());
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn concurrent_identical_and_different_publishers_never_replace_a_winner() {
    for different in [false, true] {
        let root = directory();
        let key = backup_key();
        let first = OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN));
        let second = if different { OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN)) }
            else { OwnedOwnerInput::Creation(NoteCreationWitness::decode(&encode_material(&first)).unwrap()) };
        let path = root.path().join("owner/private/artifact");
        let barrier = Arc::new(Barrier::new(2));
        let candidates = [first, second].map(|material| {
            let expected = selection(0, &public_packet(&material));
            (material, expected)
        });
        let public: Vec<_> = candidates.iter().map(|(material, _)| public_packet(material)).collect();
        let results = std::thread::scope(|scope| {
            let workers: Vec<_> = candidates.iter().map(|(material, expected)| {
                let barrier = Arc::clone(&barrier);
                let path = &path;
                let key = &key;
                scope.spawn(move || { barrier.wait(); save_snapshot(path, key, NAMESPACE, expected, material) })
            }).collect();
            workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), if different { 1 } else { 2 });
        let winner = candidates.iter().find_map(|(_, expected)|
            load_snapshot(&path, &key, NAMESPACE, expected).ok()).unwrap();
        assert!(public.contains(&public_packet(&winner)));
        assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
        assert!(!pending(&path).exists());
    }
}

#[test]
fn native_crossformat_shared_retained_unknown_prefixes_are_never_discarded() {
    let root = directory();
    let key = backup_key();
    let material = OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN));
    let expected = selection(0, &public_packet(&material));
    let prefixes: &[&[u8]] = &[
        b"z", b"ziquid.", b"ziquid.u.custody.v", b"ziquid.u.custody.v1",
        b"ziquid.u.custody.v2", b"ziquid.u.custody.v3", b"ziquid.u.custody.v9",
        b"ziquid.samechain.backup.v", b"ziquid.samechain.backup.v9", b"unknown-format",
    ];
    for (index, prefix) in prefixes.iter().enumerate() {
        for suffix in [false, true] {
            let mut bytes = prefix.to_vec();
            if suffix { bytes.extend_from_slice(&[0x77; 80]); }
            let final_path = root.path().join(format!("foreign-final-{index}-{suffix}"));
            write_private(&final_path, &bytes);
            assert!(load_snapshot(&final_path, &key, NAMESPACE, &expected).is_err());
            assert!(save_snapshot(&final_path, &key, NAMESPACE, &expected, &material).is_err());
            assert_eq!(fs::read(&final_path).unwrap(), bytes);
            let target = root.path().join(format!("foreign-stage-{index}-{suffix}"));
            write_private(&pending(&target), &bytes);
            assert!(save_snapshot(&target, &key, NAMESPACE, &expected, &material).is_err());
            assert!(!target.exists());
            assert_eq!(fs::read(pending(&target)).unwrap(), bytes);
        }
    }
    // Reverse direction through the real native public load, not a dummy P/Q
    // preparation. Reverse native save-staging is the publisher worker's suite.
    let snapshot = root.path().join("snapshot");
    save_snapshot(&snapshot, &key, NAMESPACE, &expected, &material).unwrap();
    let bytes = fs::read(&snapshot).unwrap();
    assert!(load_preparation(&snapshot, &key, NAMESPACE, [0x91; 32]).is_err());
    assert_eq!(fs::read(&snapshot).unwrap(), bytes);
    for (index, prefix) in [b"ziquid.".as_slice(), b"ziquid.samechain.backup.v".as_slice(),
        DOMAIN, b"ziquid.samechain.backup.v9".as_slice(), bytes.as_slice()].into_iter().enumerate()
    {
        let target = root.path().join(format!("native-stage-{index}"));
        write_private(&pending(&target), prefix);
        assert!(load_preparation(&target, &key, NAMESPACE, [0x91; 32]).is_err());
        assert_eq!(fs::read(pending(&target)).unwrap(), prefix);
        assert!(!target.exists());
    }
}

#[test]
fn corruption_truncation_suffix_future_and_bounded_envelopes_remain_untouched() {
    let root = directory();
    let key = backup_key();
    let material = OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN));
    let expected = selection(0, &public_packet(&material));
    let source = root.path().join("source");
    save_snapshot(&source, &key, NAMESPACE, &expected, &material).unwrap();
    let original = fs::read(&source).unwrap();
    let mut cases = vec![Vec::new(), original[..DOMAIN.len() - 1].to_vec(), DOMAIN.to_vec(),
        original[..original.len() - 1].to_vec()];
    for offset in [0, DOMAIN.len(), DOMAIN.len() + 24, DOMAIN.len() + 24 + 4, original.len() - 1] {
        let mut bytes = original.clone(); bytes[offset] ^= 1; cases.push(bytes);
    }
    let mut suffix = original.clone(); suffix.push(0); cases.push(suffix);
    let mut future = original.clone(); future[DOMAIN.len() - 1] = b'9'; cases.push(future);
    let mut advertised = original.clone();
    advertised[DOMAIN.len() + 24..DOMAIN.len() + 28].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(advertised);
    for (index, bytes) in cases.iter().enumerate() {
        let target = root.path().join(format!("invalid-envelope-{index}"));
        write_private(&target, bytes);
        assert!(load_snapshot(&target, &key, NAMESPACE, &expected).is_err());
        assert!(save_snapshot(&target, &key, NAMESPACE, &expected, &material).is_err());
        assert_eq!(fs::read(target).unwrap(), *bytes);
    }
    let target = root.path().join("oversized-sparse");
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&target).unwrap();
    file.set_len(256 * 1024 + 65_536).unwrap();
    assert!(load_snapshot(&target, &key, NAMESPACE, &expected).is_err());
    assert!(save_snapshot(&target, &key, NAMESPACE, &expected, &material).is_err());
    assert_eq!(file.metadata().unwrap().len(), 256 * 1024 + 65_536);
    assert_eq!(fs::read(&source).unwrap(), original);
}

#[test]
fn unsafe_filesystem_objects_permissions_ancestors_and_reserved_names_reject() {
    let root = directory();
    let key = backup_key();
    let material = OwnedOwnerInput::Creation(creation(Role::A, true, TOKEN));
    let expected = selection(0, &public_packet(&material));
    for basename in [".hidden", ".artifact.pending", ".artifact"] {
        let parent = root.path().join(format!("fresh-{basename}"));
        let path = parent.join(basename);
        assert!(save_snapshot(&path, &key, NAMESPACE, &expected, &material).is_err());
        assert!(load_snapshot(&path, &key, NAMESPACE, &expected).is_err());
        assert!(!parent.exists());
    }
    let target = root.path().join("unrelated-owner-data");
    write_private(&target, b"unrelated retained bytes");
    for staging in [false, true] {
        let path = root.path().join(format!("symlink-{staging}"));
        symlink(&target, if staging { pending(&path) } else { path.clone() }).unwrap();
        assert!(save_snapshot(&path, &key, NAMESPACE, &expected, &material).is_err());
        assert!(load_snapshot(&path, &key, NAMESPACE, &expected).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unrelated retained bytes");
    }
    let real = root.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, Permissions::from_mode(0o700)).unwrap();
    let alias = root.path().join("alias"); symlink(&real, &alias).unwrap();
    assert!(save_snapshot(alias.join("artifact"), &key, NAMESPACE, &expected, &material).is_err());
    assert!(!real.join("artifact").exists());
    assert!(save_snapshot(real.join("../escape"), &key, NAMESPACE, &expected, &material).is_err());
    assert!(!root.path().join("escape").exists());
    let path = root.path().join("committed");
    save_snapshot(&path, &key, NAMESPACE, &expected, &material).unwrap();
    let original = fs::read(&path).unwrap();
    for mode in [0o644, 0o400, 0o2600] {
        fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
        assert!(load_snapshot(&path, &key, NAMESPACE, &expected).is_err());
        assert!(save_snapshot(&path, &key, NAMESPACE, &expected, &material).is_err());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, mode);
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, root.path().join("hardlink")).unwrap();
    assert!(load_snapshot(&path, &key, NAMESPACE, &expected).is_err());
    assert!(save_snapshot(&path, &key, NAMESPACE, &expected, &material).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    for mode in [0o755, 0o770, 0o707, 0o777, 0o1770] {
        let ancestor = root.path().join(format!("mode-{mode:o}"));
        fs::create_dir(&ancestor).unwrap();
        fs::set_permissions(&ancestor, Permissions::from_mode(mode)).unwrap();
        assert!(save_snapshot(ancestor.join("artifact"), &key, NAMESPACE, &expected, &material).is_err());
        assert!(!ancestor.join("artifact").exists());
        if mode != 0o755 {
            assert!(save_snapshot(ancestor.join("private/artifact"), &key, NAMESPACE, &expected, &material).is_err());
            assert!(!ancestor.join("private").exists());
        }
    }
    let fifo = root.path().join("fifo");
    rustix::fs::mknodat(rustix::fs::CWD, &fifo, rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_bits_truncate(0o600), 0).unwrap();
    assert!(load_snapshot(&fifo, &key, NAMESPACE, &expected).is_err());
    assert!(save_snapshot(&fifo, &key, NAMESPACE, &expected, &material).is_err());
    assert!(fifo.exists());
    let blocker = root.path().join("private-path-marker");
    write_private(&blocker, b"not a directory");
    let error = save_snapshot(blocker.join("artifact"), &key, NAMESPACE, &expected, &material).unwrap_err();
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(root.path().to_str().unwrap()));
    assert!(!rendered.contains("private-path-marker"));
    let debug = format!("{material:?}");
    assert!(debug.to_ascii_lowercase().contains("redacted"));
    assert!(!debug.contains("owner_seed"));
    assert!(!debug.contains("recovery_key"));
}
