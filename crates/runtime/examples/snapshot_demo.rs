//! Demo-only encrypted snapshot round-trip for the S2 harness segment.
//!
//! `save <outdir>` generates one fixture Creation capability, writes an
//! encrypted snapshot, a 0600 key sidecar and a public selection JSON, then
//! prints the paths and a key fingerprint (never the key bytes).
//! `restore <file> <selection-json>` runs in a fresh process, loads and
//! authenticates the snapshot against an independent selection and prints OK.
//!
//! Fixture only: no chain-valid note/anchor, no funds, no node action. The key
//! sidecar is demo-private and must not be copied into demo/out.

use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::process::ExitCode;
use ziquid_protocol::samechain::{Asset, Deployment, Role};
use ziquid_runtime::samechain::{
    OwnedOwnerInput,
    backup::{SnapshotOperation, SnapshotScope, SnapshotSelection, load_snapshot, save_snapshot},
    preparation::{CreationRequest, prepare_note_creation},
};

const NAMESPACE: [u8; 32] = [0x84; 32];
const TOKEN: [u8; 20] = [7; 20];

fn deployment() -> Deployment {
    Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
        verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 }
}

fn fixture() -> (OwnedOwnerInput, SnapshotSelection) {
    let witness = prepare_note_creation(&CreationRequest {
        deployment: deployment(), token: TOKEN, payer: [8; 20], role: Role::A,
        asset: Asset::Native, amount: U256::from(105), expiry: 700, order: None,
    }).unwrap();
    let selection = SnapshotSelection {
        scope: SnapshotScope::ControlledGenerated, deployment: deployment(), token: TOKEN,
        token_code: [0x91; 32], policy_id: [0x92; 32], operation: SnapshotOperation::Creation,
        role: Role::A, packet_digest: witness.packet.digest().unwrap(),
        execution: None, history: None, elf_sha256: [0x94; 32], kit_manifest_digest: [0x95; 32],
    };
    (OwnedOwnerInput::Creation(witness), selection)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

fn unhex(text: &str) -> Vec<u8> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn fixed<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().unwrap()
}

#[derive(Serialize, Deserialize)]
struct SelectionJson {
    scope: u8,
    deployment_hex: String,
    token_hex: String,
    token_code_hex: String,
    policy_id_hex: String,
    operation: u8,
    role: u8,
    packet_digest_hex: String,
    elf_sha256_hex: String,
    kit_manifest_digest_hex: String,
}

fn encode_selection(selection: &SnapshotSelection) -> SelectionJson {
    SelectionJson {
        scope: selection.scope as u8,
        deployment_hex: hex(&selection.deployment.encode().unwrap()),
        token_hex: hex(&selection.token), token_code_hex: hex(&selection.token_code),
        policy_id_hex: hex(&selection.policy_id), operation: selection.operation as u8,
        role: selection.role as u8, packet_digest_hex: hex(&selection.packet_digest),
        elf_sha256_hex: hex(&selection.elf_sha256),
        kit_manifest_digest_hex: hex(&selection.kit_manifest_digest),
    }
}

fn decode_selection(json: &SelectionJson) -> SnapshotSelection {
    SnapshotSelection {
        scope: if json.scope == 0 { SnapshotScope::ControlledGenerated }
            else { SnapshotScope::IndependentlySelected },
        deployment: Deployment::decode(&unhex(&json.deployment_hex)).unwrap(),
        token: fixed(&json.token_hex), token_code: fixed(&json.token_code_hex),
        policy_id: fixed(&json.policy_id_hex),
        operation: match json.operation {
            0 => SnapshotOperation::Fill, 1 => SnapshotOperation::Cancel,
            2 => SnapshotOperation::Exit, 3 => SnapshotOperation::Withdrawal,
            _ => SnapshotOperation::Creation,
        },
        role: if json.role == 0 { Role::A } else { Role::B },
        packet_digest: fixed(&json.packet_digest_hex),
        execution: None, history: None, elf_sha256: fixed(&json.elf_sha256_hex),
        kit_manifest_digest: fixed(&json.kit_manifest_digest_hex),
    }
}

fn save(outdir: &str) -> ExitCode {
    let dir = std::path::Path::new(outdir);
    std::fs::create_dir_all(dir).unwrap();
    let (material, selection) = fixture();
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut key[..]).unwrap();
    let snapshot = dir.join("snapshot.bin");
    save_snapshot(&snapshot, &key, NAMESPACE, &selection, &material).unwrap();
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true).create_new(true).mode(0o600).open(snapshot.with_extension("key")).unwrap();
        file.write_all(&key[..]).unwrap();
    }
    let selection_path = snapshot.with_extension("selection.json");
    std::fs::write(&selection_path, serde_json::to_vec(&encode_selection(&selection)).unwrap()).unwrap();
    let fingerprint = {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(&key[..]);
        hash.finalize()
    };
    println!("SNAPSHOT {}", snapshot.display());
    println!("KEY_FINGERPRINT {}", hex(&fingerprint[..8]));
    println!("SELECTION {}", selection_path.display());
    println!("SAVE_OK");
    ExitCode::SUCCESS
}

fn restore(file: &str, selection_file: &str) -> ExitCode {
    let snapshot = std::path::Path::new(file);
    let key: [u8; 32] = std::fs::read(snapshot.with_extension("key")).unwrap().try_into().unwrap();
    let json: SelectionJson = serde_json::from_slice(&std::fs::read(selection_file).unwrap()).unwrap();
    let expected = decode_selection(&json);
    let material = load_snapshot(snapshot, &key, NAMESPACE, &expected).unwrap();
    let digest = match &material {
        OwnedOwnerInput::Creation(witness) => witness.packet.digest().unwrap(),
        _ => unreachable!("fixture is a creation capability"),
    };
    assert_eq!(digest, expected.packet_digest, "restored digest differs from selection");
    println!("RESTORED_PACKET_DIGEST {}", hex(&digest));
    println!("RESTORE_OK");
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, outdir] if mode == "save" => save(outdir),
        [mode, file, selection] if mode == "restore" => restore(file, selection),
        _ => {
            eprintln!("usage: snapshot_demo save <outdir> | restore <file> <selection-json>");
            ExitCode::from(2)
        }
    }
}