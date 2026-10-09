//! Public binding codec and generated-key negative capsule tests; no proving or SQL.
//! Genuine-positive roundtrip/retry/conflict is resource-held: the retained Fill2
//! qualification has no wrapped certificate. No synthetic proof is accepted here.
#![cfg(target_os = "linux")]

use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use std::{fs::{self, OpenOptions, Permissions}, io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::Path};
use ziquid_proofs::artifacts::local::OwnerCertificate;
use ziquid_protocol::samechain::{Action, Deployment, OwnerJournal, Role};
use ziquid_runtime::{custody::CustodyError, samechain::{backup::SnapshotOperation,
    release::{BindingDigest, ReleaseBinding, ReleaseDigest, ReleaseError, load_release, save_release}}};

const BINDING_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_RELEASE_BINDING\0";
const CAPSULE_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_RELEASE_CAPSULE\0";
const CONTEXT_DOMAIN: &[u8] = b"Z2Z_SAMECHAIN_RELEASE_CONTEXT\0";
const ENVELOPE_DOMAIN: &[u8] = b"ziquid.samechain.release.v1";
const NAMESPACE: [u8; 32] = [0x71; 32];

fn deployment() -> Deployment {
    Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
        verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 }
}

fn binding() -> ReleaseBinding {
    ReleaseBinding { op_id: [0x11; 32], deployment: deployment(),
        operation: SnapshotOperation::Fill, role: Role::A, packet_digest: [0x12; 32],
        program_vkey: [5; 32], journal_digest: Sha256::digest(journal()).into(),
        expiry: 700, required_nfs: vec![[0x14; 32], [0x15; 32]] }
}

fn journal() -> Vec<u8> {
    OwnerJournal { relation_version: 2, action: Action::Fill, role: Role::A,
        deployment_digest: deployment().digest().unwrap(), terms_commitment: [0x16; 32],
        packet_digest: [0x12; 32], input_nullifier: [0x14; 32], input_commitment: [0x17; 32],
        root: [0x18; 32], tree_id: 9, index: 1, order_id: [0x19; 32], generation: 1 }
        .encode().unwrap()
}

// Hand-derived deployment and binding frames, independent of production codecs.
fn golden_frame(value: &ReleaseBinding) -> Vec<u8> {
    let mut deployment = b"Z2Z_SAMECHAIN_DEPLOYMENT\0\0\x01".to_vec();
    deployment.extend_from_slice(&31337_u64.to_be_bytes());
    deployment.extend_from_slice(&[1; 20]);
    deployment.extend_from_slice(&[2; 32]);
    deployment.extend_from_slice(&[3; 20]);
    deployment.extend_from_slice(&[4; 32]);
    deployment.extend_from_slice(&[5; 32]);
    deployment.extend_from_slice(&1_u16.to_be_bytes());
    let mut bytes = BINDING_DOMAIN.to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&value.op_id);
    bytes.extend_from_slice(&(deployment.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&deployment);
    bytes.extend_from_slice(&[value.operation as u8, value.role as u8]);
    bytes.extend_from_slice(&value.packet_digest);
    bytes.extend_from_slice(&value.program_vkey);
    bytes.extend_from_slice(&value.journal_digest);
    bytes.extend_from_slice(&value.expiry.to_be_bytes());
    bytes.push(value.required_nfs.len() as u8);
    for nf in &value.required_nfs { bytes.extend_from_slice(nf); }
    bytes
}

#[test]
fn binding_matches_independent_canonical_frame_and_digest() {
    let selected = binding();
    let golden = golden_frame(&selected);
    assert_eq!(selected.encode().unwrap(), golden);
    assert_eq!(ReleaseBinding::decode(&golden).unwrap(), selected);
    assert_eq!(selected.digest().unwrap(), BindingDigest(Sha256::digest(&golden).into()));
    let mut reordered = selected.clone();
    reordered.required_nfs.swap(0, 1);
    assert_ne!(reordered.digest().unwrap(), selected.digest().unwrap());
}

#[test]
fn operation_role_and_nf_cardinality_are_closed_in_encode_decode_and_digest() {
    for (operation, count) in [(SnapshotOperation::Fill, 2), (SnapshotOperation::Cancel, 1),
        (SnapshotOperation::Exit, 1), (SnapshotOperation::Withdrawal, 1),
        (SnapshotOperation::Creation, 0)] {
        for role in [Role::A, Role::B] {
            for supplied in 0..=2 {
                let mut selected = binding();
                selected.operation = operation;
                selected.role = role;
                selected.required_nfs.truncate(supplied);
                let allowed = supplied == count
                    && !(operation == SnapshotOperation::Withdrawal && role == Role::B);
                let frame = golden_frame(&selected);
                if allowed {
                    assert_eq!(selected.encode().unwrap(), frame);
                    assert_eq!(ReleaseBinding::decode(&frame).unwrap(), selected);
                    assert!(selected.digest().is_ok());
                } else {
                    assert_eq!(selected.encode(), Err(ReleaseError::Binding));
                    assert_eq!(selected.digest(), Err(ReleaseError::Binding));
                    assert_eq!(ReleaseBinding::decode(&frame), Err(ReleaseError::Binding));
                }
            }
        }
    }
}

#[test]
fn zero_identifiers_expiry_nullifiers_and_duplicate_fill_are_rejected() {
    for mutation in 0..8 {
        let mut selected = binding();
        match mutation {
            0 => selected.op_id = [0; 32],
            1 => selected.packet_digest = [0; 32],
            2 => selected.program_vkey = [0; 32],
            3 => selected.journal_digest = [0; 32],
            4 => selected.expiry = 0,
            5 => selected.required_nfs[0] = [0; 32],
            6 => selected.required_nfs[1] = [0; 32],
            _ => selected.required_nfs[1] = selected.required_nfs[0],
        }
        assert_eq!(selected.encode(), Err(ReleaseError::Binding));
        assert_eq!(selected.digest(), Err(ReleaseError::Binding));
        assert_eq!(ReleaseBinding::decode(&golden_frame(&selected)), Err(ReleaseError::Binding));
    }
    for mutation in 0..7 {
        let mut selected = binding();
        match mutation {
            0 => selected.deployment.chain_id = 0,
            1 => selected.deployment.authority = [0; 20],
            2 => selected.deployment.authority_code = [0; 32],
            3 => selected.deployment.verifier = [0; 20],
            4 => selected.deployment.verifier_code = [0; 32],
            5 => selected.deployment.owner_program = [0; 32],
            _ => selected.deployment.schema = 2,
        }
        assert_eq!(selected.encode(), Err(ReleaseError::Binding));
        assert_eq!(selected.digest(), Err(ReleaseError::Binding));
    }
}

#[test]
fn binding_parser_rejects_unknown_codes_truncation_lengths_and_trailing_bytes() {
    let original = golden_frame(&binding());
    let deployment_start = BINDING_DOMAIN.len() + 2 + 32 + 4;
    let operation = deployment_start + b"Z2Z_SAMECHAIN_DEPLOYMENT\0".len() + 2 + 146;
    let count = operation + 2 + 96 + 8;
    for (offset, value) in [(0, b'X'), (BINDING_DOMAIN.len() + 1, 2),
        (operation, 5), (operation + 1, 2), (count, 3)] {
        let mut bytes = original.clone();
        bytes[offset] = value;
        assert_eq!(ReleaseBinding::decode(&bytes), Err(ReleaseError::Encoding));
    }
    for length in 0..original.len() {
        assert!(ReleaseBinding::decode(&original[..length]).is_err());
    }
    let mut trailing = original.clone(); trailing.push(0);
    assert_eq!(ReleaseBinding::decode(&trailing), Err(ReleaseError::Encoding));
    let mut oversized = original.clone();
    oversized[deployment_start - 4..deployment_start].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(ReleaseBinding::decode(&oversized).is_err());
    let mut invalid_deployment = original;
    invalid_deployment[operation - 1] = 2;
    assert_eq!(ReleaseBinding::decode(&invalid_deployment), Err(ReleaseError::Binding));
}

fn directory() -> tempfile::TempDir {
    tempfile::Builder::new().permissions(Permissions::from_mode(0o700)).tempdir().unwrap()
}

fn key() -> [u8; 32] {
    let mut key = [0; 32]; getrandom::fill(&mut key).unwrap(); key
}

// Deliberately INVALID: A=C=G1(1,2), B=G2 generator are on curve but do
// not prove this statement. The proofs consumer pins post-pairing rejection.
fn invalid_certificate() -> OwnerCertificate {
    let mut proof_bytes = vec![0; 356];
    proof_bytes[..4].copy_from_slice(&[0x43, 0x88, 0xa2, 0x1c]);
    proof_bytes[36..68].copy_from_slice(&[
        0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d,
        0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08, 0x14, 0xb0,
        0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28,
        0x57, 0x32, 0x40, 0xd0, 0x57, 0xf2, 0x53, 0x52]);
    proof_bytes[131] = 1; proof_bytes[163] = 2;
    proof_bytes[323] = 1; proof_bytes[355] = 2;
    // Gnark wire order: B.x.imaginary, B.x.real, B.y.imaginary, B.y.real.
    for (index, coordinate) in [
        "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
        "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
        "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
        "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
    ].into_iter().enumerate() {
        for (byte, pair) in coordinate.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            proof_bytes[164 + index * 32 + byte] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
    }
    OwnerCertificate { program_vkey: [5; 32], journal: journal(), proof_bytes }
}

#[test]
fn save_rejects_invalid_pairing_and_mutated_journal_proof_or_program_before_publication() {
    let directory = directory(); let key = key();
    for mutation in 0..5 {
        let selected = binding(); let mut certificate = invalid_certificate();
        match mutation {
            0 => {},
            1 => certificate.journal[0] ^= 1,
            2 => certificate.proof_bytes[0] ^= 1,
            3 => certificate.proof_bytes[100] ^= 1,
            _ => certificate.program_vkey = [6; 32],
        }
        let path = directory.path().join(format!("absent-{mutation}/capsule"));
        assert_eq!(save_release(&path, &key, NAMESPACE, &selected, &certificate), Err(ReleaseError::Certificate));
        assert!(!path.parent().unwrap().exists());
    }
}

#[test]
fn save_checks_namespace_binding_and_certificate_bounds_before_filesystem_changes() {
    let directory = directory(); let key = key();
    let path = directory.path().join("absent/capsule");
    let mut selected = binding(); let mut certificate = invalid_certificate();
    assert_eq!(save_release(&path, &key, [0; 32], &selected, &certificate), Err(ReleaseError::Binding));
    selected.expiry = 0;
    assert_eq!(save_release(&path, &key, NAMESPACE, &selected, &certificate), Err(ReleaseError::Binding));
    selected = binding();
    for length in [0, 355, 357] {
        certificate.proof_bytes.resize(length, 0);
        assert_eq!(save_release(&path, &key, NAMESPACE, &selected, &certificate), Err(ReleaseError::Encoding));
    }
    certificate = invalid_certificate(); certificate.journal = vec![1; 1025];
    selected.journal_digest = Sha256::digest(&certificate.journal).into();
    assert_eq!(save_release(&path, &key, NAMESPACE, &selected, &certificate), Err(ReleaseError::ResourceLimit));
    certificate.journal.truncate(1024);
    selected.journal_digest = Sha256::digest(&certificate.journal).into();
    assert_eq!(save_release(&path, &key, NAMESPACE, &selected, &certificate), Err(ReleaseError::Certificate));
    assert!(!path.parent().unwrap().exists());
}

fn plaintext(selected: &ReleaseBinding, certificate: &OwnerCertificate) -> Vec<u8> {
    let encoded = golden_frame(selected);
    let mut bytes = CAPSULE_DOMAIN.to_vec(); bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes()); bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(&(certificate.journal.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&certificate.journal);
    bytes.extend_from_slice(&(certificate.proof_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&certificate.proof_bytes); bytes
}

// Independently authenticate malformed capsules to reach load's decoder/verification
// boundary. This helper never calls save_release or claims semantic acceptance.
fn write_envelope(path: &Path, key: &[u8; 32], selected: &ReleaseBinding, mut bytes: Vec<u8>) -> ReleaseDigest {
    let digest: [u8; 32] = Sha256::digest(golden_frame(selected)).into();
    let mut context = Sha256::new(); context.update(CONTEXT_DOMAIN);
    context.update(1_u16.to_be_bytes()); context.update(digest);
    let context: [u8; 32] = context.finalize().into();
    let nonce = [0x72; 24];
    let mut header = ENVELOPE_DOMAIN.to_vec(); header.extend_from_slice(&nonce);
    header.extend_from_slice(&((bytes.len() + 16) as u32).to_le_bytes());
    let mut aad = header.clone(); aad.extend_from_slice(&NAMESPACE); aad.extend_from_slice(&context);
    let tag = XChaCha20Poly1305::new(key.into()).encrypt_in_place_detached(
        XNonce::from_slice(&nonce), &aad, &mut bytes).unwrap();
    let mut envelope = header; envelope.extend_from_slice(&bytes); envelope.extend_from_slice(&tag);
    let digest = ReleaseDigest(Sha256::digest(&envelope).into());
    let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(path).unwrap();
    file.write_all(&envelope).unwrap(); file.sync_all().unwrap(); digest
}

#[test]
fn load_checks_independent_key_namespace_every_binding_field_and_complete_file_digest() {
    let directory = directory(); let key = key(); let selected = binding();
    let path = directory.path().join("capsule");
    let digest = write_envelope(&path, &key, &selected, plaintext(&selected, &invalid_certificate()));
    let original = fs::read(&path).unwrap();
    assert_eq!(load_release(&path, &key, NAMESPACE, &selected, digest).err(), Some(ReleaseError::Certificate));
    let mut wrong_key = key; wrong_key[0] ^= 1;
    assert_eq!(load_release(&path, &wrong_key, NAMESPACE, &selected, digest).err(),
        Some(ReleaseError::Custody(CustodyError::Authentication)));
    assert_eq!(load_release(&path, &key, [0x73; 32], &selected, digest).err(),
        Some(ReleaseError::Custody(CustodyError::Authentication)));
    assert_eq!(load_release(&path, &key, [0; 32], &selected, digest).err(), Some(ReleaseError::Binding));
    for mutation in 0..10 {
        let mut expected = selected.clone();
        match mutation {
            0 => expected.op_id[0] ^= 1,
            1 => expected.deployment.chain_id += 1,
            2 => { expected.operation = SnapshotOperation::Cancel; expected.required_nfs.truncate(1); },
            3 => expected.role = Role::B,
            4 => expected.packet_digest[0] ^= 1,
            5 => expected.program_vkey[0] ^= 1,
            6 => expected.journal_digest[0] ^= 1,
            7 => expected.expiry += 1,
            8 => expected.required_nfs[0][0] ^= 1,
            _ => expected.required_nfs.swap(0, 1),
        }
        assert_eq!(load_release(&path, &key, NAMESPACE, &expected, digest).err(),
            Some(ReleaseError::Custody(CustodyError::Authentication)), "mutation {mutation}");
    }
    let mut wrong_digest = digest; wrong_digest.0[0] ^= 1;
    assert_eq!(load_release(&path, &key, NAMESPACE, &selected, wrong_digest).err(), Some(ReleaseError::Binding));
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn authenticated_capsule_parser_rejects_binding_mismatch_lengths_trailing_and_invalid_certificate() {
    let directory = directory(); let key = key(); let selected = binding();
    let certificate = invalid_certificate(); let original = plaintext(&selected, &certificate);
    let binding_start = CAPSULE_DOMAIN.len() + 2 + 4;
    let journal_length = binding_start + golden_frame(&selected).len();
    let proof_length = journal_length + 4 + certificate.journal.len();
    for mutation in 0..11 {
        let mut bytes = original.clone();
        let expected = match mutation {
            0 => { bytes[0] ^= 1; ReleaseError::Encoding },
            1 => { bytes[CAPSULE_DOMAIN.len() + 1] = 2; ReleaseError::Encoding },
            2 => { bytes[binding_start - 4..binding_start].copy_from_slice(&4097_u32.to_be_bytes()); ReleaseError::ResourceLimit },
            3 => { bytes[binding_start + BINDING_DOMAIN.len() + 2] ^= 1; ReleaseError::Binding },
            4 => { bytes[journal_length..journal_length + 4].copy_from_slice(&1025_u32.to_be_bytes()); ReleaseError::ResourceLimit },
            5 => { bytes[proof_length..proof_length + 4].copy_from_slice(&355_u32.to_be_bytes()); ReleaseError::Encoding },
            6 => { bytes[proof_length..proof_length + 4].copy_from_slice(&357_u32.to_be_bytes()); ReleaseError::Encoding },
            7 => { bytes.push(0); ReleaseError::Encoding },
            8 => { bytes.pop(); ReleaseError::Encoding },
            9 => { bytes[journal_length + 4] ^= 1; ReleaseError::Certificate },
            _ => { bytes[proof_length + 4 + 100] ^= 1; ReleaseError::Certificate },
        };
        let path = directory.path().join(format!("capsule-{mutation}"));
        let digest = write_envelope(&path, &key, &selected, bytes);
        assert_eq!(load_release(&path, &key, NAMESPACE, &selected, digest).err(), Some(expected), "mutation {mutation}");
    }
}
