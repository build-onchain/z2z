//! Caller-gated real Native creation qualification using synthetic owner secrets.
//! A generated deployment is NOT an actual backed target or financial acceptance.
#![cfg(target_os = "linux")]

use clap::Parser;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
use ziquid_proofs::samechain::creation::{NoteCreationWitness, verify_note_creation_relation};
use ziquid_protocol::samechain::Deployment;
use ziquid_protocol::samechain::creation::NoteCreationJournal;
use ziquid_runtime::samechain::{backup::SnapshotOperation, release::{ReleaseBinding, ReleaseDigest}};

#[allow(dead_code)]
#[path = "../../proofs/tests/support/samechain.rs"]
mod fill_support;
#[allow(dead_code)]
#[path = "../../proofs/tests/support/note_creation.rs"]
mod creation_support;

type RunResult<T> = Result<T, &'static str>;
const OUTPUT_LIMIT: usize = 65536;
const SCALAR_R: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[derive(Parser)]
#[command(version, about = "Controlled real local owner creation proof; synthetic secrets, no backed target")]
struct Args {
    #[arg(long)]
    binary: PathBuf,
    #[arg(long)]
    elf: PathBuf,
    #[arg(long)]
    elf_sha256: String,
    #[arg(long)]
    program_vkey: String,
    #[arg(long)]
    private_temp_dir: PathBuf,
    /// Public setup base, not its v6.1.0 child directory.
    #[arg(long)]
    groth16_artifact_base: PathBuf,
    /// Public light-setup budget and the child proof/transport deadline, each 1..=86400 seconds.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
    timeout_seconds: u64,
    #[arg(long)]
    release_dir: PathBuf,
    #[arg(long)]
    op_id: String,
    /// Generated owner-private 0600 backup key file; no raw key descriptor.
    #[arg(long)]
    backup_key_file: PathBuf,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(2 + bytes.len() * 2);
    value.push_str("0x");
    for byte in bytes { write!(&mut value, "{byte:02x}").expect("hex formatting failed"); }
    value
}

fn decode_hex(value: &str, out: &mut [u8]) -> RunResult<()> {
    let bytes = value.strip_prefix("0x").filter(|bytes| bytes.len() == out.len() * 2)
        .ok_or("invalid public fixed-width hex")?.as_bytes();
    for (out, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        *out = digit(pair[0]).and_then(|high| digit(pair[1]).map(|low| high * 16 + low))
            .ok_or("invalid public fixed-width hex")?;
    }
    Ok(())
}

fn fixed_hex(value: &str) -> RunResult<[u8; 32]> {
    let mut bytes = [0; 32];
    decode_hex(value, &mut bytes)?;
    if bytes == [0; 32] { return Err("invalid zero public pin"); }
    Ok(bytes)
}

fn qualification_fixture(program: [u8; 32]) -> RunResult<NoteCreationWitness> {
    if program == [0; 32] || program >= SCALAR_R { return Err("invalid canonical owner program pin"); }
    let mut witness = creation_support::ordinary_native();
    let deployment = Deployment { owner_program: program, ..fill_support::deployment() };
    witness.packet.deployment = deployment;
    witness.note.deployment_digest = deployment.digest().map_err(|_| "generated deployment rejected")?;
    // Rebuild actual authenticated ciphertext, salted terms and a fresh exact
    // synthetic consent; changing just the public program field is not enough.
    creation_support::replace_output(&mut witness);
    Ok(witness)
}

fn elf_hash(path: &Path) -> RunResult<[u8; 32]> {
    let mut file = File::open(path).map_err(|_| "public owner ELF unavailable")?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    let mut total = 0usize;
    loop {
        let count = file.read(&mut buffer).map_err(|_| "public owner ELF unavailable")?;
        if count == 0 { break; }
        total += count;
        if total > 16 * 1024 * 1024 { return Err("public owner ELF exceeds size limit"); }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

// Descriptor-bound owner root with the same custody ancestor/mode policy.
// It is caller-owned and is never deleted, even after success.
fn private_root(path: &Path) -> RunResult<File> {
    use rustix::fs::{Mode, openat};
    if !path.is_absolute() || path.to_str().is_none()
        || path.components().any(|part| matches!(part, Component::ParentDir))
    { return Err("private root rejected"); }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let uid = rustix::process::geteuid().as_raw();
    let trusted = |directory: &File, final_dir| -> RunResult<()> {
        let metadata = directory.metadata().map_err(|_| "private root unavailable")?;
        let mode = metadata.mode() & 0o7777;
        if !metadata.is_dir() || (metadata.uid() != uid && metadata.uid() != 0)
            || (mode & 0o022 != 0 && !(metadata.uid() == 0 && mode == 0o1777))
            || (final_dir && (metadata.uid() != uid || mode != 0o700))
        { return Err("private root rejected"); }
        Ok(())
    };
    let mut directory: File = rustix::fs::open("/", flags, Mode::empty())
        .map_err(|_| "private root unavailable")?.into();
    trusted(&directory, false)?;
    for part in path.components() {
        let Component::Normal(name) = part else { continue };
        directory = File::from(openat(&directory, name, flags, Mode::empty())
            .map_err(|_| "private root unavailable")?);
        trusted(&directory, false)?;
    }
    trusted(&directory, true)?;
    Ok(directory)
}

fn root_entries(directory: &File) -> RunResult<Vec<OsString>> {
    let entries = rustix::fs::Dir::read_from(directory).map_err(|_| "private root enumeration failed")?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| "private root entry unavailable")?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            use std::os::unix::ffi::OsStrExt;
            names.push(std::ffi::OsStr::from_bytes(name).to_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn finish_public_fixture(fixture: tempfile::TempDir, path: &Path, root: &File,
    root_identity: &fs::Metadata, initial_entries: &[OsString]) -> RunResult<()>
{
    // TMPDIR may equal the caller root: remove only our public fixture before
    // comparing entries. Never delete caller-owned or worker-private scratch.
    fixture.close().map_err(|_| "public fixture cleanup failed")?;
    let named = fs::symlink_metadata(path).map_err(|_| "private root missing; root retained")?;
    if !named.is_dir() || named.dev() != root_identity.dev() || named.ino() != root_identity.ino()
        || named.uid() != root_identity.uid() || named.mode() & 0o7777 != 0o700
        || root_entries(root)? != initial_entries
    { return Err("private root identity or scratch cleanup mismatch; root retained"); }
    Ok(())
}

struct ExternalCli { child: Child, reaped: bool }
impl Drop for ExternalCli {
    fn drop(&mut self) {
        if !self.reaped && let Ok(None) = self.child.try_wait() {
            // Never kill a worker group or delete possible active-writer scratch.
            // Abnormal direct-CLI termination retains the caller-owned root.
            let _ = self.child.kill();
        }
    }
}

struct Captured { status: ExitStatus, stdout: Zeroizing<Vec<u8>>, stderr: Zeroizing<Vec<u8>> }

fn nonblocking(fd: &impl std::os::fd::AsFd) -> RunResult<()> {
    let flags = fcntl_getfl(fd).map_err(|_| "pipe flags unavailable")?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|_| "nonblocking pipe setup failed")
}

fn drain(pipe: &mut impl Read, bytes: &mut [u8], length: &mut usize) -> RunResult<bool> {
    loop {
        match pipe.read(&mut bytes[*length..]) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                *length += count;
                if *length > OUTPUT_LIMIT { return Err("CLI output exceeded bound; private root retained"); }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Err("CLI output pipe failed; private root retained"),
        }
    }
}

fn run_cli(args: &Args, command_args: &[OsString], witness: &[u8], budget: Duration) -> RunResult<Captured> {
    let deadline = Instant::now() + budget;
    let mut command = Command::new(&args.binary);
    command.env_clear();
    for name in ["HOME", "PATH"] {
        if let Some(value) = std::env::var_os(name) { command.env(name, value); }
    }
    command.arg("samechain").args(command_args)
        .env("SP1_GROTH16_CIRCUIT_PATH", &args.groth16_artifact_base)
        .env("SP1_PROVER", "cpu").env("SP1_CIRCUIT_MODE", "release")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn().map_err(|_| "actual CLI spawn failed")?;
    let mut process = ExternalCli { child, reaped: false };
    let mut stdin = Some(process.child.stdin.take().ok_or("CLI stdin unavailable")?);
    let mut stdout = process.child.stdout.take().ok_or("CLI stdout unavailable")?;
    let mut stderr = process.child.stderr.take().ok_or("CLI stderr unavailable")?;
    nonblocking(stdin.as_ref().ok_or("CLI stdin unavailable")?)?;
    nonblocking(&stdout)?; nonblocking(&stderr)?;
    let mut out = Zeroizing::new(vec![0; OUTPUT_LIMIT + 1]);
    let mut err = Zeroizing::new(vec![0; OUTPUT_LIMIT + 1]);
    let (mut written, mut out_len, mut err_len) = (0, 0, 0);
    let (mut out_eof, mut err_eof) = (false, false);
    let mut status = None;
    if witness.is_empty() { stdin.take(); }
    loop {
        if Instant::now() >= deadline { return Err("CLI watchdog expired; private root retained"); }
        if let Some(pipe) = stdin.as_mut() {
            match pipe.write(&witness[written..]) {
                Ok(0) => return Err("CLI witness pipe stopped; private root retained"),
                Ok(count) => written += count,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) => {}
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => { stdin.take(); }
                Err(_) => return Err("CLI witness pipe failed; private root retained"),
            }
            if written == witness.len() { stdin.take(); }
        }
        if !out_eof { out_eof = drain(&mut stdout, &mut out, &mut out_len)?; }
        if !err_eof { err_eof = drain(&mut stderr, &mut err, &mut err_len)?; }
        if status.is_none() {
            status = process.child.try_wait().map_err(|_| "external CLI reap failed; private root retained")?;
            if status.is_some() { process.reaped = true; }
        }
        if let Some(status) = status && out_eof && err_eof {
            out.truncate(out_len); err.truncate(err_len);
            return Ok(Captured { status, stdout: out, stderr: err });
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn not_disclosed(stream: &[u8], private: &[u8]) -> RunResult<()> {
    if private.is_empty() { return Ok(()); }
    if stream.windows(private.len()).any(|window| window == private) {
        return Err("CLI disclosed private bytes or path; private root retained");
    }
    let mut json = Zeroizing::new(Vec::with_capacity(private.len() * 4 + 2));
    serde_json::to_writer(&mut *json, private).map_err(|_| "diagnostic guard encoding failed")?;
    if stream.windows(json.len()).any(|window| window == &json[..]) {
        return Err("CLI disclosed serialized private bytes; private root retained");
    }
    if private.len() == 32 {
        use std::fmt::Write as _;
        let mut encoded = Zeroizing::new(String::with_capacity(64));
        for byte in private { write!(&mut *encoded, "{byte:02x}").map_err(|_| "diagnostic guard encoding failed")?; }
        if stream.windows(64).any(|window| window.eq_ignore_ascii_case(encoded.as_bytes())) {
            return Err("CLI disclosed hexadecimal private bytes; private root retained");
        }
    }
    Ok(())
}

fn check_paths(output: &Captured, paths: &[&Path]) -> RunResult<()> {
    for stream in [&output.stdout[..], &output.stderr[..]] {
        for path in paths { not_disclosed(stream, path.as_os_str().as_encoded_bytes())?; }
    }
    Ok(())
}

fn public_deployment(deployment: &Deployment) -> serde_json::Value {
    serde_json::json!({
        "chain_id": deployment.chain_id.to_string(), "authority": hex(&deployment.authority),
        "authority_code": hex(&deployment.authority_code), "verifier": hex(&deployment.verifier),
        "verifier_code": hex(&deployment.verifier_code), "owner_program": hex(&deployment.owner_program),
        "schema": deployment.schema,
    })
}

fn unqualified(value: &serde_json::Value) -> RunResult<()> {
    for flag in ["root_eligibility", "global_unspentness", "asset_backing", "finality", "deployment_profile_qualification"] {
        if value[flag] != "UNVERIFIED" { return Err("CLI misrepresented financial qualification"); }
    }
    for flag in ["financial_execution", "strict_matching_privacy"] {
        if value[flag] != false { return Err("CLI misrepresented financial execution or privacy"); }
    }
    Ok(())
}

fn public_file(directory: &Path, name: &str, bytes: &[u8]) -> RunResult<PathBuf> {
    let path = directory.join(name);
    let mut file = fs::OpenOptions::new().create_new(true).write(true).mode(0o600)
        .open(&path).map_err(|_| "public fixture file creation failed")?;
    file.write_all(bytes).map_err(|_| "public fixture write failed")?;
    Ok(path)
}

fn qualify(args: &Args) -> RunResult<()> {
    let hash = fixed_hex(&args.elf_sha256)?;
    let program = fixed_hex(&args.program_vkey)?;
    if program >= SCALAR_R { return Err("invalid canonical owner program pin"); }
    if elf_hash(&args.elf)? != hash { return Err("owner ELF hash mismatch before setup"); }
    if !args.binary.is_absolute() || !args.elf.is_absolute()
        || !args.groth16_artifact_base.is_absolute() || args.groth16_artifact_base.to_str().is_none()
        || args.groth16_artifact_base.file_name().and_then(|name| name.to_str()) == Some("v6.1.0")
    { return Err("caller must select absolute binary, ELF and public artifact base"); }
    let root = private_root(&args.private_temp_dir)?;
    let root_identity = root.metadata().map_err(|_| "private root metadata unavailable")?;
    let initial_entries = root_entries(&root)?;
    // The actual public command must derive the caller's key before any witness
    // generation or proving. No synthetic fixture VKey stands in for real setup.
    let setup = run_cli(args, &["owner-program".into(), "--elf".into(), args.elf.clone().into(),
        "--elf-sha256".into(), args.elf_sha256.clone().into()], &[], Duration::from_secs(args.timeout_seconds))?;
    check_paths(&setup, &[&args.binary, &args.elf, &args.private_temp_dir, &args.groth16_artifact_base])?;
    if !setup.status.success() || !setup.stderr.is_empty() { return Err("actual public program setup rejected"); }
    let setup_value: serde_json::Value = serde_json::from_slice(&setup.stdout)
        .map_err(|_| "public program setup export invalid")?;
    if setup_value["kind"] != "samechain_owner_program" || setup_value["elf_sha256"] != hex(&hash)
        || setup_value["program_vkey"] != hex(&program)
        || setup_value["evidence"] != "actual_local_light_program_setup"
        || setup_value["proof_certificate"] != false || setup_value["program_identity"] != "UNVERIFIED"
        || setup_value["source_qualification"] != "UNVERIFIED" || setup_value["setup_qualification"] != "UNVERIFIED"
    { return Err("actual public program key or qualification mismatch"); }
    unqualified(&setup_value)?;
    let witness = qualification_fixture(program)?;
    let deployment = witness.packet.deployment;
    let journal = verify_note_creation_relation(&witness).map_err(|_| "native creation relation rejected")?;
    let journal_bytes = journal.encode().map_err(|_| "native journal encoding rejected")?;
    if NoteCreationJournal::decode(&journal_bytes).map_err(|_| "native journal decoding rejected")? != journal {
        return Err("native journal roundtrip mismatch");
    }
    let packet = witness.packet.encode().map_err(|_| "public creation packet encoding rejected")?;
    let frame = witness.encode().map_err(|_| "private creation frame encoding rejected")?;
    let fixture = tempfile::Builder::new().prefix("z2z-owner-qualification-public-")
        .permissions(fs::Permissions::from_mode(0o700)).tempdir()
        .map_err(|_| "public fixture directory creation failed")?;
    let deployment_path = public_file(fixture.path(), "deployment.bin",
        &deployment.encode().map_err(|_| "public deployment encoding rejected")?)?;
    let packet_path = public_file(fixture.path(), "packet.bin", &packet)?;
    let journal_path = public_file(fixture.path(), "journal.bin", &journal_bytes)?;
    let command = vec!["prove-owner".into(), "--operation".into(), "creation".into(),
        "--elf".into(), args.elf.clone().into(), "--elf-sha256".into(), args.elf_sha256.clone().into(),
        "--deployment".into(), deployment_path.clone().into(), "--program-vkey".into(), args.program_vkey.clone().into(),
        "--private-temp-dir".into(), args.private_temp_dir.clone().into(), "--timeout-seconds".into(),
        args.timeout_seconds.to_string().into(), "--witness-stdin".into(),
        "--release-dir".into(), args.release_dir.clone().into(), "--op-id".into(), args.op_id.clone().into(),
        "--backup-key-file".into(), args.backup_key_file.clone().into()];
    let started = Instant::now();
    // Child runtime proof/transport timeout and equal cleanup allowance are
    // primary. Extra watchdog slack permits artifact preflight; no group kill.
    let output = run_cli(args, &command, &frame, Duration::from_secs(args.timeout_seconds * 2 + 60))?;
    let elapsed_ms = started.elapsed().as_millis();
    check_paths(&output, &[&args.binary, &args.elf, &args.private_temp_dir, &args.groth16_artifact_base,
        &args.release_dir, &args.backup_key_file, fixture.path(), &deployment_path, &packet_path, &journal_path])?;
    let note_bytes = witness.note.encode().map_err(|_| "private note encoding rejected")?;
    for stream in [&output.stdout[..], &output.stderr[..]] {
        for private in [&frame[..], &witness.owner_seed, &witness.blind, &witness.recovery_key,
            &witness.note.nf_key, &witness.note.nonce, &witness.note.salt, &note_bytes]
        { not_disclosed(stream, private)?; }
    }
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("actual local creation proof rejected; private root retained");
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "owner capsule export invalid; private root retained")?;
    let op_id = fixed_hex(&args.op_id)?;
    let binding = ReleaseBinding { op_id, deployment, operation: SnapshotOperation::Creation,
        role: witness.packet.role, packet_digest: witness.packet.digest().map_err(|_| "packet digest rejected")?,
        program_vkey: program, journal_digest: Sha256::digest(&journal_bytes).into(),
        expiry: witness.packet.expiry, required_nfs: Vec::new() };
    let encoded = binding.encode().map_err(|_| "expected release binding rejected")?;
    let binding_digest = binding.digest().map_err(|_| "expected binding digest rejected")?;
    let capsule = format!("{}.release", hex(&op_id).trim_start_matches("0x"));
    if value["kind"] != "samechain_owner_capsule" || value["op_id"] != hex(&op_id)
        || value["binding"] != hex(&encoded) || value["binding_digest"] != hex(&binding_digest.0)
        || value["capsule"] != capsule || value.get("journal").is_some() || value.get("proof").is_some()
        || value.as_object().is_none_or(|object| object.len() != 6)
    { return Err("owner capsule exact context mismatch; private root retained"); }
    let release_digest = ReleaseDigest(fixed_hex(value["release_digest"].as_str().ok_or("capsule digest missing")?)?);
    let release_root = private_root(&args.release_dir)?;
    let encrypted: File = rustix::fs::openat(&release_root, capsule.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, rustix::fs::Mode::empty())
        .map_err(|_| "private capsule unavailable")?.into();
    let metadata = encrypted.metadata().map_err(|_| "private capsule unavailable")?;
    if !metadata.is_file() || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1 || metadata.mode() & 0o7777 != 0o600 || metadata.len() > 8192
    { return Err("private capsule rejected"); }
    let mut encrypted = encrypted;
    let mut capsule_hash = Sha256::new();
    let mut buffer = [0; 4096];
    loop {
        let count = encrypted.read(&mut buffer).map_err(|_| "private capsule read failed")?;
        if count == 0 { break; }
        capsule_hash.update(&buffer[..count]);
    }
    if <[u8; 32]>::from(capsule_hash.finalize()) != release_digest.0 {
        return Err("private capsule digest mismatch");
    }
    finish_public_fixture(fixture, &args.private_temp_dir, &root, &root_identity, &initial_entries)?;
    let result = serde_json::json!({
        "kind": "samechain_owner_creation_qualification", "status": "ACTUAL_WRAPPED_CAPSULE",
        "operation": "creation", "fixture": "GENERATED_TEST_DEPLOYMENT_NOT_BACKED_TARGET",
        "expected_deployment": public_deployment(&deployment), "elf_sha256": hex(&hash),
        "program_vkey": hex(&program), "op_id": hex(&op_id),
        "binding": hex(&encoded), "binding_digest": hex(&binding_digest.0), "release_digest": hex(&release_digest.0),
        "capsule": capsule, "witness_bytes": frame.len(), "packet_bytes": packet.len(), "elapsed_ms": elapsed_ms,
        "proof_certificate": false, "source_qualification": "UNVERIFIED", "setup_qualification": "UNVERIFIED",
        "program_identity": "UNVERIFIED", "asset_backing": "UNVERIFIED", "finality": "UNVERIFIED",
        "root_eligibility": "UNVERIFIED", "global_unspentness": "UNVERIFIED",
        "deployment_profile_qualification": "UNVERIFIED", "financial_execution": false, "strict_matching_privacy": false,
        "sdk_storage_boundary": "UNQUALIFIED_EXTERNAL_DEV_SHM_RAII_RETENTION",
    });
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    serde_json::to_writer(&mut locked, &result).map_err(|_| "public qualification output unavailable")?;
    locked.write_all(b"\n").map_err(|_| "public qualification output unavailable")
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> std::process::ExitCode {
    let args = match Args::try_parse_from(arguments) {
        Ok(args) => args,
        Err(error) => {
            if matches!(error.kind(), clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion) {
                return if error.print().is_ok() { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::FAILURE };
            }
            eprintln!("owner creation qualification rejected: invalid owner creation qualification arguments");
            return std::process::ExitCode::FAILURE;
        }
    };
    match qualify(&args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(category) => {
            eprintln!("owner creation qualification rejected: {category}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn main() -> std::process::ExitCode { run(std::env::args_os()) }

#[cfg(test)]
mod tests {
    use super::*;
    use ziquid_protocol::samechain::Asset;

    #[test]
    fn owned_public_fixture_under_private_root_closes_before_scratch_comparison() {
        let root = tempfile::Builder::new().permissions(fs::Permissions::from_mode(0o700))
            .tempdir().unwrap();
        let sentinel = public_file(root.path(), "unrelated", b"caller-owned-private-root-sentinel").unwrap();
        let existing_scratch = tempfile::Builder::new().prefix(".z2z-owner-proof-existing-")
            .permissions(fs::Permissions::from_mode(0o700)).tempdir_in(root.path()).unwrap();
        let scratch_sentinel = public_file(existing_scratch.path(), "private-state", b"preserve-caller-owned-scratch").unwrap();
        let directory = private_root(root.path()).unwrap();
        let identity = directory.metadata().unwrap();
        let initial_entries = root_entries(&directory).unwrap();
        // tempdir_in reproduces exactly TMPDIR == the selected private root,
        // without changing process-global environment or simulating a proof.
        let fixture = tempfile::Builder::new().prefix("z2z-owner-qualification-public-")
            .permissions(fs::Permissions::from_mode(0o700)).tempdir_in(root.path()).unwrap();
        let fixture_path = fixture.path().to_owned();
        public_file(fixture.path(), "deployment.bin", b"public deployment bytes").unwrap();
        public_file(fixture.path(), "packet.bin", b"public packet bytes").unwrap();
        public_file(fixture.path(), "journal.bin", b"public journal bytes").unwrap();
        assert_ne!(root_entries(&directory).unwrap(), initial_entries);
        finish_public_fixture(fixture, root.path(), &directory, &identity, &initial_entries).unwrap();
        assert!(!fixture_path.exists());
        assert_eq!(root_entries(&directory).unwrap(), initial_entries);
        assert_eq!(fs::read(&sentinel).unwrap(), b"caller-owned-private-root-sentinel");
        assert_eq!(fs::read(&scratch_sentinel).unwrap(), b"preserve-caller-owned-scratch");
        assert_eq!(fs::symlink_metadata(root.path()).unwrap().ino(), identity.ino());
    }

    #[test]
    fn help_and_version_finish_successfully_without_qualification_inputs() {
        for flag in ["--help", "--version"] {
            assert_eq!(run(["owner_creation_qualification", flag].map(OsString::from)),
                std::process::ExitCode::SUCCESS);
        }
        assert_eq!(run(["owner_creation_qualification", "--private-unknown-sentinel"].map(OsString::from)),
            std::process::ExitCode::FAILURE);
    }

    #[test]
    fn fixture_rebinds_note_recovery_terms_and_fresh_consent_to_entire_deployment() {
        let program = [1; 32]; // Public synthetic test pin only, never real setup evidence.
        let witness = qualification_fixture(program).unwrap();
        let expected = Deployment { owner_program: program, ..fill_support::deployment() };
        assert_eq!(witness.packet.deployment, expected);
        assert_eq!(witness.note.deployment_digest, expected.digest().unwrap());
        assert_eq!(witness.packet.asset, Asset::Native);
        assert!(witness.note.order.is_none() && witness.packet.order.is_none());
        let journal = verify_note_creation_relation(&witness).unwrap();
        let bytes = journal.encode().unwrap();
        assert_eq!(NoteCreationJournal::decode(&bytes).unwrap(), journal);
        let frame = witness.encode().unwrap();
        let decoded = NoteCreationWitness::decode(&frame).unwrap();
        assert_eq!(verify_note_creation_relation(&decoded).unwrap(), journal);
        let mut stale = decoded;
        stale.note.deployment_digest = fill_support::deployment().digest().unwrap();
        assert!(verify_note_creation_relation(&stale).is_err(), "deployment rebinding skipped private opening");
    }

    #[test]
    fn qualification_pin_parser_requires_nonzero_exact_hex_and_canonical_program() {
        for pin in ["0x01".to_owned(), format!("0x{}", "00".repeat(32)),
            format!("0x{}", "gg".repeat(32)), "private-pin-sentinel".to_owned()]
        { assert!(fixed_hex(&pin).is_err()); }
        assert_eq!(fixed_hex(&format!("0x{}", "01".repeat(32))).unwrap(), [1; 32]);
        for program in [[0; 32], SCALAR_R, [0xff; 32]] {
            assert!(qualification_fixture(program).is_err());
        }
    }

    #[test]
    fn qualification_runner_rejects_unused_arguments_and_invalid_deadlines() {
        let base = ["owner_creation_qualification", "--binary", "/tmp/ziquid",
            "--elf", "/tmp/owner.elf", "--elf-sha256", "0x01", "--program-vkey", "0x01",
            "--private-temp-dir", "/tmp/private", "--groth16-artifact-base", "/tmp/setup",
            "--timeout-seconds", "1"];
        assert!(Args::try_parse_from(base).is_ok());
        for extra in [vec!["unused"], vec!["--witness-stdin"], vec!["--witness", "private-witness-sentinel"]] {
            assert!(Args::try_parse_from(base.into_iter().chain(extra)).is_err());
        }
        for timeout in ["0", "86401", "-1", "NaN"] {
            let mut args = base;
            args[14] = timeout;
            assert!(Args::try_parse_from(args).is_err());
        }
    }
}
