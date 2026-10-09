//! Temporary parent-run smoke: genuine synthetic consent/AEAD, actual CLI processes.
//! Fixture deployment/program are NOT independent qualification. No valid setup/proof.
#![cfg(target_os = "linux")]

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
use ziquid_proofs::samechain::creation::verify_note_creation_relation;

#[allow(dead_code)]
#[path = "../../proofs/tests/support/samechain.rs"]
mod fill_support;
#[allow(dead_code)]
#[path = "../../proofs/tests/support/note_creation.rs"]
mod creation_support;

type SmokeResult<T> = Result<T, &'static str>;
const ELF_HASH: &str = "0x6cbd653f6dca5e23e884952ca0d7259aebd258be06591dbc1438e3c49e4a40b2";
const ARTIFACT_ERROR: &[u8] = b"samechain local owner proof artifacts unavailable\n";
const POLICY_ERROR: &[u8] = b"samechain local owner proof reap policy rejected\n";
const RETAINED_ERROR: &[u8] = b"samechain local owner proof cleanup failed; private scratch retained\n";
const SENTINEL: &[u8] = b"owner-smoke-unrelated-private-root-sentinel";
const OUTPUT_LIMIT: usize = 65536;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(2 + bytes.len() * 2);
    value.push_str("0x");
    for byte in bytes { write!(&mut value, "{byte:02x}").expect("hex formatting failed"); }
    value
}

fn private_directory(prefix: &str) -> SmokeResult<tempfile::TempDir> {
    tempfile::Builder::new().prefix(prefix)
        .permissions(fs::Permissions::from_mode(0o700)).tempdir()
        .map_err(|_| "temporary directory creation failed")
}

fn private_root() -> SmokeResult<PathBuf> {
    // No recursive deletion: failure/unknown writer termination preserves this root.
    let root = private_directory("z2z-owner-smoke-private-")?.keep();
    let mut file = fs::OpenOptions::new().create_new(true).write(true).mode(0o600)
        .open(root.join("unrelated")).map_err(|_| "sentinel creation failed; root retained")?;
    file.write_all(SENTINEL).map_err(|_| "sentinel write failed; root retained")?;
    Ok(root)
}

fn check_root(root: &Path, retained: bool) -> SmokeResult<()> {
    let metadata = fs::symlink_metadata(root).map_err(|_| "private root missing")?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err("private root mode changed");
    }
    let sentinel = root.join("unrelated");
    let metadata = fs::symlink_metadata(&sentinel).map_err(|_| "sentinel missing")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o7777 != 0o600
        || fs::read(&sentinel).map_err(|_| "sentinel read failed")? != SENTINEL
    { return Err("unrelated sentinel changed"); }
    let mut scratch_count = 0;
    for entry in fs::read_dir(root).map_err(|_| "private root enumeration failed")? {
        let entry = entry.map_err(|_| "private root entry unavailable")?;
        if entry.file_name() == "unrelated" { continue; }
        let name = entry.file_name();
        let name = name.to_str().ok_or("unexpected non-UTF8 scratch entry")?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| "scratch metadata unavailable")?;
        if !retained || !name.starts_with(".z2z-owner-proof-") || !metadata.is_dir()
            || metadata.permissions().mode() & 0o7777 != 0o700
        { return Err("unexpected private scratch state; root retained"); }
        scratch_count += 1;
    }
    if retained && scratch_count != 1 { return Err("retained cleanup error lacks one private scratch"); }
    Ok(())
}

fn remove_clean_root(root: &Path) -> SmokeResult<()> {
    check_root(root, false)?;
    fs::remove_file(root.join("unrelated")).map_err(|_| "sentinel removal failed; root retained")?;
    fs::remove_dir(root).map_err(|_| "empty root removal failed; root retained")
}

struct ExternalCli { child: Child, reaped: bool }
impl Drop for ExternalCli {
    fn drop(&mut self) {
        if !self.reaped {
            // Only the unreaped direct CLI, never a numeric worker PID/process group.
            // Watchdog failure may leave its private worker; all private roots stay.
            if let Ok(None) = self.child.try_wait() { let _ = self.child.kill(); }
        }
    }
}

struct Captured {
    status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}

fn nonblocking(fd: &impl std::os::fd::AsFd) -> SmokeResult<()> {
    let flags = fcntl_getfl(fd).map_err(|_| "pipe flags unavailable")?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|_| "nonblocking pipe setup failed")
}

fn drain(pipe: &mut impl Read, bytes: &mut [u8], length: &mut usize) -> SmokeResult<bool> {
    loop {
        match pipe.read(&mut bytes[*length..]) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                *length += count;
                if *length > OUTPUT_LIMIT { return Err("CLI diagnostic output exceeded bound"); }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Err("CLI diagnostic pipe failed"),
        }
    }
}

fn run_cli(binary: &Path, args: &[OsString], setup: &Path, witness: &[u8],
    auto_reap: bool, budget: Duration) -> SmokeResult<Captured>
{
    let deadline = Instant::now() + budget;
    let mut command = if auto_reap {
        let mut launcher = Command::new("python3");
        launcher.args(["-c", "import signal,os,sys;signal.signal(signal.SIGCHLD,signal.SIG_IGN);os.execv(sys.argv[1],sys.argv[1:])"])
            .arg(binary);
        launcher
    } else { Command::new(binary) };
    command.env_clear();
    for name in ["HOME", "PATH"] {
        if let Some(value) = std::env::var_os(name) { command.env(name, value); }
    }
    command.arg("samechain").args(args)
        .env("SP1_GROTH16_CIRCUIT_PATH", setup)
        .env("SP1_PROVER", "cpu").env("SP1_CIRCUIT_MODE", "release")
        .env("RUST_LOG", "debug").env("RUST_BACKTRACE", "1")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn().map_err(|_| "actual CLI spawn failed")?;
    let mut process = ExternalCli { child, reaped: false };
    let stdin = process.child.stdin.take().ok_or("CLI stdin missing")?;
    let mut stdout = process.child.stdout.take().ok_or("CLI stdout missing")?;
    let mut stderr = process.child.stderr.take().ok_or("CLI stderr missing")?;
    nonblocking(&stdin)?; nonblocking(&stdout)?; nonblocking(&stderr)?;
    let mut stdin = Some(stdin);
    let mut written = 0;
    let mut out = Zeroizing::new(vec![0; OUTPUT_LIMIT + 1]);
    let mut err = Zeroizing::new(vec![0; OUTPUT_LIMIT + 1]);
    let (mut out_len, mut err_len) = (0, 0);
    let (mut out_eof, mut err_eof) = (false, false);
    let mut status = None;
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
            status = process.child.try_wait().map_err(|_| "external CLI reap failed; root retained")?;
            if status.is_some() { process.reaped = true; }
        }
        if let Some(status) = status && out_eof && err_eof {
            out.truncate(out_len); err.truncate(err_len);
            return Ok(Captured { status, stdout: out, stderr: err });
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn not_disclosed(stream: &[u8], private: &[u8]) -> SmokeResult<()> {
    if private.is_empty() { return Ok(()); }
    if stream.windows(private.len()).any(|window| window == private) {
        return Err("private bytes disclosed");
    }
    let mut json = Zeroizing::new(Vec::with_capacity(private.len() * 4 + 2));
    serde_json::to_writer(&mut *json, private).map_err(|_| "private diagnostic encoding failed")?;
    if stream.windows(json.len()).any(|window| window == &json[..]) {
        return Err("private serialized bytes disclosed");
    }
    if private.len() == 32 {
        use std::fmt::Write as _;
        let mut value = Zeroizing::new(String::with_capacity(64));
        for byte in private { write!(&mut *value, "{byte:02x}").map_err(|_| "private hex encoding failed")?; }
        if stream.windows(64).any(|window| window.eq_ignore_ascii_case(value.as_bytes())) {
            return Err("private hexadecimal bytes disclosed");
        }
    }
    Ok(())
}

fn check_diagnostics(output: &Captured, witness: &ziquid_proofs::samechain::creation::NoteCreationWitness,
    bytes: &[u8], paths: &[&Path]) -> SmokeResult<()>
{
    let note = witness.note.encode().map_err(|_| "private note encoding failed")?;
    for stream in [&output.stdout[..], &output.stderr[..]] {
        for private in [bytes, &witness.owner_seed, &witness.blind, &witness.recovery_key,
            &witness.note.nf_key, &witness.note.nonce, &witness.note.salt, &note, SENTINEL]
        { not_disclosed(stream, private)?; }
        for path in paths {
            let path = path.to_str().ok_or("smoke public path is not UTF8")?;
            not_disclosed(stream, path.as_bytes())?;
        }
    }
    Ok(())
}

fn rejected(output: &Captured) -> SmokeResult<()> {
    if output.status.code() != Some(1) || !output.stdout.is_empty() {
        return Err("actual CLI did not return semantic rejection without public output");
    }
    Ok(())
}

fn smoke() -> SmokeResult<()> {
    let execute = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [flag] if flag == "--execute" => true,
        _ => return Err("usage: owner_worker_smoke [--execute]"),
    };
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = workspace.join("target/release/ziquid").canonicalize()
        .map_err(|_| "parent-built release CLI missing")?;
    let elf = workspace.join("target/z2z-samechain-tree-20261004/samechain-tree.elf").canonicalize()
        .map_err(|_| "retained public owner ELF missing")?;
    let mut public_elf = File::open(&elf).map_err(|_| "retained public ELF unreadable")?;
    let mut hash = Sha256::new();
    let mut hash_buffer = [0; 8192];
    loop {
        let count = public_elf.read(&mut hash_buffer).map_err(|_| "retained public ELF hashing failed")?;
        if count == 0 { break; }
        hash.update(&hash_buffer[..count]);
    }
    if hex(&hash.finalize()) != ELF_HASH { return Err("STOP: retained public ELF hash mismatch"); }
    let fixture = private_directory("z2z-owner-smoke-public-")?;
    let setup = private_directory("z2z-owner-smoke-empty-setup-")?;
    if !setup.path().is_absolute() || setup.path().to_str().is_none()
        || fs::read_dir(setup.path()).map_err(|_| "setup enumeration failed")?.next().is_some()
    { return Err("STOP: missing-artifact fixture is not empty absolute UTF8 directory"); }
    let deployment = fill_support::deployment(); // Synthetic [5;32], canonical but NOT qualified.
    if deployment.owner_program != [5; 32] { return Err("STOP: fixture program changed"); }
    let witness = creation_support::ordinary_native();
    if witness.packet.deployment != deployment { return Err("STOP: fixture scope mismatch"); }
    let journal = verify_note_creation_relation(&witness).map_err(|_| "STOP: native signed fixture invalid")?
        .encode().map_err(|_| "native expected journal encoding failed")?;
    let bytes = witness.encode().map_err(|_| "canonical private witness encoding failed")?;
    let deployment_path = fixture.path().join("public-deployment.bin");
    fs::write(&deployment_path, deployment.encode().map_err(|_| "public deployment encoding failed")?)
        .map_err(|_| "public deployment fixture write failed")?;
    let base: Vec<OsString> = vec!["--operation".into(), "creation".into(), "--elf".into(), elf.clone().into(),
        "--elf-sha256".into(), ELF_HASH.into(), "--deployment".into(), deployment_path.clone().into(), "--witness-stdin".into()];
    let normal_root = private_root()?;
    let release = private_directory("z2z-owner-smoke-release-")?;
    let key_path = fixture.path().join("backup-key");
    let mut key = fs::OpenOptions::new().create_new(true).write(true).mode(0o600)
        .open(&key_path).map_err(|_| "generated backup key creation failed")?;
    key.write_all(&[0x41; 32]).map_err(|_| "generated backup key write failed")?;
    drop(key);
    let mut normal_args = vec![OsString::from("prove-owner")];
    normal_args.extend(base.iter().cloned());
    normal_args.extend([OsString::from("--program-vkey"), hex(&deployment.owner_program).into(),
        "--timeout-seconds".into(), "1".into(), "--release-dir".into(), release.path().into(),
        "--backup-key-file".into(), key_path.clone().into(), "--op-id".into(), hex(&[0x11; 32]).into(),
        "--private-temp-dir".into(), normal_root.clone().into()]);
    let normal = run_cli(&binary, &normal_args, setup.path(), &bytes, false, Duration::from_secs(10))?;
    check_diagnostics(&normal, &witness, &bytes, &[&binary, &elf, &deployment_path, setup.path(), &normal_root])?;
    rejected(&normal)?;
    let retained = if normal.stderr.as_slice() == ARTIFACT_ERROR { false }
        else if normal.stderr.as_slice() == RETAINED_ERROR { true }
        else { return Err("STOP: normal CLI did not return artifact or honest retained-cleanup category"); };
    check_root(&normal_root, retained)?;
    if !retained { remove_clean_root(&normal_root)?; }

    let policy_root = private_root()?;
    let policy_before = fs::symlink_metadata(&policy_root).map_err(|_| "policy root metadata unavailable")?;
    let mut policy_args = normal_args;
    *policy_args.last_mut().ok_or("missing private-root argument")? = policy_root.clone().into();
    let policy = run_cli(&binary, &policy_args, setup.path(), &bytes, true, Duration::from_secs(10))?;
    check_diagnostics(&policy, &witness, &bytes, &[&binary, &elf, &deployment_path, setup.path(), &policy_root])?;
    rejected(&policy)?;
    if policy.stderr.as_slice() != POLICY_ERROR { return Err("STOP: inherited-auto-reap policy was not categorically rejected"); }
    check_root(&policy_root, false)?;
    let policy_after = fs::symlink_metadata(&policy_root).map_err(|_| "policy root metadata unavailable")?;
    if (policy_before.dev(), policy_before.ino(), policy_before.mtime(), policy_before.mtime_nsec(),
        policy_before.ctime(), policy_before.ctime_nsec())
        != (policy_after.dev(), policy_after.ino(), policy_after.mtime(), policy_after.mtime_nsec(),
            policy_after.ctime(), policy_after.ctime_nsec())
    { return Err("STOP: reap-policy rejection mutated private root"); }
    remove_clean_root(&policy_root)?;
    if normal.stderr == policy.stderr { return Err("normal artifact and reap-policy errors were indistinguishable"); }

    if execute {
        let mut args = vec![OsString::from("execute-owner")];
        args.extend(base);
        let execution = run_cli(&binary, &args, setup.path(), &bytes, false, Duration::from_secs(120))?;
        check_diagnostics(&execution, &witness, &bytes, &[&binary, &elf, &deployment_path, setup.path()])?;
        if !execution.status.success() || !execution.stderr.is_empty() {
            return Err("STOP: actual CPU guest execution failed or emitted diagnostics");
        }
        let value: serde_json::Value = serde_json::from_slice(&execution.stdout).map_err(|_| "CPU execution public JSON invalid")?;
        if value["kind"] != "samechain_owner_execution" || value["operation"] != "creation"
            || value["journal"] != hex(&journal) || value["exit_code"] != 0
            || value["evidence"] != "actual_cpu_owner_guest_execution"
            || value["elf_sha256"] != ELF_HASH || value["instructions"].as_u64().unwrap_or(0) == 0
            || value["expected_deployment"]["owner_program"] != hex(&deployment.owner_program)
        { return Err("CPU guest full expected journal or public execution scope mismatch"); }
        for flag in ["proof_certificate", "financial_execution", "strict_matching_privacy"] {
            if value[flag] != false { return Err("CPU execution misrepresented certificate or financial acceptance"); }
        }
        for flag in ["program_identity", "root_eligibility", "global_unspentness", "asset_backing", "finality", "deployment_profile_qualification"] {
            if value[flag] != "UNVERIFIED" { return Err("CPU execution misrepresented qualification"); }
        }
        println!("PASS: actual CPU creation journal matched; diagnostics empty; no proof/financial qualification.");
    }
    if fs::read_dir(setup.path()).map_err(|_| "setup final enumeration failed")?.next().is_some() {
        return Err("STOP: missing setup directory mutated");
    }
    fixture.close().map_err(|_| "public deployment fixture cleanup failed")?;
    setup.close().map_err(|_| "empty public setup fixture cleanup failed")?;
    if retained {
        println!("PASS: categorical cleanup rejection; private scratch honestly retained; artifact cause unconfirmed.");
    } else {
        println!("PASS: actual isolated worker missing-artifact rejection; private scratch cleaned.");
    }
    println!("PASS: actual SIGCHLD-ignore exec rejected before private scratch; root unchanged; no proof/funds/SQL/network.");
    Ok(())
}

fn main() {
    if let Err(category) = smoke() {
        eprintln!("owner worker smoke failed: {category}");
        std::process::exit(1);
    }
}
