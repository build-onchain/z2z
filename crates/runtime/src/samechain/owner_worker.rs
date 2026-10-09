//! One concrete Linux local prover boundary; no financial authority or fake producer.

use super::*;
use rustix::{
    fs::{AtFlags, FileType, Mode, OFlags},
    io::Errno,
    process::{Pid, Signal, WaitId, WaitIdOptions, WaitIdStatus},
};
use std::{
    fs::File,
    io,
    net::Shutdown,
    os::{fd::{AsFd, OwnedFd}, unix::{fs::MetadataExt, net::UnixStream, process::CommandExt}},
    process::{Child, Command as ProcessCommand, Stdio},
    time::{Duration, Instant},
};
use ziquid_proofs::artifacts::local::{
    OwnerCertificate, prove_owner, require_groth16_artifacts, verify_owner_certificate,
};

const REQUEST_MAGIC: &[u8; 8] = b"Z2ZOWQ01";
const RESPONSE_MAGIC: &[u8; 8] = b"Z2ZOWR01";

const DISALLOWED_SDK_ENV: &[&str] = &[
    "MINIMAL_TRACE_CHUNK_THRESHOLD", "GAS_TRACE_CHUNK_THRESHOLD", "TRACE_CHUNK_SLOTS",
    "GAS_TRACE_CHUNK_SLOTS", "MEMORY_LIMIT", "SHARD_SIZE", "ELEMENT_THRESHOLD",
    "HEIGHT_THRESHOLD", "FULL_SIZE_SHARDS", "SP1_WORKER_NUM_SPLICING_WORKERS",
    "SP1_WORKER_SPLICING_BUFFER_SIZE", "SP1_WORKER_MAX_REDUCE_ARITY",
    "SP1_WORKER_NUMBER_OF_SEND_SPLICE_WORKERS_PER_SPLICE",
    "SP1_WORKER_SEND_SPLICE_INPUT_BUFFER_SIZE_PER_SPLICE",
    "SP1_WORKER_GLOBAL_MEMORY_BUFFER_SIZE", "SP1_WORKER_USE_FIXED_PK",
    "SP1_WORKER_VERIFY_INTERMEDIATES", "SP1_WORKER_NUM_CORE_WORKERS",
    "SP1_WORKER_CORE_BUFFER_SIZE", "SP1_WORKER_NUM_SETUP_WORKERS",
    "SP1_WORKER_SETUP_BUFFER_SIZE", "SP1_WORKER_NORMALIZE_PROGRAM_CACHE_SIZE",
    "SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS", "SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE",
    "SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS",
    "SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE", "SP1_WORKER_NUM_RECURSION_PROVER_WORKERS",
    "SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE", "SP1_WORKER_MAX_COMPOSE_ARITY",
    "SP1_WORKER_NUMBER_OF_GAS_EXECUTORS", "SP1_WORKER_GAS_EXECUTOR_BUFFER_SIZE",
    "SP1_WORKER_NUM_DEFERRED_WORKERS", "SP1_WORKER_DEFERRED_BUFFER_SIZE",
    "SP1_RECORD_WRITE_FREQUENCY", "SP1_GNARK_IMAGE", "SP1_PLONK_CIRCUIT_PATH",
    "TRACE_SAMPLE_RATE",
];

fn check_owner_environment() -> Result<(), &'static str> {
    check_private_environment().map_err(|_| "samechain private guest environment rejected")?;
    if DISALLOWED_SDK_ENV.iter().any(|name| std::env::var_os(name).is_some()) {
        return Err("samechain private guest environment rejected");
    }
    Ok(())
}
const SCALAR_R: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Failure { Pin = 1, Input = 2, Artifact = 3, Producer = 4, Output = 5 }

impl Failure {
    fn decode(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Pin), 2 => Some(Self::Input), 3 => Some(Self::Artifact),
            4 => Some(Self::Producer), 5 => Some(Self::Output), _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkerError { Certificate, Rejected(Failure), Deadline, ReapPolicy, UnsafeRoot, CleanupRetained }

impl WorkerError {
    fn message(self) -> &'static str {
        match self {
            Self::Rejected(Failure::Artifact) => "samechain local owner proof artifacts unavailable",
            Self::Rejected(Failure::Producer) => "samechain local owner proof producer rejected",
            Self::Deadline => "samechain local owner proof deadline exceeded",
            Self::ReapPolicy => "samechain local owner proof reap policy rejected",
            Self::UnsafeRoot => "samechain local owner proof private temporary directory rejected",
            Self::CleanupRetained => "samechain local owner proof cleanup failed; private scratch retained",
            Self::Certificate | Self::Rejected(_) => "samechain local owner certificate rejected",
        }
    }
}

struct Options<'a> {
    operation: SimulationOperation,
    elf: &'a Path,
    elf_sha256: &'a str,
    deployment: &'a Path,
    program_vkey: &'a str,
    packet: Option<&'a Path>,
    groth16_artifact_dir: Option<&'a Path>,
}

fn options(command: &super::Command) -> Option<Options<'_>> {
    match command {
        super::Command::ProveOwner { operation, elf, elf_sha256, deployment, program_vkey, packet, .. } =>
            Some(Options { operation: *operation, elf, elf_sha256, deployment, program_vkey,
                packet: packet.as_deref(), groth16_artifact_dir: None }),
        super::Command::OwnerProofWorker { operation, elf, elf_sha256, deployment, program_vkey, packet, groth16_artifact_dir } =>
            Some(Options { operation: *operation, elf, elf_sha256, deployment, program_vkey,
                packet: packet.as_deref(), groth16_artifact_dir: Some(groth16_artifact_dir) }),
        _ => None,
    }
}

struct Prepared {
    owned: OwnedOwnerInput,
    expected: Deployment,
    elf: Vec<u8>,
    hash: [u8; 32],
    program: [u8; 32],
    journal: Vec<u8>,
}

struct PreflightError { message: &'static str, category: Failure }

fn prepare(options: &Options<'_>, bytes: &[u8]) -> Result<Prepared, PreflightError> {
    use sha2::{Digest, Sha256};
    let pin = |message| PreflightError { message, category: Failure::Pin };
    let input_error = |message| PreflightError { message, category: Failure::Input };
    check_owner_environment().map_err(&input_error)?;
    let program: [u8; 32] = public_fixed_hex(options.program_vkey)
        .map_err(|_| pin("invalid samechain owner program pin"))?;
    if program == [0; 32] || program >= SCALAR_R {
        return Err(pin("invalid canonical samechain owner program pin"));
    }
    let hash: [u8; 32] = public_fixed_hex(options.elf_sha256)
        .map_err(|_| pin("invalid samechain owner ELF hash pin"))?;
    if hash == [0; 32] { return Err(pin("invalid samechain owner ELF hash pin")); }
    let (deployment, length) = read_public_packet_bytes(options.deployment).map_err(pin)?;
    let expected = Deployment::decode(&deployment[..length])
        .map_err(|_| pin("invalid samechain expected deployment encoding"))?;
    if expected.owner_program != program { return Err(pin("samechain owner program mismatch")); }
    let owned = OwnedOwnerInput::decode(options.operation, options.packet, bytes).map_err(input_error)?;
    let input = owned.as_input();
    if input.deployment() != &expected { return Err(pin("samechain owner deployment mismatch")); }
    let elf = read_owner_elf(options.elf).map_err(pin)?;
    if <[u8; 32]>::from(Sha256::digest(&elf)) != hash {
        return Err(pin("samechain owner ELF hash mismatch"));
    }
    let journal = input.expected_journal().map_err(|_| input_error("samechain owner relation rejected"))?;
    if journal.is_empty() || journal.len() > MAX_PACKET_BYTES {
        return Err(input_error("samechain owner relation rejected"));
    }
    Ok(Prepared { owned, expected, elf, hash, program, journal })
}

fn release_binding(prepared: &Prepared, op_id: [u8; 32]) -> Result<release::ReleaseBinding, &'static str> {
    use sha2::{Digest, Sha256};
    use backup::SnapshotOperation;
    let packet_error = |_| "samechain release packet rejected";
    let (operation, role, packet_digest, expiry, required_nfs) = match &prepared.owned {
        OwnedOwnerInput::Fill(witness) => (SnapshotOperation::Fill, witness.role,
            witness.packet.digest().map_err(packet_error)?, witness.packet.expiry,
            witness.packet.inputs.iter().map(|input| input.nullifier).collect()),
        OwnedOwnerInput::CancelExit(witness) => (
            if witness.action == Action::Cancel { SnapshotOperation::Cancel } else { SnapshotOperation::Exit },
            witness.role, witness.packet.digest().map_err(packet_error)?, witness.packet.expiry,
            vec![witness.packet.input.nullifier]),
        OwnedOwnerInput::Withdrawal(witness) => (SnapshotOperation::Withdrawal, Role::A,
            witness.packet.digest().map_err(packet_error)?, witness.packet.expiry,
            vec![witness.packet.input.nullifier]),
        OwnedOwnerInput::Creation(witness) => (SnapshotOperation::Creation, witness.packet.role,
            witness.packet.digest().map_err(packet_error)?, witness.packet.expiry, Vec::new()),
    };
    let binding = release::ReleaseBinding { op_id, deployment: prepared.expected, operation, role,
        packet_digest, program_vkey: prepared.program, journal_digest: Sha256::digest(&prepared.journal).into(),
        expiry, required_nfs };
    binding.validate().map_err(|_| "samechain release binding rejected")?;
    Ok(binding)
}

fn operation_code(operation: SimulationOperation) -> u8 {
    match operation {
        SimulationOperation::Fill => 0, SimulationOperation::Cancel => 1,
        SimulationOperation::Exit => 2, SimulationOperation::Withdrawal => 3,
        SimulationOperation::Creation => 4,
    }
}

fn operation_name(operation: SimulationOperation) -> &'static str {
    match operation {
        SimulationOperation::Fill => "fill", SimulationOperation::Cancel => "cancel",
        SimulationOperation::Exit => "exit", SimulationOperation::Withdrawal => "withdrawal",
        SimulationOperation::Creation => "creation",
    }
}

fn worker_socket() -> Result<UnixStream, WorkerError> {
    let stdin = std::io::stdin();
    let fd = stdin.as_fd().try_clone_to_owned().map_err(|_| WorkerError::Certificate)?;
    let stream = UnixStream::from(fd);
    // Reject ordinary stdin and named/public listeners before consuming witnesses.
    if !stream.peer_addr().map_err(|_| WorkerError::Certificate)?.is_unnamed()
        || !stream.local_addr().map_err(|_| WorkerError::Certificate)?.is_unnamed()
    {
        return Err(WorkerError::Certificate);
    }
    Ok(stream)
}

struct NullLogger;

impl log::Log for NullLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool { false }
    fn log(&self, _: &log::Record<'_>) {}
    fn flush(&self) {}
}

static NULL_LOGGER: NullLogger = NullLogger;

fn child_isolation() -> Result<(UnixStream, File), WorkerError> {
    let socket = worker_socket()?;
    let null = rustix::fs::open("/dev/null", OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty()).map_err(|_| WorkerError::Certificate)?;
    let null = rustix::fs::fstat(&null).map_err(|_| WorkerError::Certificate)?;
    if FileType::from_raw_mode(null.st_mode) != FileType::CharacterDevice {
        return Err(WorkerError::Certificate);
    }
    let stdout = rustix::fs::fstat(std::io::stdout()).map_err(|_| WorkerError::Certificate)?;
    let stderr = rustix::fs::fstat(std::io::stderr()).map_err(|_| WorkerError::Certificate)?;
    for diagnostic in [stdout, stderr] {
        if diagnostic.st_dev != null.st_dev || diagnostic.st_ino != null.st_ino
            || diagnostic.st_rdev != null.st_rdev
            || FileType::from_raw_mode(diagnostic.st_mode) != FileType::CharacterDevice
        {
            return Err(WorkerError::Certificate);
        }
    }
    // Dedicated child only: reject an active scoped subscriber, then reserve
    // both process-global defaults before private input or prover threads.
    // Later scoped subscribers remain possible; this is not a logging sandbox.
    if !tracing::dispatcher::get_default(|dispatch|
        dispatch.is::<tracing::subscriber::NoSubscriber>())
    {
        return Err(WorkerError::Certificate);
    }
    tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::new())
        .map_err(|_| WorkerError::Certificate)?;
    log::set_logger(&NULL_LOGGER).map_err(|_| WorkerError::Certificate)?;
    log::set_max_level(log::LevelFilter::Off);
    check_owner_environment().map_err(|_| WorkerError::Certificate)?;
    for name in ["RUST_LOG", "RUST_BACKTRACE", "RUST_LIB_BACKTRACE"] {
        if std::env::var_os(name).is_some() { return Err(WorkerError::Certificate); }
    }
    let path = PathBuf::from(std::env::var_os("TMPDIR").ok_or(WorkerError::UnsafeRoot)?);
    if !path.is_absolute() || path.to_str().is_none() { return Err(WorkerError::UnsafeRoot); }
    let (directory, _) = crate::custody::trusted_private_directory(&path)
        .map_err(|_| WorkerError::UnsafeRoot)?;
    Ok((socket, directory))
}

fn read_request(stream: &mut UnixStream, operation: SimulationOperation)
    -> Result<(Zeroizing<Vec<u8>>, usize), Failure>
{
    // This allocation is completely initialized and guarded before private reads;
    // neither the header nor EOF probe can provoke secret reallocation.
    let mut bytes = Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES]);
    let mut header = [0; 13];
    stream.read_exact(&mut header).map_err(|_| Failure::Input)?;
    if &header[..8] != REQUEST_MAGIC || header[8] != operation_code(operation) {
        return Err(Failure::Input);
    }
    let length = u32::from_be_bytes(header[9..13].try_into().map_err(|_| Failure::Input)?) as usize;
    if length == 0 || length > MAX_PRIVATE_INPUT_BYTES { return Err(Failure::Input); }
    stream.read_exact(&mut bytes[..length]).map_err(|_| Failure::Input)?;
    let mut excess = Zeroizing::new([0; 1]);
    if stream.read(&mut *excess).map_err(|_| Failure::Input)? != 0 { return Err(Failure::Input); }
    Ok((bytes, length))
}

fn write_failure(stream: &mut UnixStream, failure: Failure) -> io::Result<()> {
    stream.write_all(RESPONSE_MAGIC)?;
    stream.write_all(&[1, failure as u8])?;
    stream.shutdown(Shutdown::Write)
}

fn write_certificate(stream: &mut UnixStream, certificate: &OwnerCertificate) -> Result<(), Failure> {
    if certificate.journal.is_empty() || certificate.journal.len() > MAX_PACKET_BYTES
        || certificate.proof_bytes.len() != 356
    {
        return Err(Failure::Output);
    }
    let length = u32::try_from(certificate.journal.len()).map_err(|_| Failure::Output)?;
    stream.write_all(RESPONSE_MAGIC).map_err(|_| Failure::Output)?;
    stream.write_all(&[0]).map_err(|_| Failure::Output)?;
    stream.write_all(&certificate.program_vkey).map_err(|_| Failure::Output)?;
    stream.write_all(&length.to_be_bytes()).map_err(|_| Failure::Output)?;
    stream.write_all(&certificate.journal).map_err(|_| Failure::Output)?;
    stream.write_all(&certificate.proof_bytes).map_err(|_| Failure::Output)?;
    stream.shutdown(Shutdown::Write).map_err(|_| Failure::Output)
}
pub(super) fn run_child(command: &super::Command) -> ExitCode {
    let options = match options(command) { Some(options) => options, None => return ExitCode::FAILURE };
    let (mut stream, _scratch) = match child_isolation() {
        Ok(isolation) => isolation,
        Err(_) => return ExitCode::FAILURE,
    };
    let artifact_dir = match options.groth16_artifact_dir {
        Some(path) => path,
        None => return ExitCode::FAILURE,
    };
    if ziquid_proofs::artifacts::local::require_groth16_artifacts_at(artifact_dir).is_err()
        || std::env::var_os("SP1_GROTH16_CIRCUIT_PATH").as_deref()
            != artifact_dir.parent().map(|path| path.as_os_str())
    { return ExitCode::FAILURE; }
    let mut produce = || -> Result<OwnerCertificate, Failure> {
        let (bytes, length) = read_request(&mut stream, options.operation)?;
        let Prepared { owned, elf, hash, program, journal, .. } =
            prepare(&options, &bytes[..length]).map_err(|error| error.category)?;
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()
            .map_err(|_| Failure::Producer)?;
        let certificate = runtime.block_on(prove_owner(
            sp1_primitives::Elf::from(elf), &owned.as_input(), &hash, &program,
        )).map_err(|_| Failure::Producer)?;
        verify_owner_certificate(&certificate, &program, &journal).map_err(|_| Failure::Output)?;
        Ok(certificate)
    };
    match produce() {
        Ok(certificate) => match write_certificate(&mut stream, &certificate) {
            Ok(()) => ExitCode::SUCCESS,
            Err(failure) => { let _ = write_failure(&mut stream, failure); ExitCode::FAILURE }
        },
        Err(failure) => { let _ = write_failure(&mut stream, failure); ExitCode::FAILURE },
    }
}

fn private_command(command: &mut ProcessCommand, scratch: &Path, artifact_base: Option<&Path>) {
    command.env_clear();
    for name in ["HOME", "PATH"] {
        if let Some(value) = std::env::var_os(name) { command.env(name, value); }
    }
    if let Some(artifact_base) = artifact_base {
        command.env("SP1_GROTH16_CIRCUIT_PATH", artifact_base);
    }
    command.env("SP1_PROVER", "cpu").env("SP1_CIRCUIT_MODE", "release")
        .env("TMPDIR", scratch).stdout(Stdio::null()).stderr(Stdio::null());
}

fn pause(deadline: Instant) -> Result<(), WorkerError> {
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(WorkerError::Deadline)?;
    if remaining.is_zero() { return Err(WorkerError::Deadline); }
    // Bounded synchronous local socket polling, not an untracked async watchdog.
    std::thread::sleep(remaining.min(Duration::from_millis(2)));
    Ok(())
}

fn observe(pid: Pid) -> Result<Option<WaitIdStatus>, Errno> {
    rustix::process::waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
}


fn reap_policy_probe(mut command: ProcessCommand, deadline: Instant) -> Result<(), WorkerError> {
    command.env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| WorkerError::ReapPolicy)?;
    let pid = Pid::from_child(&child);
    loop {
        if Instant::now() >= deadline { return Err(WorkerError::ReapPolicy); }
        match observe(pid) {
            Ok(Some(status)) => {
                // Only a retained terminal child is reaped. There is deliberately no
                // kill/Drop signaling on this no-secret probe, including timeout.
                let exit = child.wait().map_err(|_| WorkerError::ReapPolicy)?;
                return if status.exit_status() == Some(0) && exit.success() {
                    Ok(())
                } else { Err(WorkerError::ReapPolicy) };
            }
            Ok(None) | Err(Errno::INTR) => {},
            Err(_) => return Err(WorkerError::ReapPolicy),
        }
        pause(deadline).map_err(|_| WorkerError::ReapPolicy)?;
    }
}

struct Scratch {
    root: File,
    directory: File,
    name: OsString,
    path: PathBuf,
}

impl Scratch {
    fn create(path: &Path) -> Result<Self, WorkerError> {
        let (root, absolute) = crate::custody::trusted_private_directory(path)
            .map_err(|_| WorkerError::UnsafeRoot)?;
        if absolute.to_str().is_none() { return Err(WorkerError::UnsafeRoot); }
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| WorkerError::UnsafeRoot)?;
        let name = OsString::from(format!(".z2z-owner-proof-{}", &public_hex(&random)[2..]));
        rustix::fs::mkdirat(&root, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|_| WorkerError::UnsafeRoot)?;
        let directory = match rustix::fs::openat(&root, &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty())
        {
            Ok(fd) => File::from(fd),
            Err(_) => {
                return if rustix::fs::unlinkat(&root, &name, AtFlags::REMOVEDIR).is_ok() {
                    Err(WorkerError::UnsafeRoot)
                } else { Err(WorkerError::CleanupRetained) };
            }
        };
        let scratch = Self { path: absolute.join(&name), root, directory, name };
        let metadata = scratch.directory.metadata().map_err(|_| WorkerError::CleanupRetained)?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
            return Err(WorkerError::CleanupRetained);
        }
        if scratch.directory.sync_all().is_err() || scratch.root.sync_all().is_err() {
            return Err(WorkerError::CleanupRetained);
        }
        Ok(scratch)
    }

    fn cleanup(&mut self, deadline: Instant) -> Result<(), WorkerError> {
        let metadata = self.directory.metadata().map_err(|_| WorkerError::CleanupRetained)?;
        let named = rustix::fs::statat(&self.root, &self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| WorkerError::CleanupRetained)?;
        if named.st_dev != metadata.dev() || named.st_ino != metadata.ino()
            || FileType::from_raw_mode(named.st_mode) != FileType::Directory
        {
            return Err(WorkerError::CleanupRetained);
        }
        let entries = rustix::fs::Dir::read_from(&self.directory).map_err(|_| WorkerError::CleanupRetained)?;
        for entry in entries {
            if Instant::now() >= deadline { return Err(WorkerError::CleanupRetained); }
            let entry = entry.map_err(|_| WorkerError::CleanupRetained)?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." { continue; }
            let stat = rustix::fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| WorkerError::CleanupRetained)?;
            // Native Gnark creates flat temporary files. Unknown subdirectories
            // stay private for owner recovery; never follow a symlink or recurse.
            if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
                return Err(WorkerError::CleanupRetained);
            }
            rustix::fs::unlinkat(&self.directory, name, AtFlags::empty())
                .map_err(|_| WorkerError::CleanupRetained)?;
        }
        rustix::fs::unlinkat(&self.root, &self.name, AtFlags::REMOVEDIR)
            .map_err(|_| WorkerError::CleanupRetained)
    }
}

enum LeaderState {
    Running,
    TerminalUnreaped(WaitIdStatus),
    LostReapOwnership,
}


struct Worker {
    child: Child,
    pid: Pid,
    socket: Option<UnixStream>,
    scratch: Option<Scratch>,
    deadline: Instant,
    timeout: Duration,
    cleanup_deadline: Option<Instant>,
    leader: LeaderState,
}

impl Worker {
    fn spawn(mut command: ProcessCommand, mut scratch: Scratch, timeout: Duration, deadline: Instant)
        -> Result<Self, WorkerError>
    {
        if Instant::now() >= deadline {
            scratch.cleanup(Instant::now() + timeout)?;
            return Err(WorkerError::Deadline);
        }
        let spawn = (|| {
            let (parent, child) = UnixStream::pair().map_err(|_| WorkerError::Certificate)?;
            parent.set_nonblocking(true).map_err(|_| WorkerError::Certificate)?;
            let fd: OwnedFd = child.into();
            command.stdin(Stdio::from(fd)).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0);
            let child = command.spawn().map_err(|_| WorkerError::Certificate)?;
            Ok((child, parent))
        })();
        match spawn {
            Ok((child, parent)) => {
                // Immediate ownership: no fallible operation before the guard exists.
                let pid = Pid::from_child(&child);
                Ok(Self { child, pid, socket: Some(parent), scratch: Some(scratch), deadline,
                    timeout, cleanup_deadline: None, leader: LeaderState::Running })
            }
            Err(error) => {
                scratch.cleanup(Instant::now() + timeout)?;
                Err(error)
            }
        }
    }

    fn write(&mut self, mut bytes: &[u8]) -> Result<(), WorkerError> {
        while !bytes.is_empty() {
            if Instant::now() >= self.deadline { return Err(WorkerError::Deadline); }
            match self.socket.as_mut().ok_or(WorkerError::Certificate)?.write(bytes) {
                Ok(0) => return Err(WorkerError::Certificate),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => pause(self.deadline)?,
                Err(_) => return Err(WorkerError::Certificate),
            }
        }
        Ok(())
    }

    fn read(&mut self, mut bytes: &mut [u8]) -> Result<(), WorkerError> {
        while !bytes.is_empty() {
            if Instant::now() >= self.deadline { return Err(WorkerError::Deadline); }
            match self.socket.as_mut().ok_or(WorkerError::Certificate)?.read(bytes) {
                Ok(0) => return Err(WorkerError::Certificate),
                Ok(count) => bytes = &mut bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => pause(self.deadline)?,
                Err(_) => return Err(WorkerError::Certificate),
            }
        }
        Ok(())
    }

    fn eof(&mut self) -> Result<(), WorkerError> {
        let mut excess = Zeroizing::new([0; 1]);
        loop {
            if Instant::now() >= self.deadline { return Err(WorkerError::Deadline); }
            match self.socket.as_mut().ok_or(WorkerError::Certificate)?.read(&mut *excess) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(WorkerError::Certificate),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => pause(self.deadline)?,
                Err(_) => return Err(WorkerError::Certificate),
            }
        }
    }

    fn observe(&mut self) -> Result<Option<WaitIdStatus>, WorkerError> {
        if let LeaderState::TerminalUnreaped(status) = self.leader {
            return Ok(Some(status));
        }
        if matches!(self.leader, LeaderState::LostReapOwnership) {
            return Err(WorkerError::CleanupRetained);
        }
        match observe(self.pid) {
            Ok(Some(status)) => {
                self.leader = LeaderState::TerminalUnreaped(status);
                Ok(Some(status))
            }
            Ok(None) | Err(Errno::INTR) => Ok(None),
            Err(_) => {
                self.leader = LeaderState::LostReapOwnership;
                Err(WorkerError::CleanupRetained)
            }
        }
    }

    fn exchange(&mut self, operation: SimulationOperation, bytes: &[u8], expected_length: usize)
        -> Result<OwnerCertificate, WorkerError>
    {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_INPUT_BYTES
            || expected_length == 0 || expected_length > MAX_PACKET_BYTES
        {
            return Err(WorkerError::Certificate);
        }
        self.write(REQUEST_MAGIC)?;
        self.write(&[operation_code(operation)])?;
        self.write(&(bytes.len() as u32).to_be_bytes())?;
        self.write(bytes)?;
        self.socket.as_ref().ok_or(WorkerError::Certificate)?.shutdown(Shutdown::Write)
            .map_err(|_| WorkerError::Certificate)?;
        let mut header = [0; 9];
        self.read(&mut header)?;
        if &header[..8] != RESPONSE_MAGIC { return Err(WorkerError::Certificate); }
        if header[8] == 1 {
            let mut category = [0; 1];
            self.read(&mut category)?;
            let category = Failure::decode(category[0]).ok_or(WorkerError::Certificate)?;
            self.eof()?;
            return Err(WorkerError::Rejected(category));
        }
        if header[8] != 0 { return Err(WorkerError::Certificate); }
        let mut program_vkey = [0; 32];
        let mut length = [0; 4];
        self.read(&mut program_vkey)?;
        self.read(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length != expected_length || length > MAX_PACKET_BYTES { return Err(WorkerError::Certificate); }
        let mut journal = vec![0; length];
        let mut proof_bytes = vec![0; 356];
        self.read(&mut journal)?;
        self.read(&mut proof_bytes)?;
        self.eof()?;
        loop {
            if Instant::now() >= self.deadline { return Err(WorkerError::Deadline); }
            if let Some(status) = self.observe()? {
                if status.exit_status() != Some(0) { return Err(WorkerError::Certificate); }
                return Ok(OwnerCertificate { program_vkey, journal, proof_bytes });
            }
            pause(self.deadline)?;
        }
    }

    fn finish(&mut self) -> Result<(), WorkerError> {
        if self.scratch.is_none() { return Ok(()); }
        let deadline = *self.cleanup_deadline.get_or_insert_with(|| Instant::now() + self.timeout);
        if let Some(socket) = self.socket.take() { let _ = socket.shutdown(Shutdown::Both); }
        if matches!(self.leader, LeaderState::LostReapOwnership) {
            return Err(WorkerError::CleanupRetained);
        }
        // Reserve the numeric identity before any nonzero group signal. An
        // ECHILD/unknown transition is closed failure, never a kill attempt.
        if matches!(self.leader, LeaderState::Running) {
            let _status = self.observe()?;
        }
        match rustix::process::kill_process_group(self.pid, Signal::KILL) {
            Ok(()) | Err(Errno::SRCH) => {}
            Err(_) => {
                self.leader = LeaderState::LostReapOwnership;
                return Err(WorkerError::CleanupRetained);
            }
        }
        loop {
            if Instant::now() >= deadline { return Err(WorkerError::CleanupRetained); }
            // Cached TerminalUnreaped is valid only because it came from a
            // prior waitid; Running must obtain its own post-SIGKILL status.
            if self.observe()?.is_some() { break; }
            pause(deadline).map_err(|_| WorkerError::CleanupRetained)?;
        }
        if self.child.wait().is_err() {
            self.leader = LeaderState::LostReapOwnership;
            return Err(WorkerError::CleanupRetained);
        }
        self.leader = LeaderState::LostReapOwnership;
        loop {
            if Instant::now() >= deadline { return Err(WorkerError::CleanupRetained); }
            match rustix::process::test_kill_process_group(self.pid) {
                Err(Errno::SRCH) => break,
                Ok(()) | Err(Errno::INTR) => {}
                Err(_) => return Err(WorkerError::CleanupRetained),
            }
            pause(deadline).map_err(|_| WorkerError::CleanupRetained)?;
        }
        self.scratch.as_mut().ok_or(WorkerError::CleanupRetained)?.cleanup(deadline)?;
        self.scratch = None;
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Same already-started cleanup deadline on unwind/error; no panic and no
        // unconditional unlink of scratch with possibly live writers.
        let _ = self.finish();
    }
}

#[derive(Serialize)]
struct CertificateExport {
    kind: &'static str,
    operation: &'static str,
    expected_deployment: InspectionDeployment,
    program_vkey: String,
    journal: String,
    proof: String,
    sdk_storage_boundary: &'static str,
    proof_certificate: bool,
    program_identity: &'static str,
    root_eligibility: &'static str,
    global_unspentness: &'static str,
    asset_backing: &'static str,
    finality: &'static str,
    deployment_profile_qualification: &'static str,
    financial_execution: bool,
    strict_matching_privacy: bool,
}

fn produce(command: &super::Command, bytes: &[u8], program: &[u8; 32], journal: &[u8])
    -> Result<OwnerCertificate, &'static str>
{
    let super::Command::ProveOwner { private_temp_dir, timeout_seconds, .. } = command else {
        return Err("invalid samechain command arguments");
    };
    let options = options(command).ok_or("invalid samechain command arguments")?;
    let timeout = Duration::from_secs(*timeout_seconds);
    let executable = std::env::current_exe().map_err(|_| WorkerError::ReapPolicy.message())?;
    let mut probe = ProcessCommand::new(&executable);
    probe.args(["samechain", "owner-proof-reap-probe"]);
    let probe_deadline = Instant::now() + timeout;
    reap_policy_probe(probe, probe_deadline).map_err(WorkerError::message)?;
    let transport_deadline = Instant::now() + timeout;
    let artifact_dir = require_groth16_artifacts().map_err(|_| WorkerError::message(WorkerError::Rejected(Failure::Artifact)))?;
    let artifact_base = artifact_dir.parent().ok_or(WorkerError::message(WorkerError::Rejected(Failure::Artifact)))?;
    let scratch = Scratch::create(private_temp_dir).map_err(WorkerError::message)?;
    let mut child = ProcessCommand::new(executable);
    child.args(["samechain", "owner-proof-worker", "--operation", operation_name(options.operation)])
        .arg("--elf").arg(options.elf).arg("--elf-sha256").arg(options.elf_sha256)
        .arg("--deployment").arg(options.deployment).arg("--program-vkey").arg(options.program_vkey)
        .arg("--groth16-artifact-dir").arg(&artifact_dir);
    if let Some(packet) = options.packet { child.arg("--packet").arg(packet); }
    private_command(&mut child, &scratch.path, Some(artifact_base));
    let mut worker = Worker::spawn(child, scratch, timeout, transport_deadline)
        .map_err(WorkerError::message)?;
    let certificate = worker.exchange(options.operation, bytes, journal.len());
    worker.finish().map_err(WorkerError::message)?;
    let certificate = certificate.map_err(WorkerError::message)?;
    // Parent expectations are never supplied by the child certificate. This is
    // the frozen SHA-only five-input pairing, not the SDK's permissive verifier.
    verify_owner_certificate(&certificate, program, journal)
        .map_err(|_| WorkerError::Certificate.message())?;
    Ok(certificate)
}

fn certificate_export(binding: &release::ReleaseBinding, certificate: &OwnerCertificate)
    -> Result<Vec<u8>, String>
{
    let expected = binding.deployment;
    let operation = match binding.operation {
        backup::SnapshotOperation::Fill => "fill", backup::SnapshotOperation::Cancel => "cancel",
        backup::SnapshotOperation::Exit => "exit", backup::SnapshotOperation::Withdrawal => "withdrawal",
        backup::SnapshotOperation::Creation => "creation",
    };
    let export = CertificateExport {
        kind: "samechain_owner_certificate", operation,
        expected_deployment: InspectionDeployment {
            chain_id: expected.chain_id.to_string(), authority: public_hex(&expected.authority),
            authority_code: public_hex(&expected.authority_code), verifier: public_hex(&expected.verifier),
            verifier_code: public_hex(&expected.verifier_code), owner_program: public_hex(&expected.owner_program),
            schema: expected.schema,
        },
        program_vkey: public_hex(&binding.program_vkey),
        journal: public_hex(&certificate.journal), proof: public_hex(&certificate.proof_bytes),
        proof_certificate: true,
        sdk_storage_boundary: "UNQUALIFIED_EXTERNAL_DEV_SHM_RAII_RETENTION",
        program_identity: "independently_pinned_SHA_Groth16", root_eligibility: "UNVERIFIED",
        global_unspentness: "UNVERIFIED", asset_backing: "UNVERIFIED", finality: "UNVERIFIED",
        deployment_profile_qualification: "UNVERIFIED", financial_execution: false,
        strict_matching_privacy: false,
    };
    let mut output = serde_json::to_vec(&export).map_err(|_| "samechain public export rejected".to_owned())?;
    output.push(b'\n');
    Ok(output)
}

fn read_binding(path: &Path, op_id: [u8; 32]) -> Result<release::ReleaseBinding, String> {
    const MAX_HEX: usize = 2 + 2 * 4096 + 1;
    let mut encoded = vec![0; MAX_HEX + 1];
    let mut file = File::open(path).map_err(|_| "samechain release binding unavailable")?;
    let mut length = 0;
    while length < encoded.len() {
        let count = file.read(&mut encoded[length..]).map_err(|_| "samechain release binding unavailable")?;
        if count == 0 { break; }
        length += count;
    }
    if length > MAX_HEX { return Err("samechain release binding exceeds size limit".into()); }
    let text = encoded[..length].strip_suffix(b"\n").unwrap_or(&encoded[..length]);
    let hex = text.strip_prefix(b"0x").filter(|bytes| !bytes.is_empty() && bytes.len() % 2 == 0)
        .ok_or("invalid samechain release binding")?;
    if hex.len() > 2 * 4096 { return Err("samechain release binding exceeds size limit".into()); }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_chunks::<2>().0 {
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'), b'a'..=b'f' => Some(byte - b'a' + 10), _ => None,
        };
        bytes.push(digit(pair[0]).and_then(|high| digit(pair[1]).map(|low| high * 16 + low))
            .ok_or("invalid samechain release binding")?);
    }
    let binding = release::ReleaseBinding::decode(&bytes).map_err(|error| error.to_string())?;
    if binding.op_id != op_id || binding.encode().map_err(|error| error.to_string())? != bytes {
        return Err("samechain release binding mismatch".into());
    }
    Ok(binding)
}

#[derive(Serialize)]
struct ReleaseExport {
    kind: &'static str,
    op_id: String,
    binding: String,
    binding_digest: String,
    release_digest: String,
    capsule: String,
}

fn capsule_name(op_id: &[u8; 32]) -> String {
    let mut name = public_hex(op_id);
    name.drain(..2);
    name.push_str(".release");
    name
}

struct ReleaseOptions {
    op_id: [u8; 32],
    directory: File,
    release_dir: PathBuf,
    key: File,
}

fn release_key(file: &mut File) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0; 32]);
    file.read_exact(&mut key[..]).map_err(|_| "samechain backup key unavailable")?;
    let mut excess = Zeroizing::new([0; 1]);
    if file.read(&mut excess[..]).map_err(|_| "samechain backup key unavailable")? != 0 {
        return Err("invalid samechain backup key length".into());
    }
    Ok(key)
}

fn prove_release(command: &super::Command, mut selected: ReleaseOptions, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let options = options(command).ok_or("invalid samechain command arguments")?;
    let prepared = prepare(&options, bytes).map_err(|error| error.message)?;
    let binding = release_binding(&prepared, selected.op_id)?;
    let Prepared { owned, elf, program, journal, .. } = prepared;
    // Drop typed private witnesses and unused ELF before prover work; the
    // original stdin frame remains guarded for the child request.
    drop(owned);
    drop(elf);
    let certificate = produce(command, bytes, &program, &journal)?;
    let key = release_key(&mut selected.key)?;
    let capsule = capsule_name(&binding.op_id);
    let release = release::save_release(selected.release_dir.join(&capsule), &key, binding.op_id, &binding, &certificate)
        .map_err(|error| error.to_string())?;
    let export = ReleaseExport { kind: "samechain_owner_capsule", op_id: public_hex(&binding.op_id),
        binding: public_hex(&binding.encode().map_err(|error| error.to_string())?),
        binding_digest: public_hex(&binding.digest().map_err(|error| error.to_string())?.0),
        release_digest: public_hex(&release.0), capsule };
    // Local immutable custody only: no database access or plaintext certificate output.
    let mut output = serde_json::to_vec(&export).map_err(|_| "samechain public export rejected")?;
    output.push(b'\n');
    drop(selected.directory);
    Ok(output)
}

fn export_release(binding_path: &Path, config: crate::database::DatabaseConfig, mut selected: ReleaseOptions) -> Result<Vec<u8>, String> {
    let binding = read_binding(binding_path, selected.op_id)?;
    let path = selected.release_dir.join(capsule_name(&selected.op_id));
    let digest = release::capsule_digest(&path).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(|_| "samechain release journal runtime unavailable")?;
    let database = runtime.block_on(journal::ReleaseJournal::connect(config))
        .map_err(|error| error.to_string())?;
    let version = runtime.block_on(database.authorize(&binding)).map_err(|error| error.to_string())?;
    runtime.block_on(database.commit_release(&binding, version, digest)).map_err(|error| error.to_string())?;
    let committed = runtime.block_on(database.read_release(&binding)).map_err(|error| error.to_string())?;
    // Only a matching committed row permits consuming the backup capability.
    // load_release authenticates the selected binding and this row's file digest.
    let key = release_key(&mut selected.key)?;
    let certificate = release::load_release(&path, &key, selected.op_id, &binding,
        committed.release_digest()).map_err(|error| error.to_string())?;
    let output = certificate_export(&binding, &certificate)?;
    drop(selected.directory);
    Ok(output)
}

pub(super) fn release_command(command: &super::Command) -> ExitCode {
    let (op_id, release_dir, backup_key_file) = match command {
        super::Command::ProveOwner { op_id, release_dir, backup_key_file, .. }
        | super::Command::ExportCertificate { op_id, release_dir, backup_key_file, .. } =>
            (*op_id, release_dir, backup_key_file),
        _ => return ExitCode::from(2),
    };
    let key = match crate::custody::trusted_backup_key_file(backup_key_file) {
        Ok(key) => key,
        Err(error) => return print_result(Err(error.to_string())),
    };
    let (directory, release_dir) = match crate::custody::trusted_private_directory(release_dir) {
        Ok(selected) => selected,
        Err(error) => return print_result(Err(error.to_string())),
    };
    let result = (|| -> Result<Vec<u8>, String> {
        let selected = ReleaseOptions { op_id, directory, release_dir, key };
        match command {
            super::Command::ProveOwner { .. } => {
                let (bytes, length) = read_private_input()?;
                prove_release(command, selected, &bytes[..length])
            }
            super::Command::ExportCertificate { binding, database_config, .. } => {
                let invalid_config = || crate::database::DatabaseError::InvalidConfig.to_string();
                let bytes = crate::market::config::read_bytes(database_config, 16 * 1024).map_err(|_| invalid_config())?;
                let config: crate::database::DatabaseConfig = serde_json::from_slice(&bytes).map_err(|_| invalid_config())?;
                config.validate().map_err(|error| error.to_string())?;
                if std::env::var_os(&config.uri_env).is_none() {
                    return Err(crate::database::DatabaseError::MissingUri.to_string());
                }
                export_release(binding, config, selected)
            }
            _ => Err("invalid samechain command arguments".into()),
        }
    })();
    print_result(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    const SECRET: &[u8] = b"test-only-private-transport-sentinel";

    fn root() -> tempfile::TempDir {
        tempfile::Builder::new().permissions(fs::Permissions::from_mode(0o700)).tempdir().unwrap()
    }

    fn fixture(mode: &str) -> ProcessCommand {
        let mut command = ProcessCommand::new(std::env::current_exe().unwrap());
        command.args(["--exact", "samechain::owner_worker::tests::hostile_child", "--ignored", "--nocapture"])
            .env("Z2Z_TEST_CHILD", mode);
        command
    }

    fn launch(mode: &str, root: &Path, timeout: Duration) -> Worker {
        let scratch = Scratch::create(root).unwrap();
        let mut command = fixture(mode);
        let path = scratch.path.clone();
        // The fixture-specific selector is test-only, never a production flag.
        private_command(&mut command, &path, Some(root));
        command.env("Z2Z_TEST_CHILD", mode);
        Worker::spawn(command, scratch, timeout, Instant::now() + timeout).unwrap()
    }
    #[test]
    #[ignore = "invoked only as a real child isolation-check subprocess"]
    fn isolation_child() {
        if child_isolation().is_ok() { std::process::exit(9); }
        // Reading even a byte is forbidden: the test parent keeps the request
        // endpoint open and sends no data on deliberately invalid isolation.
        std::process::exit(0);
    }

    #[test]
    fn child_rejects_nonnull_diagnostics_missing_scratch_and_nonsocket_stdin() {
        for mode in 0..4 {
            let root = root();
            let mut command = ProcessCommand::new(std::env::current_exe().unwrap());
            command.args(["--exact", "samechain::owner_worker::tests::isolation_child", "--ignored", "--nocapture"]);
            private_command(&mut command, root.path(), Some(root.path()));
            let (parent, child) = UnixStream::pair().unwrap();
            if mode == 0 { command.stdin(Stdio::null()); } else {
                let fd: OwnedFd = child.into();
                command.stdin(Stdio::from(fd));
            }
            if mode == 1 { command.stdout(Stdio::piped()); }
            if mode == 2 { command.stderr(Stdio::piped()); }
            if mode == 3 { command.env_remove("TMPDIR"); }
            let mut child = command.spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            let result = (|| -> Result<_, WorkerError> {
                loop {
                    if let Some(status) = child.try_wait().map_err(|_| WorkerError::ReapPolicy)? {
                        return Ok(status);
                    }
                    pause(deadline)?;
                }
            })();
            if result.is_err() { let _ = child.kill(); }
            let reaped = child.wait();
            assert_eq!(result.unwrap().code(), Some(0));
            assert!(reaped.unwrap().success());
            drop(parent);
        }
    }

    struct HostileLogger;

    impl log::Log for HostileLogger {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool { true }
        fn log(&self, _: &log::Record<'_>) { panic!("test-only hostile logger invoked"); }
        fn flush(&self) {}
    }

    static HOSTILE_LOGGER: HostileLogger = HostileLogger;

    #[test]
    #[ignore = "invoked only as a fresh process-global diagnostic-policy subprocess"]
    fn diagnostic_policy_child() {
        let mode = std::env::var("Z2Z_TEST_DIAGNOSTIC_POLICY").unwrap();
        let _scoped_subscriber = if mode == "scoped" {
            Some(tracing::subscriber::set_default(
                tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).finish(),
            ))
        } else { None };
        match mode.as_str() {
            "subscriber" => {
                tracing::subscriber::set_global_default(
                    tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).finish(),
                ).unwrap();
            }
            "logger" => {
                log::set_logger(&HOSTILE_LOGGER).unwrap();
                log::set_max_level(log::LevelFilter::Trace);
            }
            "fresh" | "scoped" => {},
            _ => panic!("unknown test-only diagnostic policy"),
        }
        if matches!(mode.as_str(), "subscriber" | "scoped") {
            assert!(tracing::enabled!(tracing::Level::ERROR));
        }
        if mode == "logger" {
            assert!(log::log_enabled!(log::Level::Error));
        }
        if mode != "fresh" {
            match child_isolation() {
                Err(WorkerError::Certificate) => std::process::exit(0),
                Err(_) => std::process::exit(8),
                Ok((mut stream, _scratch)) => {
                    // Parent sends nothing and holds its endpoint open. If the
                    // occupied registry was ignored, this private read blocks.
                    let _ = read_request(&mut stream, SimulationOperation::Creation);
                    std::process::exit(9);
                }
            }
        }
        let (mut stream, _scratch) = child_isolation().unwrap();
        assert!(tracing::subscriber::set_global_default(
            tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).finish(),
        ).is_err());
        assert!(log::set_logger(&HOSTILE_LOGGER).is_err());
        assert_eq!(log::max_level(), log::LevelFilter::Off);
        std::thread::spawn(|| {
            assert!(!tracing::enabled!(tracing::Level::ERROR));
            assert!(!tracing::enabled!(tracing::Level::TRACE));
            tracing::error!("test-only diagnostic sentinel");
            log::error!("test-only diagnostic sentinel");
            // The null logger must also discard direct calls and a caller's
            // later max-level change, not merely rely on the initial OFF cap.
            log::set_max_level(log::LevelFilter::Trace);
            assert!(!log::logger().enabled(
                &log::Metadata::builder().level(log::Level::Error).target("test-only").build(),
            ));
            log::logger().log(&log::Record::builder()
                .args(format_args!("test-only diagnostic sentinel"))
                .level(log::Level::Error).target("test-only").build());
            log::error!("test-only diagnostic sentinel");
            log::set_max_level(log::LevelFilter::Off);
        }).join().unwrap();
        assert!(matches!(child_isolation(), Err(WorkerError::Certificate)));
        stream.write_all(b"diagnostic-policy-locked").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    }

    fn diagnostic_policy_process(mode: &str) {
        // Removing either global installation, ignoring its error, or moving
        // the lock after read_request breaks these real socket subprocesses.
        let directory = root();
        let mut command = ProcessCommand::new(std::env::current_exe().unwrap());
        command.args(["--exact", "samechain::owner_worker::tests::diagnostic_policy_child", "--ignored", "--nocapture"]);
        private_command(&mut command, directory.path(), Some(directory.path()));
        command.env("Z2Z_TEST_DIAGNOSTIC_POLICY", mode);
        let (mut parent, child_socket) = UnixStream::pair().unwrap();
        parent.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let fd: OwnedFd = child_socket.into();
        command.stdin(Stdio::from(fd));
        let mut child = command.spawn().unwrap();
        drop(command);
        // Never send a header, frame, witness or EOF to the child.
        let mut response = Vec::new();
        let received = parent.read_to_end(&mut response);
        let deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() { break status; }
            if received.is_err() || pause(deadline).is_err() {
                child.kill().unwrap();
                let _ = child.wait().unwrap();
                panic!("diagnostic policy did not finish without private input: {mode}");
            }
        };
        received.unwrap();
        assert!(status.success(), "diagnostic policy rejected the wrong boundary: {mode}");
        if mode == "fresh" { assert_eq!(response, b"diagnostic-policy-locked"); }
        else { assert!(response.is_empty()); }
        assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
    }

    #[test]
    fn diagnostic_policy_locks_fresh_children_before_input() {
        for _ in 0..2 { diagnostic_policy_process("fresh"); }
    }

    #[test]
    fn diagnostic_policy_rejects_global_subscriber_before_input() {
        diagnostic_policy_process("subscriber");
    }

    #[test]
    fn diagnostic_policy_rejects_scoped_subscriber_before_input() {
        diagnostic_policy_process("scoped");
    }

    #[test]
    fn diagnostic_policy_rejects_global_logger_before_input() {
        diagnostic_policy_process("logger");
    }

    fn request(stream: &mut UnixStream) {
        let (bytes, length) = read_request(stream, SimulationOperation::Creation).unwrap();
        assert_eq!(&bytes[..length], SECRET);
    }

    fn send_untrusted_frame(stream: &mut UnixStream, suffix: bool) {
        stream.write_all(RESPONSE_MAGIC).unwrap();
        stream.write_all(&[0]).unwrap();
        stream.write_all(&[5; 32]).unwrap();
        stream.write_all(&3u32.to_be_bytes()).unwrap();
        stream.write_all(b"pub").unwrap();
        stream.write_all(&[0; 356]).unwrap();
        if suffix { stream.write_all(b"suffix").unwrap(); }
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    }

    #[test]
    #[ignore = "invoked only as a real hostile subprocess by worker boundary tests"]
    fn hostile_child() {
        let mode = std::env::var("Z2Z_TEST_CHILD").unwrap();
        let (mut stream, _scratch) = child_isolation().unwrap();
        if mode == "no-read" {
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        request(&mut stream);
        match mode.as_str() {
            "diagnostics" => {
                assert_eq!(fs::read_link("/proc/self/fd/1").unwrap(), Path::new("/dev/null"));
                assert_eq!(fs::read_link("/proc/self/fd/2").unwrap(), Path::new("/dev/null"));
                assert!(std::env::var_os("RUST_LOG").is_none());
                assert!(std::env::var_os("RUST_BACKTRACE").is_none());
                std::io::stdout().write_all(SECRET).unwrap();
                std::io::stderr().write_all(SECRET).unwrap();
                let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).finish();
                tracing::subscriber::with_default(subscriber, || {
                    tracing::debug!("test-only-private-transport-sentinel");
                    tracing::info!("test-only-private-transport-sentinel");
                });
                stream.write_all(b"diagnostics-suppressed").unwrap();
                stream.shutdown(std::net::Shutdown::Write).unwrap();
            }
            "oversized" => {
                stream.write_all(RESPONSE_MAGIC).unwrap();
                stream.write_all(&[0]).unwrap();
                stream.write_all(&[5; 32]).unwrap();
                stream.write_all(&u32::MAX.to_be_bytes()).unwrap();
            }
            "truncated" => { stream.write_all(RESPONSE_MAGIC).unwrap(); }
            "nonzero" => {
                send_untrusted_frame(&mut stream, false);
                std::process::exit(7);
            }
            "suffix" => send_untrusted_frame(&mut stream, true),
            "forged" => send_untrusted_frame(&mut stream, false),
            "no-eof" => {
                stream.write_all(RESPONSE_MAGIC).unwrap();
                stream.write_all(&[1, Failure::Producer as u8]).unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "failure" => {
                let scratch = PathBuf::from(std::env::var_os("TMPDIR").unwrap());
                fs::write(scratch.join("private-witness"), SECRET).unwrap();
                write_failure(&mut stream, Failure::Producer).unwrap();
            }
            "hang" => {
                let scratch = PathBuf::from(std::env::var_os("TMPDIR").unwrap());
                fs::write(scratch.join("private-witness"), SECRET).unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            "late" => {
                std::thread::sleep(Duration::from_millis(1500));
                send_untrusted_frame(&mut stream, false);
            }
            "descendant" => {
                let scratch = std::env::var_os("TMPDIR").unwrap();
                let mut child = ProcessCommand::new(std::env::current_exe().unwrap())
                    .args(["--exact", "samechain::owner_worker::tests::descendant", "--ignored", "--nocapture"])
                    .env("Z2Z_TEST_SCRATCH", &scratch)
                    .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
                let pid = child.id();
                fs::write(PathBuf::from(&scratch).join("descendant-pid"), pid.to_string()).unwrap();
                // Parent termination must kill this group member, not just us.
                let _ = child.wait();
            }
            "stopped-descendant" => {
                let scratch = std::env::var_os("TMPDIR").unwrap();
                let mut child = ProcessCommand::new(std::env::current_exe().unwrap())
                    .args(["--exact", "samechain::owner_worker::tests::descendant", "--ignored", "--nocapture"])
                    .env("Z2Z_TEST_SCRATCH", &scratch)
                    .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
                let pid = Pid::from_child(&child);
                rustix::process::kill_process(pid, Signal::STOP).unwrap();
                fs::write(PathBuf::from(&scratch).join("descendant-pid"), child.id().to_string()).unwrap();
                let _ = child.wait();
            }
            _ => panic!("unknown test-only fixture"),
        }
    }



    #[test]
    #[ignore = "invoked only as a real descendant by worker boundary tests"]
    fn descendant() {
        let path = PathBuf::from(std::env::var_os("Z2Z_TEST_SCRATCH").unwrap()).join("descendant-private-witness");
        loop {
            fs::write(&path, SECRET).unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn null_diagnostics_and_hostile_result_frames_are_closed_failures() {
        // Removing the fd sinks, length/EOF/status checks, or independent verifier breaks this.
        for mode in ["diagnostics", "oversized", "truncated", "nonzero", "suffix", "forged", "no-eof", "failure", "hang", "late"] {
            let directory = root();
            fs::write(directory.path().join("unrelated"), b"retained-owner-file").unwrap();
            let mut worker = launch(mode, directory.path(), Duration::from_secs(1));
            let result = worker.exchange(SimulationOperation::Creation, SECRET, 3);
            let cleanup = worker.finish();
            match (mode, result) {
                ("forged", Ok(certificate)) =>
                    assert!(verify_owner_certificate(&certificate, &[5; 32], b"pub").is_err()),
                ("forged", Err(_)) => panic!("forged fixture never reached the independent verifier"),
                (_, Err(_)) => {},
                (_, Ok(_)) => panic!("hostile transport frame accepted"),
            }
            assert!(cleanup.is_ok(), "ordinary child cleanup failed");
            assert_eq!(fs::read(directory.path().join("unrelated")).unwrap(), b"retained-owner-file");
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn timeout_terminates_descendants_or_retains_private_scratch() {
        // Leader-only reap or deleting before whole-group disappearance breaks this.
        for mode in ["descendant", "stopped-descendant"] {
            let directory = root();
            let mut worker = launch(mode, directory.path(), Duration::from_secs(1));
            let path = worker.scratch.as_ref().unwrap().path.clone();
            assert!(worker.exchange(SimulationOperation::Creation, SECRET, 3).is_err());
            let descendant = fs::read_to_string(path.join("descendant-pid")).unwrap().parse::<i32>().unwrap();
            let cleanup = worker.finish();
            match cleanup {
                Ok(()) => assert!(!path.exists()),
                Err(WorkerError::CleanupRetained) => {
                    assert!(path.exists());
                    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o700);
                }
                other => panic!("unexpected cleanup outcome: {other:?}"),
            }
            let status = fs::read_to_string(format!("/proc/{descendant}/stat"));
            if let Ok(status) = status {
                // A retained zombie cannot write, but signal0 still sees it and
                // production must not pretend that absence was established.
                let fields = status.rsplit_once(')').unwrap().1.trim_start();
                assert!(matches!(fields.as_bytes()[0], b'Z' | b'X'));
                assert!(cleanup.is_err());
            } else {
                assert!(!fs::exists(format!("/proc/{descendant}")).unwrap());
            }
        }
    }

    #[test]
    fn terminal_unreaped_leader_reaps_before_post_reap_group_probe() {
        let directory = root();
        let mut worker = launch("failure", directory.path(), Duration::from_secs(1));
        assert!(worker.exchange(SimulationOperation::Creation, SECRET, 3).is_err());
        loop {
            if worker.observe().unwrap().is_some() { break; }
            pause(worker.deadline).unwrap();
        }
        assert!(matches!(worker.leader, LeaderState::TerminalUnreaped(_)));
        let cleanup = worker.finish();
        assert!(cleanup.is_ok() || cleanup == Err(WorkerError::CleanupRetained));
        assert!(matches!(worker.leader, LeaderState::LostReapOwnership));
    }

    #[test]
    fn absolute_deadline_also_bounds_a_child_that_never_reads_the_request() {
        let directory = root();
        let mut worker = launch("no-read", directory.path(), Duration::from_secs(1));
        let bytes = Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES]);
        assert!(matches!(worker.exchange(SimulationOperation::Creation, &bytes, 3), Err(WorkerError::Deadline)));
        assert_eq!(worker.finish(), Ok(()));
        assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
    }

    #[test]
    fn drop_cleans_normal_worker_without_panicking_on_unwind() {
        let directory = root();
        let result = std::panic::catch_unwind(|| {
            let mut worker = launch("failure", directory.path(), Duration::from_secs(1));
            assert!(worker.exchange(SimulationOperation::Creation, SECRET, 3).is_err());
            panic!("test-only unwind");
        });
        assert!(result.is_err());
        assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
    }

    #[test]
    fn scratch_cleanup_never_follows_symlinks_and_retains_unknown_entries() {
        let directory = root();
        let mut scratch = Scratch::create(directory.path()).unwrap();
        let path = scratch.path.clone();
        let outside = directory.path().join("unrelated");
        fs::write(&outside, SECRET).unwrap();
        std::os::unix::fs::symlink(&outside, path.join("link")).unwrap();
        assert!(scratch.cleanup(Instant::now() + Duration::from_secs(1)).is_ok());
        assert_eq!(fs::read(&outside).unwrap(), SECRET);
        assert!(!path.exists());
        let mut scratch = Scratch::create(directory.path()).unwrap();
        let path = scratch.path.clone();
        fs::create_dir(path.join("unexpected-subdirectory")).unwrap();
        assert_eq!(scratch.cleanup(Instant::now() + Duration::from_secs(1)), Err(WorkerError::CleanupRetained));
        assert!(path.exists());
    }

    #[test]
    fn private_root_rejects_wrong_mode_symlinks_and_untrusted_ancestors() {
        let directory = root();
        for mode in [0o755, 0o770, 0o1777] {
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(mode)).unwrap();
            assert!(Scratch::create(directory.path()).is_err());
            assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
        }
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let link = directory.path().join("root-link");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        assert!(Scratch::create(&link).is_err());
        let ancestor = directory.path().join("hostile");
        fs::create_dir(&ancestor).unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o777)).unwrap();
        let child = ancestor.join("private");
        fs::create_dir(&child).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Scratch::create(&child).is_err());
        assert!(Scratch::create(&directory.path().join("missing")).is_err());
        assert!(Scratch::create(&directory.path().join("..")).is_err());
    }

    #[test]
    fn request_rejects_wrong_operation_oversize_truncation_and_suffix() {
        for mode in 0..4 {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            sender.write_all(REQUEST_MAGIC).unwrap();
            sender.write_all(&[if mode == 0 { operation_code(SimulationOperation::Fill) } else { operation_code(SimulationOperation::Creation) }]).unwrap();
            sender.write_all(&(if mode == 1 { u32::MAX } else { 1 }).to_be_bytes()).unwrap();
            if mode != 2 { sender.write_all(b"x").unwrap(); }
            if mode == 3 { sender.write_all(b"suffix").unwrap(); }
            sender.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(read_request(&mut receiver, SimulationOperation::Creation).is_err());
        }
    }
}
