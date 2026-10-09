//! Pinned local SP1/Groth16 artifacts for sender and samechain owner relations.
//! This module cannot construct a verified financial settlement fact.

#[path = "../methods/sender/src/relation.rs"]
pub mod sender_relation;

/// Borrowed native preflight and exact private ABI for the four owner guest modes.
/// Framing alone is not semantic approval, a proof or a funded settlement fact.
pub mod owner {
    use crate::samechain::{
        CancelExitWitness, OwnerWitness, RelationError, MAX_PRIVATE_INPUT_BYTES,
        verify_cancel_exit_relation, verify_owner_relation,
        creation::{NoteCreationWitness, verify_note_creation_relation},
        withdrawal::{NoteWithdrawalWitness, verify_note_withdrawal_relation},
    };
    use zeroize::Zeroizing;
    use ziquid_protocol::samechain::Deployment;

    pub enum OwnerInput<'a> {
        Fill(&'a OwnerWitness),
        CancelExit(&'a CancelExitWitness),
        Withdrawal(&'a NoteWithdrawalWitness),
        Creation(&'a NoteCreationWitness),
    }

    impl OwnerInput<'_> {
        /// Evaluate the actual signed native predicate, not merely its shape.
        pub fn expected_journal(&self) -> Result<Vec<u8>, RelationError> {
            Ok(match self {
                Self::Fill(witness) => verify_owner_relation(&witness.packet, witness)?.encode()?,
                Self::CancelExit(witness) => verify_cancel_exit_relation(witness)?.encode()?,
                Self::Withdrawal(witness) => verify_note_withdrawal_relation(witness)?.encode()?,
                Self::Creation(witness) => verify_note_creation_relation(witness)?.encode()?,
            })
        }

        pub fn deployment(&self) -> &Deployment {
            match self {
                Self::Fill(witness) => &witness.packet.deployment,
                Self::CancelExit(witness) => &witness.packet.deployment,
                Self::Withdrawal(witness) => &witness.packet.deployment,
                Self::Creation(witness) => &witness.packet.deployment,
            }
        }

        /// Shape-only framing permits actual guest rejection tests to bypass
        /// host preflight. Both private allocations are guarded; the final frame
        /// is fully allocated before any secret append and never grows.
        pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>, RelationError> {
            // Fill already contains its frozen public packet exactly once.
            let (mode, witness) = match self {
                Self::Fill(witness) => (0, witness.encode()?),
                Self::CancelExit(witness) => (1, witness.encode()?),
                Self::Withdrawal(witness) => (2, witness.encode()?),
                Self::Creation(witness) => (3, witness.encode()?),
            };
            if witness.len() > MAX_PRIVATE_INPUT_BYTES {
                return Err(RelationError::ResourceLimit);
            }
            let length = 1usize.checked_add(witness.len()).ok_or(RelationError::ResourceLimit)?;
            let mut frame = Zeroizing::new(Vec::with_capacity(length));
            frame.push(mode);
            frame.extend_from_slice(&witness);
            Ok(frame)
        }
    }
}

/// Resolve the pinned SDK's artifact base without reading or mutating the environment.
/// `home` is the result of `dirs::home_dir`, not the raw `HOME` variable. Requiring
/// nonempty absolute UTF-8 paths prevents SDK fallback or working-directory drift.
/// Errors never include supplied paths.
pub fn groth16_artifact_base(
    explicit: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> std::io::Result<std::path::PathBuf> {
    use std::{io, path::PathBuf};

    let use_home = explicit.is_none();
    let value = explicit
        .or(home)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "home directory not found"))?;
    if value.is_empty() || value.to_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact base must be a nonempty absolute UTF-8 path",
        ));
    }
    let base = PathBuf::from(value);
    if !base.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact base must be a nonempty absolute UTF-8 path",
        ));
    }
    Ok(if use_home {
        base.join(".sp1").join("circuits/groth16")
    } else {
        base
    })
}

#[cfg(any(feature = "sp1-execute", feature = "sp1-local"))]
pub type QualificationResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Reject upstream modes that can export private witness/trace bytes or weaken
/// verification. Only variable names are included in errors, never their values.
#[cfg(any(feature = "sp1-execute", feature = "sp1-local"))]
pub fn check_private_environment() -> QualificationResult<()> {
    use std::{env, io};
    for name in [
        "SP1_DUMP",
        "TRACE_FILE",
        "DUMP_ELF_OUTPUT",
        "SP1_RECORD_WRITE_DIR",
        "SP1_RECORD_MAX_ARITY_INPUT",
        "SP1_RECORD_SHRINK_INPUT",
        "WITHOUT_VK_VERIFICATION",
        "SP1_SKIP_PROGRAM_BUILD",
        "SP1_CORE_RUNNER_OVERRIDE_BINARY",
    ] {
        if env::var_os(name).is_some() {
            return Err(io::Error::other(format!(
                "unset unsafe proof environment variable {name}"
            ))
            .into());
        }
    }
    for (name, expected) in [("SP1_PROVER", "cpu"), ("SP1_CIRCUIT_MODE", "release")] {
        if let Some(value) = env::var_os(name)
            && value != expected
        {
            return Err(io::Error::other(format!("{name} must be {expected} or unset")).into());
        }
    }
    Ok(())
}

/// Executes the actual RISC-V guest with no tracing/debugging and no proof workers,
/// Gnark, Docker or artifact installation. A successful execution is NOT a proof.
#[cfg(feature = "sp1-execute")]
pub mod execution {
    use super::{QualificationResult, check_private_environment, sender_relation::SenderWitness};
    use sp1_core_executor::{MinimalExecutorEnum, OutputConsumers, Program, with_output_consumers};
    use sp1_primitives::Elf;
    use std::{io, sync::Arc};
    use tokio::sync::watch;
    use zeroize::Zeroize;

    // Receivers must stay alive or upstream falls back to host stderr. Only the
    // final bounded channel snapshots are wiped; upstream guest/input buffers
    // and earlier snapshot allocations are not guaranteed to be erased.
    struct PrivateGuestOutput {
        consumers: OutputConsumers,
        _receivers: [watch::Receiver<String>; 2],
    }

    impl PrivateGuestOutput {
        fn new() -> Self {
            let (stdout, stdout_receiver) = watch::channel(String::new());
            let (stderr, stderr_receiver) = watch::channel(String::new());
            Self {
                consumers: OutputConsumers { stdout: Some(stdout), stderr: Some(stderr) },
                _receivers: [stdout_receiver, stderr_receiver],
            }
        }
    }

    impl Drop for PrivateGuestOutput {
        fn drop(&mut self) {
            for sender in [&self.consumers.stdout, &self.consumers.stderr].into_iter().flatten() {
                sender.send_modify(|snapshot| snapshot.zeroize());
            }
        }
    }

    pub struct GuestExecution {
        pub journal: Vec<u8>,
        pub exit_code: u32,
        pub instructions: u64,
    }

    pub fn execute_private(elf: Elf, private_input: &[u8]) -> QualificationResult<GuestExecution> {
        check_private_environment()?;
        let program = Program::from(&elf).map_err(|_| io::Error::other("invalid SP1 guest ELF"))?;
        let output = PrivateGuestOutput::new();
        // The upstream TLS guard restores prior consumers on return/error/unwind
        // before `output` drops and wipes our final snapshots. The resolved SP1
        // graph must keep profiling disabled: its cycle tracker bypasses sinks.
        with_output_consumers(&output.consumers, || {
            let mut executor = MinimalExecutorEnum::new(Arc::new(program), false, None);
            executor.with_input(private_input);
            // With tracing disabled the native executor returns None after its one full
            // run. Portable execution can return chunks. Always require an actual halt.
            while executor.try_execute_chunk()?.is_some() {}
            if !executor.is_done() {
                return Err(io::Error::other("SP1 guest did not halt").into());
            }
            let exit_code = executor.exit_code();
            let instructions = executor.global_clk();
            Ok(GuestExecution {
                journal: executor.into_public_values_stream(),
                exit_code,
                instructions,
            })
        })
    }

    pub fn execute_sender(
        elf: Elf,
        witness: &SenderWitness,
    ) -> QualificationResult<GuestExecution> {
        let expected = super::sender_relation::verify_sender(witness)?;
        let result = execute_private(elf, &witness.encode_private())?;
        if result.exit_code != 0 || result.journal != expected {
            return Err(
                io::Error::other("guest execution differs from sender reference relation").into(),
            );
        }
        Ok(result)
    }

    /// Execute the real guest after signed native preflight; CPU execution is
    /// not a proof. The upstream executor copies stdin into its own buffers.
    pub fn execute_owner(
        elf: Elf,
        input: &super::owner::OwnerInput<'_>,
    ) -> QualificationResult<GuestExecution> {
        check_private_environment()?;
        let expected = input.expected_journal()?;
        let frame = input.encode_private()?;
        let result = execute_private(elf, &frame)?;
        if result.exit_code != 0 || result.journal != expected {
            return Err(io::Error::other("guest execution differs from owner reference relation").into());
        }
        Ok(result)
    }
}

/// Actual local SP1 APIs; no environment-selected, mock, remote or TEE prover.
#[cfg(feature = "sp1-local")]
pub mod local {
    use super::sender_relation::{JOURNAL_LEN, SenderWitness, verify_sender};
    use sha2::{Digest, Sha256};
    use sp1_sdk::{
        Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1_CIRCUIT_VERSION,
        SP1Proof, SP1Stdin,
    };
    use std::{env, error::Error, fs::File, io::{self, Read}, path::{Component, Path, PathBuf}};
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    pub const SDK_REVISION: &str = "c84ada1ed5911f28c4d3c9d0ed2f9e6cd7edb824";
    pub const CONTRACT_REVISION: &str = "d3629729c3216eb51bd4859d027a8eb729399fa4";
    pub const CIRCUIT_VERSION: &str = "v6.1.0";
    // Retained local acquisition manifest digests. These establish reproducibility
    // against the retained archive, not independent release provenance or ceremony.
    const GROTH16_CIRCUIT_BYTES: u64 = 2_437_991_441;
    const GROTH16_PK_BYTES: u64 = 5_862_173_061;
    const GROTH16_VK_BYTES_LEN: u64 = 492;
    const GROTH16_CIRCUIT_SHA256: [u8; 32] = [
        0xd6, 0xa6, 0x6b, 0xe2, 0x70, 0x22, 0x06, 0xe2, 0xb1, 0xa2, 0x0b, 0xeb, 0xf7, 0x09, 0x61, 0x42,
        0x86, 0x4f, 0xea, 0xc9, 0xe3, 0x99, 0xa3, 0x09, 0xe5, 0xe6, 0xe0, 0x03, 0x53, 0x26, 0x4c, 0xbc,
    ];
    const GROTH16_PK_SHA256: [u8; 32] = [
        0xc3, 0x76, 0x0e, 0x0e, 0x3b, 0x58, 0x48, 0x7f, 0x87, 0x04, 0x68, 0x0d, 0x5b, 0x3a, 0xd3, 0x2a,
        0x9f, 0xbc, 0xa9, 0xf3, 0xcb, 0x07, 0x49, 0xd6, 0x90, 0x55, 0xc4, 0xf1, 0x27, 0x1c, 0xa1, 0x67,
    ];
    pub const GROTH16_VK_SHA256: [u8; 32] = [
        0x43, 0x88, 0xa2, 0x1c, 0x68, 0x7f, 0xdd, 0x5f, 0x21, 0x8d, 0x7e, 0x3d, 0x13, 0x19, 0x0c,
        0xac, 0x4c, 0x53, 0x55, 0x81, 0x8d, 0x36, 0x05, 0xfd, 0x5f, 0xb8, 0x11, 0xdf, 0x46, 0x8e,
        0xe6, 0x96,
    ];

    pub type LocalResult<T> = super::QualificationResult<T>;

    /// Contains only wrapped ZK proof bytes and the agreed public journal, never a
    /// Core/Compressed STARK or the private witness. Not a settlement certificate.
    pub struct SenderCertificate {
        pub program_vkey: String,
        pub journal: [u8; JOURNAL_LEN],
        pub proof_bytes: Vec<u8>,
    }

    /// Only the public exact journal and final wrapped ZK bytes leave the prover.
    /// This does not certify funding, root admission, custody or asset transfer.
    pub struct OwnerCertificate {
        pub program_vkey: [u8; 32],
        pub journal: Vec<u8>,
        pub proof_bytes: Vec<u8>,
    }

    const SCALAR_R: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
        0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
    ];

    fn check_owner_program(program: &[u8; 32]) -> LocalResult<()> {
        if *program == [0; 32] || *program >= SCALAR_R {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid independent owner program pin").into());
        }
        Ok(())
    }

    fn invalid(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
        io::Error::other(message.into()).into()
    }

    /// Fail closed on upstream debug switches that can write private inputs/traces,
    /// alter verification, or select developer-generated setup artifacts. Do not log
    /// environment values; a variable may contain a credential or private path.
    pub fn check_local_environment() -> LocalResult<()> {
        super::check_private_environment()?;
        if SP1_CIRCUIT_VERSION != CIRCUIT_VERSION {
            return Err(invalid(
                "SP1 circuit version differs from pinned base verifier",
            ));
        }
        let hash: [u8; 32] = Sha256::digest(*sp1_verifier::GROTH16_VK_BYTES).into();
        if hash != GROTH16_VK_SHA256 {
            return Err(invalid(
                "embedded Groth16 VK differs from immutable base verifier",
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn trusted_directory_metadata(metadata: &std::fs::Metadata, uid: u32, final_dir: bool) -> bool {
        metadata.is_dir()
            && (metadata.uid() == uid || metadata.uid() == 0)
            && (metadata.mode() & 0o022 == 0
                || (metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o1777))
            && (!final_dir || (metadata.uid() == uid && metadata.mode() & 0o7777 == 0o700))
    }

    #[cfg(target_os = "linux")]
    fn open_trusted_directory(path: &Path) -> LocalResult<File> {
        use rustix::fs::{openat, Mode, OFlags};
        if !path.is_absolute() || path.components().any(|component| matches!(component, Component::ParentDir)) {
            return Err(invalid("pinned Groth16 artifact path is unsafe"));
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let mut directory: File = rustix::fs::open("/", flags, Mode::empty())?.into();
        let uid = rustix::process::geteuid().as_raw();
        let check = |file: &File, final_dir: bool| -> LocalResult<()> {
            let metadata = file.metadata()?;
            if !trusted_directory_metadata(&metadata, uid, final_dir) {
                return Err(invalid("pinned Groth16 artifact directory is not owner-controlled"));
            }
            Ok(())
        };
        check(&directory, false)?;
        for component in path.components() {
            let Component::Normal(name) = component else { continue };
            directory = File::from(openat(&directory, name, flags, Mode::empty())?);
            check(&directory, false)?;
        }
        check(&directory, true)?;
        Ok(directory)
    }

    #[cfg(not(target_os = "linux"))]
    fn open_trusted_directory(_: &Path) -> LocalResult<File> {
        Err(invalid("pinned Groth16 artifact custody is unsupported on this platform"))
    }

    #[cfg(target_os = "linux")]
    fn hash_artifact(directory: &File, name: &str, expected_len: u64, expected_hash: [u8; 32]) -> LocalResult<()> {
        use rustix::fs::{openat, Mode, OFlags};
        let file: File = File::from(openat(directory, name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty())?);
        let before = file.metadata()?;
        if !before.is_file()
            || before.nlink() != 1 || before.uid() != rustix::process::geteuid().as_raw()
            || before.mode() & 0o7777 != 0o600
        {
            return Err(invalid("pinned Groth16 artifact file is not owner-private"));
        }
        let mut file = file;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        let limit = expected_len.checked_add(1)
            .ok_or_else(|| invalid("pinned Groth16 artifact length overflow"))?;
        {
            let mut bounded = (&mut file).take(limit);
            loop {
                let count = bounded.read(&mut buffer)?;
                if count == 0 { break; }
                total = total.checked_add(count as u64)
                    .ok_or_else(|| invalid("pinned Groth16 artifact length overflow"))?;
                hasher.update(&buffer[..count]);
            }
        }
        let after = file.metadata()?;
        if after.len() != before.len() || after.nlink() != before.nlink()
            || after.uid() != before.uid() || after.mode() != before.mode()
            || after.mtime() != before.mtime() || after.ctime() != before.ctime()
        {
            return Err(invalid("pinned Groth16 artifact changed during hashing"));
        }
        if total != expected_len {
            return Err(invalid("pinned Groth16 artifact length mismatch"));
        }
        if hasher.finalize().as_slice() != expected_hash {
            return Err(invalid("pinned Groth16 artifact digest mismatch"));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn validate_marker(directory: &File) -> LocalResult<()> {
        use rustix::fs::{openat, Mode, OFlags};
        let marker: File = File::from(openat(directory, ".complete",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty())?);
        let metadata = marker.metadata()?;
        if !metadata.is_file() || metadata.len() != 0
            || metadata.nlink() != 1 || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(invalid("pinned Groth16 completion marker is not owner-private"));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn validate_marker(_: &File) -> LocalResult<()> {
        Err(invalid("pinned Groth16 artifact custody is unsupported on this platform"))
    }


    #[cfg(target_os = "linux")]
    fn validate_groth16_directory(directory: PathBuf) -> LocalResult<PathBuf> {
        let directory_fd = open_trusted_directory(&directory)?;
        validate_marker(&directory_fd)?;
        hash_artifact(&directory_fd, "groth16_circuit.bin", GROTH16_CIRCUIT_BYTES, GROTH16_CIRCUIT_SHA256)?;
        hash_artifact(&directory_fd, "groth16_pk.bin", GROTH16_PK_BYTES, GROTH16_PK_SHA256)?;
        hash_artifact(&directory_fd, "groth16_vk.bin", GROTH16_VK_BYTES_LEN, GROTH16_VK_SHA256)?;
        // check_local_environment has already bound the embedded VK bytes to this
        // digest; hashing the opened VK against the same digest establishes equivalence
        // without reopening the path for a second, bare comparison.
        // The SDK later reopens the returned path by name, so this validation is not
        // descriptor-bound or an immutability guarantee after this function returns.
        Ok(directory)
    }

    #[cfg(not(target_os = "linux"))]
    fn validate_groth16_directory(_: PathBuf) -> LocalResult<PathBuf> {
        Err(invalid("pinned Groth16 artifact custody is unsupported on this platform"))
    }

    /// Validate an already-selected version directory without reading environment
    /// variables. The SDK later reopens the returned path by name.
    pub fn require_groth16_artifacts_at(directory: &std::path::Path) -> LocalResult<PathBuf> {
        check_local_environment()?;
        if !directory.is_absolute() || directory.to_str().is_none()
            || directory.file_name().and_then(|name| name.to_str()) != Some(CIRCUIT_VERSION)
        {
            return Err(invalid("invalid pinned Groth16 artifact directory"));
        }
        validate_groth16_directory(directory.to_path_buf())
    }

    /// The SDK would otherwise download a mutable 6.21 GB archive implicitly. The
    /// operator must explicitly acquire, hash, safely extract and retain the official
    /// release artifacts before proving. This function never installs or builds them.
    pub fn require_groth16_artifacts() -> LocalResult<PathBuf> {
        check_local_environment()?;
        // Match pinned sp1-prover's var/dirs::home_dir resolver, but reject
        // non-UTF-8 explicit paths instead of letting the SDK silently fall back.
        let explicit = env::var_os("SP1_GROTH16_CIRCUIT_PATH");
        let home = if explicit.is_none() {
            dirs::home_dir().map(PathBuf::into_os_string)
        } else { None };
        let base = super::groth16_artifact_base(explicit, home)?;
        validate_groth16_directory(base.join(CIRCUIT_VERSION))
    }

    /// Derive the exact public program VKey using the pinned light setup only.
    /// No witness, execution, recursion prover, artifact installation or provenance
    /// qualification is involved. A derived key is not an independent source pin.
    pub async fn owner_program(elf: Elf, expected_elf_sha256: &[u8; 32]) -> LocalResult<[u8; 32]> {
        if *expected_elf_sha256 == [0; 32] {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid owner ELF hash pin").into());
        }
        if <[u8; 32]>::from(Sha256::digest(&*elf)) != *expected_elf_sha256 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "owner ELF hash mismatch").into());
        }
        check_local_environment()?;
        let client = ProverClient::builder().light().build().await;
        let pk = client.setup(elf).await.map_err(|_| invalid("public owner program setup rejected"))?;
        let program = pk.verifying_key().bytes32_raw();
        check_owner_program(&program)?;
        Ok(program)
    }

    /// Native CPU STARK → recursive compression → actual Groth16 wrap. Only the
    /// final ZK artifact leaves this function; local intermediates remain private.
    /// This qualification function derives the guest VKey from the caller's ELF;
    /// self-verification checks cryptographic consistency, not trusted program identity.
    /// Consumers MUST independently pin that VKey before admitting a certificate.
    pub async fn prove_sender(elf: Elf, witness: &SenderWitness) -> LocalResult<SenderCertificate> {
        require_groth16_artifacts()?;
        let expected = verify_sender(witness)?;
        let client = ProverClient::builder().cpu().build().await;
        let pk = client.setup(elf).await?;
        let stdin = SP1Stdin::from(&witness.encode_private());
        let proof = client.prove(&pk, stdin).groth16().await?;
        let SP1Proof::Groth16(groth16) = &proof.proof else {
            return Err(invalid(
                "only a wrapped Groth16 private certificate is accepted",
            ));
        };
        if proof.tee_proof.is_some()
            || proof.sp1_version != CIRCUIT_VERSION
            || groth16.encoded_proof.is_empty()
            || groth16.groth16_vkey_hash != GROTH16_VK_SHA256
            || proof.public_values.as_slice() != expected
        {
            return Err(invalid("unqualified Groth16 certificate"));
        }
        client.verify(&proof, pk.verifying_key(), None)?;
        let certificate = SenderCertificate {
            program_vkey: pk.verifying_key().bytes32(),
            journal: expected,
            proof_bytes: proof.bytes(),
        };
        verify_certificate(&certificate, &certificate.program_vkey, &expected)?;
        Ok(certificate)
    }

    /// Pinned ELF and independently selected program, actual CPU prover, final
    /// Groth16 only. No implicit setup downloads, mock, remote or TEE path.
    /// SDK stdin/prover buffers are not covered by our guarded frame erasure.
    pub async fn prove_owner(
        elf: Elf,
        input: &super::owner::OwnerInput<'_>,
        expected_elf_sha256: &[u8; 32],
        expected_program_vkey: &[u8; 32],
    ) -> LocalResult<OwnerCertificate> {
        check_owner_program(expected_program_vkey)?;
        if *expected_elf_sha256 == [0; 32]
            || input.deployment().owner_program != *expected_program_vkey
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "owner ELF or packet program pin mismatch").into());
        }
        let elf_hash: [u8; 32] = Sha256::digest(&*elf).into();
        if elf_hash != *expected_elf_sha256 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "owner ELF hash mismatch").into());
        }
        let expected = input.expected_journal()?;
        let frame = input.encode_private()?;
        require_groth16_artifacts()?;
        let client = ProverClient::builder().cpu().build().await;
        let pk = client.setup(elf).await?;
        if pk.verifying_key().bytes32_raw() != *expected_program_vkey {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "owner setup program pin mismatch").into());
        }
        let stdin = SP1Stdin::from(frame.as_slice());
        let proof = client.prove(&pk, stdin).groth16().await?;
        let SP1Proof::Groth16(groth16) = &proof.proof else {
            return Err(invalid("only a wrapped Groth16 owner certificate is accepted"));
        };
        if proof.tee_proof.is_some()
            || proof.sp1_version != CIRCUIT_VERSION
            || groth16.encoded_proof.is_empty()
            || groth16.groth16_vkey_hash != GROTH16_VK_SHA256
            || proof.public_values.as_slice() != expected
            || groth16.public_inputs[1] != proof.public_values.hash_bn254().to_string()
        {
            return Err(invalid("unqualified Groth16 owner certificate"));
        }
        client.verify(&proof, pk.verifying_key(), None)?;
        let certificate = OwnerCertificate {
            program_vkey: *expected_program_vkey,
            journal: expected,
            proof_bytes: proof.bytes(),
        };
        verify_owner_certificate(&certificate, expected_program_vkey, &certificate.journal)?;
        Ok(certificate)
    }

    /// Match the frozen Solidity header/scalar checks and SHA-only five-field
    /// pairing. The high-level SDK verifier's Blake3 fallback is not used here.
    pub fn verify_owner_certificate(
        certificate: &OwnerCertificate,
        expected_program_vkey: &[u8; 32],
        expected_journal: &[u8],
    ) -> LocalResult<()> {
        check_owner_program(expected_program_vkey)?;
        if certificate.program_vkey != *expected_program_vkey
            || certificate.journal != expected_journal
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "owner certificate context or program mismatch").into());
        }
        check_local_environment()?;
        let bytes = &certificate.proof_bytes;
        if bytes.len() != 356
            || bytes[..4] != GROTH16_VK_SHA256[..4]
            || bytes[4..36] != [0; 32]
            || bytes[36..68] != *sp1_verifier::VK_ROOT_BYTES
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid wrapped owner certificate header").into());
        }
        let nonce: [u8; 32] = bytes[68..100].try_into().unwrap();
        // Lower-level native Fr parsing reduces modulo R; Solidity rejects it.
        if nonce >= SCALAR_R {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid owner certificate nonce scalar").into());
        }
        sp1_verifier::Groth16Verifier::verify_gnark_proof(
            &bytes[100..],
            &[
                *expected_program_vkey,
                sp1_verifier::hash_public_inputs(expected_journal),
                [0; 32],
                *sp1_verifier::VK_ROOT_BYTES,
                nonce,
            ],
            *sp1_verifier::GROTH16_VK_BYTES,
        ).map_err(|_| invalid("SHA Groth16 pairing verification rejected owner certificate"))
    }

    /// Pairing verification with the actual pinned release VK. The caller must
    /// supply its independently pinned guest VKey and exact expected public journal.
    pub fn verify_certificate(
        certificate: &SenderCertificate,
        expected_program_vkey: &str,
        expected_journal: &[u8; JOURNAL_LEN],
    ) -> LocalResult<()> {
        check_local_environment()?;
        if certificate.program_vkey != expected_program_vkey
            || certificate.journal != *expected_journal
        {
            return Err(invalid("sender certificate context or program mismatch"));
        }
        if certificate.proof_bytes.len() != 356
            || certificate.proof_bytes[..4] != GROTH16_VK_SHA256[..4]
        {
            return Err(invalid(
                "invalid wrapped Groth16 private certificate encoding",
            ));
        }
        sp1_verifier::Groth16Verifier::verify(
            &certificate.proof_bytes,
            &certificate.journal,
            expected_program_vkey,
            *sp1_verifier::GROTH16_VK_BYTES,
        )
        .map_err(|_| invalid("Groth16 pairing verification rejected sender certificate"))
    }
    #[cfg(all(test, target_os = "linux"))]
    mod tests {
        use super::{hash_artifact, open_trusted_directory, trusted_directory_metadata, validate_marker, LocalResult};
        use sha2::{Digest, Sha256};
        use std::{
            fs::{self, DirBuilder, File, OpenOptions},
            io::Write,
            os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
            path::{Path, PathBuf},
            sync::atomic::{AtomicU64, Ordering},
        };

        struct TempTree(PathBuf);

        impl TempTree {
            fn new() -> Self {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                let base = Path::new("/tmp");
                for _ in 0..128 {
                    let path = base.join(format!(
                        "ziquid-proofs-artifacts-{}-{}",
                        std::process::id(),
                        NEXT.fetch_add(1, Ordering::Relaxed),
                    ));
                    let mut builder = DirBuilder::new();
                    builder.mode(0o700);
                    match builder.create(&path) {
                        Ok(()) => return Self(path),
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => panic!("failed to create test directory: {error}"),
                    }
                }
                panic!("failed to choose a unique test directory");
            }

            fn path(&self) -> &Path { &self.0 }
        }

        impl Drop for TempTree {
            fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
        }

        fn private_file(path: &Path, bytes: &[u8]) {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }

        fn replace_file(path: &Path, bytes: &[u8]) {
            let mut file = OpenOptions::new().write(true).truncate(true).open(path).unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }

        fn mode(path: &Path, value: u32) {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(value);
            fs::set_permissions(path, permissions).unwrap();
        }

        fn private_directory(path: &Path) {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(path).unwrap();
        }

        fn hash_result(root: &Path, name: &str, length: u64, digest: [u8; 32]) -> LocalResult<()> {
            let directory = File::open(root).unwrap();
            hash_artifact(&directory, name, length, digest)
        }

        #[test]
        fn hash_artifact_bounds_and_authenticates_small_files() {
            let tree = TempTree::new();
            let artifact = tree.path().join("artifact");
            let digest: [u8; 32] = Sha256::digest([1u8, 2, 3]).into();
            private_file(&artifact, &[1, 2, 3]);
            assert!(hash_result(tree.path(), "artifact", 3, digest).is_ok());

            replace_file(&artifact, &[1, 2, 4]);
            assert!(hash_result(tree.path(), "artifact", 3, digest).is_err());
            replace_file(&artifact, &[1, 2]);
            assert!(hash_result(tree.path(), "artifact", 3, digest).is_err());
            replace_file(&artifact, &[1, 2, 3, 4]);
            assert!(hash_result(tree.path(), "artifact", 3, digest).is_err());
            replace_file(&artifact, &[1, 2, 3]);

            mode(&artifact, 0o644);
            assert!(hash_result(tree.path(), "artifact", 3, digest).is_err());
            mode(&artifact, 0o600);

            let hardlink = tree.path().join("hardlink");
            fs::hard_link(&artifact, &hardlink).unwrap();
            assert!(hash_result(tree.path(), "artifact", 3, digest).is_err());
            fs::remove_file(hardlink).unwrap();

            let symlink = tree.path().join("symlink");
            std::os::unix::fs::symlink(&artifact, &symlink).unwrap();
            assert!(hash_result(tree.path(), "symlink", 3, digest).is_err());
        }

        #[test]
        fn trusted_directory_traversal_checks_each_component_and_final_mode() {
            let tree = TempTree::new();
            let nested = tree.path().join("nested");
            private_directory(&nested);
            assert!(open_trusted_directory(&nested).is_ok());

            let metadata = File::open(&nested).unwrap().metadata().unwrap();
            let uid = rustix::process::geteuid().as_raw();
            assert!(trusted_directory_metadata(&metadata, uid, true));
            assert!(!trusted_directory_metadata(&metadata, uid ^ 1, true));

            let wrong_final = tree.path().join("wrong-final");
            private_directory(&wrong_final);
            mode(&wrong_final, 0o755);
            assert!(open_trusted_directory(&wrong_final).is_err());

            let hostile = tree.path().join("hostile");
            private_directory(&hostile);
            mode(&hostile, 0o777);
            let hostile_final = hostile.join("final");
            private_directory(&hostile_final);
            assert!(open_trusted_directory(&hostile_final).is_err());

            let target = tree.path().join("target");
            private_directory(&target);
            let target_final = target.join("final");
            private_directory(&target_final);
            let link = tree.path().join("ancestor-link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(open_trusted_directory(&link.join("final")).is_err());

            assert!(open_trusted_directory(&tree.path().join("..").join("missing")).is_err());
        }

        #[test]
        fn completion_marker_requires_empty_owner_private_regular_file() {
            let tree = TempTree::new();
            let marker = tree.path().join(".complete");
            let directory = File::open(tree.path()).unwrap();
            private_file(&marker, &[]);
            assert!(validate_marker(&directory).is_ok());

            replace_file(&marker, &[1]);
            assert!(validate_marker(&directory).is_err());
            replace_file(&marker, &[]);
            mode(&marker, 0o644);
            assert!(validate_marker(&directory).is_err());
            mode(&marker, 0o600);

            fs::remove_file(&marker).unwrap();
            let target = tree.path().join("marker-target");
            private_file(&target, &[]);
            std::os::unix::fs::symlink(&target, &marker).unwrap();
            assert!(validate_marker(&directory).is_err());
        }
    }

}
#[cfg(test)]
mod tests {
    use super::sender_relation::{
        JOURNAL_DOMAIN, SenderRelationError, SenderWitness, verify_sender,
    };
    use orchard::{
        Address, Note,
        keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
        note::{ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho},
        note_encryption::{CompactAction, IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use sha2::{Digest, Sha256};
    use zcash_note_encryption::{
        Domain, ENC_CIPHERTEXT_SIZE, EphemeralKeyBytes, ShieldedOutput, try_note_decryption,
    };

    // Publicly chosen, generated cryptographic fixture; not a chain transaction or wallet.
    fn fixture() -> (SenderWitness, PreparedIncomingViewingKey) {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho_bytes = [0; 32];
        let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).unwrap();
        let rseed_bytes = [9; 32];
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho)).unwrap();
        let note = Option::<Note>::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(42_000),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .unwrap();
        let memo = [11; 512];
        let encryptor = IronwoodNoteEncryption::new(None, note, memo);
        let mut witness = SenderWitness {
            context_digest: [12; 32],
            output_commitment: [0; 32],
            secret_blind: [13; 32],
            recipient: recipient.to_raw_address_bytes(),
            value: note.value().inner(),
            rho: rho_bytes,
            rseed: rseed_bytes,
            memo,
            cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
            epk: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
        };
        rebind(&mut witness);
        (
            witness,
            PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)),
        )
    }

    // Rebinding adversarial fields cannot turn incorrect encryption into a valid relation.
    fn rebind(witness: &mut SenderWitness) {
        let mut hash = Sha256::new();
        hash.update(b"ziquid.sender.output.v1");
        hash.update(witness.context_digest);
        hash.update(witness.secret_blind);
        hash.update(witness.recipient);
        hash.update(witness.value.to_le_bytes());
        hash.update(witness.rho);
        hash.update(witness.rseed);
        hash.update(witness.memo);
        hash.update(witness.cmx);
        hash.update(witness.epk);
        hash.update(witness.enc_ciphertext);
        witness.output_commitment = hash.finalize().into();
    }

    struct FullOutput<'a>(&'a SenderWitness);

    impl ShieldedOutput<IronwoodDomain, ENC_CIPHERTEXT_SIZE> for FullOutput<'_> {
        fn ephemeral_key(&self) -> EphemeralKeyBytes {
            EphemeralKeyBytes(self.0.epk)
        }
        fn cmstar_bytes(&self) -> [u8; 32] {
            self.0.cmx
        }
        fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
            &self.0.enc_ciphertext
        }
    }

    fn domain(witness: &SenderWitness) -> IronwoodDomain {
        let compact = CompactAction::from_parts(
            Option::<Nullifier>::from(Nullifier::from_bytes(&witness.rho)).unwrap(),
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
                &witness.cmx,
            ))
            .unwrap(),
            EphemeralKeyBytes(witness.epk),
            witness.enc_ciphertext[..52].try_into().unwrap(),
        );
        IronwoodDomain::for_compact_action(&compact)
    }

    #[test]
    fn sender_certificate_matches_full_receiver_decryption() {
        let (witness, ivk) = fixture();
        let (note, recipient, memo) =
            try_note_decryption(&domain(&witness), &ivk, &FullOutput(&witness)).unwrap();
        assert_eq!(note.value().inner(), witness.value);
        assert_eq!(recipient.to_raw_address_bytes(), witness.recipient);
        assert_eq!(memo, witness.memo);
        let journal = verify_sender(&witness).unwrap();
        assert_eq!(&journal[..JOURNAL_DOMAIN.len()], b"ziquid.sender.v1");
        assert_eq!(
            &journal[JOURNAL_DOMAIN.len()..JOURNAL_DOMAIN.len() + 32],
            witness.context_digest
        );
        assert_eq!(
            &journal[JOURNAL_DOMAIN.len() + 32..],
            witness.output_commitment
        );
    }

    #[test]
    fn sender_rejects_rebound_note_and_full_ciphertext_mutations() {
        let (original, ivk) = fixture();
        let mutations: [fn(&mut SenderWitness); 10] = [
            |w| w.recipient[0] ^= 1,
            |w| w.value += 1,
            |w| w.rho[0] ^= 1,
            |w| w.rseed[0] ^= 1,
            |w| w.memo[0] ^= 1,
            |w| w.cmx[0] ^= 1,
            |w| w.epk[0] ^= 1,
            |w| w.enc_ciphertext[0] ^= 1,
            |w| w.enc_ciphertext[52] ^= 1,
            |w| w.enc_ciphertext[579] ^= 1,
        ];
        for (index, mutate) in mutations.into_iter().enumerate() {
            let mut altered = original.clone();
            mutate(&mut altered);
            rebind(&mut altered);
            assert!(
                verify_sender(&altered).is_err(),
                "accepted altered field {index}"
            );
        }
        let mut altered = original.clone();
        altered.enc_ciphertext[579] ^= 1;
        assert!(try_note_decryption(&domain(&altered), &ivk, &FullOutput(&altered)).is_none());
    }

    #[test]
    fn sender_rejects_v2_ciphertext_and_invalid_or_unbound_openings() {
        let (mut witness, _) = fixture();
        let recipient =
            Option::<Address>::from(Address::from_raw_address_bytes(&witness.recipient)).unwrap();
        let rho = Option::<Rho>::from(Rho::from_bytes(&witness.rho)).unwrap();
        let rseed =
            Option::<RandomSeed>::from(RandomSeed::from_bytes(witness.rseed, &rho)).unwrap();
        let note = Option::<Note>::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(witness.value),
            rho,
            rseed,
            NoteVersion::V2,
        ))
        .unwrap();
        let encryption = IronwoodNoteEncryption::new(None, note, witness.memo);
        witness.cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
        witness.enc_ciphertext = encryption.encrypt_note_plaintext();
        rebind(&mut witness);
        assert!(verify_sender(&witness).is_err());

        let (original, _) = fixture();
        let mut altered = original.clone();
        altered.context_digest[0] ^= 1;
        assert_eq!(
            verify_sender(&altered),
            Err(SenderRelationError::OutputCommitment)
        );
        let mut altered = original.clone();
        altered.secret_blind = [0; 32];
        rebind(&mut altered);
        assert_eq!(verify_sender(&altered), Err(SenderRelationError::Blind));
        let mut altered = original.clone();
        altered.output_commitment[0] ^= 1;
        assert_eq!(
            verify_sender(&altered),
            Err(SenderRelationError::OutputCommitment)
        );
        let mut altered = original;
        altered.rho = [255; 32];
        rebind(&mut altered);
        assert_eq!(verify_sender(&altered), Err(SenderRelationError::Rho));
    }

    #[test]
    fn sender_boundary_rejects_noncanonical_private_buffers() {
        let (witness, _) = fixture();
        let encoded = witness.encode_private();
        let decoded = SenderWitness::decode_private(&encoded).unwrap();
        assert_eq!(verify_sender(&decoded), verify_sender(&witness));
        assert!(matches!(
            SenderWitness::decode_private(&encoded[..encoded.len() - 1]),
            Err(SenderRelationError::Encoding)
        ));
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(matches!(
            SenderWitness::decode_private(&trailing),
            Err(SenderRelationError::Encoding)
        ));
    }

    #[test]
    fn groth16_preflight_resolves_only_sdk_compatible_paths() {
        use std::{ffi::OsString, path::PathBuf};

        let (base, home, fallback) = if cfg!(windows) {
            (
                r"C:\operator\cache",
                r"C:\operator\home",
                r"C:\operator\home\.sp1\circuits\groth16",
            )
        } else {
            (
                "/operator/cache",
                "/operator/home",
                "/operator/home/.sp1/circuits/groth16",
            )
        };
        assert_eq!(
            super::groth16_artifact_base(Some(OsString::from(base)), None).unwrap(),
            PathBuf::from(base)
        );
        assert_eq!(
            super::groth16_artifact_base(None, Some(OsString::from(home))).unwrap(),
            PathBuf::from(fallback)
        );
        assert_eq!(
            super::groth16_artifact_base(Some(OsString::from(base)), Some(OsString::new()))
                .unwrap(),
            PathBuf::from(base)
        );
        for (explicit, home) in [
            (Some(OsString::new()), Some(OsString::from(home))),
            (
                Some(OsString::from("relative/cache")),
                Some(OsString::from(home)),
            ),
            (None, Some(OsString::new())),
            (None, Some(OsString::from("relative/home"))),
            (None, None),
        ] {
            assert_eq!(
                super::groth16_artifact_base(explicit, home)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }


    #[cfg(unix)]
    #[test]
    fn groth16_preflight_rejects_non_utf8_without_sdk_fallback() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

        let non_utf8 = OsString::from_vec(b"/operator/\xff".to_vec());
        for (explicit, home) in [
            (
                Some(non_utf8.clone()),
                Some(OsString::from("/operator/home")),
            ),
            (None, Some(non_utf8.clone())),
        ] {
            assert_eq!(
                super::groth16_artifact_base(explicit, home)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            super::groth16_artifact_base(Some(OsString::from("/operator/cache")), Some(non_utf8),)
                .unwrap(),
            PathBuf::from("/operator/cache")
        );
    }

    #[cfg(feature = "sp1-execute")]
    #[test]
    fn private_trace_events_and_register_spans_never_reach_subscribers() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use tracing_subscriber::{Layer, layer::Context, prelude::*};

        #[derive(Default)]
        struct Captured {
            trace_events: AtomicUsize,
            trace_spans: AtomicUsize,
            debug_events: AtomicUsize,
            info_events: AtomicUsize,
        }
        struct Capture(Arc<Captured>);
        impl<S: tracing::Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                let counter = match *event.metadata().level() {
                    tracing::Level::TRACE => &self.0.trace_events,
                    tracing::Level::DEBUG => &self.0.debug_events,
                    tracing::Level::INFO => &self.0.info_events,
                    _ => return,
                };
                counter.fetch_add(1, Ordering::Relaxed);
            }

            fn on_new_span(
                &self,
                span: &tracing::span::Attributes<'_>,
                _: &tracing::span::Id,
                _: Context<'_, S>,
            ) {
                if *span.metadata().level() == tracing::Level::TRACE {
                    self.0.trace_spans.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        fn emit() {
            // Public marker only; no private input is used or retained by this sink.
            tracing::trace!(target: "sp1_core_executor::vm", "trace boundary probe");
            let span = tracing::trace_span!(
                target: "sp1_core_executor::splicing",
                "SplicedMinimalTrace::new",
                start_registers = ?[0u64; 32],
            );
            let _guard = span.enter();
            tracing::debug!("debug boundary positive control");
            tracing::info!("info boundary positive control");
        }

        let captured = Arc::new(Captured::default());
        // No runtime filter: a programmatic subscriber accepts TRACE from any target.
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry().with(Capture(Arc::clone(&captured))),
        );
        tracing::dispatcher::with_default(&dispatch, emit);
        std::thread::spawn(move || tracing::dispatcher::with_default(&dispatch, emit))
            .join()
            .unwrap();
        assert_eq!(captured.debug_events.load(Ordering::Relaxed), 2);
        assert_eq!(captured.info_events.load(Ordering::Relaxed), 2);
        assert_eq!(captured.trace_events.load(Ordering::Relaxed), 0);
        assert_eq!(captured.trace_spans.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "sp1-local")]
    #[test]
    fn private_certificate_boundary_rejects_empty_and_wrong_journal_proofs() {
        use super::local::{SenderCertificate, verify_certificate};
        let (witness, _) = fixture();
        let expected = verify_sender(&witness).unwrap();
        let certificate = SenderCertificate {
            program_vkey: format!("0x{}", "00".repeat(32)),
            journal: expected,
            proof_bytes: Vec::new(),
        };
        assert!(verify_certificate(&certificate, &certificate.program_vkey, &expected).is_err());
        let mut altered = certificate;
        altered.journal[JOURNAL_DOMAIN.len()] ^= 1;
        assert!(verify_certificate(&altered, &altered.program_vkey, &expected).is_err());
    }
}
