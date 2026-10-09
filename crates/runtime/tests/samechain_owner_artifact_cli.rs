//! Source-first subprocess regressions: synthetic keys, real codecs/signatures/AEAD.
//! No accepted proofs, valid-program setup, SQL, network or retained-ELF dependency.
//! Actual CPU positives belong to the parent's independently pinned ELF smoke.
#![cfg(feature = "sp1-execute")]

use sha2::{Digest, Sha256};
use std::{ffi::OsString, io::Write, process::{Command, Output, Stdio}};
use zeroize::Zeroizing;
#[cfg(unix)]
use std::{os::{fd::OwnedFd, unix::net::UnixStream}, time::{Duration, Instant}};
use ziquid_proofs::samechain::{CancelExitWitness, MAX_PRIVATE_INPUT_BYTES, OwnerWitness};
use ziquid_proofs::samechain::creation::NoteCreationWitness;
use ziquid_proofs::samechain::withdrawal::NoteWithdrawalWitness;
use ziquid_protocol::samechain::{Action, Deployment};

#[allow(dead_code)]
#[path = "../../proofs/tests/support/samechain.rs"]
mod fill_support;
#[allow(dead_code)]
#[path = "../../proofs/tests/support/ordinary_withdrawal.rs"]
mod withdrawal_support;
#[allow(dead_code)]
#[path = "../../proofs/tests/support/note_creation.rs"]
mod creation_support;

const INVALID_ELF: &[u8] = b"owner-artifact-public-invalid-ELF-sentinel";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(2 + bytes.len() * 2);
    value.push_str("0x");
    for byte in bytes { write!(&mut value, "{byte:02x}").unwrap(); }
    value
}

fn not_disclosed(stream: &[u8], private: &[u8]) {
    if private.is_empty() { return; }
    assert!(!stream.windows(private.len()).any(|window| window == private), "private bytes disclosed");
    let mut json = Zeroizing::new(Vec::with_capacity(private.len() * 4 + 2));
    serde_json::to_writer(&mut *json, private).unwrap();
    assert!(!stream.windows(json.len()).any(|window| window == &json[..]), "private serialized bytes disclosed");
    if private.len() == 32 {
        use std::fmt::Write as _;
        let mut value = Zeroizing::new(String::with_capacity(64));
        for byte in private { write!(&mut *value, "{byte:02x}").unwrap(); }
        assert!(!stream.windows(64).any(|window| window.eq_ignore_ascii_case(value.as_bytes())), "private hex bytes disclosed");
    }
}

fn private_diagnostic(stream: &[u8], bytes: &[u8]) {
    not_disclosed(stream, bytes);
    if let Ok(witness) = OwnerWitness::decode(bytes) {
        not_disclosed(stream, &witness.owner_seed);
        not_disclosed(stream, &witness.own_salt);
        not_disclosed(stream, &witness.input.encode().unwrap());
        for opening in &witness.owned_outputs {
            not_disclosed(stream, &opening.recovery_key);
            not_disclosed(stream, &opening.note.encode().unwrap());
        }
    } else if let Ok(witness) = CancelExitWitness::decode(bytes) {
        not_disclosed(stream, &witness.owner_seed);
        not_disclosed(stream, &witness.blind);
        not_disclosed(stream, &witness.input.encode().unwrap());
        for opening in &witness.owned_outputs {
            not_disclosed(stream, &opening.recovery_key);
            not_disclosed(stream, &opening.note.encode().unwrap());
        }
    } else if let Ok(witness) = NoteWithdrawalWitness::decode(bytes) {
        not_disclosed(stream, &witness.owner_seed);
        not_disclosed(stream, &witness.blind);
        not_disclosed(stream, &witness.input.encode().unwrap());
        for opening in &witness.owned_outputs {
            not_disclosed(stream, &opening.recovery_key);
            not_disclosed(stream, &opening.note.encode().unwrap());
        }
    } else if let Ok(witness) = NoteCreationWitness::decode(bytes) {
        for private in [&witness.owner_seed, &witness.blind, &witness.recovery_key,
            &witness.note.nf_key, &witness.note.nonce, &witness.note.salt]
        {
            not_disclosed(stream, private);
        }
        not_disclosed(stream, &witness.note.encode().unwrap());
        if let Some(order) = &witness.note.order {
            not_disclosed(stream, &order.encode().unwrap());
        }
    }
}

fn run(arguments: &[OsString], bytes: &[u8], environment: Option<(&str, &str)>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ziquid"));
    command.arg("samechain").args(arguments.iter())
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Isolation only: production must still reject each explicit unsafe selection.
    for name in ["SP1_DUMP", "TRACE_FILE", "DUMP_ELF_OUTPUT", "SP1_RECORD_WRITE_DIR",
        "SP1_RECORD_MAX_ARITY_INPUT", "SP1_RECORD_SHRINK_INPUT", "WITHOUT_VK_VERIFICATION",
        "SP1_SKIP_PROGRAM_BUILD", "SP1_CORE_RUNNER_OVERRIDE_BINARY", "SP1_PROVER", "SP1_CIRCUIT_MODE"]
    {
        command.env_remove(name);
    }
    if let Some((name, value)) = environment { command.env(name, value); }
    let mut child = command.spawn().unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(bytes) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    let output = child.wait_with_output().unwrap();
    for stream in [&output.stdout, &output.stderr] {
        private_diagnostic(stream, bytes);
        for argument in arguments.iter() {
            let value = argument.to_string_lossy();
            if value.starts_with('/') || value.contains("sentinel") {
                not_disclosed(stream, value.as_bytes());
            }
        }
        if let Some((_, value)) = environment { not_disclosed(stream, value.as_bytes()); }
    }
    output
}

fn rejected(output: &Output, code: i32) {
    // Unknown subcommands exit 2, so they cannot stand in for feature-enabled
    // witness/scope/hash rejection, which must reach the real command and exit 1.
    assert_eq!(output.status.code(), Some(code));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn hidden_worker_rejects_sdk_selectors_before_reading_private_stdin() {
    use std::os::unix::fs::PermissionsExt;
    for (name, value) in [
        ("MEMORY_LIMIT", "1"),
        ("SP1_WORKER_NUM_DEFERRED_WORKERS", "1"),
        ("SP1_WORKER_DEFERRED_BUFFER_SIZE", "1"),
        ("SP1_GROTH16_CIRCUIT_PATH", "/tmp/mismatched-base"),
    ] {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir().unwrap();
        let (parent, child) = UnixStream::pair().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_ziquid"));
        command.args([
            "samechain", "owner-proof-worker", "--operation", "creation",
            "--elf", "/tmp/owner.elf", "--elf-sha256", "0x01",
            "--deployment", "/tmp/deployment", "--program-vkey", "0x01",
            "--groth16-artifact-dir", "/tmp/v6.1.0",
        ]).env_clear()
            .env("HOME", "/tmp")
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("TMPDIR", root.path())
            .env("SP1_GROTH16_CIRCUIT_PATH", "/tmp")
            .env(name, value)
            .stdin(Stdio::from(OwnedFd::from(child)))
            .stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(!status.success(), "hidden worker accepted {name}");
                break;
            }
            assert!(Instant::now() < deadline, "hidden worker did not reject {name} before reading");
            std::thread::sleep(Duration::from_millis(2));
        }
        drop(parent);
    }
}

fn public_file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    file
}

struct Files {
    elf: tempfile::NamedTempFile,
    deployment: tempfile::NamedTempFile,
    packet: tempfile::NamedTempFile,
}

impl Files {
    fn new() -> Self {
        Self {
            elf: public_file(INVALID_ELF),
            deployment: public_file(&fill_support::deployment().encode().unwrap()),
            packet: public_file(&fill_support::known_fill().packet.encode().unwrap()),
        }
    }

    fn args(&self, command: &str, operation: &str) -> Vec<OsString> {
        let hash: [u8; 32] = Sha256::digest(INVALID_ELF).into();
        let mut args: Vec<OsString> = vec![command.into(), "--operation".into(), operation.into(),
            "--elf".into(), self.elf.path().into(), "--elf-sha256".into(), hex(&hash).into(),
            "--deployment".into(), self.deployment.path().into(), "--witness-stdin".into()];
        if operation == "fill" {
            args.extend([OsString::from("--packet"), self.packet.path().into()]);
        }
        if command == "prove-owner" {
            args.extend([OsString::from("--program-vkey"), hex(&fill_support::deployment().owner_program).into()]);
        }
        args
    }
}

fn replace(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
    let index = args.iter().position(|argument| argument == flag).unwrap();
    args[index + 1] = value.into();
}

fn remove(args: &mut Vec<OsString>, flag: &str, takes_value: bool) {
    let index = args.iter().position(|argument| argument == flag).unwrap();
    args.drain(index..index + if takes_value { 2 } else { 1 });
}

fn witnesses() -> Vec<(&'static str, Zeroizing<Vec<u8>>)> {
    let fill = fill_support::known_fill();
    vec![
        ("fill", fill.a.encode().unwrap()),
        ("cancel", fill_support::cancel_exit(&fill, Action::Cancel).encode().unwrap()),
        ("exit", fill_support::cancel_exit(&fill, Action::Exit).encode().unwrap()),
        ("withdrawal", withdrawal_support::received_token_partial().encode().unwrap()),
        ("creation", creation_support::ordinary_native().encode().unwrap()),
    ]
}

#[test]
fn selected_execution_command_reaches_runtime_rejection_instead_of_unknown_command() {
    let files = Files::new();
    for (operation, bytes) in witnesses() {
        rejected(&run(&files.args("execute-owner", operation), &bytes, None), 1);
    }
}

#[test]
fn execution_requires_explicit_stdin_deployment_and_elf_hash() {
    let files = Files::new();
    let witness = creation_support::ordinary_native().encode().unwrap();
    for (flag, takes_value) in [("--witness-stdin", false), ("--deployment", true),
        ("--elf-sha256", true), ("--elf", true), ("--operation", true)]
    {
        let mut args = files.args("execute-owner", "creation");
        remove(&mut args, flag, takes_value);
        rejected(&run(&args, &witness, None), 2);
    }
}

#[test]
fn packet_is_required_only_for_fill_and_operation_is_closed() {
    let files = Files::new();
    let fill = fill_support::known_fill();
    let mut args = files.args("execute-owner", "fill");
    remove(&mut args, "--packet", true);
    rejected(&run(&args, &fill.a.encode().unwrap(), None), 2);
    for (operation, witness) in witnesses().into_iter().filter(|(operation, _)| *operation != "fill") {
        let mut args = files.args("execute-owner", operation);
        args.extend([OsString::from("--packet"), files.packet.path().into()]);
        rejected(&run(&args, &witness, None), 2);
    }
    let mut args = files.args("execute-owner", "creation");
    replace(&mut args, "--operation", "private-operation-sentinel");
    rejected(&run(&args, &[], None), 2);
}

#[test]
fn wrong_witness_mode_and_cancel_exit_action_fail_before_elf_execution() {
    let files = Files::new();
    let cases = witnesses();
    for (operation, bytes) in &cases {
        let args = files.args("execute-owner", operation);
        let baseline = run(&args, bytes, None);
        rejected(&baseline, 1);
        for (other, wrong) in &cases {
            if other == operation { continue; }
            let output = run(&args, wrong, None);
            rejected(&output, 1);
            // Paired malformed-ELF baseline prevents the ELF failure itself from
            // masking a missing witness decoder or cancel/exit action check.
            assert_ne!(output.stderr, baseline.stderr, "wrong owner mode reached ELF execution");
        }
    }
}

#[test]
fn malformed_trailing_oversized_and_outer_guest_frames_are_not_private_witnesses() {
    let files = Files::new();
    for (operation, bytes) in witnesses() {
        let args = files.args("execute-owner", operation);
        let baseline = run(&args, &bytes, None);
        rejected(&baseline, 1);
        let mut trailing = Zeroizing::new(vec![0; bytes.len() + 1]);
        trailing[..bytes.len()].copy_from_slice(&bytes);
        let mut outer = Zeroizing::new(vec![0; bytes.len() + 1]);
        outer[1..].copy_from_slice(&bytes);
        let mut oversized = Zeroizing::new(vec![0; MAX_PRIVATE_INPUT_BYTES + 1]);
        oversized[..bytes.len()].copy_from_slice(&bytes);
        for malformed in [&[][..], &bytes[..bytes.len() - 1], &trailing[..], &outer[..], &oversized[..]] {
            let output = run(&args, malformed, None);
            rejected(&output, 1);
            assert_ne!(output.stderr, baseline.stderr, "invalid private encoding reached ELF execution");
        }
    }
}

#[test]
fn every_independent_deployment_field_is_checked_before_execution() {
    let files = Files::new();
    let changes: [fn(&mut Deployment); 6] = [
        |d| d.chain_id += 1, |d| d.authority[0] ^= 1, |d| d.authority_code[0] ^= 1,
        |d| d.verifier[0] ^= 1, |d| d.verifier_code[0] ^= 1,
        |d| d.owner_program[0] ^= 1,
    ];
    for (operation, bytes) in witnesses() {
        let args = files.args("execute-owner", operation);
        let baseline = run(&args, &bytes, None);
        rejected(&baseline, 1);
        for mutate in changes {
            let mut deployment = fill_support::deployment();
            mutate(&mut deployment);
            let expected = public_file(&deployment.encode().unwrap());
            let mut args = args.clone();
            replace(&mut args, "--deployment", expected.path());
            let output = run(&args, &bytes, None);
            rejected(&output, 1);
            assert_ne!(output.stderr, baseline.stderr, "wrong deployment reached ELF execution");
        }
        // Unsupported schema cannot be encoded through the validating codec.
        // Its final u16 is literal big-endian schema; corrupt the public frame.
        let mut encoded = fill_support::deployment().encode().unwrap();
        *encoded.last_mut().unwrap() = 2;
        let expected = public_file(&encoded);
        let mut args = args;
        replace(&mut args, "--deployment", expected.path());
        let output = run(&args, &bytes, None);
        rejected(&output, 1);
        assert_ne!(output.stderr, baseline.stderr, "unsupported deployment schema reached ELF execution");
    }
}

#[test]
fn independently_selected_fill_packet_cannot_be_replaced_by_embedded_witness_packet() {
    let files = Files::new();
    let fill = fill_support::known_fill();
    let bytes = fill.a.encode().unwrap();
    let args = files.args("execute-owner", "fill");
    let baseline = run(&args, &bytes, None);
    rejected(&baseline, 1);
    let mut wrong = fill.packet.clone();
    wrong.expiry += 1;
    let packet = public_file(&wrong.encode().unwrap());
    let mut args = args;
    replace(&mut args, "--packet", packet.path());
    let output = run(&args, &bytes, None);
    rejected(&output, 1);
    assert_ne!(output.stderr, baseline.stderr, "selected packet was ignored");
}

#[test]
fn selected_fill_packet_mismatch_precedes_public_elf_reads() {
    let files = Files::new();
    let fill = fill_support::known_fill();
    let bytes = fill.a.encode().unwrap();
    let mut selected = fill.packet.clone();
    selected.expiry += 1;
    let selected = public_file(&selected.encode().unwrap());
    let mut args = files.args("execute-owner", "fill");
    replace(&mut args, "--packet", selected.path());
    replace(&mut args, "--elf", "/missing-public-owner-elf-sentinel");
    let output = run(&args, &bytes, None);
    rejected(&output, 1);
}

#[test]
fn malformed_elf_hash_and_exact_hash_mismatch_never_export_output() {
    let files = Files::new();
    let witness = creation_support::ordinary_native().encode().unwrap();
    let args = files.args("execute-owner", "creation");
    let baseline = run(&args, &witness, None);
    rejected(&baseline, 1);
    for value in [hex(&[0; 32]), hex(&[9; 32]), "0x01".into(), "not-a-hash-sentinel".into(),
        format!("0x{}", "g".repeat(64))]
    {
        let mut args = args.clone();
        replace(&mut args, "--elf-sha256", value);
        let output = run(&args, &witness, None);
        rejected(&output, 1);
        assert_ne!(output.stderr, baseline.stderr, "invalid hash reached ELF execution");
    }
}

#[test]
fn oversized_or_unavailable_public_elf_is_bounded_and_paths_are_redacted() {
    let files = Files::new();
    let witness = creation_support::ordinary_native().encode().unwrap();
    let oversized = tempfile::NamedTempFile::new().unwrap();
    let size = 16 * 1024 * 1024 + 1;
    oversized.as_file().set_len(size).unwrap();
    let mut hasher = Sha256::new();
    for _ in 0..4096 { hasher.update([0; 4096]); }
    hasher.update([0]);
    let hash: [u8; 32] = hasher.finalize().into();
    let mut args = files.args("execute-owner", "creation");
    replace(&mut args, "--elf", oversized.path());
    replace(&mut args, "--elf-sha256", hex(&hash));
    let bounded = run(&args, &witness, None);
    rejected(&bounded, 1);
    replace(&mut args, "--elf-sha256", hex(&[9; 32]));
    let wrong_hash = run(&args, &witness, None);
    rejected(&wrong_hash, 1);
    // Overflow must win even when the independently supplied hash changes.
    assert_eq!(bounded.stderr, wrong_hash.stderr);
    let missing = files.elf.path().with_file_name("missing-owner-elf-path-sentinel");
    replace(&mut args, "--elf", missing.as_path());
    rejected(&run(&args, &witness, None), 1);
}

#[test]
fn unsafe_private_environment_is_rejected_without_revealing_values() {
    let files = Files::new();
    let witness = creation_support::ordinary_native().encode().unwrap();
    let args = files.args("execute-owner", "creation");
    let baseline = run(&args, &witness, None);
    rejected(&baseline, 1);
    for name in ["SP1_DUMP", "TRACE_FILE", "DUMP_ELF_OUTPUT", "SP1_RECORD_WRITE_DIR",
        "SP1_RECORD_MAX_ARITY_INPUT", "SP1_RECORD_SHRINK_INPUT", "WITHOUT_VK_VERIFICATION",
        "SP1_SKIP_PROGRAM_BUILD", "SP1_CORE_RUNNER_OVERRIDE_BINARY", "SP1_PROVER", "SP1_CIRCUIT_MODE"]
    {
        let output = run(&args, &witness, Some((name, "private-provider-path-sentinel")));
        rejected(&output, 1);
        assert_ne!(output.stderr, baseline.stderr, "unsafe environment reached ELF execution");
    }
}

#[cfg(all(feature = "sp1-local", target_os = "linux"))]
mod producer_preflight {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use ziquid_proofs::samechain::creation::verify_note_creation_relation;

    struct Inputs {
        files: Files,
        scratch: tempfile::TempDir,
        release: tempfile::TempDir,
        key: std::path::PathBuf,
    }

    impl Inputs {
        fn new() -> Self {
            use std::os::unix::fs::OpenOptionsExt;
            let release = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
            let key = release.path().join("generated-backup-key");
            let mut file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&key).unwrap();
            file.write_all(&[0x41; 32]).unwrap();
            Self {
                files: Files::new(),
                scratch: tempfile::Builder::new()
                    .permissions(std::fs::Permissions::from_mode(0o700))
                    .tempdir().unwrap(),
                release,
                key,
            }
        }

        fn args(&self) -> Vec<OsString> {
            let mut args = self.files.args("prove-owner", "creation");
            args.extend([OsString::from("--private-temp-dir"), self.scratch.path().into(),
                OsString::from("--timeout-seconds"), OsString::from("1"),
                OsString::from("--release-dir"), self.release.path().into(),
                OsString::from("--backup-key-file"), self.key.clone().into(),
                OsString::from("--op-id"), hex(&[0x11; 32]).into()]);
            args
        }

        fn reject(&self, args: &[OsString], witness: &[u8], code: i32,
            category: Option<&str>) -> Output
        {
            let output = run(args, witness, None);
            rejected(&output, code);
            if let Some(category) = category {
                let diagnostic = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
                assert!(diagnostic.contains(category), "wrong preflight error category");
            }
            // Invalid requests must leave no per-run private scratch behind.
            // The parent source review additionally checks preflight-before-create.
            assert!(std::fs::read_dir(self.scratch.path()).unwrap().next().is_none(),
                "invalid request left private scratch");
            assert_eq!(std::fs::read_dir(self.release.path()).unwrap().count(), 1,
                "invalid request published a release capsule");
            assert_eq!(std::fs::read(&self.key).unwrap(), [0x41; 32]);
            output
        }
    }

    #[test]
    fn producer_without_database_configuration_reaches_private_witness_read() {
        use std::io::Read;
        let inputs = Inputs::new();
        let args = inputs.args();
        let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let reader = std::fs::File::from(reader);
        let mut retained = reader.try_clone().unwrap();
        let mut writer = std::fs::File::from(writer);
        let sentinel = b"generated-invalid-witness-for-db-free-producer";
        writer.write_all(sentinel).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ziquid"))
            .arg("samechain").args(&args).env_clear()
            .stdin(Stdio::from(reader)).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(child.try_wait().unwrap().is_none(), "producer rejected before private stdin without a database");
            if rustix::io::ioctl_fionread(&retained).unwrap() == 0 { break; }
            if Instant::now() >= deadline {
                child.kill().unwrap(); child.wait().unwrap();
                panic!("database-free producer never reached private stdin");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(writer); // Let the real decoder reject the fully consumed invalid frame.
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap(); child.wait().unwrap();
                panic!("database-free producer did not reject its invalid frame");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        rejected(&output, 1);
        let mut leftover = Vec::new(); retained.read_to_end(&mut leftover).unwrap();
        assert!(leftover.is_empty());
        for stream in [&output.stdout, &output.stderr] { not_disclosed(stream, sentinel); }
        assert!(std::fs::read_dir(inputs.scratch.path()).unwrap().next().is_none());
        assert_eq!(std::fs::read_dir(inputs.release.path()).unwrap().count(), 1);
    }

    #[test]
    fn producer_requires_program_pin_private_temp_directory_and_timeout() {
        let inputs = Inputs::new();
        let witness = creation_support::ordinary_native().encode().unwrap();
        for flag in ["--program-vkey", "--private-temp-dir", "--timeout-seconds"] {
            let mut args = inputs.args();
            remove(&mut args, flag, true);
            inputs.reject(&args, &witness, 2, None);
        }
    }

    #[test]
    fn producer_rejects_invalid_timeout_syntax_zero_and_over_one_day() {
        let inputs = Inputs::new();
        let witness = creation_support::ordinary_native().encode().unwrap();
        for timeout in ["NaN", "1.5", "-1", "0", "86401", "18446744073709551616"] {
            let mut args = inputs.args();
            replace(&mut args, "--timeout-seconds", timeout);
            inputs.reject(&args, &witness, 2, None);
        }
    }

    #[test]
    fn producer_rejects_noncanonical_zero_and_wrong_program_before_setup() {
        let inputs = Inputs::new();
        let scalar_r = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
            0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
        ];
        for program in [[0; 32], scalar_r, [0xff; 32]] {
            let mut witness = creation_support::ordinary_native();
            let mut args = inputs.args();
            // Nonzero out-of-field pins must agree with both public scope and
            // freshly signed private scope, so mismatch cannot mask scalar checks.
            let expected = if program != [0; 32] {
                witness.packet.deployment.owner_program = program;
                witness.note.deployment_digest = witness.packet.deployment.digest().unwrap();
                creation_support::replace_output(&mut witness);
                Some(public_file(&witness.packet.deployment.encode().unwrap()))
            } else {
                None // The deployment codec itself forbids a zero program.
            };
            if let Some(expected) = &expected {
                replace(&mut args, "--deployment", expected.path());
            }
            assert!(verify_note_creation_relation(&witness).is_ok());
            replace(&mut args, "--program-vkey", hex(&program));
            inputs.reject(&args, &witness.encode().unwrap(), 1, Some("program"));
        }
        let witness = creation_support::ordinary_native().encode().unwrap();
        let mut args = inputs.args();
        replace(&mut args, "--program-vkey", hex(&[6; 32]));
        inputs.reject(&args, &witness, 1, Some("program"));
    }

    #[test]
    fn producer_rejects_elf_hash_mismatch_before_setup() {
        let inputs = Inputs::new();
        let witness = creation_support::ordinary_native().encode().unwrap();
        for hash in [hex(&[0; 32]), hex(&[9; 32]), "0x01".into()] {
            let mut args = inputs.args();
            replace(&mut args, "--elf-sha256", hash);
            inputs.reject(&args, &witness, 1, Some("hash"));
        }
    }

    #[test]
    fn producer_checks_every_full_deployment_field_before_setup() {
        let inputs = Inputs::new();
        let witness = creation_support::ordinary_native().encode().unwrap();
        let changes: [fn(&mut Deployment); 6] = [
            |d| d.chain_id += 1, |d| d.authority[0] ^= 1, |d| d.authority_code[0] ^= 1,
            |d| d.verifier[0] ^= 1, |d| d.verifier_code[0] ^= 1,
            |d| d.owner_program[0] ^= 1,
        ];
        for mutate in changes {
            let mut deployment = fill_support::deployment();
            mutate(&mut deployment);
            let expected = public_file(&deployment.encode().unwrap());
            let mut args = inputs.args();
            replace(&mut args, "--deployment", expected.path());
            // Match the independent program to the selected public deployment;
            // only comparison with the actual signed witness can reject this.
            replace(&mut args, "--program-vkey", hex(&deployment.owner_program));
            inputs.reject(&args, &witness, 1, Some("deployment"));
        }
        let mut encoded = fill_support::deployment().encode().unwrap();
        *encoded.last_mut().unwrap() = 2;
        let expected = public_file(&encoded);
        let mut args = inputs.args();
        replace(&mut args, "--deployment", expected.path());
        inputs.reject(&args, &witness, 1, Some("deployment"));
    }

    #[test]
    fn producer_fill_packet_mismatch_precedes_elf_worker_and_scratch() {
        let inputs = Inputs::new();
        let fill = fill_support::known_fill();
        let mut selected = fill.packet.clone();
        selected.expiry += 1;
        let selected = public_file(&selected.encode().unwrap());
        let mut args = inputs.args();
        replace(&mut args, "--operation", "fill");
        replace(&mut args, "--elf", "/missing-public-owner-elf-sentinel");
        args.extend([OsString::from("--packet"), selected.path().into()]);
        inputs.reject(&args, &fill.a.encode().unwrap(), 1, Some("packet"));
    }

    #[test]
    fn producer_rejects_signed_inflation_and_invalid_consent_before_setup() {
        let inputs = Inputs::new();
        let mut inflated = creation_support::ordinary_native();
        inflated.note.value += primitive_types::U256::one();
        creation_support::replace_output(&mut inflated);
        let mut unconsented = creation_support::ordinary_native();
        unconsented.consent[0] ^= 1;
        for witness in [&inflated, &unconsented] {
            assert!(verify_note_creation_relation(witness).is_err());
            inputs.reject(&inputs.args(), &witness.encode().unwrap(), 1, Some("relation"));
        }
    }
}
