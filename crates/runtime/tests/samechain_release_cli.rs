//! Real CLI release fences: held-open witness pipe, generated private key files, no SQL or prover.
#![cfg(target_os = "linux")]

use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
use rustix::{fs::OFlags, pipe::{PipeFlags, pipe_with}};

const INPUT_SENTINEL: &[u8] = b"release-unread-private-witness-sentinel";
const KEY_SENTINEL: &[u8; 32] = b"release-unread-key-sentinel-0000";
const URI: &str = "postgresql://generated:release-uri-sentinel@database.invalid/z2z?sslmode=verify-full";

#[cfg(all(feature = "sp1-local", feature = "postgres-tests"))]
#[path = "market_support/ledger.rs"]
mod sql_support;

fn pipe(bytes: &[u8]) -> (File, File, File) {
    let (reader, writer) = pipe_with(PipeFlags::CLOEXEC).unwrap();
    let reader = File::from(reader);
    let retained = reader.try_clone().unwrap();
    let mut writer = File::from(writer);
    writer.write_all(bytes).unwrap();
    (reader, retained, writer)
}

fn remaining(reader: &mut File) -> Vec<u8> {
    rustix::fs::fcntl_setfl(&*reader, OFlags::NONBLOCK).unwrap();
    let mut bytes = Vec::new();
    match reader.read_to_end(&mut bytes) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => bytes,
        other => panic!("held-open input pipe unexpectedly ended: {other:?}"),
    }
}

fn invoke(arguments: &[OsString], uri: Option<(&str, &str)>) -> Output {
    let (stdin, mut stdin_reader, stdin_writer) = pipe(INPUT_SENTINEL);
    let mut command = Command::new(env!("CARGO_BIN_EXE_ziquid"));
    command.arg("samechain").args(arguments).env_clear()
        .stdin(Stdio::from(stdin)).stdout(Stdio::piped()).stderr(Stdio::piped());
    for name in ["HOME", "PATH"] {
        if let Some(value) = std::env::var_os(name) { command.env(name, value); }
    }
    if let Some((name, value)) = uri { command.env(name, value); }
    let mut child = command.spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new(); stdout.read_to_end(&mut bytes).unwrap(); bytes
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new(); stderr.read_to_end(&mut bytes).unwrap(); bytes
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() { break status; }
        if Instant::now() >= deadline {
            child.kill().unwrap(); child.wait().unwrap();
            panic!("release preflight waited for private input or exceeded its watchdog");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // Writers remain open until after exit and inspection: EOF cannot satisfy a read.
    assert_eq!(remaining(&mut stdin_reader), INPUT_SENTINEL, "preflight consumed private stdin");
    drop(stdin_writer);
    let output = Output { status, stdout: stdout_reader.join().unwrap(), stderr: stderr_reader.join().unwrap() };
    for stream in [&output.stdout, &output.stderr] {
        for private in [INPUT_SENTINEL, &KEY_SENTINEL[..], URI.as_bytes(),
            &b"config-private-sentinel"[..], &b"binding-private-sentinel"[..], &b"invalid=private-sentinel"[..]] {
            assert!(!stream.windows(private.len()).any(|window| window == private), "private input disclosed");
        }
        if let Some((name, value)) = uri {
            for private in [name.as_bytes(), value.as_bytes()] {
                assert!(!stream.windows(private.len()).any(|window| window == private), "private database configuration disclosed");
            }
        }
        for argument in arguments {
            let value = argument.to_string_lossy();
            if value.starts_with('/') || value.contains("sentinel") {
                assert!(!stream.windows(value.len()).any(|window| window == value.as_bytes()), "argument disclosed");
            }
        }
    }
    output
}

fn rejected(output: &Output, code: i32) {
    assert_eq!(output.status.code(), Some(code));
    assert!(output.stdout.is_empty(), "preflight exported certificate material");
    assert!(!output.stderr.is_empty());
}

#[cfg(not(feature = "sp1-local"))]
#[test]
fn release_commands_are_unavailable_without_local_proving_feature() {
    for command in ["prove-owner", "export-certificate"] {
        rejected(&invoke(&[command.into()], None), 2);
    }
}

#[cfg(feature = "sp1-local")]
mod enabled {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use sha2::{Digest, Sha256};
    use ziquid_protocol::samechain::{Deployment, Role};
    use ziquid_runtime::samechain::{backup::SnapshotOperation, release::ReleaseBinding};

    const ELF: &[u8] = b"release-public-synthetic-ELF";

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut encoded = String::from("0x");
        for byte in bytes { write!(&mut encoded, "{byte:02x}").unwrap(); }
        encoded
    }

    // Test-only bounded evidence of ordinary content reads on this watched inode.
    // An unchanged file alone is not evidence; lost events/inode changes fail closed.
    struct KeyObserver {
        notification: std::os::fd::OwnedFd,
        watch: i32,
        path: std::path::PathBuf,
        identity: (u64, u64),
    }

    impl KeyObserver {
        fn new(path: &std::path::Path) -> Self {
            use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
            use std::os::unix::fs::MetadataExt;
            let notification = inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK).unwrap();
            let watch = inotify::add_watch(&notification, path,
                WatchFlags::ACCESS | WatchFlags::OPEN | WatchFlags::DELETE_SELF | WatchFlags::MOVE_SELF).unwrap();
            let metadata = std::fs::metadata(path).unwrap();
            Self { notification, watch, path: path.into(), identity: (metadata.dev(), metadata.ino()) }
        }

        fn drain(&mut self) -> bool {
            use rustix::fs::inotify::{ReadFlags, Reader};
            use std::os::unix::fs::MetadataExt;
            let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
            let mut reader = Reader::new(&self.notification, &mut buffer);
            let mut access = false;
            loop {
                let event = match reader.next() {
                    Ok(event) => event,
                    Err(rustix::io::Errno::AGAIN) => break,
                    Err(error) => panic!("key-read evidence unavailable: {error:?}"),
                };
                assert!(!event.events().intersects(ReadFlags::QUEUE_OVERFLOW | ReadFlags::IGNORED
                    | ReadFlags::UNMOUNT | ReadFlags::DELETE_SELF | ReadFlags::MOVE_SELF),
                    "key-read watch integrity lost");
                assert_eq!(event.wd(), self.watch, "unexpected key watch descriptor");
                access |= event.events().contains(ReadFlags::ACCESS);
            }
            let metadata = std::fs::metadata(&self.path).expect("watched key inode unavailable");
            assert_eq!((metadata.dev(), metadata.ino()), self.identity, "watched key inode replaced");
            access
        }

        fn calibrate(&mut self) {
            let file = File::open(&self.path).unwrap();
            file.metadata().unwrap();
            drop(file);
            assert!(!self.drain(), "metadata-only key open generated content access");
            let mut key = zeroize::Zeroizing::new([0; 32]);
            File::open(&self.path).unwrap().read_exact(&mut key[..]).unwrap();
            assert!(self.drain(), "actual key read did not generate ACCESS; evidence unavailable");
            assert!(!self.drain(), "key calibration events were not fully drained");
        }

        fn assert_unread(&mut self) {
            assert!(!self.drain(), "CLI read key content before the release fence");
        }
    }

    fn negative_envelope(binding: &ReleaseBinding) -> Vec<u8> {
        use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
        let encoded = binding.encode().unwrap();
        let mut plaintext = b"Z2Z_SAMECHAIN_RELEASE_CAPSULE\0".to_vec();
        plaintext.extend_from_slice(&1_u16.to_be_bytes());
        plaintext.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        plaintext.extend_from_slice(&encoded);
        plaintext.extend_from_slice(&1_u32.to_be_bytes());
        plaintext.push(1); // Invalid journal/proof, never a passing certificate.
        plaintext.extend_from_slice(&356_u32.to_be_bytes());
        plaintext.extend_from_slice(&[0; 356]);
        let mut context = Sha256::new();
        context.update(b"Z2Z_SAMECHAIN_RELEASE_CONTEXT\0");
        context.update(1_u16.to_be_bytes());
        context.update(Sha256::digest(&encoded));
        let nonce = [0x72; 24];
        let mut header = b"ziquid.samechain.release.v1".to_vec();
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&((plaintext.len() + 16) as u32).to_le_bytes());
        let mut aad = header.clone();
        aad.extend_from_slice(&binding.op_id);
        aad.extend_from_slice(&context.finalize());
        let tag = XChaCha20Poly1305::new(KEY_SENTINEL.into()).encrypt_in_place_detached(
            XNonce::from_slice(&nonce), &aad, &mut plaintext).unwrap();
        header.extend_from_slice(&plaintext);
        header.extend_from_slice(&tag);
        header
    }

    struct Inputs {
        root: tempfile::TempDir,
        scratch: std::path::PathBuf,
        release: std::path::PathBuf,
        config: std::path::PathBuf,
        binding: std::path::PathBuf,
        key: std::path::PathBuf,
        uri_env: String,
    }

    fn directory_bytes(path: &std::path::Path) -> Vec<(OsString, Vec<u8>)> {
        let mut files: Vec<_> = std::fs::read_dir(path).unwrap().map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), std::fs::read(entry.path()).unwrap())
        }).collect();
        files.sort_by(|left, right| left.0.cmp(&right.0));
        files
    }

    impl Inputs {
        fn new() -> Self {
            let root = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
            let scratch = root.path().join("private-scratch-sentinel");
            let release = root.path().join("private-release-sentinel");
            std::fs::create_dir(&scratch).unwrap();
            std::fs::create_dir(&release).unwrap();
            std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&release, std::fs::Permissions::from_mode(0o700)).unwrap();
            let config = root.path().join("private-config-sentinel.json");
            let binding = root.path().join("public-binding-sentinel.hex");
            static NEXT_ENV: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let uri_env = format!("Z2Z_RELEASE_CLI_SYNTHETIC_URI_{}", NEXT_ENV.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
            let key = root.path().join("backup-key-private-sentinel");
            let mut file = std::fs::OpenOptions::new().create_new(true).write(true)
                .mode(0o600).open(&key).unwrap();
            file.write_all(KEY_SENTINEL).unwrap();
            let inputs = Self { root, scratch, release, config, binding, key, uri_env };
            inputs.write_config(serde_json::json!({"uri_env": inputs.uri_env, "schema": "z2z_release_cli", "max_connections": 1}));
            let deployment = Deployment { chain_id: 31337, authority: [1; 20], authority_code: [2; 32],
                verifier: [3; 20], verifier_code: [4; 32], owner_program: [5; 32], schema: 1 };
            std::fs::write(inputs.root.path().join("public-elf-sentinel"), ELF).unwrap();
            std::fs::write(inputs.root.path().join("public-deployment-sentinel"), deployment.encode().unwrap()).unwrap();
            let binding = ReleaseBinding { op_id: [0x11; 32], deployment,
                operation: SnapshotOperation::Creation, role: Role::A, packet_digest: [6; 32],
                program_vkey: deployment.owner_program, journal_digest: [7; 32], expiry: 900,
                required_nfs: Vec::new() };
            // Genuine canonical public binding only: no certificate or Released row is invented.
            std::fs::write(&inputs.binding, hex(&binding.encode().unwrap())).unwrap();
            let capsule = inputs.release.join(format!("{}.release", hex(&binding.op_id).trim_start_matches("0x")));
            let mut file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(capsule).unwrap();
            file.write_all(&negative_envelope(&binding)).unwrap();
            inputs
        }

        fn write_config(&self, value: serde_json::Value) {
            std::fs::write(&self.config, serde_json::to_vec(&value).unwrap()).unwrap();
        }

        fn args(&self, command: &str) -> Vec<OsString> {
            let mut args: Vec<OsString> = vec![command.into(),
                "--release-dir".into(), self.release.clone().into(),
                "--backup-key-file".into(), self.key.clone().into(),
                "--op-id".into(), format!("0x{}", "11".repeat(32)).into()];
            if command == "prove-owner" {
                // Valid public files/pins leave only the selected release-fence
                // defect; no negative may be masked by a missing deployment or ELF.
                args.extend(["--operation".into(), "creation".into(), "--elf".into(),
                    self.root.path().join("public-elf-sentinel").into(), "--elf-sha256".into(),
                    hex(&Sha256::digest(ELF)).into(), "--deployment".into(),
                    self.root.path().join("public-deployment-sentinel").into(),
                    "--program-vkey".into(), hex(&[5; 32]).into(),
                    "--witness-stdin".into(), "--private-temp-dir".into(), self.scratch.clone().into(),
                    "--timeout-seconds".into(), "1".into()]);
            } else {
                args.extend(["--binding".into(), self.binding.clone().into(),
                    "--database-config".into(), self.config.clone().into()]);
            }
            args
        }

        fn reject(&self, args: &[OsString], uri: Option<&str>, code: i32) -> Output {
            let mut observer = KeyObserver::new(&self.key);
            let before = directory_bytes(&self.release);
            observer.calibrate();
            let output = invoke(args, uri.map(|value| (self.uri_env.as_str(), value)));
            observer.assert_unread();
            rejected(&output, code);
            assert!(std::fs::read_dir(&self.scratch).unwrap().next().is_none());
            assert_eq!(directory_bytes(&self.release), before, "release directory changed");
            assert_eq!(std::fs::read(&self.key).unwrap(), KEY_SENTINEL, "key file changed");
            output
        }
    }

    fn replace(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
        let index = args.iter().position(|arg| arg == flag).unwrap();
        args[index + 1] = value.into();
    }

    #[test]
    fn release_commands_require_every_fence_argument_before_reading_private_inputs() {
        let inputs = Inputs::new();
        for command in ["prove-owner", "export-certificate"] {
            let mut flags = vec!["--release-dir", "--backup-key-file", "--op-id"];
            if command == "export-certificate" { flags.extend(["--binding", "--database-config"]); }
            for flag in flags {
                let mut args = inputs.args(command);
                let index = args.iter().position(|arg| arg == flag).unwrap();
                args.drain(index..index + 2);
                inputs.reject(&args, Some(URI), 2);
            }
        }
    }

    #[test]
    fn malformed_and_zero_operation_ids_reject_before_reading_private_inputs() {
        let inputs = Inputs::new();
        for command in ["prove-owner", "export-certificate"] {
            for value in ["op-id-private-sentinel".into(), "0x01".into(),
                format!("0x{}", "gg".repeat(32)), format!("0x{}", "00".repeat(32)),
                format!("0x{}", "11".repeat(33))] {
                let mut args = inputs.args(command);
                replace(&mut args, "--op-id", value);
                inputs.reject(&args, Some(URI), 2);
            }
        }
    }

    #[test]
    fn invalid_key_files_reject_before_private_stdin_and_leave_key_material_unchanged() {
        let inputs = Inputs::new();
        let release_before = directory_bytes(&inputs.release);
        let absent = inputs.root.path().join("missing-key-private-sentinel");
        let link = inputs.root.path().join("symlink-key-private-sentinel");
        std::os::unix::fs::symlink(&inputs.key, &link).unwrap();
        let writable = inputs.root.path().join("writable-key-parent-private-sentinel");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let untrusted = writable.join("key-private-sentinel");
        let mut file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&untrusted).unwrap();
        file.write_all(KEY_SENTINEL).unwrap();
        for command in ["prove-owner", "export-certificate"] {
            for path in [&absent, &link, &untrusted] {
                // Missing files have no key inode; only the existing generated
                // target is observed for symlink and untrusted-parent cases.
                let watched = if path == &untrusted { &untrusted } else { &inputs.key };
                std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o700)).unwrap();
                let mut observer = KeyObserver::new(watched);
                observer.calibrate();
                if path == &untrusted {
                    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770)).unwrap();
                }
                assert!(!observer.drain());
                let mut args = inputs.args(command);
                replace(&mut args, "--backup-key-file", path);
                let output = invoke(&args, Some((&inputs.uri_env, URI)));
                observer.assert_unread();
                assert!(!output.status.success());
                assert!(output.stdout.is_empty());
                assert_eq!(std::fs::read(&inputs.key).unwrap(), KEY_SENTINEL);
                assert_eq!(std::fs::read(&untrusted).unwrap(), KEY_SENTINEL);
            }
            let mut observer = KeyObserver::new(&inputs.key);
            observer.calibrate();
            std::fs::set_permissions(&inputs.key, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(!observer.drain());
            let output = invoke(&inputs.args(command), Some((&inputs.uri_env, URI)));
            observer.assert_unread();
            assert!(!output.status.success()); assert!(output.stdout.is_empty());
            std::fs::set_permissions(&inputs.key, std::fs::Permissions::from_mode(0o600)).unwrap();
            for bytes in [&KEY_SENTINEL[..31], &b"release-unread-key-sentinel-0000extra"[..]] {
                std::fs::write(&inputs.key, KEY_SENTINEL).unwrap();
                let mut observer = KeyObserver::new(&inputs.key);
                observer.calibrate();
                std::fs::write(&inputs.key, bytes).unwrap();
                assert!(!observer.drain());
                let output = invoke(&inputs.args(command), Some((&inputs.uri_env, URI)));
                observer.assert_unread();
                assert!(!output.status.success()); assert!(output.stdout.is_empty());
                assert_eq!(std::fs::read(&inputs.key).unwrap(), bytes);
            }
            std::fs::write(&inputs.key, KEY_SENTINEL).unwrap();
        }
        assert!(!absent.exists());
        assert_eq!(directory_bytes(&inputs.release), release_before);
        assert!(std::fs::read_dir(&inputs.scratch).unwrap().next().is_none());
    }

    #[test]
    fn unreadable_and_invalid_configurations_reject_before_reading_private_inputs() {
        let inputs = Inputs::new();
        for command in ["export-certificate"] {
            let mut args = inputs.args(command);
            replace(&mut args, "--database-config", inputs.root.path().join("missing-config-sentinel"));
            inputs.reject(&args, Some(URI), 1);
            std::fs::write(&inputs.config, b"config-private-sentinel invalid JSON").unwrap();
            inputs.reject(&inputs.args(command), Some(URI), 1);
            for config in [
                serde_json::json!({"uri_env": inputs.uri_env, "schema": "public", "max_connections": 1}),
                serde_json::json!({"uri_env": inputs.uri_env, "schema": "z2z_release_cli", "max_connections": 0}),
                serde_json::json!({"uri_env": "invalid=private-sentinel", "schema": "z2z_release_cli", "max_connections": 1}),
                serde_json::json!({"uri_env": inputs.uri_env, "schema": "z2z_release_cli", "max_connections": 1, "uri": "config-private-sentinel"}),
            ] {
                inputs.write_config(config);
                inputs.reject(&inputs.args(command), Some(URI), 1);
            }
        }
    }

    #[test]
    fn missing_database_uri_rejects_before_witness_binding_or_key_reads() {
        let inputs = Inputs::new();
        // In the enabled feature this must reach runtime, not an unknown command.
        inputs.reject(&inputs.args("export-certificate"), None, 1);
    }

    #[test]
    fn export_rejects_missing_and_malformed_bindings_before_private_key_read() {
        let inputs = Inputs::new();
        std::fs::remove_file(&inputs.binding).unwrap();
        inputs.reject(&inputs.args("export-certificate"), Some(URI), 1);
        for bytes in [&b"binding-private-sentinel not hex"[..], b"0x0", b"0x00", b"0x0000"] {
            std::fs::write(&inputs.binding, bytes).unwrap();
            inputs.reject(&inputs.args("export-certificate"), Some(URI), 1);
        }
    }

    #[test]
    fn unsafe_missing_and_symlink_release_directories_reject_before_private_inputs() {
        let inputs = Inputs::new();
        let release_before = directory_bytes(&inputs.release);
        let absent = inputs.root.path().join("absent-release-sentinel");
        let link = inputs.root.path().join("symlink-release-sentinel");
        std::os::unix::fs::symlink(&inputs.release, &link).unwrap();
        for command in ["prove-owner", "export-certificate"] {
            for path in [&absent, &link] {
                let mut args = inputs.args(command);
                replace(&mut args, "--release-dir", path);
                let mut observer = KeyObserver::new(&inputs.key);
                observer.calibrate();
                let output = invoke(&args, Some((&inputs.uri_env, URI)));
                observer.assert_unread();
                assert!(!output.status.success());
                assert!(output.stdout.is_empty());
                assert!(!output.stderr.is_empty());
            }
            let mut observer = KeyObserver::new(&inputs.key);
            observer.calibrate();
            std::fs::set_permissions(&inputs.release, std::fs::Permissions::from_mode(0o755)).unwrap();
            let output = invoke(&inputs.args(command), Some((&inputs.uri_env, URI)));
            observer.assert_unread();
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            std::fs::set_permissions(&inputs.release, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(!absent.exists(), "preflight created the absent release directory");
        assert_eq!(directory_bytes(&inputs.release), release_before);
        assert!(std::fs::read_dir(&inputs.scratch).unwrap().next().is_none());
    }

    // Written for approved isolated SQL execution only; never run under the SQL hold.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn committed_export_reads_key_only_after_real_journal_fence() {
        use ziquid_runtime::samechain::{journal::ReleaseJournal, release::ReleaseDigest};
        let database = sql_support::TestDatabase::create("release_key").await;
        let journal = ReleaseJournal::connect(database.config.clone()).await.unwrap();
        journal.migrate().await.unwrap();
        let inputs = Inputs::new();
        inputs.write_config(serde_json::to_value(&database.config).unwrap());
        let frame = std::fs::read_to_string(&inputs.binding).unwrap();
        let encoded = frame.strip_prefix("0x").unwrap().as_bytes();
        let bytes: Vec<u8> = encoded.as_chunks::<2>().0.iter().map(|pair|
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect();
        let binding = ReleaseBinding::decode(&bytes).unwrap();
        journal.authorize(&binding).await.unwrap();
        // Existing authenticated envelope contains an intentionally invalid
        // certificate. No proof is accepted, but the real release fence commits.
        let path = inputs.release.join(format!("{}.release", hex(&binding.op_id).trim_start_matches("0x")));
        let ciphertext = std::fs::read(&path).unwrap();
        let expected = ReleaseDigest(Sha256::digest(&ciphertext).into());
        let mut connection = database.connection().await;
        let blocker: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(&mut connection).await.unwrap();
        let mut lock = sqlx::Connection::begin(&mut connection).await.unwrap();
        sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(current_database()||':'||$1||':'||pg_catalog.encode($2::bytea,'hex'),0))")
            .bind(&database.config.schema).bind(binding.op_id.as_slice()).execute(&mut *lock).await.unwrap();
        let mut observer = KeyObserver::new(&inputs.key);
        observer.calibrate();
        let arguments = inputs.args("export-certificate");
        let name = database.config.uri_env.clone();
        let uri = zeroize::Zeroizing::new(std::env::var(&name).unwrap());
        let process = tokio::task::spawn_blocking(move || invoke(&arguments, Some((&name, &uri))));
        let mut inspection = database.connection().await;
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name='z2z-runtime' AND $1=ANY(pg_catalog.pg_blocking_pids(pid)) AND wait_event_type='Lock' AND wait_event='advisory')")
                .bind(blocker).fetch_one(&mut inspection).await.unwrap();
            if waiting { break; }
            assert!(Instant::now() < deadline, "real CLI did not reach locked release journal");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        observer.assert_unread();
        lock.commit().await.unwrap();
        let output = process.await.unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(observer.drain(), "released export did not consume the watched key");
        let committed = journal.read_release(&binding).await.unwrap();
        assert_eq!(committed.release_digest(), expected);
        assert_eq!(std::fs::read(&inputs.key).unwrap(), KEY_SENTINEL);
        assert_eq!(std::fs::read(&path).unwrap(), ciphertext);
        // A different trusted encrypted file at the same name must hit the
        // already-Released digest conflict without opening key content again.
        let mut observer = KeyObserver::new(&inputs.key);
        observer.calibrate();
        let mut changed = ciphertext.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &changed).unwrap();
        let arguments = inputs.args("export-certificate");
        let name = database.config.uri_env.clone();
        let uri = zeroize::Zeroizing::new(std::env::var(&name).unwrap());
        let output = tokio::task::spawn_blocking(move || invoke(&arguments, Some((&name, &uri)))).await.unwrap();
        observer.assert_unread();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(journal.read_release(&binding).await.unwrap().release_digest(), expected);
        assert_eq!(std::fs::read(&path).unwrap(), changed);
        drop(inspection); drop(connection); drop(journal);
        database.remove().await;
    }
}
