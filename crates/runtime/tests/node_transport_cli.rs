//! Actual transport processes only: no wallets, SQL, proof jobs or order fixtures.
#![cfg(target_os = "linux")]
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_z2z-node"))
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .expect("the runnable z2z-node transport executable must exist")
}
fn events(output: &Output) -> Vec<Value> {
    std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("public transport output must be NDJSON"))
        .collect()
}

fn transport_only(started: &Value) {
    assert_eq!(started["event"], "node_started");
    assert_eq!(started["schema_version"], 1);
    assert_eq!(started["transport_only"], true);
    assert_eq!(started["identity"], "ephemeral_transport");
    assert!(started["peer_id"].as_str().is_some_and(|id| !id.is_empty()));
    for flag in [
        "persistent_identity", "discovery_ready", "gossip_ready", "trading_ready",
        "backing_ready", "proof_ready", "recovery_ready",
    ] {
        assert_eq!(started[flag], false, "transport must not imply {flag}");
    }
}

fn persistent_transport_only(started: &Value) {
    assert_eq!(started["event"], "node_started");
    assert_eq!(started["schema_version"], 1);
    assert_eq!(started["transport_only"], true);
    assert_eq!(started["identity"], "persistent_transport");
    assert_eq!(started["persistent_identity"], true);
    assert!(started["peer_id"].as_str().is_some_and(|id| !id.is_empty()));
    for flag in [
        "discovery_ready", "gossip_ready", "trading_ready", "backing_ready",
        "proof_ready", "recovery_ready",
    ] {
        assert_eq!(started[flag], false, "transport identity must not imply {flag}");
    }
}

fn private_identity_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new().prefix("z2z-peer-identity-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp").unwrap()
}

fn identity_frame(path: &std::path::Path) -> zeroize::Zeroizing<[u8; 52]> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let mut file = std::fs::File::open(path).unwrap();
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 52);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.nlink(), 1);
    let mut frame = zeroize::Zeroizing::new([0; 52]);
    file.read_exact(&mut frame[..]).unwrap();
    let mut eof = zeroize::Zeroizing::new([0; 1]);
    assert_eq!(file.read(&mut eof[..]).unwrap(), 0);
    assert!(frame[..18] == *b"Z2Z_PEER_IDENTITY\0", "transport domain differs");
    assert!(frame[18..20] == [0, 1], "transport format version differs");
    frame
}

fn rejected(args: &[&str]) {
    let output = run(args);
    assert_eq!(output.status.code(), Some(2), "{:?}", output);
    assert!(output.stdout.is_empty(), "invalid configuration must not start a node");
    assert!(!output.stderr.is_empty());
}

struct Node {
    child: Child,
    receiver: Option<Receiver<Result<Value, String>>>,
    reader: Option<thread::JoinHandle<()>>,
    seen: Vec<Value>,
}

impl Node {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(binary())
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the runnable z2z-node transport executable must exist");
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::sync_channel(128);
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let event = line
                    .map_err(|error| error.to_string())
                    .and_then(|line| serde_json::from_str(&line).map_err(|error| error.to_string()));
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
        Self { child, receiver: Some(receiver), reader: Some(reader), seen: Vec::new() }
    }

    fn event(&mut self, name: &str) -> Value {
        if let Some(event) = self.seen.iter().find(|event| event["event"] == name) {
            return event.clone();
        }
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = self.receiver.as_ref().unwrap().recv_timeout(remaining)
                .unwrap_or_else(|error| panic!("missing {name}: {error}; observed {:?}", self.seen))
                .expect("transport event must decode");
            let matches = event["event"] == name;
            self.seen.push(event.clone());
            if matches {
                return event;
            }
        }
    }

    fn exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "node did not exit after shutdown");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    fn interrupt(&self) {
        assert!(Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status().unwrap().success());
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.receiver.take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn help_version_and_invalid_cli_do_not_start_transport() {
    for args in [["--help"], ["--version"]] {
        let output = run(&args);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8(output.stdout).unwrap().contains("z2z-node"));
    }
    for args in [
        vec![], vec!["run"], vec!["trade"],
        vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--unknown"],
        vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--max-peers", "0"],
        vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--max-peers", "65"],
        vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "0"],
        vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "3600001"],
        vec!["run", "--listen", "/ip4/127.0.0.1/udp/9"],
        vec!["run", "--listen", "/dns4/localhost/tcp/9"],
        vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", "/ip4/127.0.0.1/tcp/9"],
    ] {
        rejected(&args);
    }
}

#[test]
fn strict_bounded_config_rejects_ambiguous_or_unbounded_inputs_before_start() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public transport config.json");
    let config = path.to_str().unwrap();
    let valid = json!({
        "schema_version":1, "listen":"/ip4/127.0.0.1/tcp/0", "dial":[],
        "max_peers":8, "run_for_ms":100,
    });
    for (field, value) in [
        ("schema_version", json!(2)), ("schema_version", json!("1")),
        ("listen", json!({"tcp":null})), ("listen", json!("x".repeat(257))),
        ("max_peers", json!(0)), ("max_peers", json!(65)),
        ("run_for_ms", json!(0)), ("run_for_ms", json!(3600001)),
        ("dial", json!(vec!["/ip4/127.0.0.1/tcp/9"; 65])),
        ("wallet_key", json!("PRIVATE_SENTINEL")),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        rejected(&["run", "--config", config]);
    }
    for bytes in [
        br#"{"schema_version":1,"schema_version":1,"listen":"/ip4/127.0.0.1/tcp/0"}"#.as_slice(),
        br#"{"listen":"/ip4/127.0.0.1/tcp/0"}"#.as_slice(),
        br#"{"schema_version":1}"#.as_slice(),
        br#"{"schema_version":1,"listen":"/ip4/127.0.0.1/tcp/0"} trailing"#.as_slice(),
    ] {
        std::fs::write(&path, bytes).unwrap();
        rejected(&["run", "--config", config]);
    }
    std::fs::write(&path, vec![b' '; 16_385]).unwrap();
    rejected(&["run", "--config", config]);
    std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
    rejected(&["run", "--config", config, "--listen", "/ip4/127.0.0.1/tcp/0"]);
    rejected(&["run", "--config", config, "--max-peers", "4"]);
    rejected(&["run", "--config", config, "--run-for-ms", "200"]);
    let output = run(&["run", "--config", config]);
    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty());
    let observed = events(&output);
    transport_only(&observed[0]);
    assert_eq!(observed[0]["max_peers"], 8);
    assert!(observed.iter().any(|event| event["event"] == "listening"));
    assert_eq!(observed.last().unwrap()["reason"], "duration_elapsed");
}

#[test]
fn persistent_identity_survives_process_restart() {
    let directory = private_identity_directory();
    let path = directory.path().join("transport.key");
    let args = [
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
        "--peer-identity-file", path.to_str().unwrap(),
    ];
    let first = run(&args);
    assert!(first.status.success(), "persistent identity startup failed: {}", first.status);
    assert!(first.stderr.is_empty());
    let first_events = events(&first);
    persistent_transport_only(&first_events[0]);
    assert!(first_events.iter().any(|event| event["event"] == "listening"));
    assert_eq!(first_events.last().unwrap()["reason"], "duration_elapsed");
    let original = identity_frame(&path);
    assert!(!directory.path().join(".transport.key.pending").exists());

    // The first child has exited; this is a new OS process, not a redial.
    let second = run(&args);
    assert!(second.status.success(), "persistent identity restart failed: {}", second.status);
    assert!(second.stderr.is_empty());
    let second_events = events(&second);
    persistent_transport_only(&second_events[0]);
    assert_eq!(second_events[0]["peer_id"], first_events[0]["peer_id"]);
    assert!(second_events.iter().any(|event| event["event"] == "listening"));
    assert_eq!(second_events.last().unwrap()["reason"], "duration_elapsed");
    let restarted = identity_frame(&path);
    assert!(original[..] == restarted[..], "restart mutated the transport key");
    assert!(!directory.path().join(".transport.key.pending").exists());
}

#[test]
fn strict_config_optional_peer_identity_matches_cli_and_preserves_ephemeral_default() {
    let directory = private_identity_directory();
    let config_path = directory.path().join("public.json");
    let key_path = directory.path().join("transport.key");
    let config = config_path.to_str().unwrap();
    let mut document = json!({
        "schema_version":1, "listen":"/ip4/127.0.0.1/tcp/0", "run_for_ms":100,
    });
    std::fs::write(&config_path, serde_json::to_vec(&document).unwrap()).unwrap();
    let ephemeral = Command::new(binary()).args(["run", "--config", config])
        .current_dir(directory.path()).output().unwrap();
    assert!(ephemeral.status.success(), "ephemeral startup failed: {}", ephemeral.status);
    assert!(ephemeral.stderr.is_empty());
    transport_only(&events(&ephemeral)[0]);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1,
        "omitting the option must not create key or stage files");
    let cli_ephemeral = Command::new(binary()).current_dir(directory.path())
        .args(["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100"])
        .output().unwrap();
    assert!(cli_ephemeral.status.success());
    transport_only(&events(&cli_ephemeral)[0]);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);

    document["peer_identity_file"] = json!(key_path);
    std::fs::write(&config_path, serde_json::to_vec(&document).unwrap()).unwrap();
    let persisted = run(&["run", "--config", config]);
    assert!(persisted.status.success(), "JSON identity opt-in failed: {}", persisted.status);
    assert!(persisted.stderr.is_empty());
    let persisted_events = events(&persisted);
    persistent_transport_only(&persisted_events[0]);
    let original = identity_frame(&key_path);
    let cli = run(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
        "--peer-identity-file", key_path.to_str().unwrap(),
    ]);
    assert!(cli.status.success(), "CLI identity opt-in failed: {}", cli.status);
    assert!(cli.stderr.is_empty());
    let cli_events = events(&cli);
    persistent_transport_only(&cli_events[0]);
    assert_eq!(cli_events[0]["peer_id"], persisted_events[0]["peer_id"]);

    let conflict_path = directory.path().join("conflict.key");
    let conflict = run(&["run", "--config", config, "--peer-identity-file", conflict_path.to_str().unwrap()]);
    assert_eq!(conflict.status.code(), Some(2));
    assert!(conflict.stdout.is_empty());
    assert!(!conflict.stderr.is_empty());
    assert!(!conflict_path.exists());
    assert!(!directory.path().join(".conflict.key.pending").exists());
    for invalid in [json!(42), json!(true), json!({"secret":"not a path"})] {
        document["peer_identity_file"] = invalid;
        std::fs::write(&config_path, serde_json::to_vec(&document).unwrap()).unwrap();
        let rejected = run(&["run", "--config", config]);
        assert_eq!(rejected.status.code(), Some(2));
        assert!(rejected.stdout.is_empty());
        assert!(!rejected.stderr.is_empty());
    }
    let final_frame = identity_frame(&key_path);
    assert!(original[..] == final_frame[..], "config rejection mutated the transport key");
    assert!(!directory.path().join(".transport.key.pending").exists());
}

#[test]
fn concurrent_initializers_use_one_winner_and_distinct_files_get_distinct_peers() {
    let directory = private_identity_directory();
    let path = directory.path().join("shared.key");
    let held = std::fs::File::open(directory.path()).unwrap();
    rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let args = ["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "500",
        "--peer-identity-file", path.to_str().unwrap()];
    let mut first = Node::start(&args);
    let mut second = Node::start(&args);
    drop(held);
    let first_started = first.event("node_started");
    let second_started = second.event("node_started");
    persistent_transport_only(&first_started);
    persistent_transport_only(&second_started);
    assert_eq!(first_started["peer_id"], second_started["peer_id"]);
    first.event("listening");
    second.event("listening");
    let winner = identity_frame(&path);
    first.event("node_stopped");
    second.event("node_stopped");
    assert!(first.exit().success() && second.exit().success());
    assert!(identity_frame(&path)[..] == winner[..], "concurrent publisher changed winner");
    assert!(!directory.path().join(".shared.key.pending").exists());
    let independent_path = directory.path().join("independent.key");
    let independent = run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
        "--peer-identity-file", independent_path.to_str().unwrap()]);
    assert!(independent.status.success());
    persistent_transport_only(&events(&independent)[0]);
    assert_ne!(events(&independent)[0]["peer_id"], first_started["peer_id"]);
    assert!(identity_frame(&independent_path)[..] != winner[..], "independent entropy duplicated key");
}

fn identity_rejected(output: &Output) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "identity failure must precede every public network event");
    assert!([b"node rejected: IdentityPath\n".as_slice(), b"node rejected: IdentityEncoding\n".as_slice(),
        b"node rejected: IdentityLock\n".as_slice(), b"node rejected: IdentityIo\n".as_slice(),
        b"node rejected: IdentityDurability\n".as_slice()].contains(&output.stderr.as_slice()),
        "identity diagnostic must be a fixed redacted category");
}

#[test]
fn malformed_final_or_stage_fails_before_network_and_preserves_bytes() {
    use std::{fs::OpenOptions, io::{Read, Write}, os::unix::fs::OpenOptionsExt};
    for stage in [false, true] {
        for kind in 0..6 {
            let directory = private_identity_directory();
            let path = directory.path().join("key");
            let artifact = directory.path().join(if stage { ".key.pending" } else { "key" });
            let mut frame = zeroize::Zeroizing::new(vec![0; match kind { 0 => 32, 1 => 64, 2 => 51, 3 => 53, _ => 52 }]);
            frame[..18].copy_from_slice(b"Z2Z_PEER_IDENTITY\0");
            frame[18..20].copy_from_slice(&[0, 1]);
            getrandom::fill(&mut frame[20..]).unwrap();
            if kind == 4 { frame[0] ^= 1; }
            if kind == 5 { frame[19] = 2; }
            let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&artifact).unwrap();
            file.write_all(&frame[..]).unwrap();
            file.sync_all().unwrap();
            drop(file);
            let output = run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
                "--peer-identity-file", path.to_str().unwrap()]);
            identity_rejected(&output);
            assert_eq!(artifact.metadata().unwrap().len(), frame.len() as u64);
            let mut retained = zeroize::Zeroizing::new(vec![0; frame.len()]);
            std::fs::File::open(&artifact).unwrap().read_exact(&mut retained[..]).unwrap();
            assert!(retained[..] == frame[..], "malformed artifact changed");
            assert_eq!(path.exists(), !stage);
        }
    }
}

#[test]
fn real_directory_and_file_locks_timeout_before_network_without_fallback() {
    use rustix::fs::FlockOperation;
    for file_lock in [false, true] {
        let directory = private_identity_directory();
        let path = directory.path().join("key");
        let original = if file_lock {
            let initialized = run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
                "--peer-identity-file", path.to_str().unwrap()]);
            assert!(initialized.status.success());
            Some(identity_frame(&path))
        } else { None };
        let held = std::fs::File::open(if file_lock { &path } else { directory.path() }).unwrap();
        rustix::fs::flock(&held, FlockOperation::NonBlockingLockExclusive).unwrap();
        let started = Instant::now();
        let output = run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
            "--peer-identity-file", path.to_str().unwrap()]);
        let elapsed = started.elapsed();
        identity_rejected(&output);
        assert!(output.stderr == b"node rejected: IdentityLock\n");
        assert!(elapsed >= Duration::from_secs(5) && elapsed < Duration::from_secs(8));
        if let Some(original) = original {
            assert!(identity_frame(&path)[..] == original[..], "lock timeout rotated key");
        } else { assert!(!path.exists()); }
        assert!(!directory.path().join(".key.pending").exists());
    }
}

#[test]
fn restrictive_child_umask_rejects_stage_without_chmod_or_deletion() {
    use std::{os::unix::fs::MetadataExt, fs::File};
    let directory = private_identity_directory();
    let path = directory.path().join("key");
    // Exec in the child shell keeps the restrictive umask local to that process;
    // positional arguments avoid interpolating even the public path into shell code.
    let mut command = Command::new("bash");
    command.args(["-c", "umask 0200; exec \"$@\"", "--"]).arg(binary());
    command.args(["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
        "--peer-identity-file", path.to_str().unwrap()]);
    identity_rejected(&command.output().unwrap());
    assert!(!path.exists());
    let stage = directory.path().join(".key.pending");
    assert_eq!(stage.metadata().unwrap().mode() & 0o7777, 0o400);
    assert_eq!(stage.metadata().unwrap().len(), 0);
    let retry = run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
        "--peer-identity-file", path.to_str().unwrap()]);
    identity_rejected(&retry);
    assert_eq!(File::open(&stage).unwrap().metadata().unwrap().mode() & 0o7777, 0o400);
}

#[test]
fn generated_transport_secret_is_absent_from_public_output_and_diagnostics() {
    use std::fmt::Write as _;
    let directory = private_identity_directory();
    let path = directory.path().join("key");
    let output = run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
        "--peer-identity-file", path.to_str().unwrap()]);
    assert!(output.status.success());
    let frame = identity_frame(&path);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let failure = run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
        "--peer-identity-file", path.to_str().unwrap()]);
    identity_rejected(&failure);
    let secret = &frame[20..];
    let mut hex = zeroize::Zeroizing::new(String::with_capacity(64));
    for byte in secret { write!(&mut *hex, "{byte:02x}").unwrap(); }
    let mut json = zeroize::Zeroizing::new(Vec::with_capacity(129));
    serde_json::to_writer(&mut *json, secret).unwrap();
    for stream in [&output.stdout, &output.stderr, &failure.stdout, &failure.stderr] {
        assert!(!stream.windows(32).any(|bytes| bytes == secret), "transport seed disclosed");
        assert!(!stream.windows(64).any(|bytes| bytes.eq_ignore_ascii_case(hex.as_bytes())), "hex seed disclosed");
        assert!(!stream.windows(json.len()).any(|bytes| bytes == &json[..]), "JSON seed disclosed");
    }
}

#[test]
fn relative_identity_path_is_bound_to_startup_working_directory() {
    let directory = private_identity_directory();
    let output = Command::new(binary()).current_dir(directory.path())
        .args(["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
            "--peer-identity-file", "relative.key"]).output().unwrap();
    assert!(output.status.success());
    persistent_transport_only(&events(&output)[0]);
    identity_frame(&directory.path().join("relative.key"));
}

#[test]
fn unsafe_identity_paths_and_artifacts_fail_before_any_network_event() {
    use std::{fs, os::unix::fs::{PermissionsExt, symlink}};
    for stage in [false, true] {
        for kind in 0..5 {
            let directory = private_identity_directory();
            let path = directory.path().join("key");
            let artifact = directory.path().join(if stage { ".key.pending" } else { "key" });
            let other = directory.path().join("other");
            match kind {
                0 => { fs::write(&artifact, b"wrong mode").unwrap(); fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644)).unwrap(); }
                1 => { fs::write(&other, b"private").unwrap(); fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap(); symlink(&other, &artifact).unwrap(); }
                2 => { fs::write(&other, b"private").unwrap(); fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap(); fs::hard_link(&other, &artifact).unwrap(); }
                3 => { rustix::fs::mknodat(rustix::fs::CWD, &artifact, rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR, 0).unwrap(); }
                _ => { fs::create_dir(&artifact).unwrap(); }
            }
            let output = run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
                "--peer-identity-file", path.to_str().unwrap()]);
            identity_rejected(&output);
            assert!(fs::symlink_metadata(&artifact).is_ok());
            if stage { assert!(!path.exists()); }
        }
    }
    let directory = private_identity_directory();
    let child = directory.path().join("child");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = directory.path().join("alias");
    symlink(&child, &alias).unwrap();
    for path in [directory.path().join(".key"), child.join("../key"), directory.path().join("missing/key"),
        alias.join("key"), PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("key"), binary().parent().unwrap().join("key")]
    {
        identity_rejected(&run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
            "--peer-identity-file", path.to_str().unwrap()]));
    }
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770)).unwrap();
    identity_rejected(&run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
        "--peer-identity-file", child.join("key").to_str().unwrap()]));
    assert!(!child.join("key").exists());
}

#[test]
fn complete_stage_process_resume_and_final_precedence_preserve_selected_key() {
    let directory = private_identity_directory();
    let path = directory.path().join("key");
    let stage = directory.path().join(".key.pending");
    let args = ["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
        "--peer-identity-file", path.to_str().unwrap()];
    let first = run(&args);
    assert!(first.status.success());
    let first_peer = events(&first)[0]["peer_id"].clone();
    let original = identity_frame(&path);
    // Test-owned interrupted publication: move the generated final back to its stage.
    std::fs::rename(&path, &stage).unwrap();
    let resumed = run(&args);
    assert!(resumed.status.success());
    assert_eq!(events(&resumed)[0]["peer_id"], first_peer);
    assert!(!stage.exists());
    assert!(identity_frame(&path)[..] == original[..], "stage resume changed chosen key");
    std::fs::write(&stage, b"unrecognized interrupted bytes").unwrap();
    let authoritative = run(&args);
    assert!(authoritative.status.success());
    assert_eq!(events(&authoritative)[0]["peer_id"], first_peer);
    assert!(identity_frame(&path)[..] == original[..], "leftover stage rotated final");
    assert!(std::fs::read(&stage).unwrap() == b"unrecognized interrupted bytes");
}

#[test]
fn finite_no_peer_run_is_honest_and_terminates_without_background_workers() {
    let mut node = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--max-peers", "1", "--run-for-ms", "200",
    ]);
    transport_only(&node.event("node_started"));
    let address = node.event("listening")["address"].as_str().unwrap().to_owned();
    assert!(address.starts_with("/ip4/127.0.0.1/tcp/"));
    assert!(address.contains("/p2p/"));
    let stopped = node.event("node_stopped");
    assert_eq!(stopped["reason"], "duration_elapsed");
    assert_eq!(stopped["connected_peers"], 0);
    assert!(!node.seen.iter().any(|event| event["event"] == "peer_connected" || event["event"] == "peer_ping"));
    assert!(node.exit().success());
}

#[test]
#[cfg(unix)]
fn two_loopback_processes_authenticate_identify_ping_disconnect_and_handle_ctrl_c() {
    let mut listener = Node::start(&["run", "--listen", "/ip4/127.0.0.1/tcp/0"]);
    let listener_started = listener.event("node_started");
    transport_only(&listener_started);
    let address = listener.event("listening")["address"].as_str().unwrap().to_owned();
    let mut dialer = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &address, "--run-for-ms", "2500",
    ]);
    let dialer_started = dialer.event("node_started");
    transport_only(&dialer_started);
    assert_ne!(listener_started["peer_id"], dialer_started["peer_id"]);
    for (node, expected) in [
        (&mut listener, &dialer_started["peer_id"]),
        (&mut dialer, &listener_started["peer_id"]),
    ] {
        assert_eq!(node.event("peer_connected")["peer_id"], *expected);
        assert_eq!(node.event("peer_identified")["peer_id"], *expected);
        let ping = node.event("peer_ping");
        assert_eq!(ping["peer_id"], *expected);
        assert!(ping["rtt_ms"].as_u64().is_some());
    }
    assert_eq!(dialer.event("node_stopped")["reason"], "duration_elapsed");
    assert!(dialer.exit().success());
    assert_eq!(listener.event("peer_disconnected")["peer_id"], dialer_started["peer_id"]);
    listener.interrupt();
    let stopped = listener.event("node_stopped");
    assert_eq!(stopped["reason"], "ctrl_c");
    assert_eq!(stopped["connected_peers"], 0);
    assert!(listener.exit().success());
}

#[test]
#[cfg(unix)]
fn peer_cap_keeps_existing_peer_and_never_admits_a_second_connection() {
    let mut listener = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--max-peers", "1",
    ]);
    let address = listener.event("listening")["address"].as_str().unwrap().to_owned();
    let mut first = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &address,
    ]);
    let first_peer = first.event("node_started")["peer_id"].clone();
    assert_eq!(listener.event("peer_connected")["peer_id"], first_peer);
    listener.event("peer_ping");
    let mut extra = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &address, "--run-for-ms", "1000",
    ]);
    extra.event("node_stopped");
    assert!(extra.exit().success());
    first.interrupt();
    assert_eq!(first.event("node_stopped")["reason"], "ctrl_c");
    assert!(first.exit().success());
    assert_eq!(listener.event("peer_disconnected")["peer_id"], first_peer);
    // Freeing an active slot cannot grow the process's bounded identity cohort.
    let mut unfamiliar = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &address, "--run-for-ms", "1000",
    ]);
    unfamiliar.event("node_stopped");
    assert!(unfamiliar.exit().success());
    assert_eq!(listener.event("peer_rejected")["reason"], "peer_capacity");
    listener.interrupt();
    listener.event("node_stopped");
    assert!(listener.exit().success());
    let admitted: Vec<_> = listener.seen.iter()
        .filter(|event| event["event"] == "peer_connected").collect();
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted[0]["peer_id"], first_peer);
}

#[test]
fn expected_peer_id_mismatch_never_becomes_an_authenticated_connection() {
    let unrelated = run(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100",
    ]);
    assert!(unrelated.status.success());
    let wrong_peer = events(&unrelated)[0]["peer_id"].as_str().unwrap().to_owned();
    let mut listener = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "4000",
    ]);
    let address = listener.event("listening")["address"].as_str().unwrap().to_owned();
    let (tcp, _) = address.rsplit_once("/p2p/").unwrap();
    let wrong_address = format!("{tcp}/p2p/{wrong_peer}");
    let mut dialer = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &wrong_address, "--run-for-ms", "1000",
    ]);
    assert_eq!(dialer.event("dial_failed")["reason"], "peer_id_mismatch");
    dialer.event("node_stopped");
    assert!(dialer.exit().success());
    assert!(!dialer.seen.iter().any(|event| event["event"] == "peer_connected"));
}

#[test]
fn occupied_listen_address_exits_with_transport_error_not_success() {
    let occupied = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = format!("/ip4/127.0.0.1/tcp/{}", occupied.local_addr().unwrap().port());
    let output = run(&["run", "--listen", &address, "--run-for-ms", "100"]);
    assert_eq!(output.status.code(), Some(1), "{:?}", output);
    assert!(!output.stderr.is_empty());
    assert!(!events(&output).iter().any(|event| event["event"] == "listening"));
}

#[test]
#[cfg(target_os = "linux")]
fn undrained_full_output_pipe_fails_without_hanging_or_torn_json() {
    use rustix::{fs::OFlags, pipe::{PipeFlags, pipe_with}};
    let (reader, writer) = pipe_with(PipeFlags::NONBLOCK | PipeFlags::CLOEXEC).unwrap();
    let fill = [b'x'; 4096];
    let mut filled = 0;
    loop {
        match rustix::io::write(&writer, &fill) {
            Ok(count) => filled += count,
            Err(rustix::io::Errno::AGAIN) => break,
            other => panic!("cannot fill owned test pipe: {other:?}"),
        }
    }
    assert!(filled >= fill.len());
    // The child must make its inherited blocking stdout nonblocking itself.
    rustix::fs::fcntl_setfl(&writer, OFlags::WRONLY).unwrap();
    let mut child = Command::new(binary())
        .args(["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100"])
        .stdout(Stdio::from(writer)).stderr(Stdio::null()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("undrained stdout prevented bounded transport exit");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(1));
    let mut drained = 0;
    let mut buffer = [0; 4096];
    loop {
        match rustix::io::read(&reader, &mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                assert!(buffer[..count].iter().all(|byte| *byte == b'x'));
                drained += count;
            }
            Err(rustix::io::Errno::AGAIN) => break,
            other => panic!("cannot drain owned test pipe: {other:?}"),
        }
    }
    assert_eq!(drained, filled, "a full pipe must not receive partial NDJSON");
}

#[test]
fn merged_full_output_pipe_cannot_block_error_exit() {
    use rustix::{fs::OFlags, pipe::{PipeFlags, pipe_with}};
    let (reader, writer) = pipe_with(PipeFlags::NONBLOCK | PipeFlags::CLOEXEC).unwrap();
    let fill = [b'x'; 4096];
    let mut filled = 0;
    loop {
        match rustix::io::write(&writer, &fill) {
            Ok(count) => filled += count,
            Err(rustix::io::Errno::AGAIN) => break,
            other => panic!("cannot fill owned merged pipe: {other:?}"),
        }
    }
    rustix::fs::fcntl_setfl(&writer, OFlags::WRONLY).unwrap();
    let stderr = rustix::io::dup(&writer).unwrap();
    let mut child = Command::new(binary())
        .args(["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "100"])
        .stdout(Stdio::from(writer)).stderr(Stdio::from(stderr)).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("merged stdout/stderr prevented bounded transport error exit");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(1));
    let mut buffer = [0; 4096];
    let mut drained = 0;
    loop {
        match rustix::io::read(&reader, &mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                assert!(buffer[..count].iter().all(|byte| *byte == b'x'));
                drained += count;
            }
            Err(rustix::io::Errno::AGAIN) => break,
            other => panic!("cannot drain owned merged pipe: {other:?}"),
        }
    }
    assert_eq!(drained, filled, "full pipe must receive neither partial events nor diagnostics");
}

#[test]
fn healthy_authenticated_peer_survives_idle_window_until_explicit_shutdown() {
    let mut listener = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "45000",
    ]);
    let address = listener.event("listening")["address"].as_str().unwrap().to_owned();
    let mut dialer = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &address, "--run-for-ms", "45000",
    ]);
    listener.event("peer_connected");
    dialer.event("peer_connected");
    listener.event("peer_ping");
    dialer.event("peer_ping");
    // A real process-clock boundary crosses the former 30-second idle timeout.
    // Continue consuming actual events; no test-only production timeout switch.
    let started = Instant::now();
    let mut late_ping = false;
    while started.elapsed() < Duration::from_secs(36) {
        let event = listener.receiver.as_ref().unwrap()
            .recv_timeout(Duration::from_secs(6)).expect("healthy peer stopped progressing")
            .expect("transport event must decode");
        assert_ne!(event["event"], "peer_disconnected", "healthy peer was dropped before caller shutdown");
        assert_ne!(event["event"], "node_stopped");
        if event["event"] == "peer_ping" && started.elapsed() > Duration::from_secs(32) {
            late_ping = true;
        }
        listener.seen.push(event);
    }
    assert!(late_ping, "no successful ping after the former idle window");
    dialer.interrupt();
    assert_eq!(dialer.event("node_stopped")["reason"], "ctrl_c");
    assert!(dialer.exit().success());
    listener.event("peer_disconnected");
    listener.interrupt();
    assert_eq!(listener.event("node_stopped")["reason"], "ctrl_c");
    assert!(listener.exit().success());
}

const DKG_CHAIN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DKG_DEPLOYMENT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DKG_J: &str = "00017f";

fn dkg_identity(path: &std::path::Path) -> String {
    let output = run(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--headless",
        "--peer-identity-file", path.to_str().unwrap(), "--run-for-ms", "50",
    ]);
    assert!(output.status.success(), "{output:?}");
    events(&output)[0]["peer_id"].as_str().unwrap().to_owned()
}

fn dkg_client(
    address: &str, expected: &str, identity: Option<&std::path::Path>,
    j: &str, pool: &str, chain: &str, deployment: &str,
) -> Output {
    let mut args = vec![
        "dkg-handshake", "--address", address, "--peer-id", expected, "--lane-id", "1",
        "--dkg-j-params", j, "--dkg-pool-id", pool,
        "--dkg-chain-context", chain, "--dkg-deployment-context", deployment,
    ];
    if let Some(path) = identity {
        args.extend(["--peer-identity-file", path.to_str().unwrap()]);
    }
    run(&args)
}

fn stop_dkg_node(node: &mut Node) {
    node.interrupt();
    assert_eq!(node.event("node_stopped")["reason"], "ctrl_c");
    assert!(node.exit().success());
    while let Ok(event) = node.receiver.as_ref().unwrap().try_recv() {
        node.seen.push(event.expect("public DKG event must decode"));
    }
}

#[test]
fn selected_peer_real_dkg_processes_agree_and_do_not_persist_ceremony_shares() {
    let directory = private_identity_directory();
    let path = directory.path().join("initiator.identity");
    let selected = dkg_identity(&path);
    let before = identity_frame(&path);
    let mut node = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--headless",
        "--dkg-peer", &selected, "--dkg-j-params", DKG_J, "--dkg-pool-id", "0",
        "--dkg-chain-context", DKG_CHAIN, "--dkg-deployment-context", DKG_DEPLOYMENT,
    ]);
    let peer = node.event("node_started")["peer_id"].as_str().unwrap().to_owned();
    let address = node.event("listening")["address"].as_str().unwrap().to_owned();
    let output = dkg_client(&address, &peer, Some(&path), DKG_J, "0", DKG_CHAIN, DKG_DEPLOYMENT);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let client = events(&output);
    assert_eq!(client.len(), 1, "client must print only the public completion");
    let responder = node.event("dkg_completed");
    assert_eq!(client[0]["event"], "dkg_completed");
    assert_eq!(client[0]["commit"], responder["commit"]);
    assert_eq!(client[0]["peer_id"], peer);
    assert_eq!(responder["peer_id"], selected);
    for completion in [&client[0], &responder] {
        assert_eq!(completion["ephemeral"], true);
        assert_eq!(completion["financial_authority"], false);
        let commit = completion["commit"].as_str().unwrap();
        assert_eq!(commit.len(), 64);
        assert!(commit.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(completion.get("share").is_none());
        assert!(completion.get("package").is_none());
    }
    stop_dkg_node(&mut node);
    let requests: Vec<_> = node.seen.iter().filter(|event| event["event"] == "session_request")
        .map(|event| (event["kind"].as_u64().unwrap(), event["seq"].as_u64().unwrap())).collect();
    assert_eq!(requests, [(0, 0), (9, 1), (10, 2), (11, 3), (12, 4)],
        "terminal ACK must never trigger an ACK request");
    assert_eq!(&*before, &*identity_frame(&path), "ceremony must never rotate the transport identity");
    let files: Vec<_> = std::fs::read_dir(directory.path()).unwrap()
        .map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(files, [path.file_name().unwrap().to_os_string()], "no DKG share/package custody files");
}

#[test]
fn mismatched_frozen_dkg_inputs_never_complete() {
    let directory = private_identity_directory();
    let path = directory.path().join("initiator.identity");
    let selected = dkg_identity(&path);
    for (j, pool, chain, deployment) in [
        ("000180", "0", DKG_CHAIN, DKG_DEPLOYMENT),
        (DKG_J, "1", DKG_CHAIN, DKG_DEPLOYMENT),
        (DKG_J, "0", DKG_DEPLOYMENT, DKG_DEPLOYMENT),
        (DKG_J, "0", DKG_CHAIN, DKG_CHAIN),
    ] {
        let mut node = Node::start(&[
            "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--headless",
            "--dkg-peer", &selected, "--dkg-j-params", DKG_J, "--dkg-pool-id", "0",
            "--dkg-chain-context", DKG_CHAIN, "--dkg-deployment-context", DKG_DEPLOYMENT,
        ]);
        let peer = node.event("node_started")["peer_id"].as_str().unwrap().to_owned();
        let address = node.event("listening")["address"].as_str().unwrap().to_owned();
        let output = dkg_client(&address, &peer, Some(&path), j, pool, chain, deployment);
        assert!(!output.status.success(), "{output:?}");
        assert!(events(&output).iter().all(|event| event["event"] != "dkg_completed"));
        stop_dkg_node(&mut node);
        assert!(node.seen.iter().all(|event| event["event"] != "dkg_completed"));
    }
}

#[test]
fn disabled_or_unselected_dkg_rejects_but_normal_hello_stays_usable() {
    let directory = private_identity_directory();
    let path = directory.path().join("initiator.identity");
    let selected = dkg_identity(&path);
    let other_path = directory.path().join("other.identity");
    let other = dkg_identity(&other_path);
    for (policy, identity) in [(None, Some(path.as_path())), (Some(other.as_str()), Some(path.as_path())), (Some(selected.as_str()), None)] {
        let mut args = vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--headless"];
        if let Some(peer) = policy {
            args.extend([
                "--dkg-peer", peer, "--dkg-j-params", DKG_J, "--dkg-pool-id", "0",
                "--dkg-chain-context", DKG_CHAIN, "--dkg-deployment-context", DKG_DEPLOYMENT,
            ]);
        }
        let mut node = Node::start(&args);
        let peer = node.event("node_started")["peer_id"].as_str().unwrap().to_owned();
        let address = node.event("listening")["address"].as_str().unwrap().to_owned();
        let output = dkg_client(&address, &peer, identity, DKG_J, "0", DKG_CHAIN, DKG_DEPLOYMENT);
        assert!(!output.status.success(), "{output:?}");
        assert!(events(&output).iter().all(|event| event["event"] != "dkg_completed"));
        let hello = run(&["send-hello", "--address", &address, "--peer-id", &peer]);
        assert!(hello.status.success(), "normal Hello must not need DKG opt-in: {hello:?}");
        stop_dkg_node(&mut node);
        assert!(node.seen.iter().all(|event| event["event"] != "dkg_completed"));
    }
}

#[test]
fn dkg_cli_and_json_reject_partial_unbounded_and_unbound_inputs() {
    let identity = libp2p::identity::Keypair::generate_ed25519();
    let peer = identity.public().to_peer_id().to_string();
    let address = format!("/ip4/127.0.0.1/tcp/9/p2p/{peer}");
    let directory = tempfile::tempdir().unwrap();
    let mut public_hash = vec![0x12, 0x20];
    public_hash.extend_from_slice(&[7; 32]);
    let non_ed25519 = libp2p::PeerId::from_bytes(&public_hash).unwrap().to_string();
    let non_ed_address = format!("/ip4/127.0.0.1/tcp/9/p2p/{non_ed25519}");
    let path = directory.path().join("dkg.json");
    let valid = json!({
        "schema_version":1, "listen":"/ip4/127.0.0.1/tcp/0", "run_for_ms":50,
        "dkg_peer":peer, "dkg_j_params":DKG_J, "dkg_pool_id":0,
        "dkg_chain_context":DKG_CHAIN, "dkg_deployment_context":DKG_DEPLOYMENT,
    });
    for field in ["dkg_peer", "dkg_j_params", "dkg_pool_id", "dkg_chain_context", "dkg_deployment_context"] {
        let mut invalid = valid.clone();
        invalid.as_object_mut().unwrap().remove(field);
        std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        rejected(&["run", "--config", path.to_str().unwrap()]);
    }
    for (field, value) in [
        ("dkg_j_params", json!("")), ("dkg_j_params", json!("0")),
        ("dkg_j_params", json!("gg")), ("dkg_j_params", json!("00".repeat(257))),
        ("dkg_pool_id", json!(256)), ("dkg_chain_context", json!("00".repeat(32))),
        ("dkg_chain_context", json!("11".repeat(31))),
        ("dkg_deployment_context", json!("00".repeat(32))), ("dkg_peer", json!("x".repeat(257))),
        ("dkg_peer", json!(non_ed25519)),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        rejected(&["run", "--config", path.to_str().unwrap()]);
    }
    let mut boundary = valid.clone();
    boundary["dkg_j_params"] = json!("00".repeat(256));
    boundary["dkg_pool_id"] = json!(255);
    std::fs::write(&path, serde_json::to_vec(&boundary).unwrap()).unwrap();
    let output = run(&["run", "--config", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    rejected(&["run", "--config", path.to_str().unwrap(), "--dkg-peer", &peer]);
    for (flag, value) in [
        ("--dkg-peer", peer.as_str()), ("--dkg-j-params", DKG_J), ("--dkg-pool-id", "0"),
        ("--dkg-chain-context", DKG_CHAIN), ("--dkg-deployment-context", DKG_DEPLOYMENT),
    ] {
        rejected(&["run", "--config", path.to_str().unwrap(), flag, value]);
    }
    rejected(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dkg-peer", &peer]);
    rejected(&["dkg-handshake", "--address", &address]);
    let other = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id().to_string();
    let output = dkg_client(&address, &other, None, DKG_J, "0", DKG_CHAIN, DKG_DEPLOYMENT);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "inconsistent expected PeerId must not dial or emit success");
    let output = dkg_client(&non_ed_address, &non_ed25519, None, DKG_J, "0", DKG_CHAIN, DKG_DEPLOYMENT);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "hashed/non-Ed25519 expected peers are unsupported before dial");
    let valid_args = vec![
        "dkg-handshake", "--address", address.as_str(), "--peer-id", peer.as_str(), "--lane-id", "1",
        "--dkg-j-params", DKG_J, "--dkg-pool-id", "0",
        "--dkg-chain-context", DKG_CHAIN, "--dkg-deployment-context", DKG_DEPLOYMENT,
    ];
    for missing in ["--address", "--peer-id", "--lane-id", "--dkg-j-params", "--dkg-pool-id", "--dkg-chain-context", "--dkg-deployment-context"] {
        let mut incomplete = valid_args.clone();
        let position = incomplete.iter().position(|flag| *flag == missing).unwrap();
        incomplete.drain(position..position + 2);
        rejected(&incomplete);
    }
    for (flag, value) in [
        ("--lane-id", "0"), ("--lane-id", "6"), ("--dkg-pool-id", "256"),
        ("--address", "/dns4/localhost/tcp/9"), ("--dkg-j-params", ""), ("--dkg-j-params", "0"),
        ("--dkg-j-params", "gg"), ("--dkg-chain-context", "00"), ("--dkg-deployment-context", "00"),
    ] {
        let mut invalid = valid_args.clone();
        let position = invalid.iter().position(|candidate| *candidate == flag).unwrap();
        invalid[position + 1] = value;
        let output = run(&invalid);
        assert!(!output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty(), "invalid inputs must fail before dialing");
    }
}
