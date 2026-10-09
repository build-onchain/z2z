//! Real seeded FIND_NODE processes only; no records, wallets, SQL or financial claims.
#![cfg(target_os = "linux")]
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_z2z-node"))
        .args(args).output().expect("the runnable z2z-node executable must exist")
}

fn events(output: &Output) -> Vec<Value> {
    std::str::from_utf8(&output.stdout).unwrap().lines()
        .map(|line| serde_json::from_str(line).expect("public node output must be NDJSON"))
        .collect()
}

fn started(event: &Value, enabled: bool) {
    assert_eq!(event["event"], "node_started");
    assert_eq!(event["schema_version"], 1);
    assert_eq!(event["identity"], "ephemeral_transport");
    assert_eq!(event["transport_only"], true);
    assert_eq!(event["peer_discovery_enabled"], enabled);
    for flag in [
        "persistent_identity", "discovery_ready", "gossip_ready", "trading_ready",
        "backing_ready", "proof_ready", "recovery_ready",
    ] {
        assert_eq!(event[flag], false, "peer discovery must not imply {flag}");
    }
}

fn rejected(args: &[&str]) {
    let output = run(args);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "invalid discovery configuration started a node");
    assert!(!output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
        "unknown discovery flags are not evidence of policy enforcement: {output:?}");
}

struct Node {
    child: Child,
    receiver: Option<Receiver<Result<Value, String>>>,
    reader: Option<thread::JoinHandle<()>>,
    seen: Vec<Value>,
}

impl Node {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_z2z-node"))
            .args(args).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::sync_channel(128);
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let event = line.map_err(|error| error.to_string())
                    .and_then(|line| serde_json::from_str(&line).map_err(|error| error.to_string()));
                if sender.send(event).is_err() { break; }
            }
        });
        Self { child, receiver: Some(receiver), reader: Some(reader), seen: Vec::new() }
    }

    fn next(&mut self, timeout: Duration) -> Value {
        let event = self.receiver.as_ref().unwrap().recv_timeout(timeout)
            .unwrap_or_else(|error| panic!("missing node event: {error}; observed {:?}", self.seen))
            .expect("public node event must decode");
        self.seen.push(event.clone());
        event
    }

    fn event(&mut self, name: &str, peer: Option<&str>) -> Value {
        let matches = |event: &Value| event["event"] == name
            && peer.is_none_or(|peer| event["peer_id"] == peer);
        if let Some(event) = self.seen.iter().find(|event| matches(event)) {
            return event.clone();
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let event = self.next(deadline.saturating_duration_since(Instant::now()));
            if matches(&event) { return event; }
        }
    }

    fn drain(&mut self) {
        while let Ok(event) = self.receiver.as_ref().unwrap().try_recv() {
            self.seen.push(event.expect("public node event must decode"));
        }
    }

    fn exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() { return status; }
            assert!(Instant::now() < deadline, "node did not exit after shutdown");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(&mut self) {
        assert!(Command::new("kill").args(["-INT", &self.child.id().to_string()])
            .status().unwrap().success());
        let stopped = self.event("node_stopped", None);
        assert_eq!(stopped["reason"], "ctrl_c");
        assert_eq!(stopped["connected_peers"], 0);
        assert!(self.exit().success());
        self.drain();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.receiver.take();
        if let Some(reader) = self.reader.take() { let _ = reader.join(); }
    }
}

#[test]
fn discovery_three_process_find_node_authenticates_target_and_survives_seed_shutdown() {
    let mut target = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery", "--discovery-loopback",
        "--max-peers", "2", "--run-for-ms", "90000",
    ]);
    let target_started = target.event("node_started", None);
    started(&target_started, true);
    let target_id = target_started["peer_id"].as_str().unwrap();
    let target_address = target.event("listening", None)["address"].as_str().unwrap().to_owned();
    let mut seed = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery", "--discovery-loopback",
        "--max-peers", "2", "--dial", &target_address, "--run-for-ms", "90000",
    ]);
    let seed_started = seed.event("node_started", None);
    started(&seed_started, true);
    let seed_id = seed_started["peer_id"].as_str().unwrap();
    let seed_address = seed.event("listening", None)["address"].as_str().unwrap().to_owned();
    seed.event("peer_connected", Some(target_id));
    assert_eq!(seed.event("peer_identified", Some(target_id))["protocol_matches"], true);
    seed.event("peer_ping", Some(target_id));

    // A knows S's dial address and T's identity ONLY. No T address/config file is passed to A.
    let mut seeker = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery", "--discovery-loopback",
        "--max-peers", "2", "--dial", &seed_address, "--find-peer", target_id,
        "--run-for-ms", "90000",
    ]);
    let seeker_started = seeker.event("node_started", None);
    started(&seeker_started, true);
    let seeker_id = seeker_started["peer_id"].as_str().unwrap();
    assert_ne!(seeker_id, seed_id);
    assert_ne!(seeker_id, target_id);
    seeker.event("peer_connected", Some(seed_id));
    assert_eq!(seeker.event("peer_identified", Some(seed_id))["protocol_matches"], true);
    seeker.event("peer_query_started", Some(target_id));
    let candidate = seeker.event("peer_discovered", Some(target_id));
    assert_eq!(candidate["address"], target_address);
    seeker.event("peer_query_result", Some(target_id));
    for (node, expected) in [(&mut seeker, target_id), (&mut target, seeker_id)] {
        node.event("peer_connected", Some(expected));
        assert_eq!(node.event("peer_identified", Some(expected))["protocol_matches"], true);
        assert!(node.event("peer_ping", Some(expected))["rtt_ms"].as_u64().is_some());
    }
    let candidate_index = seeker.seen.iter().position(|event|
        event["event"] == "peer_discovered" && event["peer_id"] == target_id).unwrap();
    let connection_index = seeker.seen.iter().position(|event|
        event["event"] == "peer_connected" && event["peer_id"] == target_id).unwrap();
    assert!(candidate_index < connection_index, "lookup candidate is not Noise authentication");
    let query_index = seeker.seen.iter().position(|event| event["event"] == "peer_query_started").unwrap();
    let seed_identified_index = seeker.seen.iter().position(|event|
        event["event"] == "peer_identified" && event["peer_id"] == seed_id).unwrap();
    assert!(seed_identified_index < query_index, "query must wait for authenticated seed protocol confirmation");

    seed.stop();
    seeker.event("peer_disconnected", Some(seed_id));
    target.event("peer_disconnected", Some(seed_id));
    seeker.drain();
    target.drain();
    let deadline = Instant::now() + Duration::from_secs(15);
    // Consume a fresh successful ping after S has exited, not a cached pre-stop event.
    loop {
        let event = seeker.next(deadline.saturating_duration_since(Instant::now()));
        assert_ne!(event["event"], "node_stopped");
        assert!(!(event["event"] == "peer_disconnected" && event["peer_id"] == target_id));
        assert_ne!(event["event"], "peer_ping_failed");
        if event["event"] == "peer_ping" && event["peer_id"] == target_id {
            assert!(event["rtt_ms"].as_u64().is_some());
            break;
        }
    }
    let target_mark = target.seen.len();
    target.drain();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let event = target.next(deadline.saturating_duration_since(Instant::now()));
        assert_ne!(event["event"], "node_stopped");
        assert_ne!(event["event"], "peer_ping_failed");
        assert!(!(event["event"] == "peer_disconnected" && event["peer_id"] == seeker_id));
        if event["event"] == "peer_ping" && event["peer_id"] == seeker_id {
            assert!(event["rtt_ms"].as_u64().is_some());
            break;
        }
    }
    assert!(!target.seen[target_mark..].iter().any(|event| event["event"] == "peer_ping_failed"
        || (event["event"] == "peer_disconnected" && event["peer_id"] == seeker_id)));
    seeker.stop();
    target.event("peer_disconnected", Some(seeker_id));
    target.stop();
    for node in [&seed, &target] {
        assert!(!node.seen.iter().any(|event| event["event"].as_str().is_some_and(|name|
            name.starts_with("peer_query_"))), "serving FIND_NODE must not initiate automatic queries");
    }
    assert_eq!(seeker.seen.iter().filter(|event| event["event"] == "peer_query_started").count(), 1);
    assert_eq!(seeker.seen.iter().filter(|event| event["event"] == "peer_query_result").count(), 1);
    assert!(!seeker.seen.iter().any(|event| event["event"] == "peer_query_failure"));
}

#[test]
fn discovery_is_opt_in_and_idle_enabled_node_does_not_start_automatic_queries() {
    for (args, enabled) in [
        (vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "200"], false),
        (vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery",
            "--discovery-loopback", "--run-for-ms", "200"], true),
    ] {
        let output = run(&args);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
        let observed = events(&output);
        started(&observed[0], enabled);
        assert_eq!(observed.last().unwrap()["reason"], "duration_elapsed");
        assert!(!observed.iter().any(|event| event["event"] == "peer_discovered"
            || event["event"].as_str().is_some_and(|name| name.starts_with("peer_query_"))));
    }
}

#[test]
fn discovery_public_config_preserves_defaults_and_rejects_ambiguous_controls() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public discovery config.json");
    let config_path = path.to_str().unwrap();
    let old = json!({"schema_version":1,"listen":"/ip4/127.0.0.1/tcp/0","run_for_ms":100});
    let mut configured = old.clone();
    configured["peer_discovery"] = json!(true);
    configured["discovery_loopback"] = json!(true);
    configured["find_peer"] = Value::Null;
    for (config, enabled) in [(&old, false), (&configured, true)] {
        std::fs::write(&path, serde_json::to_vec(config).unwrap()).unwrap();
        let output = run(&["run", "--config", config_path]);
        assert!(output.status.success(), "{output:?}");
        started(&events(&output)[0], enabled);
    }
    for (field, value) in [
        ("peer_discovery", json!("true")), ("discovery_loopback", json!(1)),
        ("find_peer", json!("invalid-peer")), ("max_peers", json!(0)),
        ("max_peers", json!(65)),
    ] {
        let mut invalid = configured.clone();
        invalid[field] = value;
        std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        rejected(&["run", "--config", config_path]);
    }
    let mut disabled = configured.clone();
    disabled["peer_discovery"] = json!(false);
    std::fs::write(&path, serde_json::to_vec(&disabled).unwrap()).unwrap();
    rejected(&["run", "--config", config_path]);
    std::fs::write(&path, serde_json::to_vec(&configured).unwrap()).unwrap();
    for flags in [vec!["--peer-discovery"], vec!["--discovery-loopback"],
        vec!["--find-peer", "invalid-peer"]] {
        let mut args = vec!["run", "--config", config_path];
        args.extend(flags);
        rejected(&args);
    }
}

#[test]
fn discovery_rejects_disabled_invalid_and_nonpublic_seed_addresses_before_start() {
    let baseline = run(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--run-for-ms", "50"]);
    assert!(baseline.status.success());
    let observed = events(&baseline);
    let peer = observed[0]["peer_id"].as_str().unwrap();
    rejected(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--find-peer", peer]);
    rejected(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--discovery-loopback"]);
    rejected(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery", "--find-peer", "bad"]);
    rejected(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery",
        "--discovery-loopback", "--find-peer", peer]);
    for (host, allow_loopback) in [
        ("/ip4/127.0.0.1", false), ("/ip6/::1", false),
        ("/ip4/10.0.0.1", false), ("/ip4/169.254.1.1", false),
        ("/ip4/0.0.0.0", false), ("/ip4/224.0.0.1", false),
        ("/ip4/255.255.255.255", false), ("/ip6/fc00::1", false),
        ("/ip6/fe80::1", false), ("/ip6/::", false), ("/ip6/ff02::1", false),
        ("/ip4/10.0.0.1", true), ("/ip6/fc00::1", true),
        ("/ip6/::ffff:127.0.0.1", false), ("/ip6/::ffff:10.0.0.1", true),
        ("/ip6/::ffff:169.254.1.1", true), ("/ip6/::ffff:255.255.255.255", true),
        ("/dns4/localhost", true),
    ] {
        let address = format!("{host}/tcp/9/p2p/{peer}");
        let mut args = vec!["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery",
            "--dial", &address, "--run-for-ms", "100"];
        if allow_loopback { args.push("--discovery-loopback"); }
        rejected(&args);
    }
}

#[test]
fn discovery_candidate_limit_counts_initial_seed_and_never_truncates_to_success() {
    let mut target = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery", "--discovery-loopback",
    ]);
    let target_started = target.event("node_started", None);
    let target_id = target_started["peer_id"].as_str().unwrap();
    let target_address = target.event("listening", None)["address"].as_str().unwrap().to_owned();
    let mut seed = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery", "--discovery-loopback",
        "--max-peers", "2", "--dial", &target_address,
    ]);
    let seed_started = seed.event("node_started", None);
    let seed_id = seed_started["peer_id"].as_str().unwrap();
    let seed_address = seed.event("listening", None)["address"].as_str().unwrap().to_owned();
    seed.event("peer_identified", Some(target_id));
    let mut seeker = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--peer-discovery", "--discovery-loopback",
        "--max-peers", "1", "--dial", &seed_address, "--find-peer", target_id,
    ]);
    started(&seeker.event("node_started", None), true);
    seeker.event("peer_connected", Some(seed_id));
    seeker.event("peer_query_started", Some(target_id));
    assert_eq!(seeker.event("peer_query_failure", Some(target_id))["reason"], "resource_limit");
    seeker.event("peer_ping", Some(seed_id));
    seeker.stop();
    assert!(!seeker.seen.iter().any(|event| event["event"] == "peer_query_result"
        || event["event"] == "peer_discovered"
        || (event["event"] == "peer_connected" && event["peer_id"] == target_id)));
    assert_eq!(seeker.seen.iter().filter(|event| event["event"] == "peer_query_started").count(), 1);
    seed.stop();
    target.stop();
}
