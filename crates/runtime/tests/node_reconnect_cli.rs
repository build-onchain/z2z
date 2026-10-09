//! Real transport outage/recovery only: forwarding never terminates Noise or changes identity.
#![cfg(target_os = "linux")]
use serde_json::Value;
use std::{
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, sync::mpsc as async_mpsc, task::JoinSet};

struct Node {
    child: Child,
    receiver: Option<Receiver<Result<Value, String>>>,
    reader: Option<thread::JoinHandle<()>>,
    seen: Vec<Value>,
}

impl Node {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_z2z-node"))
            .args(args).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()
            .expect("the runnable z2z-node executable must exist");
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
        let result = self.receiver.as_ref().unwrap().recv_timeout(timeout);
        let event = match result {
            Ok(event) => event.expect("public transport event must decode"),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let status = self.exit();
                panic!("runnable z2z-node exited with {status} while awaiting an event; observed {:?}", self.seen);
            }
            Err(error) => panic!("missing node event: {error}; observed {:?}", self.seen),
        };
        assert!(self.seen.len() < 256, "transport event history exceeded test bound");
        self.seen.push(event.clone());
        event
    }

    fn event_after(&mut self, mark: usize, name: &str, peer: Option<&str>) -> Value {
        let matches = |event: &Value| event["event"] == name
            && peer.is_none_or(|peer| event["peer_id"] == peer);
        if let Some(event) = self.seen[mark..].iter().find(|event| matches(event)) {
            return event.clone();
        }
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let event = self.next(deadline.saturating_duration_since(Instant::now()));
            if matches(&event) { return event; }
        }
    }

    fn observe_for(&mut self, duration: Duration) {
        let deadline = Instant::now() + duration;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.receiver.as_ref().unwrap().recv_timeout(remaining) {
                Ok(event) => {
                    let event = event.expect("public transport event must decode");
                    assert_ne!(event["event"], "node_stopped", "retry exhaustion must leave the node running");
                    assert!(self.seen.len() < 256, "transport event history exceeded test bound");
                    self.seen.push(event);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(error) => panic!("node stopped during outage: {error}; observed {:?}", self.seen),
            }
        }
        assert!(self.child.try_wait().unwrap().is_none());
    }

    fn exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() { return status; }
            assert!(Instant::now() < deadline, "node did not exit within shutdown deadline");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(&mut self) {
        let mark = self.seen.len();
        assert!(Command::new("kill").args(["-INT", &self.child.id().to_string()])
            .status().unwrap().success());
        let stopped = self.event_after(mark, "node_stopped", None);
        assert_eq!(stopped["reason"], "ctrl_c");
        assert_eq!(stopped["connected_peers"], 0);
        assert!(self.exit().success());
        while let Ok(event) = self.receiver.as_ref().unwrap().try_recv() {
            assert!(self.seen.len() < 256, "transport event history exceeded test bound");
            self.seen.push(event.expect("public transport event must decode"));
        }
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

enum ForwardCommand { SetEnabled(bool), Stop }

// One owned runtime/thread, at most four accepted connections and four bounded
// copy buffers. Cut aborts and reaps every socket task before acknowledging;
// restoring keeps the very same listening socket and literal dial address.
struct Forwarder {
    address: SocketAddr,
    commands: async_mpsc::Sender<ForwardCommand>,
    acknowledgements: Receiver<()>,
    accepts: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<Result<(), String>>>,
}

impl Forwarder {
    fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (commands, mut receiver) = async_mpsc::channel(1);
        let (acknowledge, acknowledgements) = mpsc::sync_channel(1);
        let accepts = Arc::new(AtomicUsize::new(0));
        let worker_accepts = Arc::clone(&accepts);
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all()
                .build().map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .map_err(|error| error.to_string())?;
                let mut connections = JoinSet::new();
                let mut enabled = true;
                let result = loop {
                    tokio::select! {
                        biased;
                        command = receiver.recv() => {
                            match command {
                                Some(ForwardCommand::SetEnabled(value)) => {
                                    enabled = value;
                                    if !enabled {
                                        connections.abort_all();
                                        while connections.join_next().await.is_some() {}
                                    }
                                    if acknowledge.send(()).is_err() { break Ok(()); }
                                }
                                Some(ForwardCommand::Stop) | None => break Ok(()),
                            }
                        }
                        accepted = listener.accept() => {
                            let (mut incoming, _) = match accepted {
                                Ok(connection) => connection,
                                Err(error) => break Err(error.to_string()),
                            };
                            let count = worker_accepts.fetch_add(1, Ordering::SeqCst) + 1;
                            if count > 4 { break Err("more than initial plus three actual dials".into()); }
                            if enabled {
                                connections.spawn(async move {
                                    if let Ok(Ok(mut outgoing)) = tokio::time::timeout(
                                        Duration::from_millis(250), TcpStream::connect(target),
                                    ).await {
                                        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                                    }
                                });
                            }
                        }
                        _ = connections.join_next(), if !connections.is_empty() => {}
                    }
                };
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                result
            })
        });
        Self { address, commands, acknowledgements, accepts, worker: Some(worker) }
    }

    fn set_enabled(&self, enabled: bool) {
        self.commands.blocking_send(ForwardCommand::SetEnabled(enabled)).unwrap();
        self.acknowledgements.recv_timeout(Duration::from_secs(2))
            .expect("forwarder must acknowledge cut/restore within its owned deadline");
    }

    fn accepts(&self) -> usize { self.accepts.load(Ordering::SeqCst) }

    fn stop(&mut self) {
        let _ = self.commands.blocking_send(ForwardCommand::Stop);
        self.worker.take().unwrap().join().expect("forwarder worker panicked")
            .expect("forwarder must stay within initial plus three dials");
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = self.commands.blocking_send(ForwardCommand::Stop);
            // All worker IO is async/cancellable; Stop reaps every task before return.
            let _ = worker.join();
        }
    }
}

fn transport_only(started: &Value, reconnect: bool) {
    assert_eq!(started["event"], "node_started");
    assert_eq!(started["transport_only"], true);
    assert_eq!(started["identity"], "ephemeral_transport");
    assert_eq!(started["reconnect_enabled"], reconnect);
    for flag in [
        "persistent_identity", "discovery_ready", "gossip_ready", "trading_ready",
        "backing_ready", "proof_ready", "recovery_ready",
    ] {
        assert_eq!(started[flag], false, "reconnection must not imply {flag}");
    }
}

#[test]
fn reconnect_restores_same_expected_peer_after_transport_cut() {
    let mut target = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--max-peers", "1", "--run-for-ms", "60000",
    ]);
    let target_started = target.event_after(0, "node_started", None);
    let target_id = target_started["peer_id"].as_str().unwrap();
    let target_address = target.event_after(0, "listening", None)["address"].as_str().unwrap().to_owned();
    let address: libp2p::Multiaddr = target_address.parse().unwrap();
    let target_port = address.iter().find_map(|part| match part {
        libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
        _ => None,
    }).unwrap();
    let mut forwarder = Forwarder::start(SocketAddr::from(([127, 0, 0, 1], target_port)));
    let dial = format!("/ip4/127.0.0.1/tcp/{}/p2p/{target_id}", forwarder.address.port());
    let mut seeker = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &dial, "--reconnect",
        "--max-peers", "1", "--run-for-ms", "60000",
    ]);
    // Against the pre-feature executable, RED must report its actual exit status
    // rejecting --reconnect, not a missing Rust API or a default-off field check.
    let seeker_started = seeker.event_after(0, "node_started", None);
    transport_only(&seeker_started, true);
    transport_only(&target_started, false);
    let seeker_id = seeker_started["peer_id"].as_str().unwrap();
    assert_ne!(seeker_id, target_id);
    for (node, peer) in [(&mut seeker, target_id), (&mut target, seeker_id)] {
        node.event_after(0, "peer_connected", Some(peer));
        assert_eq!(node.event_after(0, "peer_identified", Some(peer))["protocol_matches"], true);
        assert!(node.event_after(0, "peer_ping", Some(peer))["rtt_ms"].as_u64().is_some());
    }
    assert_eq!(forwarder.accepts(), 1);

    let seeker_cut = seeker.seen.len();
    let target_cut = target.seen.len();
    forwarder.set_enabled(false);
    seeker.event_after(seeker_cut, "peer_disconnected", Some(target_id));
    target.event_after(target_cut, "peer_disconnected", Some(seeker_id));
    assert!(target.child.try_wait().unwrap().is_none(), "target identity must remain alive during the cut");
    let scheduled = seeker.event_after(seeker_cut, "peer_retry_scheduled", Some(target_id));
    assert_eq!(scheduled["attempt"], 1);
    assert_eq!(scheduled["delay_ms"], 1000);
    let seeker_reconnect = seeker.seen.len();
    let target_reconnect = target.seen.len();
    forwarder.set_enabled(true);
    for (node, mark, peer) in [
        (&mut seeker, seeker_reconnect, target_id), (&mut target, target_reconnect, seeker_id),
    ] {
        node.event_after(mark, "peer_connected", Some(peer));
        let connected = node.seen.len() - 1;
        assert_eq!(node.event_after(connected, "peer_identified", Some(peer))["protocol_matches"], true);
        assert!(node.event_after(connected, "peer_ping", Some(peer))["rtt_ms"].as_u64().is_some());
    }
    assert_eq!(forwarder.accepts(), 2, "fresh Noise connection must cross the original forwarding address");

    // A successful reconnection must not reset the lifetime retry budget.
    let seeker_second_cut = seeker.seen.len();
    forwarder.set_enabled(false);
    seeker.event_after(seeker_second_cut, "peer_disconnected", Some(target_id));
    seeker.observe_for(Duration::from_secs(8));
    assert_eq!(forwarder.accepts(), 4, "only initial plus three actual attempts are allowed across flaps");
    seeker.stop();
    target.stop();
    forwarder.stop();
    let retries: Vec<_> = seeker.seen.iter().filter(|event| event["event"] == "peer_retry_scheduled")
        .map(|event| {
            assert_eq!(event["peer_id"], target_id);
            (event["attempt"].as_u64().unwrap(), event["delay_ms"].as_u64().unwrap())
        }).collect();
    assert_eq!(retries, [(1, 1000), (2, 2000), (3, 4000)]);
    for node in [&target, &seeker] {
        assert_eq!(node.seen.iter().filter(|event| event["event"] == "node_started").count(), 1);
        assert_eq!(node.seen.iter().filter(|event| event["event"] == "peer_connected").count(), 2);
        assert!(!node.seen.iter().any(|event| event["event"] == "peer_query_started"));
    }
}

fn listener_and_forwarder() -> (Node, Forwarder, String) {
    let mut target = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--max-peers", "2", "--run-for-ms", "60000",
    ]);
    let id = target.event_after(0, "node_started", None)["peer_id"].as_str().unwrap().to_owned();
    let address: libp2p::Multiaddr = target.event_after(0, "listening", None)["address"]
        .as_str().unwrap().parse().unwrap();
    let port = address.iter().find_map(|part| match part {
        libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
        _ => None,
    }).unwrap();
    let forwarder = Forwarder::start(SocketAddr::from(([127, 0, 0, 1], port)));
    let dial = format!("/ip4/127.0.0.1/tcp/{}/p2p/{id}", forwarder.address.port());
    (target, forwarder, dial)
}

#[test]
fn reconnect_default_off_does_not_redial_after_cut_and_restore() {
    let (mut target, mut forwarder, dial) = listener_and_forwarder();
    let target_id = target.seen[0]["peer_id"].as_str().unwrap().to_owned();
    let mut seeker = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &dial, "--run-for-ms", "60000",
    ]);
    transport_only(&seeker.event_after(0, "node_started", None), false);
    seeker.event_after(0, "peer_connected", Some(&target_id));
    seeker.event_after(0, "peer_identified", Some(&target_id));
    seeker.event_after(0, "peer_ping", Some(&target_id));
    let mark = seeker.seen.len();
    forwarder.set_enabled(false);
    seeker.event_after(mark, "peer_disconnected", Some(&target_id));
    forwarder.set_enabled(true);
    seeker.observe_for(Duration::from_secs(2));
    assert_eq!(forwarder.accepts(), 1, "default off must not submit a retry even after restore");
    assert!(!seeker.seen.iter().any(|event| event["event"] == "peer_retry_scheduled"));
    seeker.stop();
    target.stop();
    forwarder.stop();
}

#[test]
fn reconnect_wrong_expected_noise_identity_is_terminal() {
    let (mut target, mut forwarder, _) = listener_and_forwarder();
    let wrong_id = libp2p::PeerId::from(libp2p::identity::Keypair::generate_ed25519().public());
    assert_ne!(target.seen[0]["peer_id"], wrong_id.to_string());
    let dial = format!("/ip4/127.0.0.1/tcp/{}/p2p/{wrong_id}", forwarder.address.port());
    let mut seeker = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &dial, "--reconnect",
        "--run-for-ms", "60000",
    ]);
    transport_only(&seeker.event_after(0, "node_started", None), true);
    assert_eq!(seeker.event_after(0, "dial_failed", None)["reason"], "peer_id_mismatch");
    seeker.observe_for(Duration::from_secs(2));
    assert_eq!(forwarder.accepts(), 1, "Noise mismatch is not a transient retryable outage");
    assert!(!seeker.seen.iter().any(|event| event["event"] == "peer_retry_scheduled"
        || event["event"] == "peer_connected"));
    seeker.stop();
    target.stop();
    forwarder.stop();
}

#[test]
fn reconnect_unreachable_primary_keeps_configured_alternative_usable() {
    let (mut primary, mut blocked, primary_dial) = listener_and_forwarder();
    blocked.set_enabled(false);
    let primary_id = primary.seen[0]["peer_id"].as_str().unwrap().to_owned();
    let (mut alternative, mut available, alternative_dial) = listener_and_forwarder();
    let alternative_id = alternative.seen[0]["peer_id"].as_str().unwrap().to_owned();
    let mut seeker = Node::start(&[
        "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &primary_dial,
        "--dial", &alternative_dial, "--reconnect", "--max-peers", "2", "--run-for-ms", "60000",
    ]);
    transport_only(&seeker.event_after(0, "node_started", None), true);
    seeker.event_after(0, "peer_connected", Some(&alternative_id));
    assert_eq!(seeker.event_after(0, "peer_identified", Some(&alternative_id))["protocol_matches"], true);
    seeker.event_after(0, "peer_ping", Some(&alternative_id));
    seeker.observe_for(Duration::from_secs(9));
    let mark = seeker.seen.len();
    assert!(seeker.event_after(mark, "peer_ping", Some(&alternative_id))["rtt_ms"].as_u64().is_some());
    assert_eq!(blocked.accepts(), 4, "unreachable configured primary gets only three extra actual dials");
    assert_eq!(available.accepts(), 1, "healthy alternative must not get redundant direct dials");
    assert!(!seeker.seen.iter().any(|event| event["event"] == "peer_disconnected"
        || event["event"] == "peer_query_started"));
    assert!(seeker.seen.iter().filter(|event| event["event"] == "peer_retry_scheduled")
        .all(|event| event["peer_id"] == primary_id));
    seeker.stop();
    primary.stop();
    alternative.stop();
    blocked.stop();
    available.stop();
}

fn rejected(args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_z2z-node")).args(args).output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "invalid reconnect configuration must fail before sockets");
    assert!(!output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
        "missing CLI support is not evidence of reconnect policy: {output:?}");
}

#[test]
fn reconnect_configuration_is_strict_and_requires_a_configured_dial() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public reconnect config.json");
    let config = path.to_str().unwrap();
    let valid = serde_json::json!({
        "schema_version": 1, "listen": "/ip4/127.0.0.1/tcp/0", "dial": [],
        "reconnect": false, "run_for_ms": 100,
    });
    for invalid in [serde_json::json!("true"), serde_json::json!(1), serde_json::json!(null),
        serde_json::json!({}), serde_json::json!(true)] {
        let mut input = valid.clone();
        input["reconnect"] = invalid;
        std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
        rejected(&["run", "--config", config]);
    }
    std::fs::write(&path,
        br#"{"schema_version":1,"listen":"/ip4/127.0.0.1/tcp/0","reconnect":false,"reconnect":false}"#,
    ).unwrap();
    rejected(&["run", "--config", config]);
    std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
    rejected(&["run", "--config", config, "--reconnect"]);
    rejected(&["run", "--listen", "/ip4/127.0.0.1/tcp/0", "--reconnect"]);
    let output = Command::new(env!("CARGO_BIN_EXE_z2z-node"))
        .args(["run", "--config", config]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let observed: Vec<Value> = String::from_utf8(output.stdout).unwrap().lines()
        .map(|line| serde_json::from_str(line).unwrap()).collect();
    transport_only(&observed[0], false);
    assert_eq!(observed.last().unwrap()["reason"], "duration_elapsed");
}

#[test]
fn reconnect_ctrl_c_and_duration_cancel_backoff_without_poststop_dials() {
    for finite in [false, true] {
        let (mut target, mut forwarder, dial) = listener_and_forwarder();
        forwarder.set_enabled(false);
        let target_id = target.seen[0]["peer_id"].as_str().unwrap().to_owned();
        let mut seeker = Node::start(&[
            "run", "--listen", "/ip4/127.0.0.1/tcp/0", "--dial", &dial, "--reconnect",
            "--run-for-ms", if finite { "400" } else { "60000" },
        ]);
        transport_only(&seeker.event_after(0, "node_started", None), true);
        let scheduled = seeker.event_after(0, "peer_retry_scheduled", Some(&target_id));
        assert_eq!(scheduled["attempt"], 1);
        assert_eq!(forwarder.accepts(), 1);
        let started = Instant::now();
        if finite {
            let stopped = seeker.event_after(0, "node_stopped", None);
            assert_eq!(stopped["reason"], "duration_elapsed");
            assert_eq!(stopped["connected_peers"], 0);
            assert!(seeker.exit().success());
        } else {
            seeker.stop();
        }
        assert!(started.elapsed() < Duration::from_secs(2), "shutdown must not wait for retry deadlines");
        forwarder.set_enabled(true);
        // Keep the original literal listener alive beyond the cancelled deadline.
        thread::sleep(Duration::from_millis(1200));
        assert_eq!(forwarder.accepts(), 1, "stopped node submitted a retry or leaked a socket task");
        target.stop();
        forwarder.stop();
    }
}

#[test]
fn persistent_identity_restart_reconnects_expected_peer() {
    use std::{fs, io::Read, os::unix::fs::PermissionsExt};
    let directory = tempfile::Builder::new().prefix("z2z-restart-identity-")
        .permissions(fs::Permissions::from_mode(0o700)).tempdir_in("/tmp").unwrap();
    let path = directory.path().join("transport.key");
    let mut target = Node::start(&["run", "--listen", "/ip4/127.0.0.1/tcp/0",
        "--peer-identity-file", path.to_str().unwrap()]);
    let target_started = target.event_after(0, "node_started", None);
    assert_eq!(target_started["identity"], "persistent_transport");
    assert_eq!(target_started["persistent_identity"], true);
    let target_id = target_started["peer_id"].as_str().unwrap().to_owned();
    let target_address = target.event_after(0, "listening", None)["address"].as_str().unwrap().to_owned();
    let listen = target_address.rsplit_once("/p2p/").unwrap().0.to_owned();
    let mut original = zeroize::Zeroizing::new([0; 52]);
    fs::File::open(&path).unwrap().read_exact(&mut original[..]).unwrap();
    let mut seeker = Node::start(&["run", "--listen", "/ip4/127.0.0.1/tcp/0",
        "--dial", &target_address, "--reconnect", "--max-peers", "1"]);
    let seeker_started = seeker.event_after(0, "node_started", None);
    transport_only(&seeker_started, true);
    let seeker_id = seeker_started["peer_id"].as_str().unwrap().to_owned();
    for (node, peer) in [(&mut seeker, target_id.as_str()), (&mut target, seeker_id.as_str())] {
        node.event_after(0, "peer_connected", Some(peer));
        assert_eq!(node.event_after(0, "peer_identified", Some(peer))["protocol_matches"], true);
        assert!(node.event_after(0, "peer_ping", Some(peer))["rtt_ms"].as_u64().is_some());
    }
    let seeker_mark = seeker.seen.len();
    target.stop();
    seeker.event_after(seeker_mark, "peer_disconnected", Some(&target_id));
    let scheduled = seeker.event_after(seeker_mark, "peer_retry_scheduled", Some(&target_id));
    assert_eq!(scheduled["attempt"], 1);
    assert_eq!(scheduled["delay_ms"], 1000);
    assert!(seeker.child.try_wait().unwrap().is_none(), "configured consumer must stay alive");
    let old_pid = target.child.id();
    let mut restarted = Node::start(&["run", "--listen", &listen,
        "--peer-identity-file", path.to_str().unwrap()]);
    assert_ne!(restarted.child.id(), old_pid);
    let restarted_started = restarted.event_after(0, "node_started", None);
    assert_eq!(restarted_started["peer_id"], target_id);
    assert_eq!(restarted_started["identity"], "persistent_transport");
    assert_eq!(restarted_started["persistent_identity"], true);
    assert_eq!(restarted.event_after(0, "listening", None)["address"], target_address);
    for (node, mark, peer) in [(&mut seeker, seeker_mark, target_id.as_str()),
        (&mut restarted, 0, seeker_id.as_str())] {
        node.event_after(mark, "peer_connected", Some(peer));
        assert_eq!(node.event_after(mark, "peer_identified", Some(peer))["protocol_matches"], true);
        assert!(node.event_after(mark, "peer_ping", Some(peer))["rtt_ms"].as_u64().is_some());
    }
    seeker.stop();
    restarted.stop();
    let retries: Vec<_> = seeker.seen.iter().filter(|event| event["event"] == "peer_retry_scheduled")
        .map(|event| {
            assert_eq!(event["peer_id"], target_id);
            event["attempt"].as_u64().unwrap()
        }).collect();
    assert!(!retries.is_empty() && retries.len() <= 3);
    assert!(retries.iter().copied().eq(1..=retries.len() as u64));
    assert_eq!(seeker.seen.iter().filter(|event| event["event"] == "node_started").count(), 1);
    assert_eq!(seeker.seen.iter().filter(|event| event["event"] == "peer_connected").count(), 2);
    for started in [&target_started, &restarted_started] {
        assert_eq!(started["schema_version"], 1);
        assert_eq!(started["transport_only"], true);
        for flag in ["discovery_ready", "gossip_ready", "trading_ready", "backing_ready", "proof_ready", "recovery_ready"] {
            assert_eq!(started[flag], false);
        }
    }
    let mut retained = zeroize::Zeroizing::new([0; 52]);
    fs::File::open(&path).unwrap().read_exact(&mut retained[..]).unwrap();
    assert!(original[..] == retained[..], "actual restart changed transport key");
    assert!(!directory.path().join(".transport.key.pending").exists());
    // Public-only evidence for the parent's single smoke invocation.
    println!("persisted-restart smoke: peer={target_id}; old_pid={old_pid}; new_pid={}; authenticated identify+ping before/after; retries={retries:?}; orderly shutdown", restarted.child.id());
}
