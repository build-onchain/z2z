use super::{Error, Result, config, discovery, dkg, reconnect};
#[cfg(target_os = "linux")]
use super::tui;
use super::session;
use futures_util::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, connection_limits,
    core::{Endpoint, transport::PortUse, upgrade::DeniedUpgrade},
    identify, multiaddr::Protocol, noise, ping, request_response,
    swarm::{
        ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId,
        DialError, FromSwarm, ListenError, NetworkBehaviour, SubstreamProtocol, SwarmEvent, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm, dummy, handler::ConnectionEvent, behaviour::toggle::Toggle,
    },
    tcp, yamux,
};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};
use std::{
    collections::HashSet,
    convert::Infallible,
    fmt::Display,
    io::{Cursor, Write},
    num::{NonZeroU8, NonZeroUsize},
    task::{Context, Poll},
    time::Duration,
};

const IDENTIFY_PROTOCOL: &str = "/z2z/transport/1.0.0";

// Reject unknown identities before connection_limits, whose per-peer map keeps
// empty historical entries. No private owner identity is read or authenticated.
pub(super) struct PeerCohort {
    maximum: usize,
    peers: HashSet<PeerId>,
}

impl PeerCohort {
    fn admit(&mut self, peer: PeerId) -> std::result::Result<DirectConnection, ConnectionDenied> {
        if !self.peers.contains(&peer) {
            if self.peers.len() == self.maximum {
                return Err(ConnectionDenied::new(PeerCapacity));
            }
            // ponytail: lifetime cohort is capped; restart to select new peers.
            // Discovery shares this ceiling; scalable rotation needs eviction-safe accounting.
            self.peers.insert(peer);
        }
        Ok(DirectConnection(dummy::ConnectionHandler))
    }
}

#[derive(Debug)]
struct PeerCapacity;
impl std::fmt::Display for PeerCapacity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("peer capacity")
    }
}
impl std::error::Error for PeerCapacity {}

impl NetworkBehaviour for PeerCohort {
    type ConnectionHandler = DirectConnection;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self, _: ConnectionId, peer: PeerId, _: &Multiaddr, _: &Multiaddr,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        self.admit(peer)
    }

    fn handle_established_outbound_connection(
        &mut self, _: ConnectionId, peer: PeerId, _: &Multiaddr, _: Endpoint, _: PortUse,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        self.admit(peer)
    }

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self, _: PeerId, _: ConnectionId, event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

// Ping deliberately opts out of libp2p keepalive. Keep the owner's bounded direct
// connection until explicit shutdown, remote close or our ping-failure policy.
pub(super) struct DirectConnection(dummy::ConnectionHandler);

impl ConnectionHandler for DirectConnection {
    type FromBehaviour = Infallible;
    type ToBehaviour = Infallible;
    type InboundProtocol = DeniedUpgrade;
    type OutboundProtocol = DeniedUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        self.0.listen_protocol()
    }

    fn connection_keep_alive(&self) -> bool {
        true
    }

    fn on_behaviour_event(&mut self, event: Infallible) {
        self.0.on_behaviour_event(event);
    }

    fn poll(
        &mut self, cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, (), Self::ToBehaviour>> {
        self.0.poll(cx)
    }

    fn on_connection_event(
        &mut self, event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        self.0.on_connection_event(event);
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
pub(super) struct Behaviour {
    cohort: PeerCohort,
    limits: connection_limits::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub(super) session: request_response::Behaviour<session::SessionCodec>,
    discovery: Toggle<discovery::Discovery>,
}

// Keep only public authenticated identity and a comparison result from identify;
// never retain/log remote agent strings, addresses or arbitrary diagnostic text.
pub(super) enum Event {
    Ping(ping::Event),
    Identified { peer: PeerId, protocol_matches: bool, supports_kad: bool },
    IdentifyFailed(PeerId),
    Ignore,
    Session(session::Event),
    Discovery(discovery::Event),
}

impl From<Infallible> for Event {
    fn from(event: Infallible) -> Self {
        match event {}
    }
}
impl From<ping::Event> for Event {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}
impl From<discovery::Event> for Event {
    fn from(event: discovery::Event) -> Self { Self::Discovery(event) }
}
impl From<session::Event> for Event {
    fn from(event: session::Event) -> Self { Self::Session(event) }
}
impl From<identify::Event> for Event {
    fn from(event: identify::Event) -> Self {
        match event {
            identify::Event::Received { peer_id, info, .. } => Self::Identified {
                peer: peer_id,
                protocol_matches: info.protocol_version == IDENTIFY_PROTOCOL,
                supports_kad: info.protocols.contains(&discovery::PROTOCOL),
            },
            identify::Event::Error { peer_id, .. } => Self::IdentifyFailed(peer_id),
            _ => Self::Ignore,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum PublicEvent<'a> {
    NodeStarted {
        schema_version: u16,
        transport_only: bool,
        identity: &'static str,
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        max_peers: u32,
        features: [&'static str; 5],
        persistent_identity: bool,
        discovery_ready: bool,
        peer_discovery_enabled: bool,
        reconnect_enabled: bool,
        gossip_ready: bool,
        trading_ready: bool,
        backing_ready: bool,
        proof_ready: bool,
        recovery_ready: bool,
    },
    Listening {
        #[serde(serialize_with = "serialize_display")]
        address: &'a Multiaddr,
    },
    PeerConnected {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        connected_peers: usize,
    },
    PeerIdentified {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        protocol_matches: bool,
    },
    PeerPing {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        rtt_ms: u64,
    },
    PeerPingFailed {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        reason: &'static str,
    },
    PeerIdentifyFailed {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
    },
    PeerDisconnected {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        connected_peers: usize,
    },
    PeerRejected { reason: &'static str },
    DialFailed { reason: &'static str },
    PeerRetryScheduled {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        attempt: u8,
        delay_ms: u64,
    },
    PeerQueryStarted {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
    },
    PeerQueryResult {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
    },
    PeerQueryFailure {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        reason: &'static str,
    },
    PeerDiscovered {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        #[serde(serialize_with = "serialize_display")]
        address: &'a Multiaddr,
    },
    SessionRequest {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        kind: u8,
        seq: u32,
    },
    SessionRejected {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
    },
    SessionResponse {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        request_id: u64,
        ok: bool,
    },
    SessionOutboundFailure {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        reason: &'static str,
    },
    SessionInboundFailure {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
    },
    DkgCompleted {
        #[serde(serialize_with = "serialize_display")]
        peer_id: &'a PeerId,
        commit: &'a str,
        ephemeral: bool,
        financial_authority: bool,
    },
    NodeStopped { reason: &'static str, connected_peers: usize },
}

fn serialize_display<T: Display, S: serde::Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

struct Output {
    stdout: std::io::Stdout,
    original_flags: rustix::fs::OFlags,
    state_path: Option<std::path::PathBuf>,
    /// Only authenticated terminal-ACK request channels intentionally omitted.
    /// Pinned behaviour IDs are unique locally; capacity follows live sessions
    /// times the existing eight concurrent session streams, never remote bytes.
    intentional_omissions: HashSet<(PeerId, request_response::InboundRequestId)>,
}

impl Output {
    fn new() -> Result<Self> {
        let stdout = std::io::stdout();
        let original_flags = rustix::fs::fcntl_getfl(&stdout).map_err(|_| Error::Output)?;
        rustix::fs::fcntl_setfl(&stdout, original_flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(|_| Error::Output)?;
        Ok(Self { stdout, original_flags, state_path: None, intentional_omissions: HashSet::new() })
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        let _ = rustix::fs::fcntl_setfl(&self.stdout, self.original_flags);
    }
}

fn emit(output: &mut Output, event: PublicEvent<'_>) -> Result<()> {
    // One stack record below Linux PIPE_BUF: a nonblocking pipe write is atomic.
    // No buffered/blocking stdout worker or growing event queue survives shutdown.
    let mut bytes = [0_u8; 1024];
    let length = {
        let mut cursor = Cursor::new(bytes.as_mut_slice());
        serde_json::to_writer(&mut cursor, &event).map_err(|_| Error::Output)?;
        cursor.write_all(b"\n").map_err(|_| Error::Output)?;
        cursor.position() as usize
    };
    for _ in 0..2 {
        match rustix::io::write(&output.stdout, &bytes[..length]) {
            Ok(count) if count == length => return Ok(()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::AGAIN) => return Err(Error::OutputBackpressure),
            _ => return Err(Error::Output),
        }
    }
    Err(Error::Output)
}

pub(super) fn completed(peer: &PeerId, commit: &[u8; 32]) -> Result<()> {
    emit_completion(&mut Output::new()?, peer, commit)
}

fn emit_completion(output: &mut Output, peer: &PeerId, commit: &[u8; 32]) -> Result<()> {
    emit(output, PublicEvent::DkgCompleted {
        peer_id: peer, commit: &crate::market::native::hex(commit),
        ephemeral: true, financial_authority: false,
    })
}

pub(super) async fn run(mut config: config::Config) -> Result<()> {
    #[cfg(target_os = "linux")]
    let use_tui = {
        use std::io::IsTerminal as _;
        config.tui || (std::io::stdin().is_terminal() && std::io::stdout().is_terminal())
    };
    #[cfg(not(target_os = "linux"))]
    let use_tui = false;
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    #[cfg_attr(target_os = "linux", allow(unused_mut, unused_variables))]
    let (terminal, mut view): (Option<tui::Terminal>, Option<tui::View>) = if use_tui {
        #[cfg(target_os = "linux")]
        {
            use std::io::IsTerminal as _;
            if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
                return Err(Error::TuiNotTerminal);
            }
        }
        let terminal = tui::Terminal::enter().map_err(|_| Error::TuiNotTerminal)?;
        (Some(terminal), None::<tui::View>)
    } else {
        (None, None)
    };
    #[cfg(not(target_os = "linux"))]
    let _ = use_tui;
    let maximum = config.max_peers;
    let persistent_identity = config.peer_identity_file.is_some();
    let identity = match &config.peer_identity_file {
        Some(path) => super::identity::load_or_create(path)?,
        None => libp2p::identity::Keypair::generate_ed25519(),
    };
    let ed25519_pair = identity.clone().try_into_ed25519().map_err(|_| Error::Transport)?;
    let secret = Zeroizing::new(<[u8; 32]>::try_from(ed25519_pair.secret().as_ref())
        .map_err(|_| Error::Transport)?);
    let session_signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    drop(secret);
    drop(ed25519_pair);
    let mut sessions =
        session::SessionTable::new(*session_signing_key.verifying_key().as_bytes());
    let builder = SwarmBuilder::with_existing_identity(identity);
    let mut swarm = builder
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, || {
            let mut config = yamux::Config::default();
            // The pinned wrapper selects its supported yamux 0.12 implementation
            // for this setter. It retains OnRead backpressure and Noise security.
            config.set_max_num_streams(8);
            config
        })
        .map_err(|_| Error::Transport)?
        .with_behaviour(|key| Behaviour {
            cohort: PeerCohort { maximum: maximum as usize, peers: HashSet::with_capacity(maximum as usize) },
            limits: connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default()
                    .with_max_pending_incoming(Some(maximum))
                    .with_max_pending_outgoing(Some(maximum))
                    .with_max_established_incoming(Some(maximum))
                    .with_max_established_outgoing(Some(maximum))
                    .with_max_established(Some(maximum))
                    .with_max_established_per_peer(Some(1)),
            ),
            ping: ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_secs(5)).with_timeout(Duration::from_secs(10)),
            ),
            identify: identify::Behaviour::new(
                identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), key.public())
                    .with_agent_version(concat!("z2z-node/", env!("CARGO_PKG_VERSION")).to_owned())
                    .with_cache_size(0)
                    .with_push_listen_addr_updates(false),
            ),
            session: request_response::Behaviour::new(
                [(session::PROTOCOL_ID, request_response::ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30))
                    .with_max_concurrent_streams(8),
            ),
            discovery: config.peer_discovery.then(|| discovery::Discovery::new(key.public().to_peer_id(), &config)).into(),
        })
        .map_err(|_| Error::Transport)?
        .with_swarm_config(|_| {
            // Poll the bounded connection futures inside the swarm itself: drop
            // cancels all of them, with no detached executor tasks to outlive run.
            libp2p::swarm::Config::without_executor()
                .with_notify_handler_buffer_size(NonZeroUsize::new(8).expect("nonzero constant"))
                .with_per_connection_event_buffer_size(8)
                .with_dial_concurrency_factor(NonZeroU8::new(1).expect("nonzero constant"))
                .with_max_negotiating_inbound_streams(4)
                .with_idle_connection_timeout(Duration::from_secs(30))
        })
        .with_connection_timeout(Duration::from_secs(10))
        .build();
    let local_peer = *swarm.local_peer_id();
    if config.find_peer == Some(local_peer)
        || config.dkg.as_ref().is_some_and(|policy| policy.peer == local_peer)
    {
        return Err(Error::Configuration);
    }
    let listen_display = config.listen.to_string();
    let listener = swarm.listen_on(config.listen.clone()).map_err(|_| Error::Transport)?;
    let mut output = Output::new()?;
    output.state_path = config.state_file.clone();
    #[cfg(target_os = "linux")]
    let mut view = if terminal.is_some() {
        Some(tui::View::new(
            if persistent_identity { "persistent_transport" } else { "ephemeral_transport" },
            local_peer.to_string(),
            listen_display.clone(),
            maximum,
            persistent_identity,
            config.peer_discovery,
            config.reconnect,
        ))
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let mut view: Option<()> = None;
    #[cfg(target_os = "linux")]
    if view.is_some() {
        view_slot_set(&mut view);
    }
    emit(&mut output, PublicEvent::NodeStarted {
        schema_version: 1,
        transport_only: true,
        identity: if persistent_identity { "persistent_transport" } else { "ephemeral_transport" },
        peer_id: &local_peer,
        max_peers: maximum,
        features: ["tcp", "noise", "yamux", "ping", "identify"],
        persistent_identity,
        discovery_ready: false,
        peer_discovery_enabled: config.peer_discovery,
        reconnect_enabled: config.reconnect,
        gossip_ready: false,
        trading_ready: false,
        backing_ready: false,
        proof_ready: false,
        recovery_ready: false,
    })?;
    super::state::write_state(
        output.state_path.as_deref(),
        &super::state::StateSnapshot {
            schema_version: 1,
            running: true,
            stopped_reason: None,
            peer_id: &local_peer.to_string(),
            listen: &listen_display,
            connected_peers: 0,
            updated_unix: super::state::now_unix_secs(),
        },
    )
    .map_err(|_| Error::StateFile)?;
    let mut reconnect = config.reconnect.then(|| {
        reconnect::Reconnect::new(std::mem::take(&mut config.dial), maximum as usize)
    });
    if let Some(reconnect) = &mut reconnect {
        for index in 0..reconnect.len() {
            direct_dial(&mut swarm, &mut output, reconnect, index, false)?;
        }
    } else {
        for address in config.dial {
            let peer = config::dial_peer(&address);
            let options = libp2p::swarm::dial_opts::DialOpts::peer_id(peer).addresses(vec![address]).build();
            if let Err(error) = swarm.dial(options) {
                emit(&mut output, PublicEvent::DialFailed { reason: dial_reason(&error) })?;
            }
        }
    }
    let signal = tokio::signal::ctrl_c();
    let duration = async {
        match config.run_for_ms {
            Some(ms) => tokio::time::sleep(Duration::from_millis(ms)).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(signal, duration);
    #[cfg(target_os = "linux")]
    let mut redraw = tokio::time::interval(std::time::Duration::from_millis(tui::EVENT_TICK_MS));
    #[cfg(target_os = "linux")]
    redraw.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    #[cfg(not(target_os = "linux"))]
    let redraw = tokio::time::interval(std::time::Duration::from_millis(u64::MAX));
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut redraw = redraw;
    let mut expiry = tokio::time::interval(Duration::from_secs(5));
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let reason = loop {
        let retry_deadline = reconnect.as_ref().and_then(reconnect::Reconnect::deadline);
        let retry = async {
            match retry_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            result = &mut signal => {
                result.map_err(|_| Error::Signal)?;
                break "ctrl_c";
            }
            () = &mut duration => break "duration_elapsed",
            event = swarm.next() => handle_event(&mut swarm, &mut output, &mut reconnect, event.ok_or(Error::Transport)?, false, &session_signing_key, &mut sessions, config.dkg.as_ref())?,
            () = retry => {
                if let Some(reconnect) = &mut reconnect
                    && let Some(index) = reconnect.due(tokio::time::Instant::now())
                {
                    direct_dial(&mut swarm, &mut output, reconnect, index, true)?;
                }
            }
            _ = expiry.tick() => {
                // §7.3 monotonic session expiry.
                sessions.sweep(std::time::Instant::now());
            }
            _ = redraw.tick() => {
                #[cfg(target_os = "linux")]
                if terminal.is_some() {
                    let mut quit = false;
                    for _ in 0..64 {
                        match tui::poll_key() {
                            Ok(Some(tui::Key::Quit)) => { quit = true; break; }
                            Ok(Some(tui::Key::Clear)) => { let _ = tui::clear(); }
                            Ok(Some(_)) | Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                    if quit { break "tui_quit"; }
                    view_slot_with(|v| {
                        let _ = tui::render(v);
                    });
                }
            }
        }
    };
    if let Some(reconnect) = &mut reconnect { reconnect.stop(); }
    if let Some(discovery) = swarm.behaviour_mut().discovery.as_mut() {
        discovery.stop();
    }
    swarm.remove_listener(listener);
    let peers: Vec<_> = swarm.connected_peers().copied().collect();
    for peer in peers {
        let _ = swarm.disconnect_peer_id(peer);
    }
    let grace = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(grace);
    while swarm.connected_peers().next().is_some() {
        tokio::select! {
            () = &mut grace => break,
            event = swarm.next() => handle_event(&mut swarm, &mut output, &mut reconnect, event.ok_or(Error::Transport)?, true, &session_signing_key, &mut sessions, config.dkg.as_ref())?,
        }
    }
    let remaining: Vec<_> = swarm.connected_peers().copied().collect();
    drop(swarm); // Owned connection and handshake futures/sockets are closed here.
    for (index, peer) in remaining.iter().enumerate() {
        emit(&mut output, PublicEvent::PeerDisconnected {
            peer_id: peer, connected_peers: remaining.len() - index - 1,
        })?;
    }
    emit(&mut output, PublicEvent::NodeStopped { reason, connected_peers: 0 })?;
    view_slot_with(|view| view.stop(reason, 0));
    let _ = super::state::write_state(
        output.state_path.as_deref(),
        &super::state::StateSnapshot {
            schema_version: 1,
            running: false,
            stopped_reason: Some(reason),
            peer_id: &local_peer.to_string(),
            listen: &listen_display,
            connected_peers: 0,
            updated_unix: super::state::now_unix_secs(),
        },
    );
    Ok(())
}

fn scheduled(output: &mut Output, scheduled: Option<reconnect::Scheduled>) -> Result<()> {
    if let Some(scheduled) = scheduled {
        emit(output, PublicEvent::PeerRetryScheduled {
            peer_id: &scheduled.peer, attempt: scheduled.attempt, delay_ms: scheduled.delay_ms,
        })?;
        view_slot_with(|view| view.retry_scheduled(
            &scheduled.peer.to_string(), scheduled.attempt, scheduled.delay_ms,
        ));
    }
    Ok(())
}

fn direct_dial(
    swarm: &mut Swarm<Behaviour>, output: &mut Output, reconnect: &mut reconnect::Reconnect,
    index: usize, retry: bool,
) -> Result<()> {
    let options = reconnect.begin(index);
    let id = options.connection_id();
    match swarm.dial(options) {
        Ok(()) => reconnect.accepted(index, retry),
        Err(error) => {
            emit(output, PublicEvent::DialFailed { reason: dial_reason(&error) })?;
            scheduled(output, reconnect.failed(id, &error, tokio::time::Instant::now()))?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_event(
    swarm: &mut Swarm<Behaviour>, output: &mut Output, reconnect: &mut Option<reconnect::Reconnect>,
    event: SwarmEvent<Event>, stopping: bool, signing_key: &ed25519_dalek::SigningKey,
    sessions: &mut session::SessionTable, policy: Option<&config::DkgPolicy>,
) -> Result<()> {
    handle_event_inner(swarm, output, reconnect, event, stopping, signing_key, sessions, policy)
}

// TUI view slot: set once at run start, read by every event handler. Kept in a
// thread-local because `handle_event` is called from the single runtime thread.
#[cfg(target_os = "linux")]
thread_local! {
    static VIEW: std::cell::RefCell<Option<tui::View>> = const { std::cell::RefCell::new(None) };
}
#[cfg(target_os = "linux")]
fn view_slot_set(view: &mut Option<tui::View>) {
    if let Some(view) = view.take() {
        VIEW.with(|cell| *cell.borrow_mut() = Some(view));
    }
}
#[cfg(target_os = "linux")]
fn view_slot_with<R>(f: impl FnOnce(&mut tui::View) -> R) -> Option<R> {
    VIEW.with(|cell| {
        let mut borrow = cell.borrow_mut();
        borrow.as_mut().map(f)
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_event_inner(
    swarm: &mut Swarm<Behaviour>, output: &mut Output, reconnect: &mut Option<reconnect::Reconnect>,
    event: SwarmEvent<Event>, stopping: bool, signing_key: &ed25519_dalek::SigningKey,
    sessions: &mut session::SessionTable, policy: Option<&config::DkgPolicy>,
) -> Result<()> {
    match event {
        SwarmEvent::NewListenAddr { mut address, .. } if !stopping => {
            address.push(Protocol::P2p(*swarm.local_peer_id()));
            emit(output, PublicEvent::Listening { address: &address })?;
            view_slot_with(|view| view.set_listen(address.to_string()));
            let _ = super::state::write_state(
                output.state_path.as_deref(),
                &super::state::StateSnapshot {
                    schema_version: 1,
                    running: true,
                    stopped_reason: None,
                    peer_id: &swarm.local_peer_id().to_string(),
                    listen: &address.to_string(),
                    connected_peers: swarm.connected_peers().count(),
                    updated_unix: super::state::now_unix_secs(),
                },
            );
        }
        SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
            if !stopping && let Some(reconnect) = reconnect {
                reconnect.established(peer_id, connection_id);
            }
            emit(output, PublicEvent::PeerConnected { peer_id: &peer_id, connected_peers: swarm.connected_peers().count() })?;
            view_slot_with(|view| view.connect(&peer_id.to_string(), swarm.connected_peers().count()));
            if stopping {
                let _ = swarm.disconnect_peer_id(peer_id);
            }
        }
        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
            if num_established == 0 {
                // §7.2 transcripts are bound to the authenticated direct
                // connection; a closed connection ends its sessions.
                sessions.drop_peer(&peer_id);
                output.intentional_omissions.retain(|(peer, _)| peer != &peer_id);
            }
            if !stopping && num_established == 0 && !swarm.is_connected(&peer_id)
                && let Some(reconnect) = reconnect
            {
                scheduled(output, reconnect.closed(peer_id, tokio::time::Instant::now()))?;
            }
            emit(output, PublicEvent::PeerDisconnected { peer_id: &peer_id, connected_peers: swarm.connected_peers().count() })?;
            view_slot_with(|view| view.disconnect(&peer_id.to_string(), swarm.connected_peers().count()));
        }
        SwarmEvent::Behaviour(Event::Ping(ping::Event { peer, result, .. })) => match result {
            Ok(rtt) => {
                emit(output, PublicEvent::PeerPing { peer_id: &peer, rtt_ms: rtt.as_millis() as u64 })?;
                view_slot_with(|view| view.ping(&peer.to_string(), rtt.as_millis() as u64));
            }
            Err(error) => {
                let reason = match error {
                    ping::Failure::Timeout => "timeout",
                    ping::Failure::Unsupported => "unsupported",
                    ping::Failure::Other { .. } => "io_or_protocol",
                };
                emit(output, PublicEvent::PeerPingFailed { peer_id: &peer, reason })?;
                view_slot_with(|view| view.ping_failed(&peer.to_string(), reason));
                let _ = swarm.disconnect_peer_id(peer);
            }
        },
        SwarmEvent::Behaviour(Event::Identified { peer, protocol_matches, supports_kad }) => {
            emit(output, PublicEvent::PeerIdentified { peer_id: &peer, protocol_matches })?;
            view_slot_with(|view| view.identified(&peer.to_string(), protocol_matches));
            if !stopping && let Some(discovery) = swarm.behaviour_mut().discovery.as_mut() {
                discovery.identified(peer, protocol_matches && supports_kad);
            }
        }
        SwarmEvent::Behaviour(Event::IdentifyFailed(peer)) => {
            emit(output, PublicEvent::PeerIdentifyFailed { peer_id: &peer })?;
            view_slot_with(|view| view.identify_failed(&peer.to_string()));
        }
        SwarmEvent::Behaviour(Event::Session(event)) => match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request { request_id, request, channel } => {
                    let request = Zeroizing::new(request);
                    let decoded = session::parse(&request).map(dkg::GuardedEnvelope);
                    let result = decoded.map_err(|_| Error::SessionEnvelope).and_then(|envelope| {
                        if stopping { return Err(Error::DkgProtocol); }
                        let (mut payload, completed) = if matches!(envelope.kind,
                            session::kind::NATIVE_QUOTE | session::kind::NATIVE_ACCEPTANCE)
                            || sessions.is_native_session(&peer, &envelope.session_id)
                        {
                            let response = sessions.respond_native(&peer, &envelope, signing_key,
                                super::state::now_unix_secs()).map_err(|_| Error::SessionEnvelope)?;
                            (response, None)
                        } else {
                            let response = dkg::respond(&peer, &envelope, policy, signing_key, sessions)?;
                            (Some(response.payload), response.completed)
                        };
                        emit(output, PublicEvent::SessionRequest {
                            peer_id: &peer, kind: envelope.kind, seq: envelope.seq,
                        })?;
                        view_slot_with(|view| view.session_request(&peer.to_string(), envelope.kind, envelope.seq));
                        // A terminal ACK consumes no response and never forms an
                        // ACK loop. Quote acceptance is an explicit local action.
                        let Some(payload) = payload.as_mut() else {
                            if envelope.kind != session::kind::ACK
                                || output.intentional_omissions.len() >= session::MAX_SESSIONS * 8 {
                                return Err(Error::SessionEnvelope);
                            }
                            output.intentional_omissions.insert((peer, request_id));
                            return Ok(());
                        };
                        match swarm.behaviour_mut().session.send_response(
                            channel, std::mem::take(&mut **payload),
                        ) {
                            Ok(()) => {
                                if let Some(commit) = completed {
                                    emit_completion(output, &peer, &commit)?;
                                }
                                Ok(())
                            }
                            Err(mut bytes) => {
                                bytes.zeroize();
                                Err(Error::DkgProtocol)
                            }
                        }
                    });
                    if let Err(error) = result {
                        sessions.drop_peer(&peer);
                        let _ = swarm.disconnect_peer_id(peer);
                        if matches!(error, Error::Output | Error::OutputBackpressure) {
                            return Err(error);
                        }
                        emit(output, PublicEvent::SessionRejected { peer_id: &peer })?;
                        view_slot_with(|view| view.session_reject());
                    }
                }
                request_response::Message::Response { request_id, response } => {
                    let response = Zeroizing::new(response);
                    // Only a selected native session's signed ACK may finish
                    // its exact outstanding frame. Other unsolicited responses
                    // preserve the original responder-only rejection policy.
                    let ok = session::parse(&response).is_ok_and(|envelope| {
                        envelope.kind == session::kind::ACK
                            && sessions.is_native_session(&peer, &envelope.session_id)
                            && sessions.respond_native(&peer, &envelope, signing_key,
                                super::state::now_unix_secs()).is_ok_and(|reply| reply.is_none())
                    });
                    if !ok {
                        sessions.drop_peer(&peer);
                        let _ = swarm.disconnect_peer_id(peer);
                    }
                    emit(output, PublicEvent::SessionResponse {
                        peer_id: &peer,
                        request_id: display_id(&request_id),
                        ok,
                    })?;
                }
            },
            request_response::Event::OutboundFailure { peer, error, .. } => {
                emit(output, PublicEvent::SessionOutboundFailure { peer_id: &peer, reason: outbound_reason(&error) })?;
            }
            request_response::Event::InboundFailure { peer, request_id, error, .. } => {
                let intentional = output.intentional_omissions.remove(&(peer, request_id));
                if intentional && matches!(error, request_response::InboundFailure::ResponseOmission) {
                    return Ok(()); // Accepted terminal ACK, not a protocol failure.
                }
                sessions.drop_peer(&peer);
                output.intentional_omissions.retain(|(pending_peer, _)| pending_peer != &peer);
                let _ = swarm.disconnect_peer_id(peer);
                emit(output, PublicEvent::SessionInboundFailure { peer_id: &peer })?;
            }
            request_response::Event::ResponseSent { peer, request_id, .. } => {
                output.intentional_omissions.remove(&(peer, request_id));
            }
        },
        SwarmEvent::Behaviour(Event::Discovery(event)) if !stopping => match event {
            discovery::Event::Started(peer) => {
                emit(output, PublicEvent::PeerQueryStarted { peer_id: &peer })?;
                view_slot_with(|view| view.query("query started", &peer.to_string()));
            }
            discovery::Event::Result(peer) => {
                emit(output, PublicEvent::PeerQueryResult { peer_id: &peer })?;
                view_slot_with(|view| view.query("query result", &peer.to_string()));
            }
            discovery::Event::Failure { peer, reason } => {
                emit(output, PublicEvent::PeerQueryFailure { peer_id: &peer, reason })?;
                view_slot_with(|view| view.query("query failed", &peer.to_string()));
            }
            discovery::Event::Candidate { peer, address } => {
                emit(output, PublicEvent::PeerDiscovered { peer_id: &peer, address: &address })?;
                view_slot_with(|view| view.discovered(&peer.to_string(), &address.to_string()));
            }
        },
        SwarmEvent::Dialing { peer_id: Some(peer), connection_id } if !stopping => {
            if let Some(reconnect) = reconnect { reconnect.dialing(peer, connection_id); }
        }
        SwarmEvent::OutgoingConnectionError { connection_id, error, .. } => {
            emit(output, PublicEvent::DialFailed { reason: dial_reason(&error) })?;
            view_slot_with(|view| view.dial_failed(dial_reason(&error)));
            if !stopping && let Some(reconnect) = reconnect {
                scheduled(output, reconnect.failed(connection_id, &error, tokio::time::Instant::now()))?;
            }
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            let reason = match &error {
                ListenError::Denied { cause } if capacity(cause) => "peer_capacity",
                _ => "handshake_failed",
            };
            emit(output, PublicEvent::PeerRejected { reason })?;
            view_slot_with(|view| view.rejected(reason));
        }
        SwarmEvent::ListenerClosed { .. } | SwarmEvent::ListenerError { .. } if !stopping => {
            return Err(Error::Transport);
        }
        _ => {}
    }
    Ok(())
}

fn display_id(request_id: &request_response::OutboundRequestId) -> u64 {
    request_id.to_string().parse().unwrap_or(u64::MAX)
}

fn outbound_reason(error: &request_response::OutboundFailure) -> &'static str {
    match error {
        request_response::OutboundFailure::Timeout => "timeout",
        request_response::OutboundFailure::UnsupportedProtocols => "unsupported",
        request_response::OutboundFailure::Io(_) => "io",
        _ => "other",
    }
}

fn capacity(error: &ConnectionDenied) -> bool {
    error.downcast_ref::<PeerCapacity>().is_some()
        || error.downcast_ref::<connection_limits::Exceeded>().is_some()
}

fn dial_reason(error: &DialError) -> &'static str {
    match error {
        DialError::WrongPeerId { .. } => "peer_id_mismatch",
        DialError::Denied { cause } if capacity(cause) => "peer_capacity",
        DialError::LocalPeerId { .. } => "self_dial",
        _ => "unreachable_or_handshake_failed",
    }
}

pub(super) fn client_swarm(local: libp2p::identity::Keypair) -> Result<Swarm<Behaviour>> {
    Ok(SwarmBuilder::with_existing_identity(local)
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)
        .map_err(|_| Error::Transport)?
        .with_behaviour(|key| Behaviour {
            cohort: PeerCohort { maximum: 1, peers: HashSet::new() },
            limits: connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default()
                    .with_max_pending_incoming(Some(0))
                    .with_max_pending_outgoing(Some(1))
                    .with_max_established(Some(1))
                    .with_max_established_per_peer(Some(1)),
            ),
            ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(5))),
            identify: identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.to_owned(), key.public(),
            ).with_cache_size(0)),
            session: request_response::Behaviour::new(
                [(session::PROTOCOL_ID, request_response::ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30))
                    .with_max_concurrent_streams(1),
            ),
            discovery: None.into(),
        })
        .map_err(|_| Error::Transport)?
        .with_swarm_config(|_| libp2p::swarm::Config::without_executor()
            .with_max_negotiating_inbound_streams(1)
            .with_notify_handler_buffer_size(NonZeroUsize::new(1).expect("nonzero"))
            .with_per_connection_event_buffer_size(2))
        .with_connection_timeout(Duration::from_secs(30))
        .build())
}

/// One-shot `/z2z/session/1` handshake: dial the expected peer, send a Hello
/// envelope with a fresh session id and challenges, and print the decoded
/// response. Exits nonzero on dial/timeout/decode failure.
pub async fn send_hello(options: hello::Options) -> Result<()> {
    use libp2p::swarm::dial_opts::DialOpts;
    let expected = options.expected_peer_id()?;
    let local = libp2p::identity::Keypair::generate_ed25519();
    let ed25519_pair = local.clone().try_into_ed25519().map_err(|_| Error::Transport)?;
    let secret = Zeroizing::new(<[u8; 32]>::try_from(ed25519_pair.secret().as_ref())
        .map_err(|_| Error::Transport)?);
    let coordination = ed25519_dalek::SigningKey::from_bytes(&secret);
    drop(secret);
    drop(ed25519_pair);
    let mut swarm = client_swarm(local)?;
    let mut output = Output::new()?;
    let envelope = session::Envelope {
        lane_id: options.lane_id,
        chain_context_digest: [0; 32],
        deployment_digest: [0; 32],
        session_id: options.session_id(),
        initiator_coord_key: *coordination.verifying_key().as_bytes(),
        responder_coord_key: [0; 32],
        role_map: 0,
        challenge_i: options.challenge_i(),
        challenge_r: [0; 32],
        // §7.2: Hello request uses seq 0.
        seq: 0,
        kind: session::kind::HELLO,
        sent_at_unix: options.sent_at_unix(),
        body: Vec::new(),
        signature: [0; 64],
    };
    let mut envelope = envelope;
    use ed25519_dalek::Signer;
    envelope.signature = coordination.sign(&envelope.signed_bytes()).to_bytes();
    let wire = envelope.to_wire().map_err(|_| Error::SessionEnvelope)?;
    let address: Multiaddr = options.address.parse().map_err(|_| Error::Configuration)?;
    let dial = DialOpts::peer_id(expected).addresses(vec![address]).condition(
        libp2p::swarm::dial_opts::PeerCondition::Always).build();
    swarm.dial(dial).map_err(|_| Error::Transport)?;
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => return Err(Error::SessionTimeout),
            event = swarm.next() => match event.ok_or(Error::Transport)? {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == expected => {
                    let _ = swarm
                        .behaviour_mut()
                        .session
                        .send_request(&peer_id, wire[4..].to_vec());
                }
                SwarmEvent::Behaviour(Event::Session(request_response::Event::Message {
                    peer,
                    connection_id: _,
                    message: request_response::Message::Response { response, .. },
                })) if peer == expected => {
                    let decoded = session::parse(&response).map_err(|_| Error::SessionEnvelope)?;
                    if decoded.kind != session::kind::ACK
                        || decoded.seq != 0
                        || decoded.role_map != envelope.role_map
                        || decoded.lane_id != envelope.lane_id
                        || decoded.session_id != envelope.session_id
                        || decoded.challenge_i != envelope.challenge_i
                        || decoded.initiator_coord_key != envelope.initiator_coord_key
                        || decoded.responder_coord_key == [0; 32]
                        || decoded.challenge_r == [0; 32]
                    {
                        return Err(Error::SessionEnvelope);
                    }
                    // Bind the responder coordination key to the expected
                    // PeerId's Ed25519 transport identity (§7 transcript pin).
                    {
                        let ed_public = libp2p::identity::ed25519::PublicKey::try_from_bytes(
                            &decoded.responder_coord_key,
                        )
                        .map_err(|_| Error::SessionEnvelope)?;
                        let public: libp2p::identity::PublicKey = ed_public.into();
                        if public.to_peer_id() != expected {
                            return Err(Error::SessionEnvelope);
                        }
                    }
                    // Verify the Ack signature by the responder coordination key.
                    {
                        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                        let key = VerifyingKey::from_bytes(&decoded.responder_coord_key)
                            .map_err(|_| Error::SessionEnvelope)?;
                        key.verify(&decoded.signed_bytes(), &Signature::from_bytes(&decoded.signature))
                            .map_err(|_| Error::SessionEnvelope)?;
                    }
                    // Verify the Ack binds this Hello: body = SHA256(signed_bytes).
                    {
                        let expect = envelope.ack_digest();
                        let session::Body::Ack(digest) = session::validate_body(&decoded)
                            .map_err(|_| Error::SessionEnvelope)?
                        else {
                            return Err(Error::SessionEnvelope);
                        };
                        if digest.as_slice() != expect.as_slice() {
                            return Err(Error::SessionEnvelope);
                        }
                    }
                    emit(&mut output, PublicEvent::SessionResponse {
                        peer_id: &peer,
                        request_id: 0,
                        ok: decoded.kind == session::kind::ACK,
                    })?;
                    return Ok(());
                }
                SwarmEvent::Behaviour(Event::Session(request_response::Event::OutboundFailure { error, .. })) => {
                    let _ = error;
                    return Err(Error::SessionTimeout);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == expected => {
                    return Err(Error::Transport);
                }
                _ => {}
            },
        }
    }
}

/// Options for the one-shot Hello handshake.
pub mod hello {
    use clap::Args;
    use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
    use super::{Error, Result};

    #[derive(Args)]
    pub struct Options {
        /// Direct TCP address ending in /p2p/<expected PeerId>.
        #[arg(long)]
        pub address: String,
        /// Optional explicit expected PeerId; defaults to the address suffix.
        #[arg(long)]
        pub peer_id: Option<String>,
        /// Session lane id (u16, default 1).
        #[arg(long, default_value_t = 1)]
        pub lane_id: u16,
    }

    impl Options {
        pub fn expected_peer_id(&self) -> Result<PeerId> {
            if let Some(text) = &self.peer_id {
                return text.parse::<PeerId>().map_err(|_| Error::Configuration);
            }
            let address: Multiaddr = self.address.parse().map_err(|_| Error::Configuration)?;
            for protocol in address.iter() {
                if let Protocol::P2p(peer) = protocol {
                    return Ok(peer);
                }
            }
            Err(Error::Configuration)
        }

        /// Independent random nonzero session id (§7.2).
        pub fn session_id(&self) -> [u8; 32] {
            sent_nonce()
        }

        pub fn challenge_i(&self) -> [u8; 32] {
            sent_nonce()
        }

        pub fn sent_at_unix(&self) -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }
    }

    /// Random nonzero 32 bytes; regenerating on the (2^-256) all-zero draw
    /// is cheaper than rejecting at the peer.
    fn sent_nonce() -> [u8; 32] {
        use rand_core::OsRng;
        use rand_core::RngCore;
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        if nonce == [0_u8; 32] {
            nonce[0] = 1;
        }
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_quote::{NativeRole, QuotePhase, QuoteSelection, QuoteV1, QUOTE_BYTES};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn socket_swarm(identity: libp2p::identity::Keypair) -> Swarm<Behaviour> {
        SwarmBuilder::with_existing_identity(identity).with_tokio()
            .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default).unwrap()
            .with_behaviour(|key| Behaviour {
                cohort: PeerCohort { maximum: 1, peers: HashSet::new() },
                limits: connection_limits::Behaviour::new(connection_limits::ConnectionLimits::default()
                    .with_max_pending_incoming(Some(1)).with_max_pending_outgoing(Some(1))
                    .with_max_established(Some(1)).with_max_established_per_peer(Some(1))),
                ping: ping::Behaviour::new(ping::Config::default()),
                identify: identify::Behaviour::new(identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), key.public()).with_cache_size(0)),
                session: request_response::Behaviour::new([(session::PROTOCOL_ID, request_response::ProtocolSupport::Full)],
                    request_response::Config::default().with_request_timeout(Duration::from_secs(5)).with_max_concurrent_streams(1)),
                discovery: None.into(),
            }).unwrap()
            .with_swarm_config(|_| libp2p::swarm::Config::without_executor().with_idle_connection_timeout(Duration::from_secs(30)))
            .build()
    }

    fn identity() -> (libp2p::identity::Keypair, SigningKey) {
        let identity = libp2p::identity::Keypair::generate_ed25519();
        let pair = identity.clone().try_into_ed25519().unwrap();
        let bytes = Zeroizing::new(<[u8; 32]>::try_from(pair.secret().as_ref()).unwrap());
        let signer = SigningKey::from_bytes(&bytes);
        (identity, signer)
    }

    fn signed(selection: &QuoteSelection, key: &SigningKey, seq: u32, kind: u8, body: &[u8], hello: bool) -> session::Envelope {
        let mut envelope = session::Envelope { lane_id: 5, chain_context_digest: selection.chain_context,
            deployment_digest: selection.deployment_context, session_id: selection.session_id,
            initiator_coord_key: selection.initiator_coord_key,
            responder_coord_key: if hello { [0; 32] } else { selection.responder_coord_key },
            role_map: 0, challenge_i: selection.challenge_i,
            challenge_r: if hello { [0; 32] } else { selection.challenge_r },
            seq, kind, sent_at_unix: super::super::state::now_unix_secs(), body: body.to_vec(), signature: [0; 64] };
        let bytes = Zeroizing::new(envelope.signed_bytes()); envelope.signature = key.sign(&bytes).to_bytes();
        envelope
    }

    struct SocketPair {
        user: Swarm<Behaviour>, solver: Swarm<Behaviour>,
        user_key: SigningKey, solver_key: SigningKey,
        users: session::SessionTable, solvers: session::SessionTable,
        output: Output,
    }

    impl SocketPair {
        async fn new() -> (Self, QuoteSelection, QuoteV1) {
            let (user_id, user_key) = identity(); let (solver_id, solver_key) = identity();
            let mut pair = Self { user: socket_swarm(user_id), solver: socket_swarm(solver_id),
                users: session::SessionTable::new(user_key.verifying_key().to_bytes()),
                solvers: session::SessionTable::new(solver_key.verifying_key().to_bytes()),
                user_key, solver_key, output: Output::new().unwrap() };
            pair.solver.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
            let address = loop { if let SwarmEvent::NewListenAddr { address, .. } = pair.solver.next().await.unwrap() { break address; } };
            pair.user.dial(address).unwrap();
            while !pair.user.is_connected(pair.solver.local_peer_id()) || !pair.solver.is_connected(pair.user.local_peer_id()) {
                let _ = pair.step().await;
            }
            let mut bytes = Zeroizing::new([0_u8; QUOTE_BYTES]);
            for (offset, domain) in [(0, b"Z2Z_NATIVE_QUOTE\0".as_slice()), (91, b"Z2Z_NATIVE_ROUTE\0".as_slice()),
                (303, b"Z2Z_NATIVE_DEPLOY\0".as_slice()), (587, b"Z2Z_NATIVE_WINDOW\0".as_slice())] {
                bytes[offset..offset + domain.len()].copy_from_slice(domain);
                bytes[offset + domain.len()..offset + domain.len() + 2].copy_from_slice(&1_u16.to_be_bytes());
            }
            bytes[19..51].fill(8); bytes[51..83].fill(9); bytes[90] = 1;
            let terms = QuoteV1::decode(bytes.as_slice()).unwrap();
            let selected = QuoteSelection { local_role: NativeRole::User, owner_scope: [1; 32], session_id: [2; 32],
                initiator_coord_key: pair.user_key.verifying_key().to_bytes(), responder_coord_key: pair.solver_key.verifying_key().to_bytes(),
                chain_context: Sha256::digest(&terms.as_bytes()[91..303]).into(), deployment_context: Sha256::digest(&terms.as_bytes()[303..587]).into(),
                quote_id: [8; 32], s_offer_id: [9; 32], u_trade_intent_id: [10; 32], challenge_i: [11; 32], challenge_r: [12; 32],
                proposal_seq: 1, user_acceptance_seq: 3, solver_acceptance_seq: 3 };
            let hello = signed(&selected, &pair.user_key, 0, session::kind::HELLO, &[], true);
            let ack = signed(&selected, &pair.solver_key, 0, session::kind::ACK, &hello.ack_digest(), false);
            let confirmation = signed(&selected, &pair.user_key, 1, session::kind::ACK, &ack.ack_digest(), false);
            let now = super::super::state::now_unix_secs();
            pair.users.retain_confirmed_transcript(pair.solver.local_peer_id(), &hello.payload().unwrap(), &ack.payload().unwrap(), &confirmation.payload().unwrap(), now).unwrap();
            pair.solvers.retain_confirmed_transcript(pair.user.local_peer_id(), &hello.payload().unwrap(), &ack.payload().unwrap(), &confirmation.payload().unwrap(), now).unwrap();
            pair.users.select_native_quote(pair.solver.local_peer_id(), selected).unwrap();
            let mut solver_selection = selected; solver_selection.local_role = NativeRole::Solver;
            pair.solvers.select_native_quote(pair.user.local_peer_id(), solver_selection).unwrap();
            (pair, selected, terms)
        }

        // Both swarms use the same receiving event handler as run-node, not an echo.
        async fn step(&mut self) -> (bool, Option<Zeroizing<Vec<u8>>>, bool) {
            let (user, event) = tokio::select! {
                event = self.user.next() => (true, event.unwrap()),
                event = self.solver.next() => (false, event.unwrap()),
            };
            assert!(!matches!(&event, SwarmEvent::ConnectionClosed { .. }), "authenticated ACK must not disconnect");
            let response = match &event { SwarmEvent::Behaviour(Event::Session(request_response::Event::Message {
                message: request_response::Message::Response { response, .. }, .. })) => Some(Zeroizing::new(response.clone())), _ => None };
            let omitted = matches!(&event, SwarmEvent::Behaviour(Event::Session(request_response::Event::InboundFailure {
                error: request_response::InboundFailure::ResponseOmission, .. })));
            let mut reconnect = None;
            if user {
                handle_event_inner(&mut self.user, &mut self.output, &mut reconnect, event, false, &self.user_key, &mut self.users, None).unwrap();
            } else {
                handle_event_inner(&mut self.solver, &mut self.output, &mut reconnect, event, false, &self.solver_key, &mut self.solvers, None).unwrap();
            }
            (user, response, omitted)
        }

        async fn exchange(&mut self, user: bool, payload: &[u8]) -> Zeroizing<Vec<u8>> {
            if user { self.user.behaviour_mut().session.send_request(self.solver.local_peer_id(), payload.to_vec()); }
            else { self.solver.behaviour_mut().session.send_request(self.user.local_peer_id(), payload.to_vec()); }
            loop {
                let (from_user, response, _) = self.step().await;
                if from_user == user && let Some(response) = response { return response; }
            }
        }
    }

    #[tokio::test]
    async fn socket_terminal_ack_omission_preserves_full_quote_and_genuine_failures_still_close() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (mut pair, selected, terms) = SocketPair::new().await;
            let now = super::super::state::now_unix_secs();
            let proposal = pair.solvers.native_proposal(pair.user.local_peer_id(), &selected.session_id, &terms, &pair.solver_key, now).unwrap();
            let ack = pair.exchange(false, &proposal).await;
            assert_eq!(pair.users.native_quote(pair.solver.local_peer_id(), &selected.session_id).unwrap().phase(), QuotePhase::Proposal);
            let retry = pair.exchange(false, &proposal).await; assert_eq!(ack.as_slice(), retry.as_slice());
            // The genuine terminal ACK may itself arrive as a request (including
            // its exact retransmission). Intentionally no ACK-of-ACK is sent.
            pair.user.behaviour_mut().session.send_request(pair.solver.local_peer_id(), ack.to_vec());
            loop { let (user, _, omitted) = pair.step().await; if !user && omitted { break; } }
            assert!(pair.output.intentional_omissions.is_empty(), "consume the exact omission exemption");
            assert!(pair.solvers.native_quote(pair.user.local_peer_id(), &selected.session_id).is_some());
            let acceptance = pair.users.native_acceptance(pair.solver.local_peer_id(), &selected.session_id, &pair.user_key, now).unwrap();
            let ack = pair.exchange(true, &acceptance).await;
            let retry = pair.exchange(true, &acceptance).await; assert_eq!(ack.as_slice(), retry.as_slice());
            let agreement = pair.solvers.native_acceptance(pair.user.local_peer_id(), &selected.session_id, &pair.solver_key, now).unwrap();
            let ack = pair.exchange(false, &agreement).await;
            let retry = pair.exchange(false, &agreement).await; assert_eq!(ack.as_slice(), retry.as_slice());
            let user_quote = pair.users.native_quote(pair.solver.local_peer_id(), &selected.session_id).unwrap();
            let solver_quote = pair.solvers.native_quote(pair.user.local_peer_id(), &selected.session_id).unwrap();
            assert_eq!(user_quote.phase(), QuotePhase::Agreed); assert_eq!(solver_quote.phase(), QuotePhase::Agreed);
            assert_eq!(user_quote.agreement_digest(), solver_quote.agreement_digest());
            // A different omission is not exempt: obtain a real inbound id from
            // the socket, omit its channel without authenticating a terminal ACK.
            pair.user.behaviour_mut().session.send_request(pair.solver.local_peer_id(), proposal.to_vec());
            loop {
                tokio::select! {
                    event = pair.user.next() => { let event = event.unwrap(); let mut reconnect = None;
                        handle_event_inner(&mut pair.user, &mut pair.output, &mut reconnect, event, false, &pair.user_key, &mut pair.users, None).unwrap(); }
                    event = pair.solver.next() => { let event = event.unwrap();
                        if let SwarmEvent::Behaviour(Event::Session(request_response::Event::Message {
                            message: request_response::Message::Request { channel, .. }, .. })) = event { drop(channel); break; } }
                }
            }
            loop { let (user, _, omitted) = pair.step().await; if !user && omitted { break; } }
            assert!(pair.solvers.native_quote(pair.user.local_peer_id(), &selected.session_id).is_none(), "genuine failures destroy session");
        }).await.expect("bounded real loopback quote exchange must finish");
    }
}
