//! Minimal terminal dashboard for `z2z-node`. Hand-rolled ANSI + rustix termios
//! only: no new crates, no per-frame allocation growth, one extra input thread.
//!
//! The dashboard renders bounded node state from the transport event stream in
//! an alternate screen. It displays only public transport facts (peer id,
//! listen address, peers, ping RTT, event log). It never renders owner keys,
//! orders, wallets or proving artifacts; `run --headless` keeps the exact
//! existing NDJSON output for scripts and tests.
//!
//! ponytail: fixed 2 Hz full-screen redraw with whole-line ANSI writes. A
//! diff-based renderer is unnecessary at this state size; add one only if
//! profiling shows terminal bandwidth problems.

use rustix::termios;
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::time::Instant;

const LOG_LINES: usize = 200;

pub(crate) const EVENT_TICK_MS: u64 = 500;

/// Public view state accumulated from `PublicEvent`s. Every field is a
/// bounded, non-secret transport fact.
pub(crate) struct View {
    identity: &'static str,
    peer_id: String,
    listen: String,
    max_peers: u32,
    persistent_identity: bool,
    peer_discovery: bool,
    reconnect: bool,
    peers: BTreeMap<String, PeerRow>,
    log: VecDeque<String>,
    session_requests: u32,
    session_rejects: u32,
    started: Instant,
    stopped: Option<&'static str>,
}

#[derive(Default)]
struct PeerRow {
    connected: bool,
    identified: bool,
    protocol_ok: bool,
    rtt_ms: Option<u64>,
}

impl View {
    pub(crate) fn new(
        identity: &'static str,
        peer_id: String,
        listen: String,
        max_peers: u32,
        persistent_identity: bool,
        peer_discovery: bool,
        reconnect: bool,
    ) -> Self {
        let mut log = VecDeque::new();
        push_log(
            &mut log,
            format!("started peer_id={peer_id} max_peers={max_peers} identity={identity}"),
        );
        Self {
            identity,
            peer_id,
            listen,
            max_peers,
            persistent_identity,
            peer_discovery,
            reconnect,
            peers: BTreeMap::new(),
            log,
            session_requests: 0,
            session_rejects: 0,
            started: Instant::now(),
            stopped: None,
        }
    }

    pub(crate) fn log(&mut self, line: String) {
        push_log(&mut self.log, line);
    }

    pub(crate) fn set_listen(&mut self, address: String) {
        self.listen = address;
    }

    pub(crate) fn connect(&mut self, peer: &str, connected_peers: usize) {
        let row = self.peers.entry(peer.to_owned()).or_default();
        row.connected = true;
        self.log(format!("peer connected (total {connected_peers})"));
    }

    pub(crate) fn disconnect(&mut self, peer: &str, connected_peers: usize) {
        if let Some(row) = self.peers.get_mut(peer) {
            row.connected = false;
            row.rtt_ms = None;
        }
        self.log(format!("peer disconnected (total {connected_peers})"));
    }

    pub(crate) fn identified(&mut self, peer: &str, protocol_ok: bool) {
        let row = self.peers.entry(peer.to_owned()).or_default();
        row.identified = true;
        row.protocol_ok = protocol_ok;
    }

    pub(crate) fn identify_failed(&mut self, peer: &str) {
        if let Some(row) = self.peers.get_mut(peer) {
            row.identified = false;
            row.protocol_ok = false;
        }
    }

    pub(crate) fn ping(&mut self, peer: &str, rtt_ms: u64) {
        let row = self.peers.entry(peer.to_owned()).or_default();
        row.rtt_ms = Some(rtt_ms);
    }

    pub(crate) fn ping_failed(&mut self, peer: &str, reason: &'static str) {
        self.log(format!("ping failed: {peer} ({reason})"));
    }

    pub(crate) fn dial_failed(&mut self, reason: &'static str) {
        self.log(format!("dial failed: {reason}"));
    }

    pub(crate) fn rejected(&mut self, reason: &'static str) {
        self.log(format!("peer rejected: {reason}"));
    }

    /// Count one admitted signed session request (§7 admission gate passed).
    pub(crate) fn session_request(&mut self, peer: &str, kind: u8, seq: u32) {
        self.session_requests += 1;
        self.log(format!("session request from {peer} (kind {kind}, seq {seq})"));
    }

    /// Count one admission-gate rejection (bad signature/timestamp/dedup/parse).
    pub(crate) fn session_reject(&mut self) {
        self.session_rejects += 1;
    }

    pub(crate) fn retry_scheduled(&mut self, peer: &str, attempt: u8, delay_ms: u64) {
        self.log(format!("retry scheduled for peer (attempt {attempt}, delay {delay_ms}ms)"));
        if let Some(row) = self.peers.get_mut(peer) {
            row.connected = false;
        }
    }

    pub(crate) fn query(&mut self, kind: &str, peer: &str) {
        self.log(format!("discovery {kind}: {peer}"));
    }

    pub(crate) fn discovered(&mut self, peer: &str, address: &str) {
        self.log(format!("discovered peer via discovery at {address}"));
        let _ = self.peers.entry(peer.to_owned()).or_default();
    }

    pub(crate) fn stop(&mut self, reason: &'static str, connected_peers: usize) {
        self.stopped = Some(reason);
        self.log(format!("node stopped ({reason}), {connected_peers} peers remaining"));
    }
}

fn push_log(log: &mut VecDeque<String>, line: String) {
    if log.len() == LOG_LINES {
        log.pop_front();
    }
    log.push_back(line);
}

/// Owns the terminal raw/alternate-screen mode for the process lifetime.
/// `stdin` is process-owned and never closed here; `drop` restores the mode.
pub(crate) struct Terminal {
    saved: termios::Termios,
}

impl Terminal {
    pub(crate) fn enter() -> Result<Self, ()> {
        let stdin = std::io::stdin();
        let saved = termios::tcgetattr(&stdin).map_err(|_| ())?;
        let mut raw = saved.clone();
        raw.make_raw();
        termios::tcsetattr(&stdin, termios::OptionalActions::Now, &raw).map_err(|_| ())?;
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[?1049h\x1b[?25l"); // alt screen, hide cursor
        let _ = out.flush();
        Ok(Self { saved })
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let stdin = std::io::stdin();
        let _ = termios::tcsetattr(&stdin, termios::OptionalActions::Now, &self.saved);
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[?25h\x1b[?1049l"); // show cursor, leave alt screen
        let _ = out.flush();
    }
}

/// Size-capped key events delivered from the dedicated input thread.
pub(crate) enum Key {
    Quit,
    Clear,
    Other,
}

/// One bounded nonblocking read pass over pending stdin bytes, returning the
/// first recognized key. `Ok(None)` means no input is ready. Terminal EOF is
/// surfaced as `Quit` so a closed controlling terminal exits cleanly.
pub(crate) fn poll_key() -> std::io::Result<Option<Key>> {
    use std::os::fd::AsFd as _;
    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    let mut fds = [rustix::event::PollFd::new(&fd, rustix::event::PollFlags::IN)];
    let ready = rustix::event::poll(
        &mut fds,
        Some(&rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 }),
    )
    .unwrap_or(0);
    if ready == 0 || (fds[0].revents() & (rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP)).is_empty() {
        return Ok(None);
    }
    if fds[0].revents().contains(rustix::event::PollFlags::HUP)
        && !fds[0].revents().contains(rustix::event::PollFlags::IN)
    {
        return Ok(Some(Key::Quit));
    }
    let mut byte = [0_u8; 1];
    let read = std::io::Read::read(&mut std::io::stdin().lock(), &mut byte)?;
    if read == 0 {
        return Ok(Some(Key::Quit)); // EOF: controlling terminal closed
    }
    Ok(Some(match byte[0] {
        b'q' | b'Q' => Key::Quit,
        3 => Key::Quit,    // Ctrl-C byte (SIGINT also fires)
        12 => Key::Clear,  // Ctrl-L
        _ => Key::Other,
    }))
}

const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const RESET: &str = "\x1b[0m";

pub(crate) fn render(view: &View) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let Ok(size) = termios::tcgetwinsize(&stdin) else { return Ok(()) };
    let (rows, cols) = (size.ws_row.max(10) as usize, size.ws_col.max(40) as usize);
    let _ = cols;
    let mut out = std::io::stdout().lock();
    out.write_all(b"\x1b[H\x1b[2J")?;

    let mut line: usize = 1;
    macro_rules! put {
        ($text:expr) => {{
            let text: std::borrow::Cow<'_, str> = std::borrow::Cow::Owned($text);
            out.write_all(format!("\x1b[{line};1H\x1b[K{}", text).as_bytes())?;
            line += 1;
        }};
    }

    let elapsed = view.started.elapsed().as_secs();
    let status = match view.stopped {
        Some(reason) => format!("stopped ({reason})"),
        None => "running".to_owned(),
    };
    let (status_color, status_reset) = if view.stopped.is_some() {
        (YELLOW, RESET)
    } else {
        (GREEN, RESET)
    };
    put!(format!(
        "{BOLD}z2z-node{RESET}  {status_color}{status}{status_reset}  up={elapsed}s  mode={}  identity={}",
        if view.persistent_identity { "persistent" } else { "ephemeral" },
        view.identity
    ));
    put!(format!(
        "{DIM}peer_id={}{RESET}  max_peers={}",
        view.peer_id, view.max_peers
    ));
    put!(format!("listen: {CYAN}{}{RESET}", view.listen));
    put!(format!(
        "flags: discovery={} reconnect={}",
        on_off(view.peer_discovery),
        on_off(view.reconnect)
    ));
    put!(format!(
        "session: requests={} rejected={} ({RED}no financial kinds executed{RESET})",
        view.session_requests, view.session_rejects
    ));

    line += 1;
    let connected: Vec<(&String, &PeerRow)> =
        view.peers.iter().filter(|(_, row)| row.connected).collect();
    put!(format!(
        "{BOLD}peers {}/{}{RESET}",
        connected.len(),
        view.max_peers
    ));
    let peer_rows = (rows / 2).min(connected.len().max(1));
    if connected.is_empty() {
        put!(format!("{DIM}  (no connected peers){RESET}"));
    }
    for (peer, row) in connected.iter().take(peer_rows) {
        let rtt = match row.rtt_ms {
            Some(ms) => format!("{GREEN}rtt={ms}ms{RESET}"),
            None => format!("{DIM}rtt=--{RESET}"),
        };
        let id_ok = if row.identified {
            if row.protocol_ok {
                format!("{GREEN}id=ok{RESET}")
            } else {
                format!("{YELLOW}id=mismatch{RESET}")
            }
        } else {
            format!("{DIM}id=--{RESET}")
        };
        put!(format!("  {peer}  {rtt}  {id_ok}"));
    }

    line += 1;
    put!(format!("{BOLD}events{RESET} (q=quit, Ctrl-L=clear)"));
    let log_start = rows.saturating_sub(line + 1);
    let skip = view.log.len().saturating_sub(log_start);
    for entry in view.log.iter().skip(skip) {
        put!(format!("{DIM}  {entry}{RESET}"));
    }
    out.flush()
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

pub(crate) fn clear() -> std::io::Result<()> {
    let mut out = std::io::stdout();
    out.write_all(b"\x1b[H\x1b[2J\x1b[3J")?;
    out.flush()
}
