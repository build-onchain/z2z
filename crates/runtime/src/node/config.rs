use super::{Error, Result};
use clap::Args;
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use serde::Deserialize;
use std::{collections::HashSet, path::PathBuf};

const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_ADDRESS_BYTES: usize = 256;
const MAX_PEERS: u32 = 64;
const MAX_RUN_MS: u64 = 3_600_000;

#[derive(Args)]
pub(super) struct Options {
    /// Strict public JSON configuration; cannot be combined with transport flags.
    #[arg(long, conflicts_with_all = ["listen", "dial", "max_peers", "run_for_ms", "peer_discovery", "find_peer", "discovery_loopback", "reconnect", "peer_identity_file", "dkg_peer", "dkg_pool_id", "dkg_j_params", "dkg_chain_context", "dkg_deployment_context"])]
    config: Option<PathBuf>,
    /// One explicit /ip4 or /ip6 TCP listen address; port 0 selects a free port.
    #[arg(long, required_unless_present = "config")]
    listen: Option<String>,
    /// Direct TCP address ending in /p2p/<expected PeerId>; repeat for distinct peers.
    #[arg(long)]
    dial: Vec<String>,
    /// Opt in to an immutable transport key in an existing external owner-private directory.
    #[arg(long)]
    peer_identity_file: Option<PathBuf>,
    /// Opt in to ephemeral DKG with exactly this Ed25519 transport PeerId.
    #[arg(long, requires_all = ["dkg_pool_id", "dkg_j_params", "dkg_chain_context", "dkg_deployment_context"])]
    dkg_peer: Option<String>,
    /// Caller-selected pool byte; no pool mapping is inferred.
    #[arg(long, requires = "dkg_peer")]
    dkg_pool_id: Option<u8>,
    /// Exact caller-frozen J parameter bytes, lowercase hex, 1..=256 bytes.
    #[arg(long, requires = "dkg_peer")]
    dkg_j_params: Option<String>,
    /// Caller-selected nonzero chain-context digest, 32 bytes of lowercase hex.
    #[arg(long, requires = "dkg_peer")]
    dkg_chain_context: Option<String>,
    /// Caller-selected nonzero deployment-context digest, 32 bytes of lowercase hex.
    #[arg(long, requires = "dkg_peer")]
    dkg_deployment_context: Option<String>,
    /// Retry configured expected peers after transient outages; three lifetime retries.
    #[arg(long)]
    reconnect: bool,
    /// Active connections and lifetime distinct-peer cohort; default 8, maximum 64.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=64))]
    max_peers: Option<u32>,
    /// Stop after this many milliseconds; otherwise run until Ctrl-C.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3_600_000))]
    run_for_ms: Option<u64>,
    /// Serve peer-only Kademlia in the Z2Z namespace; disabled by default.
    #[arg(long)]
    peer_discovery: bool,
    /// Find one expected PeerId through an explicitly dialed seed, once.
    #[arg(long, requires = "peer_discovery")]
    find_peer: Option<String>,
    /// Permit literal loopback discovery addresses for controlled local processes.
    #[arg(long, requires = "peer_discovery")]
    discovery_loopback: bool,
    /// Force the NDJSON event stream even on an interactive terminal.
    #[arg(long, conflicts_with = "tui")]
    headless: bool,
    /// Force the interactive dashboard; errors when stdin/stdout are not a TTY.
    #[arg(long)]
    tui: bool,
    /// Write the latest public node-state snapshot (JSON) to this path.
    #[arg(long)]
    state_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    schema_version: u16,
    listen: String,
    #[serde(default)]
    dial: Vec<String>,
    #[serde(default = "default_max_peers")]
    max_peers: u32,
    #[serde(default)]
    run_for_ms: Option<u64>,
    #[serde(default)]
    peer_discovery: bool,
    #[serde(default)]
    find_peer: Option<String>,
    #[serde(default)]
    discovery_loopback: bool,
    #[serde(default)]
    reconnect: bool,
    #[serde(default)]
    peer_identity_file: Option<PathBuf>,
    #[serde(default)]
    dkg_peer: Option<String>,
    #[serde(default)]
    dkg_pool_id: Option<u8>,
    #[serde(default)]
    dkg_j_params: Option<String>,
    #[serde(default)]
    dkg_chain_context: Option<String>,
    #[serde(default)]
    dkg_deployment_context: Option<String>,
    /// Accepted from the CLI for symmetry; NDJSON is the non-TTY default.
    #[serde(default)]
    #[allow(dead_code)]
    headless: bool,
    #[serde(default)]
    tui: bool,
    #[serde(default)]
    state_file: Option<PathBuf>,
}

fn default_max_peers() -> u32 {
    8
}

pub(super) struct Config {
    pub listen: Multiaddr,
    pub dial: Vec<Multiaddr>,
    pub max_peers: u32,
    pub run_for_ms: Option<u64>,
    pub peer_discovery: bool,
    pub find_peer: Option<PeerId>,
    pub discovery_loopback: bool,
    pub reconnect: bool,
    pub peer_identity_file: Option<PathBuf>,
    pub dkg: Option<DkgPolicy>,
    pub tui: bool,
    pub state_file: Option<PathBuf>,
}

pub(super) struct DkgParameters {
    pub pool_id: u8,
    pub j_params: Vec<u8>,
    pub chain_context: [u8; 32],
    pub deployment_context: [u8; 32],
}

pub(super) struct DkgPolicy {
    pub peer: PeerId,
    pub parameters: DkgParameters,
}

impl DkgParameters {
    pub(super) fn parse(pool_id: u8, j: &str, chain: &str, deployment: &str) -> Result<Self> {
        if !(2..=512).contains(&j.len()) {
            return Err(Error::Configuration);
        }
        let j_params = crate::market::native::unhex(j).map_err(|_| Error::Configuration)?;
        Ok(Self {
            pool_id,
            j_params,
            chain_context: context_hex(chain)?,
            deployment_context: context_hex(deployment)?,
        })
    }
}

fn context_hex(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 { return Err(Error::Configuration); }
    let bytes: [u8; 32] = crate::market::native::unhex(text)
        .map_err(|_| Error::Configuration)?.try_into().map_err(|_| Error::Configuration)?;
    if bytes == [0; 32] { return Err(Error::Configuration); }
    Ok(bytes)
}

/// This profile binds coordination keys to inline Ed25519 transport identities.
pub(super) fn peer_coord_key(peer: &PeerId) -> Result<[u8; 32]> {
    if peer.as_ref().code() != 0 { return Err(Error::Configuration); }
    let public = libp2p::identity::PublicKey::try_decode_protobuf(peer.as_ref().digest())
        .map_err(|_| Error::Configuration)?;
    if public.to_peer_id() != *peer { return Err(Error::Configuration); }
    let key = public.try_into_ed25519().map_err(|_| Error::Configuration)?.to_bytes();
    if key == [0; 32] { return Err(Error::Configuration); }
    ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| Error::Configuration)?;
    Ok(key)
}

impl Config {
    pub(super) fn from_options(options: Options) -> Result<Self> {
        let file = match options.config {
            Some(path) => {
                let bytes = crate::market::config::read_bytes(&path, MAX_CONFIG_BYTES)
                    .map_err(|_| Error::Configuration)?;
                serde_json::from_slice::<FileConfig>(&bytes).map_err(|_| Error::Configuration)?
            }
            None => FileConfig {
                schema_version: 1,
                listen: options.listen.ok_or(Error::Configuration)?,
                dial: options.dial,
                max_peers: options.max_peers.unwrap_or_else(default_max_peers),
                run_for_ms: options.run_for_ms,
                peer_discovery: options.peer_discovery,
                find_peer: options.find_peer,
                discovery_loopback: options.discovery_loopback,
                reconnect: options.reconnect,
                peer_identity_file: options.peer_identity_file,
                dkg_peer: options.dkg_peer,
                dkg_pool_id: options.dkg_pool_id,
                dkg_j_params: options.dkg_j_params,
                dkg_chain_context: options.dkg_chain_context,
                dkg_deployment_context: options.dkg_deployment_context,
                headless: options.headless,
                tui: options.tui,
                state_file: options.state_file,
            },
        };
        if file.schema_version != 1
            || !(1..=MAX_PEERS).contains(&file.max_peers)
            || file.dial.len() > file.max_peers as usize
            || file.run_for_ms.is_some_and(|ms| !(1..=MAX_RUN_MS).contains(&ms))
            || (!file.peer_discovery && (file.find_peer.is_some() || file.discovery_loopback))
            || (file.find_peer.is_some() && file.dial.is_empty())
            || (file.reconnect && file.dial.is_empty())
        {
            return Err(Error::Configuration);
        }
        let dkg = match (
            file.dkg_peer.as_deref(), file.dkg_pool_id, file.dkg_j_params.as_deref(),
            file.dkg_chain_context.as_deref(), file.dkg_deployment_context.as_deref(),
        ) {
            (None, None, None, None, None) => None,
            (Some(text), Some(pool), Some(j), Some(chain), Some(deployment)) => {
                if text.len() > MAX_ADDRESS_BYTES { return Err(Error::Configuration); }
                let peer: PeerId = text.parse().map_err(|_| Error::Configuration)?;
                peer_coord_key(&peer)?;
                Some(DkgPolicy { peer, parameters: DkgParameters::parse(pool, j, chain, deployment)? })
            }
            _ => return Err(Error::Configuration),
        };
        let listen = address(&file.listen, false)?;
        let find_peer = file.find_peer.as_deref().map(|text| {
            if text.len() > MAX_ADDRESS_BYTES { return Err(Error::Configuration); }
            text.parse::<PeerId>().map_err(|_| Error::Configuration)
        }).transpose()?;
        let mut peers = HashSet::with_capacity(file.dial.len());
        let mut dial = Vec::with_capacity(file.dial.len());
        for text in file.dial {
            let address = address(&text, true)?;
            let Some(Protocol::P2p(peer)) = address.iter().last() else {
                return Err(Error::Configuration);
            };
            if file.peer_discovery {
                checked_discovery_address(&address, peer, file.discovery_loopback)
                    .map_err(|_| Error::Configuration)?;
            }
            if !peers.insert(peer) {
                return Err(Error::Configuration);
            }
            dial.push(address);
        }
        Ok(Self {
            listen, dial, max_peers: file.max_peers, run_for_ms: file.run_for_ms,
            peer_discovery: file.peer_discovery, find_peer, discovery_loopback: file.discovery_loopback,
            reconnect: file.reconnect,
            peer_identity_file: file.peer_identity_file,
            dkg,
            tui: file.tui,
            state_file: file.state_file,
        })
    }
}

pub(super) fn address(text: &str, dial: bool) -> Result<Multiaddr> {
    if text.len() > MAX_ADDRESS_BYTES {
        return Err(Error::Configuration);
    }
    let address: Multiaddr = text.parse().map_err(|_| Error::Configuration)?;
    let mut parts = address.iter();
    let host_valid = match parts.next() {
        Some(Protocol::Ip4(ip)) => !ip.is_multicast() && (!dial || !ip.is_unspecified()),
        Some(Protocol::Ip6(ip)) => !ip.is_multicast() && (!dial || !ip.is_unspecified()),
        _ => false,
    };
    if !host_valid
        || !matches!(parts.next(), Some(Protocol::Tcp(port)) if !dial || port != 0)
        || if dial { !matches!(parts.next(), Some(Protocol::P2p(_))) } else { false }
        || parts.next().is_some()
    {
        return Err(Error::Configuration);
    }
    Ok(address)
}

pub(super) fn dial_peer(address: &Multiaddr) -> PeerId {
    match address.iter().last() {
        Some(Protocol::P2p(peer)) => peer,
        _ => unreachable!("validated direct peer address"),
    }
}

/// Only literal publicly routable TCP candidates, bound to the expected Noise identity.
/// Loopback is a separate opt-in, never permission for private LAN/link-local ranges.
pub(super) fn checked_discovery_address(
    address: &Multiaddr, peer: PeerId, loopback: bool,
) -> std::result::Result<(), ()> {
    if address.len() > MAX_ADDRESS_BYTES { return Err(()); }
    let mut parts = address.iter();
    let valid_ip = match parts.next() {
        Some(Protocol::Ip4(ip)) => discovery_ipv4(ip, loopback),
        Some(Protocol::Ip6(ip)) => match ip.to_ipv4_mapped() {
            Some(ip) => discovery_ipv4(ip, loopback),
            None => (loopback && ip.is_loopback()) || {
                let segments = ip.segments();
                // Accept IPv6 global unicast only; exclude protocol-assignment and documentation.
                (segments[0] & 0xe000) == 0x2000
                    && !(segments[0] == 0x2001 && segments[1] < 0x0200)
                    && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                    && !(segments[0] == 0x2002)
                    && !(segments[0] == 0x3fff && segments[1] < 0x1000)
            },
        },
        _ => false,
    };
    if !valid_ip
        || !matches!(parts.next(), Some(Protocol::Tcp(port)) if port != 0)
        || !matches!(parts.next(), Some(Protocol::P2p(id)) if id == peer)
        || parts.next().is_some()
    { return Err(()); }
    Ok(())
}

fn discovery_ipv4(ip: std::net::Ipv4Addr, loopback: bool) -> bool {
    if ip.is_loopback() { return loopback; }
    let [a, b, c, _] = ip.octets();
    !ip.is_private() && !ip.is_link_local() && !ip.is_multicast() && !ip.is_broadcast()
        && a != 0 && a < 240
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 192 && b == 0 && c == 0)
        && !ip.is_documentation()
        && !(a == 198 && (b == 18 || b == 19))
}
