//! Peer-only Kademlia. Every outbound address crosses policy before the swarm.
use super::config;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, kad,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, DialError, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm, behaviour::DialFailure, dial_opts::DialOpts,
    },
};
use std::{collections::HashMap, num::NonZeroUsize, task::{Context, Poll}, time::Duration};

pub(super) const PROTOCOL: StreamProtocol = StreamProtocol::new("/z2z/peer-discovery/kad/1.0.0");
type Kad = kad::Behaviour<kad::store::MemoryStore>;

pub(super) enum Event {
    Started(PeerId),
    Candidate { peer: PeerId, address: Multiaddr },
    Result(PeerId),
    Failure { peer: PeerId, reason: &'static str },
}

#[derive(Debug)]
struct AddressDenied;
impl std::fmt::Display for AddressDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("discovery address denied")
    }
}
impl std::error::Error for AddressDenied {}

pub(super) struct Discovery {
    inner: Kad,
    local: PeerId,
    maximum: usize,
    loopback: bool,
    // Failed attempts remain counted. No failed-ID list can grow beyond this cohort.
    attempts: HashMap<PeerId, Multiaddr>,
    routing: HashMap<PeerId, Multiaddr>,
    target: Option<PeerId>,
    query: Option<kad::QueryId>,
    query_started: bool,
    failure: Option<&'static str>,
    pending_event: Option<Event>,
    pending_dial: Option<DialOpts>,
    stopping: bool,
}

impl Discovery {
    pub(super) fn new(local: PeerId, config: &config::Config) -> Self {
        let maximum = config.max_peers as usize;
        let one = NonZeroUsize::new(1).expect("nonzero constant");
        let bound = NonZeroUsize::new(maximum).expect("validated peer bound");
        let mut settings = kad::Config::new(PROTOCOL);
        settings.set_closest_peer_limits(bound, one, NonZeroUsize::new(256).unwrap())
            .set_max_packet_size(4096)
            .set_query_timeout(Duration::from_secs(10))
            .set_substreams_timeout(Duration::from_secs(5))
            .set_parallelism(one)
            .set_replication_factor(NonZeroUsize::new(maximum.min(20)).unwrap())
            .set_kbucket_inserts(kad::BucketInserts::Manual)
            .set_periodic_bootstrap_interval(None)
            .set_automatic_bootstrap_throttle(None)
            .set_replication_interval(None)
            .set_publication_interval(None)
            .set_provider_publication_interval(None)
            .set_record_filtering(kad::StoreInserts::FilterBoth)
            .set_caching(kad::Caching::Disabled);
        let store = kad::store::MemoryStore::with_config(local, kad::store::MemoryStoreConfig {
            max_records: 0, max_value_bytes: 0, max_providers_per_key: 0, max_provided_keys: 0,
        });
        let mut inner = Kad::with_config(local, store, settings);
        inner.set_mode(Some(kad::Mode::Server));
        let mut attempts = HashMap::with_capacity(maximum);
        for address in &config.dial {
            attempts.insert(config::dial_peer(address), address.clone());
        }
        Self {
            inner, local, maximum, loopback: config.discovery_loopback, attempts,
            routing: HashMap::with_capacity(maximum), target: config.find_peer,
            query: None, query_started: false, failure: None,
            pending_event: None, pending_dial: None, stopping: false,
        }
    }

    // Called only after Noise establishment and identify's authenticated protocol list.
    // Never ingest identify.listen_addrs or an inbound ephemeral source port.
    pub(super) fn identified(&mut self, peer: PeerId, supports_kad: bool) {
        if self.stopping || !supports_kad { return; }
        if let Some(address) = self.attempts.get(&peer) {
            if !self.routing.contains_key(&peer) && self.routing.len() < self.maximum {
                self.routing.insert(peer, address.clone());
                self.inner.add_address(&peer, address.clone());
            }
            if !self.query_started && let Some(target) = self.target {
                self.query_started = true;
                if target == self.local || self.inner.iter_queries().next().is_some() {
                    self.pending_event = Some(Event::Failure { peer: target, reason: "query_policy" });
                } else {
                    self.query = Some(self.inner.get_n_closest_peers(target,
                        NonZeroUsize::new(self.maximum.min(20)).unwrap()));
                    self.pending_event = Some(Event::Started(target));
                }
            }
        }
    }

    pub(super) fn stop(&mut self) {
        self.stopping = true;
        self.pending_dial = None;
        self.pending_event = None;
        if let Some(id) = self.query && let Some(mut query) = self.inner.query_mut(&id) {
            query.finish();
        }
    }

    fn reject(&mut self, peer: Option<PeerId>, id: ConnectionId, reason: &'static str) {
        // Real Kad failure bookkeeping, not a fabricated successful completion.
        let error = DialError::Denied { cause: ConnectionDenied::new(AddressDenied) };
        self.inner.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: peer, error: &error, connection_id: id,
        }));
        if !self.stopping {
            self.failure.get_or_insert(reason);
            if let Some(id) = self.query && let Some(mut query) = self.inner.query_mut(&id) {
                query.finish();
            }
        }
    }
}

/// Validate the whole union before deduplicating identical checked addresses.
/// A second distinct address or poisoned suffix invalidates the complete candidate.
fn checked_address_union<'a>(
    addresses: impl IntoIterator<Item = &'a Multiaddr>, peer: PeerId, loopback: bool,
) -> Result<&'a Multiaddr, ()> {
    let mut selected: Option<&Multiaddr> = None;
    for address in addresses {
        config::checked_discovery_address(address, peer, loopback)?;
        if selected.is_some_and(|selected| selected != address) { return Err(()); }
        selected = Some(address);
    }
    selected.ok_or(())
}

fn checked_address(addresses: &[Multiaddr], peer: PeerId, loopback: bool) -> Result<Multiaddr, ()> {
    checked_address_union(addresses, peer, loopback).cloned()
}

impl NetworkBehaviour for Discovery {
    type ConnectionHandler = THandler<Kad>;
    type ToSwarm = Event;

    fn handle_pending_inbound_connection(
        &mut self, id: ConnectionId, local: &Multiaddr, remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner.handle_pending_inbound_connection(id, local, remote)
    }

    fn handle_established_inbound_connection(
        &mut self, id: ConnectionId, peer: PeerId, local: &Multiaddr, remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(id, peer, local, remote)
    }

    fn handle_pending_outbound_connection(
        &mut self, _: ConnectionId, peer: Option<PeerId>, addresses: &[Multiaddr], _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let allowed = !self.stopping && peer.is_some_and(|peer|
            checked_address(addresses, peer, self.loopback).is_ok());
        if !allowed { return Err(ConnectionDenied::new(AddressDenied)); }
        // Never extend an explicit dial with behaviour-supplied addresses.
        Ok(Vec::new())
    }

    fn handle_established_outbound_connection(
        &mut self, id: ConnectionId, peer: PeerId, address: &Multiaddr, role: Endpoint, port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        config::checked_discovery_address(address, peer, self.loopback)
            .map_err(|_| ConnectionDenied::new(AddressDenied))?;
        self.inner.handle_established_outbound_connection(id, peer, address, role, port)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        // No unchecked remote address change/cache or inferred external addresses.
        if matches!(event, FromSwarm::AddressChange(_) | FromSwarm::NewExternalAddrOfPeer(_)) { return; }
        self.inner.on_swarm_event(event);
        if let FromSwarm::ConnectionClosed(closed) = event && closed.remaining_established == 0 {
            self.routing.remove(&closed.peer_id);
            self.inner.remove_peer(&closed.peer_id);
        }
    }

    fn on_connection_handler_event(
        &mut self, peer: PeerId, id: ConnectionId, event: THandlerOutEvent<Self>,
    ) {
        self.inner.on_connection_handler_event(peer, id, event);
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Event, THandlerInEvent<Self>>> {
        if let Some(event) = self.pending_event.take() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }
        if let Some(opts) = self.pending_dial.take() && !self.stopping {
            return Poll::Ready(ToSwarm::Dial { opts });
        }
        loop {
            let action = match self.inner.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(action) => action,
            };
            match action {
                ToSwarm::Dial { opts } => {
                    let peer = opts.get_peer_id();
                    let id = opts.connection_id();
                    if self.stopping { self.reject(peer, id, "stopping"); continue; }
                    let Some(peer) = peer else { self.reject(None, id, "address_policy"); continue; };
                    // Upstream Kad emits bare-peer dials. Resolve its entire routing/query union
                    // ourselves, before letting the swarm touch DNS, sockets or address caches.
                    let addresses = self.inner.handle_pending_outbound_connection(id,
                        Some(peer), &[], Endpoint::Dialer);
                    let address = match addresses.ok().and_then(|addresses|
                        checked_address(&addresses, peer, self.loopback).ok()) {
                        Some(address) => address,
                        None => { self.reject(Some(peer), id, "address_policy"); continue; }
                    };
                    if peer == self.local { self.reject(Some(peer), id, "address_policy"); continue; }
                    let first = !self.attempts.contains_key(&peer);
                    if first && self.attempts.len() == self.maximum {
                        self.reject(Some(peer), id, "resource_limit"); continue;
                    }
                    if self.attempts.get(&peer).is_some_and(|previous| previous != &address) {
                        self.reject(Some(peer), id, "address_policy"); continue;
                    }
                    let opts = DialOpts::peer_id(peer).addresses(vec![address.clone()]).build();
                    if first {
                        self.attempts.insert(peer, address.clone());
                        self.pending_dial = Some(opts);
                        return Poll::Ready(ToSwarm::GenerateEvent(Event::Candidate { peer, address }));
                    }
                    return Poll::Ready(ToSwarm::Dial { opts });
                }
                ToSwarm::GenerateEvent(kad::Event::OutboundQueryProgressed { id, result, .. }) => {
                    if self.stopping || Some(id) != self.query { continue; }
                    let Some(target) = self.target else { continue; };
                    self.query = None;
                    // A categorical decoder resource error wins over local policy and timeout.
                    let event = match result {
                        kad::QueryResult::GetClosestPeers(Err(kad::GetClosestPeersError::ResourceLimit { .. })) =>
                            Event::Failure { peer: target, reason: "resource_limit" },
                        _ if self.failure.is_some() => Event::Failure {
                            peer: target, reason: self.failure.take().expect("checked failure"),
                        },
                        kad::QueryResult::GetClosestPeers(Err(kad::GetClosestPeersError::Timeout { .. })) =>
                            Event::Failure { peer: target, reason: "timeout" },
                        kad::QueryResult::GetClosestPeers(Ok(result)) => {
                            let valid = result.peers.iter().all(|peer| {
                                if peer.peer_id == self.local { return false; }
                                // Initial seeds have empty query addresses. Include authenticated
                                // routing and owner/candidate-attempt addresses without ignoring extras.
                                checked_address_union(peer.addrs.iter()
                                    .chain(self.routing.get(&peer.peer_id))
                                    .chain(self.attempts.get(&peer.peer_id)),
                                    peer.peer_id, self.loopback).is_ok()
                            });
                            if valid { Event::Result(target) }
                            else { Event::Failure { peer: target, reason: "address_policy" } }
                        }
                        _ => Event::Failure { peer: target, reason: "query_policy" },
                    };
                    return Poll::Ready(ToSwarm::GenerateEvent(event));
                }
                ToSwarm::GenerateEvent(_) | ToSwarm::NewExternalAddrOfPeer { .. }
                    | ToSwarm::NewExternalAddrCandidate(_) | ToSwarm::ExternalAddrConfirmed(_)
                    | ToSwarm::ExternalAddrExpired(_) => continue,
                action => return Poll::Ready(action.map_out(|_| unreachable!("Kad events handled above"))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_checked_union_accepts_identical_addresses_but_rejects_every_poisoned_extra() {
        let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let address: Multiaddr = format!("/ip4/127.0.0.1/tcp/9000/p2p/{peer}").parse().unwrap();
        assert_eq!(checked_address(&[address.clone(), address.clone()], peer, true), Ok(address.clone()));
        let other: Multiaddr = format!("/ip4/127.0.0.1/tcp/9001/p2p/{peer}").parse().unwrap();
        let private: Multiaddr = format!("/ip4/10.0.0.1/tcp/9000/p2p/{peer}").parse().unwrap();
        let mapped: Multiaddr = format!("/ip6/::ffff:10.0.0.1/tcp/9000/p2p/{peer}").parse().unwrap();
        for poisoned in [other, private, mapped] {
            assert!(checked_address(&[address.clone(), poisoned.clone()], peer, true).is_err());
            assert!(checked_address(&[poisoned, address.clone()], peer, true).is_err());
        }
        assert!(checked_address(&[address], peer, false).is_err());
        assert!(checked_address(&[], peer, true).is_err());
    }

    #[test]
    fn discovery_result_union_uses_known_seed_without_ignoring_conflicting_response() {
        let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let known: Multiaddr = format!("/ip4/127.0.0.1/tcp/9000/p2p/{peer}").parse().unwrap();
        let conflicting: Multiaddr = format!("/ip4/127.0.0.1/tcp/9001/p2p/{peer}").parse().unwrap();
        let empty: [Multiaddr; 0] = [];
        assert_eq!(checked_address_union(empty.iter().chain(Some(&known)), peer, true), Ok(&known));
        assert_eq!(checked_address_union([&known].into_iter().chain(Some(&known)), peer, true), Ok(&known));
        assert!(checked_address_union([&conflicting].into_iter().chain(Some(&known)), peer, true).is_err());
        assert!(checked_address_union(empty.iter(), peer, true).is_err());
    }
}
