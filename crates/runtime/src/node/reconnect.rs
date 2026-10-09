//! Configured literal addresses only. No discovery address adoption or peer history.
use super::config;
use libp2p::{Multiaddr, PeerId, swarm::{ConnectionId, DialError, dial_opts::DialOpts}};
use std::time::Duration;
use tokio::time::Instant;

struct Pending {
    id: ConnectionId,
    superseded: bool,
}

struct Peer {
    id: PeerId,
    address: Multiaddr,
    retries: u8,
    direct: Option<Pending>,
    connected: bool,
    deferred: bool,
    deadline: Option<Instant>,
}

pub(super) struct Scheduled {
    pub peer: PeerId,
    pub attempt: u8,
    pub delay_ms: u64,
}

pub(super) struct Reconnect {
    peers: Vec<Peer>,
    // Only configured peers, and no more external IDs than the swarm pending cap.
    external: Vec<(usize, ConnectionId)>,
    maximum: usize,
}

impl Reconnect {
    pub fn new(addresses: Vec<Multiaddr>, maximum: usize) -> Self {
        Self {
            peers: addresses.into_iter().map(|address| Peer {
                id: config::dial_peer(&address), address, retries: 0, direct: None,
                connected: false, deferred: false, deadline: None,
            }).collect(),
            external: Vec::with_capacity(maximum), maximum,
        }
    }

    pub fn len(&self) -> usize { self.peers.len() }

    fn index(&self, peer: PeerId) -> Option<usize> {
        self.peers.iter().position(|state| state.id == peer)
    }

    fn pending(&self, index: usize) -> bool {
        self.peers[index].direct.is_some() || self.external.iter().any(|(peer, _)| *peer == index)
    }

    fn schedule(&mut self, index: usize, now: Instant) -> Option<Scheduled> {
        let pending = self.pending(index);
        let state = &mut self.peers[index];
        if state.connected || state.deadline.is_some() { return None; }
        if pending {
            state.deferred = true;
            return None;
        }
        state.deferred = false;
        if state.retries == 3 { return None; }
        let attempt = state.retries + 1;
        let delay_ms = 1000u64 << state.retries;
        state.deadline = Some(now + Duration::from_millis(delay_ms));
        Some(Scheduled { peer: state.id, attempt, delay_ms })
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.peers.iter().filter_map(|state| state.deadline).min()
    }

    pub fn due(&self, now: Instant) -> Option<usize> {
        self.peers.iter().position(|state| state.deadline.is_some_and(|deadline| deadline <= now))
    }

    // Register before swarm.dial: synchronous errors are completed inline using
    // this exact ID, whereas accepted direct dials emit no SwarmEvent::Dialing.
    pub fn begin(&mut self, index: usize) -> DialOpts {
        assert!(!self.pending(index));
        let state = &mut self.peers[index];
        assert!(!state.connected);
        state.deadline = None;
        let options = DialOpts::peer_id(state.id).addresses(vec![state.address.clone()]).build();
        state.direct = Some(Pending { id: options.connection_id(), superseded: false });
        options
    }

    pub fn accepted(&mut self, index: usize, retry: bool) {
        if retry { self.peers[index].retries += 1; }
    }

    pub fn dialing(&mut self, peer: PeerId, id: ConnectionId) {
        let Some(index) = self.index(peer) else { return };
        if self.peers[index].direct.as_ref().is_some_and(|pending| pending.id == id)
            || self.external.iter().any(|(_, pending)| *pending == id)
        { return; }
        // The swarm's configured pending cap bounds this vector; ignore events
        // outside that cap rather than retaining arbitrary connection history.
        if self.external.len() < self.maximum { self.external.push((index, id)); }
        let state = &mut self.peers[index];
        if state.deadline.take().is_some() && !state.connected { state.deferred = true; }
    }

    pub fn established(&mut self, peer: PeerId, id: ConnectionId) {
        let Some(index) = self.index(peer) else { return };
        self.external.retain(|(_, pending)| *pending != id);
        let state = &mut self.peers[index];
        if let Some(pending) = &mut state.direct {
            if pending.id == id { state.direct = None; }
            else { pending.superseded = true; }
        }
        state.connected = true;
        state.deferred = false;
        state.deadline = None;
    }

    pub fn closed(&mut self, peer: PeerId, now: Instant) -> Option<Scheduled> {
        let index = self.index(peer)?;
        self.peers[index].connected = false;
        self.schedule(index, now)
    }

    pub fn failed(&mut self, id: ConnectionId, error: &DialError, now: Instant) -> Option<Scheduled> {
        if let Some(index) = self.peers.iter().position(|state|
            state.direct.as_ref().is_some_and(|pending| pending.id == id))
        {
            let pending = self.peers[index].direct.take().expect("matching direct ID");
            if self.peers[index].connected { return None; }
            if self.peers[index].deferred { return self.schedule(index, now); }
            if pending.superseded { return None; }
            match error {
                DialError::Transport(_) => self.schedule(index, now),
                DialError::DialPeerConditionFalse(_) => {
                    // No recurring suppression timer: observe pending completion
                    // or a connected peer's final close before another request.
                    self.peers[index].deferred = true;
                    None
                }
                _ => None,
            }
        } else if let Some(position) = self.external.iter().position(|(_, pending)| *pending == id) {
            let (index, _) = self.external.swap_remove(position);
            if self.peers[index].deferred && !self.peers[index].connected {
                self.schedule(index, now)
            } else { None }
        } else { None }
    }

    pub fn stop(&mut self) {
        self.external.clear();
        for state in &mut self.peers {
            state.direct = None;
            state.deadline = None;
            state.deferred = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheduler() -> (Reconnect, PeerId) {
        let peer = PeerId::from(libp2p::identity::Keypair::generate_ed25519().public());
        let address = format!("/ip4/127.0.0.1/tcp/9/p2p/{peer}").parse().unwrap();
        (Reconnect::new(vec![address], 1), peer)
    }

    #[test]
    fn close_before_superseded_error_defers_one_retry_without_overlapping() {
        let (mut scheduler, peer) = scheduler();
        let now = Instant::now();
        let old = scheduler.begin(0).connection_id();
        scheduler.accepted(0, false);
        scheduler.established(peer, ConnectionId::new_unchecked(100));
        assert!(scheduler.closed(peer, now).is_none());
        assert!(scheduler.deadline().is_none());
        let scheduled = scheduler.failed(old, &DialError::Aborted, now).unwrap();
        assert_eq!((scheduled.attempt, scheduled.delay_ms), (1, 1000));
        assert!(scheduler.failed(old, &DialError::Aborted, now).is_none());
        assert!(scheduler.due(now).is_none());
        assert_eq!(scheduler.due(now + Duration::from_secs(1)), Some(0));
        let retry = scheduler.begin(0).connection_id();
        scheduler.accepted(0, true);
        scheduler.established(peer, retry);
        let scheduled = scheduler.closed(peer, now).unwrap();
        assert_eq!((scheduled.attempt, scheduled.delay_ms), (2, 2000));
    }

    #[test]
    fn healthy_establishment_survives_late_terminal_error_and_unrelated_kad_failure() {
        let (mut scheduler, peer) = scheduler();
        let now = Instant::now();
        let old = scheduler.begin(0).connection_id();
        scheduler.established(peer, ConnectionId::new_unchecked(101));
        let error = DialError::WrongPeerId {
            obtained: PeerId::from(libp2p::identity::Keypair::generate_ed25519().public()),
            address: scheduler.peers[0].address.clone(),
        };
        assert!(scheduler.failed(old, &error, now).is_none());
        assert!(scheduler.failed(ConnectionId::new_unchecked(102), &DialError::Transport(vec![]), now).is_none());
        assert!(scheduler.deadline().is_none());
        assert_eq!(scheduler.peers[0].retries, 0);
        assert_eq!(scheduler.closed(peer, now).unwrap().attempt, 1);
    }

    #[test]
    fn suppression_waits_for_external_completion_and_only_accepted_dials_count() {
        let (mut scheduler, peer) = scheduler();
        let now = Instant::now();
        let old = scheduler.begin(0).connection_id();
        assert!(scheduler.failed(old, &DialError::DialPeerConditionFalse(
            libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing,
        ), now).is_none());
        assert!(scheduler.deadline().is_none());
        let external = ConnectionId::new_unchecked(103);
        scheduler.dialing(peer, external);
        assert_eq!(scheduler.failed(external, &DialError::Aborted, now).unwrap().attempt, 1);
        let retry = scheduler.begin(0).connection_id();
        assert_eq!(scheduler.failed(retry, &DialError::Transport(vec![]), now).unwrap().attempt, 1);
        assert_eq!(scheduler.peers[0].retries, 0);
        let retry = scheduler.begin(0).connection_id();
        scheduler.accepted(0, true);
        assert_eq!(scheduler.failed(retry, &DialError::Transport(vec![]), now).unwrap().attempt, 2);
        scheduler.stop();
        assert!(scheduler.deadline().is_none());
        assert!(scheduler.external.is_empty());
        assert!(scheduler.peers[0].direct.is_none());
        assert!(!scheduler.peers[0].deferred);
    }
}
