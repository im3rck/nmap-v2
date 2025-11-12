//! Connection state tracking for high-concurrency scanning

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Probe state
#[derive(Debug, Clone)]
pub struct ProbeState {
    pub sequence: u32,
    pub src_port: u16,
    pub sent_at: Instant,
    pub retries: u32,
}

/// State tracker for managing probe responses
pub struct StateTracker {
    /// Maps (target_ip, target_port, src_port) -> ProbeState
    states: DashMap<(IpAddr, u16, u16), ProbeState>,
}

impl StateTracker {
    pub fn new() -> Self {
        Self {
            states: DashMap::new(),
        }
    }

    pub fn track_probe(
        &self,
        target: IpAddr,
        target_port: u16,
        src_port: u16,
        sequence: u32,
    ) {
        let state = ProbeState {
            sequence,
            src_port,
            sent_at: Instant::now(),
            retries: 0,
        };

        self.states.insert((target, target_port, src_port), state);
    }

    pub fn get_probe(
        &self,
        target: IpAddr,
        target_port: u16,
        src_port: u16,
    ) -> Option<ProbeState> {
        self.states
            .get(&(target, target_port, src_port))
            .map(|entry| entry.clone())
    }

    pub fn remove_probe(
        &self,
        target: IpAddr,
        target_port: u16,
        src_port: u16,
    ) {
        self.states.remove(&(target, target_port, src_port));
    }

    pub fn cleanup_old_probes(&self, max_age: Duration) {
        let now = Instant::now();
        self.states.retain(|_, state| {
            now.duration_since(state.sent_at) < max_age
        });
    }

    pub fn active_probes(&self) -> usize {
        self.states.len()
    }
}

impl Default for StateTracker {
    fn default() -> Self {
        Self::new()
    }
}
