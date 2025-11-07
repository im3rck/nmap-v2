//! Optimized Timing Engine - Main coordinator

use crate::{TimingConfig, TimingProfile};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Optimized Timing Engine
pub struct OptimizedTimingEngine {
    /// Per-target timing profiles
    profiles: Arc<DashMap<IpAddr, TimingProfile>>,

    /// Configuration
    config: TimingConfig,
}

impl OptimizedTimingEngine {
    pub fn new(config: TimingConfig) -> Self {
        Self {
            profiles: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Get or create timing profile for a target
    pub fn get_profile(&self, target: IpAddr) -> TimingProfile {
        self.profiles
            .entry(target)
            .or_insert_with(|| {
                debug!("Created new timing profile for {}", target);
                TimingProfile::new(self.config.clone())
            })
            .value()
            .clone()
    }

    /// Record a packet sent to a target
    pub fn record_sent(&self, target: IpAddr) {
        if let Some(mut profile) = self.profiles.get_mut(&target) {
            profile.record_sent();
        }
    }

    /// Record a packet received from a target
    pub fn record_received(&self, target: IpAddr, sent_at: Instant) {
        let rtt = sent_at.elapsed();

        if let Some(mut profile) = self.profiles.get_mut(&target) {
            profile.record_received(rtt);
            trace!(
                "Recorded RTT for {}: {:?} (SRTT: {:?}, parallelism: {})",
                target,
                rtt,
                profile.rtt(),
                profile.parallelism()
            );
        }
    }

    /// Record a packet loss for a target
    pub fn record_loss(&self, target: IpAddr) {
        if let Some(mut profile) = self.profiles.get_mut(&target) {
            profile.record_loss();
            debug!(
                "Recorded loss for {} (loss rate: {:.2}%, state: {:?})",
                target,
                profile.loss_rate() * 100.0,
                profile.state()
            );
        }
    }

    /// Get optimal timeout for a target
    pub fn get_timeout(&self, target: IpAddr) -> Duration {
        self.profiles
            .get(&target)
            .map(|profile| profile.rto())
            .unwrap_or(self.config.initial_rtt * 4)
    }

    /// Get optimal parallelism for a target
    pub fn get_parallelism(&self, target: IpAddr) -> usize {
        self.profiles
            .get(&target)
            .map(|profile| profile.parallelism())
            .unwrap_or(1)
    }

    /// Get optimal send delay for a target
    pub fn get_send_delay(&self, target: IpAddr) -> Duration {
        self.profiles
            .get(&target)
            .map(|profile| profile.send_delay())
            .unwrap_or(self.config.initial_rtt)
    }

    /// Get statistics for a target
    pub fn get_stats(&self, target: IpAddr) -> Option<TargetStats> {
        self.profiles.get(&target).map(|profile| TargetStats {
            rtt: profile.rtt(),
            rto: profile.rto(),
            parallelism: profile.parallelism(),
            loss_rate: profile.loss_rate(),
            state: format!("{:?}", profile.state()),
        })
    }

    /// Clean up old profiles
    pub fn cleanup(&self) {
        // Remove profiles that haven't been used recently
        // This would be implemented in production
    }
}

#[derive(Debug, Clone)]
pub struct TargetStats {
    pub rtt: Duration,
    pub rto: Duration,
    pub parallelism: usize,
    pub loss_rate: f64,
    pub state: String,
}

impl Default for OptimizedTimingEngine {
    fn default() -> Self {
        Self::new(TimingConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_timing_engine() {
        let engine = OptimizedTimingEngine::new(TimingConfig::default());
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Initial timeout should be default
        let timeout = engine.get_timeout(target);
        assert!(timeout > Duration::from_millis(100));

        // Record good performance
        for _ in 0..10 {
            engine.record_sent(target);
            tokio::time::sleep(Duration::from_millis(1));
            engine.record_received(target, Instant::now() - Duration::from_millis(50));
        }

        // Timeout should adjust based on measured RTT
        let new_timeout = engine.get_timeout(target);
        assert!(new_timeout < timeout);
    }
}
