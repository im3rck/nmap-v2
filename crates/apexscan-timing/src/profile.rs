//! Per-target timing profiles

use crate::rtt::RttTracker;
use crate::TimingConfig;
use std::time::{Duration, Instant};

/// Timing profile for a single target
#[derive(Debug, Clone)]
pub struct TimingProfile {
    /// RTT tracker
    rtt: RttTracker,

    /// Current parallelism (number of concurrent probes)
    parallelism: usize,

    /// Maximum parallelism allowed
    max_parallelism: usize,

    /// Number of packets sent
    sent: u64,

    /// Number of packets received
    received: u64,

    /// Number of packets lost
    lost: u64,

    /// Last packet sent time
    last_sent: Option<Instant>,

    /// Configuration
    config: TimingConfig,

    /// Current state
    state: TimingState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingState {
    /// Initial probing phase
    Probing,

    /// Normal operation
    Normal,

    /// Congestion detected, backing off
    Congested,

    /// Recovering from congestion
    Recovering,
}

impl TimingProfile {
    pub fn new(config: TimingConfig) -> Self {
        let rtt = RttTracker::new(config.initial_rtt, config.alpha);

        Self {
            rtt,
            parallelism: 1, // Start conservatively
            max_parallelism: config.max_parallelism,
            sent: 0,
            received: 0,
            lost: 0,
            last_sent: None,
            config,
            state: TimingState::Probing,
        }
    }

    /// Record a packet sent
    pub fn record_sent(&mut self) {
        self.sent += 1;
        self.last_sent = Some(Instant::now());
    }

    /// Record a packet received with RTT
    pub fn record_received(&mut self, rtt: Duration) {
        self.received += 1;
        self.rtt.update(rtt);

        // Adjust state and parallelism based on performance
        self.adjust_performance();
    }

    /// Record a packet loss
    pub fn record_loss(&mut self) {
        self.lost += 1;

        // Check for congestion
        let loss_rate = self.loss_rate();
        if loss_rate > self.config.loss_threshold {
            self.enter_congestion();
        }
    }

    /// Get current RTT estimate
    pub fn rtt(&self) -> Duration {
        self.rtt.srtt()
    }

    /// Get current RTO (timeout) estimate
    pub fn rto(&self) -> Duration {
        self.rtt.rto().clamp(self.config.min_rtt, self.config.max_rtt)
    }

    /// Get current parallelism level
    pub fn parallelism(&self) -> usize {
        self.parallelism
    }

    /// Get packet loss rate
    pub fn loss_rate(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            self.lost as f64 / self.sent as f64
        }
    }

    /// Get current state
    pub fn state(&self) -> TimingState {
        self.state
    }

    /// Calculate optimal send delay between packets
    pub fn send_delay(&self) -> Duration {
        match self.state {
            TimingState::Probing => self.rtt.srtt() * 2,
            TimingState::Normal => self.rtt.srtt() / (self.parallelism as u32),
            TimingState::Congested => self.rtt.srtt() * 4,
            TimingState::Recovering => self.rtt.srtt(),
        }
    }

    fn adjust_performance(&mut self) {
        let loss_rate = self.loss_rate();

        match self.state {
            TimingState::Probing => {
                // After initial samples, transition to normal
                if self.rtt.samples() >= 10 {
                    self.state = TimingState::Normal;
                    self.parallelism = (self.max_parallelism / 4).max(1);
                }
            }
            TimingState::Normal => {
                // Gradually increase parallelism if no loss
                if loss_rate < self.config.loss_threshold / 2.0 && !self.rtt.is_jittery() {
                    self.parallelism = (self.parallelism + 1).min(self.max_parallelism);
                }
            }
            TimingState::Congested => {
                // Stay congested until loss rate improves
                if loss_rate < self.config.loss_threshold / 2.0 {
                    self.state = TimingState::Recovering;
                }
            }
            TimingState::Recovering => {
                // Slowly increase parallelism
                if loss_rate < self.config.loss_threshold / 4.0 {
                    self.parallelism =
                        ((self.parallelism as f64 * self.config.recovery_rate) as usize + 1)
                            .min(self.max_parallelism);

                    // Transition back to normal after recovery
                    if self.parallelism >= self.max_parallelism / 2 {
                        self.state = TimingState::Normal;
                    }
                }
            }
        }
    }

    fn enter_congestion(&mut self) {
        self.state = TimingState::Congested;
        // Reduce parallelism aggressively
        self.parallelism =
            ((self.parallelism as f64 / self.config.backoff_factor) as usize).max(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_profile() {
        let config = TimingConfig::default();
        let mut profile = TimingProfile::new(config);

        assert_eq!(profile.state(), TimingState::Probing);

        // Simulate good network conditions
        for _ in 0..20 {
            profile.record_sent();
            profile.record_received(Duration::from_millis(100));
        }

        // Should transition to normal and increase parallelism
        assert_eq!(profile.state(), TimingState::Normal);
        assert!(profile.parallelism() > 1);
    }

    #[test]
    fn test_congestion_detection() {
        let config = TimingConfig::default();
        let mut profile = TimingProfile::new(config);

        // Simulate packet loss
        for _ in 0..10 {
            profile.record_sent();
            profile.record_loss();
        }

        // Should detect congestion
        assert_eq!(profile.state(), TimingState::Congested);
        assert_eq!(profile.parallelism(), 1);
    }
}
