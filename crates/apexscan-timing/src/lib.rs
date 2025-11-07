//! Optimized Timing Engine (OTE)
//!
//! The OTE is ApexScan's key performance differentiator. It implements a deterministic
//! state-machine approach to dynamically adjust scan rates based on real-time network
//! conditions.
//!
//! Key Features:
//! - Real-time RTT measurement and tracking
//! - Jitter detection and compensation using EWMA
//! - Per-target timing profiles
//! - Dynamic rate adjustment based on network conditions
//! - Congestion detection and automatic backoff

pub mod rtt;
pub mod profile;
pub mod engine;

pub use engine::OptimizedTimingEngine;
pub use profile::TimingProfile;
pub use rtt::RttTracker;

use std::time::Duration;

/// Timing configuration
#[derive(Debug, Clone)]
pub struct TimingConfig {
    /// Initial RTT estimate
    pub initial_rtt: Duration,

    /// Minimum RTT (floor)
    pub min_rtt: Duration,

    /// Maximum RTT (ceiling)
    pub max_rtt: Duration,

    /// EWMA smoothing factor (0.0-1.0)
    /// Lower = more smoothing, Higher = more responsive
    pub alpha: f64,

    /// Maximum number of concurrent probes per target
    pub max_parallelism: usize,

    /// Packet loss threshold for congestion detection (0.0-1.0)
    pub loss_threshold: f64,

    /// Backoff multiplier when congestion detected
    pub backoff_factor: f64,

    /// Recovery rate when conditions improve
    pub recovery_rate: f64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            initial_rtt: Duration::from_millis(100),
            min_rtt: Duration::from_millis(10),
            max_rtt: Duration::from_secs(5),
            alpha: 0.125, // Standard TCP RTT smoothing factor
            max_parallelism: 100,
            loss_threshold: 0.1, // 10% loss triggers backoff
            backoff_factor: 1.5,
            recovery_rate: 0.95,
        }
    }
}

impl TimingConfig {
    /// Create aggressive timing profile (T4-T5 equivalent)
    pub fn aggressive() -> Self {
        Self {
            initial_rtt: Duration::from_millis(50),
            min_rtt: Duration::from_millis(5),
            max_rtt: Duration::from_secs(2),
            alpha: 0.25,
            max_parallelism: 1000,
            loss_threshold: 0.15,
            backoff_factor: 1.3,
            recovery_rate: 0.9,
        }
    }

    /// Create polite timing profile (T1-T2 equivalent)
    pub fn polite() -> Self {
        Self {
            initial_rtt: Duration::from_millis(200),
            min_rtt: Duration::from_millis(20),
            max_rtt: Duration::from_secs(10),
            alpha: 0.0625,
            max_parallelism: 10,
            loss_threshold: 0.05,
            backoff_factor: 2.0,
            recovery_rate: 0.99,
        }
    }
}
