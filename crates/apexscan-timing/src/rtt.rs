//! RTT (Round-Trip Time) measurement and tracking
//!
//! Uses Exponential Weighted Moving Average (EWMA) for prediction.

use std::time::Duration;

/// RTT tracker using EWMA
#[derive(Debug, Clone)]
pub struct RttTracker {
    /// Smoothed RTT estimate
    srtt: Duration,

    /// RTT variance (for jitter calculation)
    rttvar: Duration,

    /// EWMA smoothing factor
    alpha: f64,

    /// Beta factor for variance calculation
    beta: f64,

    /// Number of samples
    samples: u64,
}

impl RttTracker {
    pub fn new(initial_rtt: Duration, alpha: f64) -> Self {
        Self {
            srtt: initial_rtt,
            rttvar: initial_rtt / 2,
            alpha,
            beta: 0.25, // Standard TCP variance smoothing
            samples: 0,
        }
    }

    /// Update RTT with a new sample
    pub fn update(&mut self, rtt: Duration) {
        self.samples += 1;

        if self.samples == 1 {
            // First sample
            self.srtt = rtt;
            self.rttvar = rtt / 2;
        } else {
            // Calculate difference between sample and smoothed RTT
            let diff = if rtt > self.srtt {
                rtt - self.srtt
            } else {
                self.srtt - rtt
            };

            // Update variance: RTTVAR = (1 - β) * RTTVAR + β * |RTT - SRTT|
            self.rttvar = Duration::from_secs_f64(
                (1.0 - self.beta) * self.rttvar.as_secs_f64()
                    + self.beta * diff.as_secs_f64(),
            );

            // Update smoothed RTT: SRTT = (1 - α) * SRTT + α * RTT
            self.srtt = Duration::from_secs_f64(
                (1.0 - self.alpha) * self.srtt.as_secs_f64()
                    + self.alpha * rtt.as_secs_f64(),
            );
        }
    }

    /// Get the current smoothed RTT estimate
    pub fn srtt(&self) -> Duration {
        self.srtt
    }

    /// Get the RTT variance (jitter estimate)
    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    /// Get RTO (Retransmission Timeout) estimate
    /// RTO = SRTT + 4 * RTTVAR
    pub fn rto(&self) -> Duration {
        self.srtt + (self.rttvar * 4)
    }

    /// Get the number of samples
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Check if jitter is high
    pub fn is_jittery(&self) -> bool {
        // High jitter if variance is more than 50% of SRTT
        self.rttvar > self.srtt / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_tracker() {
        let mut tracker = RttTracker::new(Duration::from_millis(100), 0.125);

        // Add samples
        tracker.update(Duration::from_millis(95));
        tracker.update(Duration::from_millis(105));
        tracker.update(Duration::from_millis(100));

        // SRTT should be close to 100ms
        assert!(tracker.srtt().as_millis() >= 95 && tracker.srtt().as_millis() <= 105);
    }

    #[test]
    fn test_jitter_detection() {
        let mut tracker = RttTracker::new(Duration::from_millis(100), 0.125);

        // Add stable samples
        for _ in 0..10 {
            tracker.update(Duration::from_millis(100));
        }
        assert!(!tracker.is_jittery());

        // Add jittery samples
        tracker.update(Duration::from_millis(50));
        tracker.update(Duration::from_millis(150));
        tracker.update(Duration::from_millis(75));
        tracker.update(Duration::from_millis(125));

        assert!(tracker.is_jittery());
    }
}
