//! Circuit breaker state machine.

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// The current state of a circuit breaker.
#[derive(Debug, Clone)]
pub enum BreakerState {
    /// Circuit is closed; requests pass through normally.
    Closed {
        /// Number of consecutive failures.
        failure_count: u32,
    },

    /// Circuit is open; requests are rejected.
    Open {
        /// When the circuit was opened.
        opened_at: Instant,
        /// When the circuit should transition to half-open.
        until: Instant,
    },

    /// Circuit is half-open; allowing probe requests through.
    HalfOpen {
        /// Number of successful probes.
        success_count: u32,
        /// Number of probe requests allowed through.
        probe_count: u32,
    },
}

impl BreakerState {
    /// Creates a new closed state.
    pub fn closed() -> Self {
        Self::Closed { failure_count: 0 }
    }

    /// Returns `true` if the circuit is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }

    /// Returns `true` if the circuit is open.
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }

    /// Returns `true` if the circuit is half-open.
    pub fn is_half_open(&self) -> bool {
        matches!(self, Self::HalfOpen { .. })
    }

    /// Returns the failure count if closed.
    pub fn failure_count(&self) -> Option<u32> {
        match self {
            Self::Closed { failure_count } => Some(*failure_count),
            _ => None,
        }
    }

    /// Returns the name of the state.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Closed { .. } => "closed",
            Self::Open { .. } => "open",
            Self::HalfOpen { .. } => "half_open",
        }
    }
}

impl Default for BreakerState {
    fn default() -> Self {
        Self::closed()
    }
}

/// Metrics about circuit breaker behavior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BreakerMetrics {
    /// Total number of requests.
    pub total_requests: u64,
    /// Number of successful requests.
    pub successful_requests: u64,
    /// Number of failed requests.
    pub failed_requests: u64,
    /// Number of requests rejected due to open circuit.
    pub rejected_requests: u64,
    /// Number of times the circuit has opened.
    pub times_opened: u64,
    /// Number of times the circuit has closed from half-open.
    pub times_closed: u64,
}

impl BreakerMetrics {
    /// Creates new empty metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a successful request.
    pub fn record_success(&mut self) {
        self.total_requests += 1;
        self.successful_requests += 1;
    }

    /// Records a failed request.
    pub fn record_failure(&mut self) {
        self.total_requests += 1;
        self.failed_requests += 1;
    }

    /// Records a rejected request.
    pub fn record_rejected(&mut self) {
        self.total_requests += 1;
        self.rejected_requests += 1;
    }

    /// Records that the circuit opened.
    pub fn record_opened(&mut self) {
        self.times_opened += 1;
    }

    /// Records that the circuit closed.
    pub fn record_closed(&mut self) {
        self.times_closed += 1;
    }

    /// Returns the success rate (0.0 to 1.0).
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 1.0;
        }
        self.successful_requests as f64 / self.total_requests as f64
    }

    /// Returns the failure rate (0.0 to 1.0).
    pub fn failure_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.failed_requests as f64 / self.total_requests as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breaker_state_default() {
        let state = BreakerState::default();
        assert!(state.is_closed());
        assert_eq!(state.failure_count(), Some(0));
    }

    #[test]
    fn test_breaker_state_names() {
        assert_eq!(BreakerState::closed().name(), "closed");
        assert_eq!(
            BreakerState::Open {
                opened_at: Instant::now(),
                until: Instant::now(),
            }
            .name(),
            "open"
        );
        assert_eq!(
            BreakerState::HalfOpen {
                success_count: 0,
                probe_count: 0,
            }
            .name(),
            "half_open"
        );
    }

    #[test]
    fn test_metrics() {
        let mut metrics = BreakerMetrics::new();
        assert_eq!(metrics.success_rate(), 1.0);
        assert_eq!(metrics.failure_rate(), 0.0);

        metrics.record_success();
        metrics.record_success();
        metrics.record_failure();

        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.successful_requests, 2);
        assert_eq!(metrics.failed_requests, 1);
        assert!((metrics.success_rate() - 0.666).abs() < 0.01);
    }
}
