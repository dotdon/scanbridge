//! Circuit breaker configuration.

use crate::core::{ArcScanner, ScanError};
use std::time::Duration;

/// Configuration for a circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit.
    pub failure_threshold: u32,

    /// Number of successes in half-open state to close the circuit.
    pub success_threshold: u32,

    /// How long to keep the circuit open before transitioning to half-open.
    pub open_duration: Duration,

    /// Maximum number of concurrent probes in half-open state.
    pub half_open_max_probes: u32,

    /// What types of errors count as failures.
    pub failure_policy: FailurePolicy,

    /// What to do when the circuit is open.
    pub fallback_behavior: FallbackBehavior,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            open_duration: Duration::from_secs(30),
            half_open_max_probes: 1,
            failure_policy: FailurePolicy::default(),
            fallback_behavior: FallbackBehavior::FailClosed,
        }
    }
}

impl CircuitBreakerConfig {
    /// Creates a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the failure threshold.
    pub fn with_failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Sets the success threshold.
    pub fn with_success_threshold(mut self, threshold: u32) -> Self {
        self.success_threshold = threshold;
        self
    }

    /// Sets the open duration.
    pub fn with_open_duration(mut self, duration: Duration) -> Self {
        self.open_duration = duration;
        self
    }

    /// Sets the maximum number of half-open probes.
    pub fn with_half_open_max_probes(mut self, max: u32) -> Self {
        self.half_open_max_probes = max;
        self
    }

    /// Sets the failure policy.
    pub fn with_failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Sets the fallback behavior.
    pub fn with_fallback_behavior(mut self, behavior: FallbackBehavior) -> Self {
        self.fallback_behavior = behavior;
        self
    }

    /// Creates a configuration optimized for strict security.
    ///
    /// This configuration:
    /// - Uses a lower failure threshold (3)
    /// - Keeps circuits open longer (60 seconds)
    /// - Fails closed (rejects scans when circuit is open)
    pub fn strict() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 5,
            open_duration: Duration::from_secs(60),
            half_open_max_probes: 1,
            failure_policy: FailurePolicy::default(),
            fallback_behavior: FallbackBehavior::FailClosed,
        }
    }

    /// Creates a configuration optimized for high availability.
    ///
    /// This configuration:
    /// - Uses a higher failure threshold (10)
    /// - Keeps circuits open for a shorter time (10 seconds)
    /// - Allows more probe attempts
    pub fn high_availability() -> Self {
        Self {
            failure_threshold: 10,
            success_threshold: 2,
            open_duration: Duration::from_secs(10),
            half_open_max_probes: 3,
            failure_policy: FailurePolicy::default(),
            fallback_behavior: FallbackBehavior::FailClosed,
        }
    }
}

/// Defines what types of errors count as failures for the circuit breaker.
#[derive(Debug, Clone)]
pub struct FailurePolicy {
    /// Count timeouts as failures.
    pub count_timeouts: bool,
    /// Count connection failures as failures.
    pub count_connection_failures: bool,
    /// Count engine unavailable as failures.
    pub count_engine_unavailable: bool,
    /// Count rate limiting as failures.
    pub count_rate_limited: bool,
    /// Count all errors as failures.
    pub count_all_errors: bool,
}

impl Default for FailurePolicy {
    fn default() -> Self {
        Self {
            count_timeouts: true,
            count_connection_failures: true,
            count_engine_unavailable: true,
            count_rate_limited: false, // Rate limiting is expected behavior
            count_all_errors: false,
        }
    }
}

impl FailurePolicy {
    /// Creates a new failure policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a policy that counts all errors as failures.
    pub fn all_errors() -> Self {
        Self {
            count_all_errors: true,
            ..Self::default()
        }
    }

    /// Creates a policy that only counts connection-related failures.
    pub fn connection_only() -> Self {
        Self {
            count_timeouts: true,
            count_connection_failures: true,
            count_engine_unavailable: true,
            count_rate_limited: false,
            count_all_errors: false,
        }
    }

    /// Determines if an error should be counted as a failure.
    pub fn should_count(&self, error: &ScanError) -> bool {
        if self.count_all_errors {
            return true;
        }

        match error {
            ScanError::Timeout { .. } => self.count_timeouts,
            ScanError::ConnectionFailed { .. } => self.count_connection_failures,
            ScanError::EngineUnavailable { .. } => self.count_engine_unavailable,
            ScanError::RateLimited { .. } => self.count_rate_limited,
            _ => false,
        }
    }
}

/// What to do when the circuit is open.
#[derive(Debug, Clone)]
pub enum FallbackBehavior {
    /// Reject all requests when circuit is open (safest).
    FailClosed,

    /// Allow all files through when circuit is open (most available).
    /// Warning: This means potentially infected files could pass through!
    FailOpen,

    /// Use a fallback scanner when the primary is unavailable.
    Fallback(ArcScanner),
}

impl FallbackBehavior {
    /// Returns true if this behavior will block files when the circuit is open.
    pub fn blocks_on_open(&self) -> bool {
        matches!(self, Self::FailClosed)
    }

    /// Returns true if this behavior allows files through when the circuit is open.
    pub fn allows_on_open(&self) -> bool {
        matches!(self, Self::FailOpen)
    }

    /// Returns true if this behavior uses a fallback scanner.
    pub fn has_fallback(&self) -> bool {
        matches!(self, Self::Fallback(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.success_threshold, 3);
        assert_eq!(config.open_duration, Duration::from_secs(30));
    }

    #[test]
    fn test_config_builder() {
        let config = CircuitBreakerConfig::new()
            .with_failure_threshold(10)
            .with_open_duration(Duration::from_secs(60));

        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.open_duration, Duration::from_secs(60));
    }

    #[test]
    fn test_failure_policy() {
        let policy = FailurePolicy::default();

        let timeout_err = ScanError::timeout("test", Duration::from_secs(30));
        assert!(policy.should_count(&timeout_err));

        let rate_limit_err = ScanError::RateLimited {
            engine: "test".into(),
            retry_after: None,
        };
        assert!(!policy.should_count(&rate_limit_err));
    }

    #[test]
    fn test_fallback_behavior() {
        assert!(FallbackBehavior::FailClosed.blocks_on_open());
        assert!(FallbackBehavior::FailOpen.allows_on_open());
    }
}
