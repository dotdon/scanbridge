//! Circuit breaker implementation.

use crate::circuit_breaker::config::{CircuitBreakerConfig, FallbackBehavior};
use crate::circuit_breaker::state::{BreakerMetrics, BreakerState};
use crate::core::{FileInput, ScanError, ScanResult, Scanner};

use async_trait::async_trait;
use std::fmt;
use std::sync::RwLock;
use std::time::Instant;

/// A circuit breaker wrapper around a scanner.
///
/// The circuit breaker monitors failures and prevents cascading failures
/// by temporarily rejecting requests to unhealthy backends.
///
/// # States
///
/// - **Closed**: Normal operation. Requests pass through, failures are counted.
/// - **Open**: Backend is failing. Requests are rejected immediately.
/// - **Half-Open**: Probing. A limited number of requests are allowed through
///   to test if the backend has recovered.
///
/// # Example
///
/// ```rust,ignore
/// use scanbridge::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
/// use scanbridge::backends::MockScanner;
///
/// let scanner = MockScanner::new();
/// let config = CircuitBreakerConfig::default();
/// let protected = CircuitBreaker::new(scanner, config);
///
/// // Use `protected` as a normal scanner
/// let result = protected.scan(&input).await;
/// ```
pub struct CircuitBreaker<S: Scanner> {
    /// The wrapped scanner.
    inner: S,
    /// Current state of the circuit.
    state: RwLock<BreakerState>,
    /// Configuration.
    config: CircuitBreakerConfig,
    /// Metrics.
    metrics: RwLock<BreakerMetrics>,
}

impl<S: Scanner> CircuitBreaker<S> {
    /// Creates a new circuit breaker with the given scanner and configuration.
    pub fn new(scanner: S, config: CircuitBreakerConfig) -> Self {
        Self {
            inner: scanner,
            state: RwLock::new(BreakerState::closed()),
            config,
            metrics: RwLock::new(BreakerMetrics::new()),
        }
    }

    /// Creates a new circuit breaker with default configuration.
    pub fn with_defaults(scanner: S) -> Self {
        Self::new(scanner, CircuitBreakerConfig::default())
    }

    /// Returns the current state of the circuit breaker.
    pub fn state(&self) -> BreakerState {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Returns a copy of the current metrics.
    pub fn metrics(&self) -> BreakerMetrics {
        self.metrics
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Forces the circuit into the open state.
    pub fn force_open(&self) {
        let until = Instant::now() + self.config.open_duration;
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = BreakerState::Open {
            opened_at: Instant::now(),
            until,
        };
        self.metrics
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_opened();
    }

    /// Forces the circuit into the closed state.
    pub fn force_close(&self) {
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = BreakerState::closed();
        self.metrics
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_closed();
    }

    /// Resets the circuit breaker state and metrics.
    pub fn reset(&self) {
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = BreakerState::closed();
        *self
            .metrics
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = BreakerMetrics::new();
    }

    /// Returns a reference to the wrapped scanner.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    /// Checks if a request should be allowed through.
    fn should_allow_request(&self) -> Result<(), ScanError> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();

        match &*state {
            BreakerState::Closed { .. } => Ok(()),

            BreakerState::Open { until, .. } => {
                if now >= *until {
                    // Transition to half-open
                    *state = BreakerState::HalfOpen {
                        success_count: 0,
                        probe_count: 1,
                    };
                    Ok(())
                } else {
                    Err(ScanError::CircuitOpen {
                        engine: self.inner.name().to_string(),
                        recovery_hint: Some(format!("Circuit may recover in {:?}", *until - now)),
                    })
                }
            }

            BreakerState::HalfOpen {
                success_count,
                probe_count,
            } => {
                if *probe_count < self.config.half_open_max_probes {
                    // Allow this probe - preserve the current success_count
                    *state = BreakerState::HalfOpen {
                        success_count: *success_count,
                        probe_count: probe_count + 1,
                    };
                    Ok(())
                } else {
                    Err(ScanError::CircuitOpen {
                        engine: self.inner.name().to_string(),
                        recovery_hint: Some("Maximum probes in progress".to_string()),
                    })
                }
            }
        }
    }

    /// Records a successful request.
    fn record_success(&self) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.metrics
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_success();

        match &*state {
            BreakerState::Closed { .. } => {
                // Reset failure count on success
                *state = BreakerState::closed();
            }

            BreakerState::HalfOpen {
                success_count,
                probe_count,
            } => {
                let new_success_count = success_count + 1;
                if new_success_count >= self.config.success_threshold {
                    // Transition to closed
                    *state = BreakerState::closed();
                    self.metrics
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .record_closed();
                } else {
                    *state = BreakerState::HalfOpen {
                        success_count: new_success_count,
                        probe_count: *probe_count,
                    };
                }
            }

            BreakerState::Open { .. } => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }

    /// Records a failed request.
    fn record_failure(&self, error: &ScanError) {
        // Check if this error should count as a failure
        if !self.config.failure_policy.should_count(error) {
            return;
        }

        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.metrics
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_failure();

        match &*state {
            BreakerState::Closed { failure_count } => {
                let new_count = failure_count + 1;
                if new_count >= self.config.failure_threshold {
                    // Transition to open
                    let until = Instant::now() + self.config.open_duration;
                    *state = BreakerState::Open {
                        opened_at: Instant::now(),
                        until,
                    };
                    self.metrics
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .record_opened();
                } else {
                    *state = BreakerState::Closed {
                        failure_count: new_count,
                    };
                }
            }

            BreakerState::HalfOpen { .. } => {
                // Any failure in half-open reopens the circuit
                let until = Instant::now() + self.config.open_duration;
                *state = BreakerState::Open {
                    opened_at: Instant::now(),
                    until,
                };
                self.metrics
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .record_opened();
            }

            BreakerState::Open { .. } => {
                // Already open, nothing to do
            }
        }
    }

    /// Handles a request when the circuit is open.
    async fn handle_open_circuit(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
        self.metrics
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_rejected();

        match &self.config.fallback_behavior {
            FallbackBehavior::FailClosed => Err(ScanError::CircuitOpen {
                engine: self.inner.name().to_string(),
                recovery_hint: Some("Circuit is open; scan rejected".to_string()),
            }),

            FallbackBehavior::FailOpen => {
                // Return a "clean" result with a warning
                // This is dangerous! Only use if availability > safety
                tracing::warn!(
                    engine = self.inner.name(),
                    "Circuit open, allowing file through (fail-open mode)"
                );

                use crate::core::{FileHash, FileHasher, FileMetadata, ScanContext, ScanOutcome};
                use std::time::Duration;

                let hasher = FileHasher::new();
                let hash = match input {
                    FileInput::Path(path) => hasher.hash_file(path)?,
                    FileInput::Bytes { data, .. } => hasher.hash_bytes(data),
                    FileInput::Stream { .. } => FileHash::new("unknown-stream"),
                };

                let metadata = FileMetadata::new(input.size_hint().unwrap_or(0), hash);
                let context = ScanContext::new();

                let mut result = ScanResult::new(
                    ScanOutcome::Clean,
                    metadata,
                    format!("{}-failopen", self.inner.name()),
                    Duration::ZERO,
                    context,
                );
                result.details.insert(
                    "warning".to_string(),
                    serde_json::Value::String(
                        "Scan skipped due to circuit breaker; file allowed through fail-open policy"
                            .to_string(),
                    ),
                );
                Ok(result)
            }

            FallbackBehavior::Fallback(fallback) => {
                tracing::info!(
                    primary = self.inner.name(),
                    fallback = fallback.name(),
                    "Using fallback scanner due to open circuit"
                );
                fallback.scan(input).await
            }
        }
    }
}

impl<S: Scanner> fmt::Debug for CircuitBreaker<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircuitBreaker")
            .field("inner", &self.inner)
            .field(
                "state",
                &*self
                    .state
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            )
            .field("config", &self.config)
            .finish()
    }
}

#[async_trait]
impl<S: Scanner> Scanner for CircuitBreaker<S> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
        // Check if we should allow this request
        if self.should_allow_request().is_err() {
            return self.handle_open_circuit(input).await;
        }

        // Perform the scan
        match self.inner.scan(input).await {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                self.record_failure(&e);
                Err(e)
            }
        }
    }

    async fn health_check(&self) -> Result<(), ScanError> {
        // Health check always goes through, but updates state
        match self.inner.health_check().await {
            Ok(()) => {
                // If we're half-open and health check succeeds, count it
                if self.state().is_half_open() {
                    self.record_success();
                }
                Ok(())
            }
            Err(e) => {
                if self.state().is_half_open() {
                    self.record_failure(&e);
                }
                Err(e)
            }
        }
    }

    fn max_file_size(&self) -> Option<u64> {
        self.inner.max_file_size()
    }

    async fn signature_version(&self) -> Option<String> {
        self.inner.signature_version().await
    }

    fn supports_streaming(&self) -> bool {
        self.inner.supports_streaming()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::MockScanner;
    use std::time::Duration;

    #[tokio::test]
    async fn test_circuit_breaker_passes_through() {
        let scanner = MockScanner::new_clean();
        let breaker = CircuitBreaker::with_defaults(scanner);

        let input = FileInput::from_bytes(b"test".to_vec());
        let result = breaker.scan(&input).await.unwrap();

        assert!(result.is_clean());
        assert!(breaker.state().is_closed());
    }

    #[tokio::test]
    async fn test_circuit_opens_on_failures() {
        let scanner = MockScanner::new().with_fail_rate(1.0);
        let config = CircuitBreakerConfig::default().with_failure_threshold(3);
        let breaker = CircuitBreaker::new(scanner, config);

        let input = FileInput::from_bytes(b"test".to_vec());

        // First 3 failures should open the circuit
        for _ in 0..3 {
            let _ = breaker.scan(&input).await;
        }

        assert!(breaker.state().is_open());
        assert_eq!(breaker.metrics().times_opened, 1);
    }

    #[tokio::test]
    async fn test_circuit_rejects_when_open() {
        let scanner = MockScanner::new_clean();
        let breaker = CircuitBreaker::with_defaults(scanner);

        // Force open
        breaker.force_open();
        assert!(breaker.state().is_open());

        let input = FileInput::from_bytes(b"test".to_vec());
        let result = breaker.scan(&input).await;

        assert!(matches!(result, Err(ScanError::CircuitOpen { .. })));
    }

    #[tokio::test]
    async fn test_circuit_transitions_to_half_open() {
        let scanner = MockScanner::new_clean();
        let config = CircuitBreakerConfig::default().with_open_duration(Duration::from_millis(10));
        let breaker = CircuitBreaker::new(scanner, config);

        breaker.force_open();
        assert!(breaker.state().is_open());

        // Wait for open duration
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Next request should transition to half-open
        let input = FileInput::from_bytes(b"test".to_vec());
        let result = breaker.scan(&input).await;

        // Should succeed and transition states
        assert!(result.is_ok());
    }

    #[test]
    fn test_force_open_close() {
        let scanner = MockScanner::new_clean();
        let breaker = CircuitBreaker::with_defaults(scanner);

        assert!(breaker.state().is_closed());

        breaker.force_open();
        assert!(breaker.state().is_open());

        breaker.force_close();
        assert!(breaker.state().is_closed());
    }
}
