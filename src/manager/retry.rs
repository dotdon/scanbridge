//! Retry configuration and logic.

use std::time::Duration;

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_attempts: u32,

    /// Initial delay before first retry.
    pub initial_delay: Duration,

    /// Maximum delay between retries.
    pub max_delay: Duration,

    /// Multiplier for exponential backoff.
    pub backoff_multiplier: f64,

    /// Whether to add jitter to delays.
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryConfig {
    /// Creates a new retry configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Disables retries.
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }

    /// Sets the maximum number of attempts.
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts.max(1);
        self
    }

    /// Sets the initial delay.
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Sets the maximum delay.
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Sets the backoff multiplier.
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier.max(1.0);
        self
    }

    /// Enables or disables jitter.
    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    /// Calculates the delay for a given attempt number (0-indexed).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let base_delay = self.initial_delay.as_millis() as f64
            * self.backoff_multiplier.powi(attempt as i32 - 1);

        let capped_delay = base_delay.min(self.max_delay.as_millis() as f64);

        let final_delay = if self.jitter {
            // Simple deterministic jitter based on attempt number
            let jitter_factor = 0.5 + (attempt as f64 * 0.618033988749895) % 0.5;
            capped_delay * jitter_factor
        } else {
            capped_delay
        };

        Duration::from_millis(final_delay as u64)
    }

    /// Returns whether another attempt should be made.
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }
}

/// Executes an async operation with retry logic.
#[cfg(feature = "tokio-runtime")]
pub async fn retry_async<F, Fut, T, E>(
    config: &RetryConfig,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut attempt = 0;
    loop {
        let delay = config.delay_for_attempt(attempt);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }

        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                attempt += 1;
                if !config.should_retry(attempt) {
                    return Err(e);
                }
                tracing::debug!(
                    attempt = attempt,
                    max_attempts = config.max_attempts,
                    error = ?e,
                    "Retrying operation"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert!(config.jitter);
    }

    #[test]
    fn test_no_retry() {
        let config = RetryConfig::no_retry();
        assert_eq!(config.max_attempts, 1);
        assert!(!config.should_retry(1));
    }

    #[test]
    fn test_delay_calculation() {
        let config = RetryConfig::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        assert_eq!(config.delay_for_attempt(0), Duration::ZERO);
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(400));
    }

    #[test]
    fn test_delay_capped() {
        let config = RetryConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(5))
            .with_backoff_multiplier(10.0)
            .with_jitter(false);

        // 1 * 10 = 10, but capped at 5
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(5));
    }

    #[test]
    fn test_should_retry() {
        let config = RetryConfig::new().with_max_attempts(3);
        assert!(config.should_retry(0));
        assert!(config.should_retry(1));
        assert!(config.should_retry(2));
        assert!(!config.should_retry(3));
    }
}
