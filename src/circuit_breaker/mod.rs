//! Circuit breaker implementation for scanner resilience.
//!
//! The circuit breaker pattern prevents cascading failures by temporarily
//! stopping traffic to failing backends and periodically probing them to
//! detect recovery.
//!
//! ## States
//!
//! - **Closed**: Normal operation; requests pass through.
//! - **Open**: Backend is failing; requests are rejected immediately.
//! - **Half-Open**: Probing the backend to see if it has recovered.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use scanbridge::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
//! use scanbridge::backends::MockScanner;
//! use std::time::Duration;
//!
//! let scanner = MockScanner::new();
//! let config = CircuitBreakerConfig::default()
//!     .with_failure_threshold(5)
//!     .with_open_duration(Duration::from_secs(30));
//!
//! let protected = CircuitBreaker::new(scanner, config);
//! ```

mod breaker;
mod config;
mod state;

pub use breaker::CircuitBreaker;
pub use config::{CircuitBreakerConfig, FailurePolicy, FallbackBehavior};
pub use state::BreakerState;
