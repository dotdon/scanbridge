//! Error types for the scanbridge library.
//!
//! This module provides structured, typed errors for all failure scenarios.
//! The library never panics; all errors are returned as `Result` values.

use std::time::Duration;
use thiserror::Error;

/// The main error type for scan operations.
///
/// All error variants include context about what failed and why,
/// enabling proper error handling and debugging.
#[derive(Debug, Error)]
pub enum ScanError {
    /// The scanning engine is unavailable or not responding.
    #[error("engine '{engine}' is unavailable: {reason}")]
    EngineUnavailable {
        /// Name of the engine that is unavailable.
        engine: String,
        /// Human-readable reason for unavailability.
        reason: String,
    },

    /// The scan operation timed out.
    #[error("scan timed out after {elapsed:?} on engine '{engine}'")]
    Timeout {
        /// Name of the engine that timed out.
        engine: String,
        /// How long the operation ran before timing out.
        elapsed: Duration,
    },

    /// Failed to connect to the scanning engine.
    #[error("connection to engine '{engine}' failed: {message}")]
    ConnectionFailed {
        /// Name of the engine.
        engine: String,
        /// Error message describing the failure.
        message: String,
    },

    /// The file is malformed or cannot be processed.
    #[error("malformed file: {reason}")]
    MalformedFile {
        /// Description of what's wrong with the file.
        reason: String,
    },

    /// The file exceeds the maximum allowed size.
    #[error("file size {size} bytes exceeds maximum {max} bytes")]
    FileTooLarge {
        /// Actual file size in bytes.
        size: u64,
        /// Maximum allowed size in bytes.
        max: u64,
    },

    /// The circuit breaker is open for this engine.
    #[error("circuit breaker open for engine '{engine}'")]
    CircuitOpen {
        /// Name of the engine with open circuit.
        engine: String,
        /// When the circuit might close (if known).
        recovery_hint: Option<String>,
    },

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// File not found at the specified path.
    #[error("file not found: {path}")]
    FileNotFound {
        /// Path that was not found.
        path: String,
    },

    /// The engine returned an ambiguous or unparseable response.
    #[error("ambiguous response from engine '{engine}': {details}")]
    AmbiguousResponse {
        /// Name of the engine.
        engine: String,
        /// Details about the ambiguity.
        details: String,
    },

    /// Rate limit exceeded for the engine.
    #[error("rate limit exceeded for engine '{engine}': retry after {retry_after:?}")]
    RateLimited {
        /// Name of the engine.
        engine: String,
        /// Suggested wait time before retry.
        retry_after: Option<Duration>,
    },

    /// Authentication failed for the engine.
    #[error("authentication failed for engine '{engine}': {reason}")]
    AuthenticationFailed {
        /// Name of the engine.
        engine: String,
        /// Reason for authentication failure.
        reason: String,
    },

    /// The scan was cancelled.
    #[error("scan was cancelled")]
    Cancelled,

    /// An internal error occurred.
    #[error("internal error: {message}")]
    Internal {
        /// Description of the internal error.
        message: String,
    },

    /// Configuration error.
    #[error("configuration error: {message}")]
    Configuration {
        /// Description of the configuration error.
        message: String,
    },
}

impl ScanError {
    /// Returns `true` if this error is recoverable (can be retried).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. }
                | Self::ConnectionFailed { .. }
                | Self::RateLimited { .. }
                | Self::CircuitOpen { .. }
        )
    }

    /// Returns `true` if this error indicates the engine is unhealthy.
    pub fn indicates_unhealthy_engine(&self) -> bool {
        matches!(
            self,
            Self::EngineUnavailable { .. }
                | Self::Timeout { .. }
                | Self::ConnectionFailed { .. }
                | Self::AuthenticationFailed { .. }
        )
    }

    /// Returns the engine name if this error is associated with one.
    pub fn engine(&self) -> Option<&str> {
        match self {
            Self::EngineUnavailable { engine, .. }
            | Self::Timeout { engine, .. }
            | Self::ConnectionFailed { engine, .. }
            | Self::CircuitOpen { engine, .. }
            | Self::AmbiguousResponse { engine, .. }
            | Self::RateLimited { engine, .. }
            | Self::AuthenticationFailed { engine, .. } => Some(engine),
            _ => None,
        }
    }

    /// Creates an `EngineUnavailable` error.
    pub fn engine_unavailable(engine: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::EngineUnavailable {
            engine: engine.into(),
            reason: reason.into(),
        }
    }

    /// Creates a `Timeout` error.
    pub fn timeout(engine: impl Into<String>, elapsed: Duration) -> Self {
        Self::Timeout {
            engine: engine.into(),
            elapsed,
        }
    }

    /// Creates a `ConnectionFailed` error.
    pub fn connection_failed(engine: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ConnectionFailed {
            engine: engine.into(),
            message: message.into(),
        }
    }

    /// Creates an `Internal` error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Creates a `Configuration` error.
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }
}

/// Error type for quarantine operations.
#[derive(Debug, Error)]
pub enum QuarantineError {
    /// Failed to store the file in quarantine.
    #[error("failed to store file in quarantine: {reason}")]
    StoreFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Quarantine record not found.
    #[error("quarantine record not found: {id}")]
    NotFound {
        /// The quarantine ID that was not found.
        id: String,
    },

    /// Failed to retrieve file from quarantine.
    #[error("failed to retrieve file from quarantine: {reason}")]
    RetrieveFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Failed to delete file from quarantine.
    #[error("failed to delete file from quarantine: {reason}")]
    DeleteFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Quarantine storage is full.
    #[error("quarantine storage is full")]
    StorageFull,

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// File integrity check failed.
    #[error("file integrity check failed: expected {expected}, got {actual}")]
    IntegrityCheckFailed {
        /// Expected hash.
        expected: String,
        /// Actual hash.
        actual: String,
    },
}

/// Error type for policy operations.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// No matching policy rule found.
    #[error("no matching policy rule for the given context")]
    NoMatchingRule,

    /// Policy rule configuration is invalid.
    #[error("invalid policy rule '{rule_id}': {reason}")]
    InvalidRule {
        /// ID of the invalid rule.
        rule_id: String,
        /// Reason for invalidity.
        reason: String,
    },

    /// Policy evaluation failed.
    #[error("policy evaluation failed: {reason}")]
    EvaluationFailed {
        /// Reason for the failure.
        reason: String,
    },
}

/// A specialized `Result` type for scan operations.
pub type ScanResult<T> = Result<T, ScanError>;

/// A specialized `Result` type for quarantine operations.
pub type QuarantineResult<T> = Result<T, QuarantineError>;

/// A specialized `Result` type for policy operations.
pub type PolicyResult<T> = Result<T, PolicyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_error_is_recoverable() {
        let timeout = ScanError::timeout("test", Duration::from_secs(30));
        assert!(timeout.is_recoverable());

        let malformed = ScanError::MalformedFile {
            reason: "corrupt header".into(),
        };
        assert!(!malformed.is_recoverable());
    }

    #[test]
    fn test_scan_error_engine() {
        let err = ScanError::engine_unavailable("clamav", "service not running");
        assert_eq!(err.engine(), Some("clamav"));

        let io_err = ScanError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "test error",
        ));
        assert_eq!(io_err.engine(), None);
    }

    #[test]
    fn test_scan_error_display() {
        let err = ScanError::FileTooLarge {
            size: 100_000_000,
            max: 50_000_000,
        };
        assert!(err.to_string().contains("100000000"));
        assert!(err.to_string().contains("50000000"));
    }
}
