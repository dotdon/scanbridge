//! Core traits for the scanbridge library.
//!
//! This module defines the `Scanner` trait that all scanning backends
//! must implement, as well as related configuration traits.

use crate::core::error::ScanError;
use crate::core::input::FileInput;
use crate::core::result::ScanResult;

use async_trait::async_trait;
use std::fmt::Debug;
use std::time::Duration;

/// The core trait for malware scanning engines.
///
/// All scanning backends (ClamAV, VirusTotal, etc.) implement this trait,
/// providing a consistent interface for file scanning.
///
/// # Implementation Notes
///
/// - Implementations must be `Send + Sync` for use in async contexts.
/// - The `scan` method should handle timeouts internally or defer to the caller.
/// - Health checks should be lightweight and not require file data.
/// - Implementations should never panic; all errors should be returned as `ScanError`.
///
/// # Example Implementation
///
/// ```rust,ignore
/// use scanbridge::core::{Scanner, ScanResult, ScanError, FileInput};
/// use async_trait::async_trait;
///
/// struct MyScanner {
///     name: String,
/// }
///
/// #[async_trait]
/// impl Scanner for MyScanner {
///     fn name(&self) -> &str {
///         &self.name
///     }
///
///     async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
///         // Perform scan...
///         todo!()
///     }
///
///     async fn health_check(&self) -> Result<(), ScanError> {
///         // Check if engine is reachable...
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait Scanner: Send + Sync + Debug {
    /// Returns the name of this scanner engine.
    ///
    /// This should be a stable, human-readable identifier like "clamav" or "virustotal".
    fn name(&self) -> &str;

    /// Scans the given file input for malware.
    ///
    /// # Arguments
    ///
    /// * `input` - The file to scan, provided as path, bytes, or stream.
    ///
    /// # Returns
    ///
    /// * `Ok(ScanResult)` - The scan completed successfully.
    /// * `Err(ScanError)` - The scan failed.
    ///
    /// # Errors
    ///
    /// Returns `ScanError` for various failure modes:
    /// - `EngineUnavailable` - The engine is not running or reachable.
    /// - `Timeout` - The scan took too long.
    /// - `ConnectionFailed` - Network or socket connection failed.
    /// - `MalformedFile` - The file could not be processed.
    /// - `FileTooLarge` - The file exceeds size limits.
    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError>;

    /// Performs a health check on the scanner.
    ///
    /// This should be a lightweight check that verifies the engine is
    /// reachable and operational without requiring file data.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The engine is healthy.
    /// * `Err(ScanError)` - The engine is unhealthy.
    async fn health_check(&self) -> Result<(), ScanError>;

    /// Returns the maximum file size this scanner can handle.
    ///
    /// Returns `None` if there is no specific limit.
    fn max_file_size(&self) -> Option<u64> {
        None
    }

    /// Returns the scanner's signature database version, if available.
    async fn signature_version(&self) -> Option<String> {
        None
    }

    /// Returns whether this scanner supports streaming input.
    ///
    /// Scanners that support streaming can process files without
    /// loading them entirely into memory.
    fn supports_streaming(&self) -> bool {
        false
    }
}

/// Configuration for a scanner instance.
///
/// This trait provides common configuration options that apply
/// to most scanner implementations.
pub trait ScannerConfig: Debug + Clone + Send + Sync {
    /// Returns the connection timeout.
    fn connection_timeout(&self) -> Duration;

    /// Returns the scan operation timeout.
    fn scan_timeout(&self) -> Duration;

    /// Returns the maximum file size to accept.
    fn max_file_size(&self) -> u64;

    /// Returns whether to enable debug logging.
    fn debug(&self) -> bool {
        false
    }
}

/// Default scanner configuration.
#[derive(Debug, Clone)]
pub struct DefaultScannerConfig {
    /// Timeout for establishing connections.
    pub connection_timeout: Duration,
    /// Timeout for scan operations.
    pub scan_timeout: Duration,
    /// Maximum file size in bytes.
    pub max_file_size: u64,
    /// Enable debug logging.
    pub debug: bool,
}

impl Default for DefaultScannerConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            scan_timeout: Duration::from_secs(300), // 5 minutes
            max_file_size: 100 * 1024 * 1024,       // 100 MB
            debug: false,
        }
    }
}

impl ScannerConfig for DefaultScannerConfig {
    fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    fn scan_timeout(&self) -> Duration {
        self.scan_timeout
    }

    fn max_file_size(&self) -> u64 {
        self.max_file_size
    }

    fn debug(&self) -> bool {
        self.debug
    }
}

impl DefaultScannerConfig {
    /// Creates a new default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the connection timeout.
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Sets the scan timeout.
    pub fn with_scan_timeout(mut self, timeout: Duration) -> Self {
        self.scan_timeout = timeout;
        self
    }

    /// Sets the maximum file size.
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Enables or disables debug mode.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }
}

/// A boxed scanner for type-erased storage.
pub type BoxedScanner = Box<dyn Scanner>;

/// An arc-wrapped scanner for shared ownership.
pub type ArcScanner = std::sync::Arc<dyn Scanner>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DefaultScannerConfig::default();
        assert_eq!(config.connection_timeout(), Duration::from_secs(10));
        assert_eq!(config.scan_timeout(), Duration::from_secs(300));
        assert_eq!(config.max_file_size(), 100 * 1024 * 1024);
        assert!(!config.debug());
    }

    #[test]
    fn test_config_builder() {
        let config = DefaultScannerConfig::new()
            .with_connection_timeout(Duration::from_secs(5))
            .with_scan_timeout(Duration::from_secs(60))
            .with_max_file_size(50 * 1024 * 1024)
            .with_debug(true);

        assert_eq!(config.connection_timeout(), Duration::from_secs(5));
        assert_eq!(config.scan_timeout(), Duration::from_secs(60));
        assert_eq!(config.max_file_size(), 50 * 1024 * 1024);
        assert!(config.debug());
    }
}
