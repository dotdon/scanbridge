//! Mock scanner for testing.
//!
//! This module provides a configurable mock scanner that can be used
//! in tests to simulate various scan outcomes without requiring a real
//! scanning engine.

use crate::core::{
    FileHasher, FileInput, FileMetadata, ScanContext, ScanError, ScanOutcome, ScanResult, Scanner,
    ThreatInfo,
};

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

/// A mock scanner for testing purposes.
///
/// The mock scanner can be configured to return specific outcomes
/// for specific file hashes, or a default outcome for unknown files.
///
/// # Examples
///
/// ```rust
/// use scanbridge::backends::MockScanner;
/// use scanbridge::core::{ScanOutcome, ThreatInfo, ThreatSeverity};
/// use std::time::Duration;
///
/// // Create a scanner that reports all files as clean
/// let scanner = MockScanner::new_clean();
///
/// // Create a scanner that reports all files as infected
/// let threat = ThreatInfo::new("Test.Malware", ThreatSeverity::High, "mock");
/// let scanner = MockScanner::new_infected(vec![threat]);
///
/// // Create a scanner with custom responses per file hash
/// let scanner = MockScanner::new()
///     .with_response("abc123", ScanOutcome::Clean)
///     .with_latency(Duration::from_millis(100));
/// ```
#[derive(Debug)]
pub struct MockScanner {
    /// Name of this scanner instance.
    name: String,
    /// Responses keyed by file hash (BLAKE3).
    responses: RwLock<HashMap<String, ScanOutcome>>,
    /// Default outcome for files not in the response map.
    default_outcome: ScanOutcome,
    /// Simulated latency for scans.
    latency: Option<Duration>,
    /// Probability of failure (0.0 to 1.0).
    fail_rate: f32,
    /// Counter for scan operations.
    scan_count: AtomicU64,
    /// Whether to fail health checks.
    unhealthy: RwLock<bool>,
}

impl MockScanner {
    /// Creates a new mock scanner with default settings.
    pub fn new() -> Self {
        Self {
            name: "mock".to_string(),
            responses: RwLock::new(HashMap::new()),
            default_outcome: ScanOutcome::Clean,
            latency: None,
            fail_rate: 0.0,
            scan_count: AtomicU64::new(0),
            unhealthy: RwLock::new(false),
        }
    }

    /// Creates a mock scanner that always reports clean.
    pub fn new_clean() -> Self {
        Self::new()
    }

    /// Creates a mock scanner that always reports infected.
    pub fn new_infected(threats: Vec<ThreatInfo>) -> Self {
        Self {
            default_outcome: ScanOutcome::Infected { threats },
            ..Self::new()
        }
    }

    /// Sets the name of this scanner.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the default outcome for files not in the response map.
    pub fn with_default_outcome(mut self, outcome: ScanOutcome) -> Self {
        self.default_outcome = outcome;
        self
    }

    /// Adds a response for a specific file hash.
    pub fn with_response(self, hash: impl Into<String>, outcome: ScanOutcome) -> Self {
        self.responses.write().unwrap().insert(hash.into(), outcome);
        self
    }

    /// Sets the simulated latency for scans.
    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// Sets the probability of failure.
    pub fn with_fail_rate(mut self, rate: f32) -> Self {
        self.fail_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Returns the number of scans performed.
    pub fn scan_count(&self) -> u64 {
        self.scan_count.load(Ordering::Relaxed)
    }

    /// Sets the health status.
    pub fn set_healthy(&self, healthy: bool) {
        *self.unhealthy.write().unwrap() = !healthy;
    }

    /// Makes the scanner unhealthy (health checks will fail).
    pub fn make_unhealthy(&self) {
        self.set_healthy(false);
    }

    /// Makes the scanner healthy again.
    pub fn make_healthy(&self) {
        self.set_healthy(true);
    }

    /// Adds a response for a specific file hash (mutable version).
    pub fn add_response(&self, hash: impl Into<String>, outcome: ScanOutcome) {
        self.responses.write().unwrap().insert(hash.into(), outcome);
    }

    /// Clears all configured responses.
    pub fn clear_responses(&self) {
        self.responses.write().unwrap().clear();
    }

    fn should_fail(&self) -> bool {
        if self.fail_rate <= 0.0 {
            return false;
        }
        if self.fail_rate >= 1.0 {
            return true;
        }
        // Simple deterministic "randomness" based on scan count
        let count = self.scan_count.load(Ordering::Relaxed);
        (count as f32 * 0.618033988749895) % 1.0 < self.fail_rate
    }
}

impl Default for MockScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for MockScanner {
    fn name(&self) -> &str {
        &self.name
    }

    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
        self.scan_count.fetch_add(1, Ordering::Relaxed);

        // Check for simulated failures
        if self.should_fail() {
            return Err(ScanError::engine_unavailable(
                &self.name,
                "simulated failure",
            ));
        }

        // Simulate latency
        if let Some(latency) = self.latency {
            #[cfg(feature = "tokio-runtime")]
            tokio::time::sleep(latency).await;
            #[cfg(not(feature = "tokio-runtime"))]
            std::thread::sleep(latency);
        }

        // Compute file hash
        let hasher = FileHasher::new();
        let hash = match input {
            FileInput::Path(path) => hasher.hash_file(path)?,
            FileInput::Bytes { data, .. } => hasher.hash_bytes(data),
            FileInput::Stream { .. } => {
                return Err(ScanError::internal(
                    "Mock scanner does not support streaming",
                ));
            }
        };

        // Look up response or use default
        let outcome = self
            .responses
            .read()
            .unwrap()
            .get(&hash.blake3)
            .cloned()
            .unwrap_or_else(|| self.default_outcome.clone());

        // Build file metadata
        let size = input.size_hint().unwrap_or(0);
        let metadata = FileMetadata::new(size, hash);

        // Build scan result
        let duration = self.latency.unwrap_or(Duration::from_millis(1));
        let context = ScanContext::new();

        Ok(ScanResult::new(
            outcome,
            metadata,
            self.name.clone(),
            duration,
            context,
        ))
    }

    async fn health_check(&self) -> Result<(), ScanError> {
        if *self.unhealthy.read().unwrap() {
            return Err(ScanError::engine_unavailable(
                &self.name,
                "mock scanner is unhealthy",
            ));
        }
        Ok(())
    }

    fn max_file_size(&self) -> Option<u64> {
        Some(100 * 1024 * 1024) // 100 MB
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ThreatSeverity;

    #[tokio::test]
    async fn test_mock_scanner_clean() {
        let scanner = MockScanner::new_clean();
        let input = FileInput::from_bytes(b"test data".to_vec());

        let result = scanner.scan(&input).await.unwrap();
        assert!(result.is_clean());
        assert_eq!(scanner.scan_count(), 1);
    }

    #[tokio::test]
    async fn test_mock_scanner_infected() {
        let threats = vec![ThreatInfo::new("Test.Malware", ThreatSeverity::High, "mock")];
        let scanner = MockScanner::new_infected(threats);
        let input = FileInput::from_bytes(b"malicious data".to_vec());

        let result = scanner.scan(&input).await.unwrap();
        assert!(result.is_infected());
        assert_eq!(result.threats().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_mock_scanner_health_check() {
        let scanner = MockScanner::new();

        // Initially healthy
        assert!(scanner.health_check().await.is_ok());

        // Make unhealthy
        scanner.make_unhealthy();
        assert!(scanner.health_check().await.is_err());

        // Make healthy again
        scanner.make_healthy();
        assert!(scanner.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_scanner_custom_response() {
        let scanner = MockScanner::new()
            .with_default_outcome(ScanOutcome::Clean)
            .with_response(
                "known-malware-hash",
                ScanOutcome::Infected {
                    threats: vec![ThreatInfo::new("Known.Malware", ThreatSeverity::Critical, "mock")],
                },
            );

        // Unknown file should be clean
        let input = FileInput::from_bytes(b"unknown file".to_vec());
        let result = scanner.scan(&input).await.unwrap();
        assert!(result.is_clean());
    }
}
