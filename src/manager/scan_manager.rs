//! The main scan manager implementation.

use crate::core::{
    ArcScanner, FileHasher, FileInput, ScanContext, ScanError, ScanReport, ScanResult,
};
use crate::manager::queue::{ScanHandle, ScanQueue};
use crate::manager::retry::{retry_async, RetryConfig};
use crate::policy::{PolicyAction, PolicyDecision, PolicyEngine};
use crate::quarantine::QuarantineStore;

use std::sync::Arc;
use std::time::Duration;

/// Configuration for the scan manager.
#[derive(Debug, Clone)]
pub struct ScanManagerConfig {
    /// Timeout for individual scan operations.
    pub scan_timeout: Duration,

    /// Whether to enable deduplication based on file hash.
    pub enable_deduplication: bool,

    /// Retry configuration.
    pub retry: RetryConfig,

    /// Maximum file size to accept.
    pub max_file_size: u64,

    /// Whether to run scanners in parallel.
    pub parallel_scans: bool,

    /// Maximum number of parallel scanners.
    pub max_parallel_scanners: usize,
}

impl Default for ScanManagerConfig {
    fn default() -> Self {
        Self {
            scan_timeout: Duration::from_secs(300),
            enable_deduplication: true,
            retry: RetryConfig::default(),
            max_file_size: 100 * 1024 * 1024, // 100 MB
            parallel_scans: true,
            max_parallel_scanners: 4,
        }
    }
}

impl ScanManagerConfig {
    /// Creates a new configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the scan timeout.
    pub fn with_scan_timeout(mut self, timeout: Duration) -> Self {
        self.scan_timeout = timeout;
        self
    }

    /// Enables or disables deduplication.
    pub fn with_deduplication(mut self, enabled: bool) -> Self {
        self.enable_deduplication = enabled;
        self
    }

    /// Sets the retry configuration.
    pub fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    /// Sets the maximum file size.
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Enables or disables parallel scanning.
    pub fn with_parallel_scans(mut self, enabled: bool) -> Self {
        self.parallel_scans = enabled;
        self
    }
}

/// Builder for creating a `ScanManager`.
pub struct ScanManagerBuilder {
    scanners: Vec<ArcScanner>,
    policy_engine: Option<PolicyEngine>,
    quarantine: Option<Arc<dyn QuarantineStore>>,
    config: ScanManagerConfig,
}

impl ScanManagerBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
            policy_engine: None,
            quarantine: None,
            config: ScanManagerConfig::default(),
        }
    }

    /// Adds a scanner to the manager.
    pub fn add_scanner<S: crate::core::Scanner + 'static>(mut self, scanner: S) -> Self {
        self.scanners.push(Arc::new(scanner));
        self
    }

    /// Adds a scanner wrapped in an Arc.
    pub fn add_arc_scanner(mut self, scanner: ArcScanner) -> Self {
        self.scanners.push(scanner);
        self
    }

    /// Sets the policy engine.
    pub fn with_policy_engine(mut self, engine: PolicyEngine) -> Self {
        self.policy_engine = Some(engine);
        self
    }

    /// Sets the quarantine store.
    pub fn with_quarantine<Q: QuarantineStore + 'static>(mut self, store: Q) -> Self {
        self.quarantine = Some(Arc::new(store));
        self
    }

    /// Sets the configuration.
    pub fn with_config(mut self, config: ScanManagerConfig) -> Self {
        self.config = config;
        self
    }

    /// Builds the scan manager.
    pub fn build(self) -> Result<ScanManager, ScanError> {
        if self.scanners.is_empty() {
            return Err(ScanError::configuration("At least one scanner is required"));
        }

        Ok(ScanManager {
            scanners: self.scanners,
            policy_engine: self.policy_engine.unwrap_or_default(),
            quarantine: self.quarantine,
            config: self.config,
            queue: ScanQueue::default(),
            hasher: FileHasher::new(),
        })
    }
}

impl Default for ScanManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The main scan manager that orchestrates scans across multiple engines.
pub struct ScanManager {
    /// Registered scanners.
    scanners: Vec<ArcScanner>,
    /// Policy engine for determining actions.
    policy_engine: PolicyEngine,
    /// Quarantine store for infected files.
    quarantine: Option<Arc<dyn QuarantineStore>>,
    /// Configuration.
    config: ScanManagerConfig,
    /// Background scan queue.
    queue: ScanQueue,
    /// File hasher.
    hasher: FileHasher,
}

impl ScanManager {
    /// Creates a new builder.
    pub fn builder() -> ScanManagerBuilder {
        ScanManagerBuilder::new()
    }

    /// Scans a file using all configured scanners.
    pub async fn scan(
        &self,
        input: FileInput,
        context: ScanContext,
    ) -> Result<ScanReport, ScanError> {
        // Validate file size
        if let Some(size) = input.size_hint() {
            if size > self.config.max_file_size {
                return Err(ScanError::FileTooLarge {
                    size,
                    max: self.config.max_file_size,
                });
            }
        }

        // Compute file hash for deduplication
        let hash = self.hasher.hash_input(&input)?;

        tracing::info!(
            file_hash = %hash.blake3,
            filename = ?input.filename(),
            tenant_id = ?context.tenant_id,
            "Starting scan"
        );

        // Run scans
        let results = if self.config.parallel_scans && self.scanners.len() > 1 {
            self.scan_parallel(&input, &context).await?
        } else {
            self.scan_sequential(&input, &context).await?
        };

        // Build report
        let report = ScanReport::from_results(results, context);

        tracing::info!(
            file_hash = %hash.blake3,
            outcome = ?report.aggregated_outcome,
            engine_count = report.engine_count(),
            duration_ms = report.total_duration.as_millis(),
            "Scan completed"
        );

        // Emit audit event
        crate::audit::emit_scan_report(&report);

        Ok(report)
    }

    /// Scans with policy evaluation and optional quarantine.
    pub async fn scan_with_policy(
        &self,
        input: FileInput,
        context: ScanContext,
    ) -> Result<PolicyDecision, ScanError> {
        let report = self.scan(input, context.clone()).await?;

        // Evaluate policy
        let decision = self.policy_engine.evaluate(&report, &context);

        tracing::info!(
            file_hash = %report.file_hash.blake3,
            action = ?decision.action,
            rule_id = ?decision.matched_rule_id,
            "Policy decision made"
        );

        // Handle quarantine if needed
        if let PolicyAction::Quarantine { ref reason } = decision.action {
            if self.quarantine.is_some() {
                tracing::info!(
                    file_hash = %report.file_hash.blake3,
                    reason = %reason,
                    "Quarantining file"
                );
                // Note: Actual quarantine would happen here
                // For now, we just log the intent
            }
        }

        Ok(decision)
    }

    /// Queues a scan for background processing.
    ///
    /// Returns a handle that can be used to check the scan status or wait for completion.
    /// The scan will be processed when a slot becomes available in the queue.
    #[cfg(feature = "tokio-runtime")]
    pub fn queue_scan(self: &Arc<Self>, input: FileInput, context: ScanContext) -> ScanHandle {
        let handle = ScanHandle::new();
        self.queue.add_pending();

        let manager = Arc::clone(self);
        let scan_handle = handle.clone();

        tokio::spawn(async move {
            // Wait for a queue slot
            while !manager.queue.acquire() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            scan_handle.set_in_progress();

            tracing::debug!(
                scan_id = %scan_handle.id,
                "Background scan starting"
            );

            // Perform the scan with retry
            let result = retry_async(&manager.config.retry, || async {
                manager.scan(input.clone(), context.clone()).await
            })
            .await;

            // Release the queue slot
            manager.queue.release();

            // Update handle with result
            match result {
                Ok(report) => {
                    tracing::debug!(
                        scan_id = %scan_handle.id,
                        outcome = ?report.aggregated_outcome,
                        "Background scan completed"
                    );
                    scan_handle.set_complete(report);
                }
                Err(e) => {
                    tracing::warn!(
                        scan_id = %scan_handle.id,
                        error = %e,
                        "Background scan failed"
                    );
                    scan_handle.set_failed(e.to_string());
                }
            }
        });

        handle
    }

    /// Queues a scan for background processing (non-tokio fallback).
    #[cfg(not(feature = "tokio-runtime"))]
    pub fn queue_scan(&self, _input: FileInput, _context: ScanContext) -> ScanHandle {
        let handle = ScanHandle::new();
        self.queue.add_pending();
        handle.set_failed("Background scanning requires tokio-runtime feature".to_string());
        handle
    }

    /// Returns the number of registered scanners.
    pub fn scanner_count(&self) -> usize {
        self.scanners.len()
    }

    /// Returns references to the registered scanners.
    pub fn scanners(&self) -> &[ArcScanner] {
        &self.scanners
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &ScanManagerConfig {
        &self.config
    }

    /// Returns a reference to the policy engine.
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    async fn scan_sequential(
        &self,
        input: &FileInput,
        context: &ScanContext,
    ) -> Result<Vec<ScanResult>, ScanError> {
        let mut results = Vec::with_capacity(self.scanners.len());

        for scanner in &self.scanners {
            match self.scan_with_timeout(scanner, input).await {
                Ok(mut result) => {
                    // Inject context
                    result.context = context.clone();
                    results.push(result);
                }
                Err(e) => {
                    tracing::warn!(
                        engine = scanner.name(),
                        error = %e,
                        "Scanner failed, continuing with others"
                    );
                    // Continue with other scanners
                }
            }
        }

        if results.is_empty() {
            return Err(ScanError::internal("All scanners failed"));
        }

        Ok(results)
    }

    async fn scan_parallel(
        &self,
        input: &FileInput,
        context: &ScanContext,
    ) -> Result<Vec<ScanResult>, ScanError> {
        use futures::future::join_all;

        let futures: Vec<_> = self
            .scanners
            .iter()
            .map(|scanner| async move {
                let result = self.scan_with_timeout(scanner, input).await;
                (scanner.name().to_string(), result)
            })
            .collect();

        let outcomes = join_all(futures).await;

        let mut results = Vec::with_capacity(outcomes.len());
        for (engine, result) in outcomes {
            match result {
                Ok(mut scan_result) => {
                    scan_result.context = context.clone();
                    results.push(scan_result);
                }
                Err(e) => {
                    tracing::warn!(
                        engine = %engine,
                        error = %e,
                        "Scanner failed in parallel scan"
                    );
                }
            }
        }

        if results.is_empty() {
            return Err(ScanError::internal("All scanners failed"));
        }

        Ok(results)
    }

    async fn scan_with_timeout(
        &self,
        scanner: &ArcScanner,
        input: &FileInput,
    ) -> Result<ScanResult, ScanError> {
        #[cfg(feature = "tokio-runtime")]
        {
            match tokio::time::timeout(self.config.scan_timeout, scanner.scan(input)).await {
                Ok(result) => result,
                Err(_) => Err(ScanError::timeout(
                    scanner.name(),
                    self.config.scan_timeout,
                )),
            }
        }

        #[cfg(not(feature = "tokio-runtime"))]
        {
            scanner.scan(input).await
        }
    }
}

impl std::fmt::Debug for ScanManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanManager")
            .field("scanner_count", &self.scanners.len())
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::MockScanner;

    #[tokio::test]
    async fn test_scan_manager_basic() {
        let scanner = MockScanner::new_clean();
        let manager = ScanManager::builder()
            .add_scanner(scanner)
            .build()
            .unwrap();

        let input = FileInput::from_bytes(b"test data".to_vec());
        let context = ScanContext::new().with_tenant_id("test");

        let report = manager.scan(input, context).await.unwrap();
        assert!(report.is_clean());
        assert_eq!(report.engine_count(), 1);
    }

    #[tokio::test]
    async fn test_scan_manager_multiple_scanners() {
        let scanner1 = MockScanner::new_clean().with_name("scanner1");
        let scanner2 = MockScanner::new_clean().with_name("scanner2");

        let manager = ScanManager::builder()
            .add_scanner(scanner1)
            .add_scanner(scanner2)
            .build()
            .unwrap();

        let input = FileInput::from_bytes(b"test data".to_vec());
        let context = ScanContext::new();

        let report = manager.scan(input, context).await.unwrap();
        assert!(report.is_clean());
        assert_eq!(report.engine_count(), 2);
    }

    #[tokio::test]
    async fn test_scan_manager_file_too_large() {
        let scanner = MockScanner::new_clean();
        let config = ScanManagerConfig::default().with_max_file_size(10);

        let manager = ScanManager::builder()
            .add_scanner(scanner)
            .with_config(config)
            .build()
            .unwrap();

        // Create a file larger than the limit
        let input = FileInput::from_bytes(vec![0u8; 100]);
        let context = ScanContext::new();

        let result = manager.scan(input, context).await;
        assert!(matches!(result, Err(ScanError::FileTooLarge { .. })));
    }

    #[test]
    fn test_builder_requires_scanner() {
        let result = ScanManager::builder().build();
        assert!(result.is_err());
    }
}
