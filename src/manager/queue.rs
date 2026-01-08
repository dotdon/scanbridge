//! Background scan queue for non-blocking scan operations.

use crate::core::{ScanError, ScanReport};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// A handle to a queued scan operation.
#[derive(Debug, Clone)]
pub struct ScanHandle {
    /// Unique identifier for this scan.
    pub id: String,
    /// Status of the scan.
    status: Arc<std::sync::RwLock<ScanStatus>>,
}

impl ScanHandle {
    /// Creates a new scan handle.
    pub(crate) fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            status: Arc::new(std::sync::RwLock::new(ScanStatus::Pending)),
        }
    }

    /// Returns the current status of the scan.
    pub fn status(&self) -> ScanStatus {
        self.status
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Returns true if the scan is complete.
    pub fn is_complete(&self) -> bool {
        matches!(
            self.status(),
            ScanStatus::Complete { .. } | ScanStatus::Failed { .. }
        )
    }

    /// Returns true if the scan is still pending.
    pub fn is_pending(&self) -> bool {
        matches!(self.status(), ScanStatus::Pending)
    }

    /// Returns true if the scan is in progress.
    pub fn is_in_progress(&self) -> bool {
        matches!(self.status(), ScanStatus::InProgress)
    }

    /// Sets the status to in progress.
    pub(crate) fn set_in_progress(&self) {
        *self
            .status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = ScanStatus::InProgress;
    }

    /// Sets the status to complete with the given result.
    pub(crate) fn set_complete(&self, result: ScanReport) {
        *self
            .status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = ScanStatus::Complete {
            result: Box::new(result),
        };
    }

    /// Sets the status to failed with the given error.
    pub(crate) fn set_failed(&self, error: String) {
        *self
            .status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = ScanStatus::Failed { error };
    }

    /// Waits for the scan to complete and returns the result.
    #[cfg(feature = "tokio-runtime")]
    pub async fn wait(self) -> Result<ScanReport, ScanError> {
        loop {
            match self.status() {
                ScanStatus::Complete { result } => return Ok(*result),
                ScanStatus::Failed { error } => {
                    return Err(ScanError::internal(error));
                }
                _ => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    }
}

/// Status of a queued scan.
#[derive(Debug, Clone)]
pub enum ScanStatus {
    /// Scan is waiting in the queue.
    Pending,
    /// Scan is currently in progress.
    InProgress,
    /// Scan completed successfully.
    Complete {
        /// The scan result.
        result: Box<ScanReport>,
    },
    /// Scan failed.
    Failed {
        /// Error message.
        error: String,
    },
}

/// A queue for background scan operations.
#[derive(Debug)]
pub struct ScanQueue {
    /// Maximum number of concurrent scans.
    max_concurrent: usize,
    /// Current number of active scans.
    active_count: AtomicU64,
    /// Pending scans counter.
    pending_count: AtomicU64,
}

impl ScanQueue {
    /// Creates a new scan queue with the given concurrency limit.
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            max_concurrent: max_concurrent.max(1),
            active_count: AtomicU64::new(0),
            pending_count: AtomicU64::new(0),
        }
    }

    /// Returns the maximum number of concurrent scans.
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Returns the current number of active scans.
    pub fn active_count(&self) -> u64 {
        self.active_count.load(Ordering::Relaxed)
    }

    /// Returns the current number of pending scans.
    pub fn pending_count(&self) -> u64 {
        self.pending_count.load(Ordering::Relaxed)
    }

    /// Returns true if the queue is at capacity.
    pub fn is_full(&self) -> bool {
        self.active_count() >= self.max_concurrent as u64
    }

    /// Increments the active count.
    pub(crate) fn acquire(&self) -> bool {
        let current = self.active_count.fetch_add(1, Ordering::SeqCst);
        if current >= self.max_concurrent as u64 {
            self.active_count.fetch_sub(1, Ordering::SeqCst);
            false
        } else {
            // Only decrement pending_count if it's greater than 0 to avoid underflow
            self.pending_count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |val| {
                    if val > 0 {
                        Some(val - 1)
                    } else {
                        Some(0)
                    }
                })
                .ok();
            true
        }
    }

    /// Decrements the active count.
    pub(crate) fn release(&self) {
        self.active_count.fetch_sub(1, Ordering::SeqCst);
    }

    /// Adds to the pending count.
    pub(crate) fn add_pending(&self) {
        self.pending_count.fetch_add(1, Ordering::SeqCst);
    }
}

impl Default for ScanQueue {
    fn default() -> Self {
        Self::new(4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_handle() {
        let handle = ScanHandle::new();
        assert!(handle.is_pending());
        assert!(!handle.is_complete());
        assert!(!handle.is_in_progress());
    }

    #[test]
    fn test_scan_handle_transitions() {
        let handle = ScanHandle::new();

        handle.set_in_progress();
        assert!(handle.is_in_progress());

        handle.set_failed("test error".to_string());
        assert!(handle.is_complete());
        assert!(matches!(handle.status(), ScanStatus::Failed { .. }));
    }

    #[test]
    fn test_scan_queue() {
        let queue = ScanQueue::new(2);
        assert_eq!(queue.max_concurrent(), 2);
        assert_eq!(queue.active_count(), 0);
        assert!(!queue.is_full());
    }
}
