//! Scan manager for orchestrating scans across multiple engines.
//!
//! The `ScanManager` coordinates scanning across one or more backends,
//! handling retries, timeouts, and result aggregation.

mod queue;
mod retry;
mod scan_manager;

pub use queue::{ScanHandle, ScanQueue};
pub use retry::RetryConfig;
pub use scan_manager::{ScanManager, ScanManagerBuilder, ScanManagerConfig};
