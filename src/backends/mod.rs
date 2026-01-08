//! Scanning backend implementations.
//!
//! This module contains implementations of the `Scanner` trait for
//! various malware scanning engines.
//!
//! ## Available Backends
//!
//! - [`mock`] - A mock scanner for testing
//! - [`clamav`] - ClamAV via socket protocol (requires `clamav` feature)
//! - [`virustotal`] - VirusTotal REST API (requires `virustotal` feature)
//!
//! ## Implementing a Custom Backend
//!
//! To add a new scanning engine, implement the `Scanner` trait:
//!
//! ```rust,ignore
//! use scanbridge::core::{Scanner, ScanResult, ScanError, FileInput};
//! use async_trait::async_trait;
//!
//! #[derive(Debug)]
//! pub struct MyScanner {
//!     // Your scanner's configuration
//! }
//!
//! #[async_trait]
//! impl Scanner for MyScanner {
//!     fn name(&self) -> &str {
//!         "my-scanner"
//!     }
//!
//!     async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
//!         // Implement scanning logic
//!         todo!()
//!     }
//!
//!     async fn health_check(&self) -> Result<(), ScanError> {
//!         // Implement health check
//!         Ok(())
//!     }
//! }
//! ```

pub mod mock;

#[cfg(feature = "clamav")]
pub mod clamav;

#[cfg(feature = "virustotal")]
pub mod virustotal;

// Re-exports
pub use mock::MockScanner;

#[cfg(feature = "clamav")]
pub use clamav::ClamAvScanner;

#[cfg(feature = "virustotal")]
pub use virustotal::VirusTotalScanner;
