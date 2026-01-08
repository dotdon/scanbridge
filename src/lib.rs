//! # Scanbridge
//!
//! A unified, pluggable API for malware scanning with circuit breakers,
//! policy enforcement, quarantine support, and compliance-ready audit logging.
//!
//! ## Overview
//!
//! Scanbridge provides an abstraction layer over multiple malware scanning engines,
//! allowing you to:
//!
//! - Submit files for scanning through a consistent API
//! - Use multiple scanning backends (ClamAV, VirusTotal, etc.)
//! - Handle failures gracefully with circuit breakers
//! - Apply policies to determine actions based on scan results
//! - Quarantine infected files safely
//! - Generate structured audit logs for compliance
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use scanbridge::{ScanManager, ScanManagerConfig, FileInput, ScanContext};
//! use scanbridge::backends::MockScanner;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a scanner
//!     let scanner = MockScanner::new_clean();
//!     
//!     // Create the scan manager
//!     let manager = ScanManager::builder()
//!         .add_scanner(scanner)
//!         .build()?;
//!     
//!     // Scan a file
//!     let input = FileInput::from_bytes(b"file content".to_vec());
//!     let context = ScanContext::new().with_tenant_id("my-tenant");
//!     let result = manager.scan(input, context).await?;
//!     
//!     if result.is_clean() {
//!         println!("File is clean!");
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Features
//!
//! - `default` - Includes tokio runtime support
//! - `tokio-runtime` - Async support via tokio
//! - `clamav` - ClamAV backend support
//! - `virustotal` - VirusTotal API backend support
//!
//! ## Architecture
//!
//! The library is organized into several layers:
//!
//! - **Core**: Fundamental types, traits, and error handling
//! - **Backends**: Individual scanner implementations
//! - **Circuit Breaker**: Resilience patterns for failing scanners
//! - **Manager**: Orchestration of scans across multiple engines
//! - **Policy**: Configurable rules for handling scan results
//! - **Quarantine**: Safe storage for infected files
//! - **Audit**: Structured logging for compliance

#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]

pub mod audit;
pub mod backends;
pub mod circuit_breaker;
pub mod core;
pub mod manager;
pub mod policy;
pub mod quarantine;

// Re-export commonly used types at the crate root
pub use crate::core::{
    FileHash, FileHasher, FileInput, FileMetadata, ScanContext, ScanError, ScanOutcome,
    ScanReport, ScanResult, Scanner, ThreatInfo, ThreatSeverity,
};

pub use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
pub use crate::manager::{ScanManager, ScanManagerConfig};
pub use crate::policy::{PolicyAction, PolicyEngine, PolicyRule};
pub use crate::quarantine::{QuarantineRecord, QuarantineStore};

/// Prelude module for convenient imports.
///
/// ```rust
/// use scanbridge::prelude::*;
/// ```
pub mod prelude {
    pub use crate::core::{
        FileHash, FileHasher, FileInput, FileMetadata, ScanContext, ScanError, ScanOutcome,
        ScanReport, ScanResult, Scanner, ThreatInfo, ThreatSeverity,
    };
    pub use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
    pub use crate::manager::{ScanManager, ScanManagerConfig};
    pub use crate::policy::{PolicyAction, PolicyEngine, PolicyRule};
    pub use crate::quarantine::{QuarantineRecord, QuarantineStore};
}
