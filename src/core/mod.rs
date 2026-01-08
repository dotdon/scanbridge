//! Core types and traits for the scanbridge library.
//!
//! This module provides the fundamental building blocks used throughout
//! the library:
//!
//! - [`types`] - Common types like `ScanOutcome`, `ThreatInfo`, `FileHash`
//! - [`traits`] - The `Scanner` trait and configuration interfaces
//! - [`error`] - Structured error types
//! - [`input`] - File input abstraction
//! - [`hasher`] - BLAKE3-based file hashing
//! - [`result`] - Scan result structures

pub mod error;
pub mod hasher;
pub mod input;
pub mod result;
pub mod traits;
pub mod types;

// Re-export commonly used types at the core level
pub use error::{PolicyError, QuarantineError, ScanError};
pub use hasher::FileHasher;
pub use input::FileInput;
pub use result::{ScanReport, ScanResult};
pub use traits::{ArcScanner, BoxedScanner, DefaultScannerConfig, Scanner, ScannerConfig};
pub use types::{FileHash, FileMetadata, ScanContext, ScanOutcome, ThreatInfo, ThreatSeverity};
