//! Quarantine storage for infected files.
//!
//! This module provides a trait-based abstraction for quarantine storage,
//! allowing infected files to be safely stored and tracked.

mod filesystem;
mod record;
mod traits;

pub use filesystem::FilesystemQuarantine;
pub use record::{QuarantineFilter, QuarantineId, QuarantineRecord};
pub use traits::{NoOpQuarantineStore, QuarantineStore};
