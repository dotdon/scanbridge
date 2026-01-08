//! Quarantine record types.

use crate::core::{FileHash, ScanResult};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Unique identifier for a quarantined file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuarantineId(pub String);

impl QuarantineId {
    /// Creates a new random quarantine ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Creates a quarantine ID from a string.
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for QuarantineId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for QuarantineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for QuarantineId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for QuarantineId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Metadata about a quarantined file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// Unique identifier for this quarantine record.
    pub id: QuarantineId,

    /// Original path of the file, if known.
    pub original_path: Option<PathBuf>,

    /// Original filename.
    pub original_filename: Option<String>,

    /// Hash of the file.
    pub file_hash: FileHash,

    /// Size of the file in bytes.
    pub file_size: u64,

    /// When the file was quarantined.
    pub quarantined_at: DateTime<Utc>,

    /// Reason for quarantine.
    pub reason: String,

    /// The scan result that triggered quarantine.
    pub scan_result: ScanResult,

    /// Tenant ID, for multi-tenant systems.
    pub tenant_id: Option<String>,

    /// When the quarantine record expires (for auto-cleanup).
    pub expires_at: Option<DateTime<Utc>>,

    /// Additional metadata.
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

impl QuarantineRecord {
    /// Creates a new quarantine record.
    pub fn new(
        file_hash: FileHash,
        file_size: u64,
        reason: impl Into<String>,
        scan_result: ScanResult,
    ) -> Self {
        Self {
            id: QuarantineId::new(),
            original_path: None,
            original_filename: None,
            file_hash,
            file_size,
            quarantined_at: Utc::now(),
            reason: reason.into(),
            scan_result,
            tenant_id: None,
            expires_at: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Sets the original path.
    pub fn with_original_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.original_path = Some(path.into());
        self
    }

    /// Sets the original filename.
    pub fn with_original_filename(mut self, filename: impl Into<String>) -> Self {
        self.original_filename = Some(filename.into());
        self
    }

    /// Sets the tenant ID.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets the expiration time.
    pub fn with_expires_at(mut self, expires: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires);
        self
    }

    /// Adds metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Returns true if this record has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
    }
}

/// Filter for listing quarantine records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineFilter {
    /// Filter by tenant ID.
    pub tenant_id: Option<String>,

    /// Filter by file hash.
    pub file_hash: Option<String>,

    /// Filter by minimum quarantine date.
    pub quarantined_after: Option<DateTime<Utc>>,

    /// Filter by maximum quarantine date.
    pub quarantined_before: Option<DateTime<Utc>>,

    /// Maximum number of records to return.
    pub limit: Option<usize>,

    /// Offset for pagination.
    pub offset: Option<usize>,

    /// Include expired records.
    pub include_expired: bool,
}

impl QuarantineFilter {
    /// Creates a new empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by tenant ID.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Filters by file hash.
    pub fn with_file_hash(mut self, hash: impl Into<String>) -> Self {
        self.file_hash = Some(hash.into());
        self
    }

    /// Filters by date range.
    pub fn with_date_range(
        mut self,
        after: Option<DateTime<Utc>>,
        before: Option<DateTime<Utc>>,
    ) -> Self {
        self.quarantined_after = after;
        self.quarantined_before = before;
        self
    }

    /// Sets pagination.
    pub fn with_pagination(mut self, limit: usize, offset: usize) -> Self {
        self.limit = Some(limit);
        self.offset = Some(offset);
        self
    }

    /// Includes or excludes expired records.
    pub fn with_include_expired(mut self, include: bool) -> Self {
        self.include_expired = include;
        self
    }

    /// Checks if a record matches this filter.
    pub fn matches(&self, record: &QuarantineRecord) -> bool {
        if let Some(ref tenant_id) = self.tenant_id {
            if record.tenant_id.as_ref() != Some(tenant_id) {
                return false;
            }
        }

        if let Some(ref hash) = self.file_hash {
            if &record.file_hash.blake3 != hash {
                return false;
            }
        }

        if let Some(after) = self.quarantined_after {
            if record.quarantined_at < after {
                return false;
            }
        }

        if let Some(before) = self.quarantined_before {
            if record.quarantined_at > before {
                return false;
            }
        }

        if !self.include_expired && record.is_expired() {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FileMetadata, ScanContext, ScanOutcome};
    use std::time::Duration;

    fn make_test_record() -> QuarantineRecord {
        let hash = FileHash::new("test-hash");
        let metadata = FileMetadata::new(1000, hash.clone());
        let result = ScanResult::new(
            ScanOutcome::Infected {
                threats: vec![],
            },
            metadata,
            "test",
            Duration::from_millis(10),
            ScanContext::new(),
        );

        QuarantineRecord::new(hash, 1000, "test reason", result)
    }

    #[test]
    fn test_quarantine_id() {
        let id1 = QuarantineId::new();
        let id2 = QuarantineId::new();
        assert_ne!(id1, id2);

        let id3 = QuarantineId::from_string("custom-id");
        assert_eq!(id3.as_str(), "custom-id");
    }

    #[test]
    fn test_quarantine_record() {
        let record = make_test_record()
            .with_original_filename("test.exe")
            .with_tenant_id("tenant-1");

        assert_eq!(record.original_filename, Some("test.exe".to_string()));
        assert_eq!(record.tenant_id, Some("tenant-1".to_string()));
        assert!(!record.is_expired());
    }

    #[test]
    fn test_quarantine_filter() {
        let record = make_test_record().with_tenant_id("tenant-1");

        let filter = QuarantineFilter::new().with_tenant_id("tenant-1");
        assert!(filter.matches(&record));

        let filter = QuarantineFilter::new().with_tenant_id("tenant-2");
        assert!(!filter.matches(&record));
    }
}
