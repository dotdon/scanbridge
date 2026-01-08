//! Core types used throughout the scanbridge library.
//!
//! This module defines the fundamental data structures for representing
//! scan outcomes, threat information, file hashes, and severity levels.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The outcome of a malware scan operation.
///
/// This enum represents the four possible states after scanning a file:
/// - `Clean`: No threats detected
/// - `Infected`: One or more threats found
/// - `Suspicious`: Potentially harmful but not definitively malicious
/// - `Error`: Scan could not complete properly
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanOutcome {
    /// The file is clean; no threats were detected.
    Clean,

    /// The file is infected with one or more threats.
    Infected {
        /// List of detected threats.
        threats: Vec<ThreatInfo>,
    },

    /// The file is suspicious but not definitively malicious.
    Suspicious {
        /// Human-readable reason for suspicion.
        reason: String,
        /// Confidence level (0.0 to 1.0) in the suspicion.
        confidence: f32,
    },

    /// An error occurred during scanning.
    Error {
        /// Whether this error is recoverable (can be retried).
        recoverable: bool,
    },
}

impl ScanOutcome {
    /// Returns `true` if the outcome indicates a clean file.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }

    /// Returns `true` if the outcome indicates an infected file.
    pub fn is_infected(&self) -> bool {
        matches!(self, Self::Infected { .. })
    }

    /// Returns `true` if the outcome indicates a suspicious file.
    pub fn is_suspicious(&self) -> bool {
        matches!(self, Self::Suspicious { .. })
    }

    /// Returns `true` if the outcome indicates an error occurred.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// Returns `true` if the file should be blocked based on outcome.
    pub fn should_block(&self) -> bool {
        matches!(self, Self::Infected { .. } | Self::Error { recoverable: false })
    }
}

/// Severity level of a detected threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatSeverity {
    /// Low severity - potentially unwanted programs, adware.
    Low,
    /// Medium severity - suspicious behavior, minor malware.
    Medium,
    /// High severity - confirmed malware, ransomware, trojans.
    High,
    /// Critical severity - severe threats requiring immediate action.
    Critical,
}

impl ThreatSeverity {
    /// Returns the severity as a numeric score (0-100).
    pub fn score(&self) -> u8 {
        match self {
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 75,
            Self::Critical => 100,
        }
    }
}

impl fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Information about a detected threat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatInfo {
    /// Human-readable name of the threat (e.g., "Trojan.GenericKD.12345").
    pub name: String,

    /// Optional signature identifier from the scanning engine.
    pub signature_id: Option<String>,

    /// Severity level of the threat.
    pub severity: ThreatSeverity,

    /// Name of the engine that detected this threat.
    pub engine: String,

    /// Optional category of the threat (e.g., "trojan", "ransomware", "pup").
    pub category: Option<String>,

    /// Optional description with more details about the threat.
    pub description: Option<String>,
}

impl ThreatInfo {
    /// Creates a new `ThreatInfo` with required fields.
    pub fn new(name: impl Into<String>, severity: ThreatSeverity, engine: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            signature_id: None,
            severity,
            engine: engine.into(),
            category: None,
            description: None,
        }
    }

    /// Sets the signature ID.
    pub fn with_signature_id(mut self, id: impl Into<String>) -> Self {
        self.signature_id = Some(id.into());
        self
    }

    /// Sets the category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// File hash information using multiple algorithms.
///
/// BLAKE3 is the primary hash used for deduplication due to its speed.
/// SHA256 and MD5 are optional and provided for compatibility with
/// external systems like VirusTotal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileHash {
    /// BLAKE3 hash (always computed, primary hash for deduplication).
    pub blake3: String,

    /// SHA256 hash (optional, for external API compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// MD5 hash (optional, for legacy system compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
}

impl FileHash {
    /// Creates a new `FileHash` with only BLAKE3.
    pub fn new(blake3: impl Into<String>) -> Self {
        Self {
            blake3: blake3.into(),
            sha256: None,
            md5: None,
        }
    }

    /// Sets the SHA256 hash.
    pub fn with_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.sha256 = Some(sha256.into());
        self
    }

    /// Sets the MD5 hash.
    pub fn with_md5(mut self, md5: impl Into<String>) -> Self {
        self.md5 = Some(md5.into());
        self
    }

    /// Returns the primary hash (BLAKE3) for deduplication.
    pub fn primary(&self) -> &str {
        &self.blake3
    }
}

impl fmt::Display for FileHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake3:{}", self.blake3)
    }
}

/// Metadata about a file being scanned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Original filename, if known.
    pub filename: Option<String>,

    /// MIME type, if detected.
    pub mime_type: Option<String>,

    /// File size in bytes.
    pub size: u64,

    /// File hash information.
    pub hash: FileHash,

    /// When the file was received for scanning.
    pub received_at: DateTime<Utc>,
}

impl FileMetadata {
    /// Creates new file metadata with required fields.
    pub fn new(size: u64, hash: FileHash) -> Self {
        Self {
            filename: None,
            mime_type: None,
            size,
            hash,
            received_at: Utc::now(),
        }
    }

    /// Sets the filename.
    pub fn with_filename(mut self, filename: impl Into<String>) -> Self {
        self.filename = Some(filename.into());
        self
    }

    /// Sets the MIME type.
    pub fn with_mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.mime_type = Some(mime_type.into());
        self
    }
}

/// Context information for a scan request.
///
/// This carries metadata about who requested the scan and why,
/// useful for policy decisions and audit logging.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanContext {
    /// Tenant identifier for multi-tenant systems.
    pub tenant_id: Option<String>,

    /// User identifier who initiated the upload/scan.
    pub user_id: Option<String>,

    /// Request or correlation ID for tracing.
    pub request_id: Option<String>,

    /// Source of the file (e.g., "upload", "email", "api").
    pub source: Option<String>,

    /// Additional custom metadata as key-value pairs.
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

impl ScanContext {
    /// Creates a new empty scan context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the tenant ID.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets the user ID.
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Sets the request ID.
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Sets the source.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Adds a custom metadata entry.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_outcome_is_methods() {
        assert!(ScanOutcome::Clean.is_clean());
        assert!(!ScanOutcome::Clean.is_infected());

        let infected = ScanOutcome::Infected {
            threats: vec![ThreatInfo::new("Test.Malware", ThreatSeverity::High, "test")],
        };
        assert!(infected.is_infected());
        assert!(infected.should_block());

        let suspicious = ScanOutcome::Suspicious {
            reason: "Heuristic match".into(),
            confidence: 0.7,
        };
        assert!(suspicious.is_suspicious());
    }

    #[test]
    fn test_threat_severity_ordering() {
        assert!(ThreatSeverity::Low < ThreatSeverity::Medium);
        assert!(ThreatSeverity::Medium < ThreatSeverity::High);
        assert!(ThreatSeverity::High < ThreatSeverity::Critical);
    }

    #[test]
    fn test_file_hash_display() {
        let hash = FileHash::new("abc123").with_sha256("def456");
        assert_eq!(format!("{}", hash), "blake3:abc123");
    }

    #[test]
    fn test_scan_context_builder() {
        let ctx = ScanContext::new()
            .with_tenant_id("tenant-1")
            .with_user_id("user-42")
            .with_metadata("env", "production");

        assert_eq!(ctx.tenant_id, Some("tenant-1".into()));
        assert_eq!(ctx.user_id, Some("user-42".into()));
        assert_eq!(ctx.metadata.get("env"), Some(&"production".to_string()));
    }
}
