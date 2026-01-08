//! Scan result structures.
//!
//! This module defines `ScanResult` and related types that represent
//! the outcome of a scanning operation, including metadata about
//! which engine was used and how long the scan took.

use crate::core::types::{FileHash, FileMetadata, ScanContext, ScanOutcome, ThreatInfo};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The complete result of a scan operation.
///
/// This structure contains all information about a completed scan,
/// including the outcome, metadata, timing, and engine information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique identifier for this scan result.
    pub id: String,

    /// The outcome of the scan.
    pub outcome: ScanOutcome,

    /// Metadata about the scanned file.
    pub file_metadata: FileMetadata,

    /// Name of the engine that performed the scan.
    pub engine: String,

    /// Version of the engine's signature database, if available.
    pub engine_version: Option<String>,

    /// When the scan started.
    pub started_at: DateTime<Utc>,

    /// When the scan completed.
    pub completed_at: DateTime<Utc>,

    /// How long the scan took.
    #[serde(with = "duration_serde")]
    pub duration: Duration,

    /// The context in which the scan was requested.
    pub context: ScanContext,

    /// Whether this result came from a cache.
    pub cached: bool,

    /// Additional engine-specific details.
    #[serde(default)]
    pub details: std::collections::HashMap<String, serde_json::Value>,
}

impl ScanResult {
    /// Creates a new `ScanResult` with the given outcome.
    pub fn new(
        outcome: ScanOutcome,
        file_metadata: FileMetadata,
        engine: impl Into<String>,
        duration: Duration,
        context: ScanContext,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            outcome,
            file_metadata,
            engine: engine.into(),
            engine_version: None,
            started_at: now - chrono::Duration::from_std(duration).unwrap_or_default(),
            completed_at: now,
            duration,
            context,
            cached: false,
            details: std::collections::HashMap::new(),
        }
    }

    /// Returns `true` if the file is clean.
    pub fn is_clean(&self) -> bool {
        self.outcome.is_clean()
    }

    /// Returns `true` if the file is infected.
    pub fn is_infected(&self) -> bool {
        self.outcome.is_infected()
    }

    /// Returns the threats if infected.
    pub fn threats(&self) -> Option<&[ThreatInfo]> {
        match &self.outcome {
            ScanOutcome::Infected { threats } => Some(threats),
            _ => None,
        }
    }

    /// Returns the file hash.
    pub fn file_hash(&self) -> &FileHash {
        &self.file_metadata.hash
    }

    /// Sets the engine version.
    pub fn with_engine_version(mut self, version: impl Into<String>) -> Self {
        self.engine_version = Some(version.into());
        self
    }

    /// Marks this result as cached.
    pub fn with_cached(mut self, cached: bool) -> Self {
        self.cached = cached;
        self
    }

    /// Adds a detail entry.
    pub fn with_detail(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.details.insert(key.into(), value);
        self
    }
}

/// A report combining results from multiple scan engines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Unique identifier for this report.
    pub id: String,

    /// Individual results from each engine.
    pub results: Vec<ScanResult>,

    /// The aggregated outcome (worst case from all engines).
    pub aggregated_outcome: ScanOutcome,

    /// File hash (consistent across all results).
    pub file_hash: FileHash,

    /// When the scan was requested.
    pub requested_at: DateTime<Utc>,

    /// When the scan completed.
    pub completed_at: DateTime<Utc>,

    /// Total duration including all engines.
    #[serde(with = "duration_serde")]
    pub total_duration: Duration,

    /// The context in which the scan was requested.
    pub context: ScanContext,
}

impl ScanReport {
    /// Creates a new `ScanReport` from multiple results.
    pub fn from_results(results: Vec<ScanResult>, context: ScanContext) -> Self {
        let now = Utc::now();
        let aggregated_outcome = aggregate_outcomes(results.iter().map(|r| &r.outcome));
        let file_hash = results
            .first()
            .map(|r| r.file_metadata.hash.clone())
            .unwrap_or_else(|| FileHash::new("unknown"));

        let total_duration = results.iter().map(|r| r.duration).sum();

        let requested_at = results
            .iter()
            .map(|r| r.started_at)
            .min()
            .unwrap_or(now);

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            results,
            aggregated_outcome,
            file_hash,
            requested_at,
            completed_at: now,
            total_duration,
            context,
        }
    }

    /// Returns `true` if all engines reported clean.
    pub fn is_clean(&self) -> bool {
        self.aggregated_outcome.is_clean()
    }

    /// Returns `true` if any engine reported infected.
    pub fn is_infected(&self) -> bool {
        self.aggregated_outcome.is_infected()
    }

    /// Returns all detected threats from all engines.
    pub fn all_threats(&self) -> Vec<&ThreatInfo> {
        self.results
            .iter()
            .filter_map(|r| r.threats())
            .flatten()
            .collect()
    }

    /// Returns the engines that detected threats.
    pub fn detecting_engines(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter(|r| r.is_infected())
            .map(|r| r.engine.as_str())
            .collect()
    }

    /// Returns the number of engines that participated in the scan.
    pub fn engine_count(&self) -> usize {
        self.results.len()
    }
}

/// Aggregates multiple outcomes into a single worst-case outcome.
fn aggregate_outcomes<'a>(outcomes: impl Iterator<Item = &'a ScanOutcome>) -> ScanOutcome {
    let mut has_error = false;
    let mut has_infected = false;
    let mut all_threats = Vec::new();
    let mut has_suspicious = false;
    let mut suspicious_reason = String::new();
    let mut suspicious_confidence = 0.0f32;

    for outcome in outcomes {
        match outcome {
            ScanOutcome::Error { recoverable: false } => {
                return ScanOutcome::Error { recoverable: false };
            }
            ScanOutcome::Error { .. } => has_error = true,
            ScanOutcome::Infected { threats } => {
                has_infected = true;
                all_threats.extend(threats.clone());
            }
            ScanOutcome::Suspicious { reason, confidence } => {
                has_suspicious = true;
                if *confidence > suspicious_confidence {
                    suspicious_confidence = *confidence;
                    suspicious_reason = reason.clone();
                }
            }
            ScanOutcome::Clean => {}
        }
    }

    if has_infected {
        ScanOutcome::Infected {
            threats: all_threats,
        }
    } else if has_suspicious {
        ScanOutcome::Suspicious {
            reason: suspicious_reason,
            confidence: suspicious_confidence,
        }
    } else if has_error {
        ScanOutcome::Error { recoverable: true }
    } else {
        ScanOutcome::Clean
    }
}

/// Serde helper for Duration serialization.
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::ThreatSeverity;

    #[test]
    fn test_scan_result_creation() {
        let hash = FileHash::new("abc123");
        let metadata = FileMetadata::new(1000, hash);
        let context = ScanContext::new().with_tenant_id("test");

        let result = ScanResult::new(
            ScanOutcome::Clean,
            metadata,
            "test-engine",
            Duration::from_millis(100),
            context,
        );

        assert!(result.is_clean());
        assert!(!result.is_infected());
        assert!(result.threats().is_none());
    }

    #[test]
    fn test_scan_result_infected() {
        let hash = FileHash::new("abc123");
        let metadata = FileMetadata::new(1000, hash);
        let context = ScanContext::new();

        let threats = vec![ThreatInfo::new("Test.Malware", ThreatSeverity::High, "test")];
        let result = ScanResult::new(
            ScanOutcome::Infected {
                threats: threats.clone(),
            },
            metadata,
            "test-engine",
            Duration::from_millis(100),
            context,
        );

        assert!(!result.is_clean());
        assert!(result.is_infected());
        assert_eq!(result.threats().unwrap().len(), 1);
    }

    #[test]
    fn test_aggregate_outcomes() {
        let outcomes = vec![ScanOutcome::Clean, ScanOutcome::Clean];
        assert!(aggregate_outcomes(outcomes.iter()).is_clean());

        let outcomes = vec![
            ScanOutcome::Clean,
            ScanOutcome::Infected {
                threats: vec![ThreatInfo::new("Test", ThreatSeverity::High, "engine")],
            },
        ];
        assert!(aggregate_outcomes(outcomes.iter()).is_infected());
    }
}
