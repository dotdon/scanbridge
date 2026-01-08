//! Audit event types and emission functions.

use crate::core::{FileHash, ScanContext, ScanOutcome, ScanReport, ScanResult, ThreatInfo};
use crate::policy::PolicyDecision;
use crate::quarantine::QuarantineRecord;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Base trait for audit events.
pub trait AuditEvent: Serialize {
    /// Returns the event type name.
    fn event_type(&self) -> &'static str;

    /// Returns the timestamp of the event.
    fn timestamp(&self) -> DateTime<Utc>;
}

/// Audit event for a completed scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAuditEvent {
    /// Event type.
    pub event_type: String,

    /// Timestamp of the event.
    pub timestamp: DateTime<Utc>,

    /// Unique scan ID.
    pub scan_id: String,

    /// File hash (BLAKE3).
    pub file_hash_blake3: String,

    /// File hash (SHA256, if available).
    pub file_hash_sha256: Option<String>,

    /// Scan outcome.
    pub outcome: String,

    /// Engine that performed the scan.
    pub engine: String,

    /// Scan duration in milliseconds.
    pub duration_ms: u64,

    /// Tenant ID, if multi-tenant.
    pub tenant_id: Option<String>,

    /// User ID, if available.
    pub user_id: Option<String>,

    /// Request ID, if available.
    pub request_id: Option<String>,

    /// Detected threats, if any.
    pub threats: Vec<ThreatSummary>,

    /// Whether the result was cached.
    pub cached: bool,
}

/// Summary of a detected threat for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSummary {
    /// Name of the threat.
    pub name: String,
    /// Severity level.
    pub severity: String,
    /// Detection engine.
    pub engine: String,
}

impl From<&ThreatInfo> for ThreatSummary {
    fn from(t: &ThreatInfo) -> Self {
        Self {
            name: t.name.clone(),
            severity: t.severity.to_string(),
            engine: t.engine.clone(),
        }
    }
}

/// Audit event for a policy decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAuditEvent {
    /// Event type.
    pub event_type: String,

    /// Timestamp of the event.
    pub timestamp: DateTime<Utc>,

    /// File hash.
    pub file_hash_blake3: String,

    /// The action taken.
    pub action: String,

    /// ID of the matched rule.
    pub matched_rule_id: Option<String>,

    /// Name of the matched rule.
    pub matched_rule_name: Option<String>,

    /// Tenant ID.
    pub tenant_id: Option<String>,

    /// Reason for the decision.
    pub reason: Option<String>,
}

/// Audit event for a quarantine operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineAuditEvent {
    /// Event type.
    pub event_type: String,

    /// Timestamp of the event.
    pub timestamp: DateTime<Utc>,

    /// Quarantine ID.
    pub quarantine_id: String,

    /// File hash.
    pub file_hash_blake3: String,

    /// Operation performed.
    pub operation: String,

    /// Reason for quarantine.
    pub reason: Option<String>,

    /// Tenant ID.
    pub tenant_id: Option<String>,
}

/// Emits an audit event for a scan starting.
pub fn emit_scan_started(
    scan_id: &str,
    file_hash: &FileHash,
    context: &ScanContext,
) {
    tracing::info!(
        target: "scanbridge::audit",
        event_type = "scan_started",
        scan_id = %scan_id,
        file_hash_blake3 = %file_hash.blake3,
        file_hash_sha256 = ?file_hash.sha256,
        tenant_id = ?context.tenant_id,
        user_id = ?context.user_id,
        request_id = ?context.request_id,
        source = ?context.source,
        "Scan started"
    );
}

/// Emits an audit event for a completed scan.
pub fn emit_scan_completed(result: &ScanResult) {
    let outcome_str = match &result.outcome {
        ScanOutcome::Clean => "clean",
        ScanOutcome::Infected { .. } => "infected",
        ScanOutcome::Suspicious { .. } => "suspicious",
        ScanOutcome::Error { .. } => "error",
    };

    let threats: Vec<ThreatSummary> = result
        .threats()
        .map(|t| t.iter().map(ThreatSummary::from).collect())
        .unwrap_or_default();

    tracing::info!(
        target: "scanbridge::audit",
        event_type = "scan_completed",
        scan_id = %result.id,
        file_hash_blake3 = %result.file_metadata.hash.blake3,
        file_hash_sha256 = ?result.file_metadata.hash.sha256,
        outcome = %outcome_str,
        engine = %result.engine,
        duration_ms = result.duration.as_millis() as u64,
        tenant_id = ?result.context.tenant_id,
        user_id = ?result.context.user_id,
        request_id = ?result.context.request_id,
        threats = ?threats,
        cached = result.cached,
        "Scan completed"
    );
}

/// Emits an audit event for a scan report (aggregated results).
pub fn emit_scan_report(report: &ScanReport) {
    let outcome_str = match &report.aggregated_outcome {
        ScanOutcome::Clean => "clean",
        ScanOutcome::Infected { .. } => "infected",
        ScanOutcome::Suspicious { .. } => "suspicious",
        ScanOutcome::Error { .. } => "error",
    };

    let threats: Vec<ThreatSummary> = report
        .all_threats()
        .iter()
        .map(|&t| ThreatSummary::from(t))
        .collect();

    let engines: Vec<&str> = report.results.iter().map(|r| r.engine.as_str()).collect();

    tracing::info!(
        target: "scanbridge::audit",
        event_type = "scan_report",
        report_id = %report.id,
        file_hash_blake3 = %report.file_hash.blake3,
        file_hash_sha256 = ?report.file_hash.sha256,
        aggregated_outcome = %outcome_str,
        engines = ?engines,
        engine_count = report.engine_count(),
        total_duration_ms = report.total_duration.as_millis() as u64,
        tenant_id = ?report.context.tenant_id,
        user_id = ?report.context.user_id,
        threats = ?threats,
        threat_count = threats.len(),
        "Scan report generated"
    );
}

/// Emits an audit event for a policy decision.
pub fn emit_policy_decision(decision: &PolicyDecision, file_hash: &FileHash, context: &ScanContext) {
    let action_str = match &decision.action {
        crate::policy::PolicyAction::Allow => "allow",
        crate::policy::PolicyAction::AllowWithWarning { .. } => "allow_with_warning",
        crate::policy::PolicyAction::Quarantine { .. } => "quarantine",
        crate::policy::PolicyAction::Block { .. } => "block",
        crate::policy::PolicyAction::RequireManualReview => "require_manual_review",
    };

    tracing::info!(
        target: "scanbridge::audit",
        event_type = "policy_decision",
        file_hash_blake3 = %file_hash.blake3,
        action = %action_str,
        matched_rule_id = ?decision.matched_rule_id,
        matched_rule_name = ?decision.matched_rule_name,
        reason = ?decision.reason,
        tenant_id = ?context.tenant_id,
        user_id = ?context.user_id,
        "Policy decision made"
    );
}

/// Emits an audit event for a quarantine operation.
pub fn emit_quarantine_event(record: &QuarantineRecord, operation: &str) {
    tracing::info!(
        target: "scanbridge::audit",
        event_type = "quarantine_operation",
        quarantine_id = %record.id,
        file_hash_blake3 = %record.file_hash.blake3,
        operation = %operation,
        reason = %record.reason,
        tenant_id = ?record.tenant_id,
        original_filename = ?record.original_filename,
        file_size = record.file_size,
        "Quarantine operation performed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ThreatSeverity;

    #[test]
    fn test_threat_summary_from() {
        let threat = ThreatInfo::new("Test.Malware", ThreatSeverity::High, "test-engine");
        let summary = ThreatSummary::from(&threat);

        assert_eq!(summary.name, "Test.Malware");
        assert_eq!(summary.severity, "high");
        assert_eq!(summary.engine, "test-engine");
    }
}
