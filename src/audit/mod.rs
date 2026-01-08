//! Structured audit logging for compliance environments.
//!
//! This module provides functions for emitting structured audit events
//! using the `tracing` crate. Events can be captured by any tracing
//! subscriber (JSON file, OpenTelemetry, etc.) for tamper-resistant logging.

mod events;

pub use events::{
    emit_policy_decision, emit_quarantine_event, emit_scan_completed, emit_scan_report,
    emit_scan_started, AuditEvent, PolicyAuditEvent, QuarantineAuditEvent, ScanAuditEvent,
};
