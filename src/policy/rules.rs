//! Policy rules and conditions.

use crate::core::{ScanContext, ScanOutcome, ScanReport, ThreatSeverity};
use crate::policy::action::PolicyAction;

use serde::{Deserialize, Serialize};

/// A policy rule that matches certain conditions and produces an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique identifier for this rule.
    pub id: String,

    /// Human-readable name for the rule.
    pub name: String,

    /// Description of what this rule does.
    pub description: Option<String>,

    /// Conditions that must all match for this rule to apply.
    pub conditions: Vec<Condition>,

    /// Action to take when all conditions match.
    pub action: PolicyAction,

    /// Priority of the rule (higher = evaluated first).
    pub priority: i32,

    /// Whether this rule is enabled.
    pub enabled: bool,
}

impl PolicyRule {
    /// Creates a new policy rule.
    pub fn new(id: impl Into<String>, action: PolicyAction) -> Self {
        Self {
            id: id.into(),
            name: String::new(),
            description: None,
            conditions: Vec::new(),
            action,
            priority: 0,
            enabled: true,
        }
    }

    /// Sets the name of the rule.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Adds a condition.
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Sets the priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Enables or disables the rule.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Evaluates whether this rule matches the given report and context.
    pub fn matches(&self, report: &ScanReport, context: &ScanContext) -> bool {
        if !self.enabled {
            return false;
        }

        // All conditions must match
        self.conditions.iter().all(|c| c.matches(report, context))
    }
}

/// A condition that can be evaluated against a scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Matches if the outcome is of a specific type.
    OutcomeIs {
        /// The outcome type to match.
        outcome: OutcomeType,
    },

    /// Matches if the tenant ID equals the specified value.
    TenantEquals {
        /// The tenant ID to match.
        tenant_id: String,
    },

    /// Matches if the tenant ID is in the specified list.
    TenantIn {
        /// List of tenant IDs to match.
        tenant_ids: Vec<String>,
    },

    /// Matches if the file type is in the specified list.
    FileTypeIn {
        /// List of file extensions or MIME types.
        file_types: Vec<String>,
    },

    /// Matches if the maximum threat severity is at least the specified level.
    SeverityAtLeast {
        /// Minimum severity to match.
        severity: ThreatSeverity,
    },

    /// Matches if the file size exceeds the specified value.
    FileSizeExceeds {
        /// Size in bytes.
        size: u64,
    },

    /// Matches if the file size is below the specified value.
    FileSizeBelow {
        /// Size in bytes.
        size: u64,
    },

    /// Matches if any threat name contains the specified substring.
    ThreatNameContains {
        /// Substring to search for.
        substring: String,
    },

    /// Matches if the source equals the specified value.
    SourceEquals {
        /// Source to match (e.g., "upload", "email").
        source: String,
    },

    /// Always matches.
    Always,

    /// Never matches.
    Never,

    /// Logical AND of multiple conditions.
    And {
        /// Conditions that must all match.
        conditions: Vec<Condition>,
    },

    /// Logical OR of multiple conditions.
    Or {
        /// Conditions where at least one must match.
        conditions: Vec<Condition>,
    },

    /// Logical NOT of a condition.
    Not {
        /// Condition to negate.
        condition: Box<Condition>,
    },
}

/// Simplified outcome type for matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeType {
    /// File is clean.
    Clean,
    /// File is infected.
    Infected,
    /// File is suspicious.
    Suspicious,
    /// An error occurred.
    Error,
}

impl Condition {
    /// Creates a condition that matches clean files.
    pub fn is_clean() -> Self {
        Self::OutcomeIs {
            outcome: OutcomeType::Clean,
        }
    }

    /// Creates a condition that matches infected files.
    pub fn is_infected() -> Self {
        Self::OutcomeIs {
            outcome: OutcomeType::Infected,
        }
    }

    /// Creates a condition that matches suspicious files.
    pub fn is_suspicious() -> Self {
        Self::OutcomeIs {
            outcome: OutcomeType::Suspicious,
        }
    }

    /// Creates a condition that matches errors.
    pub fn is_error() -> Self {
        Self::OutcomeIs {
            outcome: OutcomeType::Error,
        }
    }

    /// Creates a condition that matches a specific tenant.
    pub fn tenant_equals(tenant_id: impl Into<String>) -> Self {
        Self::TenantEquals {
            tenant_id: tenant_id.into(),
        }
    }

    /// Creates a condition that matches specific file types.
    pub fn file_type_in(types: Vec<String>) -> Self {
        Self::FileTypeIn { file_types: types }
    }

    /// Creates a condition that matches severity at or above the given level.
    pub fn severity_at_least(severity: ThreatSeverity) -> Self {
        Self::SeverityAtLeast { severity }
    }

    /// Evaluates this condition against the given report and context.
    pub fn matches(&self, report: &ScanReport, context: &ScanContext) -> bool {
        match self {
            Self::OutcomeIs { outcome } => {
                let report_outcome = match &report.aggregated_outcome {
                    ScanOutcome::Clean => OutcomeType::Clean,
                    ScanOutcome::Infected { .. } => OutcomeType::Infected,
                    ScanOutcome::Suspicious { .. } => OutcomeType::Suspicious,
                    ScanOutcome::Error { .. } => OutcomeType::Error,
                };
                *outcome == report_outcome
            }

            Self::TenantEquals { tenant_id } => {
                context.tenant_id.as_ref() == Some(tenant_id)
            }

            Self::TenantIn { tenant_ids } => {
                context
                    .tenant_id
                    .as_ref()
                    .map(|t| tenant_ids.contains(t))
                    .unwrap_or(false)
            }

            Self::FileTypeIn { file_types } => {
                // Check against file extension or MIME type
                report
                    .results
                    .first()
                    .and_then(|r| r.file_metadata.filename.as_ref())
                    .and_then(|f| f.rsplit('.').next())
                    .map(|ext| file_types.iter().any(|t| t.eq_ignore_ascii_case(ext)))
                    .unwrap_or(false)
            }

            Self::SeverityAtLeast { severity } => {
                report.all_threats().iter().any(|t| t.severity >= *severity)
            }

            Self::FileSizeExceeds { size } => {
                report
                    .results
                    .first()
                    .map(|r| r.file_metadata.size > *size)
                    .unwrap_or(false)
            }

            Self::FileSizeBelow { size } => {
                report
                    .results
                    .first()
                    .map(|r| r.file_metadata.size < *size)
                    .unwrap_or(false)
            }

            Self::ThreatNameContains { substring } => {
                let lower = substring.to_lowercase();
                report
                    .all_threats()
                    .iter()
                    .any(|t| t.name.to_lowercase().contains(&lower))
            }

            Self::SourceEquals { source } => context.source.as_ref() == Some(source),

            Self::Always => true,

            Self::Never => false,

            Self::And { conditions } => conditions.iter().all(|c| c.matches(report, context)),

            Self::Or { conditions } => conditions.iter().any(|c| c.matches(report, context)),

            Self::Not { condition } => !condition.matches(report, context),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FileHash, FileMetadata, ScanResult, ThreatInfo};
    use std::time::Duration;

    fn make_test_report(outcome: ScanOutcome) -> ScanReport {
        let hash = FileHash::new("test");
        let metadata = FileMetadata::new(1000, hash);
        let result = ScanResult::new(
            outcome,
            metadata,
            "test",
            Duration::from_millis(10),
            ScanContext::new(),
        );
        ScanReport::from_results(vec![result], ScanContext::new())
    }

    #[test]
    fn test_condition_is_clean() {
        let report = make_test_report(ScanOutcome::Clean);
        let context = ScanContext::new();

        assert!(Condition::is_clean().matches(&report, &context));
        assert!(!Condition::is_infected().matches(&report, &context));
    }

    #[test]
    fn test_condition_is_infected() {
        let threats = vec![ThreatInfo::new("Test", ThreatSeverity::High, "test")];
        let report = make_test_report(ScanOutcome::Infected { threats });
        let context = ScanContext::new();

        assert!(Condition::is_infected().matches(&report, &context));
        assert!(!Condition::is_clean().matches(&report, &context));
    }

    #[test]
    fn test_condition_tenant_equals() {
        let report = make_test_report(ScanOutcome::Clean);
        let context = ScanContext::new().with_tenant_id("tenant-1");

        assert!(Condition::tenant_equals("tenant-1").matches(&report, &context));
        assert!(!Condition::tenant_equals("tenant-2").matches(&report, &context));
    }

    #[test]
    fn test_policy_rule_matches() {
        let rule = PolicyRule::new("test-rule", PolicyAction::block("infected"))
            .with_condition(Condition::is_infected());

        let threats = vec![ThreatInfo::new("Test", ThreatSeverity::High, "test")];
        let report = make_test_report(ScanOutcome::Infected { threats });
        let context = ScanContext::new();

        assert!(rule.matches(&report, &context));
    }
}
