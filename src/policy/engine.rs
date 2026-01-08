//! Policy engine implementation.

use crate::core::{ScanContext, ScanReport};
use crate::policy::action::PolicyAction;
use crate::policy::rules::{Condition, PolicyRule};

use serde::{Deserialize, Serialize};

/// The result of policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// The action to take.
    pub action: PolicyAction,

    /// ID of the rule that matched, if any.
    pub matched_rule_id: Option<String>,

    /// Name of the rule that matched, if any.
    pub matched_rule_name: Option<String>,

    /// Additional context about the decision.
    pub reason: Option<String>,
}

impl PolicyDecision {
    /// Creates a new policy decision.
    pub fn new(action: PolicyAction) -> Self {
        Self {
            action,
            matched_rule_id: None,
            matched_rule_name: None,
            reason: None,
        }
    }

    /// Sets the matched rule ID.
    pub fn with_rule(mut self, rule: &PolicyRule) -> Self {
        self.matched_rule_id = Some(rule.id.clone());
        self.matched_rule_name = Some(rule.name.clone());
        self
    }

    /// Sets the reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Configuration for the policy engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyEngineConfig {
    /// Default action when no rules match.
    pub default_action: PolicyAction,

    /// Whether to stop at the first matching rule.
    pub first_match_wins: bool,
}

impl PolicyEngineConfig {
    /// Creates a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the default action.
    pub fn with_default_action(mut self, action: PolicyAction) -> Self {
        self.default_action = action;
        self
    }

    /// Sets whether first match wins.
    pub fn with_first_match_wins(mut self, enabled: bool) -> Self {
        self.first_match_wins = enabled;
        self
    }
}

/// The policy engine evaluates scan results against configurable rules.
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    /// Ordered list of policy rules.
    rules: Vec<PolicyRule>,

    /// Configuration.
    config: PolicyEngineConfig,
}

impl PolicyEngine {
    /// Creates a new policy engine with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a policy engine with the given configuration.
    pub fn with_config(config: PolicyEngineConfig) -> Self {
        Self {
            rules: Vec::new(),
            config,
        }
    }

    /// Adds a rule to the engine.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        // Sort by priority (highest first)
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Adds a rule and returns self for chaining.
    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.add_rule(rule);
        self
    }

    /// Returns the number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns a reference to the rules.
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Clears all rules.
    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }

    /// Evaluates the scan report against all rules.
    pub fn evaluate(&self, report: &ScanReport, context: &ScanContext) -> PolicyDecision {
        for rule in &self.rules {
            if rule.matches(report, context) {
                tracing::debug!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    "Policy rule matched"
                );

                return PolicyDecision::new(rule.action.clone())
                    .with_rule(rule)
                    .with_reason(format!("Matched rule: {}", rule.name));
            }
        }

        // No rules matched, use default action
        PolicyDecision::new(self.config.default_action.clone())
            .with_reason("No matching rules; using default action")
    }

    /// Creates a default policy engine with standard rules.
    ///
    /// The default policy:
    /// - Blocks infected files
    /// - Quarantines suspicious files
    /// - Requires review for errors
    /// - Allows clean files
    pub fn default_policy() -> Self {
        Self::new()
            .with_rule(
                PolicyRule::new("block-infected", PolicyAction::block("Malware detected"))
                    .with_name("Block Infected Files")
                    .with_condition(Condition::is_infected())
                    .with_priority(100),
            )
            .with_rule(
                PolicyRule::new("quarantine-suspicious", PolicyAction::quarantine("Suspicious content"))
                    .with_name("Quarantine Suspicious Files")
                    .with_condition(Condition::is_suspicious())
                    .with_priority(90),
            )
            .with_rule(
                PolicyRule::new("review-errors", PolicyAction::require_review())
                    .with_name("Review Scan Errors")
                    .with_condition(Condition::is_error())
                    .with_priority(80),
            )
            .with_rule(
                PolicyRule::new("allow-clean", PolicyAction::allow())
                    .with_name("Allow Clean Files")
                    .with_condition(Condition::is_clean())
                    .with_priority(0),
            )
    }

    /// Creates a strict policy that blocks on errors.
    pub fn strict_policy() -> Self {
        Self::new()
            .with_rule(
                PolicyRule::new("block-infected", PolicyAction::block("Malware detected"))
                    .with_name("Block Infected Files")
                    .with_condition(Condition::is_infected())
                    .with_priority(100),
            )
            .with_rule(
                PolicyRule::new("block-suspicious", PolicyAction::block("Suspicious content"))
                    .with_name("Block Suspicious Files")
                    .with_condition(Condition::is_suspicious())
                    .with_priority(90),
            )
            .with_rule(
                PolicyRule::new("block-errors", PolicyAction::block("Scan error occurred"))
                    .with_name("Block on Scan Errors")
                    .with_condition(Condition::is_error())
                    .with_priority(80),
            )
            .with_rule(
                PolicyRule::new("allow-clean", PolicyAction::allow())
                    .with_name("Allow Clean Files")
                    .with_condition(Condition::is_clean())
                    .with_priority(0),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FileHash, FileMetadata, ScanOutcome, ScanResult, ThreatInfo, ThreatSeverity};
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
    fn test_policy_engine_default() {
        let engine = PolicyEngine::default_policy();
        let context = ScanContext::new();

        // Clean files should be allowed
        let clean_report = make_test_report(ScanOutcome::Clean);
        let decision = engine.evaluate(&clean_report, &context);
        assert!(decision.action.is_allowed());

        // Infected files should be blocked
        let threats = vec![ThreatInfo::new("Test", ThreatSeverity::High, "test")];
        let infected_report = make_test_report(ScanOutcome::Infected { threats });
        let decision = engine.evaluate(&infected_report, &context);
        assert!(decision.action.is_blocked());
    }

    #[test]
    fn test_policy_engine_strict() {
        let engine = PolicyEngine::strict_policy();
        let context = ScanContext::new();

        // Errors should be blocked in strict mode
        let error_report = make_test_report(ScanOutcome::Error { recoverable: true });
        let decision = engine.evaluate(&error_report, &context);
        assert!(decision.action.is_blocked());
    }

    #[test]
    fn test_policy_engine_custom_rule() {
        let engine = PolicyEngine::new()
            .with_rule(
                PolicyRule::new("test-rule", PolicyAction::quarantine("Test reason"))
                    .with_condition(Condition::tenant_equals("test-tenant"))
                    .with_priority(100),
            )
            .with_rule(
                PolicyRule::new("default-allow", PolicyAction::allow())
                    .with_condition(Condition::Always)
                    .with_priority(0),
            );

        let report = make_test_report(ScanOutcome::Clean);

        // With matching tenant
        let context = ScanContext::new().with_tenant_id("test-tenant");
        let decision = engine.evaluate(&report, &context);
        assert!(decision.action.is_quarantine());
        assert_eq!(decision.matched_rule_id, Some("test-rule".to_string()));

        // Without matching tenant
        let context = ScanContext::new().with_tenant_id("other-tenant");
        let decision = engine.evaluate(&report, &context);
        assert!(decision.action.is_allowed());
    }
}
