//! Policy actions that can be taken based on scan results.

use serde::{Deserialize, Serialize};

/// An action to take based on policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow the file through.
    Allow,

    /// Allow the file but with a warning.
    AllowWithWarning {
        /// Warning message to display/log.
        message: String,
    },

    /// Quarantine the file.
    Quarantine {
        /// Reason for quarantine.
        reason: String,
    },

    /// Block the file entirely.
    Block {
        /// Reason for blocking.
        reason: String,
    },

    /// Require manual review before proceeding.
    RequireManualReview,
}

impl PolicyAction {
    /// Creates an Allow action.
    pub fn allow() -> Self {
        Self::Allow
    }

    /// Creates an AllowWithWarning action.
    pub fn allow_with_warning(message: impl Into<String>) -> Self {
        Self::AllowWithWarning {
            message: message.into(),
        }
    }

    /// Creates a Quarantine action.
    pub fn quarantine(reason: impl Into<String>) -> Self {
        Self::Quarantine {
            reason: reason.into(),
        }
    }

    /// Creates a Block action.
    pub fn block(reason: impl Into<String>) -> Self {
        Self::Block {
            reason: reason.into(),
        }
    }

    /// Creates a RequireManualReview action.
    pub fn require_review() -> Self {
        Self::RequireManualReview
    }

    /// Returns true if this action allows the file through.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::AllowWithWarning { .. })
    }

    /// Returns true if this action blocks the file.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    /// Returns true if this action quarantines the file.
    pub fn is_quarantine(&self) -> bool {
        matches!(self, Self::Quarantine { .. })
    }

    /// Returns true if this action requires manual review.
    pub fn requires_review(&self) -> bool {
        matches!(self, Self::RequireManualReview)
    }

    /// Returns the severity level of the action (higher = more severe).
    pub fn severity(&self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::AllowWithWarning { .. } => 1,
            Self::RequireManualReview => 2,
            Self::Quarantine { .. } => 3,
            Self::Block { .. } => 4,
        }
    }
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_action_helpers() {
        assert!(PolicyAction::allow().is_allowed());
        assert!(PolicyAction::allow_with_warning("test").is_allowed());
        assert!(PolicyAction::block("malware").is_blocked());
        assert!(PolicyAction::quarantine("suspicious").is_quarantine());
        assert!(PolicyAction::require_review().requires_review());
    }

    #[test]
    fn test_policy_action_severity() {
        assert!(PolicyAction::Block { reason: "".into() }.severity() 
            > PolicyAction::Quarantine { reason: "".into() }.severity());
        assert!(PolicyAction::Quarantine { reason: "".into() }.severity() 
            > PolicyAction::Allow.severity());
    }
}
