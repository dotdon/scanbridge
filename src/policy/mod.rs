//! Policy engine for determining actions based on scan results.
//!
//! The policy engine evaluates scan results against configurable rules
//! to determine what action should be taken (allow, block, quarantine, etc.).

mod action;
mod engine;
mod rules;

pub use action::PolicyAction;
pub use engine::{PolicyDecision, PolicyEngine};
pub use rules::{Condition, PolicyRule};
