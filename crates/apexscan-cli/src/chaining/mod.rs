//! Smart Scan Chaining Engine
//!
//! Implements deterministic rule-based follow-up scanning based on
//! detection results from CAP (Contextual Asset Profiling) and
//! AVM (Automated Vulnerability Mapping).

pub mod rules;
pub mod matcher;
pub mod engine;

pub use engine::{ChainingEngine, ChainedTask, ChainedTaskType};
pub use rules::{ScanRule, RuleSet, Condition, Action, ConditionOperator, ActionType};
