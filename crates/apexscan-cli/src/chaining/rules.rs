//! Rule data structures for Smart Scan Chaining

use serde::{Deserialize, Serialize};

/// Complete rule set loaded from YAML
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleSet {
    pub version: String,
    pub rules: Vec<ScanRule>,
    pub config: ChainConfig,
}

/// Chain configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainConfig {
    pub enabled: bool,
    pub max_depth: u32,
    pub timeout: u64,
    pub parallel: bool,
    pub verbose_logging: bool,
}

/// A single scan chaining rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScanRule {
    pub name: String,
    pub description: Option<String>,
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
}

/// Condition for rule matching
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Condition {
    pub field: String,
    pub operator: ConditionOperator,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_yaml::Value>>,
}

/// Condition operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionOperator {
    Equals,
    Contains,
    In,
    #[serde(rename = "gte")]
    GreaterThanOrEqual,
}

/// Action to take when rule matches
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

/// Action types
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    RunScript,
    Rescan,
    IncreaseVerbosity,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: 3,
            timeout: 300,
            parallel: true,
            verbose_logging: false,
        }
    }
}
