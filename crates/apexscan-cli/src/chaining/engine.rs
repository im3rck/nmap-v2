//! Smart Scan Chaining Engine
//!
//! Orchestrates rule-based follow-up scanning based on detection results

use super::matcher::matches_rule;
use super::rules::{ActionType, RuleSet, ScanRule};
use apexscan_core::{scan::PortResult, Result};
use std::net::IpAddr;
use std::path::Path;
use tracing::{debug, info, warn};

/// Smart Scan Chaining Engine
pub struct ChainingEngine {
    rules: Vec<ScanRule>,
    enabled: bool,
    max_depth: u32,
    current_depth: u32,
}

impl ChainingEngine {
    /// Create a new chaining engine by loading rules from YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| apexscan_core::Error::InvalidInput(
                format!("Failed to read rules file: {}", e)
            ))?;

        let ruleset: RuleSet = serde_yaml::from_str(&content)
            .map_err(|e| apexscan_core::Error::InvalidInput(
                format!("Failed to parse scan-chain-rules.yaml: {}", e)
            ))?;

        info!("Loaded {} chaining rules from {:?}", ruleset.rules.len(), path.as_ref());

        Ok(Self {
            rules: ruleset.rules,
            enabled: ruleset.config.enabled,
            max_depth: ruleset.config.max_depth,
            current_depth: 0,
        })
    }

    /// Create a disabled engine (no-op mode)
    pub fn disabled() -> Self {
        Self {
            rules: Vec::new(),
            enabled: false,
            max_depth: 0,
            current_depth: 0,
        }
    }

    /// Check if chaining is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.current_depth < self.max_depth
    }

    /// Process a port result and execute any matching rules
    pub async fn process_port_result(
        &mut self,
        ip: IpAddr,
        port_result: &PortResult,
    ) -> Vec<ChainedTask> {
        if !self.is_enabled() {
            return Vec::new();
        }

        let mut tasks = Vec::new();

        // Evaluate all rules against this port result
        for rule in &self.rules {
            if matches_rule(port_result, rule) {
                info!("Rule '{}' matched for {}:{}", rule.name, ip, port_result.port.value());

                // Create tasks for each action
                for action in &rule.actions {
                    let task = ChainedTask::from_action(
                        ip,
                        port_result.port.value(),
                        action,
                        rule.name.clone(),
                    );
                    tasks.push(task);
                }

                // Increment depth for next iteration
                self.current_depth += 1;

                if self.current_depth >= self.max_depth {
                    warn!("Chaining depth limit reached ({}). No further chaining will occur.",
                        self.max_depth);
                    break;
                }
            }
        }

        tasks
    }

    /// Reset depth counter for new target
    pub fn reset_depth(&mut self) {
        self.current_depth = 0;
    }
}

/// A chained task to be executed
#[derive(Debug, Clone)]
pub struct ChainedTask {
    pub ip: IpAddr,
    pub port: u16,
    pub task_type: ChainedTaskType,
    pub rule_name: String,
}

/// Types of chained tasks
#[derive(Debug, Clone)]
pub enum ChainedTaskType {
    RunScript { script_name: String },
    Rescan { scan_type: String },
    IncreaseVerbosity { level: String },
}

impl ChainedTask {
    fn from_action(
        ip: IpAddr,
        port: u16,
        action: &super::rules::Action,
        rule_name: String,
    ) -> Self {
        let task_type = match action.action_type {
            ActionType::RunScript => ChainedTaskType::RunScript {
                script_name: action.script.clone().unwrap_or_default(),
            },
            ActionType::Rescan => ChainedTaskType::Rescan {
                scan_type: action.scan_type.clone().unwrap_or_default(),
            },
            ActionType::IncreaseVerbosity => ChainedTaskType::IncreaseVerbosity {
                level: action.level.clone().unwrap_or("debug".to_string()),
            },
        };

        Self {
            ip,
            port,
            task_type,
            rule_name,
        }
    }
}
