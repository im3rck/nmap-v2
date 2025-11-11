//! Conditional matcher logic for Smart Scan Chaining

use super::rules::{Condition, ConditionOperator, ScanRule};
use apexscan_core::scan::PortResult;
use tracing::debug;

/// Evaluate if a PortResult matches all conditions of a rule
pub fn matches_rule(port_result: &PortResult, rule: &ScanRule) -> bool {
    // All conditions must be true (AND logic)
    for condition in &rule.conditions {
        if !evaluate_condition(port_result, condition) {
            return false;
        }
    }

    debug!("Port {}:{} matches rule: {}",
        port_result.port.value(),
        port_result.protocol,
        rule.name
    );

    true
}

/// Evaluate a single condition against a PortResult
fn evaluate_condition(port_result: &PortResult, condition: &Condition) -> bool {
    match condition.field.as_str() {
        "service" => evaluate_service_condition(port_result, condition),
        "port" => evaluate_port_condition(port_result, condition),
        "state" => evaluate_state_condition(port_result, condition),
        "impact_score" => evaluate_impact_score_condition(port_result, condition),
        "security_posture" => evaluate_security_posture_condition(port_result, condition),
        _ => {
            debug!("Unknown condition field: {}", condition.field);
            false
        }
    }
}

/// Evaluate service name condition
fn evaluate_service_condition(port_result: &PortResult, condition: &Condition) -> bool {
    if let Some(ref service) = port_result.service {
        match condition.operator {
            ConditionOperator::Equals => {
                if let Some(ref value) = condition.value {
                    return service.to_lowercase() == value.to_lowercase();
                }
            }
            ConditionOperator::Contains => {
                if let Some(ref value) = condition.value {
                    return service.to_lowercase().contains(&value.to_lowercase());
                }
            }
            _ => {}
        }
    }
    false
}

/// Evaluate port number condition
fn evaluate_port_condition(port_result: &PortResult, condition: &Condition) -> bool {
    let port_num = port_result.port.value();

    match condition.operator {
        ConditionOperator::Equals => {
            if let Some(ref value) = condition.value {
                if let Ok(target_port) = value.parse::<u16>() {
                    return port_num == target_port;
                }
            }
        }
        ConditionOperator::In => {
            if let Some(ref values) = condition.values {
                for val in values {
                    if let Some(port) = val.as_u64() {
                        if port_num == port as u16 {
                            return true;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    false
}

/// Evaluate port state condition
fn evaluate_state_condition(port_result: &PortResult, condition: &Condition) -> bool {
    if let Some(ref value) = condition.value {
        let state_str = format!("{:?}", port_result.state).to_lowercase();
        return state_str == value.to_lowercase();
    }
    false
}

/// Evaluate impact score condition (AVM data)
fn evaluate_impact_score_condition(port_result: &PortResult, condition: &Condition) -> bool {
    if let Some(impact) = port_result.impact_score {
        match condition.operator {
            ConditionOperator::GreaterThanOrEqual => {
                if let Some(ref value) = condition.value {
                    if let Ok(threshold) = value.parse::<f64>() {
                        return impact >= threshold;
                    }
                }
            }
            ConditionOperator::Equals => {
                if let Some(ref value) = condition.value {
                    if let Ok(target) = value.parse::<f64>() {
                        return (impact - target).abs() < 0.1;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Evaluate security posture condition (CAP data)
fn evaluate_security_posture_condition(port_result: &PortResult, condition: &Condition) -> bool {
    if let Some(ref posture) = port_result.security_posture {
        match condition.operator {
            ConditionOperator::Equals => {
                if let Some(ref value) = condition.value {
                    return posture.to_lowercase() == value.to_lowercase();
                }
            }
            ConditionOperator::In => {
                if let Some(ref values) = condition.values {
                    for val in values {
                        if let Some(s) = val.as_str() {
                            if posture.to_lowercase() == s.to_lowercase() {
                                return true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use apexscan_core::types::{Port, PortState, Protocol};

    #[test]
    fn test_service_equals_condition() {
        let mut port_result = PortResult {
            port: Port::new(80).unwrap(),
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".to_string()),
            version: None,
            extra_info: None,
            confidence: 0.9,
            patch_level: None,
            security_posture: None,
            impact_score: None,
            cve_ids: None,
        };

        let condition = Condition {
            field: "service".to_string(),
            operator: ConditionOperator::Equals,
            value: Some("http".to_string()),
            values: None,
        };

        assert!(evaluate_condition(&port_result, &condition));
    }

    #[test]
    fn test_impact_score_gte_condition() {
        let port_result = PortResult {
            port: Port::new(22).unwrap(),
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("ssh".to_string()),
            version: Some("OpenSSH 7.4".to_string()),
            extra_info: None,
            confidence: 0.9,
            patch_level: None,
            security_posture: None,
            impact_score: Some(9.8),
            cve_ids: Some(vec!["CVE-2023-38408".to_string()]),
        };

        let condition = Condition {
            field: "impact_score".to_string(),
            operator: ConditionOperator::GreaterThanOrEqual,
            value: Some("9.0".to_string()),
            values: None,
        };

        assert!(evaluate_condition(&port_result, &condition));
    }
}
