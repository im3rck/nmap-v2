//! Automated Vulnerability Mapping (AVM)
//!
//! Deterministic vulnerability matching and impact scoring based on detected versions

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CVE Entry in local database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    /// CVE ID
    pub cve_id: String,

    /// Service name
    pub service: String,

    /// Affected version range
    pub version_range: VersionRange,

    /// CVSS score
    pub cvss_score: f64,

    /// Severity level
    pub severity: Severity,

    /// Description
    pub description: String,

    /// Exploit available
    pub exploit_available: bool,
}

/// Version range specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    /// Minimum affected version (inclusive)
    pub min_version: Option<String>,

    /// Maximum affected version (exclusive)
    pub max_version: Option<String>,

    /// Specific affected versions
    pub specific_versions: Vec<String>,
}

impl VersionRange {
    /// Check if a version falls within this range
    pub fn matches(&self, version: &str) -> bool {
        // Check specific versions first
        if !self.specific_versions.is_empty() {
            return self.specific_versions.iter().any(|v| version.contains(v));
        }

        // Simplified version comparison (production would use proper semver)
        let version_clean = version.split_whitespace().next().unwrap_or(version);

        if let Some(ref min) = self.min_version {
            if !Self::version_gte(version_clean, min) {
                return false;
            }
        }

        if let Some(ref max) = self.max_version {
            if !Self::version_lt(version_clean, max) {
                return false;
            }
        }

        true
    }

    /// Simplified version comparison: v1 >= v2
    fn version_gte(v1: &str, v2: &str) -> bool {
        // Extract numeric parts
        let v1_num: Vec<u32> = v1.split('.').filter_map(|s| s.parse().ok()).collect();
        let v2_num: Vec<u32> = v2.split('.').filter_map(|s| s.parse().ok()).collect();

        for i in 0..v1_num.len().max(v2_num.len()) {
            let a = v1_num.get(i).copied().unwrap_or(0);
            let b = v2_num.get(i).copied().unwrap_or(0);

            if a < b {
                return false;
            } else if a > b {
                return true;
            }
        }

        true // Equal
    }

    /// Simplified version comparison: v1 < v2
    fn version_lt(v1: &str, v2: &str) -> bool {
        !Self::version_gte(v1, v2) || v1 == v2
    }
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// From CVSS score
    pub fn from_cvss(score: f64) -> Self {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score >= 0.1 {
            Severity::Low
        } else {
            Severity::Info
        }
    }

    /// Get ANSI color for console output
    pub fn color_code(&self) -> &'static str {
        match self {
            Severity::Critical => "\x1b[1;31m", // Bold Red
            Severity::High => "\x1b[33m",       // Yellow
            Severity::Medium => "\x1b[36m",     // Cyan
            Severity::Low => "\x1b[37m",        // White
            Severity::Info => "\x1b[90m",       // Gray
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Impact score result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactScore {
    /// Matched CVEs
    pub cves: Vec<CveEntry>,

    /// Overall impact score (0.0-10.0)
    pub score: f64,

    /// Highest severity found
    pub max_severity: Severity,

    /// Exploitable vulnerabilities count
    pub exploitable_count: usize,

    /// Risk assessment
    pub risk_assessment: String,
}

impl ImpactScore {
    /// Create empty impact score
    pub fn none() -> Self {
        Self {
            cves: Vec::new(),
            score: 0.0,
            max_severity: Severity::Info,
            exploitable_count: 0,
            risk_assessment: "No known vulnerabilities".to_string(),
        }
    }

    /// Get color-coded severity string
    pub fn colored_severity(&self) -> String {
        format!("{}{}\x1b[0m", self.max_severity.color_code(), self.max_severity)
    }
}

/// Local CVE Database (mock implementation)
pub struct CveDatabase {
    /// Entries indexed by service name
    entries: HashMap<String, Vec<CveEntry>>,
}

impl CveDatabase {
    /// Load mock CVE database
    pub fn load_mock() -> Self {
        let mut entries = HashMap::new();

        // Apache HTTP Server vulnerabilities
        entries.insert("apache".to_string(), vec![
            CveEntry {
                cve_id: "CVE-2021-41773".to_string(),
                service: "apache".to_string(),
                version_range: VersionRange {
                    min_version: Some("2.4.49".to_string()),
                    max_version: Some("2.4.51".to_string()),
                    specific_versions: vec![],
                },
                cvss_score: 7.5,
                severity: Severity::High,
                description: "Path traversal and RCE vulnerability".to_string(),
                exploit_available: true,
            },
            CveEntry {
                cve_id: "CVE-2022-31813".to_string(),
                service: "apache".to_string(),
                version_range: VersionRange {
                    min_version: Some("2.4.0".to_string()),
                    max_version: Some("2.4.54".to_string()),
                    specific_versions: vec![],
                },
                cvss_score: 9.8,
                severity: Severity::Critical,
                description: "mod_proxy X-Forwarded-For vulnerability".to_string(),
                exploit_available: false,
            },
        ]);

        // Nginx vulnerabilities
        entries.insert("nginx".to_string(), vec![
            CveEntry {
                cve_id: "CVE-2021-23017".to_string(),
                service: "nginx".to_string(),
                version_range: VersionRange {
                    min_version: Some("0.6.18".to_string()),
                    max_version: Some("1.21.0".to_string()),
                    specific_versions: vec![],
                },
                cvss_score: 8.1,
                severity: Severity::High,
                description: "DNS resolver off-by-one heap write".to_string(),
                exploit_available: true,
            },
        ]);

        // OpenSSH vulnerabilities
        entries.insert("ssh".to_string(), vec![
            CveEntry {
                cve_id: "CVE-2023-38408".to_string(),
                service: "ssh".to_string(),
                version_range: VersionRange {
                    min_version: Some("9.0".to_string()),
                    max_version: Some("9.3p2".to_string()),
                    specific_versions: vec![],
                },
                cvss_score: 9.8,
                severity: Severity::Critical,
                description: "Remote code execution via ssh-agent".to_string(),
                exploit_available: true,
            },
        ]);

        // MySQL vulnerabilities
        entries.insert("mysql".to_string(), vec![
            CveEntry {
                cve_id: "CVE-2023-22015".to_string(),
                service: "mysql".to_string(),
                version_range: VersionRange {
                    min_version: Some("8.0.0".to_string()),
                    max_version: Some("8.0.33".to_string()),
                    specific_versions: vec![],
                },
                cvss_score: 7.1,
                severity: Severity::High,
                description: "Privilege escalation vulnerability".to_string(),
                exploit_available: false,
            },
        ]);

        // FTP vulnerabilities
        entries.insert("ftp".to_string(), vec![
            CveEntry {
                cve_id: "CVE-2023-ANON-FTP".to_string(),
                service: "ftp".to_string(),
                version_range: VersionRange {
                    min_version: None,
                    max_version: None,
                    specific_versions: vec![],
                },
                cvss_score: 7.5,
                severity: Severity::High,
                description: "Anonymous FTP access enabled".to_string(),
                exploit_available: true,
            },
        ]);

        Self { entries }
    }

    /// Query vulnerabilities for a service and version
    pub fn query(&self, service_name: &str, version: Option<&str>) -> ImpactScore {
        // Normalize service name
        let service_key = service_name.to_lowercase();
        let service_key = if service_key.contains("http") {
            if service_key.contains("nginx") {
                "nginx"
            } else if service_key.contains("apache") {
                "apache"
            } else {
                "http"
            }
        } else if service_key.contains("ssh") {
            "ssh"
        } else if service_key.contains("mysql") || service_key.contains("mariadb") {
            "mysql"
        } else if service_key.contains("ftp") {
            "ftp"
        } else {
            service_key.as_str()
        };

        // Get matching CVEs
        let cves = if let Some(entries) = self.entries.get(service_key) {
            if let Some(ver) = version {
                entries.iter()
                    .filter(|cve| cve.version_range.matches(ver))
                    .cloned()
                    .collect()
            } else {
                // No version info - return all CVEs for service with lower confidence
                entries.clone()
            }
        } else {
            Vec::new()
        };

        if cves.is_empty() {
            return ImpactScore::none();
        }

        // Calculate impact score
        let max_cvss = cves.iter()
            .map(|cve| cve.cvss_score)
            .fold(0.0, f64::max);

        let max_severity = Severity::from_cvss(max_cvss);

        let exploitable_count = cves.iter()
            .filter(|cve| cve.exploit_available)
            .count();

        let risk_assessment = if exploitable_count > 0 {
            format!("{} known vulnerabilities ({} exploitable)", cves.len(), exploitable_count)
        } else {
            format!("{} known vulnerabilities", cves.len())
        };

        ImpactScore {
            cves,
            score: max_cvss,
            max_severity,
            exploitable_count,
            risk_assessment,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_range_matching() {
        let range = VersionRange {
            min_version: Some("2.4.0".to_string()),
            max_version: Some("2.4.50".to_string()),
            specific_versions: vec![],
        };

        assert!(range.matches("2.4.25"));
        assert!(range.matches("2.4.49"));
        assert!(!range.matches("2.4.51"));
        assert!(!range.matches("2.3.0"));
    }

    #[test]
    fn test_cve_database_query() {
        let db = CveDatabase::load_mock();

        let impact = db.query("apache", Some("2.4.49"));
        assert!(!impact.cves.is_empty());
        assert!(impact.score > 0.0);
    }

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(Severity::from_cvss(9.5), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
    }
}
