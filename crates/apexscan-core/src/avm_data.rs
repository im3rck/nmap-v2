//! Automated Vulnerability Mapping (AVM) Data Module
//!
//! Provides CVE data structures and lookup functionality for vulnerability mapping.

use regex::Regex;
use std::sync::OnceLock;

/// AVM entry representing a known vulnerability
#[derive(Debug, Clone)]
pub struct AVMEntry {
    /// Service name (e.g., "Apache httpd", "OpenSSH")
    pub service_name: String,

    /// Regex pattern to match vulnerable versions
    pub version_regex: String,

    /// CVSS impact score (0.0-10.0)
    pub impact_score: f64,

    /// List of associated CVE IDs
    pub cve_ids: Vec<String>,

    /// Cached compiled regex
    regex: OnceLock<Regex>,
}

impl AVMEntry {
    /// Create a new AVM entry
    pub fn new(
        service_name: String,
        version_regex: String,
        impact_score: f64,
        cve_ids: Vec<String>,
    ) -> Self {
        Self {
            service_name,
            version_regex,
            impact_score,
            cve_ids,
            regex: OnceLock::new(),
        }
    }

    /// Get the compiled regex, compiling it lazily if needed
    fn get_regex(&self) -> Option<&Regex> {
        // Try to get or initialize the regex
        let regex_opt = self.regex.get_or_init(|| {
            Regex::new(&self.version_regex).unwrap_or_else(|_| {
                // If regex compilation fails, create a regex that never matches
                Regex::new("^$").unwrap()
            })
        });

        // Check if the regex is the "never match" pattern
        if regex_opt.as_str() == "^$" && self.version_regex != "^$" {
            None
        } else {
            Some(regex_opt)
        }
    }

    /// Check if this entry matches the given service and version
    pub fn matches(&self, service: &str, version: &str) -> bool {
        // Case-insensitive service name matching
        if !self.service_name.to_lowercase().contains(&service.to_lowercase()) {
            return false;
        }

        // Version regex matching
        if let Some(regex) = self.get_regex() {
            regex.is_match(version)
        } else {
            // If regex compilation failed, fall back to simple string matching
            version.contains(&self.version_regex)
        }
    }
}

/// Load hardcoded AVM vulnerability data
///
/// This function returns a collection of known CVE entries for testing and validation.
/// In production, this would be loaded from an external database or API.
pub fn load_avm_data() -> Vec<AVMEntry> {
    vec![
        // Apache httpd 2.4.49 - Path Traversal (CVE-2021-41773)
        AVMEntry::new(
            "Apache httpd".to_string(),
            r"2\.4\.(49|50)".to_string(),
            9.8, // Critical CVSS score
            vec![
                "CVE-2021-41773".to_string(),
                "CVE-2021-42013".to_string(),
            ],
        ),

        // Apache httpd 2.4.x < 2.4.51 - Multiple vulnerabilities
        AVMEntry::new(
            "Apache httpd".to_string(),
            r"2\.4\.(([0-4][0-9])|50)".to_string(),
            7.5, // High CVSS score
            vec![
                "CVE-2021-44790".to_string(),
                "CVE-2021-39275".to_string(),
            ],
        ),

        // OpenSSH < 8.5 - Multiple vulnerabilities
        AVMEntry::new(
            "OpenSSH".to_string(),
            r"^[1-7]\.|^8\.[0-4]".to_string(),
            8.1, // High CVSS score
            vec![
                "CVE-2021-28041".to_string(),
                "CVE-2020-14145".to_string(),
            ],
        ),

        // nginx < 1.20.1 - DNS resolver vulnerabilities
        AVMEntry::new(
            "nginx".to_string(),
            r"^1\.(1[0-9]\.|20\.0)".to_string(),
            7.7, // High CVSS score
            vec![
                "CVE-2021-23017".to_string(),
            ],
        ),

        // vsftpd 2.3.4 - Backdoor vulnerability
        AVMEntry::new(
            "vsftpd".to_string(),
            r"2\.3\.4".to_string(),
            10.0, // Critical - known backdoor
            vec![
                "CVE-2011-2523".to_string(),
            ],
        ),

        // ProFTPD < 1.3.6 - Multiple vulnerabilities
        AVMEntry::new(
            "ProFTPD".to_string(),
            r"1\.3\.[0-5]".to_string(),
            9.8, // Critical CVSS score
            vec![
                "CVE-2019-12815".to_string(),
                "CVE-2020-9273".to_string(),
            ],
        ),

        // MySQL 5.7.x < 5.7.35 - Multiple vulnerabilities
        AVMEntry::new(
            "MySQL".to_string(),
            r"5\.7\.(([0-2][0-9])|3[0-4])".to_string(),
            7.5, // High CVSS score
            vec![
                "CVE-2021-2389".to_string(),
                "CVE-2021-2372".to_string(),
            ],
        ),

        // PostgreSQL < 13.4 - Information disclosure
        AVMEntry::new(
            "PostgreSQL".to_string(),
            r"^(9\.|1[0-2]\.|13\.[0-3])".to_string(),
            6.5, // Medium CVSS score
            vec![
                "CVE-2021-32027".to_string(),
            ],
        ),

        // Samba 4.x < 4.13.14 - RCE vulnerability
        AVMEntry::new(
            "Samba".to_string(),
            r"4\.(([0-9]|1[0-2])\.|13\.(([0-9]|1[0-3])[^0-9]))".to_string(),
            9.9, // Critical CVSS score
            vec![
                "CVE-2021-44142".to_string(),
            ],
        ),

        // Microsoft IIS 10.0 - HTTP.sys vulnerability
        AVMEntry::new(
            "Microsoft-IIS".to_string(),
            r"10\.0".to_string(),
            9.8, // Critical CVSS score
            vec![
                "CVE-2021-31166".to_string(),
            ],
        ),
    ]
}

/// Lookup AVM data for a given service and version
///
/// Returns the first matching CVE entry, or None if no match found.
///
/// # Arguments
/// * `service` - Service name (e.g., "Apache httpd", "http")
/// * `version` - Service version string (e.g., "2.4.49")
///
/// # Returns
/// * `Some(&AVMEntry)` - First matching vulnerability entry
/// * `None` - No matching vulnerabilities found
///
/// # Examples
/// ```
/// let avm_data = load_avm_data();
/// if let Some(entry) = lookup_avm(&avm_data, "Apache", "2.4.49") {
///     println!("Found CVE: {:?}", entry.cve_ids);
///     println!("Impact: {}", entry.impact_score);
/// }
/// ```
pub fn lookup_avm<'a>(avm_data: &'a [AVMEntry], service: &str, version: &str) -> Option<&'a AVMEntry> {
    avm_data.iter()
        .find(|entry| entry.matches(service, version))
}

/// Lookup all matching AVM entries (not just the first)
///
/// # Arguments
/// * `service` - Service name
/// * `version` - Service version string
///
/// # Returns
/// * Vector of all matching vulnerability entries
pub fn lookup_all_avm<'a>(avm_data: &'a [AVMEntry], service: &str, version: &str) -> Vec<&'a AVMEntry> {
    avm_data.iter()
        .filter(|entry| entry.matches(service, version))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_avm_data() {
        let data = load_avm_data();
        assert!(!data.is_empty());
        assert!(data.len() >= 5);
    }

    #[test]
    fn test_apache_vulnerability_match() {
        let data = load_avm_data();
        let result = lookup_avm(&data, "Apache", "2.4.49");
        assert!(result.is_some());

        let entry = result.unwrap();
        assert_eq!(entry.impact_score, 9.8);
        assert!(entry.cve_ids.contains(&"CVE-2021-41773".to_string()));
    }

    #[test]
    fn test_vsftpd_backdoor_match() {
        let data = load_avm_data();
        let result = lookup_avm(&data, "vsftpd", "2.3.4");
        assert!(result.is_some());

        let entry = result.unwrap();
        assert_eq!(entry.impact_score, 10.0);
        assert!(entry.cve_ids.contains(&"CVE-2011-2523".to_string()));
    }

    #[test]
    fn test_openssh_vulnerability_match() {
        let data = load_avm_data();
        let result = lookup_avm(&data, "OpenSSH", "8.2");
        assert!(result.is_some());

        let entry = result.unwrap();
        assert_eq!(entry.impact_score, 8.1);
    }

    #[test]
    fn test_no_match_safe_version() {
        let data = load_avm_data();
        let result = lookup_avm(&data, "Apache", "2.4.52");
        // Version 2.4.52 is newer and should not match the vulnerable patterns
        assert!(result.is_none());
    }

    #[test]
    fn test_case_insensitive_service_match() {
        let data = load_avm_data();
        let result = lookup_avm(&data, "apache", "2.4.49");
        assert!(result.is_some());
    }

    #[test]
    fn test_lookup_all_multiple_matches() {
        let data = load_avm_data();
        let results = lookup_all_avm(&data, "Apache httpd", "2.4.30");
        // Should match the second Apache entry (2.4.x < 2.4.51)
        assert!(!results.is_empty());
    }
}
