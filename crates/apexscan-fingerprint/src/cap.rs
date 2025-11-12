//! Contextual Asset Profiling (CAP)
//!
//! Advanced protocol analysis that goes beyond version strings to infer:
//! - Patch levels and configurations
//! - Security posture
//! - Deployment context

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HTTP/S Protocol Profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProfile {
    /// HTTP headers detected
    pub headers: HashMap<String, String>,

    /// Server version inferred from Server header
    pub server_version: Option<String>,

    /// Powered-by framework detection
    pub powered_by: Option<String>,

    /// ETag format analysis
    pub etag_format: Option<String>,

    /// Detected proxy/cache layer
    pub proxy_detected: Option<String>,

    /// Inferred patch level confidence (0.0-1.0)
    pub patch_level_confidence: f64,

    /// Security headers present
    pub security_headers: Vec<String>,

    /// Configuration notes
    pub config_notes: Vec<String>,
}

impl HttpProfile {
    /// Analyze HTTP response headers to create a profile
    pub fn from_headers(headers: &str) -> Self {
        let mut header_map = HashMap::new();
        let mut security_headers = Vec::new();
        let mut config_notes = Vec::new();

        // Parse headers line by line
        for line in headers.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                // Track security headers
                if matches!(key.as_str(),
                    "strict-transport-security" | "x-frame-options" |
                    "x-content-type-options" | "content-security-policy" |
                    "x-xss-protection" | "referrer-policy") {
                    security_headers.push(key.clone());
                }

                header_map.insert(key, value);
            }
        }

        // Extract Server header
        let server_version = header_map.get("server").cloned();

        // Extract X-Powered-By
        let powered_by = header_map.get("x-powered-by").cloned();

        // Analyze ETag format
        let etag_format = header_map.get("etag").map(|etag| {
            if etag.contains('-') {
                "Apache-style".to_string()
            } else if etag.starts_with('W') {
                "Weak-validator".to_string()
            } else {
                "Strong-validator".to_string()
            }
        });

        // Detect proxy/cache layers
        let proxy_detected = header_map.get("via")
            .or_else(|| header_map.get("x-cache"))
            .or_else(|| header_map.get("x-proxy-cache"))
            .cloned();

        // Infer configuration
        if let Some(ref server) = server_version {
            if server.contains("nginx") && server.contains('/') {
                config_notes.push("Nginx version disclosed in Server header".to_string());
            }
            if server.contains("Apache") && server.contains("OpenSSL") {
                config_notes.push("Apache with OpenSSL detected".to_string());
            }
        }

        if powered_by.is_some() {
            config_notes.push("X-Powered-By header disclosure detected".to_string());
        }

        // Calculate patch level confidence based on header analysis
        let patch_level_confidence = Self::calculate_patch_confidence(
            &header_map,
            &security_headers,
        );

        Self {
            headers: header_map,
            server_version,
            powered_by,
            etag_format,
            proxy_detected,
            patch_level_confidence,
            security_headers,
            config_notes,
        }
    }

    /// Calculate patch level confidence based on security headers and configurations
    fn calculate_patch_confidence(
        headers: &HashMap<String, String>,
        security_headers: &[String],
    ) -> f64 {
        let mut confidence: f64 = 0.5; // Base confidence

        // Modern security headers indicate recent patches
        if security_headers.len() >= 4 {
            confidence += 0.3;
        } else if security_headers.len() >= 2 {
            confidence += 0.15;
        }

        // HSTS with long max-age suggests maintained security
        if let Some(hsts) = headers.get("strict-transport-security") {
            if hsts.contains("max-age") && hsts.contains("includeSubDomains") {
                confidence += 0.1;
            }
        }

        // CSP header suggests modern deployment
        if headers.contains_key("content-security-policy") {
            confidence += 0.05;
        }

        confidence.min(1.0)
    }

    /// Infer probable patch level description
    pub fn infer_patch_level(&self) -> String {
        if self.patch_level_confidence > 0.8 {
            "Likely well-patched (modern security headers)".to_string()
        } else if self.patch_level_confidence > 0.6 {
            "Possibly patched (some security headers)".to_string()
        } else if self.patch_level_confidence > 0.4 {
            "Unknown patch level (mixed indicators)".to_string()
        } else {
            "Possibly outdated (lacking security headers)".to_string()
        }
    }
}

/// TLS/SSL Configuration Profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsProfile {
    /// TLS version negotiated
    pub tls_version: Option<String>,

    /// Cipher suite used
    pub cipher_suite: Option<String>,

    /// Certificate subject
    pub cert_subject: Option<String>,

    /// Certificate issuer
    pub cert_issuer: Option<String>,

    /// Certificate validity
    pub cert_valid: bool,

    /// Security posture score (0.0-1.0)
    pub security_score: f64,

    /// Configuration notes
    pub notes: Vec<String>,
}

impl TlsProfile {
    /// Create placeholder TLS profile
    /// Full implementation would use OpenSSL/rustls to inspect TLS handshake
    pub fn placeholder() -> Self {
        Self {
            tls_version: Some("TLS 1.2+".to_string()),
            cipher_suite: Some("Unknown".to_string()),
            cert_subject: None,
            cert_issuer: None,
            cert_valid: true,
            security_score: 0.5,
            notes: vec!["TLS inspection not yet implemented".to_string()],
        }
    }
}

/// Enhanced Asset Profile (combines multiple analyses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetProfile {
    /// HTTP profile (if HTTP/S service)
    pub http_profile: Option<HttpProfile>,

    /// TLS profile (if HTTPS)
    pub tls_profile: Option<TlsProfile>,

    /// Inferred operating system
    pub os_inference: Option<String>,

    /// OS confidence (0.0-1.0)
    pub os_confidence: f64,

    /// Overall security posture assessment
    pub security_posture: String,

    /// Risk indicators
    pub risk_indicators: Vec<String>,
}

impl AssetProfile {
    /// Create a new asset profile
    pub fn new() -> Self {
        Self {
            http_profile: None,
            tls_profile: None,
            os_inference: None,
            os_confidence: 0.0,
            security_posture: "Unknown".to_string(),
            risk_indicators: Vec::new(),
        }
    }

    /// Add HTTP analysis
    pub fn with_http_profile(mut self, profile: HttpProfile) -> Self {
        // Identify risk indicators from HTTP profile
        if profile.security_headers.is_empty() {
            self.risk_indicators.push("No security headers detected".to_string());
        }

        if profile.powered_by.is_some() {
            self.risk_indicators.push("Information disclosure via X-Powered-By".to_string());
        }

        if profile.patch_level_confidence < 0.5 {
            self.risk_indicators.push("Potentially outdated configuration".to_string());
        }

        self.http_profile = Some(profile);
        self.update_security_posture();
        self
    }

    /// Add TLS analysis
    pub fn with_tls_profile(mut self, profile: TlsProfile) -> Self {
        self.tls_profile = Some(profile);
        self.update_security_posture();
        self
    }

    /// Add OS inference
    pub fn with_os_inference(mut self, os: String, confidence: f64) -> Self {
        self.os_inference = Some(os);
        self.os_confidence = confidence;
        self
    }

    /// Update overall security posture based on profiles
    fn update_security_posture(&mut self) {
        let mut score = 0.5;

        if let Some(ref http) = self.http_profile {
            score = (score + http.patch_level_confidence) / 2.0;
        }

        if let Some(ref tls) = self.tls_profile {
            score = (score + tls.security_score) / 2.0;
        }

        self.security_posture = if score > 0.8 {
            "Strong".to_string()
        } else if score > 0.6 {
            "Moderate".to_string()
        } else if score > 0.4 {
            "Weak".to_string()
        } else {
            "Poor".to_string()
        };
    }
}

impl Default for AssetProfile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_profile_from_headers() {
        let headers = "Server: nginx/1.25.3\n\
                       X-Powered-By: PHP/8.2.0\n\
                       Strict-Transport-Security: max-age=31536000; includeSubDomains\n\
                       X-Frame-Options: SAMEORIGIN\n\
                       Content-Security-Policy: default-src 'self'";

        let profile = HttpProfile::from_headers(headers);

        assert_eq!(profile.server_version, Some("nginx/1.25.3".to_string()));
        assert_eq!(profile.powered_by, Some("PHP/8.2.0".to_string()));
        assert!(profile.security_headers.len() >= 3);
        assert!(profile.patch_level_confidence > 0.7);
    }

    #[test]
    fn test_asset_profile_risk_detection() {
        let headers = "Server: Apache/2.2.15\nX-Powered-By: ASP.NET";
        let http_profile = HttpProfile::from_headers(headers);

        let asset_profile = AssetProfile::new()
            .with_http_profile(http_profile);

        assert!(!asset_profile.risk_indicators.is_empty());
    }
}
