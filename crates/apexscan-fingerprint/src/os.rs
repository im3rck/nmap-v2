//! OS fingerprinting using TCP/IP stack analysis

use crate::OsInfo;
use apexscan_core::Result;
use std::net::IpAddr;
use tracing::debug;

/// OS fingerprinter
pub struct OsDetector {
    // Will be expanded with signature database
}

impl OsDetector {
    pub fn new() -> Self {
        Self {}
    }

    /// Detect operating system
    pub async fn detect_os(&self, target: IpAddr, fingerprint_data: &TcpFingerprint) -> Result<OsInfo> {
        debug!("Detecting OS for {}", target);

        // Analyze TCP/IP stack characteristics
        let os_guess = self.analyze_fingerprint(fingerprint_data);

        Ok(os_guess)
    }

    /// Analyze fingerprint data to determine OS
    fn analyze_fingerprint(&self, fp: &TcpFingerprint) -> OsInfo {
        // Simple heuristic-based OS detection
        // In production, this would use a comprehensive signature database

        let (os_name, os_family, details) = if fp.ttl >= 60 && fp.ttl <= 64 {
            // Linux/Unix typically uses TTL 64
            if fp.window_size == 65535 || fp.window_size > 29200 {
                (
                    "Linux".to_string(),
                    Some("Unix".to_string()),
                    vec!["TTL: 64 range".to_string(), format!("Window: {}", fp.window_size)],
                )
            } else {
                (
                    "Unix".to_string(),
                    Some("Unix".to_string()),
                    vec!["TTL: 64 range".to_string()],
                )
            }
        } else if fp.ttl >= 120 && fp.ttl <= 128 {
            // Windows typically uses TTL 128
            (
                "Windows".to_string(),
                Some("Windows".to_string()),
                vec!["TTL: 128 range".to_string(), format!("Window: {}", fp.window_size)],
            )
        } else if fp.ttl >= 250 {
            // Cisco/network devices often use TTL 255
            (
                "Cisco IOS".to_string(),
                Some("Network Device".to_string()),
                vec!["TTL: 255 range".to_string()],
            )
        } else {
            (
                "Unknown".to_string(),
                None,
                vec![format!("TTL: {}", fp.ttl)],
            )
        };

        let confidence = if os_name != "Unknown" {
            0.6 // Medium confidence with basic heuristics
        } else {
            0.1
        };

        OsInfo {
            os_name,
            os_family,
            os_version: None,
            os_cpe: None,
            confidence,
            details,
        }
    }
}

impl Default for OsDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP/IP stack fingerprint data
#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    pub ttl: u8,
    pub window_size: u16,
    pub df_flag: bool,
    pub initial_seq: u32,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub tcp_options: Vec<u8>,
}

impl TcpFingerprint {
    pub fn new() -> Self {
        Self {
            ttl: 0,
            window_size: 0,
            df_flag: false,
            initial_seq: 0,
            mss: None,
            window_scale: None,
            sack_permitted: false,
            tcp_options: Vec::new(),
        }
    }
}

impl Default for TcpFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_detection() {
        let detector = OsDetector::new();
        
        // Linux fingerprint
        let linux_fp = TcpFingerprint {
            ttl: 64,
            window_size: 65535,
            ..Default::default()
        };
        
        let os_info = detector.analyze_fingerprint(&linux_fp);
        assert_eq!(os_info.os_family, Some("Unix".to_string()));

        // Windows fingerprint
        let windows_fp = TcpFingerprint {
            ttl: 128,
            window_size: 8192,
            ..Default::default()
        };
        
        let os_info = detector.analyze_fingerprint(&windows_fp);
        assert_eq!(os_info.os_family, Some("Windows".to_string()));
    }
}
