//! Service and OS signature database

/// Service signature
#[derive(Debug, Clone)]
pub struct ServiceSignature {
    pub service: String,
    pub product: Option<String>,
    pub version_regex: String,
    pub banner_pattern: String,
}

/// OS signature
#[derive(Debug, Clone)]
pub struct OsSignature {
    pub os_name: String,
    pub os_family: String,
    pub ttl_range: (u8, u8),
    pub window_size: u16,
    pub tcp_options: Vec<u8>,
}

/// Signature database (placeholder - would be loaded from file)
pub struct SignatureDatabase {
    service_signatures: Vec<ServiceSignature>,
    os_signatures: Vec<OsSignature>,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        Self {
            service_signatures: Self::load_service_signatures(),
            os_signatures: Self::load_os_signatures(),
        }
    }

    fn load_service_signatures() -> Vec<ServiceSignature> {
        // In production, load from JSON/database
        vec![
            ServiceSignature {
                service: "ssh".to_string(),
                product: Some("OpenSSH".to_string()),
                version_regex: r"OpenSSH_(\d+\.\d+p?\d*)".to_string(),
                banner_pattern: "SSH-2.0-OpenSSH".to_string(),
            },
            ServiceSignature {
                service: "http".to_string(),
                product: Some("Apache".to_string()),
                version_regex: r"Apache/([\d.]+)".to_string(),
                banner_pattern: "Server: Apache".to_string(),
            },
            ServiceSignature {
                service: "http".to_string(),
                product: Some("nginx".to_string()),
                version_regex: r"nginx/([\d.]+)".to_string(),
                banner_pattern: "Server: nginx".to_string(),
            },
        ]
    }

    fn load_os_signatures() -> Vec<OsSignature> {
        // In production, load from comprehensive database
        vec![
            OsSignature {
                os_name: "Linux 4.x/5.x".to_string(),
                os_family: "Linux".to_string(),
                ttl_range: (64, 64),
                window_size: 65535,
                tcp_options: vec![],
            },
            OsSignature {
                os_name: "Windows 10".to_string(),
                os_family: "Windows".to_string(),
                ttl_range: (128, 128),
                window_size: 8192,
                tcp_options: vec![],
            },
        ]
    }

    pub fn match_service(&self, banner: &str) -> Option<&ServiceSignature> {
        self.service_signatures
            .iter()
            .find(|sig| banner.contains(&sig.banner_pattern))
    }

    pub fn match_os(&self, ttl: u8, window: u16) -> Option<&OsSignature> {
        self.os_signatures.iter().find(|sig| {
            ttl >= sig.ttl_range.0 && ttl <= sig.ttl_range.1 && window == sig.window_size
        })
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}
