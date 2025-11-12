//! ApexScan Fingerprinting Module
//!
//! Service version detection, OS fingerprinting, and asset profiling

pub mod service;
pub mod os;
pub mod banner;
pub mod signatures;
pub mod cap; // Contextual Asset Profiling
pub mod avm; // Automated Vulnerability Mapping

use std::net::IpAddr;

/// Service detection result
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub banner: String,  // Raw banner for CAP analysis
    pub confidence: f32,
}

/// OS detection result
#[derive(Debug, Clone)]
pub struct OsInfo {
    pub os_name: String,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub os_cpe: Option<String>,
    pub confidence: f32,
    pub details: Vec<String>,
}

/// Combined fingerprint result
#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub target: IpAddr,
    pub services: Vec<ServiceInfo>,
    pub os: Option<OsInfo>,
}
