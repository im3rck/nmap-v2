//! ApexScan TCP Scanner Engine
//!
//! High-performance port scanning with state tracking and async I/O.

pub mod syn_scanner;
pub mod connect_scanner;
pub mod covert_scanner;
pub mod udp_scanner;
pub mod specialized_scanner;
pub mod state;
pub mod coordinator;

use apexscan_core::{scan::ScanType, types::{Port, PortState, Protocol, Target}, Error, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

/// Port scan result
#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub target: Target,
    pub port: Port,
    pub protocol: Protocol,
    pub state: PortState,
    pub rtt: Option<Duration>,
    pub info: Option<String>,
}

/// Trait for port scanners
#[async_trait]
pub trait PortScanner: Send + Sync {
    /// Scan a single port on a target
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult>;

    /// Scan multiple ports on a target
    async fn scan_ports(&self, target: IpAddr, ports: Vec<Port>) -> Result<Vec<PortScanResult>>;

    /// Get the scan type
    fn scan_type(&self) -> ScanType;
}

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub timeout: Duration,
    pub max_retries: u32,
    pub max_concurrent: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            max_retries: 2,
            max_concurrent: 1000,
        }
    }
}
