//! Scan result types

use crate::types::{HostState, Port, PortState, Protocol, Target};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Scan type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    /// TCP SYN scan (-sS)
    TcpSyn,

    /// TCP Connect scan (-sT)
    TcpConnect,

    /// UDP scan (-sU)
    Udp,

    /// TCP NULL scan (-sN)
    TcpNull,

    /// TCP FIN scan (-sF)
    TcpFin,

    /// TCP Xmas scan (-sX)
    TcpXmas,

    /// ACK scan (-sA)
    TcpAck,

    /// Window scan (-sW)
    TcpWindow,

    /// Maimon scan (-sM)
    TcpMaimon,
}

/// Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Scan type
    pub scan_type: ScanType,

    /// Targets to scan
    pub targets: Vec<Target>,

    /// Ports to scan
    pub ports: Vec<Port>,

    /// Enable OS detection
    pub os_detection: bool,

    /// Enable service version detection
    pub version_detection: bool,

    /// Enable script scanning
    pub script_scan: bool,

    /// Scripts to run
    pub scripts: Vec<String>,

    /// Timing template
    pub timing: crate::types::TimingTemplate,

    /// Maximum retries
    pub max_retries: u32,

    /// Timeout per probe
    pub timeout: Duration,

    /// Enable verbose output
    pub verbose: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scan_type: ScanType::TcpSyn,
            targets: Vec::new(),
            ports: Vec::new(),
            os_detection: false,
            version_detection: false,
            script_scan: false,
            scripts: Vec::new(),
            timing: crate::types::TimingTemplate::T3,
            max_retries: 3,
            timeout: Duration::from_secs(2),
            verbose: false,
        }
    }
}

/// Port scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    /// Port number
    pub port: Port,

    /// Protocol
    pub protocol: Protocol,

    /// Port state
    pub state: PortState,

    /// Service name (if detected)
    pub service: Option<String>,

    /// Service version (if detected)
    pub version: Option<String>,

    /// Additional information
    pub extra_info: Option<String>,

    /// Confidence score (0.0-1.0)
    pub confidence: f32,
}

/// OS detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsResult {
    /// OS name
    pub name: String,

    /// OS family (Linux, Windows, etc.)
    pub family: Option<String>,

    /// OS version
    pub version: Option<String>,

    /// Confidence score (0.0-1.0)
    pub confidence: f32,

    /// Additional details
    pub details: HashMap<String, String>,
}

/// Script execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    /// Script name
    pub script: String,

    /// Output
    pub output: String,

    /// Execution time
    pub duration: Duration,

    /// Success/failure
    pub success: bool,
}

/// Host scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    /// Target information
    pub target: Target,

    /// Host state
    pub state: HostState,

    /// Port scan results
    pub ports: Vec<PortResult>,

    /// OS detection results
    pub os: Vec<OsResult>,

    /// Script results
    pub scripts: Vec<ScriptResult>,

    /// Scan start time
    pub start_time: DateTime<Utc>,

    /// Scan end time
    pub end_time: DateTime<Utc>,

    /// Total scan duration
    pub duration: Duration,

    /// Latency (RTT)
    pub latency: Option<Duration>,
}

impl HostResult {
    pub fn new(target: Target) -> Self {
        let now = Utc::now();
        Self {
            target,
            state: HostState::Unknown,
            ports: Vec::new(),
            os: Vec::new(),
            scripts: Vec::new(),
            start_time: now,
            end_time: now,
            duration: Duration::from_secs(0),
            latency: None,
        }
    }

    /// Get all open ports
    pub fn open_ports(&self) -> Vec<&PortResult> {
        self.ports.iter().filter(|p| p.state == PortState::Open).collect()
    }

    /// Get all closed ports
    pub fn closed_ports(&self) -> Vec<&PortResult> {
        self.ports.iter().filter(|p| p.state == PortState::Closed).collect()
    }

    /// Get all filtered ports
    pub fn filtered_ports(&self) -> Vec<&PortResult> {
        self.ports.iter().filter(|p| p.state == PortState::Filtered).collect()
    }
}

/// Complete scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Scan configuration
    pub config: ScanConfig,

    /// Host results
    pub hosts: Vec<HostResult>,

    /// Scan start time
    pub start_time: DateTime<Utc>,

    /// Scan end time
    pub end_time: DateTime<Utc>,

    /// Total duration
    pub duration: Duration,

    /// Summary statistics
    pub stats: ScanStats,
}

/// Scan statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    /// Total hosts scanned
    pub total_hosts: usize,

    /// Hosts up
    pub hosts_up: usize,

    /// Hosts down
    pub hosts_down: usize,

    /// Total ports scanned
    pub total_ports: usize,

    /// Open ports
    pub open_ports: usize,

    /// Closed ports
    pub closed_ports: usize,

    /// Filtered ports
    pub filtered_ports: usize,

    /// Total packets sent
    pub packets_sent: u64,

    /// Total packets received
    pub packets_received: u64,

    /// Packet loss rate
    pub packet_loss_rate: f32,
}

impl ScanResults {
    pub fn new(config: ScanConfig) -> Self {
        let now = Utc::now();
        Self {
            config,
            hosts: Vec::new(),
            start_time: now,
            end_time: now,
            duration: Duration::from_secs(0),
            stats: ScanStats::default(),
        }
    }

    /// Calculate statistics from host results
    pub fn calculate_stats(&mut self) {
        self.stats.total_hosts = self.hosts.len();
        self.stats.hosts_up = self.hosts.iter().filter(|h| h.state == HostState::Up).count();
        self.stats.hosts_down = self.hosts.iter().filter(|h| h.state == HostState::Down).count();

        let mut open = 0;
        let mut closed = 0;
        let mut filtered = 0;

        for host in &self.hosts {
            for port in &host.ports {
                match port.state {
                    PortState::Open => open += 1,
                    PortState::Closed => closed += 1,
                    PortState::Filtered => filtered += 1,
                    _ => {}
                }
            }
        }

        self.stats.open_ports = open;
        self.stats.closed_ports = closed;
        self.stats.filtered_ports = filtered;
        self.stats.total_ports = open + closed + filtered;
    }
}
