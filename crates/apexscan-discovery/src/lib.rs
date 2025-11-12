//! ApexScan Host Discovery Library
//!
//! This crate implements various host discovery methods for detecting live hosts.

pub mod icmp;
pub mod arp;
pub mod tcp;
pub mod udp;
pub mod coordinator;

use apexscan_core::{types::Target, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

/// Host discovery result
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// Target that was probed
    pub target: Target,

    /// Whether the host is alive
    pub is_alive: bool,

    /// RTT if host responded
    pub rtt: Option<Duration>,

    /// Discovery method used
    pub method: DiscoveryMethod,

    /// Additional information
    pub info: Option<String>,
}

/// Discovery method used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMethod {
    IcmpEcho,
    IcmpTimestamp,
    IcmpNetmask,
    ArpRequest,
    TcpSyn,
    TcpAck,
    UdpProbe,
}

impl std::fmt::Display for DiscoveryMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryMethod::IcmpEcho => write!(f, "ICMP Echo"),
            DiscoveryMethod::IcmpTimestamp => write!(f, "ICMP Timestamp"),
            DiscoveryMethod::IcmpNetmask => write!(f, "ICMP Netmask"),
            DiscoveryMethod::ArpRequest => write!(f, "ARP Request"),
            DiscoveryMethod::TcpSyn => write!(f, "TCP SYN"),
            DiscoveryMethod::TcpAck => write!(f, "TCP ACK"),
            DiscoveryMethod::UdpProbe => write!(f, "UDP Probe"),
        }
    }
}

/// Trait for host discovery methods
#[async_trait]
pub trait HostDiscovery: Send + Sync {
    /// Discover if a host is alive
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult>;

    /// Discover multiple hosts concurrently
    async fn discover_many(&self, targets: Vec<IpAddr>) -> Result<Vec<DiscoveryResult>> {
        let mut results = Vec::new();
        for target in targets {
            results.push(self.discover(target).await?);
        }
        Ok(results)
    }

    /// Get the discovery method name
    fn method(&self) -> DiscoveryMethod;
}

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Timeout for each probe
    pub timeout: Duration,

    /// Number of retries
    pub retries: u32,

    /// Enable ICMP discovery
    pub use_icmp: bool,

    /// Enable ARP discovery
    pub use_arp: bool,

    /// Enable TCP discovery
    pub use_tcp: bool,

    /// TCP ports for discovery probes
    pub tcp_ports: Vec<u16>,

    /// Enable UDP discovery
    pub use_udp: bool,

    /// UDP ports for discovery probes
    pub udp_ports: Vec<u16>,

    /// Maximum concurrent probes
    pub max_concurrency: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            retries: 1,
            use_icmp: true,
            use_arp: true,
            use_tcp: true,
            tcp_ports: vec![80, 443],
            use_udp: false,
            udp_ports: vec![],
            max_concurrency: 100,
        }
    }
}
