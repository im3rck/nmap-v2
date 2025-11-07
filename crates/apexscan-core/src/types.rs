//! Common type definitions

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

/// Target specification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    /// IP address of the target
    pub ip: IpAddr,

    /// Optional hostname
    pub hostname: Option<String>,

    /// MAC address (if known)
    pub mac: Option<MacAddr>,
}

impl Target {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            hostname: None,
            mac: None,
        }
    }

    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    pub fn with_mac(mut self, mac: MacAddr) -> Self {
        self.mac = Some(mac);
        self
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(hostname) = &self.hostname {
            write!(f, "{} ({})", hostname, self.ip)
        } else {
            write!(f, "{}", self.ip)
        }
    }
}

/// MAC address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Port number (1-65535)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Port(u16);

impl Port {
    pub fn new(port: u16) -> Option<Self> {
        if port == 0 {
            None
        } else {
            Some(Port(port))
        }
    }

    pub fn value(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Port> for u16 {
    fn from(port: Port) -> u16 {
        port.0
    }
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Sctp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Sctp => write!(f, "SCTP"),
        }
    }
}

/// Port state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    /// Port is open and accepting connections
    Open,

    /// Port is closed
    Closed,

    /// Port is filtered (firewall or other filtering)
    Filtered,

    /// Port is open or filtered (cannot determine)
    OpenFiltered,

    /// Port is closed or filtered (cannot determine)
    ClosedFiltered,

    /// Port state is unknown
    Unknown,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
            PortState::ClosedFiltered => write!(f, "closed|filtered"),
            PortState::Unknown => write!(f, "unknown"),
        }
    }
}

/// Host state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostState {
    /// Host is up and responding
    Up,

    /// Host is down or not responding
    Down,

    /// Host state is unknown
    Unknown,
}

impl fmt::Display for HostState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostState::Up => write!(f, "up"),
            HostState::Down => write!(f, "down"),
            HostState::Unknown => write!(f, "unknown"),
        }
    }
}

/// Timing template (like Nmap's -T)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingTemplate {
    /// Paranoid (T0) - very slow, IDS evasion
    T0,

    /// Sneaky (T1) - slow, IDS evasion
    T1,

    /// Polite (T2) - slow, less bandwidth
    T2,

    /// Normal (T3) - default
    T3,

    /// Aggressive (T4) - fast, assumes fast network
    T4,

    /// Insane (T5) - very fast, may miss results
    T5,
}

impl TimingTemplate {
    /// Get the base RTT timeout for this timing template
    pub fn base_rtt_timeout(&self) -> Duration {
        match self {
            TimingTemplate::T0 => Duration::from_millis(5000),
            TimingTemplate::T1 => Duration::from_millis(3000),
            TimingTemplate::T2 => Duration::from_millis(1000),
            TimingTemplate::T3 => Duration::from_millis(500),
            TimingTemplate::T4 => Duration::from_millis(200),
            TimingTemplate::T5 => Duration::from_millis(100),
        }
    }

    /// Get the maximum parallelism for this timing template
    pub fn max_parallelism(&self) -> usize {
        match self {
            TimingTemplate::T0 => 1,
            TimingTemplate::T1 => 10,
            TimingTemplate::T2 => 50,
            TimingTemplate::T3 => 100,
            TimingTemplate::T4 => 1000,
            TimingTemplate::T5 => 5000,
        }
    }

    /// Get the scan delay between probes
    pub fn scan_delay(&self) -> Duration {
        match self {
            TimingTemplate::T0 => Duration::from_millis(5000),
            TimingTemplate::T1 => Duration::from_millis(1000),
            TimingTemplate::T2 => Duration::from_millis(400),
            TimingTemplate::T3 => Duration::from_millis(0),
            TimingTemplate::T4 => Duration::from_millis(0),
            TimingTemplate::T5 => Duration::from_millis(0),
        }
    }
}

impl Default for TimingTemplate {
    fn default() -> Self {
        TimingTemplate::T3
    }
}

impl fmt::Display for TimingTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimingTemplate::T0 => write!(f, "T0 (Paranoid)"),
            TimingTemplate::T1 => write!(f, "T1 (Sneaky)"),
            TimingTemplate::T2 => write!(f, "T2 (Polite)"),
            TimingTemplate::T3 => write!(f, "T3 (Normal)"),
            TimingTemplate::T4 => write!(f, "T4 (Aggressive)"),
            TimingTemplate::T5 => write!(f, "T5 (Insane)"),
        }
    }
}
