//! UDP-based host discovery

use crate::{DiscoveryMethod, DiscoveryResult, HostDiscovery};
use apexscan_core::{types::Target, Error, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

/// UDP probe-based discovery
pub struct UdpDiscovery {
    timeout: Duration,
    ports: Vec<u16>,
}

impl UdpDiscovery {
    pub fn new(timeout_duration: Duration, ports: Vec<u16>) -> Result<Self> {
        Ok(Self {
            timeout: timeout_duration,
            ports,
        })
    }
}

#[async_trait]
impl HostDiscovery for UdpDiscovery {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult> {
        // TODO: Implement UDP discovery
        // UDP discovery is tricky because we need to look for ICMP port unreachable
        // messages, which indicates the host is alive but port is closed
        Ok(DiscoveryResult {
            target: Target::new(target),
            is_alive: false,
            rtt: None,
            method: DiscoveryMethod::UdpProbe,
            info: Some("UDP discovery not yet implemented".to_string()),
        })
    }

    fn method(&self) -> DiscoveryMethod {
        DiscoveryMethod::UdpProbe
    }
}
