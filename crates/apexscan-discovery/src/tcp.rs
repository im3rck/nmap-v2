//! TCP-based host discovery

use crate::{DiscoveryMethod, DiscoveryResult, HostDiscovery};
use apexscan_core::{types::Target, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

pub struct TcpSynDiscovery {
    timeout: Duration,
    ports: Vec<u16>,
}

impl TcpSynDiscovery {
    pub fn new(timeout_duration: Duration, ports: Vec<u16>) -> Result<Self> {
        Ok(Self {
            timeout: timeout_duration,
            ports,
        })
    }
}

#[async_trait]
impl HostDiscovery for TcpSynDiscovery {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult> {
        // TODO: Implement TCP SYN probes
        Ok(DiscoveryResult {
            target: Target::new(target),
            is_alive: false,
            rtt: None,
            method: DiscoveryMethod::TcpSyn,
            info: Some("TCP SYN discovery pending full implementation".to_string()),
        })
    }

    fn method(&self) -> DiscoveryMethod {
        DiscoveryMethod::TcpSyn
    }
}
