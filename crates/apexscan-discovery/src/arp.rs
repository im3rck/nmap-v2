//! ARP-based host discovery

use crate::{DiscoveryMethod, DiscoveryResult, HostDiscovery};
use apexscan_core::{types::Target, Error, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

pub struct ArpDiscovery {
    timeout: Duration,
}

impl ArpDiscovery {
    pub fn new(timeout_duration: Duration) -> Result<Self> {
        Ok(Self { timeout: timeout_duration })
    }
}

#[async_trait]
impl HostDiscovery for ArpDiscovery {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult> {
        // TODO: Full ARP implementation (requires pnet datalink)
        Ok(DiscoveryResult {
            target: Target::new(target),
            is_alive: false,
            rtt: None,
            method: DiscoveryMethod::ArpRequest,
            info: Some("ARP discovery requires pnet integration".to_string()),
        })
    }

    fn method(&self) -> DiscoveryMethod {
        DiscoveryMethod::ArpRequest
    }
}
