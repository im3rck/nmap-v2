//! Discovery coordinator - manages multiple discovery methods

use crate::{DiscoveryConfig, DiscoveryResult, HostDiscovery};
use apexscan_core::Result;
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

pub struct DiscoveryCoordinator {
    config: DiscoveryConfig,
    methods: Vec<Arc<dyn HostDiscovery>>,
}

impl DiscoveryCoordinator {
    pub fn new(config: DiscoveryConfig) -> Result<Self> {
        let mut methods: Vec<Arc<dyn HostDiscovery>> = Vec::new();

        // Add ICMP discovery if enabled
        if config.use_icmp {
            let icmp = crate::icmp::IcmpEchoDiscovery::new(config.timeout)?;
            methods.push(Arc::new(icmp));
        }

        // Add ARP discovery if enabled
        if config.use_arp {
            let arp = crate::arp::ArpDiscovery::new(config.timeout)?;
            methods.push(Arc::new(arp));
        }

        // Add TCP discovery if enabled
        if config.use_tcp && !config.tcp_ports.is_empty() {
            let tcp = crate::tcp::TcpSynDiscovery::new(
                config.timeout,
                config.tcp_ports.clone(),
            )?;
            methods.push(Arc::new(tcp));
        }

        Ok(Self { config, methods })
    }

    pub async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult> {
        debug!("Starting discovery for {}", target);

        // Try each discovery method until one succeeds
        for method in &self.methods {
            let result = method.discover(target).await?;
            if result.is_alive {
                return Ok(result);
            }
        }

        // If no method found the host alive, return the last result
        if let Some(method) = self.methods.last() {
            method.discover(target).await
        } else {
            Err(apexscan_core::Error::Config(
                "No discovery methods configured".to_string(),
            ))
        }
    }

    pub async fn discover_many(&self, targets: Vec<IpAddr>) -> Result<Vec<DiscoveryResult>> {
        let max_concurrency = self.config.max_concurrency;

        let results: Vec<DiscoveryResult> = stream::iter(targets)
            .map(|target| async move {
                self.discover(target).await.unwrap_or_else(|_| {
                    DiscoveryResult {
                        target: apexscan_core::types::Target::new(target),
                        is_alive: false,
                        rtt: None,
                        method: crate::DiscoveryMethod::IcmpEcho,
                        info: Some("Discovery failed".to_string()),
                    }
                })
            })
            .buffer_unordered(max_concurrency)
            .collect()
            .await;

        Ok(results)
    }
}
