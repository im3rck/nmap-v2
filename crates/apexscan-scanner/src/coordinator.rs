//! Scan coordinator - manages scanning workflow

use crate::{PortScanResult, PortScanner, ScannerConfig};
use apexscan_core::{
    types::Port,
    Result,
};
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

pub struct ScanCoordinator {
    scanner: Arc<dyn PortScanner>,
    config: ScannerConfig,
}

impl ScanCoordinator {
    pub fn new(scanner: Arc<dyn PortScanner>, config: ScannerConfig) -> Self {
        Self { scanner, config }
    }

    pub async fn scan_target(
        &self,
        target: IpAddr,
        ports: Vec<Port>,
    ) -> Result<Vec<PortScanResult>> {
        info!("Scanning {} with {} ports", target, ports.len());

        let results: Vec<PortScanResult> = stream::iter(ports)
            .map(|port| {
                let scanner = Arc::clone(&self.scanner);
                async move {
                    scanner
                        .scan_port(target, port)
                        .await
                        .unwrap_or_else(|_| PortScanResult {
                            target: apexscan_core::types::Target::new(target),
                            port,
                            protocol: apexscan_core::types::Protocol::Tcp,
                            state: apexscan_core::types::PortState::Unknown,
                            rtt: None,
                            info: Some("Scan error".to_string()),
                        })
                }
            })
            .buffer_unordered(self.config.max_concurrent)
            .collect()
            .await;

        Ok(results)
    }
}
