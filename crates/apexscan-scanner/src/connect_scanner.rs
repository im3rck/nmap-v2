//! TCP Connect Scanner - Fallback scanner using OS TCP stack

use crate::{PortScanResult, PortScanner, ScannerConfig};
use apexscan_core::{
    scan::ScanType,
    types::{Port, PortState, Protocol, Target},
    Result,
};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

/// TCP Connect Scanner
pub struct TcpConnectScanner {
    config: ScannerConfig,
}

impl TcpConnectScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl PortScanner for TcpConnectScanner {
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult> {
        debug!("Scanning {}:{} with Connect", target, port.value());

        let addr = SocketAddr::new(target, port.value());
        let start = Instant::now();

        let result = timeout(self.config.timeout, TcpStream::connect(addr)).await;

        let (state, rtt_option) = match result {
            Ok(Ok(_stream)) => {
                // Connection succeeded -> port is OPEN
                let rtt = start.elapsed();
                (PortState::Open, Some(rtt))
            }
            Ok(Err(_)) => {
                // Connection refused -> port is CLOSED
                let rtt = start.elapsed();
                (PortState::Closed, Some(rtt))
            }
            Err(_) => {
                // Timeout -> port is FILTERED
                (PortState::Filtered, None)
            }
        };

        Ok(PortScanResult {
            target: Target::new(target),
            port,
            protocol: Protocol::Tcp,
            state,
            rtt: rtt_option,
            info: None,
        })
    }

    async fn scan_ports(&self, target: IpAddr, ports: Vec<Port>) -> Result<Vec<PortScanResult>> {
        let mut results = Vec::new();
        for port in ports {
            let result = self.scan_port(target, port).await?;
            results.push(result);
        }
        Ok(results)
    }

    fn scan_type(&self) -> ScanType {
        ScanType::TcpConnect
    }
}
