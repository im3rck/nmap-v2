//! UDP Scanner - Challenging scan type due to ICMP Port Unreachable reliance

use crate::{PortScanResult, PortScanner, ScannerConfig};
use apexscan_core::{
    scan::ScanType,
    types::{Port, PortState, Protocol, Target},
    Error, Result,
};
use apexscan_packet::{
    builders::{Ipv4PacketBuilder, UdpPacketBuilder},
    parsers::{parse_icmp, parse_ipv4},
    protocols,
    raw::RawSocket,
    types::IcmpType,
    PacketBuilder,
};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace};

/// UDP Scanner (-sU)
/// 
/// UDP scanning is challenging because:
/// - Open ports often don't respond
/// - Closed ports send ICMP Port Unreachable
/// - Filtered ports remain silent (like open ports)
/// - Rate limiting on ICMP responses
pub struct UdpScanner {
    config: ScannerConfig,
}

impl UdpScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    /// Send UDP probe and listen for ICMP unreachable
    async fn probe_udp(&self, target: Ipv4Addr, port: u16) -> Result<(PortState, Option<Duration>)> {
        // Bind UDP socket for sending
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let udp_socket = UdpSocket::bind(local_addr).await
            .map_err(|e| Error::Network(format!("Failed to bind UDP socket: {}", e)))?;

        // Create ICMP socket for receiving unreachable messages
        let icmp_socket = RawSocket::new_ipv4(protocols::ICMP)?;
        icmp_socket.set_timeout(self.config.timeout)?;

        let start = Instant::now();

        // Send UDP probe (empty or with common protocol-specific payload)
        let payload = Self::get_udp_payload(port);
        let target_addr = SocketAddr::new(IpAddr::V4(target), port);
        
        udp_socket.send_to(&payload, target_addr).await
            .map_err(|e| Error::Network(format!("Failed to send UDP: {}", e)))?;

        trace!("Sent UDP probe to {}:{}", target, port);

        // Listen for ICMP Port Unreachable (Type 3, Code 3)
        let mut buffer = vec![0u8; 1500];
        
        let recv_result = timeout(self.config.timeout, async {
            loop {
                match icmp_socket.recv_from(&mut buffer) {
                    Ok((size, _)) => {
                        // Parse IPv4 to get to ICMP
                        if let Ok(ipv4) = parse_ipv4(&buffer[..size]) {
                            if ipv4.protocol == 1 { // ICMP
                                if let Ok(icmp) = parse_icmp(&ipv4.payload) {
                                    if icmp.icmp_type == IcmpType::DestinationUnreachable {
                                        // Code 3 = Port Unreachable
                                        if icmp.code == 3 {
                                            let rtt = start.elapsed();
                                            trace!("Received ICMP Port Unreachable for port {}", port);
                                            return Ok((PortState::Closed, Some(rtt)));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        })
        .await;

        match recv_result {
            Ok(state_rtt) => state_rtt,
            Err(_) => {
                // No ICMP response -> Open|Filtered
                // Could be open, filtered, or rate-limited ICMP
                Ok((PortState::OpenFiltered, None))
            }
        }
    }

    /// Get protocol-specific UDP payload for common services
    fn get_udp_payload(port: u16) -> Vec<u8> {
        match port {
            53 => {
                // DNS query for version.bind
                vec![
                    0x00, 0x00, // Transaction ID
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs: 0
                    0x00, 0x00, // Authority RRs: 0
                    0x00, 0x00, // Additional RRs: 0
                ]
            }
            161 => {
                // SNMP GetRequest for sysDescr.0
                vec![
                    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
                    0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
                ]
            }
            _ => {
                // Generic empty probe
                vec![]
            }
        }
    }
}

#[async_trait]
impl PortScanner for UdpScanner {
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput("IPv6 not yet supported".to_string()))
            }
        };

        debug!("Scanning {}:{}/udp", target, port.value());

        let (state, rtt) = self.probe_udp(target_v4, port.value()).await?;

        Ok(PortScanResult {
            target: Target::new(target),
            port,
            protocol: Protocol::Udp,
            state,
            rtt,
            info: None,
        })
    }

    async fn scan_ports(&self, target: IpAddr, ports: Vec<Port>) -> Result<Vec<PortScanResult>> {
        let mut results = Vec::new();
        
        // UDP scanning should be slower due to rate limiting
        for port in ports {
            let result = self.scan_port(target, port).await?;
            results.push(result);
            
            // Add delay between UDP probes to avoid rate limiting
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        Ok(results)
    }

    fn scan_type(&self) -> ScanType {
        ScanType::Udp
    }
}
