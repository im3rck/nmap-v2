//! ICMP-based host discovery
//!
//! Implements ICMP Echo, Timestamp, and Netmask discovery methods.

use crate::{DiscoveryMethod, DiscoveryResult, HostDiscovery};
use apexscan_core::{types::Target, Error, Result};
use apexscan_packet::{
    builders::{IcmpPacketBuilder, Ipv4PacketBuilder},
    parsers::parse_icmp,
    raw::RawSocket,
    types::IcmpType,
    PacketBuilder,
};
use async_trait::async_trait;
use socket2::Protocol;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, trace};

/// ICMP Echo discovery
pub struct IcmpEchoDiscovery {
    timeout: Duration,
    socket: Arc<RawSocket>,
    sequence: Arc<AtomicU16>,
}

impl IcmpEchoDiscovery {
    pub fn new(timeout_duration: Duration) -> Result<Self> {
        let socket = RawSocket::new_ipv4(Protocol::ICMPV4)?;
        socket.set_timeout(timeout_duration)?;

        Ok(Self {
            timeout: timeout_duration,
            socket: Arc::new(socket),
            sequence: Arc::new(AtomicU16::new(1)),
        })
    }

    async fn send_echo_request(&self, target: Ipv4Addr) -> Result<u16> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);

        // Build ICMP Echo Request
        let icmp_builder = IcmpPacketBuilder::echo_request(
            std::process::id() as u16, // Use PID as ID
            seq,
        );

        let icmp_packet = icmp_builder.build()?;

        // Build IPv4 packet
        let local_ip = Ipv4Addr::new(0, 0, 0, 0); // Kernel will fill this
        let ipv4_builder = Ipv4PacketBuilder::new(local_ip, target, 1) // Protocol 1 = ICMP
            .payload(icmp_packet);

        let packet = ipv4_builder.build()?;

        // Send packet
        let addr = SocketAddr::new(IpAddr::V4(target), 0);
        self.socket.send_to(&packet, &addr)?;

        trace!("Sent ICMP Echo Request to {} (seq={})", target, seq);

        Ok(seq)
    }

    async fn recv_echo_reply(&self, expected_seq: u16) -> Result<Duration> {
        let start = Instant::now();
        let mut buffer = vec![0u8; 1024];

        // Try to receive with timeout
        let recv_result = timeout(self.timeout, async {
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, _addr)) => {
                        // Parse IPv4 header to get to ICMP
                        if size < 20 {
                            continue;
                        }

                        // ICMP starts after IPv4 header (typically 20 bytes)
                        let ihl = (buffer[0] & 0x0F) as usize * 4;
                        if size < ihl + 8 {
                            continue;
                        }

                        let icmp_data = &buffer[ihl..size];

                        match parse_icmp(icmp_data) {
                            Ok(icmp) => {
                                if icmp.icmp_type == IcmpType::EchoReply {
                                    // Extract sequence from payload
                                    if icmp.payload.len() >= 4 {
                                        let recv_seq = u16::from_be_bytes([
                                            icmp.payload[2],
                                            icmp.payload[3],
                                        ]);

                                        if recv_seq == expected_seq {
                                            let rtt = start.elapsed();
                                            trace!("Received ICMP Echo Reply (seq={}, rtt={:?})", recv_seq, rtt);
                                            return Ok(rtt);
                                        }
                                    }
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    Err(_) => continue,
                }
            }
        })
        .await;

        match recv_result {
            Ok(rtt) => rtt,
            Err(_) => Err(Error::Timeout),
        }
    }
}

#[async_trait]
impl HostDiscovery for IcmpEchoDiscovery {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput(
                    "IPv6 not yet supported for ICMP discovery".to_string(),
                ))
            }
        };

        debug!("Discovering {} via ICMP Echo", target);

        let seq = self.send_echo_request(target_v4).await?;

        match self.recv_echo_reply(seq).await {
            Ok(rtt) => {
                debug!("Host {} is UP (RTT: {:?})", target, rtt);
                Ok(DiscoveryResult {
                    target: Target::new(target),
                    is_alive: true,
                    rtt: Some(rtt),
                    method: DiscoveryMethod::IcmpEcho,
                    info: Some(format!("ICMP Echo Reply received")),
                })
            }
            Err(_) => {
                debug!("Host {} is DOWN (no ICMP reply)", target);
                Ok(DiscoveryResult {
                    target: Target::new(target),
                    is_alive: false,
                    rtt: None,
                    method: DiscoveryMethod::IcmpEcho,
                    info: Some(format!("No ICMP Echo Reply")),
                })
            }
        }
    }

    fn method(&self) -> DiscoveryMethod {
        DiscoveryMethod::IcmpEcho
    }
}

/// ICMP Timestamp discovery
pub struct IcmpTimestampDiscovery {
    timeout: Duration,
    socket: Arc<RawSocket>,
    sequence: Arc<AtomicU16>,
}

impl IcmpTimestampDiscovery {
    pub fn new(timeout_duration: Duration) -> Result<Self> {
        let socket = RawSocket::new_ipv4(Protocol::ICMPV4)?;
        socket.set_timeout(timeout_duration)?;

        Ok(Self {
            timeout: timeout_duration,
            socket: Arc::new(socket),
            sequence: Arc::new(AtomicU16::new(1)),
        })
    }
}

#[async_trait]
impl HostDiscovery for IcmpTimestampDiscovery {
    async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput(
                    "IPv6 not yet supported".to_string(),
                ))
            }
        };

        debug!("Discovering {} via ICMP Timestamp", target);

        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);

        // Build ICMP Timestamp Request (Type 13)
        let mut icmp_builder = IcmpPacketBuilder::new(IcmpType::TimestampRequest, 0);

        // Add identifier and sequence
        let mut payload = Vec::new();
        payload.extend_from_slice(&(std::process::id() as u16).to_be_bytes());
        payload.extend_from_slice(&seq.to_be_bytes());
        // Add timestamps (set to 0 for request)
        payload.extend_from_slice(&0u32.to_be_bytes()); // Originate timestamp
        payload.extend_from_slice(&0u32.to_be_bytes()); // Receive timestamp
        payload.extend_from_slice(&0u32.to_be_bytes()); // Transmit timestamp

        icmp_builder = icmp_builder.payload(payload);
        let icmp_packet = icmp_builder.build()?;

        // Build IPv4 packet
        let local_ip = Ipv4Addr::new(0, 0, 0, 0);
        let ipv4_builder = Ipv4PacketBuilder::new(local_ip, target_v4, 1)
            .payload(icmp_packet);

        let packet = ipv4_builder.build()?;

        // Send packet
        let start = Instant::now();
        let addr = SocketAddr::new(IpAddr::V4(target_v4), 0);
        self.socket.send_to(&packet, &addr)?;

        // Try to receive reply (Type 14)
        let mut buffer = vec![0u8; 1024];
        let recv_result = timeout(self.timeout, async {
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, _)) => {
                        if size < 20 {
                            continue;
                        }
                        let ihl = (buffer[0] & 0x0F) as usize * 4;
                        if size < ihl + 8 {
                            continue;
                        }

                        let icmp_data = &buffer[ihl..size];
                        match parse_icmp(icmp_data) {
                            Ok(icmp) => {
                                if icmp.icmp_type == IcmpType::TimestampReply {
                                    return Ok(start.elapsed());
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    Err(_) => continue,
                }
            }
        })
        .await;

        match recv_result {
            Ok(rtt) => Ok(DiscoveryResult {
                target: Target::new(target),
                is_alive: true,
                rtt: Some(rtt),
                method: DiscoveryMethod::IcmpTimestamp,
                info: Some("ICMP Timestamp Reply received".to_string()),
            }),
            Err(_) => Ok(DiscoveryResult {
                target: Target::new(target),
                is_alive: false,
                rtt: None,
                method: DiscoveryMethod::IcmpTimestamp,
                info: Some("No ICMP Timestamp Reply".to_string()),
            }),
        }
    }

    fn method(&self) -> DiscoveryMethod {
        DiscoveryMethod::IcmpTimestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires root/CAP_NET_RAW
    async fn test_icmp_echo_localhost() {
        let discovery = IcmpEchoDiscovery::new(Duration::from_secs(2)).unwrap();
        let result = discovery
            .discover(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .await
            .unwrap();

        assert!(result.is_alive);
        assert!(result.rtt.is_some());
    }
}
