//! TCP SYN Scanner - High-performance SYN scanning using raw sockets

use crate::{PortScanResult, PortScanner, ScannerConfig};
use apexscan_core::{
    scan::ScanType,
    types::{Port, PortState, Protocol, Target},
    Error, Result,
};
use apexscan_packet::{
    builders::{Ipv4PacketBuilder, TcpPacketBuilder},
    parsers::{parse_ipv4, parse_tcp},
    raw::RawSocket,
    types::TcpFlags,
    PacketBuilder,
};
use async_trait::async_trait;
use socket2::Protocol as SocketProtocol;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, trace};

/// TCP SYN Scanner
pub struct TcpSynScanner {
    config: ScannerConfig,
    socket: Arc<RawSocket>,
    sequence: Arc<AtomicU32>,
}

impl TcpSynScanner {
    pub fn new(config: ScannerConfig) -> Result<Self> {
        let socket = RawSocket::new_ipv4(SocketProtocol::TCP)?;
        socket.set_timeout(config.timeout)?;

        Ok(Self {
            config,
            socket: Arc::new(socket),
            sequence: Arc::new(AtomicU32::new(rand::random())),
        })
    }

    async fn send_syn(&self, target: Ipv4Addr, port: u16) -> Result<(u32, u16)> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let src_port = 40000 + (seq % 20000) as u16;
        let local_ip = Ipv4Addr::new(0, 0, 0, 0);

        // Build TCP SYN packet
        let tcp_builder = TcpPacketBuilder::new(local_ip, target, src_port, port)
            .flags(TcpFlags::syn())
            .seq(seq)
            .window(65535);

        let tcp_packet = tcp_builder.build()?;

        // Build IPv4 packet
        let ipv4_builder = Ipv4PacketBuilder::new(local_ip, target, 6)
            .payload(tcp_packet);

        let packet = ipv4_builder.build()?;

        // Send packet
        let addr = SocketAddr::new(IpAddr::V4(target), port);
        self.socket.send_to(&packet, &addr)?;

        trace!("Sent SYN to {}:{} (seq={})", target, port, seq);

        Ok((seq, src_port))
    }

    async fn recv_response(&self, expected_seq: u32, src_port: u16) -> Result<(PortState, Duration)> {
        let start = Instant::now();
        let mut buffer = vec![0u8; 1500];

        let recv_result = timeout(self.config.timeout, async {
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, _)) => {
                        if let Ok(ipv4) = parse_ipv4(&buffer[..size]) {
                            if let Ok(tcp) = parse_tcp(&ipv4.payload) {
                                // Check if this is a response to our SYN
                                if tcp.src_port == src_port as u16 {
                                    let rtt = start.elapsed();

                                    if tcp.flags.syn && tcp.flags.ack {
                                        // SYN-ACK received -> port is OPEN
                                        trace!("Received SYN-ACK from port {} (RTT: {:?})", src_port, rtt);
                                        return Ok((PortState::Open, rtt));
                                    } else if tcp.flags.rst {
                                        // RST received -> port is CLOSED
                                        trace!("Received RST from port {} (RTT: {:?})", src_port, rtt);
                                        return Ok((PortState::Closed, rtt));
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
            Err(_) => Ok((PortState::Filtered, Duration::from_secs(0))),
        }
    }
}

#[async_trait]
impl PortScanner for TcpSynScanner {
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput("IPv6 not yet supported".to_string()))
            }
        };

        debug!("Scanning {}:{} with SYN", target, port.value());

        let (seq, src_port) = self.send_syn(target_v4, port.value()).await?;
        let (state, rtt) = self.recv_response(seq, src_port).await?;

        let rtt_option = if state != PortState::Filtered {
            Some(rtt)
        } else {
            None
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
        ScanType::TcpSyn
    }
}

// Simple random number generator (replace with proper rand crate in production)
mod rand {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEED: AtomicU32 = AtomicU32::new(123456789);

    pub fn random() -> u32 {
        let mut seed = SEED.load(Ordering::Relaxed);
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        SEED.store(seed, Ordering::Relaxed);
        seed
    }
}
