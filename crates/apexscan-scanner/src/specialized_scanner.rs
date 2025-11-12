//! Specialized TCP Scanners - ACK, Window, Maimon

use crate::{PortScanResult, PortScanner, ScannerConfig};
use apexscan_core::{
    scan::ScanType,
    types::{Port, PortState, Protocol, Target},
    Error, Result,
};
use apexscan_packet::{
    builders::{Ipv4PacketBuilder, TcpPacketBuilder},
    parsers::{parse_ipv4, parse_tcp},
    protocols,
    raw::RawSocket,
    types::TcpFlags,
    PacketBuilder,
};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::timeout;
use tracing::debug;

/// TCP ACK Scanner (-sA)
/// Used for firewall rule mapping
/// Unfiltered: RST response
/// Filtered: No response or ICMP unreachable
pub struct TcpAckScanner {
    config: ScannerConfig,
    socket: Arc<RawSocket>,
    sequence: Arc<AtomicU32>,
}

impl TcpAckScanner {
    pub fn new(config: ScannerConfig) -> Result<Self> {
        let socket = RawSocket::new_ipv4(protocols::TCP)?;
        socket.set_timeout(config.timeout)?;

        Ok(Self {
            config,
            socket: Arc::new(socket),
            sequence: Arc::new(AtomicU32::new(rand::random())),
        })
    }
}

#[async_trait]
impl PortScanner for TcpAckScanner {
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput("IPv6 not yet supported".to_string()))
            }
        };

        debug!("Scanning {}:{} with ACK", target, port.value());

        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let src_port = 40000 + (seq % 20000) as u16;
        let local_ip = Ipv4Addr::new(0, 0, 0, 0);

        let tcp_builder = TcpPacketBuilder::new(local_ip, target_v4, src_port, port.value())
            .flags(TcpFlags::ack())
            .seq(seq)
            .ack(0)
            .window(1024);

        let tcp_packet = tcp_builder.build()?;
        let ipv4_builder = Ipv4PacketBuilder::new(local_ip, target_v4, 6).payload(tcp_packet);
        let packet = ipv4_builder.build()?;

        let start = Instant::now();
        let addr = SocketAddr::new(IpAddr::V4(target_v4), port.value());
        self.socket.send_to(&packet, &addr)?;

        let mut buffer = vec![0u8; 1500];
        let recv_result = timeout(self.config.timeout, async {
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, _)) => {
                        if let Ok(ipv4) = parse_ipv4(&buffer[..size]) {
                            if let Ok(tcp) = parse_tcp(&ipv4.payload) {
                                if tcp.flags.rst {
                                    let rtt = start.elapsed();
                                    // RST = Unfiltered (can't determine open/closed)
                                    return (PortState::Closed, rtt); // Using Closed to mean "unfiltered"
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        })
        .await;

        let (state, rtt_option) = match recv_result {
            Ok((_, rtt)) => (PortState::Closed, Some(rtt)), // Unfiltered
            Err(_) => (PortState::Filtered, None),
        };

        Ok(PortScanResult {
            target: Target::new(target),
            port,
            protocol: Protocol::Tcp,
            state,
            rtt: rtt_option,
            info: Some(if state == PortState::Closed {
                "unfiltered".to_string()
            } else {
                "filtered".to_string()
            }),
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
        ScanType::TcpAck
    }
}

/// TCP Window Scanner (-sW)
/// Similar to ACK scan but examines window field in RST
pub struct TcpWindowScanner {
    config: ScannerConfig,
    socket: Arc<RawSocket>,
    sequence: Arc<AtomicU32>,
}

impl TcpWindowScanner {
    pub fn new(config: ScannerConfig) -> Result<Self> {
        let socket = RawSocket::new_ipv4(protocols::TCP)?;
        socket.set_timeout(config.timeout)?;

        Ok(Self {
            config,
            socket: Arc::new(socket),
            sequence: Arc::new(AtomicU32::new(rand::random())),
        })
    }
}

#[async_trait]
impl PortScanner for TcpWindowScanner {
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput("IPv6 not yet supported".to_string()))
            }
        };

        debug!("Scanning {}:{} with Window", target, port.value());

        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let src_port = 40000 + (seq % 20000) as u16;
        let local_ip = Ipv4Addr::new(0, 0, 0, 0);

        let tcp_builder = TcpPacketBuilder::new(local_ip, target_v4, src_port, port.value())
            .flags(TcpFlags::ack())
            .seq(seq)
            .ack(0)
            .window(1024);

        let tcp_packet = tcp_builder.build()?;
        let ipv4_builder = Ipv4PacketBuilder::new(local_ip, target_v4, 6).payload(tcp_packet);
        let packet = ipv4_builder.build()?;

        let start = Instant::now();
        let addr = SocketAddr::new(IpAddr::V4(target_v4), port.value());
        self.socket.send_to(&packet, &addr)?;

        let mut buffer = vec![0u8; 1500];
        let recv_result = timeout(self.config.timeout, async {
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, _)) => {
                        if let Ok(ipv4) = parse_ipv4(&buffer[..size]) {
                            if let Ok(tcp) = parse_tcp(&ipv4.payload) {
                                if tcp.flags.rst {
                                    let rtt = start.elapsed();
                                    // Non-zero window = Open
                                    // Zero window = Closed
                                    let state = if tcp.window > 0 {
                                        PortState::Open
                                    } else {
                                        PortState::Closed
                                    };
                                    return (state, rtt);
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        })
        .await;

        let (state, rtt_option) = match recv_result {
            Ok((state, rtt)) => (state, Some(rtt)),
            Err(_) => (PortState::Filtered, None),
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
        ScanType::TcpWindow
    }
}

/// TCP Maimon Scanner (-sM)
/// Sends FIN/ACK combination
pub struct TcpMaimonScanner {
    config: ScannerConfig,
    socket: Arc<RawSocket>,
    sequence: Arc<AtomicU32>,
}

impl TcpMaimonScanner {
    pub fn new(config: ScannerConfig) -> Result<Self> {
        let socket = RawSocket::new_ipv4(protocols::TCP)?;
        socket.set_timeout(config.timeout)?;

        Ok(Self {
            config,
            socket: Arc::new(socket),
            sequence: Arc::new(AtomicU32::new(rand::random())),
        })
    }
}

#[async_trait]
impl PortScanner for TcpMaimonScanner {
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput("IPv6 not yet supported".to_string()))
            }
        };

        debug!("Scanning {}:{} with Maimon", target, port.value());

        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let src_port = 40000 + (seq % 20000) as u16;
        let local_ip = Ipv4Addr::new(0, 0, 0, 0);

        // FIN/ACK combination
        let mut flags = TcpFlags::fin();
        flags.ack = true;

        let tcp_builder = TcpPacketBuilder::new(local_ip, target_v4, src_port, port.value())
            .flags(flags)
            .seq(seq)
            .ack(0)
            .window(1024);

        let tcp_packet = tcp_builder.build()?;
        let ipv4_builder = Ipv4PacketBuilder::new(local_ip, target_v4, 6).payload(tcp_packet);
        let packet = ipv4_builder.build()?;

        let start = Instant::now();
        let addr = SocketAddr::new(IpAddr::V4(target_v4), port.value());
        self.socket.send_to(&packet, &addr)?;

        let mut buffer = vec![0u8; 1500];
        let recv_result = timeout(self.config.timeout, async {
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, _)) => {
                        if let Ok(ipv4) = parse_ipv4(&buffer[..size]) {
                            if let Ok(tcp) = parse_tcp(&ipv4.payload) {
                                if tcp.flags.rst {
                                    let rtt = start.elapsed();
                                    return (PortState::Closed, rtt);
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        })
        .await;

        let (state, rtt_option) = match recv_result {
            Ok((state, rtt)) => (state, Some(rtt)),
            Err(_) => (PortState::OpenFiltered, None),
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
        ScanType::TcpMaimon
    }
}

mod rand {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEED: AtomicU32 = AtomicU32::new(192837465);

    pub fn random() -> u32 {
        let mut seed = SEED.load(Ordering::Relaxed);
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        SEED.store(seed, Ordering::Relaxed);
        seed
    }
}
