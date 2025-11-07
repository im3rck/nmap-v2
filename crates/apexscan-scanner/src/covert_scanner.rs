//! Covert TCP Scanners - NULL, FIN, Xmas
//!
//! These scanners exploit RFC 793 behavior where closed ports respond with RST
//! and open/filtered ports remain silent.

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
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, trace};

/// TCP NULL Scanner (-sN)
/// Sends packets with no flags set
/// Open/Filtered: No response
/// Closed: RST response
pub struct TcpNullScanner {
    config: ScannerConfig,
    socket: Arc<RawSocket>,
    sequence: Arc<AtomicU32>,
}

impl TcpNullScanner {
    pub fn new(config: ScannerConfig) -> Result<Self> {
        let socket = RawSocket::new_ipv4(protocols::TCP)?;
        socket.set_timeout(config.timeout)?;

        Ok(Self {
            config,
            socket: Arc::new(socket),
            sequence: Arc::new(AtomicU32::new(rand::random())),
        })
    }

    async fn send_null(&self, target: Ipv4Addr, port: u16) -> Result<(u32, u16)> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let src_port = 40000 + (seq % 20000) as u16;
        let local_ip = Ipv4Addr::new(0, 0, 0, 0);

        // Build TCP packet with NULL flags (no flags set)
        let tcp_builder = TcpPacketBuilder::new(local_ip, target, src_port, port)
            .flags(TcpFlags::null())
            .seq(seq)
            .window(1024);

        let tcp_packet = tcp_builder.build()?;
        let ipv4_builder = Ipv4PacketBuilder::new(local_ip, target, 6).payload(tcp_packet);
        let packet = ipv4_builder.build()?;

        let addr = SocketAddr::new(IpAddr::V4(target), port);
        self.socket.send_to(&packet, &addr)?;

        trace!("Sent NULL to {}:{} (seq={})", target, port, seq);

        Ok((seq, src_port))
    }

    async fn recv_response(&self, _seq: u32, _src_port: u16) -> Result<(PortState, Duration)> {
        let start = Instant::now();
        let mut buffer = vec![0u8; 1500];

        let recv_result = timeout(self.config.timeout, async {
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, _)) => {
                        if let Ok(ipv4) = parse_ipv4(&buffer[..size]) {
                            if let Ok(tcp) = parse_tcp(&ipv4.payload) {
                                if tcp.flags.rst {
                                    // RST received -> port is CLOSED
                                    let rtt = start.elapsed();
                                    trace!("Received RST (NULL scan), port CLOSED");
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

        match recv_result {
            Ok(state_rtt) => Ok(state_rtt),
            Err(_) => {
                // No response -> Open|Filtered
                Ok((PortState::OpenFiltered, Duration::from_secs(0)))
            }
        }
    }
}

#[async_trait]
impl PortScanner for TcpNullScanner {
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput("IPv6 not yet supported".to_string()))
            }
        };

        debug!("Scanning {}:{} with NULL", target, port.value());

        let (seq, src_port) = self.send_null(target_v4, port.value()).await?;
        let (state, rtt) = self.recv_response(seq, src_port).await?;

        let rtt_option = if state != PortState::OpenFiltered {
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
        ScanType::TcpNull
    }
}

/// TCP FIN Scanner (-sF)
/// Sends packets with only FIN flag set
pub struct TcpFinScanner {
    config: ScannerConfig,
    socket: Arc<RawSocket>,
    sequence: Arc<AtomicU32>,
}

impl TcpFinScanner {
    pub fn new(config: ScannerConfig) -> Result<Self> {
        let socket = RawSocket::new_ipv4(protocols::TCP)?;
        socket.set_timeout(config.timeout)?;

        Ok(Self {
            config,
            socket: Arc::new(socket),
            sequence: Arc::new(AtomicU32::new(rand::random())),
        })
    }

    async fn send_fin(&self, target: Ipv4Addr, port: u16) -> Result<(u32, u16)> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let src_port = 40000 + (seq % 20000) as u16;
        let local_ip = Ipv4Addr::new(0, 0, 0, 0);

        let tcp_builder = TcpPacketBuilder::new(local_ip, target, src_port, port)
            .flags(TcpFlags::fin())
            .seq(seq)
            .window(1024);

        let tcp_packet = tcp_builder.build()?;
        let ipv4_builder = Ipv4PacketBuilder::new(local_ip, target, 6).payload(tcp_packet);
        let packet = ipv4_builder.build()?;

        let addr = SocketAddr::new(IpAddr::V4(target), port);
        self.socket.send_to(&packet, &addr)?;

        trace!("Sent FIN to {}:{} (seq={})", target, port, seq);

        Ok((seq, src_port))
    }
}

#[async_trait]
impl PortScanner for TcpFinScanner {
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput("IPv6 not yet supported".to_string()))
            }
        };

        debug!("Scanning {}:{} with FIN", target, port.value());

        let (seq, src_port) = self.send_fin(target_v4, port.value()).await?;
        
        // Same response logic as NULL scan
        let start = Instant::now();
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
        ScanType::TcpFin
    }
}

/// TCP Xmas Scanner (-sX)
/// Sends packets with FIN, PSH, URG flags set ("lit up like a Christmas tree")
pub struct TcpXmasScanner {
    config: ScannerConfig,
    socket: Arc<RawSocket>,
    sequence: Arc<AtomicU32>,
}

impl TcpXmasScanner {
    pub fn new(config: ScannerConfig) -> Result<Self> {
        let socket = RawSocket::new_ipv4(protocols::TCP)?;
        socket.set_timeout(config.timeout)?;

        Ok(Self {
            config,
            socket: Arc::new(socket),
            sequence: Arc::new(AtomicU32::new(rand::random())),
        })
    }

    async fn send_xmas(&self, target: Ipv4Addr, port: u16) -> Result<(u32, u16)> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let src_port = 40000 + (seq % 20000) as u16;
        let local_ip = Ipv4Addr::new(0, 0, 0, 0);

        let tcp_builder = TcpPacketBuilder::new(local_ip, target, src_port, port)
            .flags(TcpFlags::xmas())
            .seq(seq)
            .window(1024);

        let tcp_packet = tcp_builder.build()?;
        let ipv4_builder = Ipv4PacketBuilder::new(local_ip, target, 6).payload(tcp_packet);
        let packet = ipv4_builder.build()?;

        let addr = SocketAddr::new(IpAddr::V4(target), port);
        self.socket.send_to(&packet, &addr)?;

        trace!("Sent Xmas to {}:{} (seq={})", target, port, seq);

        Ok((seq, src_port))
    }
}

#[async_trait]
impl PortScanner for TcpXmasScanner {
    async fn scan_port(&self, target: IpAddr, port: Port) -> Result<PortScanResult> {
        let target_v4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                return Err(Error::InvalidInput("IPv6 not yet supported".to_string()))
            }
        };

        debug!("Scanning {}:{} with Xmas", target, port.value());

        let (seq, src_port) = self.send_xmas(target_v4, port.value()).await?;
        
        let start = Instant::now();
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
        ScanType::TcpXmas
    }
}

// Simple random number generator
mod rand {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEED: AtomicU32 = AtomicU32::new(987654321);

    pub fn random() -> u32 {
        let mut seed = SEED.load(Ordering::Relaxed);
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        SEED.store(seed, Ordering::Relaxed);
        seed
    }
}
