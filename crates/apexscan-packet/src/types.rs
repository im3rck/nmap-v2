//! Packet type definitions

use std::net::Ipv4Addr;

/// TCP flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn new() -> Self {
        Self {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            urg: false,
        }
    }

    pub fn syn() -> Self {
        Self {
            syn: true,
            ..Self::new()
        }
    }

    pub fn syn_ack() -> Self {
        Self {
            syn: true,
            ack: true,
            ..Self::new()
        }
    }

    pub fn ack() -> Self {
        Self {
            ack: true,
            ..Self::new()
        }
    }

    pub fn fin_ack() -> Self {
        Self {
            fin: true,
            ack: true,
            ..Self::new()
        }
    }

    pub fn rst() -> Self {
        Self {
            rst: true,
            ..Self::new()
        }
    }

    pub fn null() -> Self {
        Self::new()
    }

    pub fn fin() -> Self {
        Self {
            fin: true,
            ..Self::new()
        }
    }

    pub fn xmas() -> Self {
        Self {
            fin: true,
            psh: true,
            urg: true,
            ..Self::new()
        }
    }

    pub fn to_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin {
            flags |= 0x01;
        }
        if self.syn {
            flags |= 0x02;
        }
        if self.rst {
            flags |= 0x04;
        }
        if self.psh {
            flags |= 0x08;
        }
        if self.ack {
            flags |= 0x10;
        }
        if self.urg {
            flags |= 0x20;
        }
        flags
    }

    pub fn from_u8(value: u8) -> Self {
        Self {
            fin: (value & 0x01) != 0,
            syn: (value & 0x02) != 0,
            rst: (value & 0x04) != 0,
            psh: (value & 0x08) != 0,
            ack: (value & 0x10) != 0,
            urg: (value & 0x20) != 0,
        }
    }
}

impl Default for TcpFlags {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP packet representation
#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub urgent_ptr: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

impl TcpPacket {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq: 0,
            ack: 0,
            flags: TcpFlags::new(),
            window: 65535,
            urgent_ptr: 0,
            options: Vec::new(),
            payload: Vec::new(),
        }
    }
}

/// UDP packet representation
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            payload: Vec::new(),
        }
    }

    pub fn length(&self) -> u16 {
        (8 + self.payload.len()) as u16
    }
}

/// ICMP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    EchoRequest,
    DestinationUnreachable,
    TimeExceeded,
    TimestampRequest,
    TimestampReply,
    Other(u8),
}

impl IcmpType {
    pub fn to_u8(&self) -> u8 {
        match self {
            IcmpType::EchoReply => 0,
            IcmpType::EchoRequest => 8,
            IcmpType::DestinationUnreachable => 3,
            IcmpType::TimeExceeded => 11,
            IcmpType::TimestampRequest => 13,
            IcmpType::TimestampReply => 14,
            IcmpType::Other(t) => *t,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => IcmpType::EchoReply,
            8 => IcmpType::EchoRequest,
            3 => IcmpType::DestinationUnreachable,
            11 => IcmpType::TimeExceeded,
            13 => IcmpType::TimestampRequest,
            14 => IcmpType::TimestampReply,
            t => IcmpType::Other(t),
        }
    }
}

/// ICMP packet representation
#[derive(Debug, Clone)]
pub struct IcmpPacket {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub payload: Vec<u8>,
}

impl IcmpPacket {
    pub fn new(icmp_type: IcmpType, code: u8) -> Self {
        Self {
            icmp_type,
            code,
            payload: Vec::new(),
        }
    }

    pub fn echo_request(id: u16, seq: u16) -> Self {
        let mut packet = Self::new(IcmpType::EchoRequest, 0);
        packet.payload.extend_from_slice(&id.to_be_bytes());
        packet.payload.extend_from_slice(&seq.to_be_bytes());
        packet
    }
}

/// IPv4 packet representation
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            protocol,
            ttl: 64,
            id: 0,
            flags: 0,
            fragment_offset: 0,
            payload: Vec::new(),
        }
    }

    pub fn total_length(&self) -> u16 {
        (20 + self.payload.len()) as u16
    }
}

/// ARP operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
}

impl ArpOperation {
    pub fn to_u16(&self) -> u16 {
        match self {
            ArpOperation::Request => 1,
            ArpOperation::Reply => 2,
        }
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(ArpOperation::Request),
            2 => Some(ArpOperation::Reply),
            _ => None,
        }
    }
}

/// ARP packet representation
#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub operation: ArpOperation,
    pub sender_hw_addr: [u8; 6],
    pub sender_proto_addr: Ipv4Addr,
    pub target_hw_addr: [u8; 6],
    pub target_proto_addr: Ipv4Addr,
}

impl ArpPacket {
    pub fn request(sender_hw: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        Self {
            operation: ArpOperation::Request,
            sender_hw_addr: sender_hw,
            sender_proto_addr: sender_ip,
            target_hw_addr: [0; 6],
            target_proto_addr: target_ip,
        }
    }
}
