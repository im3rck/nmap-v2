//! Packet builders for constructing raw packets

use crate::types::*;
use crate::{calculate_checksum, calculate_transport_checksum, PacketBuilder};
use apexscan_core::Result;
use std::net::Ipv4Addr;

/// TCP packet builder
pub struct TcpPacketBuilder {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    packet: TcpPacket,
}

impl TcpPacketBuilder {
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            packet: TcpPacket::new(src_port, dst_port),
        }
    }

    pub fn flags(mut self, flags: TcpFlags) -> Self {
        self.packet.flags = flags;
        self
    }

    pub fn seq(mut self, seq: u32) -> Self {
        self.packet.seq = seq;
        self
    }

    pub fn ack(mut self, ack: u32) -> Self {
        self.packet.ack = ack;
        self
    }

    pub fn window(mut self, window: u16) -> Self {
        self.packet.window = window;
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.packet.payload = payload;
        self
    }
}

impl PacketBuilder for TcpPacketBuilder {
    fn build(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // TCP header (20 bytes minimum + options)
        let data_offset = ((20 + self.packet.options.len()) / 4) as u8;

        // Source port
        buffer.extend_from_slice(&self.packet.src_port.to_be_bytes());
        // Destination port
        buffer.extend_from_slice(&self.packet.dst_port.to_be_bytes());
        // Sequence number
        buffer.extend_from_slice(&self.packet.seq.to_be_bytes());
        // Acknowledgment number
        buffer.extend_from_slice(&self.packet.ack.to_be_bytes());
        // Data offset (4 bits) + reserved (3 bits) + flags (9 bits)
        buffer.push((data_offset << 4) | 0);
        buffer.push(self.packet.flags.to_u8());
        // Window size
        buffer.extend_from_slice(&self.packet.window.to_be_bytes());
        // Checksum (placeholder)
        buffer.extend_from_slice(&[0u8, 0u8]);
        // Urgent pointer
        buffer.extend_from_slice(&self.packet.urgent_ptr.to_be_bytes());
        // Options
        buffer.extend_from_slice(&self.packet.options);
        // Payload
        buffer.extend_from_slice(&self.packet.payload);

        // Calculate checksum
        let checksum = calculate_transport_checksum(
            self.src_ip,
            self.dst_ip,
            6, // TCP protocol number
            buffer.len() as u16,
            &buffer,
        );

        // Insert checksum at offset 16
        buffer[16] = (checksum >> 8) as u8;
        buffer[17] = checksum as u8;

        Ok(buffer)
    }

    fn size(&self) -> usize {
        20 + self.packet.options.len() + self.packet.payload.len()
    }
}

/// UDP packet builder
pub struct UdpPacketBuilder {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    packet: UdpPacket,
}

impl UdpPacketBuilder {
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            packet: UdpPacket::new(src_port, dst_port),
        }
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.packet.payload = payload;
        self
    }
}

impl PacketBuilder for UdpPacketBuilder {
    fn build(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        let length = self.packet.length();

        // Source port
        buffer.extend_from_slice(&self.packet.src_port.to_be_bytes());
        // Destination port
        buffer.extend_from_slice(&self.packet.dst_port.to_be_bytes());
        // Length
        buffer.extend_from_slice(&length.to_be_bytes());
        // Checksum (placeholder)
        buffer.extend_from_slice(&[0u8, 0u8]);
        // Payload
        buffer.extend_from_slice(&self.packet.payload);

        // Calculate checksum
        let checksum = calculate_transport_checksum(
            self.src_ip,
            self.dst_ip,
            17, // UDP protocol number
            length,
            &buffer,
        );

        // Insert checksum at offset 6
        buffer[6] = (checksum >> 8) as u8;
        buffer[7] = checksum as u8;

        Ok(buffer)
    }

    fn size(&self) -> usize {
        8 + self.packet.payload.len()
    }
}

/// ICMP packet builder
pub struct IcmpPacketBuilder {
    packet: IcmpPacket,
}

impl IcmpPacketBuilder {
    pub fn new(icmp_type: IcmpType, code: u8) -> Self {
        Self {
            packet: IcmpPacket::new(icmp_type, code),
        }
    }

    pub fn echo_request(id: u16, seq: u16) -> Self {
        Self {
            packet: IcmpPacket::echo_request(id, seq),
        }
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.packet.payload = payload;
        self
    }
}

impl PacketBuilder for IcmpPacketBuilder {
    fn build(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Type
        buffer.push(self.packet.icmp_type.to_u8());
        // Code
        buffer.push(self.packet.code);
        // Checksum (placeholder)
        buffer.extend_from_slice(&[0u8, 0u8]);
        // Payload
        buffer.extend_from_slice(&self.packet.payload);

        // Calculate checksum
        let checksum = calculate_checksum(&buffer);

        // Insert checksum at offset 2
        buffer[2] = (checksum >> 8) as u8;
        buffer[3] = checksum as u8;

        Ok(buffer)
    }

    fn size(&self) -> usize {
        4 + self.packet.payload.len()
    }
}

/// IPv4 packet builder
pub struct Ipv4PacketBuilder {
    packet: Ipv4Packet,
}

impl Ipv4PacketBuilder {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, protocol: u8) -> Self {
        Self {
            packet: Ipv4Packet::new(src_ip, dst_ip, protocol),
        }
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.packet.ttl = ttl;
        self
    }

    pub fn id(mut self, id: u16) -> Self {
        self.packet.id = id;
        self
    }

    pub fn flags(mut self, flags: u8) -> Self {
        self.packet.flags = flags;
        self
    }

    pub fn fragment_offset(mut self, offset: u16) -> Self {
        self.packet.fragment_offset = offset;
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.packet.payload = payload;
        self
    }
}

impl PacketBuilder for Ipv4PacketBuilder {
    fn build(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        let total_length = self.packet.total_length();

        // Version (4 bits) + IHL (4 bits)
        buffer.push(0x45); // Version 4, IHL 5 (20 bytes)
        // DSCP (6 bits) + ECN (2 bits)
        buffer.push(0);
        // Total length
        buffer.extend_from_slice(&total_length.to_be_bytes());
        // Identification
        buffer.extend_from_slice(&self.packet.id.to_be_bytes());
        // Flags (3 bits) + Fragment offset (13 bits)
        let flags_frag = ((self.packet.flags as u16) << 13) | self.packet.fragment_offset;
        buffer.extend_from_slice(&flags_frag.to_be_bytes());
        // TTL
        buffer.push(self.packet.ttl);
        // Protocol
        buffer.push(self.packet.protocol);
        // Header checksum (placeholder)
        buffer.extend_from_slice(&[0u8, 0u8]);
        // Source IP
        buffer.extend_from_slice(&self.packet.src_ip.octets());
        // Destination IP
        buffer.extend_from_slice(&self.packet.dst_ip.octets());

        // Calculate header checksum
        let checksum = calculate_checksum(&buffer);

        // Insert checksum at offset 10
        buffer[10] = (checksum >> 8) as u8;
        buffer[11] = checksum as u8;

        // Payload
        buffer.extend_from_slice(&self.packet.payload);

        Ok(buffer)
    }

    fn size(&self) -> usize {
        20 + self.packet.payload.len()
    }
}

/// ARP packet builder
pub struct ArpPacketBuilder {
    packet: ArpPacket,
}

impl ArpPacketBuilder {
    pub fn new(operation: ArpOperation) -> Self {
        Self {
            packet: ArpPacket {
                operation,
                sender_hw_addr: [0; 6],
                sender_proto_addr: Ipv4Addr::new(0, 0, 0, 0),
                target_hw_addr: [0; 6],
                target_proto_addr: Ipv4Addr::new(0, 0, 0, 0),
            },
        }
    }

    pub fn request(sender_hw: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        Self {
            packet: ArpPacket::request(sender_hw, sender_ip, target_ip),
        }
    }

    pub fn sender(mut self, hw_addr: [u8; 6], proto_addr: Ipv4Addr) -> Self {
        self.packet.sender_hw_addr = hw_addr;
        self.packet.sender_proto_addr = proto_addr;
        self
    }

    pub fn target(mut self, hw_addr: [u8; 6], proto_addr: Ipv4Addr) -> Self {
        self.packet.target_hw_addr = hw_addr;
        self.packet.target_proto_addr = proto_addr;
        self
    }
}

impl PacketBuilder for ArpPacketBuilder {
    fn build(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Hardware type (Ethernet = 1)
        buffer.extend_from_slice(&1u16.to_be_bytes());
        // Protocol type (IPv4 = 0x0800)
        buffer.extend_from_slice(&0x0800u16.to_be_bytes());
        // Hardware address length (6 for MAC)
        buffer.push(6);
        // Protocol address length (4 for IPv4)
        buffer.push(4);
        // Operation
        buffer.extend_from_slice(&self.packet.operation.to_u16().to_be_bytes());
        // Sender hardware address
        buffer.extend_from_slice(&self.packet.sender_hw_addr);
        // Sender protocol address
        buffer.extend_from_slice(&self.packet.sender_proto_addr.octets());
        // Target hardware address
        buffer.extend_from_slice(&self.packet.target_hw_addr);
        // Target protocol address
        buffer.extend_from_slice(&self.packet.target_proto_addr.octets());

        Ok(buffer)
    }

    fn size(&self) -> usize {
        28
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_syn_builder() {
        let builder = TcpPacketBuilder::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            12345,
            80,
        )
        .flags(TcpFlags::syn())
        .seq(1000);

        let packet = builder.build().unwrap();
        assert!(packet.len() >= 20);
    }

    #[test]
    fn test_icmp_echo_builder() {
        let builder = IcmpPacketBuilder::echo_request(1, 1);
        let packet = builder.build().unwrap();
        assert_eq!(packet.len(), 8);
        assert_eq!(packet[0], 8); // Echo request type
    }

    #[test]
    fn test_udp_builder() {
        let builder = UdpPacketBuilder::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            12345,
            53,
        )
        .payload(vec![1, 2, 3, 4]);

        let packet = builder.build().unwrap();
        assert_eq!(packet.len(), 12); // 8 byte header + 4 byte payload
    }
}
