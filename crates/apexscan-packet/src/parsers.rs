//! Packet parsers for analyzing received packets

use crate::types::*;
use apexscan_core::{Error, Result};
use std::net::Ipv4Addr;

/// Parse TCP packet from raw bytes
pub fn parse_tcp(data: &[u8]) -> Result<TcpPacket> {
    if data.len() < 20 {
        return Err(Error::PacketParse("TCP packet too short".to_string()));
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = (data[12] >> 4) as usize * 4;
    let flags = TcpFlags::from_u8(data[13]);
    let window = u16::from_be_bytes([data[14], data[15]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

    let options = if data_offset > 20 {
        data[20..data_offset].to_vec()
    } else {
        Vec::new()
    };

    let payload = if data.len() > data_offset {
        data[data_offset..].to_vec()
    } else {
        Vec::new()
    };

    Ok(TcpPacket {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        urgent_ptr,
        options,
        payload,
    })
}

/// Parse UDP packet from raw bytes
pub fn parse_udp(data: &[u8]) -> Result<UdpPacket> {
    if data.len() < 8 {
        return Err(Error::PacketParse("UDP packet too short".to_string()));
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    let payload = if data.len() > 8 {
        data[8..].to_vec()
    } else {
        Vec::new()
    };

    Ok(UdpPacket {
        src_port,
        dst_port,
        payload,
    })
}

/// Parse ICMP packet from raw bytes
pub fn parse_icmp(data: &[u8]) -> Result<IcmpPacket> {
    if data.len() < 4 {
        return Err(Error::PacketParse("ICMP packet too short".to_string()));
    }

    let icmp_type = IcmpType::from_u8(data[0]);
    let code = data[1];

    let payload = if data.len() > 4 {
        data[4..].to_vec()
    } else {
        Vec::new()
    };

    Ok(IcmpPacket {
        icmp_type,
        code,
        payload,
    })
}

/// Parse IPv4 packet from raw bytes
pub fn parse_ipv4(data: &[u8]) -> Result<Ipv4Packet> {
    if data.len() < 20 {
        return Err(Error::PacketParse("IPv4 packet too short".to_string()));
    }

    let version = data[0] >> 4;
    if version != 4 {
        return Err(Error::PacketParse(format!("Not an IPv4 packet: version {}", version)));
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let id = u16::from_be_bytes([data[4], data[5]]);
    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    let flags = (flags_frag >> 13) as u8;
    let fragment_offset = flags_frag & 0x1FFF;
    let ttl = data[8];
    let protocol = data[9];
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let payload = if data.len() > ihl {
        data[ihl..].to_vec()
    } else {
        Vec::new()
    };

    Ok(Ipv4Packet {
        src_ip,
        dst_ip,
        protocol,
        ttl,
        id,
        flags,
        fragment_offset,
        payload,
    })
}

/// Parse ARP packet from raw bytes
pub fn parse_arp(data: &[u8]) -> Result<ArpPacket> {
    if data.len() < 28 {
        return Err(Error::PacketParse("ARP packet too short".to_string()));
    }

    let operation = ArpOperation::from_u16(u16::from_be_bytes([data[6], data[7]]))
        .ok_or_else(|| Error::PacketParse("Invalid ARP operation".to_string()))?;

    let mut sender_hw = [0u8; 6];
    sender_hw.copy_from_slice(&data[8..14]);

    let sender_proto = Ipv4Addr::new(data[14], data[15], data[16], data[17]);

    let mut target_hw = [0u8; 6];
    target_hw.copy_from_slice(&data[18..24]);

    let target_proto = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

    Ok(ArpPacket {
        operation,
        sender_hw_addr: sender_hw,
        sender_proto_addr: sender_proto,
        target_hw_addr: target_hw,
        target_proto_addr: target_proto,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp() {
        let data = vec![
            0x00, 0x50, // src port 80
            0x30, 0x39, // dst port 12345
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, // offset + flags (SYN)
            0xFF, 0xFF, // window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent
        ];

        let packet = parse_tcp(&data).unwrap();
        assert_eq!(packet.src_port, 80);
        assert_eq!(packet.dst_port, 12345);
        assert!(packet.flags.syn);
    }
}
