//! ApexScan Packet Crafting Library
//!
//! This crate provides low-level packet construction, parsing, and manipulation
//! for all supported network protocols.

pub mod builders;
pub mod parsers;
pub mod raw;
pub mod types;

pub use builders::*;
pub use parsers::*;
pub use types::*;

use apexscan_core::{Error, Result};

/// Trait for packet building
pub trait PacketBuilder {
    /// Build the packet into bytes
    fn build(&self) -> Result<Vec<u8>>;

    /// Get the expected packet size
    fn size(&self) -> usize;
}

/// Trait for packet parsing
pub trait PacketParser: Sized {
    /// Parse packet from bytes
    fn parse(data: &[u8]) -> Result<Self>;

    /// Validate the packet
    fn validate(&self) -> Result<()>;
}

/// Calculate Internet checksum (RFC 1071)
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum up 16-bit words
    while i < data.len() - 1 {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }

    // Add remaining byte if odd length
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

/// Calculate TCP/UDP pseudo-header checksum
pub fn calculate_transport_checksum(
    src_ip: std::net::Ipv4Addr,
    dst_ip: std::net::Ipv4Addr,
    protocol: u8,
    length: u16,
    data: &[u8],
) -> u16 {
    let mut pseudo_header = Vec::new();

    // Source IP
    pseudo_header.extend_from_slice(&src_ip.octets());
    // Destination IP
    pseudo_header.extend_from_slice(&dst_ip.octets());
    // Zero + Protocol
    pseudo_header.push(0);
    pseudo_header.push(protocol);
    // Length
    pseudo_header.extend_from_slice(&length.to_be_bytes());
    // Data
    pseudo_header.extend_from_slice(data);

    calculate_checksum(&pseudo_header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        // Simple test data
        let data = vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00];
        let checksum = calculate_checksum(&data);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_checksum_odd_length() {
        let data = vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40];
        let checksum = calculate_checksum(&data);
        assert_ne!(checksum, 0);
    }
}
