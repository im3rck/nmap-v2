//! Network utilities

use crate::types::{Port, Target};
use crate::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Parse a CIDR notation into a list of IP addresses
pub fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidInput(format!("Invalid CIDR notation: {}", cidr)));
    }

    let ip = IpAddr::from_str(parts[0])
        .map_err(|e| Error::InvalidInput(format!("Invalid IP address: {}", e)))?;

    let prefix_len: u8 = parts[1]
        .parse()
        .map_err(|e| Error::InvalidInput(format!("Invalid prefix length: {}", e)))?;

    match ip {
        IpAddr::V4(ipv4) => expand_ipv4_cidr(ipv4, prefix_len),
        IpAddr::V6(ipv6) => expand_ipv6_cidr(ipv6, prefix_len),
    }
}

fn expand_ipv4_cidr(ip: Ipv4Addr, prefix_len: u8) -> Result<Vec<IpAddr>> {
    if prefix_len > 32 {
        return Err(Error::InvalidInput(format!("Invalid IPv4 prefix length: {}", prefix_len)));
    }

    let ip_u32 = u32::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    let network = ip_u32 & mask;
    let broadcast = network | !mask;

    let mut ips = Vec::new();
    for addr in network..=broadcast {
        ips.push(IpAddr::V4(Ipv4Addr::from(addr)));
    }

    Ok(ips)
}

fn expand_ipv6_cidr(ip: Ipv6Addr, prefix_len: u8) -> Result<Vec<IpAddr>> {
    if prefix_len > 128 {
        return Err(Error::InvalidInput(format!("Invalid IPv6 prefix length: {}", prefix_len)));
    }

    // For IPv6, we typically don't expand the entire range due to size
    // Instead, return just the network address for now
    // TODO: Implement IPv6 range expansion with sensible limits
    Ok(vec![IpAddr::V6(ip)])
}

/// Parse a port range (e.g., "1-1000", "80", "22,80,443")
pub fn parse_port_range(range: &str) -> Result<Vec<Port>> {
    let mut ports = Vec::new();

    for part in range.split(',') {
        if part.contains('-') {
            // Range: "1-1000"
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(Error::InvalidInput(format!("Invalid port range: {}", part)));
            }

            let start: u16 = bounds[0]
                .parse()
                .map_err(|e| Error::InvalidInput(format!("Invalid port: {}", e)))?;
            let end: u16 = bounds[1]
                .parse()
                .map_err(|e| Error::InvalidInput(format!("Invalid port: {}", e)))?;

            if start == 0 || end == 0 || start > end {
                return Err(Error::InvalidInput(format!("Invalid port range: {}-{}", start, end)));
            }

            for p in start..=end {
                if let Some(port) = Port::new(p) {
                    ports.push(port);
                }
            }
        } else {
            // Single port: "80"
            let p: u16 = part
                .parse()
                .map_err(|e| Error::InvalidInput(format!("Invalid port: {}", e)))?;

            if let Some(port) = Port::new(p) {
                ports.push(port);
            } else {
                return Err(Error::InvalidInput(format!("Invalid port: {}", p)));
            }
        }
    }

    Ok(ports)
}

/// Common port sets
pub mod ports {
    use crate::types::Port;

    /// Top 100 most common ports
    pub fn top_100() -> Vec<Port> {
        vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
            // ... (truncated for brevity, should include all 100)
        ]
        .into_iter()
        .filter_map(Port::new)
        .collect()
    }

    /// Top 1000 most common ports
    pub fn top_1000() -> Vec<Port> {
        // TODO: Implement full list
        top_100()
    }

    /// All ports (1-65535)
    pub fn all() -> Vec<Port> {
        (1..=65535).filter_map(Port::new).collect()
    }

    /// Well-known ports (1-1023)
    pub fn well_known() -> Vec<Port> {
        (1..=1023).filter_map(Port::new).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_range() {
        let ports = parse_port_range("80").unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].value(), 80);

        let ports = parse_port_range("80,443,8080").unwrap();
        assert_eq!(ports.len(), 3);

        let ports = parse_port_range("1-10").unwrap();
        assert_eq!(ports.len(), 10);

        let ports = parse_port_range("80,443,8000-8010").unwrap();
        assert_eq!(ports.len(), 13);
    }

    #[test]
    fn test_parse_cidr() {
        let ips = parse_cidr("192.168.1.0/30").unwrap();
        assert_eq!(ips.len(), 4);

        let ips = parse_cidr("10.0.0.0/24").unwrap();
        assert_eq!(ips.len(), 256);
    }
}
