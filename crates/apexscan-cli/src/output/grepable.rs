//! Grepable output format (-oG equivalent)
//!
//! Produces output compatible with nmap's grepable format for easy parsing

use apexscan_core::scan::{HostResult, ScanResults};
use std::io::Write;

/// Format scan results in grepable format
///
/// Format: Host: <IP> (<hostname>) Status: <Up/Down> Ports: <port/state/proto/service, ...>
pub fn format_grepable(results: &ScanResults) -> String {
    let mut output = String::new();

    // Header comment
    output.push_str(&format!(
        "# ApexScan grepable output\n# Command: apexscan\n# Scan started at: {}\n",
        results.start_time
    ));

    // Process each host
    for host_result in &results.hosts {
        let line = format_host_grepable(host_result);
        output.push_str(&line);
        output.push('\n');
    }

    // Footer comment
    output.push_str(&format!(
        "# Scan finished at: {} ({:.2}s elapsed)\n",
        results.end_time,
        results.duration.as_secs_f64()
    ));

    output
}

/// Format a single host in grepable format
fn format_host_grepable(host: &HostResult) -> String {
    let ip = host.target.ip;
    let status = match host.state {
        apexscan_core::types::HostState::Up => "Up",
        apexscan_core::types::HostState::Down => "Down",
        apexscan_core::types::HostState::Unknown => "Unknown",
    };

    // Build ports list: port/state/protocol/service,port/state/protocol/service,...
    let mut ports_str = String::new();
    for (idx, port) in host.ports.iter().enumerate() {
        if idx > 0 {
            ports_str.push_str(", ");
        }

        let port_num = port.port.value();
        let state = match port.state {
            apexscan_core::types::PortState::Open => "open",
            apexscan_core::types::PortState::Closed => "closed",
            apexscan_core::types::PortState::Filtered => "filtered",
            apexscan_core::types::PortState::OpenFiltered => "open|filtered",
            apexscan_core::types::PortState::ClosedFiltered => "closed|filtered",
            apexscan_core::types::PortState::Unknown => "unknown",
        };
        let protocol = match port.protocol {
            apexscan_core::types::Protocol::Tcp => "tcp",
            apexscan_core::types::Protocol::Udp => "udp",
            apexscan_core::types::Protocol::Sctp => "sctp",
            apexscan_core::types::Protocol::Icmp => "icmp",
        };
        let service = port.service.as_deref().unwrap_or("");

        // Format: port/state/protocol/service/version/extra
        let version = port.version.as_deref().unwrap_or("");
        if !version.is_empty() {
            ports_str.push_str(&format!(
                "{}/{}/{}/{}/{}",
                port_num, state, protocol, service, version
            ));
        } else {
            ports_str.push_str(&format!("{}/{}/{}/{}", port_num, state, protocol, service));
        }
    }

    // Build the grepable line
    if ports_str.is_empty() {
        format!("Host: {}\tStatus: {}", ip, status)
    } else {
        format!("Host: {}\tStatus: {}\tPorts: {}", ip, status, ports_str)
    }
}

/// Write grepable output to a writer
pub fn write_grepable<W: Write>(writer: &mut W, results: &ScanResults) -> std::io::Result<()> {
    let output = format_grepable(results);
    writer.write_all(output.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use apexscan_core::scan::{HostResult, PortResult};
    use apexscan_core::types::{HostState, Port, PortState, Protocol, Target};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_grepable_format() {
        let mut results = ScanResults::default();
        results.start_time = chrono::Utc::now();
        results.end_time = chrono::Utc::now();

        let mut host = HostResult::new(Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        host.state = HostState::Up;

        let port_result = PortResult {
            port: Port::new(80).unwrap(),
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".to_string()),
            version: Some("Apache 2.4".to_string()),
            extra_info: None,
            confidence: 0.9,
            patch_level: None,
            security_posture: None,
            impact_score: None,
            cve_ids: None,
        };

        host.ports.push(port_result);
        results.hosts.push(host);

        let output = format_grepable(&results);

        // Should contain the host line
        assert!(output.contains("Host: 192.168.1.1"));
        assert!(output.contains("Status: Up"));
        assert!(output.contains("Ports: 80/open/tcp/http/Apache 2.4"));
    }

    #[test]
    fn test_grepable_multiple_ports() {
        let mut host = HostResult::new(Target::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        host.state = HostState::Up;

        let port1 = PortResult {
            port: Port::new(22).unwrap(),
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("ssh".to_string()),
            version: None,
            extra_info: None,
            confidence: 0.9,
            patch_level: None,
            security_posture: None,
            impact_score: None,
            cve_ids: None,
        };

        let port2 = PortResult {
            port: Port::new(80).unwrap(),
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".to_string()),
            version: None,
            extra_info: None,
            confidence: 0.9,
            patch_level: None,
            security_posture: None,
            impact_score: None,
            cve_ids: None,
        };

        host.ports.push(port1);
        host.ports.push(port2);

        let line = format_host_grepable(&host);

        assert!(line.contains("22/open/tcp/ssh"));
        assert!(line.contains("80/open/tcp/http"));
        assert!(line.contains(", "));
    }

    #[test]
    fn test_grepable_no_ports() {
        let host = HostResult::new(Target::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));

        let line = format_host_grepable(&host);

        assert!(line.contains("Host: 10.0.0.1"));
        assert!(line.contains("Status:"));
        assert!(!line.contains("Ports:"));
    }
}
