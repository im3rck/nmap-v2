//! CSV output formatter

use apexscan_core::scan::ScanResults;
use apexscan_core::Result;

pub fn format_csv(results: &ScanResults) -> Result<String> {
    let mut csv = String::new();
    
    // Header
    csv.push_str("IP Address,Port,Protocol,State,Service,Version\n");

    // Data rows
    for host in &results.hosts {
        let ip = host.target.ip.to_string();

        for port_result in &host.ports {
            csv.push_str(&format!(
                "{},{},{},{},{},{}\n",
                ip,
                port_result.port.value(),
                port_result.protocol,
                port_result.state,
                port_result.service.as_ref().unwrap_or(&"unknown".to_string()),
                port_result.version.as_ref().unwrap_or(&"".to_string())
            ));
        }
    }
    
    Ok(csv)
}
