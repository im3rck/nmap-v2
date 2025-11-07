//! Colorized console output

use apexscan_core::scan::{HostResult, ScanResults};
use apexscan_core::types::{HostState, PortState};
use apexscan_core::Result;
use colored::*;

pub fn format_console(results: &ScanResults) -> Result<String> {
    let mut output = String::new();
    
    output.push_str(&format!("\n{}\n", "═".repeat(70).bright_blue()));
    output.push_str(&format!("{}\n", "ApexScan v0.1.0 - Scan Complete".bright_cyan().bold()));
    output.push_str(&format!("{}\n\n", "═".repeat(70).bright_blue()));
    
    for host in &results.hosts {
        output.push_str(&format_host_result_string(host));
        output.push('\n');
    }
    
    // Summary statistics
    output.push_str(&format!("{}\n", "─".repeat(70).bright_black()));
    output.push_str(&format!("{}\n", "Scan Summary".bright_white().bold()));
    output.push_str(&format!("{}\n", "─".repeat(70).bright_black()));
    output.push_str(&format!("Total hosts:     {}\n", results.stats.total_hosts));
    output.push_str(&format!("Hosts up:        {} {}\n", 
        results.stats.hosts_up.to_string().bright_green(),
        if results.stats.hosts_up > 0 { "✓" } else { "" }.bright_green()
    ));
    output.push_str(&format!("Hosts down:      {}\n", results.stats.hosts_down));
    output.push_str(&format!("Open ports:      {} {}\n", 
        results.stats.open_ports.to_string().bright_green().bold(),
        if results.stats.open_ports > 0 { "⚠" } else { "" }.yellow()
    ));
    output.push_str(&format!("Closed ports:    {}\n", results.stats.closed_ports));
    output.push_str(&format!("Filtered ports:  {}\n", results.stats.filtered_ports));
    output.push_str(&format!("Scan duration:   {:.2}s\n", results.duration.as_secs_f64()));
    output.push_str(&format!("{}\n", "═".repeat(70).bright_blue()));
    
    Ok(output)
}

pub fn print_host_result(host: &HostResult) {
    println!("{}", format_host_result_string(host));
}

fn format_host_result_string(host: &HostResult) -> String {
    let mut output = String::new();
    
    // Host header
    let status = match host.state {
        HostState::Up => "UP".bright_green().bold(),
        HostState::Down => "DOWN".bright_red(),
        HostState::Unknown => "UNKNOWN".yellow(),
    };
    
    output.push_str(&format!("\n{} {} [{}]\n", 
        "◆".bright_cyan(),
        host.target.to_string().bright_white().bold(),
        status
    ));
    
    if let Some(rtt) = host.latency {
        output.push_str(&format!("  {} {:.2}ms\n", 
            "RTT:".bright_black(),
            rtt.as_secs_f64() * 1000.0
        ));
    }
    
    // OS detection
    if !host.os.is_empty() {
        output.push_str(&format!("\n  {} {}\n", 
            "OS:".bright_yellow(),
            host.os.first().unwrap().name.bright_white()
        ));
        output.push_str(&format!("      {} {:.0}%\n",
            "Confidence:".bright_black(),
            host.os.first().unwrap().confidence * 100.0
        ));
    }
    
    // Ports
    if !host.ports.is_empty() {
        output.push_str(&format!("\n  {} ({} open)\n", 
            "Ports:".bright_cyan().bold(),
            host.open_ports().len()
        ));
        
        for port in &host.ports {
            if port.state == PortState::Open || port.state == PortState::OpenFiltered {
                let port_str = format!("{}/{}", port.port.value(), port.protocol);
                let state_str = match port.state {
                    PortState::Open => "open".bright_green(),
                    PortState::OpenFiltered => "open|filtered".yellow(),
                    _ => continue,
                };
                
                let service = port.service.as_ref()
                    .unwrap_or(&"unknown".to_string())
                    .bright_white();
                
                let version = port.version.as_ref()
                    .map(|v| format!(" ({})", v).bright_black().to_string())
                    .unwrap_or_default();
                
                output.push_str(&format!("    {} {} {} {}{}\n",
                    "▸".bright_cyan(),
                    port_str.bright_yellow(),
                    state_str,
                    service,
                    version
                ));
            }
        }
    }
    
    output
}
