//! Nmap-compatible XML output formatter

use apexscan_core::scan::ScanResults;
use apexscan_core::Result;
use chrono::Utc;

pub fn format_xml(results: &ScanResults) -> Result<String> {
    let mut xml = String::new();
    
    // XML header
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<!DOCTYPE nmaprun>\n");
    xml.push_str("<?xml-stylesheet href=\"file:///usr/local/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?>\n");
    
    // nmaprun element
    xml.push_str(&format!(
        "<nmaprun scanner=\"apexscan\" args=\"{}\" start=\"{}\" version=\"0.1.0\">\n",
        "apexscan",  // TODO: Get actual command line args
        results.start_time.timestamp()
    ));
    
    // scaninfo
    xml.push_str("  <scaninfo type=\"syn\" protocol=\"tcp\" numservices=\"1000\" services=\"1-65535\"/>\n");
    
    // verbose
    xml.push_str("  <verbose level=\"0\"/>\n");
    xml.push_str("  <debugging level=\"0\"/>\n");
    
    // hosts
    for host in &results.hosts {
        xml.push_str(&format!("  <host starttime=\"{}\" endtime=\"{}\">\n", 
            host.start_time.timestamp(),
            host.end_time.timestamp()
        ));
        
        // status
        xml.push_str(&format!("    <status state=\"{}\" reason=\"echo-reply\" reason_ttl=\"64\"/>\n",
            if host.state == apexscan_core::types::HostState::Up { "up" } else { "down" }
        ));
        
        // address
        xml.push_str(&format!("    <address addr=\"{}\" addrtype=\"ipv4\"/>\n", host.target.ip));
        
        if let Some(ref mac) = host.target.mac {
            xml.push_str(&format!("    <address addr=\"{}\" addrtype=\"mac\"/>\n", mac));
        }
        
        // hostnames (if any)
        if let Some(ref hostname) = host.target.hostname {
            xml.push_str("    <hostnames>\n");
            xml.push_str(&format!("      <hostname name=\"{}\" type=\"PTR\"/>\n", hostname));
            xml.push_str("    </hostnames>\n");
        } else {
            xml.push_str("    <hostnames/>\n");
        }
        
        // ports
        if !host.ports.is_empty() {
            xml.push_str("    <ports>\n");
            
            for port in &host.ports {
                xml.push_str(&format!(
                    "      <port protocol=\"{}\" portid=\"{}\">\n",
                    port.protocol.to_string().to_lowercase(),
                    port.port.value()
                ));
                
                xml.push_str(&format!("        <state state=\"{}\" reason=\"syn-ack\" reason_ttl=\"64\"/>\n",
                    port.state.to_string()
                ));
                
                if let Some(ref service) = port.service {
                    xml.push_str(&format!("        <service name=\"{}\"", service));
                    if let Some(ref version) = port.version {
                        xml.push_str(&format!(" product=\"{}\"", version));
                    }
                    xml.push_str(" method=\"probed\" conf=\"10\"/>\n");
                } else {
                    xml.push_str("        <service name=\"unknown\" method=\"table\" conf=\"3\"/>\n");
                }
                
                xml.push_str("      </port>\n");
            }
            
            xml.push_str("    </ports>\n");
        }
        
        // os detection
        if !host.os.is_empty() {
            xml.push_str("    <os>\n");
            for os in &host.os {
                xml.push_str(&format!(
                    "      <osmatch name=\"{}\" accuracy=\"{:.0}\"/>\n",
                    os.name,
                    os.confidence * 100.0
                ));
            }
            xml.push_str("    </os>\n");
        }
        
        // times
        if let Some(rtt) = host.latency {
            xml.push_str(&format!("    <times srtt=\"{}\" rttvar=\"5000\" to=\"100000\"/>\n", 
                rtt.as_micros()
            ));
        }
        
        xml.push_str("  </host>\n");
    }
    
    // runstats
    xml.push_str("  <runstats>\n");
    xml.push_str("    <finished time=\"");
    xml.push_str(&Utc::now().timestamp().to_string());
    xml.push_str("\" timestr=\"");
    xml.push_str(&Utc::now().format("%a %b %d %H:%M:%S %Y").to_string());
    xml.push_str("\" elapsed=\"");
    xml.push_str(&results.duration.as_secs().to_string());
    xml.push_str("\" summary=\"ApexScan done");
    xml.push_str(&format!("; {} IP address", results.stats.total_hosts));
    if results.stats.total_hosts != 1 {
        xml.push_str("es");
    }
    xml.push_str(&format!(" ({} host", results.stats.hosts_up));
    if results.stats.hosts_up != 1 {
        xml.push_str("s");
    }
    xml.push_str(" up) scanned in ");
    xml.push_str(&format!("{:.2}", results.duration.as_secs_f64()));
    xml.push_str(" seconds\"/>\n");
    
    xml.push_str(&format!("    <hosts up=\"{}\" down=\"{}\" total=\"{}\"/>\n",
        results.stats.hosts_up,
        results.stats.hosts_down,
        results.stats.total_hosts
    ));
    xml.push_str("  </runstats>\n");
    
    xml.push_str("</nmaprun>\n");
    
    Ok(xml)
}
