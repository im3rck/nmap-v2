//! Execution pipeline coordinator

use apexscan_core::{
    net::parse_cidr,
    scan::{HostResult, ScanConfig, ScanResults, ScanType},
    types::{HostState, Port, PortState, Protocol, Target, TimingTemplate},
    Result,
};
use apexscan_scanner::{
    connect_scanner::TcpConnectScanner,
    covert_scanner::{TcpFinScanner, TcpNullScanner, TcpXmasScanner},
    specialized_scanner::{TcpAckScanner, TcpMaimonScanner, TcpWindowScanner},
    syn_scanner::TcpSynScanner,
    udp_scanner::UdpScanner,
    PortScanner,
    ScannerConfig,
};
use crate::chaining::{ChainingEngine, ChainedTask, ChainedTaskType};
use colored::*;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub scan_type: ScanType,
    pub ports: Vec<Port>,
    pub os_detection: bool,
    pub version_detection: bool,
    pub script_scan: bool,
    pub scripts: Vec<String>,
    pub timing: TimingTemplate,
    pub max_concurrent_hosts: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            scan_type: ScanType::TcpSyn,
            ports: Vec::new(),
            os_detection: false,
            version_detection: false,
            script_scan: false,
            scripts: Vec::new(),
            timing: TimingTemplate::T3,
            max_concurrent_hosts: 10,
        }
    }
}

/// Pipeline coordinator
pub struct Pipeline {
    config: PipelineConfig,
    chaining_engine: RefCell<ChainingEngine>,
}

impl Pipeline {
    pub fn new(config: PipelineConfig) -> Self {
        // Try to load chaining rules, fall back to disabled engine if not found
        let chaining_engine = ChainingEngine::from_file("scan-chain-rules.yaml")
            .unwrap_or_else(|e| {
                warn!("Could not load Smart Scan Chaining rules: {}. Chaining disabled.", e);
                ChainingEngine::disabled()
            });

        Self {
            config,
            chaining_engine: RefCell::new(chaining_engine),
        }
    }

    /// Execute the full scanning pipeline
    pub async fn execute(&self, targets: Vec<String>) -> Result<ScanResults> {
        let start_time = Instant::now();
        
        // Step 1: Parse and expand targets
        info!("Parsing targets...");
        let ips = self.parse_targets(targets)?;
        println!("{} Scanning {} target(s)...", "→".bright_cyan(), ips.len());
        
        // Step 2: Host discovery
        info!("Starting host discovery...");
        let live_hosts = self.discover_hosts(&ips).await?;
        println!("{} {} host(s) up", "✓".bright_green(), live_hosts.len());
        
        if live_hosts.is_empty() {
            println!("{} No live hosts found", "!".bright_yellow());
            return self.create_empty_results(start_time);
        }
        
        // Step 3: Port scanning
        info!("Starting port scanning...");
        let mut host_results = Vec::new();
        
        for (idx, ip) in live_hosts.iter().enumerate() {
            println!("{} Scanning host {}/{}: {}", 
                "→".bright_cyan(),
                idx + 1,
                live_hosts.len(),
                ip.to_string().bright_white()
            );
            
            let result = self.scan_host(*ip).await?;
            
            // Print result immediately (streaming output)
            crate::output::console::print_host_result(&result);
            
            host_results.push(result);
        }
        
        // Step 4: Create final results
        let mut results = ScanResults::new(self.create_scan_config());
        results.hosts = host_results;
        results.end_time = chrono::Utc::now();
        results.duration = start_time.elapsed();
        results.calculate_stats();
        
        Ok(results)
    }

    /// Parse target specifications into IP addresses
    fn parse_targets(&self, targets: Vec<String>) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        
        for target in targets {
            if target.contains('/') {
                // CIDR notation
                let cidr_ips = parse_cidr(&target)?;
                ips.extend(cidr_ips);
            } else {
                // Single IP or hostname
                let ip: IpAddr = target.parse()
                    .map_err(|_| apexscan_core::Error::InvalidInput(
                        format!("Invalid IP address: {}", target)
                    ))?;
                ips.push(ip);
            }
        }
        
        Ok(ips)
    }

    /// Discover live hosts (simplified for now)
    async fn discover_hosts(&self, ips: &[IpAddr]) -> Result<Vec<IpAddr>> {
        // For now, assume all hosts are up (discovery implementation would go here)
        // In production, this would use apexscan-discovery
        Ok(ips.to_vec())
    }

    /// Scan a single host
    async fn scan_host(&self, ip: IpAddr) -> Result<HostResult> {
        let mut result = HostResult::new(Target::new(ip));
        result.state = HostState::Up;
        result.start_time = chrono::Utc::now();

        // Create scanner configuration
        let scanner_config = ScannerConfig {
            timeout: Duration::from_secs(2),
            max_retries: 2,
            max_concurrent: 100,
        };

        // Scan ports based on scan type
        match self.config.scan_type {
            ScanType::TcpSyn => {
                result.ports = self.scan_tcp_syn(ip, &scanner_config).await?;
            }
            ScanType::TcpConnect => {
                result.ports = self.scan_tcp_connect(ip, &scanner_config).await?;
            }
            ScanType::Udp => {
                result.ports = self.scan_udp(ip, &scanner_config).await?;
            }
            ScanType::TcpNull => {
                result.ports = self.scan_tcp_null(ip, &scanner_config).await?;
            }
            ScanType::TcpFin => {
                result.ports = self.scan_tcp_fin(ip, &scanner_config).await?;
            }
            ScanType::TcpXmas => {
                result.ports = self.scan_tcp_xmas(ip, &scanner_config).await?;
            }
            ScanType::TcpAck => {
                result.ports = self.scan_tcp_ack(ip, &scanner_config).await?;
            }
            ScanType::TcpWindow => {
                result.ports = self.scan_tcp_window(ip, &scanner_config).await?;
            }
            ScanType::TcpMaimon => {
                result.ports = self.scan_tcp_maimon(ip, &scanner_config).await?;
            }
        }

        // Filter to only show open ports and interesting states
        result.ports.retain(|p| {
            matches!(p.state, PortState::Open | PortState::OpenFiltered | PortState::Filtered)
        });

        // Step 4: Service/Version Detection (with CAP & AVM)
        if self.config.version_detection && !result.ports.is_empty() {
            result.ports = self.detect_services(ip, result.ports).await?;
        }

        // Step 5: Smart Scan Chaining (process CAP/AVM results)
        let mut chained_tasks = Vec::new();
        if !result.ports.is_empty() {
            let mut engine = self.chaining_engine.borrow_mut();
            for port in &result.ports {
                let tasks = engine.process_port_result(ip, port).await;
                chained_tasks.extend(tasks);
            }
        }

        // Step 6: Execute Chained Tasks
        if !chained_tasks.is_empty() {
            info!("Executing {} chained tasks for {}", chained_tasks.len(), ip);
            for task in chained_tasks {
                self.execute_chained_task(task, &mut result).await;
            }
        }

        // Step 7: OS Detection
        if self.config.os_detection {
            if let Ok(os_result) = self.detect_os(ip).await {
                result.os = vec![os_result];
            }
        }

        // Step 8: Script Scanning (ASE)
        if self.config.script_scan && !result.ports.is_empty() {
            result.scripts = self.run_scripts(ip, &result.ports).await.unwrap_or_default();
        }

        result.end_time = chrono::Utc::now();
        result.duration = result.end_time.signed_duration_since(result.start_time)
            .to_std()
            .unwrap_or_default();

        Ok(result)
    }

    /// TCP SYN scan implementation
    async fn scan_tcp_syn(&self, ip: IpAddr, config: &ScannerConfig) -> Result<Vec<apexscan_core::scan::PortResult>> {
        let scanner = TcpSynScanner::new(config.clone())?;
        let mut results = Vec::new();

        for &port in &self.config.ports {
            match scanner.scan_port(ip, port).await {
                Ok(scan_result) => {
                    results.push(apexscan_core::scan::PortResult {
                        port,
                        protocol: Protocol::Tcp,
                        state: scan_result.state,
                        service: None,
                        version: None,
                        extra_info: None,
                        confidence: 0.0,
                        patch_level: None,
                        security_posture: None,
                        impact_score: None,
                        cve_ids: None,
                    });
                }
                Err(e) => {
                    warn!("SYN scan failed for {}:{} - {}", ip, port, e);
                }
            }
        }

        Ok(results)
    }

    /// TCP Connect scan implementation
    async fn scan_tcp_connect(&self, ip: IpAddr, config: &ScannerConfig) -> Result<Vec<apexscan_core::scan::PortResult>> {
        let scanner = TcpConnectScanner::new(config.clone());
        let mut results = Vec::new();

        for &port in &self.config.ports {
            match scanner.scan_port(ip, port).await {
                Ok(scan_result) => {
                    results.push(apexscan_core::scan::PortResult {
                        port,
                        protocol: Protocol::Tcp,
                        state: scan_result.state,
                        service: None,
                        version: None,
                        extra_info: None,
                        confidence: 0.0,
                        patch_level: None,
                        security_posture: None,
                        impact_score: None,
                        cve_ids: None,
                    });
                }
                Err(e) => {
                    warn!("Connect scan failed for {}:{} - {}", ip, port, e);
                }
            }
        }

        Ok(results)
    }

    /// UDP scan implementation
    async fn scan_udp(&self, ip: IpAddr, config: &ScannerConfig) -> Result<Vec<apexscan_core::scan::PortResult>> {
        let scanner = UdpScanner::new(config.clone());
        let mut results = Vec::new();

        for &port in &self.config.ports {
            match scanner.scan_port(ip, port).await {
                Ok(scan_result) => {
                    results.push(apexscan_core::scan::PortResult {
                        port,
                        protocol: Protocol::Udp,
                        state: scan_result.state,
                        service: None,
                        version: None,
                        extra_info: None,
                        confidence: 0.0,
                        patch_level: None,
                        security_posture: None,
                        impact_score: None,
                        cve_ids: None,
                    });
                }
                Err(e) => {
                    warn!("UDP scan failed for {}:{} - {}", ip, port, e);
                }
            }
        }

        Ok(results)
    }

    /// TCP NULL scan implementation
    async fn scan_tcp_null(&self, ip: IpAddr, config: &ScannerConfig) -> Result<Vec<apexscan_core::scan::PortResult>> {
        let scanner = TcpNullScanner::new(config.clone())?;
        let mut results = Vec::new();

        for &port in &self.config.ports {
                match scanner.scan_port(ip, port).await {
                    Ok(scan_result) => {
                        results.push(apexscan_core::scan::PortResult {
                            port,
                            protocol: Protocol::Tcp,
                            state: scan_result.state,
                            service: None,
                            version: None,
                            extra_info: None,
                            confidence: 0.0,
                            patch_level: None,
                            security_posture: None,
                            impact_score: None,
                            cve_ids: None,
                        });
                    }
                    Err(e) => {
                        warn!("NULL scan failed for {}:{} - {}", ip, port, e);
                    }
                }
            }

            Ok(results)
    }

    /// TCP FIN scan implementation
    async fn scan_tcp_fin(&self, ip: IpAddr, config: &ScannerConfig) -> Result<Vec<apexscan_core::scan::PortResult>> {
        let scanner = TcpFinScanner::new(config.clone())?;
        let mut results = Vec::new();

        for &port in &self.config.ports {
                match scanner.scan_port(ip, port).await {
                    Ok(scan_result) => {
                        results.push(apexscan_core::scan::PortResult {
                            port,
                            protocol: Protocol::Tcp,
                            state: scan_result.state,
                            service: None,
                            version: None,
                            extra_info: None,
                            confidence: 0.0,
                            patch_level: None,
                            security_posture: None,
                            impact_score: None,
                            cve_ids: None,
                        });
                    }
                    Err(e) => {
                        warn!("FIN scan failed for {}:{} - {}", ip, port, e);
                    }
                }
            }

            Ok(results)
    }

    /// TCP Xmas scan implementation
    async fn scan_tcp_xmas(&self, ip: IpAddr, config: &ScannerConfig) -> Result<Vec<apexscan_core::scan::PortResult>> {
        let scanner = TcpXmasScanner::new(config.clone())?;
            let mut results = Vec::new();

            for &port in &self.config.ports {
                match scanner.scan_port(ip, port).await {
                    Ok(scan_result) => {
                        results.push(apexscan_core::scan::PortResult {
                            port,
                            protocol: Protocol::Tcp,
                            state: scan_result.state,
                            service: None,
                            version: None,
                            extra_info: None,
                            confidence: 0.0,
                            patch_level: None,
                            security_posture: None,
                            impact_score: None,
                            cve_ids: None,
                        });
                    }
                    Err(e) => {
                        warn!("Xmas scan failed for {}:{} - {}", ip, port, e);
                    }
                }
            }

            Ok(results)
    }

    /// TCP ACK scan implementation
    async fn scan_tcp_ack(&self, ip: IpAddr, config: &ScannerConfig) -> Result<Vec<apexscan_core::scan::PortResult>> {
        let scanner = TcpAckScanner::new(config.clone())?;
            let mut results = Vec::new();

            for &port in &self.config.ports {
                match scanner.scan_port(ip, port).await {
                    Ok(scan_result) => {
                        results.push(apexscan_core::scan::PortResult {
                            port,
                            protocol: Protocol::Tcp,
                            state: scan_result.state,
                            service: None,
                            version: None,
                            extra_info: None,
                            confidence: 0.0,
                            patch_level: None,
                            security_posture: None,
                            impact_score: None,
                            cve_ids: None,
                        });
                    }
                    Err(e) => {
                        warn!("ACK scan failed for {}:{} - {}", ip, port, e);
                    }
                }
            }

            Ok(results)
    }

    /// TCP Window scan implementation
    async fn scan_tcp_window(&self, ip: IpAddr, config: &ScannerConfig) -> Result<Vec<apexscan_core::scan::PortResult>> {
        let scanner = TcpWindowScanner::new(config.clone())?;
            let mut results = Vec::new();

            for &port in &self.config.ports {
                match scanner.scan_port(ip, port).await {
                    Ok(scan_result) => {
                        results.push(apexscan_core::scan::PortResult {
                            port,
                            protocol: Protocol::Tcp,
                            state: scan_result.state,
                            service: None,
                            version: None,
                            extra_info: None,
                            confidence: 0.0,
                            patch_level: None,
                            security_posture: None,
                            impact_score: None,
                            cve_ids: None,
                        });
                    }
                    Err(e) => {
                        warn!("Window scan failed for {}:{} - {}", ip, port, e);
                    }
                }
            }

            Ok(results)
    }

    /// TCP Maimon scan implementation
    async fn scan_tcp_maimon(&self, ip: IpAddr, config: &ScannerConfig) -> Result<Vec<apexscan_core::scan::PortResult>> {
        let scanner = TcpMaimonScanner::new(config.clone())?;
            let mut results = Vec::new();

            for &port in &self.config.ports {
                match scanner.scan_port(ip, port).await {
                    Ok(scan_result) => {
                        results.push(apexscan_core::scan::PortResult {
                            port,
                            protocol: Protocol::Tcp,
                            state: scan_result.state,
                            service: None,
                            version: None,
                            extra_info: None,
                            confidence: 0.0,
                            patch_level: None,
                            security_posture: None,
                            impact_score: None,
                            cve_ids: None,
                        });
                    }
                    Err(e) => {
                        warn!("Maimon scan failed for {}:{} - {}", ip, port, e);
                    }
                }
            }

            Ok(results)
    }

    /// Service/version detection with CAP and AVM integration
    async fn detect_services(&self, ip: IpAddr, ports: Vec<apexscan_core::scan::PortResult>) -> Result<Vec<apexscan_core::scan::PortResult>> {
        use apexscan_fingerprint::{
            banner::BannerGrabber,
            service::ServiceDetector,
            cap::HttpProfile,
            avm::CveDatabase,
        };

        let detector = ServiceDetector::new(Duration::from_secs(3));

        // Load CVE database for AVM
        let cve_db = CveDatabase::load_mock();

        let mut enhanced_ports = Vec::new();

        for mut port_result in ports {
            // Only detect services on open ports
            if port_result.state == PortState::Open {
                match detector.detect_service(ip, port_result.port.value()).await {
                    Ok(service_info) => {
                        port_result.service = service_info.service_name.clone();
                        port_result.version = service_info.version.clone();
                        port_result.extra_info = Some(service_info.banner.clone());
                        port_result.confidence = service_info.confidence;

                        // CAP: Contextual Asset Profiling for HTTP/HTTPS services
                        if let Some(ref svc) = service_info.service_name {
                            if svc == "http" || svc == "https" {
                                // Analyze HTTP headers for patch level inference
                                let http_profile = HttpProfile::from_headers(&service_info.banner);
                                port_result.patch_level = Some(http_profile.infer_patch_level());

                                // Determine security posture
                                let posture = if http_profile.patch_level_confidence > 0.8 {
                                    "Strong"
                                } else if http_profile.patch_level_confidence > 0.6 {
                                    "Moderate"
                                } else if http_profile.patch_level_confidence > 0.4 {
                                    "Weak"
                                } else {
                                    "Poor"
                                };
                                port_result.security_posture = Some(posture.to_string());

                                debug!("CAP analysis for {}:{} - Patch: {}, Posture: {}",
                                    ip, port_result.port,
                                    http_profile.infer_patch_level(),
                                    posture
                                );
                            }
                        }

                        // AVM: Automated Vulnerability Mapping
                        if let Some(ref svc) = service_info.service_name {
                            let impact = cve_db.query(svc, service_info.version.as_deref());

                            if !impact.cves.is_empty() {
                                port_result.impact_score = Some(impact.score);
                                port_result.cve_ids = Some(
                                    impact.cves.iter()
                                        .map(|cve| cve.cve_id.clone())
                                        .collect()
                                );

                                debug!("AVM analysis for {}:{} - Impact: {:.1}, CVEs: {}",
                                    ip, port_result.port,
                                    impact.score,
                                    impact.cves.len()
                                );
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Service detection failed for {}:{} - {}", ip, port_result.port, e);
                    }
                }
            }

            enhanced_ports.push(port_result);
        }

        Ok(enhanced_ports)
    }

    /// OS detection
    async fn detect_os(&self, ip: IpAddr) -> Result<apexscan_core::scan::OsResult> {
        // For now, return basic OS detection
        // Full implementation would use TCP/IP stack fingerprinting
        Ok(apexscan_core::scan::OsResult {
            name: "Unknown".to_string(),
            family: Some("Unknown".to_string()),
            version: None,
            confidence: 0.0,
            details: std::collections::HashMap::new(),
        })
    }

    /// Execute a chained task generated by Smart Scan Chaining
    async fn execute_chained_task(&self, task: ChainedTask, result: &mut HostResult) {
        info!("Executing chained task '{}' for {}:{}", task.rule_name, task.ip, task.port);

        match task.task_type {
            ChainedTaskType::RunScript { script_name } => {
                // Execute ASE script
                if let Ok(executor) = apexscan_scripting::python::PythonExecutor::new() {
                    let script_path = format!("scripts/{}.py", script_name);

                    // Find the port result to get service info
                    let port_result = result.ports.iter().find(|p| p.port.value() == task.port);

                    let context = apexscan_scripting::ScriptContext {
                        target_ip: task.ip.to_string(),
                        target_port: Some(task.port),
                        service_name: port_result.and_then(|p| p.service.clone()),
                        service_version: port_result.and_then(|p| p.version.clone()),
                        os_name: None,
                        banner: port_result.and_then(|p| p.extra_info.clone()),
                    };

                    match executor.execute_script(&script_path, &context) {
                        Ok(script_result) => {
                            info!("Chained script '{}' completed successfully", script_name);
                            result.scripts.push(apexscan_core::scan::ScriptResult {
                                script: format!("{} [chained]", script_name),
                                output: script_result.output,
                                duration: Duration::from_secs(0),
                                success: script_result.success,
                            });
                        }
                        Err(e) => {
                            warn!("Chained script '{}' failed: {}", script_name, e);
                        }
                    }
                }
            }
            ChainedTaskType::Rescan { scan_type } => {
                info!("Chained rescan requested (type: {}), but not yet implemented", scan_type);
                // TODO: Implement dynamic rescanning
            }
            ChainedTaskType::IncreaseVerbosity { level } => {
                info!("Chained verbosity increase requested (level: {})", level);
                // This would adjust tracing level dynamically
            }
        }
    }

    /// Run ApexScan Scripting Engine (ASE) scripts
    async fn run_scripts(&self, ip: IpAddr, ports: &[apexscan_core::scan::PortResult]) -> Result<Vec<apexscan_core::scan::ScriptResult>> {
        use apexscan_scripting::{python::PythonExecutor, ScriptContext};

        let executor = PythonExecutor::new()?;
        let mut script_results = Vec::new();

        // Run scripts for each open port
        for port_result in ports {
            if port_result.state == PortState::Open {
                // Determine which scripts to run based on port/service
                let scripts_to_run = self.select_scripts_for_port(port_result);

                for script_name in scripts_to_run {
                    let script_path = format!("scripts/{}.py", script_name);

                    let context = ScriptContext {
                        target_ip: ip.to_string(),
                        target_port: Some(port_result.port.value()),
                        service_name: port_result.service.clone(),
                        service_version: port_result.version.clone(),
                        os_name: None,
                        banner: port_result.extra_info.clone(),
                    };

                    match executor.execute_script(&script_path, &context) {
                        Ok(result) => {
                            script_results.push(apexscan_core::scan::ScriptResult {
                                script: script_name.to_string(),
                                output: result.output,
                                duration: Duration::from_secs(0), // TODO: actual duration
                                success: result.success,
                            });
                        }
                        Err(e) => {
                            warn!("Script {} failed: {}", script_name, e);
                        }
                    }
                }
            }
        }

        Ok(script_results)
    }

    /// Select appropriate scripts for a port based on service
    fn select_scripts_for_port(&self, port_result: &apexscan_core::scan::PortResult) -> Vec<String> {
        let mut scripts = Vec::new();

        // If user specified scripts, use those
        if !self.config.scripts.is_empty() {
            return self.config.scripts.clone();
        }

        // Otherwise, auto-select based on service/port
        match port_result.port.value() {
            21 => scripts.push("ftp-anon".to_string()),
            22 => scripts.push("ssh-auth-methods".to_string()),
            80 | 443 | 8080 | 8000 | 8443 => scripts.push("http-title".to_string()),
            _ => {}
        }

        scripts
    }

    fn create_scan_config(&self) -> ScanConfig {
        ScanConfig {
            scan_type: self.config.scan_type,
            targets: Vec::new(),
            ports: self.config.ports.clone(),
            os_detection: self.config.os_detection,
            version_detection: self.config.version_detection,
            script_scan: self.config.script_scan,
            scripts: self.config.scripts.clone(),
            timing: self.config.timing,
            max_retries: 2,
            timeout: std::time::Duration::from_secs(2),
            verbose: false,
        }
    }

    fn create_empty_results(&self, start_time: Instant) -> Result<ScanResults> {
        let mut results = ScanResults::new(self.create_scan_config());
        results.end_time = chrono::Utc::now();
        results.duration = start_time.elapsed();
        Ok(results)
    }
}
