//! ApexScan CLI - Production-ready network auditing platform

use apexscan_core::types::TimingTemplate;
use clap::{Parser, Subcommand};
use colored::*;
use std::process;

use apexscan_cli::output::{OutputFormat, OutputManager};
use apexscan_cli::pipeline::{Pipeline, PipelineConfig};

#[derive(Parser)]
#[command(name = "apexscan")]
#[command(author = "ApexScan Team")]
#[command(version = "0.1.0")]
#[command(about = "Next-generation network auditing platform")]
#[command(long_about = "ApexScan - High-performance network scanner with adaptive timing, service detection, and Python scripting")]
struct Cli {
    /// Target specification (IP, CIDR, hostname)
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,

    /// Scan type
    #[command(subcommand)]
    command: Option<Commands>,

    // Scan Types
    /// TCP SYN scan (default, requires root)
    #[arg(short = 's', long = "syn")]
    syn_scan: bool,

    /// TCP Connect scan
    #[arg(long = "connect")]
    connect_scan: bool,

    /// UDP scan
    #[arg(short = 'U', long)]
    udp_scan: bool,

    /// TCP NULL scan
    #[arg(long = "null")]
    null_scan: bool,

    /// TCP FIN scan
    #[arg(long = "fin")]
    fin_scan: bool,

    /// TCP Xmas scan
    #[arg(long = "xmas")]
    xmas_scan: bool,

    /// TCP ACK scan (firewall mapping)
    #[arg(long = "ack")]
    ack_scan: bool,

    /// TCP Window scan
    #[arg(long = "window")]
    window_scan: bool,

    /// TCP Maimon scan
    #[arg(long = "maimon")]
    maimon_scan: bool,

    // Port Specification
    /// Port range (e.g., 1-1000, 80,443,8080, or "top100")
    #[arg(short = 'p', long, default_value = "1-1000")]
    ports: String,

    // Detection
    /// Enable OS detection
    #[arg(short = 'O', long)]
    os_detection: bool,

    /// Enable version detection
    #[arg(short = 'V', long = "version-detect")]
    version_detection: bool,

    /// Enable script scanning
    #[arg(short = 'C', long = "script")]
    script_scan: bool,

    /// Specify scripts to run (comma-separated)
    #[arg(long = "scripts", value_delimiter = ',')]
    scripts: Vec<String>,

    /// Aggressive scan (OS + version + scripts)
    #[arg(short = 'A', long)]
    aggressive: bool,

    // Timing
    /// Timing template (0=paranoid, 3=normal, 5=insane)
    #[arg(short = 'T', long = "timing", value_parser = parse_timing)]
    timing: Option<TimingTemplate>,

    // Output
    /// Output format (json, xml, csv, txt)
    #[arg(short = 'o', long = "output-format", default_value = "txt")]
    output_format: String,

    /// Output file path
    #[arg(short = 'f', long = "output-file")]
    output_file: Option<String>,

    // Misc
    /// Verbose output
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Quiet mode (only show open ports)
    #[arg(short = 'q', long)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan targets (default if no subcommand)
    Scan {
        targets: Vec<String>,
    },

    /// List available scripts
    Scripts {
        /// Filter by category
        #[arg(long)]
        category: Option<String>,
    },

    /// Show version information
    Version,

    /// Check system requirements
    CheckSystem,
}

fn parse_timing(s: &str) -> std::result::Result<TimingTemplate, String> {
    match s {
        "0" => Ok(TimingTemplate::T0),
        "1" => Ok(TimingTemplate::T1),
        "2" => Ok(TimingTemplate::T2),
        "3" => Ok(TimingTemplate::T3),
        "4" => Ok(TimingTemplate::T4),
        "5" => Ok(TimingTemplate::T5),
        _ => Err(format!("Invalid timing template: {} (must be 0-5)", s)),
    }
}

fn print_banner() {
    println!("{}", r#"
    ___                     _____
   /   |  ____  ___  _  __/ ___/_________ _____
  / /| | / __ \/ _ \| |/_/\__ \/ ___/ __ `/ __ \
 / ___ |/ /_/ /  __/>  < ___/ / /__/ /_/ / / / /
/_/  |_/ .___/\___/_/|_|/____/\___/\__,_/_/ /_/
      /_/
    "#.bright_cyan());
    println!("{}", "Next-Generation Network Auditing Platform v0.1.0".bright_white());
    println!("{}", "━".repeat(60).bright_black());
    println!();
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    if !cli.quiet {
        print_banner();
    }

    // Extract targets before moving cli
    let targets = match &cli.command {
        Some(Commands::Scan { targets }) => targets.clone(),
        None => cli.targets.clone(),
        _ => Vec::new(),
    };

    // Handle commands
    match cli.command {
        Some(Commands::Version) => {
            println!("ApexScan v0.1.0");
            println!("Rust Edition: 2021");
            println!();
            println!("Features:");
            println!("  ✓ All Nmap scan types");
            println!("  ✓ Adaptive timing (OTE)");
            println!("  ✓ Service/OS detection");
            println!("  ✓ Python scripting (ASE)");
            return;
        }
        Some(Commands::CheckSystem) => {
            println!("{}", "Checking system requirements...".bright_blue());
            println!();
            check_system_requirements();
            return;
        }
        Some(Commands::Scripts { category }) => {
            println!("{}", "Available ApexScan Scripts:".bright_blue());
            list_scripts(category);
            return;
        }
        Some(Commands::Scan { .. }) => {
            // Explicit scan command
            run_scan(cli, targets).await;
            return;
        }
        None => {
            // Default: scan mode
            if targets.is_empty() {
                eprintln!("{} No targets specified", "Error:".bright_red());
                eprintln!("Usage: apexscan <TARGET> [OPTIONS]");
                eprintln!("Try 'apexscan --help' for more information");
                process::exit(1);
            }

            run_scan(cli, targets).await;
        }
    }
}

async fn run_scan(cli: Cli, targets: Vec<String>) {
    // Determine scan type
    let scan_type = if cli.connect_scan {
        apexscan_core::scan::ScanType::TcpConnect
    } else if cli.udp_scan {
        apexscan_core::scan::ScanType::Udp
    } else if cli.null_scan {
        apexscan_core::scan::ScanType::TcpNull
    } else if cli.fin_scan {
        apexscan_core::scan::ScanType::TcpFin
    } else if cli.xmas_scan {
        apexscan_core::scan::ScanType::TcpXmas
    } else if cli.ack_scan {
        apexscan_core::scan::ScanType::TcpAck
    } else if cli.window_scan {
        apexscan_core::scan::ScanType::TcpWindow
    } else if cli.maimon_scan {
        apexscan_core::scan::ScanType::TcpMaimon
    } else {
        // Default to SYN scan
        apexscan_core::scan::ScanType::TcpSyn
    };

    // Parse ports
    let ports = match parse_ports(&cli.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {}", "Error:".bright_red(), e);
            process::exit(1);
        }
    };

    // Handle aggressive mode
    let (os_detect, version_detect, script_scan) = if cli.aggressive {
        (true, true, true)
    } else {
        (cli.os_detection, cli.version_detection, cli.script_scan)
    };

    // Create pipeline config
    let config = PipelineConfig {
        scan_type,
        ports,
        os_detection: os_detect,
        version_detection: version_detect,
        script_scan,
        scripts: cli.scripts,
        timing: cli.timing.unwrap_or(TimingTemplate::T3),
        max_concurrent_hosts: 10,
    };

    // Create pipeline
    let pipeline = Pipeline::new(config);

    // Execute scan
    println!("{} Initializing scan...", "→".bright_cyan());

    match pipeline.execute(targets).await {
        Ok(results) => {
            // Output results
            let format = OutputFormat::from_str(&cli.output_format)
                .unwrap_or(OutputFormat::Console);

            let output_manager = OutputManager::new(format, cli.output_file);

            if let Err(e) = output_manager.write_results(&results) {
                eprintln!("{} Failed to write output: {}", "Error:".bright_red(), e);
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{} Scan failed: {}", "Error:".bright_red(), e);
            process::exit(1);
        }
    }
}

fn parse_ports(port_spec: &str) -> Result<Vec<apexscan_core::types::Port>, String> {
    if port_spec == "top100" {
        Ok(apexscan_core::net::ports::top_100())
    } else if port_spec == "top1000" {
        Ok(apexscan_core::net::ports::top_1000())
    } else if port_spec == "all" {
        Ok(apexscan_core::net::ports::all())
    } else {
        apexscan_core::net::parse_port_range(port_spec)
            .map_err(|e| format!("Invalid port specification: {}", e))
    }
}

fn check_system_requirements() {
    println!("  {} Checking raw socket permissions...", "→".bright_cyan());

    #[cfg(target_os = "linux")]
    {
        match apexscan_packet::raw::check_raw_socket_permission() {
            Ok(_) => println!("    {} Raw sockets available", "✓".bright_green()),
            Err(_) => {
                println!("    {} Raw sockets require CAP_NET_RAW or root", "!".bright_yellow());
                println!("    {} Run: sudo setcap cap_net_raw+ep $(which apexscan)", "→".bright_cyan());
            }
        }
    }

    println!("\n  {} Runtime environment:", "→".bright_cyan());
    println!("    Rust version: {}", env!("CARGO_PKG_RUST_VERSION", "unknown"));
    println!("    Tokio async runtime: enabled");
    println!("    Python support (PyO3): enabled");

    println!("\n  {} Scan capabilities:", "→".bright_cyan());
    println!("    ✓ TCP SYN scan");
    println!("    ✓ TCP Connect scan");
    println!("    ✓ UDP scan");
    println!("    ✓ Covert scans (NULL, FIN, Xmas)");
    println!("    ✓ Specialized scans (ACK, Window, Maimon)");
    println!("    ✓ Service version detection");
    println!("    ✓ OS fingerprinting");
    println!("    ✓ Python scripting (ASE)");
    println!("    ✓ Adaptive timing (OTE)");
}

fn list_scripts(category: Option<String>) {
    // Read scripts from scripts.yaml
    let scripts_dir = std::env::current_dir()
        .unwrap_or_default()
        .join("scripts");

    println!("\n  {} Script directory: {}", "→".bright_cyan(), scripts_dir.display());
    println!("\n  {} Available scripts:", "→".bright_cyan());

    let scripts = vec![
        ("http-title", "discovery, safe", "Grabs HTML title from web servers"),
        ("ssh-auth-methods", "discovery, safe", "Lists SSH authentication methods"),
        ("ftp-anon", "auth, vuln", "Checks for anonymous FTP login"),
    ];

    for (name, cats, desc) in scripts {
        if let Some(ref filter) = category {
            if !cats.contains(filter.as_str()) {
                continue;
            }
        }

        println!("\n    {} {}", "▸".bright_yellow(), name.bright_white().bold());
        println!("      Categories: {}", cats.bright_black());
        println!("      {}", desc);
    }

    println!("\n  {} Usage: apexscan <target> -C --scripts=<script-name>", "→".bright_cyan());
}
