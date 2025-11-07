//! ApexScan CLI - Command-line interface for ApexScan network auditing platform

use apexscan_core::types::TimingTemplate;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::process;

#[derive(Parser)]
#[command(name = "apexscan")]
#[command(author = "ApexScan Team")]
#[command(version = "0.1.0")]
#[command(about = "Next-generation network auditing platform", long_about = None)]
struct Cli {
    /// Target specification (IP, CIDR, hostname)
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    /// Scan type
    #[command(subcommand)]
    command: Option<Commands>,

    /// TCP SYN scan (default)
    #[arg(short = 'S', long)]
    syn_scan: bool,

    /// TCP Connect scan
    #[arg(short = 'T', long)]
    connect_scan: bool,

    /// UDP scan
    #[arg(short = 'U', long)]
    udp_scan: bool,

    /// TCP NULL scan
    #[arg(long)]
    null_scan: bool,

    /// TCP FIN scan
    #[arg(long)]
    fin_scan: bool,

    /// TCP Xmas scan
    #[arg(long)]
    xmas_scan: bool,

    /// Port range (e.g., 1-1000, 80,443, or "top100")
    #[arg(short = 'p', long, default_value = "top100")]
    ports: String,

    /// Enable OS detection
    #[arg(short = 'O', long)]
    os_detection: bool,

    /// Enable version detection
    #[arg(short = 'V', long)]
    version_detection: bool,

    /// Enable script scanning
    #[arg(short = 'C', long)]
    script_scan: bool,

    /// Specify scripts to run
    #[arg(long, value_delimiter = ',')]
    scripts: Vec<String>,

    /// Aggressive scan (OS + version + scripts)
    #[arg(short = 'A', long)]
    aggressive: bool,

    /// Timing template (0-5)
    #[arg(short = 't', long, value_parser = parse_timing)]
    timing: Option<TimingTemplate>,

    /// Verbose output
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Output format (json, xml, txt)
    #[arg(short = 'o', long, default_value = "txt")]
    output_format: String,

    /// Output file
    #[arg(long)]
    output_file: Option<String>,

    /// Distributed scan mode
    #[arg(long)]
    distributed: bool,

    /// Scan nodes (comma-separated)
    #[arg(long, value_delimiter = ',')]
    nodes: Vec<String>,

    /// Web UI mode
    #[arg(long)]
    web_ui: bool,

    /// Web UI port
    #[arg(long, default_value = "8080")]
    ui_port: u16,

    /// Passive discovery mode
    #[arg(long)]
    passive: bool,

    /// Network interface for passive mode
    #[arg(long)]
    interface: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan targets
    Scan {
        /// Target(s) to scan
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

    /// Start web UI server
    WebUI {
        /// Port to bind to
        #[arg(short = 'p', long, default_value = "8080")]
        port: u16,
    },

    /// Check system requirements
    CheckSystem,
}

fn parse_timing(s: &str) -> Result<TimingTemplate, String> {
    match s {
        "0" => Ok(TimingTemplate::T0),
        "1" => Ok(TimingTemplate::T1),
        "2" => Ok(TimingTemplate::T2),
        "3" => Ok(TimingTemplate::T3),
        "4" => Ok(TimingTemplate::T4),
        "5" => Ok(TimingTemplate::T5),
        _ => Err(format!("Invalid timing template: {}", s)),
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

fn check_permissions() -> bool {
    #[cfg(target_os = "linux")]
    {
        match apexscan_packet::raw::check_raw_socket_permission() {
            Ok(_) => true,
            Err(e) => {
                eprintln!("{} {}", "Error:".bright_red(), e);
                eprintln!(
                    "{} Run with sudo or set capabilities: sudo setcap cap_net_raw+ep /path/to/apexscan",
                    "Hint:".bright_yellow()
                );
                false
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        match apexscan_packet::raw::check_raw_socket_permission() {
            Ok(_) => true,
            Err(e) => {
                eprintln!("{} {}", "Error:".bright_red(), e);
                eprintln!("{} Run with administrator privileges", "Hint:".bright_yellow());
                false
            }
        }
    }
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

    print_banner();

    // Handle commands
    match cli.command {
        Some(Commands::Version) => {
            println!("ApexScan version 0.1.0");
            println!("Rust core engine: {}", env!("RUSTC_VERSION", "unknown"));
            return;
        }
        Some(Commands::CheckSystem) => {
            println!("{}", "Checking system requirements...".bright_blue());
            println!();

            // Check raw socket permissions
            print!("  Raw socket permissions: ");
            if check_permissions() {
                println!("{}", "✓ OK".bright_green());
            } else {
                println!("{}", "✗ FAILED".bright_red());
            }

            println!();
            return;
        }
        Some(Commands::Scripts { category }) => {
            println!("{}", "Available scripts:".bright_blue());
            println!("  (Script engine not yet implemented)");
            return;
        }
        Some(Commands::WebUI { port }) => {
            println!(
                "{}",
                format!("Starting web UI on port {}...", port).bright_blue()
            );
            println!("  (Web UI not yet implemented)");
            return;
        }
        Some(Commands::Scan { targets }) => {
            // Scan subcommand
            println!("{}", "Scan functionality coming soon...".bright_yellow());
            println!("Targets: {:?}", targets);
            return;
        }
        None => {}
    }

    // Main scan mode
    if let Some(target) = cli.target {
        // Check permissions first
        if !check_permissions() {
            process::exit(1);
        }

        println!("{}", format!("Scanning target: {}", target).bright_blue());
        println!("  Ports: {}", cli.ports);
        println!("  Timing: {:?}", cli.timing.unwrap_or(TimingTemplate::T3));

        if cli.aggressive {
            println!("  Mode: {}", "Aggressive".bright_yellow());
        }

        println!();
        println!(
            "{}",
            "Core scanning engine is under development. Stay tuned!".bright_yellow()
        );
    } else if cli.web_ui {
        println!(
            "{}",
            format!("Starting web UI on port {}...", cli.ui_port).bright_blue()
        );
        println!("  (Web UI not yet implemented)");
    } else if cli.passive {
        println!("{}", "Starting passive discovery mode...".bright_blue());
        if let Some(iface) = cli.interface {
            println!("  Interface: {}", iface);
        }
        println!("  (Passive mode not yet implemented)");
    } else {
        println!(
            "{}",
            "No target specified. Use --help for usage information.".bright_yellow()
        );
        process::exit(1);
    }
}
