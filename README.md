# ApexScan v1.0 - Next-Generation Network Auditing Platform

ApexScan is a high-performance network security auditing platform designed as a successor to Nmap, providing full feature parity with enhanced performance, distributed scanning capabilities, and advanced data analysis.

## Key Features

### Nmap Feature Parity
- **Host Discovery**: ICMP, ARP sweeps, custom TCP/UDP probes
- **Port Scanning**: TCP SYN, Connect, UDP, NULL, FIN, Xmas scans
- **Service Detection**: Version detection with enhanced protocol analysis
- **OS Fingerprinting**: Deterministic state machine-based fingerprinting
- **Evasion Techniques**: Fragmentation, IP spoofing, decoy scans
- **Timing Controls**: Advanced timing control with dynamic optimization

### Advanced Features
- **Distributed Scanning**: Master-worker architecture for scalable scanning
- **Optimized Timing Engine (OTE)**: Dynamic RTT prediction and adaptive rate limiting
- **Contextual Asset Profiling (CAP)**: Deep protocol analysis for enhanced detection
- **Automated Vulnerability Mapping (AVM)**: Real-time CVE correlation and risk scoring
- **Passive Discovery Mode**: Zero-footprint network monitoring via packet inspection
- **Graph Database Integration**: Network topology modeling with Neo4j
- **ApexScan Scripting Engine (ASE)**: NSE-compatible scripting with Python/Go support
- **Web Interface**: Real-time visualization and control dashboard

## Technology Stack

- **Core Engine**: Rust (async with tokio)
- **Scripting**: Python (primary), Go (performance-critical)
- **Database**: Neo4j (graph), PostgreSQL (metadata)
- **Web Framework**: Axum (backend), React (frontend)
- **Distribution**: Redis (coordination)
- **Packet Processing**: libpnet, raw sockets

## Architecture

```
apexscan/
├── core/              # Core scanning engine (Rust)
│   ├── packet-craft/  # Raw packet creation and parsing
│   ├── discovery/     # Host discovery methods
│   ├── scanner/       # Port scanning engines
│   ├── fingerprint/   # OS and service detection
│   └── timing/        # Optimized timing engine
├── scripting/         # ApexScan Scripting Engine
├── distributed/       # Distributed scanning coordinator
├── database/          # Graph and relational database interfaces
├── api/               # RESTful API server
├── ui/                # Web user interface
└── cli/               # Command-line interface
```

## Project Status

**Current Phase**: Core Setup and Foundation

See [ROADMAP.md](ROADMAP.md) for detailed development plan.

## Requirements

- Rust 1.75+ (stable)
- Python 3.11+
- Go 1.21+ (optional, for performance scripts)
- Neo4j 5.0+
- Redis 7.0+
- Linux kernel 4.0+ (for raw socket support)

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/apexscan.git
cd apexscan

# Build core engine
cargo build --release

# Run tests
cargo test

# Install CLI
cargo install --path cli
```

## Quick Start

```bash
# Basic TCP SYN scan
apexscan -sS 192.168.1.0/24

# Full scan with OS detection and version detection
apexscan -A 192.168.1.1

# Distributed scan across multiple nodes
apexscan --distributed --nodes node1,node2,node3 -sS 10.0.0.0/8

# Launch web UI
apexscan --web-ui
```

## Design Principles

1. **Deterministic Logic Only**: No AI/ML models - all detection logic is rules-based and deterministic
2. **Memory Safety**: Rust's ownership system prevents common vulnerabilities
3. **Performance First**: Optimized for maximum throughput with minimal resource usage
4. **Scalability**: Designed from the ground up for distributed operation
5. **Extensibility**: Modular architecture with comprehensive scripting support

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

[License TBD]

## Security Notice

ApexScan is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems.
