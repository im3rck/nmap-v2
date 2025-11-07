# ApexScan Architecture

## Overview

ApexScan is built on a modular, high-performance architecture designed for scalability, extensibility, and maintainability.

## Core Principles

### 1. Memory Safety & Performance
- **Language**: Rust for core engine provides memory safety without garbage collection overhead
- **Concurrency**: Tokio async runtime for efficient I/O multiplexing
- **Zero-copy**: Minimize data copying in hot paths

### 2. Modularity
- **Workspace Structure**: Cargo workspace with independent crates
- **Clear Interfaces**: Well-defined APIs between modules
- **Dependency Management**: Minimal coupling between components

### 3. Deterministic Intelligence
- **No ML Models**: All detection logic is rules-based and explainable
- **State Machines**: Formal state machine models for protocol analysis
- **Signature Database**: Continuously updated detection signatures

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Web UI (React)                          │
│                    Network Topology Viewer                      │
│                    Real-time Progress Dashboard                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ REST API / WebSocket
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    API Server (Axum)                            │
│  - Authentication & Authorization                               │
│  - Job Management                                               │
│  - Real-time Event Streaming                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┴─────────────┐
                ▼                           ▼
┌───────────────────────────┐   ┌───────────────────────────┐
│  Master Coordinator       │   │  Graph Database (Neo4j)   │
│  - Job Distribution       │   │  - Network Topology       │
│  - Result Aggregation     │   │  - Asset Relationships    │
│  - Health Monitoring      │   │  - Attack Path Modeling   │
└───────────────────────────┘   └───────────────────────────┘
         │
         │ Redis Pub/Sub
         │
    ┌────┴────┬────────┬────────┐
    ▼         ▼        ▼        ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│ Node 1 │ │ Node 2 │ │ Node 3 │ │ Node N │
│        │ │        │ │        │ │        │
└────────┘ └────────┘ └────────┘ └────────┘
    │
    │ Each Node Contains:
    ├─ Packet Crafting Engine
    ├─ Scanning Engine
    ├─ Timing Engine (OTE)
    ├─ Detection Engine
    └─ Scripting Engine (ASE)
```

## Core Components

### 1. Packet Crafting Engine (`apexscan-packet`)

**Responsibilities**:
- Raw packet construction (TCP, UDP, ICMP, ARP)
- Packet parsing and validation
- Protocol-specific builders
- Checksum calculation

**Key Technologies**:
- Raw sockets (Linux)
- Custom packet structures
- Zero-copy parsing where possible

**Interfaces**:
```rust
pub trait PacketBuilder {
    fn build(&self) -> Result<Vec<u8>>;
}

pub trait PacketParser {
    fn parse(data: &[u8]) -> Result<Self>;
}
```

### 2. Discovery Engine (`apexscan-discovery`)

**Responsibilities**:
- Host discovery (ICMP, ARP, TCP/UDP)
- Network range management
- Live host detection
- Target prioritization

**Discovery Methods**:
- ICMP Echo/Timestamp/Netmask
- ARP sweeps (Layer 2)
- TCP SYN/ACK discovery
- UDP probe discovery
- SCTP INIT discovery

### 3. Scanning Engine (`apexscan-scanner`)

**Responsibilities**:
- Port scanning (all Nmap scan types)
- Connection state tracking
- Packet rate limiting
- Retry logic

**Scan Types**:
- TCP SYN (`-sS`)
- TCP Connect (`-sT`)
- UDP (`-sU`)
- TCP NULL (`-sN`)
- TCP FIN (`-sF`)
- TCP Xmas (`-sX`)
- ACK scan (`-sA`)
- Window scan (`-sW`)
- Maimon scan (`-sM`)

**Architecture**:
```rust
pub struct Scanner {
    timing_engine: Arc<TimingEngine>,
    packet_sender: PacketSender,
    state_tracker: StateTracker,
}

impl Scanner {
    pub async fn scan_port(&self, target: IpAddr, port: u16) -> Result<PortState>;
    pub async fn scan_range(&self, targets: Vec<Target>) -> ScanResults;
}
```

### 4. Optimized Timing Engine (OTE) (`apexscan-timing`)

**Responsibilities**:
- RTT measurement and prediction
- Adaptive rate limiting
- Jitter compensation
- Parallelism optimization

**Key Features**:
- **Dynamic Rate Adjustment**: Continuously monitors network conditions
- **Per-target Timing**: Independent timing profiles for each target
- **Predictive Modeling**: Uses exponential weighted moving average (EWMA) for RTT prediction
- **Congestion Detection**: Backs off when packet loss detected

**Algorithm**:
```
1. Initial probe: Measure baseline RTT
2. Establish timing class (T0-T5 equivalent)
3. For each packet:
   a. Predict optimal send time based on:
      - Current RTT estimate
      - Outstanding probe count
      - Historical loss rate
      - Network jitter
   b. Adjust parallelism window
   c. Update RTT estimate using EWMA
4. Continuously adapt to changing conditions
```

### 5. Fingerprinting Engine (`apexscan-fingerprint`)

**Responsibilities**:
- OS detection
- Service version detection
- Protocol analysis
- Banner grabbing

**OS Fingerprinting**:
- TCP/IP stack fingerprinting (window size, TTL, options)
- ICMP fingerprinting
- TCP timestamp analysis
- Deterministic state machine matching

**Service Detection**:
- Protocol-specific probes
- Banner analysis
- TLS cipher suite analysis
- HTTP header analysis
- Application-layer fingerprinting

**Contextual Asset Profiling (CAP)**:
```rust
pub struct AssetProfile {
    service: ServiceInfo,
    version: Option<String>,
    probable_patch_level: Option<String>,
    tls_ciphers: Vec<CipherSuite>,
    http_headers: HashMap<String, String>,
    tcp_fingerprint: TcpFingerprint,
    confidence: f32,
}
```

### 6. Scripting Engine (ASE) (`apexscan-scripting`)

**Responsibilities**:
- Script execution (Python/Go)
- NSE compatibility layer
- Result aggregation
- Resource management

**Architecture**:
```
┌─────────────────────────────────────────┐
│         Script Execution Layer          │
├─────────────────────────────────────────┤
│  Python Runtime  │  Go Runtime          │
│  (PyO3)          │  (via subprocess)    │
└─────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│      NSE Compatibility Shim             │
│  - API translation                      │
│  - Data structure conversion            │
└─────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         Core Scanning Engine            │
└─────────────────────────────────────────┘
```

**Script Categories**:
- Auth: Authentication testing
- Broadcast: Network broadcast analysis
- Brute: Credential brute-forcing
- Default: Default credential checking
- Discovery: Service enumeration
- DOS: Denial of service testing
- Exploit: Vulnerability exploitation
- Fuzzer: Protocol fuzzing
- Intrusive: Intrusive testing
- Malware: Malware detection
- Safe: Safe enumeration scripts
- Version: Version detection
- Vuln: Vulnerability detection

### 7. Distributed Coordinator (`apexscan-distributed`)

**Responsibilities**:
- Job distribution
- Node health monitoring
- Result aggregation
- Load balancing

**Components**:
- **Master**: Job scheduling and coordination
- **Workers**: Scan execution nodes
- **Redis**: Message queue and state storage
- **Health Monitor**: Node availability tracking

**Communication Protocol**:
```
Job Submission → Master
    ↓
Master splits job into tasks
    ↓
Tasks published to Redis queue
    ↓
Workers subscribe and claim tasks
    ↓
Workers execute scans
    ↓
Results published to Redis
    ↓
Master aggregates results
    ↓
Results written to database
```

### 8. Graph Database Integration (`apexscan-database`)

**Schema Design**:

**Nodes**:
- `Host`: IP address, MAC, OS info
- `Service`: Port, protocol, version
- `Vulnerability`: CVE ID, CVSS score
- `Network`: CIDR range, organization
- `Device`: Hardware type, vendor

**Edges**:
- `RUNS`: Host → Service
- `HAS_VULN`: Service → Vulnerability
- `COMMUNICATES`: Host → Host
- `MEMBER_OF`: Host → Network
- `ROUTES_TO`: Network → Network

**Example Queries**:
```cypher
// Find attack paths to critical servers
MATCH path = (attacker:Host)-[*1..5]-(critical:Host {criticality: 'high'})
WHERE attacker.external = true
RETURN path

// Find all hosts running vulnerable services
MATCH (h:Host)-[:RUNS]->(s:Service)-[:HAS_VULN]->(v:Vulnerability)
WHERE v.cvss_score > 7.0
RETURN h, s, v
```

### 9. Vulnerability Mapping Engine (`apexscan-vuln`)

**Automated Vulnerability Mapping (AVM)**:

**Data Sources**:
- NVD (National Vulnerability Database)
- CVE database
- VulnDB
- Exploit-DB
- Custom signatures

**Process**:
```
1. Service detected → Extract version
2. Query local CVE database
3. Match version against known vulnerabilities
4. Calculate Impact Score:
   - Base: CVSS score
   - Context: Asset criticality
   - Exploitability: Known exploits?
   - Network position: Internet-facing?
5. Return prioritized vulnerability list
```

**Impact Score Calculation**:
```rust
pub struct ImpactScore {
    cvss_base: f32,        // 0.0-10.0
    exploitability: f32,   // 0.0-1.0 (exploit availability)
    asset_value: f32,      // 0.0-1.0 (business impact)
    exposure: f32,         // 0.0-1.0 (external vs internal)
    age: f32,              // 0.0-1.0 (days since disclosure)
}

impl ImpactScore {
    pub fn calculate(&self) -> f32 {
        (self.cvss_base / 10.0) * 0.4 +
        self.exploitability * 0.25 +
        self.asset_value * 0.20 +
        self.exposure * 0.10 +
        self.age * 0.05
    }
}
```

### 10. Passive Discovery Engine (`apexscan-passive`)

**Responsibilities**:
- Network traffic capture
- Protocol analysis
- Asset discovery from traffic
- Service mapping

**Architecture**:
```
Network TAP / Mirror Port
         ↓
   Packet Capture (libpcap)
         ↓
   Protocol Dissection
    ├─ TCP/UDP flows
    ├─ DNS queries
    ├─ HTTP traffic
    ├─ TLS handshakes
    └─ SMB/CIFS
         ↓
   Asset Extraction
         ↓
   Graph Database Update
```

## Data Flow

### Active Scan Flow
```
1. User submits scan job via CLI/UI
2. API server validates and queues job
3. Master coordinator:
   a. Splits targets into chunks
   b. Assigns chunks to available workers
4. Workers perform scanning:
   a. Discovery phase (find live hosts)
   b. Port scanning phase
   c. Service detection phase
   d. OS fingerprinting phase
   e. Script execution phase
5. Results streamed back to master
6. Master writes to graph database
7. AVM triggers CVE correlation
8. UI updates in real-time
9. Final report generated
```

### Smart Scan Chaining
```
Port 445 (SMB) detected
    ↓
Check SMB version → SMB 2.1
    ↓
Execute smb-os-discovery.py
    ↓
Windows Server 2012 R2 detected
    ↓
Execute smb-vuln-ms17-010.py (EternalBlue)
    ↓
Vulnerability confirmed
    ↓
Log to database with HIGH priority
    ↓
Alert via UI
```

## Security Considerations

### Privilege Management
- Raw socket access requires CAP_NET_RAW
- Drop privileges after socket creation
- Sandboxed script execution

### Rate Limiting
- Per-target rate limits
- Global bandwidth limits
- Respect scan policies

### Data Protection
- Encrypted storage of sensitive scan results
- TLS for all API communications
- Role-based access control

## Performance Optimization

### Concurrency Model
- Async I/O for all network operations
- Work-stealing scheduler (tokio)
- Lock-free data structures where possible

### Memory Management
- Object pooling for frequent allocations
- Memory-mapped files for large datasets
- Streaming results to database

### Caching Strategy
- DNS cache
- ARP cache
- Service signature cache
- CVE database cache

## Testing Strategy

### Unit Tests
- Per-component test coverage >80%
- Property-based testing for packet parsing
- Mock network interfaces

### Integration Tests
- Test lab with virtual networks
- Automated scan result validation
- Performance benchmarking

### Fuzzing
- AFL++ for packet parsers
- Protocol state machine fuzzing
- Input validation testing

## Deployment Models

### Standalone
- Single binary
- Local database
- Web UI on localhost

### Distributed
- Multiple scan nodes
- Centralized database
- Centralized web UI
- Redis coordination

### Cloud Native
- Kubernetes deployment
- Auto-scaling workers
- Cloud database (Neo4j Aura)
- Object storage for results

## Future Enhancements

1. **IPv6 Support**: Full IPv6 scanning capabilities
2. **Mobile App**: iOS/Android clients
3. **Plugin System**: Third-party extension support
4. **Machine Learning**: Anomaly detection (optional, separate module)
5. **Blockchain Integration**: Immutable audit logs
6. **Container Scanning**: Docker/Kubernetes security auditing

## References

- [Nmap Network Scanning](https://nmap.org/book/)
- [TCP/IP Illustrated](https://www.amazon.com/TCP-Illustrated-Vol-Implementation/dp/0201633469)
- [The Rust Programming Language](https://doc.rust-lang.org/book/)
- [Tokio Documentation](https://tokio.rs/)
- [Neo4j Graph Database](https://neo4j.com/docs/)
