# Network Monitor (netmon)

A free, open-source, per-process network monitor for macOS - an open-source alternative to Little Snitch.

## Overview

macOS shows network activity in Activity Monitor, but lacks:
- Per-connection visibility (just aggregate bytes)
- DNS resolution of remote IPs
- Historical logging
- Alerting for suspicious connections

This tool provides real-time network connection monitoring per process with DNS resolution, GeoIP location, and suspicious activity alerting.

## Sample Output

```
$ netmon
┌─────────────────────────────────────────────────────────────────────────────┐
│ PID    PROCESS           REMOTE                    PORT   STATE   LOCATION │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1842   Firefox           140.82.114.4 (github)     443    ESTAB   US       │
│ 1842   Firefox           151.101.1.69 (reddit)     443    ESTAB   US       │
│ 2103   Slack             34.120.54.55              443    ESTAB   US       │
│ 2451   Spotify           35.186.224.47             4070   ESTAB   US       │
│ 9012   suspicious.app    185.220.101.1             4444   ESTAB   RU  ⚠️   │
│ 501    mDNSResponder     224.0.0.251               5353   UDP     Local    │
└─────────────────────────────────────────────────────────────────────────────┘
Connections: 47 | Processes: 12 | Bandwidth: ↓ 2.3 MB/s ↑ 156 KB/s
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Network Monitor                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │   Collector  │───▶│   Enricher   │───▶│      Presenter       │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│         │                   │                      │                │
│         ▼                   ▼                      ▼                │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │ libproc API  │    │  DNS Cache   │    │    TUI (ratatui)     │  │
│  │ proc_info    │    │  GeoIP DB    │    │    JSON output       │  │
│  │ netstat data │    │  Process DB  │    │    Log file          │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                        Alert Engine                           │   │
│  │   • New process connecting    • Unusual port                  │   │
│  │   • Known malicious IP        • High bandwidth spike          │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. Connection Collector
Retrieves active network connections and maps them to processes using macOS `libproc` API.

### 2. DNS Enricher
Resolves IPs to hostnames with caching to avoid repeated lookups.

### 3. GeoIP Locator
Maps IPs to countries using MaxMind GeoLite2 database.

### 4. Alert Engine
Detects suspicious activity based on configurable rules.

### 5. TUI Presenter
Interactive terminal UI using `ratatui`.

---

## Milestones & Todo List

### Milestone 1: Core Skeleton ✅
- [x] Fix Cargo.toml (edition 2021 + dependencies)
- [x] Fix net_strucs.rs (proper type definitions)
- [x] Fix main.rs collector (libproc integration)
- [x] Basic console output

**Milestone 1 Summary**: Successfully implemented the basic project structure with:
- Fixed Cargo.toml with edition 2021 and core dependencies (tokio, clap, serde, chrono, anyhow)
- Implemented proper data structures in `net_strucs.rs` with Protocol, ConnectionState enums and Connection struct
- Created working process enumeration using libproc API
- Added basic console output showing all running processes with PID and process names
- Project compiles and runs successfully, listing ~270 processes on the system

*Next: Implement actual network connection collection and DNS resolution in Milestone 2*

### Milestone 2: Enrichment Foundation
- [ ] DNS resolution with caching
- [ ] GeoIP lookup (MaxMind GeoLite2)
- [ ] Process name resolution

### Milestone 3: Alert System Base
- [ ] Alert engine structure
- [ ] Basic rules
- [ ] Alert output format

### Milestone 4: TUI Foundation
- [ ] ratatui setup
- [ ] Connection table display
- [ ] Refresh loop

### Milestone 5: Interactive Features
- [ ] Filtering by process
- [ ] Sorting options
- [ ] Color coding by threat level

---

## Key Crates

| Crate | Purpose |
|-------|---------|
| `libproc` | macOS process/socket enumeration |
| `dns-lookup` | Reverse DNS resolution |
| `maxminddb` | GeoIP database reader |
| `ratatui` | Terminal UI |
| `tokio` | Async runtime |
| `clap` | CLI argument parsing |
| `serde` | Config/output serialization |
| `chrono` | Date/time handling |

---

## Data Structures

### Connection
```rust
pub struct Connection {
    pub pid: i32,
    pub process_name: String,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: Protocol,    // TCP, UDP
    pub state: ConnectionState,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
```

### Protocol
```rust
pub enum Protocol {
    Tcp,
    Udp,
}
```

### ConnectionState
```rust
pub enum ConnectionState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Unknown,
}
```

---

## Alert Rules

### Default Suspicious Ports
- 4444 (Metasploit)
- 1337 (Common backdoor)
- 31337 (Back Orifice)
- 6667 (IRC - potential C2)
- 5555 (ADB)
- 12345 (NetBus)
- 54321 (Back Orifice)

### Country Block List
- RU (Russia)
- CN (China)
- KP (North Korea)
- IR (Iran)
- SY (Syria)

---

## Configuration

Default config location: `~/.config/netmon/default.toml`

```toml
[refresh]
interval_ms = 1000

[geoip]
database_path = "data/GeoLite2-Country.mmdb"
auto_download = true

[alerts]
enabled = true
suspicious_ports = [4444, 1337, 31337, 6667, 5555, 12345, 54321]
blocked_countries = ["RU", "CN", "KP", "IR", "SY"]

[display]
show_dns = true
show_country = true
color_output = true
```

---

## File Structure

```
netmon/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs              # Entry point, CLI
│   ├── strucs/
│   │   └── net_strucs.rs    # Data structures
│   ├── collector/
│   │   ├── mod.rs
│   │   └── macos.rs         # libproc integration
│   ├── enricher/
│   │   ├── mod.rs
│   │   ├── dns.rs           # Reverse DNS
│   │   └── geoip.rs         # Country lookup
│   ├── alert/
│   │   ├── mod.rs
│   │   └── rules.rs         # Alert definitions
│   └── ui/
│       ├── mod.rs
│       └── tui.rs           # ratatui interface
├── config/
│   └── default.toml         # Default configuration
└── data/
    └── GeoLite2-Country.mmdb  # GeoIP database (downloaded on first run)
```

---

## Security Considerations

1. **Process name spoofing** - Malicious apps can impersonate legitimate processes
2. **Root access** - Some data requires elevated privileges
3. **GeoIP accuracy** - Not 100% accurate, use as heuristic only
4. **Short-lived connections** - May miss very brief connections

---

## Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| Root access needed | Graceful degradation - show what's available |
| High CPU on many connections | Efficient diffing, batch updates |
| GeoIP database updates | Auto-download MaxMind GeoLite2 |
| Short-lived connections | Consider eBPF for packet-level (future) |

---

## Future Enhancements

- Historical logging (SQLite)
- Network Extension for true firewall blocking
- Protocol detection (HTTP, SSH, TLS fingerprinting)
- Slack/webhook notifications
- Bandwidth tracking per connection

---

## License

MIT License - Open source and free forever.
