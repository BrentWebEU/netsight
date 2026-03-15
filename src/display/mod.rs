//! Structured display formatting for network connections.
//!
//! This module provides various output formats for network connections including
//! table, JSON, CSV, and enhanced visual displays with statistics.

#![allow(dead_code)]

use crate::error::{NetworkMonitorError, Result};
use crate::strucs::net_strucs::Connection;
use crate::config::SortBy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Display configuration
#[derive(Debug, Clone)]
pub struct DisplayConfig {
    pub show_colors: bool,
    pub show_stats: bool,
    pub max_table_rows: Option<usize>,
    pub sort_by: SortBy,
}


impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            show_colors: true,
            show_stats: true,
            max_table_rows: Some(50),
            sort_by: crate::config::SortBy::ProcessName,
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub total_connections: usize,
    pub by_protocol: HashMap<String, usize>,
    pub by_state: HashMap<String, usize>,
    pub unique_remote_hosts: usize,
    pub unique_processes: usize,
    pub external_connections: usize,
    pub local_connections: usize,
}

/// Structured display formatter
pub struct ConnectionDisplay {
    config: DisplayConfig,
}

impl ConnectionDisplay {
    pub fn new(config: DisplayConfig) -> Self {
        Self { config }
    }

    pub fn display_connections(&mut self, connections: Vec<Connection>) -> Result<()> {
        if connections.is_empty() {
            self.print_header("No connections found");
            println!("No active network connections match the current filters.");
            return Ok(());
        }

        // Sort connections
        let mut sorted_connections = connections;
        self.sort_connections(&mut sorted_connections);

        // Apply row limit
        let display_connections = if let Some(limit) = self.config.max_table_rows {
            if sorted_connections.len() > limit {
                println!("\n⚠️  Showing first {} of {} connections:", limit, sorted_connections.len());
                sorted_connections.into_iter().take(limit).collect()
            } else {
                sorted_connections
            }
        } else {
            sorted_connections
        };

        // Display header and stats
        self.print_header(&format!("Network Connections ({})", display_connections.len()));

        if self.config.show_stats {
            let stats = self.calculate_stats(&display_connections);
            self.display_stats(&stats);
        }

        // Display table
        self.display_table(&display_connections)?;

        Ok(())
    }

    fn print_header(&self, title: &str) {
        if self.config.show_colors {
            println!("\n\x1b[1;36m{}\x1b[0m", title);
            println!("{}", "═".repeat(title.len()));
        } else {
            println!("\n{}", title);
            println!("{}", "═".repeat(title.len()));
        }
    }

    fn display_table(&self, connections: &[Connection]) -> Result<()> {
        println!();

        // Table header
        let header = format!(
            "{:<8} {:<30} {:<20} {:<8} {:<12} {:<12} {:<10}",
            "PID", "PROCESS", "REMOTE", "PORT", "PROTOCOL", "STATE", "BYTES"
        );
        
        if self.config.show_colors {
            println!("\x1b[1;37m{}\x1b[0m", header);
        } else {
            println!("{}", header);
        }
        println!("{}", "─".repeat(95));

        // Table rows
        for conn in connections {
            let process_name = self.truncate_string(&conn.process_name, 29);
            let remote_ip = conn.remote_addr.ip();
            let port = conn.remote_addr.port();
            let protocol = self.format_protocol(&conn.protocol);
            let state = self.format_state(&conn.state);
            let bytes = self.format_bytes(conn.bytes_in + conn.bytes_out);

            let row = format!(
                "{:<8} {:<30} {:<20} {:<8} {:<12} {:<12} {:<10}",
                conn.pid, process_name, remote_ip, port, protocol, state, bytes
            );

            if self.config.show_colors {
                let colored_row = self.colorize_connection(&row, conn);
                println!("{}", colored_row);
            } else {
                println!("{}", row);
            }
        }

        println!();
        Ok(())
    }

    fn display_stats(&self, stats: &ConnectionStats) {
        println!("\n📊 Connection Statistics:");
        println!("   Total: {} | External: {} | Local: {}", 
                stats.total_connections, stats.external_connections, stats.local_connections);
        println!("   Unique Hosts: {} | Processes: {}", stats.unique_remote_hosts, stats.unique_processes);
        
        // Protocol breakdown
        if !stats.by_protocol.is_empty() {
            let protocols: Vec<String> = stats.by_protocol
                .iter()
                .map(|(p, c)| format!("{}: {}", p, c))
                .collect();
            println!("   Protocols: {}", protocols.join(", "));
        }

        // State breakdown
        if !stats.by_state.is_empty() {
            let states: Vec<String> = stats.by_state
                .iter()
                .map(|(s, c)| format!("{}: {}", s, c))
                .collect();
            println!("   States: {}", states.join(", "));
        }
        println!();
    }

    fn calculate_stats(&self, connections: &[Connection]) -> ConnectionStats {
        let mut stats = ConnectionStats {
            total_connections: connections.len(),
            by_protocol: HashMap::new(),
            by_state: HashMap::new(),
            unique_remote_hosts: 0,
            unique_processes: 0,
            external_connections: 0,
            local_connections: 0,
        };

        let mut remote_hosts = std::collections::HashSet::new();
        let mut processes = std::collections::HashSet::new();

        for conn in connections {
            // Protocol stats
            let protocol = format!("{:?}", conn.protocol);
            *stats.by_protocol.entry(protocol).or_insert(0) += 1;

            // State stats
            let state = format!("{:?}", conn.state);
            *stats.by_state.entry(state).or_insert(0) += 1;

            // Unique hosts and processes
            remote_hosts.insert(conn.remote_addr.ip());
            processes.insert(conn.pid);

            // External vs local
            if self.is_external_ip(conn.remote_addr.ip()) {
                stats.external_connections += 1;
            } else {
                stats.local_connections += 1;
            }
        }

        stats.unique_remote_hosts = remote_hosts.len();
        stats.unique_processes = processes.len();

        stats
    }

    fn sort_connections(&self, connections: &mut [Connection]) {
        use crate::strucs::net_strucs::Protocol;
        match self.config.sort_by {
            SortBy::ProcessName => connections.sort_by(|a, b| a.process_name.cmp(&b.process_name)),
            SortBy::RemoteAddress => connections.sort_by(|a, b| a.remote_addr.ip().cmp(&b.remote_addr.ip())),
            SortBy::LocalAddress => connections.sort_by(|a, b| a.local_addr.ip().cmp(&b.local_addr.ip())),
            SortBy::Port => connections.sort_by_key(|c| c.remote_addr.port()),
            SortBy::Protocol => connections.sort_by(|a, b| {
                match (&a.protocol, &b.protocol) {
                    (Protocol::Tcp, Protocol::Tcp) => std::cmp::Ordering::Equal,
                    (Protocol::Tcp, Protocol::Udp) => std::cmp::Ordering::Less,
                    (Protocol::Udp, Protocol::Tcp) => std::cmp::Ordering::Greater,
                    (Protocol::Udp, Protocol::Udp) => std::cmp::Ordering::Equal,
                }
            }),
            SortBy::State => connections.sort_by(|a, b| format!("{:?}", a.state).cmp(&format!("{:?}", b.state))),
            SortBy::Bandwidth => connections.sort_by(|a, b| (a.bytes_in + a.bytes_out).cmp(&(b.bytes_in + b.bytes_out))),
        }
    }

    fn format_protocol(&self, protocol: &crate::strucs::net_strucs::Protocol) -> String {
        match protocol {
            crate::strucs::net_strucs::Protocol::Tcp => "TCP".to_string(),
            crate::strucs::net_strucs::Protocol::Udp => "UDP".to_string(),
        }
    }

    fn format_state(&self, state: &crate::strucs::net_strucs::ConnectionState) -> String {
        format!("{:?}", state).chars().take(10).collect()
    }

    fn format_bytes(&self, bytes: u64) -> String {
        if bytes < 1024 {
            format!("{}B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1}K", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    fn truncate_string(&self, s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len.saturating_sub(3)])
        }
    }

    fn is_external_ip(&self, ip: std::net::IpAddr) -> bool {
        use crate::scanner::network_utils::NetworkUtils;
        !NetworkUtils::is_private_ip(&ip) && !ip.is_loopback()
    }

    fn colorize_connection(&self, row: &str, conn: &Connection) -> String {
        let mut colored = row.to_string();
        
        // Color based on protocol
        let protocol_color = match conn.protocol {
            crate::strucs::net_strucs::Protocol::Tcp => "\x1b[32m", // Green
            crate::strucs::net_strucs::Protocol::Udp => "\x1b[34m", // Blue
        };
        
        // Color based on state
        let _state_color = match conn.state {
            crate::strucs::net_strucs::ConnectionState::Established => "\x1b[32m", // Green
            crate::strucs::net_strucs::ConnectionState::Listen => "\x1b[33m",    // Yellow
            crate::strucs::net_strucs::ConnectionState::TimeWait => "\x1b[31m",     // Red
            _ => "\x1b[37m", // White
        };

        // Apply colors (simplified - in a real implementation, you'd want more precise positioning)
        colored = colored.replace("TCP", &format!("{}TCP\x1b[0m", protocol_color));
        colored = colored.replace("UDP", &format!("{}UDP\x1b[0m", protocol_color));
        
        colored
    }

    pub fn display_json(&self, connections: &[Connection]) -> Result<()> {
        let json = serde_json::to_string_pretty(connections)
            .map_err(|e| NetworkMonitorError::parse_with_source("Failed to serialize JSON", "output", e))?;
        println!("{}", json);
        Ok(())
    }

    pub fn display_csv(&self, connections: &[Connection]) -> Result<()> {
        println!("pid,process_name,local_address,remote_address,protocol,state,bytes_in,bytes_out");
        for conn in connections {
            println!("{},{},{},{},{},{},{},{}",
                conn.pid,
                self.escape_csv_field(&conn.process_name),
                conn.local_addr,
                conn.remote_addr,
                self.format_protocol(&conn.protocol),
                self.format_state(&conn.state),
                conn.bytes_in,
                conn.bytes_out
            );
        }
        Ok(())
    }

    fn escape_csv_field(&self, field: &str) -> String {
        if field.contains(',') || field.contains('"') || field.contains('\n') {
            format!("\"{}\"", field.replace('"', "\"\""))
        } else {
            field.to_string()
        }
    }
}

impl Default for ConnectionDisplay {
    fn default() -> Self {
        Self::new(DisplayConfig::default())
    }
}
