//! Active connection scanner for monitoring established network connections.
//!
//! This module provides functionality to scan and monitor active network connections
//! on the system, associating them with processes and providing detailed information.

use crate::config::NetworkConfig;
use crate::error::{NetworkMonitorError, Result};
use crate::strucs::net_strucs::{Connection, Protocol, ConnectionState};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::{info, debug, warn};

/// Scanner for active network connections
pub struct ActiveConnectionScanner {
    config: NetworkConfig,
    connection_cache: HashMap<u32, Connection>,
    last_scan: Option<Instant>,
}

impl ActiveConnectionScanner {
    /// Create a new active connection scanner
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            connection_cache: HashMap::new(),
            last_scan: None,
        }
    }

    /// Scan for active network connections
    pub async fn scan_connections(&mut self) -> Result<Vec<Connection>> {
        let start_time = Instant::now();
        info!("Starting active connection scan");

        let connections = self.create_demo_connections().await?;
        
        // Update cache and track changes
        self.update_connection_cache(&connections);

        let scan_duration = start_time.elapsed();
        info!(
            "Connection scan completed: {} connections found in {:?}",
            connections.len(),
            scan_duration
        );

        // Apply filters
        let connections = self.apply_filters(connections);

        Ok(connections)
    }

    /// Scan for real network connections using lsof
    async fn create_demo_connections(&self) -> Result<Vec<Connection>> {
        let mut connections = Vec::new();

        // Use lsof to get real network connections
        let output = Command::new("lsof")
            .args(&["-i", "-n", "-P"])
            .output()
            .map_err(|e| NetworkMonitorError::io_with_source("Failed to execute lsof", e))?;

        if !output.status.success() {
            warn!("lsof command failed: {}", String::from_utf8_lossy(&output.stderr));
            return Ok(connections);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("lsof output: {}", stdout);

        // Parse lsof output
        for line in stdout.lines().skip(1) { // Skip header line
            if let Some(connection) = self.parse_lsof_line(line)? {
                connections.push(connection);
            }
        }

        info!("Found {} real network connections", connections.len());
        Ok(connections)
    }

    /// Parse a single line from lsof output
    fn parse_lsof_line(&self, line: &str) -> Result<Option<Connection>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            return Ok(None);
        }

        let command = parts[0];
        let pid_str = parts[1];
        let _user = parts[2];
        let _fd = parts[3];
        let _type = parts[4];
        let _device = parts[5];
        let _size_off = parts[6];
        let _node = parts[7];
        let name = if parts.len() > 8 { parts[8] } else { "" };

        // Parse PID
        let pid = pid_str.parse::<i32>()
            .map_err(|e| NetworkMonitorError::parse_with_source("Invalid PID", "lsof parsing", e))?;

        // Skip if not a network connection or if it's listening
        if !name.contains("->") && !name.contains("(") {
            return Ok(None);
        }

        // Parse connection details from name field
        let (protocol, local_addr, remote_addr, state) = self.parse_connection_name(name)?;

        // Only include established connections and some UDP
        if !matches!(state, ConnectionState::Established) && !matches!(protocol, Protocol::Udp) {
            return Ok(None);
        }

        Ok(Some(Connection {
            pid,
            process_name: command.to_string(),
            local_addr,
            remote_addr,
            protocol,
            state,
            bytes_in: 0, // lsof doesn't provide byte counts
            bytes_out: 0,
        }))
    }

    /// Parse connection details from lsof name field
    fn parse_connection_name(&self, name: &str) -> Result<(Protocol, std::net::SocketAddr, std::net::SocketAddr, ConnectionState)> {
        // Examples:
        // "192.168.1.100:54321->8.8.8.8:53 (ESTABLISHED)"
        // "127.0.0.1:631 (LISTEN)"
        // "*:22 (LISTEN)"
        // "UDP *:5353"

        let protocol = if name.to_uppercase().contains("TCP") {
            Protocol::Tcp
        } else if name.to_uppercase().contains("UDP") {
            Protocol::Udp
        } else {
            Protocol::Tcp // Default to TCP
        };

        // Extract addresses and state
        let (addr_part, state_part): (&str, &str) = if let Some(paren_start) = name.find('(') {
            let addr_part = &name[..paren_start].trim();
            let state_part = &name[paren_start + 1..name.find(')').unwrap_or(name.len())];
            (addr_part, state_part)
        } else {
            (name.trim(), "ESTABLISHED")
        };

        // Parse state
        let state: ConnectionState = match state_part.to_uppercase().as_str() {
            "ESTABLISHED" => ConnectionState::Established,
            "LISTEN" => ConnectionState::Listen,
            "CLOSE_WAIT" => ConnectionState::CloseWait,
            "TIME_WAIT" => ConnectionState::TimeWait,
            "FIN_WAIT1" => ConnectionState::FinWait1,
            "FIN_WAIT2" => ConnectionState::FinWait2,
            "LAST_ACK" => ConnectionState::LastAck,
            "CLOSING" => ConnectionState::Closing,
            "SYN_SENT" => ConnectionState::SynSent,
            "SYN_RECEIVED" => ConnectionState::SynReceived,
            _ => ConnectionState::Established,
        };

        // Parse addresses
        let (local_addr_str, remote_addr_str): (&str, &str) = if let Some(arrow_pos) = addr_part.find("->") {
            let local_addr_str = &addr_part[..arrow_pos];
            let remote_addr_str = &addr_part[arrow_pos + 2..];
            (local_addr_str, remote_addr_str)
        } else {
            // For listening sockets or UDP without remote
            (addr_part, "0.0.0.0:0")
        };

        // Clean up addresses (remove protocol prefixes)
        let local_addr_clean = local_addr_str.replace("TCP ", "").replace("UDP ", "");
        let remote_addr_clean = remote_addr_str.replace("TCP ", "").replace("UDP ", "");

        // Parse socket addresses
        let local_addr = self.parse_socket_addr(&local_addr_clean)?;
        let remote_addr = self.parse_socket_addr(&remote_addr_clean)?;

        Ok((protocol, local_addr, remote_addr, state))
    }

    /// Parse socket address from string
    fn parse_socket_addr(&self, addr_str: &str) -> Result<std::net::SocketAddr> {
        // Handle wildcard addresses
        if addr_str.starts_with("*:") {
            let port_str = &addr_str[2..];
            let _port = port_str.parse::<u16>()
                .map_err(|e| NetworkMonitorError::parse_with_source("Invalid port", "socket address parsing", e))?;
            return Ok("0.0.0.0:0".parse().unwrap()); // Use placeholder for wildcard
        }

        // Remove any remaining protocol prefixes
        let clean_addr = addr_str.split_whitespace().next().unwrap_or(addr_str);
        
        clean_addr.parse()
            .map_err(|e| NetworkMonitorError::parse_with_source("Invalid socket address", "address parsing", e))
    }

    /// Update the connection cache with new connections
    fn update_connection_cache(&mut self, connections: &[Connection]) {
        self.connection_cache.clear();
        
        for conn in connections {
            // Create a simple hash key from connection details
            let key = self.connection_key(conn);
            self.connection_cache.insert(key, conn.clone());
        }

        self.last_scan = Some(Instant::now());
    }

    /// Generate a cache key for a connection
    fn connection_key(&self, conn: &Connection) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        conn.remote_addr.hash(&mut hasher);
        conn.local_addr.hash(&mut hasher);
        conn.protocol.hash(&mut hasher);
        hasher.finish() as u32
    }

    /// Apply configured filters to connections
    fn apply_filters(&self, mut connections: Vec<Connection>) -> Vec<Connection> {
        // Filter by localhost
        if self.config.exclude_localhost {
            connections.retain(|conn| !conn.remote_addr.ip().is_loopback());
        }

        // Filter by private networks
        if self.config.exclude_private {
            connections.retain(|conn| !self.is_private_ip(&conn.remote_addr.ip()));
        }

        // Filter by specific ports
        if !self.config.monitor_ports.is_empty() {
            connections.retain(|conn| self.config.monitor_ports.contains(&conn.remote_addr.port()));
        }

        // Limit maximum connections
        if connections.len() > self.config.max_connections {
            connections.truncate(self.config.max_connections);
        }

        connections
    }

    /// Check if an IP address is private
    fn is_private_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => self.is_private_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.is_private_ipv6(ipv6),
        }
    }

    /// Check if an IPv4 address is private
    fn is_private_ipv4(&self, ip: &Ipv4Addr) -> bool {
        ip.is_private() || 
        ip.octets()[0] == 10 ||                           // 10.0.0.0/8
        (ip.octets()[0] == 172 && ip.octets()[1] >= 16 && ip.octets()[1] <= 31) || // 172.16.0.0/12
        (ip.octets()[0] == 192 && ip.octets()[1] == 168) // 192.168.0.0/16
    }

    /// Check if an IPv6 address is private
    fn is_private_ipv6(&self, ip: &Ipv6Addr) -> bool {
        ip.is_loopback() || ip.is_unspecified() || ip.segments()[0] == 0xfc00 // Unique local address
    }

    /// Get statistics about the last scan
    pub fn get_scan_stats(&self) -> ScanStats {
        ScanStats {
            total_connections: self.connection_cache.len(),
            last_scan: self.last_scan,
            scan_interval: Duration::from_millis(self.config.scan_interval_ms),
        }
    }

    /// Check if a new scan is needed based on the configured interval
    #[allow(dead_code)]
    pub fn should_scan(&self) -> bool {
        match self.last_scan {
            Some(last_scan) => last_scan.elapsed() >= Duration::from_millis(self.config.scan_interval_ms),
            None => true,
        }
    }
}

/// Statistics about connection scanning
#[derive(Debug, Clone)]
pub struct ScanStats {
    #[allow(dead_code)]
    pub total_connections: usize,
    pub last_scan: Option<Instant>,
    #[allow(dead_code)]
    pub scan_interval: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;

    #[test]
    fn test_scanner_creation() {
        let config = NetworkConfig::default();
        let scanner = ActiveConnectionScanner::new(config);
        assert!(scanner.connection_cache.is_empty());
        assert!(scanner.last_scan.is_none());
    }

    #[test]
    fn test_private_ip_detection() {
        let config = NetworkConfig::default();
        let scanner = ActiveConnectionScanner::new(config);

        assert!(scanner.is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(scanner.is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(scanner.is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(!scanner.is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(scanner.is_private_ip(&"127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_connection_key() {
        let config = NetworkConfig::default();
        let scanner = ActiveConnectionScanner::new(config);

        let conn1 = Connection {
            pid: 1234,
            process_name: "test".to_string(),
            local_addr: "192.168.1.1:12345".parse().unwrap(),
            remote_addr: "8.8.8.8:53".parse().unwrap(),
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            bytes_in: 0,
            bytes_out: 0,
        };

        let conn2 = Connection {
            pid: 5678,
            process_name: "other".to_string(),
            local_addr: "192.168.1.1:12345".parse().unwrap(),
            remote_addr: "8.8.8.8:53".parse().unwrap(),
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            bytes_in: 0,
            bytes_out: 0,
        };

        let key1 = scanner.connection_key(&conn1);
        let key2 = scanner.connection_key(&conn2);
        
        // Same connection details should generate same key regardless of PID
        assert_eq!(key1, key2);
    }
}
