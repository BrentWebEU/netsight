//! Network scanning utilities for security monitoring and auditing
//!
//! This module provides ethical network scanning capabilities for security
//! monitoring, vulnerability assessment, and network discovery.

use crate::error::{NetworkMonitorError, Result};
use crate::strucs::net_strucs::{Connection, Protocol, ConnectionState};
use std::net::{IpAddr, SocketAddr, Ipv4Addr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout as tokio_timeout;
use tracing::{info, debug, warn};

/// Network scanner for security monitoring
pub struct NetworkScanner {
    timeout: Duration,
    max_concurrent: usize,
}

impl NetworkScanner {
    /// Create a new network scanner
    pub fn new(timeout_ms: u64, max_concurrent: usize) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            max_concurrent,
        }
    }

    /// Scan specific ports on a target host
    pub async fn scan_ports(&self, target: &str, ports: &[u16]) -> Result<Vec<PortScanResult>> {
        info!("Scanning {} ports on {}", ports.len(), target);
        
        let target_ip = target.parse::<IpAddr>()
            .map_err(|e| NetworkMonitorError::parse_with_source("Invalid target IP", "port scanning", e))?;

        let mut results = Vec::new();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        
        for &port in ports {
            let semaphore = semaphore.clone();
            let target_ip = target_ip;
            let timeout = self.timeout;
            
            let result = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                Self::scan_single_port(target_ip, port, timeout).await
            });
            
            results.push(result);
        }
        
        let mut scan_results = Vec::new();
        for result in results {
            match result.await {
                Ok(scan_result) => scan_results.push(scan_result),
                Err(e) => warn!("Port scan task failed: {}", e),
            }
        }
        
        Ok(scan_results)
    }

    /// Scan a network range for active hosts
    pub async fn scan_network(&self, network: &str, ports: &[u16]) -> Result<Vec<HostScanResult>> {
        info!("Scanning network {} with {} ports", network, ports.len());
        
        let hosts = self.generate_host_list(network)?;
        let mut results = Vec::new();
        
        for host in hosts {
            debug!("Scanning host {}", host);
            let port_results = self.scan_ports(&host, ports).await?;
            
            let open_ports: Vec<u16> = port_results
                .into_iter()
                .filter(|r| r.is_open)
                .map(|r| r.port)
                .collect();
            
            if !open_ports.is_empty() {
                results.push(HostScanResult {
                    host,
                    open_ports,
                });
            }
        }
        
        Ok(results)
    }

    /// Generate list of hosts from network CIDR
    fn generate_host_list(&self, network: &str) -> Result<Vec<String>> {
        let parts: Vec<&str> = network.split('/').collect();
        if parts.len() != 2 {
            return Err(NetworkMonitorError::parse("Invalid CIDR format", "network scanning"));
        }

        let base_ip = parts[0].parse::<Ipv4Addr>()
            .map_err(|e| NetworkMonitorError::parse_with_source("Invalid base IP", "network scanning", e))?;
        
        let prefix = parts[1].parse::<u32>()
            .map_err(|e| NetworkMonitorError::parse_with_source("Invalid prefix length", "network scanning", e))?;

        if prefix < 24 || prefix > 30 {
            warn!("Network prefix {} may result in too many hosts. Use /24 to /30 for best results.", prefix);
        }

        let host_bits = 32 - prefix;
        let host_count = if host_bits >= 31 { 2 } else { 2u32.pow(host_bits) };
        
        let mut hosts = Vec::new();
        let base_u32 = u32::from(base_ip);
        let network_mask = !0u32 << host_bits;
        let network_addr = base_u32 & network_mask;
        
        // Skip network and broadcast addresses
        for i in 1..host_count.saturating_sub(1) {
            let host_ip = network_addr + i;
            let ip = Ipv4Addr::from(host_ip);
            hosts.push(ip.to_string());
        }
        
        Ok(hosts)
    }

    /// Scan a single port
    async fn scan_single_port(target: IpAddr, port: u16, timeout: Duration) -> PortScanResult {
        match tokio_timeout(timeout, TcpStream::connect(SocketAddr::new(target, port))).await {
            Ok(Ok(_stream)) => PortScanResult {
                port,
                is_open: true,
            },
            Ok(Err(_)) => PortScanResult {
                port,
                is_open: false,
            },
            Err(_) => PortScanResult {
                port,
                is_open: false,
            },
        }
    }

    /// Convert scan results to connections for display
    pub fn results_to_connections(&self, results: &[HostScanResult]) -> Vec<Connection> {
        let mut connections = Vec::new();
        
        for result in results {
            for &port in &result.open_ports {
                connections.push(Connection {
                    pid: 0, // System scan
                    process_name: "Network Scanner".to_string(),
                    local_addr: "0.0.0.0:0".parse().unwrap(),
                    remote_addr: format!("{}:{}", result.host, port).parse().unwrap(),
                    protocol: Protocol::Tcp,
                    state: ConnectionState::Established,
                    bytes_in: 0,
                    bytes_out: 0,
                });
            }
        }
        
        connections
    }
}

/// Result of scanning a single port
#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub port: u16,
    pub is_open: bool,
}

/// Result of scanning a host
#[derive(Debug, Clone)]
pub struct HostScanResult {
    pub host: String,
    pub open_ports: Vec<u16>,
}

/// Common ports for security scanning
pub const COMMON_PORTS: &[u16] = &[
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    25,   // SMTP
    53,   // DNS
    80,   // HTTP
    110,  // POP3
    143,  // IMAP
    443,  // HTTPS
    993,  // IMAPS
    995,  // POP3S
    1433, // MSSQL
    3306, // MySQL
    3389, // RDP
    5432, // PostgreSQL
    5900, // VNC
    6379, // Redis
    8080, // HTTP Alternate
    8443, // HTTPS Alternate
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = NetworkScanner::new(1000, 10);
        assert_eq!(scanner.timeout, Duration::from_millis(1000));
        assert_eq!(scanner.max_concurrent, 10);
    }

    #[test]
    fn test_host_generation() {
        let scanner = NetworkScanner::new(1000, 10);
        let hosts = scanner.generate_host_list("192.168.1.0/30").unwrap();
        assert_eq!(hosts.len(), 2); // .1 and .2
    }
}
