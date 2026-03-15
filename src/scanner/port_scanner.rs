//! Port scanning functionality for the network monitor.
//!
//! This module provides port scanning capabilities to detect open ports
//! and services running on the local system or remote hosts.

#![allow(dead_code)]

use crate::error::Result;
use socket2::{Socket, Domain, Type, Protocol as Socket2Protocol, SockAddr};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, trace};

/// Port scanner for detecting open ports
pub struct PortScanner {
    timeout: Duration,
}

impl PortScanner {
    /// Create a new port scanner with default timeout
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(3),
        }
    }

    /// Create a new port scanner with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Scan a single port on a host
    pub async fn scan_port(&self, host: &str, port: u16) -> Result<bool> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Socket2Protocol::TCP))?;
        
        socket.set_read_timeout(Some(self.timeout))?;
        socket.set_write_timeout(Some(self.timeout))?;
        
        let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
        let sock_addr = SockAddr::from(addr);

        match socket.connect(&sock_addr) {
            Ok(_) => {
                trace!("Port {} is open on {}", port, host);
                Ok(true)
            }
            Err(e) => {
                trace!("Port {} is closed on {}: {}", port, host, e);
                Ok(false)
            }
        }
    }

    /// Scan multiple ports on a host
    pub async fn scan_ports(&self, host: &str, ports: &[u16]) -> Result<Vec<u16>> {
        let mut open_ports = Vec::new();

        for &port in ports {
            if self.scan_port(host, port).await? {
                open_ports.push(port);
            }
        }

        debug!("Found {} open ports on {}", open_ports.len(), host);
        Ok(open_ports)
    }

    /// Scan common ports on a host
    pub async fn scan_common_ports(&self, host: &str) -> Result<Vec<u16>> {
        let common_ports = vec![
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
            3306, // MySQL
            5432, // PostgreSQL
            6379, // Redis
            8080, // HTTP Alternate
        ];

        self.scan_ports(host, &common_ports).await
    }
}

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}
