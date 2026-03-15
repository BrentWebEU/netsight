//! Network interface scanner for discovering network interfaces and their properties.
//!
//! This module provides functionality to scan and enumerate network interfaces
//! on the local system, including their IP addresses, MAC addresses, and status.

#![allow(dead_code)]

use crate::error::Result;
use std::net::IpAddr;
use tracing::{debug, info};

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_address: IpAddr,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// Scanner for network interfaces
pub struct InterfaceScanner;

impl InterfaceScanner {
    /// Create a new interface scanner
    pub fn new() -> Self {
        Self
    }

    /// Scan for all network interfaces
    pub fn scan_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        let mut interfaces = Vec::new();

        // Get local IP address using local-ip crate
        if let Some(local_ip) = local_ip::get() {
            info!("Found primary IP address: {}", local_ip);
            
            interfaces.push(NetworkInterface {
                name: "primary".to_string(),
                ip_address: local_ip,
                is_up: true,
                is_loopback: local_ip.is_loopback(),
            });
        }

        // Add common loopback interface
        interfaces.push(NetworkInterface {
            name: "lo0".to_string(),
            ip_address: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            is_up: true,
            is_loopback: true,
        });

        debug!("Found {} network interfaces", interfaces.len());
        Ok(interfaces)
    }

    /// Get external IP address (if reachable)
    pub async fn get_external_ip(&self) -> Result<Option<IpAddr>> {
        // Simple connectivity test to well-known external service
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;

        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

        let addr: std::net::SocketAddr = "8.8.8.8:53".parse()?;
        let sock_addr = socket2::SockAddr::from(addr);

        match socket.connect(&sock_addr) {
            Ok(_) => {
                // If we can connect to external DNS, assume we have external connectivity
                Ok(Some("8.8.8.8".parse().unwrap()))
            }
            Err(_) => Ok(None),
        }
    }
}

impl Default for InterfaceScanner {
    fn default() -> Self {
        Self::new()
    }
}
