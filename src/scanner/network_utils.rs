//! Network utility functions for the network monitor.
//!
//! This module provides various utility functions for network operations,
//! including IP address validation, port checking, and network calculations.

#![allow(dead_code)]

use crate::error::{NetworkMonitorError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Network utility functions
pub struct NetworkUtils;

impl NetworkUtils {
    /// Check if an IP address is private
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => Self::is_private_ipv4(ipv4),
            IpAddr::V6(ipv6) => Self::is_private_ipv6(ipv6),
        }
    }

    /// Check if an IPv4 address is private
    pub fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
        ip.is_private() || 
        ip.octets()[0] == 10 ||                           // 10.0.0.0/8
        (ip.octets()[0] == 172 && ip.octets()[1] >= 16 && ip.octets()[1] <= 31) || // 172.16.0.0/12
        (ip.octets()[0] == 192 && ip.octets()[1] == 168) // 192.168.0.0/16
    }

    /// Check if an IPv6 address is private
    pub fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
        ip.is_loopback() || ip.is_unspecified() || ip.segments()[0] == 0xfc00 // Unique local address
    }

    /// Check if a port is commonly used for a specific service
    pub fn is_common_service_port(port: u16) -> Option<&'static str> {
        match port {
            21 => Some("FTP"),
            22 => Some("SSH"),
            23 => Some("Telnet"),
            25 => Some("SMTP"),
            53 => Some("DNS"),
            80 => Some("HTTP"),
            110 => Some("POP3"),
            143 => Some("IMAP"),
            443 => Some("HTTPS"),
            993 => Some("IMAPS"),
            995 => Some("POP3S"),
            3306 => Some("MySQL"),
            5432 => Some("PostgreSQL"),
            6379 => Some("Redis"),
            8080 => Some("HTTP-Alt"),
            _ => None,
        }
    }

    /// Check if a port is suspicious (commonly used by malware)
    pub fn is_suspicious_port(port: u16) -> bool {
        matches!(port, 
            4444 | 1337 | 31337 | 6667 | 5555 | 12345 | 54321 | 9999 | 3128 | 1080
        )
    }

    /// Validate IP address format
    pub fn validate_ip_address(ip_str: &str) -> Result<IpAddr> {
        ip_str.parse()
            .map_err(|_| NetworkMonitorError::validation_field(
                format!("Invalid IP address: {}", ip_str),
                "ip_address"
            ))
    }

    /// Get the network class for an IPv4 address
    pub fn get_ipv4_class(ip: &Ipv4Addr) -> char {
        let first_octet = ip.octets()[0];
        match first_octet {
            0..=126 => 'A',
            128..=191 => 'B',
            192..=223 => 'C',
            224..=239 => 'D',
            240..=255 => 'E',
            127 => 'L', // Loopback
        }
    }

    /// Calculate subnet mask from CIDR notation
    pub fn cidr_to_subnet_mask(cidr: u8) -> Result<Ipv4Addr> {
        if cidr > 32 {
            return Err(NetworkMonitorError::validation("CIDR must be between 0 and 32"));
        }

        let mask = u32::MAX << (32 - cidr);
        let bytes = mask.to_be_bytes();
        Ok(Ipv4Addr::from(bytes))
    }

    /// Check if two IPs are in the same subnet
    pub fn same_subnet(ip1: &Ipv4Addr, ip2: &Ipv4Addr, cidr: u8) -> Result<bool> {
        let mask = Self::cidr_to_subnet_mask(cidr)?;
        let masked1 = Self::apply_subnet_mask(ip1, &mask);
        let masked2 = Self::apply_subnet_mask(ip2, &mask);
        Ok(masked1 == masked2)
    }

    /// Apply subnet mask to IP address
    fn apply_subnet_mask(ip: &Ipv4Addr, mask: &Ipv4Addr) -> u32 {
        let ip_bytes = ip.octets();
        let mask_bytes = mask.octets();
        
        let ip_u32 = u32::from_be_bytes(ip_bytes);
        let mask_u32 = u32::from_be_bytes(mask_bytes);
        
        ip_u32 & mask_u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip_detection() {
        assert!(NetworkUtils::is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(NetworkUtils::is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(NetworkUtils::is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(!NetworkUtils::is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(NetworkUtils::is_private_ip(&"127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_common_service_ports() {
        assert_eq!(NetworkUtils::is_common_service_port(80), Some("HTTP"));
        assert_eq!(NetworkUtils::is_common_service_port(443), Some("HTTPS"));
        assert_eq!(NetworkUtils::is_common_service_port(22), Some("SSH"));
        assert_eq!(NetworkUtils::is_common_service_port(9999), None);
    }

    #[test]
    fn test_suspicious_ports() {
        assert!(NetworkUtils::is_suspicious_port(4444));
        assert!(NetworkUtils::is_suspicious_port(1337));
        assert!(NetworkUtils::is_suspicious_port(31337));
        assert!(!NetworkUtils::is_suspicious_port(80));
        assert!(!NetworkUtils::is_suspicious_port(443));
    }

    #[test]
    fn test_cidr_to_subnet_mask() {
        assert_eq!(NetworkUtils::cidr_to_subnet_mask(24).unwrap(), "255.255.255.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(NetworkUtils::cidr_to_subnet_mask(16).unwrap(), "255.255.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(NetworkUtils::cidr_to_subnet_mask(8).unwrap(), "255.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert!(NetworkUtils::cidr_to_subnet_mask(33).is_err());
    }

    #[test]
    fn test_same_subnet() {
        let ip1: Ipv4Addr = "192.168.1.10".parse().unwrap();
        let ip2: Ipv4Addr = "192.168.1.20".parse().unwrap();
        let ip3: Ipv4Addr = "192.168.2.10".parse().unwrap();

        assert!(NetworkUtils::same_subnet(&ip1, &ip2, 24).unwrap());
        assert!(!NetworkUtils::same_subnet(&ip1, &ip3, 24).unwrap());
        assert!(NetworkUtils::same_subnet(&ip1, &ip3, 16).unwrap());
    }

    #[test]
    fn test_ipv4_class() {
        assert_eq!(NetworkUtils::get_ipv4_class(&"10.0.0.1".parse().unwrap()), 'A');
        assert_eq!(NetworkUtils::get_ipv4_class(&"172.16.0.1".parse().unwrap()), 'B');
        assert_eq!(NetworkUtils::get_ipv4_class(&"192.168.1.1".parse().unwrap()), 'C');
        assert_eq!(NetworkUtils::get_ipv4_class(&"127.0.0.1".parse().unwrap()), 'L');
    }
}
