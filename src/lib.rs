//! Network Monitor Library
//!
//! This library provides comprehensive network monitoring capabilities for macOS.
//! It includes connection tracking, DNS resolution, GeoIP lookup, and more.

pub mod config;
pub mod enricher;
pub mod error;
pub mod scanner;
pub mod strucs;

// Re-export commonly used types
pub use crate::config::{ConfigManager, NetworkMonitorConfig};
pub use crate::error::{NetworkMonitorError, Result};
pub use crate::scanner::ActiveConnectionScanner;
pub use crate::strucs::net_strucs::{Connection, Protocol, ConnectionState};
