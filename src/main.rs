//! Network Monitor - A free, open-source, per-process network monitor for macOS
//!
//! This application provides comprehensive network monitoring capabilities including:
//! - Real-time connection tracking per process
//! - DNS resolution with caching
//! - GeoIP lookup for external connections
//! - Configurable alerts and filtering
//! - Multiple output formats (table, JSON, CSV)

mod strucs {
    pub mod net_strucs;
}

mod scanner;
mod enricher;
mod config;
mod error;
mod display;
mod alerts;

use crate::config::{ConfigManager, NetworkMonitorConfig, OutputFormat, SortBy};
use crate::error::Result;
use crate::scanner::{ActiveConnectionScanner, NetworkScanner};
use crate::enricher::{DnsResolver, GeoIpLookup};
use crate::display::{ConnectionDisplay, DisplayConfig};
use crate::strucs::net_strucs::Connection;
use clap::{Arg, Command};
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Application version
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Application description
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// Main network monitor application
pub struct NetworkMonitor {
    config: NetworkMonitorConfig,
    connection_scanner: ActiveConnectionScanner,
    network_scanner: NetworkScanner,
    dns_resolver: DnsResolver,
    geoip_lookup: GeoIpLookup,
    display: ConnectionDisplay,
    alert_engine: crate::alerts::AlertEngine,
}

impl NetworkMonitor {
    /// Create a new network monitor instance
    fn new() -> Result<Self> {
        // Initialize configuration
        let mut config_manager = ConfigManager::new();
        config_manager.load()?;
        let config = config_manager.get().clone();

        // Initialize logging
        Self::init_logging(&config.logging)?;

        // Initialize components
        let connection_scanner = ActiveConnectionScanner::new(config.network.clone());
        let network_scanner = NetworkScanner::new(
            config.network.connection_timeout_ms,
            config.performance.worker_threads.unwrap_or(4)
        );
        let dns_resolver = DnsResolver::new();
        let geoip_lookup = Self::init_geoip(&config.geoip)?;
        let alert_engine = crate::alerts::AlertEngine::with_config(config.alerts.max_alerts);
        
        // Initialize display
        let display_config = DisplayConfig {
            show_colors: config.display.color_output,
            show_stats: true, // Always show stats for now
            max_table_rows: Some(config.display.max_display_connections),
            sort_by: SortBy::ProcessName,
        };
        let display = ConnectionDisplay::new(display_config);

        info!("NetSight v{} initialized", VERSION);

        Ok(Self {
            config,
            connection_scanner,
            network_scanner,
            dns_resolver,
            geoip_lookup,
            display,
            alert_engine,
        })
    }

    /// Initialize logging based on configuration
    fn init_logging(config: &crate::config::LoggingConfig) -> Result<()> {
        use tracing_subscriber::fmt::format::FmtSpan;
        use tracing_subscriber::EnvFilter;

        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&config.level));

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_span_events(FmtSpan::CLOSE)
            .with_target(config.console_logging);

        match config.format {
            crate::config::LogFormat::Json => {
                let json_layer = tracing_subscriber::fmt::layer().json();
                tracing_subscriber::registry()
                    .with(env_filter.clone())
                    .with(json_layer)
                    .init();
            }
            crate::config::LogFormat::Compact => {
                let compact_layer = tracing_subscriber::fmt::layer().compact();
                tracing_subscriber::registry()
                    .with(env_filter.clone())
                    .with(compact_layer)
                    .init();
            }
            crate::config::LogFormat::Pretty => {
                tracing_subscriber::registry()
                    .with(env_filter.clone())
                    .with(fmt_layer)
                    .init();
            }
        }

        if config.log_to_file {
            if let Some(log_file) = &config.log_file {
                // Create log directory if it doesn't exist
                if let Some(parent) = log_file.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let file_appender = tracing_appender::rolling::daily(
                    log_file.parent().unwrap_or_else(|| std::path::Path::new(".")),
                    log_file.file_name().unwrap_or_else(|| std::ffi::OsStr::new("netsight.log")),
                );

                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().with_writer(file_appender))
                    .init();
            }
        }

        Ok(())
    }

    /// Initialize GeoIP lookup
    fn init_geoip(config: &crate::config::GeoIpConfig) -> Result<GeoIpLookup> {
        if !config.enabled {
            return Ok(GeoIpLookup::new());
        }

        if let Some(db_path) = &config.database_path {
            // Resolve path relative to current working directory
            let resolved_path = if db_path.is_relative() {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(db_path)
            } else {
                db_path.clone()
            };
            
            match GeoIpLookup::with_database_path(&resolved_path) {
                Ok(geoip) => {
                    info!("GeoIP database loaded from {:?}", db_path);
                    return Ok(geoip);
                }
                Err(e) => {
                    warn!("Failed to load GeoIP database {:?}: {}", db_path, e);
                    if config.auto_download {
                        info!("Attempting to auto-download GeoIP database...");
                        // TODO: Implement auto-download
                        warn!("Auto-download not implemented yet");
                    }
                }
            }
        }

        info!("GeoIP functionality disabled");
        Ok(GeoIpLookup::new())
    }

    /// Run the network monitor
    async fn run(&mut self) -> Result<()> {
        info!("Starting NetSight network monitoring scan");

        // Perform initial scan
        let connections = self.scan_and_enrich().await?;

        // Display results
        self.display_connections(&connections)?;

        // Show statistics
        self.display_statistics(&connections)?;

        // Check for alerts
        self.check_alerts(&connections)?;

        Ok(())
    }

    /// Check for security alerts using the alert engine
    fn check_alerts(&mut self, connections: &[Connection]) -> Result<()> {
        let alerts = self.alert_engine.process_connections(connections);
        
        if !alerts.is_empty() {
            println!("\n🚨 SECURITY ALERTS DETECTED:");
            println!("════════════════════════════════");
            
            for alert in &alerts {
                self.display_alert(alert);
            }
            
            println!("════════════════════════════════");
            println!("⚠️  Total alerts: {} | Review the connections above for details.", alerts.len());
        }

        Ok(())
    }

    /// Display a single alert
    fn display_alert(&self, alert: &crate::alerts::Alert) {
        let severity_icon = match alert.severity {
            crate::alerts::AlertSeverity::Critical => "🔴",
            crate::alerts::AlertSeverity::Warning => "🟡",
            crate::alerts::AlertSeverity::Info => "🔵",
        };

        let category_icon = match alert.category {
            crate::alerts::AlertCategory::Security => "🛡️",
            crate::alerts::AlertCategory::Performance => "📊",
            crate::alerts::AlertCategory::Anomaly => "⚠️",
            crate::alerts::AlertCategory::Compliance => "📋",
        };

        println!("{} {} [{}] {}", 
            severity_icon, 
            alert.rule_name, 
            format!("{:?}", alert.severity).to_uppercase(),
            category_icon
        );
        println!("   📅 {}", alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("   📝 {}", alert.message);
        
        if !alert.details.connections.is_empty() {
            println!("   � Affected connections: {}", alert.details.connections.len());
        }
        
        if !alert.details.metadata.is_empty() {
            println!("   📊 Details:");
            for (key, value) in &alert.details.metadata {
                println!("      {}: {}", key, value);
            }
        }
        println!();
    }

    /// Scan for connections and enrich them with additional data
    async fn scan_and_enrich(&mut self) -> Result<Vec<Connection>> {
        let mut connections = Vec::new();

        // Check if we should perform network scanning
        if let Some(network) = &self.config.display.scan_network {
            info!("Scanning network range: {}", network);
            let ports = if self.config.display.scan_ports.is_empty() {
                crate::scanner::network_scanner::COMMON_PORTS.to_vec()
            } else {
                self.config.display.scan_ports.clone()
            };
            
            match self.network_scanner.scan_network(network, &ports).await {
                Ok(results) => {
                    connections.extend(self.network_scanner.results_to_connections(&results));
                    info!("Network scan found {} hosts with open ports", results.len());
                }
                Err(e) => {
                    warn!("Network scan failed: {}", e);
                }
            }
        }

        // Perform regular connection scanning
        let mut system_connections = self.connection_scanner.scan_connections().await?;
        connections.append(&mut system_connections);

        info!("Found {} total network connections", connections.len());

        // Enrich with DNS resolution
        if self.config.dns.enabled {
            info!("Enriching connections with DNS resolution...");
            connections = self.enrich_with_dns(connections).await?;
        }

        // Enrich with GeoIP data
        if self.config.geoip.enabled {
            info!("Enriching connections with GeoIP data...");
            connections = self.enrich_with_geoip(connections).await?;
        }

        // Apply display filters
        connections = self.apply_display_filters(connections);

        Ok(connections)
    }

    /// Enrich connections with DNS resolution
    async fn enrich_with_dns(&mut self, mut connections: Vec<Connection>) -> Result<Vec<Connection>> {
        for conn in &mut connections {
            let remote_ip = conn.remote_addr.ip();
            let hostname = self.dns_resolver.resolve_hostname(remote_ip);
            
            if hostname != remote_ip.to_string() && self.config.display.show_dns {
                conn.process_name = format!("{} ({})", conn.process_name, hostname);
            }
        }
        Ok(connections)
    }

    /// Enrich connections with GeoIP data
    async fn enrich_with_geoip(&mut self, mut connections: Vec<Connection>) -> Result<Vec<Connection>> {
        if !self.geoip_lookup.is_available() {
            return Ok(connections);
        }

        for conn in &mut connections {
            let remote_ip = conn.remote_addr.ip();
            let country = self.geoip_lookup.lookup_country(remote_ip);
            
            if country != "Local" && country != "Unknown" && country != "No DB" && self.config.display.show_geoip {
                conn.process_name = format!("{} [{}]", conn.process_name, country);
            }
        }
        Ok(connections)
    }

    /// Apply display filters
    fn apply_display_filters(&self, mut connections: Vec<Connection>) -> Vec<Connection> {
        // Filter by process name
        if let Some(filter_process) = &self.config.display.filter_process {
            connections.retain(|conn| 
                conn.process_name.to_lowercase().contains(&filter_process.to_lowercase())
            );
        }

        // Filter by port
        if let Some(filter_port) = self.config.display.filter_port {
            connections.retain(|conn| conn.remote_addr.port() == filter_port);
        }

        // Filter by IP address (supports CIDR notation)
        if let Some(filter_ip) = &self.config.display.filter_ip {
            connections.retain(|conn| self.matches_ip_filter(&conn.remote_addr.ip(), filter_ip));
        }

        // Sort connections
        connections.sort_by(|a, b| self.compare_connections(a, b));

        // Limit display connections
        if connections.len() > self.config.display.max_display_connections {
            connections.truncate(self.config.display.max_display_connections);
        }

        connections
    }

    /// Check if IP matches filter (supports CIDR notation)
    fn matches_ip_filter(&self, ip: &std::net::IpAddr, filter: &str) -> bool {
        if filter.contains('/') {
            // CIDR notation
            if let Ok((network, prefix)) = self.parse_cidr(filter) {
                self.ip_in_network(ip, &network, prefix)
            } else {
                false
            }
        } else {
            // Single IP
            if let Ok(filter_ip) = filter.parse::<std::net::IpAddr>() {
                ip == &filter_ip
            } else {
                false
            }
        }
    }

    /// Parse CIDR notation into network and prefix length
    fn parse_cidr(&self, cidr: &str) -> std::result::Result<(std::net::IpAddr, u32), Box<dyn std::error::Error>> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format".into());
        }

        let network = parts[0].parse::<std::net::IpAddr>()?;
        let prefix = parts[1].parse::<u32>()?;

        Ok((network, prefix))
    }

    /// Check if IP is in the given network
    fn ip_in_network(&self, ip: &std::net::IpAddr, network: &std::net::IpAddr, prefix: u32) -> bool {
        match (ip, network) {
            (std::net::IpAddr::V4(ip), std::net::IpAddr::V4(network)) => {
                let ip_u32 = u32::from(*ip);
                let network_u32 = u32::from(*network);
                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                (ip_u32 & mask) == (network_u32 & mask)
            }
            (std::net::IpAddr::V6(ip), std::net::IpAddr::V6(network)) => {
                let ip_u128 = u128::from(*ip);
                let network_u128 = u128::from(*network);
                let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                (ip_u128 & mask) == (network_u128 & mask)
            }
            _ => false,
        }
    }

    /// Compare two connections for sorting
    fn compare_connections(&self, a: &Connection, b: &Connection) -> std::cmp::Ordering {
        use crate::config::SortBy;

        match self.config.display.sort_by {
            SortBy::ProcessName => a.process_name.cmp(&b.process_name),
            SortBy::RemoteAddress => a.remote_addr.cmp(&b.remote_addr),
            SortBy::LocalAddress => a.local_addr.cmp(&b.local_addr),
            SortBy::Port => a.remote_addr.port().cmp(&b.remote_addr.port()),
            SortBy::Protocol => a.protocol.cmp(&b.protocol),
            SortBy::State => format!("{:?}", a.state).cmp(&format!("{:?}", b.state)),
            SortBy::Bandwidth => (a.bytes_in + a.bytes_out).cmp(&(b.bytes_in + b.bytes_out)),
        }
    }

    /// Display connections based on configured format
    fn display_connections(&mut self, connections: &[Connection]) -> Result<()> {
        match self.config.display.output_format {
            OutputFormat::Table => self.display_table(connections.to_vec()),
            OutputFormat::Json => self.display_json(connections),
            OutputFormat::Csv => self.display_csv(connections),
            OutputFormat::Xml => self.display_xml(connections),
        }
    }

    /// Display connections in table format
    fn display_table(&mut self, connections: Vec<Connection>) -> Result<()> {
        self.display.display_connections(connections)
    }

    /// Display connections in JSON format
    fn display_json(&self, connections: &[Connection]) -> Result<()> {
        self.display.display_json(connections)
    }

    /// Display connections in CSV format
    fn display_csv(&self, connections: &[Connection]) -> Result<()> {
        self.display.display_csv(connections)
    }

    /// Display connections in XML format
    fn display_xml(&self, connections: &[Connection]) -> Result<()> {
        println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        println!("<connections>");
        for conn in connections {
            println!("  <connection>");
            println!("    <pid>{}</pid>", conn.pid);
            println!("    <process_name>{}</process_name>", escape_xml(&conn.process_name));
            println!("    <local_address>{}</local_address>", conn.local_addr);
            println!("    <remote_address>{}</remote_address>", conn.remote_addr);
            println!("    <protocol>{:?}</protocol>", conn.protocol);
            println!("    <state>{:?}</state>", conn.state);
            println!("    <bytes_in>{}</bytes_in>", conn.bytes_in);
            println!("    <bytes_out>{}</bytes_out>", conn.bytes_out);
            println!("  </connection>");
        }
        println!("</connections>");
        Ok(())
    }

    /// Display connection statistics
    fn display_statistics(&self, connections: &[Connection]) -> Result<()> {
        let total_connections = connections.len();
        let external_connections = connections.iter().filter(|c| 
            !c.remote_addr.ip().is_loopback() && 
            !is_private_ip(c.remote_addr.ip())
        ).count();

        let tcp_connections = connections.iter().filter(|c| matches!(c.protocol, crate::strucs::net_strucs::Protocol::Tcp)).count();
        let udp_connections = connections.iter().filter(|c| matches!(c.protocol, crate::strucs::net_strucs::Protocol::Udp)).count();

        let established_connections = connections.iter().filter(|c| matches!(c.state, crate::strucs::net_strucs::ConnectionState::Established)).count();

        println!("\n📊 Connection Statistics:");
        println!("  Total connections: {}", total_connections);
        println!("  External connections: {}", external_connections);
        println!("  TCP connections: {}", tcp_connections);
        println!("  UDP connections: {}", udp_connections);
        println!("  Established connections: {}", established_connections);

        // Show scan statistics
        let scan_stats = self.connection_scanner.get_scan_stats();
        if let Some(last_scan) = scan_stats.last_scan {
            println!("  Last scan: {:?} ago", last_scan.elapsed());
        }

        Ok(())
    }
}

/// Check if an IP address is private
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || 
            ipv4.octets()[0] == 10 ||                           // 10.0.0.0/8
            (ipv4.octets()[0] == 172 && ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31) || // 172.16.0.0/12
            (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168) // 192.168.0.0/16
        }
        IpAddr::V6(_) => false, // Simplified IPv6 handling
    }
}

/// Escape XML special characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&apos;")
}

/// Create and configure the CLI application
fn create_cli() -> Command {
    Command::new("netsight")
        .version(VERSION)
        .about("A free, open-source, per-process network monitor for macOS")
        .long_about(DESCRIPTION)
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FORMAT")
                .help("Output format (table, json, csv, xml)")
                .value_parser(["table", "json", "csv", "xml"])
        )
        .arg(
            Arg::new("filter-process")
                .short('p')
                .long("filter-process")
                .value_name("NAME")
                .help("Filter by process name")
        )
        .arg(
            Arg::new("filter-port")
                .short('P')
                .long("filter-port")
                .value_name("PORT")
                .help("Filter by port")
                .value_parser(clap::value_parser!(u16))
        )
        .arg(
            Arg::new("filter-ip")
                .short('i')
                .long("filter-ip")
                .value_name("IP")
                .help("Filter by IP address (supports CIDR notation)")
        )
        .arg(
            Arg::new("scan-network")
                .short('n')
                .long("scan-network")
                .value_name("NETWORK")
                .help("Scan specific network range (e.g., 192.168.1.0/24)")
        )
        .arg(
            Arg::new("scan-ports")
                .long("scan-ports")
                .value_name("PORTS")
                .help("Scan specific ports on target (comma-separated, e.g., 22,80,443)")
        )
        .arg(
            Arg::new("monitor-mode")
                .short('m')
                .long("monitor")
                .help("Enable continuous monitoring mode")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("alert-threshold")
                .long("alert-threshold")
                .value_name("COUNT")
                .help("Alert when connection count exceeds threshold")
                .value_parser(clap::value_parser!(usize))
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::Count)
        )
        .arg(
            Arg::new("no-dns")
                .long("no-dns")
                .help("Disable DNS resolution")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-geoip")
                .long("no-geoip")
                .help("Disable GeoIP lookup")
                .action(clap::ArgAction::SetTrue)
        )
}

#[tokio::main]
async fn main() {
    // Parse CLI arguments
    let matches = create_cli().get_matches();

    // Initialize network monitor
    let mut monitor = match NetworkMonitor::new() {
        Ok(monitor) => monitor,
        Err(e) => {
            eprintln!("Failed to initialize NetSight: {}", e);
            if let Some(suggestion) = e.user_suggestion() {
                eprintln!("Suggestion: {}", suggestion);
            }
            std::process::exit(1);
        }
    };

    // Apply CLI overrides
    if let Some(output_format) = matches.get_one::<String>("output") {
        monitor.config.display.output_format = output_format.parse()
            .unwrap_or(OutputFormat::Table);
    }

    if let Some(filter_process) = matches.get_one::<String>("filter-process") {
        monitor.config.display.filter_process = Some(filter_process.clone());
    }

    if let Some(filter_port) = matches.get_one::<u16>("filter-port") {
        monitor.config.display.filter_port = Some(*filter_port);
    }

    if let Some(filter_ip) = matches.get_one::<String>("filter-ip") {
        monitor.config.display.filter_ip = Some(filter_ip.clone());
    }

    if let Some(scan_network) = matches.get_one::<String>("scan-network") {
        monitor.config.display.scan_network = Some(scan_network.clone());
    }

    if let Some(scan_ports) = matches.get_one::<String>("scan-ports") {
        let ports: Vec<u16> = scan_ports.split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        monitor.config.display.scan_ports = ports;
    }

    if matches.get_flag("monitor-mode") {
        monitor.config.display.monitor_mode = true;
    }

    if let Some(alert_threshold) = matches.get_one::<usize>("alert-threshold") {
        monitor.config.display.alert_threshold = Some(*alert_threshold);
    }

    if matches.get_flag("no-dns") {
        monitor.config.dns.enabled = false;
    }

    if matches.get_flag("no-geoip") {
        monitor.config.geoip.enabled = false;
    }

    // Run the monitor
    if let Err(e) = monitor.run().await {
        error!("Network monitor failed: {}", e);
        if let Some(suggestion) = e.user_suggestion() {
            eprintln!("Suggestion: {}", suggestion);
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("hello & world"), "hello &amp; world");
        assert_eq!(escape_xml("<tag>"), "&lt;tag&gt;");
        assert_eq!(escape_xml("\"quote\""), "&quot;quote&quot;");
    }

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
    }
}
