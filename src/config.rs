//! Configuration management for the network monitor.
//!
//! This module handles loading, validating, and providing access to configuration
//! settings from various sources (files, environment variables, CLI arguments).

use crate::error::{NetworkMonitorError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Default configuration file name
pub const DEFAULT_CONFIG_FILE: &str = "netsight.toml";

/// Default configuration directory
pub const DEFAULT_CONFIG_DIR: &str = ".config/netsight";

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    /// Network scanning configuration
    pub network: NetworkConfig,
    /// DNS resolution configuration
    pub dns: DnsConfig,
    /// GeoIP configuration
    pub geoip: GeoIpConfig,
    /// Display configuration
    pub display: DisplayConfig,
    /// Alert configuration
    pub alerts: AlertsConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            dns: DnsConfig::default(),
            geoip: GeoIpConfig::default(),
            display: DisplayConfig::default(),
            alerts: AlertsConfig::default(),
            performance: PerformanceConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Network scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Scan interval in milliseconds
    pub scan_interval_ms: u64,
    /// Connection timeout in milliseconds
    pub connection_timeout_ms: u64,
    /// Maximum number of concurrent connections to track
    pub max_connections: usize,
    /// Enable IPv6 support
    pub enable_ipv6: bool,
    /// Ports to monitor specifically (empty means all ports)
    pub monitor_ports: Vec<u16>,
    /// Exclude localhost connections
    pub exclude_localhost: bool,
    /// Exclude private network ranges
    pub exclude_private: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            scan_interval_ms: 1000,
            connection_timeout_ms: 5000,
            max_connections: 10000,
            enable_ipv6: true,
            monitor_ports: vec![],
            exclude_localhost: true,
            exclude_private: true,
        }
    }
}

/// DNS resolution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Enable DNS resolution
    pub enabled: bool,
    /// DNS cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// DNS servers to use (empty means system default)
    pub dns_servers: Vec<String>,
    /// Timeout for DNS queries in milliseconds
    pub timeout_ms: u64,
    /// Number of retry attempts
    pub retry_attempts: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl_seconds: 300,
            max_cache_size: 1000,
            dns_servers: vec![],
            timeout_ms: 2000,
            retry_attempts: 3,
        }
    }
}

/// GeoIP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    /// Enable GeoIP lookup
    pub enabled: bool,
    /// Path to GeoIP database file
    pub database_path: Option<PathBuf>,
    /// Auto-download database if missing
    pub auto_download: bool,
    /// Database URL for auto-download
    pub database_url: String,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// Maximum cache size
    pub max_cache_size: usize,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database_path: Some(PathBuf::from("data/dbip-country.mmdb")),
            auto_download: false,
            database_url: "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb".to_string(),
            cache_ttl_seconds: 3600,
            max_cache_size: 5000,
        }
    }
}

/// Display configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayConfig {
    /// Output format
    pub output_format: OutputFormat,
    /// Show DNS names
    pub show_dns: bool,
    /// Show GeoIP information
    pub show_geoip: bool,
    /// Show process names
    pub show_process_names: bool,
    /// Show connection state
    pub show_state: bool,
    /// Show bandwidth information
    pub show_bandwidth: bool,
    /// Color output
    pub color_output: bool,
    /// Maximum number of connections to display
    pub max_display_connections: usize,
    /// Sort connections by
    pub sort_by: SortBy,
    /// Filter by process name
    pub filter_process: Option<String>,
    /// Filter by port
    pub filter_port: Option<u16>,
    /// Filter by IP address (supports CIDR)
    pub filter_ip: Option<String>,
    /// Scan specific network range
    pub scan_network: Option<String>,
    /// Scan specific ports
    pub scan_ports: Vec<u16>,
    /// Monitor mode (continuous monitoring)
    pub monitor_mode: bool,
    /// Alert threshold for connection count
    pub alert_threshold: Option<usize>,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            output_format: OutputFormat::Table,
            show_dns: true,
            show_geoip: true,
            show_process_names: true,
            show_state: true,
            show_bandwidth: false,
            color_output: true,
            max_display_connections: 100,
            sort_by: SortBy::RemoteAddress,
            filter_process: None,
            filter_port: None,
            filter_ip: None,
            scan_network: None,
            scan_ports: Vec::new(),
            monitor_mode: false,
            alert_threshold: None,
        }
    }
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsConfig {
    /// Enable alerts
    pub enabled: bool,
    /// Suspicious ports to monitor
    pub suspicious_ports: Vec<u16>,
    /// Blocked countries
    pub blocked_countries: Vec<String>,
    /// High bandwidth threshold in bytes per second
    pub high_bandwidth_threshold: u64,
    /// New process connection alert
    pub alert_new_process: bool,
    /// Unusual port alert
    pub alert_unusual_port: bool,
    /// Known malicious IP alert
    pub alert_malicious_ip: bool,
    /// Maximum number of alerts to keep in history
    pub max_alerts: usize,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suspicious_ports: vec![4444, 1337, 31337, 6667, 5555, 12345, 54321],
            blocked_countries: vec!["RU".to_string(), "CN".to_string(), "KP".to_string()],
            high_bandwidth_threshold: 1024 * 1024, // 1MB/s
            alert_new_process: true,
            alert_unusual_port: true,
            alert_malicious_ip: true,
            max_alerts: 1000,
        }
    }
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Number of worker threads
    pub worker_threads: Option<usize>,
    /// Enable connection pooling
    pub enable_connection_pooling: bool,
    /// Pool size
    pub pool_size: usize,
    /// Batch size for processing
    pub batch_size: usize,
    /// Enable metrics collection
    pub enable_metrics: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: None, // Use number of CPU cores
            enable_connection_pooling: true,
            pool_size: 100,
            batch_size: 50,
            enable_metrics: true,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Log format
    pub format: LogFormat,
    /// Log to file
    pub log_to_file: bool,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// Enable console logging
    pub console_logging: bool,
    /// Enable structured logging
    pub structured: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Pretty,
            log_to_file: false,
            log_file: Some(PathBuf::from("logs/netsight.log")),
            console_logging: true,
            structured: false,
        }
    }
}

/// Output format options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
    Xml,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "csv" => Ok(OutputFormat::Csv),
            "xml" => Ok(OutputFormat::Xml),
            _ => Err(format!("Invalid output format: {}. Valid options: table, json, csv, xml", s)),
        }
    }
}

/// Sort options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortBy {
    ProcessName,
    RemoteAddress,
    LocalAddress,
    Port,
    Protocol,
    State,
    Bandwidth,
}

/// Log format options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
    Compact,
}

/// Configuration loader and manager
pub struct ConfigManager {
    config: NetworkMonitorConfig,
    config_path: Option<PathBuf>,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new() -> Self {
        Self {
            config: NetworkMonitorConfig::default(),
            config_path: None,
        }
    }

    /// Load configuration from various sources
    pub fn load(&mut self) -> Result<()> {
        debug!("Loading configuration");

        // Start with defaults
        let mut config = NetworkMonitorConfig::default();

        // Try to load from config file
        if let Some(config_path) = self.get_config_file_path() {
            match self.load_from_file(&config_path) {
                Ok(file_config) => {
                    config = file_config;
                    info!("Loaded configuration from {:?}", config_path);
                    self.config_path = Some(config_path);
                }
                Err(e) => {
                    warn!("Failed to load config file {:?}: {}", config_path, e);
                    // Continue with defaults for missing config file
                }
            }
        }

        // Override with environment variables
        self.apply_env_overrides(&mut config)?;

        // Validate configuration
        self.validate(&config)?;

        self.config = config;
        Ok(())
    }

    /// Get the current configuration
    pub fn get(&self) -> &NetworkMonitorConfig {
        &self.config
    }

    /// Get mutable configuration
    #[allow(dead_code)]
    pub fn get_mut(&mut self) -> &mut NetworkMonitorConfig {
        &mut self.config
    }

    /// Save configuration to file
    #[allow(dead_code)]
    pub fn save(&self) -> Result<()> {
        if let Some(config_path) = &self.config_path {
            self.save_to_file(config_path)?;
        } else {
            return Err(NetworkMonitorError::config("No config file path set"));
        }
        Ok(())
    }

    /// Get the configuration file path
    fn get_config_file_path(&self) -> Option<PathBuf> {
        // Check various locations in order of preference
        let paths = vec![
            std::env::var("NETSIGHT_CONFIG").ok().map(PathBuf::from),
            dirs::home_dir().map(|h| h.join(DEFAULT_CONFIG_DIR).join(DEFAULT_CONFIG_FILE)),
            Some(PathBuf::from(DEFAULT_CONFIG_FILE)),
        ];

        paths.into_iter().flatten().find(|p| p.exists())
    }

    /// Load configuration from file
    fn load_from_file(&self, path: &PathBuf) -> Result<NetworkMonitorConfig> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| NetworkMonitorError::io_with_source("Failed to read config file", e))?;

        toml::from_str(&content)
            .map_err(|e| NetworkMonitorError::parse_with_source("Failed to parse config", "TOML", e))
    }

    /// Save configuration to file
    #[allow(dead_code)]
    fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| NetworkMonitorError::io_with_source("Failed to create config directory", e))?;
        }

        let content = toml::to_string_pretty(&self.config)
            .map_err(|e| NetworkMonitorError::parse_with_source("Failed to serialize config", "TOML", e))?;

        std::fs::write(path, content)
            .map_err(|e| NetworkMonitorError::io_with_source("Failed to write config file", e))?;

        info!("Configuration saved to {:?}", path);
        Ok(())
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&self, config: &mut NetworkMonitorConfig) -> Result<()> {
        // Network settings
        if let Ok(interval) = std::env::var("NETSIGHT_SCAN_INTERVAL") {
            config.network.scan_interval_ms = interval
                .parse()
                .map_err(|_| NetworkMonitorError::validation("Invalid NETSIGHT_SCAN_INTERVAL"))?;
        }

        // DNS settings
        if let Ok(enabled) = std::env::var("NETSIGHT_DNS_ENABLED") {
            config.dns.enabled = enabled
                .parse()
                .map_err(|_| NetworkMonitorError::validation("Invalid NETSIGHT_DNS_ENABLED"))?;
        }

        // GeoIP settings
        if let Ok(enabled) = std::env::var("NETSIGHT_GEOIP_ENABLED") {
            config.geoip.enabled = enabled
                .parse()
                .map_err(|_| NetworkMonitorError::validation("Invalid NETSIGHT_GEOIP_ENABLED"))?;
        }

        // Display settings
        if let Ok(format) = std::env::var("NETSIGHT_OUTPUT_FORMAT") {
            config.display.output_format = format
                .parse()
                .map_err(|_| NetworkMonitorError::validation("Invalid NETSIGHT_OUTPUT_FORMAT"))?;
        }

        // Logging settings
        if let Ok(level) = std::env::var("NETSIGHT_LOG_LEVEL") {
            config.logging.level = level;
        }

        Ok(())
    }

    /// Validate configuration
    fn validate(&self, config: &NetworkMonitorConfig) -> Result<()> {
        // Validate network settings
        if config.network.scan_interval_ms == 0 {
            return Err(NetworkMonitorError::validation_field(
                "Scan interval must be greater than 0",
                "network.scan_interval_ms",
            ));
        }

        if config.network.max_connections == 0 {
            return Err(NetworkMonitorError::validation_field(
                "Max connections must be greater than 0",
                "network.max_connections",
            ));
        }

        // Validate DNS settings
        if config.dns.cache_ttl_seconds == 0 {
            return Err(NetworkMonitorError::validation_field(
                "DNS cache TTL must be greater than 0",
                "dns.cache_ttl_seconds",
            ));
        }

        // Validate GeoIP settings
        if config.geoip.enabled {
            if let Some(db_path) = &config.geoip.database_path {
                if !db_path.exists() && !config.geoip.auto_download {
                    // Don't fail validation for GeoIP - let the application handle it at runtime
                    warn!("GeoIP database not found: {:?}. GeoIP features will be disabled.", db_path);
                }
            }
        }

        // Validate display settings
        if config.display.max_display_connections == 0 {
            return Err(NetworkMonitorError::validation_field(
                "Max display connections must be greater than 0",
                "display.max_display_connections",
            ));
        }

        Ok(())
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = NetworkMonitorConfig::default();
        assert_eq!(config.network.scan_interval_ms, 1000);
        assert!(config.dns.enabled);
        assert!(config.geoip.enabled);
    }

    #[test]
    fn test_config_validation() {
        let manager = ConfigManager::new();
        let mut config = NetworkMonitorConfig::default();
        
        // Valid config should pass
        assert!(manager.validate(&config).is_ok());
        
        // Invalid scan interval should fail
        config.network.scan_interval_ms = 0;
        assert!(manager.validate(&config).is_err());
    }

    #[test]
    fn test_config_save_load() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("test_config.toml");
        
        let mut manager = ConfigManager::new();
        manager.config.network.scan_interval_ms = 2000;
        manager.config_path = Some(config_path.clone());
        
        // Save config
        assert!(manager.save().is_ok());
        
        // Load config
        let mut manager2 = ConfigManager::new();
        manager2.config_path = Some(config_path);
        assert!(manager2.load().is_ok());
        
        // Check loaded value
        assert_eq!(manager2.config.network.scan_interval_ms, 2000);
    }
}
