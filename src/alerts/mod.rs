//! Alert system for network monitoring
//!
//! This module provides a comprehensive alerting system that can detect
//! and report suspicious network activity, security threats, and anomalies.

use crate::error::{NetworkMonitorError, Result};
use crate::strucs::net_strucs::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{info, warn, error};

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Alert categories
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertCategory {
    Security,
    Performance,
    Anomaly,
    Compliance,
}

/// Alert rule types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertRuleType {
    /// Alert when connection count exceeds threshold
    ConnectionThreshold { threshold: usize },
    /// Alert when suspicious ports are detected
    SuspiciousPort { ports: Vec<u16> },
    /// Alert when connections to certain countries are detected
    GeoLocation { countries: Vec<String> },
    /// Alert when process has too many connections
    ProcessConnectionCount { threshold: usize },
    /// Alert when unknown processes are detected
    UnknownProcess,
    /// Alert when high bandwidth usage is detected
    HighBandwidth { threshold_bytes_per_second: u64 },
}

/// Alert rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rule_type: AlertRuleType,
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub enabled: bool,
}

/// Alert event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub message: String,
    pub details: AlertDetails,
    pub timestamp: DateTime<Utc>,
    pub resolved: bool,
}

/// Alert details containing context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDetails {
    pub connections: Vec<Connection>,
    pub metadata: HashMap<String, String>,
}

/// Alert engine for processing connections and generating alerts
pub struct AlertEngine {
    rules: Vec<AlertRule>,
    alert_history: Vec<Alert>,
    max_history_size: usize,
}

impl AlertEngine {
    /// Create a new alert engine with default rules
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            alert_history: Vec::new(),
            max_history_size: 1000,
        };
        
        // Load default rules
        engine.load_default_rules();
        engine
    }

    /// Create alert engine with custom configuration
    pub fn with_config(max_history_size: usize) -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            alert_history: Vec::new(),
            max_history_size,
        };
        
        engine.load_default_rules();
        engine
    }

    /// Load default alert rules
    fn load_default_rules(&mut self) {
        self.rules = vec![
            AlertRule {
                id: "conn_threshold".to_string(),
                name: "High Connection Count".to_string(),
                description: "Alert when total connections exceed threshold".to_string(),
                rule_type: AlertRuleType::ConnectionThreshold { threshold: 100 },
                severity: AlertSeverity::Warning,
                category: AlertCategory::Performance,
                enabled: true,
            },
            AlertRule {
                id: "suspicious_ports".to_string(),
                name: "Suspicious Port Activity".to_string(),
                description: "Alert when connections to suspicious ports are detected".to_string(),
                rule_type: AlertRuleType::SuspiciousPort { 
                    ports: vec![4444, 1337, 31337, 6667, 5555, 12345, 54321] 
                },
                severity: AlertSeverity::Critical,
                category: AlertCategory::Security,
                enabled: true,
            },
            AlertRule {
                id: "process_conn_threshold".to_string(),
                name: "Process Connection Limit".to_string(),
                description: "Alert when a process has too many connections".to_string(),
                rule_type: AlertRuleType::ProcessConnectionCount { threshold: 50 },
                severity: AlertSeverity::Warning,
                category: AlertCategory::Anomaly,
                enabled: true,
            },
            AlertRule {
                id: "high_bandwidth".to_string(),
                name: "High Bandwidth Usage".to_string(),
                description: "Alert when bandwidth usage exceeds threshold".to_string(),
                rule_type: AlertRuleType::HighBandwidth { threshold_bytes_per_second: 1024 * 1024 }, // 1MB/s
                severity: AlertSeverity::Warning,
                category: AlertCategory::Performance,
                enabled: true,
            },
        ];
    }

    /// Add a custom alert rule
    pub fn add_rule(&mut self, rule: AlertRule) {
        self.rules.push(rule);
    }

    /// Remove an alert rule by ID
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule_id) {
            self.rules.remove(pos);
            true
        } else {
            false
        }
    }

    /// Enable/disable a rule
    pub fn toggle_rule(&mut self, rule_id: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Process connections and generate alerts
    pub fn process_connections(&mut self, connections: &[Connection]) -> Vec<Alert> {
        let mut new_alerts = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if let Some(alert) = self.evaluate_rule(rule, connections) {
                new_alerts.push(alert);
            }
        }

        // Store alerts in history
        for alert in &new_alerts {
            self.add_to_history(alert.clone());
        }

        new_alerts
    }

    /// Evaluate a single rule against connections
    fn evaluate_rule(&self, rule: &AlertRule, connections: &[Connection]) -> Option<Alert> {
        match &rule.rule_type {
            AlertRuleType::ConnectionThreshold { threshold } => {
                if connections.len() > *threshold {
                    Some(self.create_alert(
                        rule,
                        format!("Connection count ({}) exceeds threshold ({})", connections.len(), threshold),
                        connections.to_vec(),
                        [("total_connections".to_string(), connections.len().to_string())]
                            .into_iter()
                            .collect(),
                    ))
                } else {
                    None
                }
            }
            AlertRuleType::SuspiciousPort { ports } => {
                let suspicious_connections: Vec<Connection> = connections
                    .iter()
                    .filter(|c| ports.contains(&c.remote_addr.port()))
                    .cloned()
                    .collect();

                if !suspicious_connections.is_empty() {
                    let port_list: Vec<String> = suspicious_connections
                        .iter()
                        .map(|c| c.remote_addr.port().to_string())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();

                    Some(self.create_alert(
                        rule,
                        format!("Suspicious port activity detected: {}", port_list.join(", ")),
                        suspicious_connections,
                        [("suspicious_ports".to_string(), port_list.join(", "))]
                            .into_iter()
                            .collect(),
                    ))
                } else {
                    None
                }
            }
            AlertRuleType::GeoLocation { countries: _ } => {
                // TODO: Implement once we have GeoIP data in connections
                None
            }
            AlertRuleType::ProcessConnectionCount { threshold } => {
                let mut process_counts: HashMap<String, usize> = HashMap::new();
                let mut process_connections: HashMap<String, Vec<Connection>> = HashMap::new();

                for conn in connections {
                    let count = process_counts.entry(conn.process_name.clone()).or_insert(0);
                    *count += 1;
                    process_connections.entry(conn.process_name.clone()).or_insert_with(Vec::new).push(conn.clone());
                }

                for (process, count) in process_counts {
                    if count > *threshold {
                        let conns = process_connections.get(&process).unwrap_or(&vec![]).clone();
                        return Some(self.create_alert(
                            rule,
                            format!("Process {} has {} connections (threshold: {})", process, count, threshold),
                            conns,
                            [("process_name".to_string(), process.clone()), 
                             ("connection_count".to_string(), count.to_string())]
                                .into_iter()
                                .collect(),
                        ));
                    }
                }
                None
            }
            AlertRuleType::UnknownProcess => {
                // TODO: Implement with a whitelist of known processes
                None
            }
            AlertRuleType::HighBandwidth { threshold_bytes_per_second } => {
                let total_bytes: u64 = connections.iter().map(|c| c.bytes_in + c.bytes_out).sum();
                if total_bytes > *threshold_bytes_per_second {
                    Some(self.create_alert(
                        rule,
                        format!("High bandwidth usage detected: {} bytes/s", total_bytes),
                        connections.to_vec(),
                        [("bandwidth_bytes".to_string(), total_bytes.to_string())]
                            .into_iter()
                            .collect(),
                    ))
                } else {
                    None
                }
            }
        }
    }

    /// Create a new alert
    fn create_alert(&self, rule: &AlertRule, message: String, connections: Vec<Connection>, metadata: HashMap<String, String>) -> Alert {
        Alert {
            id: format!("{}-{}", rule.id, Utc::now().timestamp()),
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.severity.clone(),
            category: rule.category.clone(),
            message,
            details: AlertDetails {
                connections,
                metadata,
            },
            timestamp: Utc::now(),
            resolved: false,
        }
    }

    /// Add alert to history
    fn add_to_history(&mut self, alert: Alert) {
        self.alert_history.push(alert);
        
        // Trim history if it exceeds maximum size
        if self.alert_history.len() > self.max_history_size {
            let excess = self.alert_history.len() - self.max_history_size;
            self.alert_history.drain(0..excess);
        }
    }

    /// Get alert history
    pub fn get_alert_history(&self) -> &[Alert] {
        &self.alert_history
    }

    /// Get active (unresolved) alerts
    pub fn get_active_alerts(&self) -> Vec<&Alert> {
        self.alert_history.iter().filter(|a| !a.resolved).collect()
    }

    /// Resolve an alert
    pub fn resolve_alert(&mut self, alert_id: &str) -> bool {
        if let Some(alert) = self.alert_history.iter_mut().find(|a| a.id == alert_id) {
            alert.resolved = true;
            info!("Alert {} resolved", alert_id);
            true
        } else {
            false
        }
    }

    /// Get all rules
    pub fn get_rules(&self) -> &[AlertRule] {
        &self.rules
    }

    /// Get alert statistics
    pub fn get_statistics(&self) -> AlertStatistics {
        let total_alerts = self.alert_history.len();
        let active_alerts = self.get_active_alerts().len();
        let critical_alerts = self.alert_history.iter().filter(|a| matches!(a.severity, AlertSeverity::Critical)).count();
        let warning_alerts = self.alert_history.iter().filter(|a| matches!(a.severity, AlertSeverity::Warning)).count();
        let info_alerts = self.alert_history.iter().filter(|a| matches!(a.severity, AlertSeverity::Info)).count();

        AlertStatistics {
            total_alerts,
            active_alerts,
            critical_alerts,
            warning_alerts,
            info_alerts,
        }
    }
}

/// Alert statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatistics {
    pub total_alerts: usize,
    pub active_alerts: usize,
    pub critical_alerts: usize,
    pub warning_alerts: usize,
    pub info_alerts: usize,
}

impl Default for AlertEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strucs::net_strucs::{Protocol, ConnectionState};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_connection(port: u16, process: &str) -> Connection {
        Connection {
            pid: 1234,
            process_name: process.to_string(),
            local_addr: "127.0.0.1:0".parse().unwrap(),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port),
            protocol: Protocol::Tcp,
            state: ConnectionState::Established,
            bytes_in: 1000,
            bytes_out: 500,
        }
    }

    #[test]
    fn test_connection_threshold_alert() {
        let mut engine = AlertEngine::new();
        let connections: Vec<Connection> = (0..150).map(|i| create_test_connection(8080 + i, "test")).collect();
        
        let alerts = engine.process_connections(&connections);
        assert!(!alerts.is_empty());
        
        let threshold_alert = alerts.iter().find(|a| a.rule_id == "conn_threshold");
        assert!(threshold_alert.is_some());
    }

    #[test]
    fn test_suspicious_port_alert() {
        let mut engine = AlertEngine::new();
        let connections = vec![
            create_test_connection(4444, "suspicious"),
            create_test_connection(80, "normal"),
        ];
        
        let alerts = engine.process_connections(&connections);
        assert!(!alerts.is_empty());
        
        let suspicious_alert = alerts.iter().find(|a| a.rule_id == "suspicious_ports");
        assert!(suspicious_alert.is_some());
    }

    #[test]
    fn test_process_connection_count_alert() {
        let mut engine = AlertEngine::new();
        let connections: Vec<Connection> = (0..60).map(|_| create_test_connection(80, "busy_process")).collect();
        
        let alerts = engine.process_connections(&connections);
        assert!(!alerts.is_empty());
        
        let process_alert = alerts.iter().find(|a| a.rule_id == "process_conn_threshold");
        assert!(process_alert.is_some());
    }
}
