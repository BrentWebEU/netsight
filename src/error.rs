//! Comprehensive error handling for the network monitor.
//!
//! This module provides custom error types that give specific context about
//! what went wrong during network monitoring operations.

use thiserror::Error;

/// Main error type for the network monitor application.
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum NetworkMonitorError {
    /// Errors related to process information gathering
    #[error("Process error: {message}")]
    Process {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Errors related to network operations
    #[error("Network error: {message}")]
    Network {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Errors related to DNS resolution
    #[error("DNS resolution error: {message}")]
    Dns {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Errors related to GeoIP database operations
    #[error("GeoIP error: {message}")]
    GeoIp {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Configuration related errors
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// I/O related errors
    #[error("I/O error: {message}")]
    Io {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Parsing related errors
    #[error("Parse error: {message} in {context}")]
    Parse {
        message: String,
        context: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Validation errors
    #[error("Validation error: {message}")]
    Validation {
        message: String,
        field: Option<String>,
    },

    /// Resource not found errors
    #[error("Resource not found: {resource}")]
    NotFound {
        resource: String,
        suggestion: Option<String>,
    },

    /// Permission related errors
    #[error("Permission denied: {operation}")]
    Permission {
        operation: String,
        suggestion: Option<String>,
    },

    /// Timeout errors
    #[error("Operation timed out: {operation} after {duration_ms}ms")]
    Timeout {
        operation: String,
        duration_ms: u64,
    },

    /// Generic error with context
    #[error("Error: {message}")]
    Generic {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

#[allow(dead_code)]
impl NetworkMonitorError {
    /// Create a new process error
    pub fn process<S: Into<String>>(message: S) -> Self {
        Self::Process {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new process error with a source
    pub fn process_with_source<S: Into<String>, E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        message: S,
        source: E,
    ) -> Self {
        Self::Process {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// Create a new network error
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new DNS error
    pub fn dns<S: Into<String>>(message: S) -> Self {
        Self::Dns {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new GeoIP error
    pub fn geoip<S: Into<String>>(message: S) -> Self {
        Self::GeoIp {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new configuration error
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Config {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new I/O error
    pub fn io<S: Into<String>>(message: S) -> Self {
        Self::Io {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new parse error
    pub fn parse<S: Into<String>, C: Into<String>>(message: S, context: C) -> Self {
        Self::Parse {
            message: message.into(),
            context: context.into(),
            source: None,
        }
    }

    /// Create a new validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
            field: None,
        }
    }

    /// Create a new validation error for a specific field
    pub fn validation_field<S: Into<String>, F: Into<String>>(message: S, field: F) -> Self {
        Self::Validation {
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Create a new not found error
    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        Self::NotFound {
            resource: resource.into(),
            suggestion: None,
        }
    }

    /// Create a new not found error with a suggestion
    pub fn not_found_with_suggestion<S: Into<String>, R: Into<String>, T: Into<String>>(
        resource: R,
        suggestion: T,
    ) -> Self {
        Self::NotFound {
            resource: resource.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    /// Create a new permission error
    pub fn permission<S: Into<String>>(operation: S) -> Self {
        Self::Permission {
            operation: operation.into(),
            suggestion: None,
        }
    }

    /// Create a new permission error with a suggestion
    pub fn permission_with_suggestion<O: Into<String>, S: Into<String>>(
        operation: O,
        suggestion: S,
    ) -> Self {
        Self::Permission {
            operation: operation.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    /// Create a new timeout error
    pub fn timeout<S: Into<String>>(operation: S, duration_ms: u64) -> Self {
        Self::Timeout {
            operation: operation.into(),
            duration_ms,
        }
    }

    /// Create a new I/O error with source
    pub fn io_with_source<S: Into<String>, E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        message: S,
        source: E,
    ) -> Self {
        Self::Io {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// Create a new parse error with source
    pub fn parse_with_source<S: Into<String>, C: Into<String>, E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        message: S,
        context: C,
        source: E,
    ) -> Self {
        Self::Parse {
            message: message.into(),
            context: context.into(),
            source: Some(source.into()),
        }
    }

    /// Create a new generic error
    pub fn generic<S: Into<String>>(message: S) -> Self {
        Self::Generic {
            message: message.into(),
            source: None,
        }
    }

    /// Check if this is a recoverable error
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::Network { .. } | Self::Dns { .. } | Self::Timeout { .. } => true,
            Self::Permission { .. } | Self::NotFound { .. } => false,
            _ => false,
        }
    }

    /// Get a user-friendly suggestion for resolving this error
    pub fn user_suggestion(&self) -> Option<String> {
        match self {
            Self::Permission { suggestion, .. } => suggestion.clone(),
            Self::NotFound { suggestion, .. } => suggestion.clone(),
            Self::Config { .. } => Some("Check your configuration file".to_string()),
            Self::GeoIp { .. } => Some("Download GeoIP database or disable GeoIP features".to_string()),
            Self::Network { .. } => Some("Check your network connection".to_string()),
            _ => None,
        }
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, NetworkMonitorError>;

/// Convert from std::io::Error
impl From<std::io::Error> for NetworkMonitorError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

/// Convert from serde_json::Error
impl From<serde_json::Error> for NetworkMonitorError {
    fn from(err: serde_json::Error) -> Self {
        Self::Parse {
            message: err.to_string(),
            context: "JSON parsing".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

/// Convert from config::ConfigError
impl From<config::ConfigError> for NetworkMonitorError {
    fn from(err: config::ConfigError) -> Self {
        Self::Config {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

/// Convert from chrono::ParseError
impl From<chrono::ParseError> for NetworkMonitorError {
    fn from(err: chrono::ParseError) -> Self {
        Self::Parse {
            message: err.to_string(),
            context: "Date/time parsing".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

/// Convert from std::net::AddrParseError
impl From<std::net::AddrParseError> for NetworkMonitorError {
    fn from(err: std::net::AddrParseError) -> Self {
        Self::Parse {
            message: err.to_string(),
            context: "IP address parsing".to_string(),
            source: Some(Box::new(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = NetworkMonitorError::network("Failed to connect");
        assert!(matches!(err, NetworkMonitorError::Network { .. }));
    }

    #[test]
    fn test_error_recoverability() {
        assert!(NetworkMonitorError::network("test").is_recoverable());
        assert!(!NetworkMonitorError::permission("test").is_recoverable());
    }

    #[test]
    fn test_user_suggestions() {
        let err = NetworkMonitorError::permission("read file");
        assert!(err.user_suggestion().is_none());

        let err = NetworkMonitorError::permission_with_suggestion(
            "read file",
            "Try running with sudo",
        );
        assert_eq!(err.user_suggestion(), Some("Try running with sudo".to_string()));
    }
}
