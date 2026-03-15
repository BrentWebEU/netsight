//! Data structures for the network monitor.
//!
//! This module contains all the core data structures used throughout
//! the network monitor application.

pub mod net_strucs;

// Re-export commonly used types
pub use net_strucs::{Connection, Protocol, ConnectionState};
