#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use dns_lookup::lookup_addr;

pub struct DnsResolver {
    cache: HashMap<IpAddr, (String, Instant)>,
    cache_ttl: Duration,
}

impl DnsResolver {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            cache_ttl: Duration::from_secs(300), // 5 minutes cache
        }
    }

    pub fn with_cache_ttl(ttl_seconds: u64) -> Self {
        Self {
            cache: HashMap::new(),
            cache_ttl: Duration::from_secs(ttl_seconds),
        }
    }

    pub fn resolve_hostname(&mut self, ip: IpAddr) -> String {
        // Check cache first
        if let Some((hostname, cached_at)) = self.cache.get(&ip) {
            if cached_at.elapsed() < self.cache_ttl {
                return hostname.clone();
            }
        }

        // Perform DNS lookup
        let hostname = match lookup_addr(&ip) {
            Ok(name) => name,
            Err(_) => ip.to_string(),
        };

        // Cache the result
        self.cache.insert(ip, (hostname.clone(), Instant::now()));
        
        hostname
    }

    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.cache.retain(|_, (_, cached_at)| {
            now.duration_since(*cached_at) < self.cache_ttl
        });
    }
}
