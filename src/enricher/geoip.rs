#![allow(dead_code)]

use anyhow::Result;
use maxminddb::Reader;
use crate::scanner::network_utils::NetworkUtils;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct GeoIpLookup {
    reader: Option<Reader<Vec<u8>>>,
    cache: HashMap<IpAddr, (String, Instant)>,
    cache_ttl: Duration,
}

impl GeoIpLookup {
    pub fn new() -> Self {
        Self {
            reader: None,
            cache: HashMap::new(),
            cache_ttl: Duration::from_secs(3600), // 1 hour cache
        }
    }

    pub fn with_database_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = Reader::open_readfile(path)?;
        Ok(Self {
            reader: Some(reader),
            cache: HashMap::new(),
            cache_ttl: Duration::from_secs(3600),
        })
    }

    pub fn lookup_country(&mut self, ip: IpAddr) -> String {
        // Check cache first
        if let Some((country, cached_at)) = self.cache.get(&ip) {
            if cached_at.elapsed() < self.cache_ttl {
                return country.clone();
            }
        }

        // Skip private IPs
        if ip.is_loopback() || ip.is_unspecified() {
            return "Local".to_string();
        }
        
        // Check for private IP ranges
        if NetworkUtils::is_private_ip(&ip) {
            return "Local".to_string();
        }

        // Perform GeoIP lookup
        let country = if let Some(ref reader) = self.reader {
            match reader.lookup::<maxminddb::geoip2::Country>(ip) {
                Ok(result) => {
                    if let Some(country) = result.country {
                        country.iso_code.unwrap_or("Unknown").to_string()
                    } else {
                        "Unknown".to_string()
                    }
                }
                Err(_) => "Unknown".to_string(),
            }
        } else {
            "No DB".to_string()
        };

        // Cache the result
        self.cache.insert(ip, (country.clone(), Instant::now()));
        
        country
    }

    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }

    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.cache.retain(|_, (_, cached_at)| {
            now.duration_since(*cached_at) < self.cache_ttl
        });
    }

    pub fn download_database() -> Result<()> {
        // For now, just return an error - user needs to download manually
        Err(anyhow::anyhow!(
            "Please download dbip-country.mmdb from DB-IP and place it in data/ directory"
        ))
    }
}
