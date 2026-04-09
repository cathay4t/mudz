// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, Ipv6Addr},
};

/// Path to the hosts file
const HOSTS_FILE: &str = "/etc/hosts";

/// Parsed /etc/hosts entries
#[derive(Clone)]
pub(crate) struct HostsFile {
    /// Map of domain -> list of IPv4 addresses
    a_records: HashMap<String, Vec<Ipv4Addr>>,
    /// Map of domain -> list of IPv6 addresses
    aaaa_records: HashMap<String, Vec<Ipv6Addr>>,
}

impl HostsFile {
    /// Parse /etc/hosts and return the parsed entries
    pub fn new() -> Self {
        let mut a_records: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();
        let mut aaaa_records: HashMap<String, Vec<Ipv6Addr>> = HashMap::new();

        if let Ok(file) = fs::File::open(HOSTS_FILE) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                Self::parse_line(&line, &mut a_records, &mut aaaa_records);
            }
            log::info!(
                "Loaded /etc/hosts: {} A records, {} AAAA records",
                a_records.len(),
                aaaa_records.len()
            );
        } else {
            log::debug!("Could not open {}, skipping", HOSTS_FILE);
        }

        Self {
            a_records,
            aaaa_records,
        }
    }

    /// Parse a single line from /etc/hosts
    fn parse_line(
        line: &str,
        a_records: &mut HashMap<String, Vec<Ipv4Addr>>,
        aaaa_records: &mut HashMap<String, Vec<Ipv6Addr>>,
    ) {
        let line = line.trim();
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            return;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }

        let addr_str = parts[0];
        let hostnames = &parts[1..];

        // Try to parse as IPv4 or IPv6 address
        if let Ok(ipv4) = addr_str.parse::<Ipv4Addr>() {
            for hostname in hostnames {
                if !hostname.starts_with('#') {
                    a_records
                        .entry(hostname.to_lowercase())
                        .or_default()
                        .push(ipv4);
                }
            }
        } else if let Ok(ipv6) = addr_str.parse::<Ipv6Addr>() {
            for hostname in hostnames {
                if !hostname.starts_with('#') {
                    aaaa_records
                        .entry(hostname.to_lowercase())
                        .or_default()
                        .push(ipv6);
                }
            }
        }
    }

    /// Look up A records for a domain
    pub fn lookup_a(&self, domain: &str) -> Option<&Vec<Ipv4Addr>> {
        self.a_records.get(&domain.to_lowercase())
    }

    /// Look up AAAA records for a domain
    pub fn lookup_aaaa(&self, domain: &str) -> Option<&Vec<Ipv6Addr>> {
        self.aaaa_records.get(&domain.to_lowercase())
    }
}
