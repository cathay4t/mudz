// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use mudz::{DnsClass, DnsPacket, DnsResourceRecord, DnsType};

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
    pub(crate) fn new() -> Self {
        let mut a_records: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();
        let mut aaaa_records: HashMap<String, Vec<Ipv6Addr>> = HashMap::new();

        if let Ok(file) = std::fs::File::open(HOSTS_FILE) {
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
        // Strip inline comments
        let line = match line.split('#').next() {
            Some(content) => content.trim(),
            None => return,
        };
        // Skip empty lines and comments
        if line.is_empty() {
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
                a_records
                    .entry(hostname.to_lowercase())
                    .or_default()
                    .push(ipv4);
            }
        } else if let Ok(ipv6) = addr_str.parse::<Ipv6Addr>() {
            for hostname in hostnames {
                aaaa_records
                    .entry(hostname.to_lowercase())
                    .or_default()
                    .push(ipv6);
            }
        }
    }

    pub(crate) fn get(&self, packet: &DnsPacket) -> Option<DnsPacket> {
        let query_type = packet.questions.first()?.kind;
        let domain_obj = &packet.questions.first()?.domain;
        let domain = packet.questions.first()?.domain.to_string();

        let mut packet = packet.clone();

        packet.header.set_response(true);

        match query_type {
            DnsType::A => {
                let ips = self.a_records.get(&domain)?;
                packet.header.ancount = ips.len() as u16;
                packet.answers = ips
                    .iter()
                    .map(|ip| DnsResourceRecord {
                        domain: domain_obj.clone(),
                        kind: DnsType::A,
                        class: DnsClass::IN,
                        ttl: 300,
                        rdlength: (Ipv4Addr::BITS / 8) as u16,
                        rdata: ip.octets().to_vec(),
                    })
                    .collect();
                Some(packet)
            }
            DnsType::AAAA => {
                let ips = self.aaaa_records.get(&domain)?;
                packet.header.ancount = ips.len() as u16;
                packet.answers = ips
                    .iter()
                    .map(|ip| DnsResourceRecord {
                        domain: domain_obj.clone(),
                        kind: DnsType::AAAA,
                        class: DnsClass::IN,
                        ttl: 300,
                        rdlength: (Ipv6Addr::BITS / 8) as u16,
                        rdata: ip.octets().to_vec(),
                    })
                    .collect();
                Some(packet)
            }
            _ => None,
        }
    }

    pub(crate) fn lookup_ips(&self, domain: &str) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        if let Some(ipv4s) = self.a_records.get(domain) {
            ips.extend(ipv4s.iter().map(|&ip| IpAddr::V4(ip)));
        }
        if let Some(ipv6s) = self.aaaa_records.get(domain) {
            ips.extend(ipv6s.iter().map(|&ip| IpAddr::V6(ip)));
        }
        ips
    }
}
