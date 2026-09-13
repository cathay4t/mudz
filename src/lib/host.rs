// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::{DnsClass, DnsPacket, DnsResourceRecord, DnsType};

const HOSTS_FILE: &str = "/etc/hosts";

#[derive(Clone)]
pub(crate) struct HostsFile {
    a_records: HashMap<String, Vec<Ipv4Addr>>,
    aaaa_records: HashMap<String, Vec<Ipv6Addr>>,
}

impl HostsFile {
    /// A hosts file with no entries, used when `/etc/hosts` answers are
    /// disabled by configuration.
    pub(crate) fn empty() -> Self {
        Self {
            a_records: HashMap::new(),
            aaaa_records: HashMap::new(),
        }
    }

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

    fn parse_line(
        line: &str,
        a_records: &mut HashMap<String, Vec<Ipv4Addr>>,
        aaaa_records: &mut HashMap<String, Vec<Ipv6Addr>>,
    ) {
        let line = match line.split('#').next() {
            Some(content) => content.trim(),
            None => return,
        };
        if line.is_empty() {
            return;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }

        let addr_str = parts[0];
        let hostnames = &parts[1..];

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
        let question = packet.questions.first()?;
        let query_type = question.kind;
        let domain_obj = &question.domain;
        let domain = question.domain.to_string();

        match query_type {
            DnsType::A => {
                let ips = self.a_records.get(&domain)?;
                Some(DnsPacket {
                    header: packet.header.to_response(ips.len() as u16),
                    questions: vec![question.clone()],
                    answers: ips
                        .iter()
                        .map(|ip| DnsResourceRecord {
                            domain: domain_obj.clone(),
                            kind: DnsType::A,
                            class: DnsClass::IN,
                            ttl: 300,
                            rdlength: (Ipv4Addr::BITS / 8) as u16,
                            rdata: ip.octets().to_vec(),
                        })
                        .collect(),
                    authorities: Vec::new(),
                    additionals: Vec::new(),
                })
            }
            DnsType::AAAA => {
                let ips = self.aaaa_records.get(&domain)?;
                Some(DnsPacket {
                    header: packet.header.to_response(ips.len() as u16),
                    questions: vec![question.clone()],
                    answers: ips
                        .iter()
                        .map(|ip| DnsResourceRecord {
                            domain: domain_obj.clone(),
                            kind: DnsType::AAAA,
                            class: DnsClass::IN,
                            ttl: 300,
                            rdlength: (Ipv6Addr::BITS / 8) as u16,
                            rdata: ip.octets().to_vec(),
                        })
                        .collect(),
                    authorities: Vec::new(),
                    additionals: Vec::new(),
                })
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
