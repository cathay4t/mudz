// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs, net::IpAddr, path::Path};

use mudz::{ErrorKind, MudzError};
use serde::Deserialize;

const DEFAULT_MAX_CACHE_SIZE: usize = 4096;
const DEFAULT_UDP_BIND: &str = "127.0.0.1:53";

/// Configuration for the main section
#[derive(Debug, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct MudzMainConfig {
    /// UDP socket bind address
    pub(crate) udp_bind: String,
    /// TCP socket bind address (RFC 7766 §6.1: every DNS server must support
    /// TCP, used when a UDP reply is truncated). Defaults to the same
    /// address as `udp_bind` when omitted.
    pub(crate) tcp_bind: Option<String>,
    /// Maximum number of cache entries
    pub(crate) max_cache_size: usize,
    #[serde(default)]
    /// Log level (e.g., "info", "debug", "warn", "error")
    pub(crate) log_level: String,
}

impl Default for MudzMainConfig {
    fn default() -> Self {
        Self {
            udp_bind: DEFAULT_UDP_BIND.to_string(),
            tcp_bind: None,
            max_cache_size: DEFAULT_MAX_CACHE_SIZE,
            log_level: "info".to_string(),
        }
    }
}

/// Configuration for the fallback (default upstream) section
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct MudzFallbackConfig {
    /// Upstream DNS servers for fallback
    pub(crate) nameservers: Vec<String>,
    /// Disable AAAA queries for fallback servers
    #[serde(default)]
    pub(crate) disable_ipv6: bool,
}

/// Configuration for the [doh] section. Provides plain IP nameservers for
/// resolving DoH server hostnames. Mandatory if any nameserver is a DoH URL.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct MudzDohConfig {
    /// UDP nameservers for resolving DoH server hostnames
    pub(crate) nameservers: Vec<IpAddr>,
    /// Disable AAAA queries for DoH resolver
    #[serde(default)]
    pub(crate) disable_ipv6: bool,
}

/// Configuration for a named group of upstream DNS servers
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DnsUpstreamGroup {
    /// Nameservers in this group
    pub(crate) nameservers: Vec<String>,
    /// Domains that should be routed to this group, empty means reply NXDOMAIN
    /// immediately without forwarding to fallback.
    pub(crate) domains: Vec<String>,
    /// Disable AAAA queries for this group
    pub(crate) disable_ipv6: bool,
}

/// Full mudz configuration
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct MudzConfig {
    /// Main settings
    pub(crate) main: MudzMainConfig,
    /// Fallback (default upstream) settings
    pub(crate) fallback: MudzFallbackConfig,
    /// DoH resolver settings (mandatory if any nameserver is a DoH URL)
    pub(crate) doh: Option<MudzDohConfig>,
    /// Named upstream groups, keyed by group name (from [group.*] sections)
    #[serde(rename = "group")]
    pub(crate) groups: HashMap<String, DnsUpstreamGroup>,
}

impl MudzConfig {
    /// Load configuration from a TOML file
    pub(crate) fn from_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, MudzError> {
        let path_ref = path.as_ref();
        let content = fs::read_to_string(path_ref).map_err(|e| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!(
                    "Config file '{}' not found or not readable: {}",
                    path_ref.display(),
                    e
                ),
            )
        })?;
        Self::validate_unique_group_names(&content)?;
        let config = toml::from_str::<Self>(&content).map_err(|e| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!("Failed to parse config: {e}"),
            )
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate that group names are not empty
    fn validate_group_names(&self) -> Result<(), MudzError> {
        for name in self.groups.keys() {
            if name.is_empty() {
                return Err(MudzError::new(
                    mudz::ErrorKind::InvalidConfig,
                    "group name cannot be empty",
                ));
            }
        }
        Ok(())
    }

    /// Validate the configuration:
    /// 1. Group name cannot be empty
    /// 2. Group domains cannot overlap
    /// 3. If any nameserver uses DoH, [doh] section must be present with plain
    ///    IP nameservers
    pub(crate) fn validate(&self) -> Result<(), MudzError> {
        self.validate_group_names()?;
        self.validate_domain_overlap()?;
        self.validate_doh_nameservers()?;
        Ok(())
    }

    /// Validate that no two groups have overlapping domains.
    fn validate_domain_overlap(&self) -> Result<(), MudzError> {
        let group_list: Vec<(&String, &DnsUpstreamGroup)> =
            self.groups.iter().collect();
        for i in 0..group_list.len() {
            for j in (i + 1)..group_list.len() {
                let (name_a, group_a) = group_list[i];
                let (name_b, group_b) = group_list[j];
                for da in &group_a.domains {
                    for db in &group_b.domains {
                        if domains_overlap(da, db) {
                            return Err(MudzError::new(
                                mudz::ErrorKind::InvalidConfig,
                                format!(
                                    "Domain '{da}' in group '{name_a}' \
                                     overlaps with domain '{db}' in group \
                                     '{name_b}'"
                                ),
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate that there are no duplicate group names in the raw TOML
    /// content. serde's HashMap silently overwrites duplicates, so we check
    /// before parsing.
    fn validate_unique_group_names(content: &str) -> Result<(), MudzError> {
        let mut seen = std::collections::HashSet::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("[group.") && trimmed.ends_with(']') {
                let name = trimmed[7..trimmed.len() - 1].trim();
                if !name.is_empty() && !seen.insert(name) {
                    return Err(MudzError::new(
                        mudz::ErrorKind::InvalidConfig,
                        format!("Duplicate DNS cache group name: {name}"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate that if any nameserver uses DoH, a [doh] section with plain
    /// IP nameservers is present
    fn validate_doh_nameservers(&self) -> Result<(), MudzError> {
        let has_doh = self
            .fallback
            .nameservers
            .iter()
            .any(|ns| ns.starts_with("https://"))
            || self.groups.values().any(|g| {
                g.nameservers.iter().any(|ns| ns.starts_with("https://"))
            });

        if !has_doh {
            return Ok(());
        }

        match &self.doh {
            None => {
                return Err(MudzError::new(
                    mudz::ErrorKind::InvalidConfig,
                    "DoH servers are configured but no [doh] section found. \
                     Please add a [doh] section with plain IP nameservers to \
                     resolve DoH server hostnames",
                ));
            }
            Some(doh) => {
                if doh.nameservers.is_empty() {
                    return Err(MudzError::new(
                        mudz::ErrorKind::InvalidConfig,
                        "[doh] section must have at least one nameserver",
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Extract lowercase hostname from a DoH URL
/// (e.g., "https://dns.alidns.com/dns-query" -> "dns.alidns.com")
pub(crate) fn extract_doh_hostname(url: &str) -> Option<String> {
    let without_scheme = url.strip_prefix("https://")?;
    let hostname = without_scheme.split('/').next()?;
    let hostname_without_port = hostname.split(':').next()?;
    if hostname_without_port.is_empty() {
        return None;
    }
    Some(hostname_without_port.to_lowercase())
}

/// Check if two domain patterns overlap (one equals the other).
/// Subdomain relationships are NOT considered overlaps — the runtime uses
/// longest-suffix matching, so `www.example.com` in one group and
/// `example.com` in another is unambiguous.
fn domains_overlap(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
