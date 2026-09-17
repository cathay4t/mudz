// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs, net::IpAddr, path::Path};

use serde::Deserialize;

use super::endpoint::{NameserverAddress, NameserverEndpoint};
use crate::{ErrorKind, MudzError};

const DEFAULT_MAX_CACHE_SIZE: usize = 4096;
const DEFAULT_UDP_BIND: &str = "127.0.0.1:53";
const DEFAULT_DOH_TIMEOUT_SEC: u64 = 5;
const DEFAULT_DOH_RETRIES: usize = 1;
const DEFAULT_DOH_KEEPALIVE_INTERVAL_SEC: u64 = 20;
const DEFAULT_DOH_KEEPALIVE_TIMEOUT_SEC: u64 = 5;
const DEFAULT_DOH_IDLE_TIMEOUT_SEC: u64 = 60;
/// The DoH lookup must finish before the 6 s group-level guard, so a longer
/// per-client timeout would only mask the group timeout.
const MAX_DOH_TIMEOUT_SEC: u64 = 5;
const MAX_DOH_RETRIES: usize = 5;

fn default_doh_timeout() -> u64 {
    DEFAULT_DOH_TIMEOUT_SEC
}

fn default_doh_retries() -> usize {
    DEFAULT_DOH_RETRIES
}

fn default_doh_keepalive_interval() -> u64 {
    DEFAULT_DOH_KEEPALIVE_INTERVAL_SEC
}

fn default_doh_keepalive_timeout() -> u64 {
    DEFAULT_DOH_KEEPALIVE_TIMEOUT_SEC
}

fn default_doh_idle_timeout() -> u64 {
    DEFAULT_DOH_IDLE_TIMEOUT_SEC
}

/// Configuration for the main section
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MudzMainConfig {
    /// UDP socket bind address
    pub udp_bind: String,
    /// TCP socket bind address (RFC 7766 §6.1: every DNS server must support
    /// TCP, used when a UDP reply is truncated). Defaults to the same
    /// address as `udp_bind` when omitted.
    pub tcp_bind: Option<String>,
    /// Maximum number of cache entries
    pub max_cache_size: usize,
    #[serde(default)]
    /// Log level (e.g., "info", "debug", "warn", "error")
    pub log_level: String,
    /// Answer A/AAAA queries from `/etc/hosts` before forwarding them.
    pub load_etc_hosts: bool,
}

impl Default for MudzMainConfig {
    fn default() -> Self {
        Self {
            udp_bind: DEFAULT_UDP_BIND.to_string(),
            tcp_bind: None,
            max_cache_size: DEFAULT_MAX_CACHE_SIZE,
            log_level: "info".to_string(),
            load_etc_hosts: true,
        }
    }
}

/// Configuration for the fallback (default upstream) section
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MudzFallbackConfig {
    /// Upstream DNS servers for fallback.
    ///
    /// Each entry is a DoH URL, a bare IP address (try DoT, then DNS over
    /// TCP, then UDP), or an IP address with a forced `tls://`, `tcp://` or
    /// `udp://` scheme.
    pub nameservers: Vec<String>,
    /// Disable AAAA queries for fallback servers
    #[serde(default)]
    pub disable_ipv6: bool,
}

/// Configuration for the [doh] section. Provides plain IP nameservers for
/// resolving DoH server hostnames and `tls://hostname` DoT endpoints.
/// Mandatory if any nameserver uses either.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MudzDohConfig {
    /// UDP nameservers for resolving DoH/DoT server hostnames
    pub nameservers: Vec<IpAddr>,
    /// Disable AAAA queries for DoH resolver
    #[serde(default)]
    pub disable_ipv6: bool,
    /// Overall timeout in seconds for one DoH lookup, including retries.
    #[serde(default = "default_doh_timeout")]
    pub timeout: u64,
    /// Number of retries after the first DoH attempt.
    #[serde(default = "default_doh_retries")]
    pub retries: usize,
    /// HTTP/2 keepalive ping interval in seconds; 0 disables keepalive.
    #[serde(default = "default_doh_keepalive_interval")]
    pub keepalive_interval: u64,
    /// Seconds to wait for a keepalive ping acknowledgement.
    #[serde(default = "default_doh_keepalive_timeout")]
    pub keepalive_timeout: u64,
    /// Seconds an idle pooled connection may stay open.
    #[serde(default = "default_doh_idle_timeout")]
    pub idle_timeout: u64,
}

impl Default for MudzDohConfig {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            disable_ipv6: false,
            timeout: DEFAULT_DOH_TIMEOUT_SEC,
            retries: DEFAULT_DOH_RETRIES,
            keepalive_interval: DEFAULT_DOH_KEEPALIVE_INTERVAL_SEC,
            keepalive_timeout: DEFAULT_DOH_KEEPALIVE_TIMEOUT_SEC,
            idle_timeout: DEFAULT_DOH_IDLE_TIMEOUT_SEC,
        }
    }
}

/// Configuration for a named group of upstream DNS servers
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MudzGroupConfig {
    /// Nameservers in this group.
    ///
    /// Each entry is a DoH URL, a bare IP address (try DoT, then DNS over
    /// TCP, then UDP), or an IP address with a forced `tls://`, `tcp://` or
    /// `udp://` scheme.
    pub nameservers: Vec<String>,
    /// Domains that should be routed to this group, empty means reply NXDOMAIN
    /// immediately without forwarding to fallback.
    pub domains: Vec<String>,
    /// Disable AAAA queries for this group
    pub disable_ipv6: bool,
}

/// Configuration of the DNS cache server.
///
/// It can be loaded from a TOML file with [`MudzConfig::from_file`] or built
/// directly for embedding the server into another daemon.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MudzConfig {
    /// Main settings
    pub main: MudzMainConfig,
    /// Fallback (default upstream) settings
    pub fallback: MudzFallbackConfig,
    /// DoH resolver settings (mandatory if any nameserver is a DoH URL)
    pub doh: Option<MudzDohConfig>,
    /// Named upstream groups, keyed by group name (from [group.*] sections)
    #[serde(rename = "group")]
    pub groups: HashMap<String, MudzGroupConfig>,
}

impl MudzConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, MudzError> {
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
                    ErrorKind::InvalidConfig,
                    "group name cannot be empty",
                ));
            }
        }
        Ok(())
    }

    /// Validate the configuration:
    /// 1. Group name cannot be empty
    /// 2. Group domains cannot overlap
    /// 3. Every nameserver must be a DoH URL, an IP literal with an optional
    ///    transport scheme, or a `tls://hostname` endpoint
    /// 4. If any nameserver uses DoH or a `tls://hostname`, the [doh] section
    ///    must be present with plain IP nameservers
    pub fn validate(&self) -> Result<(), MudzError> {
        self.validate_group_names()?;
        self.validate_domain_overlap()?;
        self.validate_nameservers()?;
        self.validate_bootstrap_nameservers()?;
        self.validate_doh_options()?;
        Ok(())
    }

    /// Validate every configured nameserver string.
    ///
    /// A malformed entry would otherwise only be reported as a warning when
    /// the group lazily builds its transports, leaving the group without any
    /// upstream and answering SERVFAIL for every query. Reject it at
    /// configuration time instead.
    fn validate_nameservers(&self) -> Result<(), MudzError> {
        let nameservers = self
            .fallback
            .nameservers
            .iter()
            .chain(self.groups.values().flat_map(|g| g.nameservers.iter()));
        for nameserver in nameservers {
            if nameserver.starts_with("https://") {
                if extract_doh_hostname(nameserver).is_none() {
                    return Err(MudzError::new(
                        ErrorKind::InvalidConfig,
                        format!("Invalid DoH URL: {nameserver}"),
                    ));
                }
                continue;
            }
            NameserverEndpoint::parse(nameserver)?;
        }
        Ok(())
    }

    /// Validate the DoH retry/timeout policy values.
    fn validate_doh_options(&self) -> Result<(), MudzError> {
        let Some(doh) = &self.doh else {
            return Ok(());
        };

        if doh.timeout == 0 || doh.timeout > MAX_DOH_TIMEOUT_SEC {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                format!(
                    "[doh] timeout must be between 1 and \
                     {MAX_DOH_TIMEOUT_SEC} seconds"
                ),
            ));
        }
        if doh.retries > MAX_DOH_RETRIES {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                format!("[doh] retries must not exceed {MAX_DOH_RETRIES}"),
            ));
        }
        if doh.keepalive_interval > 0
            && doh.keepalive_timeout >= doh.keepalive_interval
        {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                "[doh] keepalive_timeout must be smaller than \
                 keepalive_interval",
            ));
        }
        if doh.idle_timeout == 0 {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                "[doh] idle_timeout must be at least 1 second",
            ));
        }
        Ok(())
    }

    /// Validate that no two groups have overlapping domains.
    fn validate_domain_overlap(&self) -> Result<(), MudzError> {
        let group_list: Vec<(&String, &MudzGroupConfig)> =
            self.groups.iter().collect();
        for i in 0..group_list.len() {
            for j in (i + 1)..group_list.len() {
                let (name_a, group_a) = group_list[i];
                let (name_b, group_b) = group_list[j];
                for da in &group_a.domains {
                    for db in &group_b.domains {
                        if domains_overlap(da, db) {
                            return Err(MudzError::new(
                                ErrorKind::InvalidConfig,
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
                        ErrorKind::InvalidConfig,
                        format!("Duplicate DNS cache group name: {name}"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate that if any nameserver uses DoH or a `tls://hostname`, a
    /// [doh] section with plain IP nameservers is present
    fn validate_bootstrap_nameservers(&self) -> Result<(), MudzError> {
        let nameservers = self
            .fallback
            .nameservers
            .iter()
            .chain(self.groups.values().flat_map(|g| g.nameservers.iter()));
        let needs_bootstrap = nameservers.into_iter().any(|ns| {
            ns.starts_with("https://")
                || matches!(
                    NameserverEndpoint::parse(ns),
                    Ok(NameserverEndpoint {
                        address: NameserverAddress::Hostname(_),
                        ..
                    })
                )
        });

        if !needs_bootstrap {
            return Ok(());
        }

        match &self.doh {
            None => {
                return Err(MudzError::new(
                    ErrorKind::InvalidConfig,
                    "DoH or DoT hostnames are configured but no [doh] section \
                     found. Please add a [doh] section with plain IP \
                     nameservers to resolve them",
                ));
            }
            Some(doh) => {
                if doh.nameservers.is_empty() {
                    return Err(MudzError::new(
                        ErrorKind::InvalidConfig,
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

#[cfg(test)]
#[path = "unit_tests/config.rs"]
mod tests;
