// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs, path::Path};

use mudz::DnsError;
use serde::Deserialize;

const DEFAULT_MAX_CACHE_SIZE: usize = 4096;
const DEFAULT_UDP_BIND: &str = "127.0.0.1:53";

/// Configuration for the main section
#[derive(Debug, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct MainConfig {
    /// UDP socket bind address
    pub udp_bind: String,
    /// Maximum number of cache entries
    pub max_cache_size: usize,
    #[serde(default)]
    /// Log level (e.g., "info", "debug", "warn", "error")
    pub log_level: String,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            udp_bind: DEFAULT_UDP_BIND.to_string(),
            max_cache_size: DEFAULT_MAX_CACHE_SIZE,
            log_level: "info".to_string(),
        }
    }
}

/// Configuration for the fallback (default upstream) section
#[derive(Debug, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FallbackConfig {
    /// Upstream DNS servers for fallback
    pub nameservers: Vec<String>,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            nameservers: vec!["8.8.8.8".to_string()],
        }
    }
}

/// Configuration for a named group of upstream DNS servers
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct UpstreamGroup {
    /// Nameservers in this group
    pub nameservers: Vec<String>,
    /// Domains that should be routed to this group
    pub domains: Vec<String>,
    /// Disable AAAA queries for this group
    pub disable_ipv6: bool,
}

/// Full mudz configuration
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct MudzConfig {
    /// Main settings
    pub main: MainConfig,
    /// Fallback (default upstream) settings
    pub fallback: FallbackConfig,
    /// Named upstream groups, keyed by group name (from [group.*] sections)
    #[serde(rename = "group")]
    pub groups: HashMap<String, UpstreamGroup>,
}

impl MudzConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, DnsError> {
        let path_ref = path.as_ref();
        let content = fs::read_to_string(path_ref).map_err(|e| {
            DnsError::new(
                mudz::ErrorKind::IoError(e.to_string()),
                format!(
                    "Config file '{}' not found or not readable: {}",
                    path_ref.display(),
                    e
                ),
            )
        })?;
        let config = toml::from_str::<Self>(&content).map_err(|e| {
            DnsError::new(
                mudz::ErrorKind::InvalidConfig,
                format!("Failed to parse config: {e}"),
            )
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> Result<(), DnsError> {
        self.validate_doh_hostname_resolution()?;
        Ok(())
    }

    /// Validate that when all fallback servers are DoH, there's a dedicated
    /// group with plain IP nameservers to resolve DoH server hostnames
    fn validate_doh_hostname_resolution(&self) -> Result<(), DnsError> {
        // Check if all fallback nameservers are DoH
        let all_fallback_are_doh = self
            .fallback
            .nameservers
            .iter()
            .all(|ns| ns.starts_with("https://"));

        if !all_fallback_are_doh {
            return Ok(());
        }

        // Extract hostnames from DoH URLs in fallback
        let doh_hostnames: Vec<String> = self
            .fallback
            .nameservers
            .iter()
            .filter_map(|url| extract_hostname_from_doh_url(url))
            .collect();

        if doh_hostnames.is_empty() {
            return Ok(());
        }

        // Check if there's at least one group with plain IP nameservers that
        // covers all DoH hostnames in its domains
        let has_resolver_group = self.groups.values().any(|group| {
            // Group must have at least one plain IP nameserver
            let has_plain_ip_nameserver = group
                .nameservers
                .iter()
                .any(|ns| !ns.starts_with("https://"));

            if !has_plain_ip_nameserver {
                return false;
            }

            // Group's domains should cover all DoH hostnames (or a superset)
            // We check if each DoH hostname matches any domain in the group
            doh_hostnames.iter().all(|hostname| {
                group
                    .domains
                    .iter()
                    .any(|domain| domain_matches(hostname, domain))
            })
        });

        if !has_resolver_group {
            return Err(DnsError::new(
                mudz::ErrorKind::InvalidConfig,
                format!(
                    "All fallback servers are DoH servers, but no dedicated \
                     group found to resolve DoH server hostnames ({:?}). \
                     Please create a group with plain IP nameservers that \
                     includes the DoH hostnames in its domains",
                    doh_hostnames
                ),
            ));
        }

        Ok(())
    }
}

/// Extract hostname from a DoH URL (e.g., "https://dns.alidns.com/dns-query" -> "dns.alidns.com")
fn extract_hostname_from_doh_url(url: &str) -> Option<String> {
    // Remove "https://" prefix
    let without_scheme = url.strip_prefix("https://")?;
    // Get the hostname part (before the first '/')
    let hostname = without_scheme.split('/').next()?;
    // Remove port if present
    let hostname_without_port = hostname.split(':').next()?;
    if hostname_without_port.is_empty() {
        return None;
    }
    Some(hostname_without_port.to_string())
}

/// Check if a domain pattern matches a hostname
/// Supports exact match and subdomain matching
/// e.g., "dns.alidns.com" matches domain "alidns.com" or "dns.alidns.com"
fn domain_matches(hostname: &str, domain_pattern: &str) -> bool {
    let hostname = hostname.to_lowercase();
    let domain = domain_pattern.to_lowercase();

    // Exact match
    if hostname == domain {
        return true;
    }

    // Subdomain match: hostname ends with .domain
    if hostname.ends_with(&format!(".{domain}")) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_field_in_group_rejected() {
        let config_str = r#"
[fallback]
nameservers = ["8.8.8.8"]

[group.test]
nameservers = ["1.1.1.1"]
domains = ["example.com"]
unknown_field = "bad"
"#;
        let result = toml::from_str::<MudzConfig>(config_str);
        assert!(
            result.is_err(),
            "Expected error for unknown field in [group.*] section"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("unknown field `unknown_field`"),
            "Error should mention unknown_field, got: {err}"
        );
    }

    #[test]
    fn test_valid_group_accepted() {
        let config_str = r#"
[fallback]
nameservers = ["8.8.8.8"]

[group.google]
nameservers = ["8.8.4.4"]
domains = ["google.com"]
disable_ipv6 = true
"#;
        let result = toml::from_str::<MudzConfig>(config_str);
        assert!(result.is_ok(), "Expected valid config, got: {result:?}");
        let config = result.unwrap();
        assert_eq!(config.groups.len(), 1);
        assert!(config.groups.contains_key("google"));
        let google_group = &config.groups["google"];
        assert_eq!(google_group.nameservers, vec!["8.8.4.4"]);
        assert_eq!(google_group.domains, vec!["google.com"]);
        assert!(google_group.disable_ipv6);
    }

    #[test]
    fn test_all_doh_fallback_without_resolver_group_rejected() {
        let config_str = r#"
[fallback]
nameservers = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"]

[group.other]
nameservers = ["8.8.8.8"]
domains = ["other.com"]
"#;
        let config: MudzConfig =
            toml::from_str(config_str).expect("Should parse TOML successfully");
        let result = config.validate();
        assert!(
            result.is_err(),
            "Expected error when all fallbacks are DoH without resolver group"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("All fallback servers are DoH servers"),
            "Error should mention DoH servers issue, got: {err}"
        );
    }

    #[test]
    fn test_all_doh_fallback_with_resolver_group_accepted() {
        let config_str = r#"
[fallback]
nameservers = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"]

[group.doh]
nameservers = ["223.5.5.5", "119.29.29.29"]
domains = [
    "dns.alidns.com",
    "doh.pub",
]
"#;
        let config: MudzConfig =
            toml::from_str(config_str).expect("Should parse TOML successfully");
        let result = config.validate();
        assert!(
            result.is_ok(),
            "Expected valid config with resolver group for DoH hostnames, \
             got: {result:?}"
        );
    }

    #[test]
    fn test_all_doh_fallback_with_subdomain_resolver_accepted() {
        let config_str = r#"
[fallback]
nameservers = ["https://dns.alidns.com/dns-query"]

[group.doh]
nameservers = ["223.5.5.5"]
domains = ["alidns.com"]
"#;
        let config: MudzConfig =
            toml::from_str(config_str).expect("Should parse TOML successfully");
        let result = config.validate();
        assert!(
            result.is_ok(),
            "Expected valid config with subdomain matcher for DoH hostnames, \
             got: {result:?}"
        );
    }

    #[test]
    fn test_mixed_fallback_accepted() {
        let config_str = r#"
[fallback]
nameservers = ["https://dns.alidns.com/dns-query", "8.8.8.8"]
"#;
        let result = toml::from_str::<MudzConfig>(config_str);
        assert!(
            result.is_ok(),
            "Expected valid config with mixed fallback (DoH + plain IP), got: \
             {result:?}"
        );
    }

    #[test]
    fn test_extract_hostname_from_doh_url() {
        assert_eq!(
            extract_hostname_from_doh_url("https://dns.alidns.com/dns-query"),
            Some("dns.alidns.com".to_string())
        );
        assert_eq!(
            extract_hostname_from_doh_url("https://doh.pub/dns-query"),
            Some("doh.pub".to_string())
        );
        assert_eq!(
            extract_hostname_from_doh_url("https://dns.google/dns-query"),
            Some("dns.google".to_string())
        );
        assert_eq!(
            extract_hostname_from_doh_url("https://dns.google:443/dns-query"),
            Some("dns.google".to_string())
        );
        assert_eq!(extract_hostname_from_doh_url("invalid"), None);
    }

    #[test]
    fn test_domain_matches() {
        // Exact match
        assert!(domain_matches("dns.alidns.com", "dns.alidns.com"));
        // Subdomain match
        assert!(domain_matches("dns.alidns.com", "alidns.com"));
        // No match
        assert!(!domain_matches("dns.alidns.com", "other.com"));
        // Case insensitive
        assert!(domain_matches("DNS.ALIDNS.COM", "alidns.com"));
        assert!(domain_matches("dns.alidns.com", "ALIDNS.COM"));
    }
}
