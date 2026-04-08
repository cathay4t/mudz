// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs, path::Path};

use mudz::DnsError;
use serde::Deserialize;

/// Default config file path
pub const DEFAULT_CONFIG_PATH: &str = "/etc/mudz/mudz.conf";

/// Configuration for the main section
#[derive(Debug, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct MainConfig {
    /// UDP socket bind address
    pub udp_bind: String,
    /// Maximum number of cache entries
    pub max_cache_size: usize,
    /// Log level (e.g., "info", "debug", "warn", "error")
    pub log_level: String,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            udp_bind: "127.0.0.1:53".to_string(),
            max_cache_size: 4096,
            log_level: "info".to_string(),
        }
    }
}

/// Configuration for the fallback (default upstream) section
#[derive(Debug, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct FallbackConfig {
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
#[serde(deny_unknown_fields)]
pub struct UpstreamGroup {
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
pub struct MudzConfig {
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
        toml::from_str::<Self>(&content).map_err(|e| {
            DnsError::new(
                mudz::ErrorKind::InvalidConfig,
                format!("Failed to parse config: {e}"),
            )
        })
    }
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
}
