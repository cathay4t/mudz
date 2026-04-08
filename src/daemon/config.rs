// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs, path::Path};

use mudz::DnsError;
use serde::Deserialize;

/// Default config file path
pub const DEFAULT_CONFIG_PATH: &str = "/etc/mudz/mudz.conf";

/// Configuration for the main section
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
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
#[serde(default)]
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

/// Configuration for a named group of nameservers
#[derive(Debug, Deserialize, Clone, Default)]
pub struct NameserverGroup {
    /// Nameservers in this group
    pub nameservers: Vec<String>,
    /// Domains that should be routed to this group
    pub domains: Vec<String>,
}

/// Full mudz configuration
#[derive(Debug, Deserialize, Clone, Default)]
pub struct MudzConfig {
    /// Main settings
    pub main: MainConfig,
    /// Fallback (default upstream) settings
    pub fallback: FallbackConfig,
    /// Named nameserver groups, keyed by group name
    pub nameservers: HashMap<String, NameserverGroup>,
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

        Self::from_str(&content)
    }

    /// Parse configuration from a TOML string
    pub fn from_str(content: &str) -> Result<Self, DnsError> {
        let toml_value: toml::Value = toml::from_str(content).map_err(|e| {
            DnsError::new(
                mudz::ErrorKind::InvalidResponse,
                format!("Failed to parse config: {e}"),
            )
        })?;

        // The config format uses [nameservers.NAME] and [nameserver.NAME]
        // sections. We need to collect these into a single HashMap.
        let main = toml_value
            .get("main")
            .and_then(|v| MainConfig::deserialize(v.clone()).ok())
            .unwrap_or_default();

        let fallback = toml_value
            .get("fallback")
            .and_then(|v| FallbackConfig::deserialize(v.clone()).ok())
            .unwrap_or_default();

        let mut nameservers: HashMap<String, NameserverGroup> = HashMap::new();

        // Collect [nameservers.*] sections
        if let Some(nameservers_section) = toml_value.get("nameservers")
            && let Some(table) = nameservers_section.as_table()
        {
            for (name, value) in table {
                if let Ok(group) = NameserverGroup::deserialize(value.clone()) {
                    nameservers.insert(name.clone(), group);
                }
            }
        }

        // Also collect [nameserver.*] sections (singular form)
        if let Some(nameserver_section) = toml_value.get("nameserver")
            && let Some(table) = nameserver_section.as_table()
        {
            for (name, value) in table {
                if let Ok(group) = NameserverGroup::deserialize(value.clone()) {
                    nameservers.insert(name.clone(), group);
                }
            }
        }

        Ok(Self {
            main,
            fallback,
            nameservers,
        })
    }
}
