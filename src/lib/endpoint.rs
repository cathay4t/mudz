// SPDX-License-Identifier: Apache-2.0

//! Parsing of configured upstream nameserver addresses.
//!
//! A nameserver is a DoH URL (`https://...`), an IP literal (`10.0.0.1`,
//! `2001:db8::1`), an `ip:port` pair, a bracketed IPv6 form
//! (`[2001:db8::1]`, `[2001:db8::1]:853`), or an endpoint prefixed with a
//! transport scheme:
//!
//! * `tls://` - DNS over TLS only, no fallback. An IP literal or a hostname is
//!   accepted; a hostname is verified through SNI and its DNS-name certificate
//!   SANs.
//! * `tcp://` - DNS over TCP only, no fallback. IP literals only.
//! * `udp://` - DNS over UDP only, no fallback. IP literals only.
//!
//! A bare IP address has no forced transport and tries DoT, then DNS over
//! TCP, then UDP. Every transport that connects to a nameserver must agree on
//! the address mapping: when the configuration pins a port, all attempts use
//! it, and without a port each transport uses its protocol default. This
//! module is the single source of truth for that mapping.

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr as _,
};

use rustls::pki_types::DnsName;

use crate::{ErrorKind, MudzError};

/// Transport selection encoded in a nameserver's `scheme://` prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameserverScheme {
    /// No scheme: try DoT, then DNS over TCP, then UDP.
    Auto,
    /// `tls://`: DNS over TLS only.
    Tls,
    /// `tcp://`: DNS over TCP only.
    Tcp,
    /// `udp://`: DNS over UDP only.
    Udp,
}

/// The address part of a configured nameserver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NameserverAddress {
    /// An IP literal, connectable without resolution.
    Ip(IpAddr),
    /// A DNS hostname. Resolved through the `[doh]` bootstrap nameservers at
    /// startup; only DoT can verify the server identity for a hostname.
    Hostname(String),
}

impl NameserverAddress {
    /// The IP literal, if this endpoint does not need resolution.
    pub(crate) fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Hostname(_) => None,
        }
    }
}

/// An IP-literal or hostname nameserver parsed from the configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NameserverEndpoint {
    pub(crate) scheme: NameserverScheme,
    pub(crate) address: NameserverAddress,
    /// Port pinned in the configuration; `None` means the protocol default.
    pub(crate) port: Option<u16>,
}

impl NameserverEndpoint {
    /// Parse `nameserver` into its transport scheme and endpoint.
    ///
    /// A hostname is accepted only for `tls://`: plain TCP and UDP would
    /// need a resolution step but have no way to verify the server identity,
    /// so they remain IP-only. Hostnames are resolved through the `[doh]`
    /// bootstrap nameservers (see [`super::doh::bootstrap_doh_cache`]).
    pub(crate) fn parse(nameserver: &str) -> Result<Self, MudzError> {
        let srv = nameserver.trim();
        let (scheme, rest) = if let Some(rest) = srv.strip_prefix("tls://") {
            (NameserverScheme::Tls, rest)
        } else if let Some(rest) = srv.strip_prefix("tcp://") {
            (NameserverScheme::Tcp, rest)
        } else if let Some(rest) = srv.strip_prefix("udp://") {
            (NameserverScheme::Udp, rest)
        } else {
            (NameserverScheme::Auto, srv)
        };

        // `ip:port` / `[ipv6]:port`.
        if let Ok(addr) = SocketAddr::from_str(rest) {
            return Ok(Self {
                scheme,
                address: NameserverAddress::Ip(addr.ip()),
                port: Some(addr.port()),
            });
        }

        // A bare IP literal, optionally wrapped in brackets (the bracketed
        // form is required by `SocketAddr` as soon as a port is appended).
        let bare = rest
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(rest);
        if let Ok(ip) = IpAddr::from_str(bare) {
            return Ok(Self {
                scheme,
                address: NameserverAddress::Ip(ip),
                port: None,
            });
        }

        if scheme == NameserverScheme::Tls {
            return Self::parse_tls_hostname(nameserver, rest);
        }

        Err(MudzError::new(
            ErrorKind::InvalidConfig,
            format!(
                "Invalid nameserver address '{nameserver}': expected an IP \
                 literal with an optional 'tls://', 'tcp://' or 'udp://' \
                 prefix, a 'tls://hostname' endpoint, or an https:// URL"
            ),
        ))
    }

    /// Parse the hostname (and optional port) of a `tls://hostname` entry.
    fn parse_tls_hostname(
        nameserver: &str,
        rest: &str,
    ) -> Result<Self, MudzError> {
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port_text)) => {
                let port = port_text.parse::<u16>().map_err(|_| {
                    MudzError::new(
                        ErrorKind::InvalidConfig,
                        format!(
                            "Invalid port in DoT nameserver '{nameserver}': \
                             '{port_text}'"
                        ),
                    )
                })?;
                (host, Some(port))
            }
            None => (rest, None),
        };
        let host = host.to_ascii_lowercase();
        // Reuse rustls' DNS-name rules so an unverifiable name is rejected
        // at configuration time instead of failing every connect attempt.
        if DnsName::try_from(host.clone()).is_err() {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                format!("Invalid DoT hostname in nameserver '{nameserver}'"),
            ));
        }
        Ok(Self {
            scheme: NameserverScheme::Tls,
            address: NameserverAddress::Hostname(host),
            port,
        })
    }

    /// Port to connect to, using the configured port when present and
    /// `default_port` otherwise.
    pub(crate) fn port_or(&self, default_port: u16) -> u16 {
        self.port.unwrap_or(default_port)
    }
}

#[cfg(test)]
#[path = "unit_tests/endpoint.rs"]
mod tests;
