// SPDX-License-Identifier: Apache-2.0

use std::{
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use crate::{DnsPacket, ErrorKind, MudzError};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// A minimal blocking DNS-over-UDP client.
///
/// Binds an ephemeral local socket "connected" to a single server and
/// exchanges raw [`DnsPacket`]s. Intended for tests and simple tooling; the
/// daemon itself uses its own asynchronous transports.
pub struct DnsUdpClient {
    socket: UdpSocket,
}

impl DnsUdpClient {
    /// Create a client talking to `server`, given as `ip` or `ip:port`
    /// (port defaults to 53).
    pub fn new(server: &str) -> Result<Self, MudzError> {
        let addr: SocketAddr = if server.contains(':') {
            server.parse()
        } else {
            format!("{server}:53").parse()
        }
        .map_err(|e| {
            MudzError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid DNS server address '{server}': {e}"),
            )
        })?;
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).map_err(|e| {
            MudzError::new(
                ErrorKind::Bug,
                format!("Failed to bind client UDP socket: {e}"),
            )
        })?;
        socket.connect(addr).map_err(|e| {
            MudzError::new(
                ErrorKind::Bug,
                format!("Failed to connect to DNS server {addr}: {e}"),
            )
        })?;
        socket
            .set_read_timeout(Some(DEFAULT_TIMEOUT))
            .map_err(|e| {
                MudzError::new(
                    ErrorKind::Bug,
                    format!("Failed to set client read timeout: {e}"),
                )
            })?;
        Ok(Self { socket })
    }

    /// Send `query` and wait for a single response, parsed into a
    /// [`DnsPacket`].
    pub fn query(&self, query: &DnsPacket) -> Result<DnsPacket, MudzError> {
        let bytes = query.to_bytes();
        self.socket.send(&bytes).map_err(|e| {
            MudzError::new(
                ErrorKind::Bug,
                format!("Failed to send DNS query: {e}"),
            )
        })?;
        let mut buf = [0u8; DnsPacket::MAX_UDP_EDNS_PACKET_SIZE];
        let n = self.socket.recv(&mut buf).map_err(|e| {
            MudzError::new(
                ErrorKind::Timeout,
                format!("Failed to receive DNS response: {e}"),
            )
        })?;
        DnsPacket::parse(&buf[..n])
    }
}
