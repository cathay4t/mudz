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
    ///
    /// Only a datagram whose transaction ID matches the query and whose QR
    /// bit is set is accepted; anything else (a stale response to an earlier
    /// query on this socket, or an unsolicited packet) is skipped.
    pub fn query(&self, query: &DnsPacket) -> Result<DnsPacket, MudzError> {
        let bytes = query.to_bytes();
        self.socket.send(&bytes).map_err(|e| {
            MudzError::new(
                ErrorKind::Bug,
                format!("Failed to send DNS query: {e}"),
            )
        })?;
        let deadline = std::time::Instant::now() + DEFAULT_TIMEOUT;
        let mut buf = [0u8; DnsPacket::MAX_UDP_EDNS_PACKET_SIZE];
        loop {
            let now = std::time::Instant::now();
            let Some(remaining) = deadline.checked_duration_since(now) else {
                return Err(MudzError::new(
                    ErrorKind::Timeout,
                    "Timed out waiting for DNS response",
                ));
            };
            self.socket.set_read_timeout(Some(remaining)).map_err(|e| {
                MudzError::new(
                    ErrorKind::Bug,
                    format!("Failed to set client read timeout: {e}"),
                )
            })?;
            let n = match self.socket.recv(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(MudzError::new(
                        ErrorKind::Timeout,
                        "Timed out waiting for DNS response",
                    ));
                }
                Err(e) => {
                    return Err(MudzError::new(
                        ErrorKind::Bug,
                        format!("Failed to receive DNS response: {e}"),
                    ));
                }
            };
            // Skip datagrams that are not a valid response to our query: a
            // mismatched transaction ID, a non-response, or garbage that
            // does not parse as DNS.
            let Ok(packet) = DnsPacket::parse(&buf[..n]) else {
                continue;
            };
            if packet.header.id == query.header.id && packet.header.qr {
                return Ok(packet);
            }
            // Mismatched transaction ID or a non-response: keep waiting for
            // the datagram that answers our query.
        }
    }
}
