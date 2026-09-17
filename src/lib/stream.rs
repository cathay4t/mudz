// SPDX-License-Identifier: Apache-2.0

//! Framed DNS-over-stream upstream transports (RFC 7766 and RFC 7858).
//!
//! Plain DNS over TCP and DNS over TLS share the same 2-byte big-endian
//! length framing and the same query pipelining model.
//! [`DnsStreamTransport`] implements that core once and is instantiated for
//! [`TcpStream`] (`DnsTcpTransport`) and for the TLS stream
//! (`DnsDotTransport`).
//!
//! The connect (plus, for TLS, the handshake) is both the probe and the
//! working connection: queries are pipelined over the shared stream, each
//! carrying a distinct rewritten transaction ID, and a background receive
//! loop demultiplexes the length-prefixed replies by ID. The shape mirrors
//! [`super::group::DnsUdpTransport`] so the group's fan-out dispatch, upstream
//! health tracking, and suspend/resume handling treat every transport alike.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf,
        WriteHalf, split,
    },
    net::TcpStream,
    sync::{Mutex as AsyncMutex, oneshot},
};
use tokio_rustls::TlsConnector;

use super::retry::UpstreamState;
use crate::{DnsClass, DnsPacket, DnsType, ErrorKind, MudzError};

/// The concrete TLS stream that carries one RFC 7858 connection.
type DotStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Plain DNS over TCP (RFC 7766) transport.
pub(crate) type DnsTcpTransport = DnsStreamTransport<TcpStream>;
/// DNS over TLS (RFC 7858) transport.
pub(crate) type DnsDotTransport = DnsStreamTransport<DotStream>;

/// Standard DNS over TLS port (RFC 7858), used when the configuration does
/// not pin a port.
pub(crate) const DOT_PORT: u16 = 853;
/// Bounded TCP connect for a stream transport. Kept short so an IP that does
/// not offer the transport (connect refused, or silently dropped) falls back
/// promptly instead of eating the group's per-request budget.
const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
/// Bounded TLS handshake after a successful connect. A real DoT server
/// completes well within this; the budget only bounds a handshake that is
/// going to fail (e.g. a port that speaks non-TLS plaintext).
const DOT_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1500);
/// Bounded framed write. A peer that stops reading can fill the socket
/// buffer and block `write_all` indefinitely; the group sends to every
/// upstream in turn, so an unbounded write would delay its peers until the
/// request guard fires.
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_millis(2000);
/// Upper bound on a single framed DNS message: the 2-byte length prefix
/// cannot express more than this.
const STREAM_MAX_MESSAGE_SIZE: usize = u16::MAX as usize;

/// Key for matching an upstream response to its waiter: the question's
/// (domain, type, class) plus the DNS transaction ID (see the UDP transport).
type PendingKey = (String, DnsType, DnsClass, u16);
type PendingMap = HashMap<PendingKey, Vec<oneshot::Sender<DnsPacket>>>;

/// Marks the transport broken when a framed write does not complete. A
/// failed or cancelled `write_all`/`flush` can leave a partial frame on the
/// stream, so every later query would be decoded at the wrong offset.
struct PoisonWriteOnDrop<'a> {
    state: &'a UpstreamState,
    armed: bool,
}

impl Drop for PoisonWriteOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.state.mark_broken();
        }
    }
}

/// A per-upstream-server framed stream transport that fans out responses to
/// the correct caller via a background receive loop and oneshot channels,
/// mirroring `DnsUdpTransport` but over a persistent RFC 7766/7858 stream.
pub(crate) struct DnsStreamTransport<S> {
    /// Remote endpoint (used only for error messages).
    addr: SocketAddr,
    /// Protocol name for log and error messages ("TCP" or "TLS").
    protocol: &'static str,
    /// Shared write half of the stream, guarded by an async mutex so
    /// concurrent `send_query` calls serialize their framing writes.
    writer: Arc<AsyncMutex<WriteHalf<S>>>,
    /// Waiters keyed by the rewritten wire transaction ID.
    pending: Arc<Mutex<PendingMap>>,
    /// Fail-cooldown-retry state shared with `recv_loop`, and consulted by
    /// the group's fan-out to gate, record, and evict this upstream.
    pub(crate) state: Arc<UpstreamState>,
    /// Handle to the background `recv_loop` task; its liveness is the
    /// transport's liveness (recv_loop only exits on a fatal read error or a
    /// panic — in both cases the transport can dispatch nothing more).
    recv_task: tokio::task::JoinHandle<()>,
}

impl<S> Drop for DnsStreamTransport<S> {
    fn drop(&mut self) {
        // The receive loop owns the read half and the pending map. Dropping a
        // `JoinHandle` does not cancel the task, so without this abort an
        // evicted transport would keep its connection, socket and waiters
        // alive until the peer closes.
        self.recv_task.abort();
    }
}

impl<S> DnsStreamTransport<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Split `stream` and spawn the receive loop that owns the read half.
    fn from_stream(
        addr: SocketAddr,
        nameserver: &str,
        group_name: &str,
        protocol: &'static str,
        stream: S,
    ) -> Self {
        let (read_half, write_half) = split(stream);
        let pending: Arc<Mutex<PendingMap>> =
            Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(UpstreamState::new(nameserver, group_name));

        let recv_task = tokio::spawn(Self::recv_loop(
            read_half,
            Arc::clone(&pending),
            Arc::clone(&state),
            protocol,
        ));

        Self {
            addr,
            protocol,
            writer: Arc::new(AsyncMutex::new(write_half)),
            pending,
            state,
            recv_task,
        }
    }

    /// Whether this transport can still dispatch upstream responses. True
    /// when the receive loop marked the transport broken on a fatal read
    /// error, or when the receive loop task has finished for any other reason
    /// (e.g. a panic) — `recv_loop` only exits on those two events, so
    /// `JoinHandle::is_finished` is a reliable liveness signal.
    pub(crate) fn is_broken(&self) -> bool {
        self.state.is_broken() || self.recv_task.is_finished()
    }

    /// Write one framed DNS query and register a waiter keyed by a fresh
    /// random transaction ID, exactly like `DnsUdpTransport::send_query` so
    /// concurrent same-question/ID queries are never cross-delivered.
    pub(crate) async fn send_query(
        &self,
        bytes: &[u8],
        key: &PendingKey,
    ) -> Result<oneshot::Receiver<DnsPacket>, MudzError> {
        let mut buf = bytes.to_vec();
        if buf.len() < 2 {
            return Err(MudzError::new(
                ErrorKind::Bug,
                "DNS query is shorter than a header; cannot rewrite the \
                 transaction ID",
            ));
        }
        if buf.len() > STREAM_MAX_MESSAGE_SIZE {
            return Err(MudzError::new(
                ErrorKind::Bug,
                format!(
                    "DNS query of {} bytes exceeds the stream frame limit",
                    buf.len()
                ),
            ));
        }
        let mut wire_key: PendingKey = (key.0.clone(), key.1, key.2, 0);
        let mut rx = None;
        while rx.is_none() {
            wire_key.3 = rand::random::<u16>();
            let mut pending =
                self.pending.lock().expect("pending map lock poisoned");
            if pending.contains_key(&wire_key) {
                continue;
            }
            let (tx, receiver) = oneshot::channel();
            pending.entry(wire_key.clone()).or_default().push(tx);
            rx = Some(receiver);
        }
        buf[0..2].copy_from_slice(&wire_key.3.to_be_bytes());

        // Framing: 2-byte big-endian length prefix + DNS message.
        let mut frame = Vec::with_capacity(2 + buf.len());
        frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        frame.extend_from_slice(&buf);

        let mut writer = self.writer.lock().await;
        // A failed or cancelled write can leave a partial frame on the
        // stream; every later query would then be decoded at the wrong
        // offset. Mark the transport broken unless the whole frame was
        // written and flushed.
        let mut poison = PoisonWriteOnDrop {
            state: &self.state,
            armed: true,
        };
        let write_result = tokio::time::timeout(STREAM_WRITE_TIMEOUT, async {
            writer.write_all(&frame).await?;
            writer.flush().await
        })
        .await;
        match write_result {
            Ok(Ok(())) => {
                poison.armed = false;
                Ok(rx.expect("wire key registered"))
            }
            Ok(Err(e)) => {
                self.forget(&wire_key);
                Err(MudzError::new(
                    ErrorKind::Bug,
                    format!(
                        "Failed to send DNS query over {} to {}: {e}",
                        self.protocol, self.addr
                    ),
                ))
            }
            Err(_elapsed) => {
                self.forget(&wire_key);
                Err(MudzError::new(
                    ErrorKind::Timeout,
                    format!(
                        "Sending DNS query over {} to {} timed out",
                        self.protocol, self.addr
                    ),
                ))
            }
        }
    }

    /// Drop the waiter registered under `key`.
    fn forget(&self, key: &PendingKey) {
        self.pending
            .lock()
            .expect("pending map lock poisoned")
            .remove(key);
    }

    /// Background loop that reads framed replies and dispatches each to the
    /// waiter(s) registered under its transaction ID. A periodic tick prunes
    /// waiters whose response never arrived (their `rx` was dropped, i.e. the
    /// caller timed out) so the pending map does not grow without bound while
    /// the stream stays open; any read error tears down the stream and marks
    /// the transport broken, matching `DnsUdpTransport::recv_loop`.
    async fn recv_loop(
        mut read_half: ReadHalf<S>,
        pending: Arc<Mutex<PendingMap>>,
        state: Arc<UpstreamState>,
        protocol: &'static str,
    ) {
        let mut cleanup = tokio::time::interval(Duration::from_secs(30));
        // Skip the immediate first tick so pruning only runs after an
        // interval has actually elapsed (same as the resolver's GC intervals).
        cleanup.tick().await;

        loop {
            tokio::select! {
                result = read_frame(&mut read_half) => {
                    match result {
                        Ok(message) => {
                            let Ok(packet) = DnsPacket::parse(&message) else {
                                log::debug!(
                                    "Failed to parse upstream {} response; \
                                     dropping frame",
                                    protocol
                                );
                                continue;
                            };
                            let Some(question) = packet.first_question() else {
                                continue;
                            };
                            let key: PendingKey = (
                                question.domain.to_string(),
                                question.kind,
                                question.class,
                                packet.header.id,
                            );
                            let senders = pending
                                .lock()
                                .expect("pending map lock poisoned")
                                .remove(&key);
                            if let Some(senders) = senders {
                                for sender in senders {
                                    let _ = sender.send(packet.clone());
                                }
                            }
                        }
                        Err(e) => {
                            log::debug!(
                                "{} receive loop for upstream '{}' in group \
                                 '{}' exiting: {e}",
                                protocol,
                                state.name(),
                                state.group()
                            );
                            state.mark_broken();
                            // Dropping the senders wakes every in-flight
                            // waiter immediately instead of letting each one
                            // wait for the full per-query timeout on a
                            // stream that can never answer again.
                            pending
                                .lock()
                                .expect("pending map lock poisoned")
                                .clear();
                            break;
                        }
                    }
                }
                _ = cleanup.tick() => {
                    pending
                        .lock()
                        .expect("pending map lock poisoned")
                        .retain(|_, senders| {
                            senders.retain(|s| !s.is_closed());
                            !senders.is_empty()
                        });
                }
            }
        }
    }
}

impl DnsStreamTransport<TcpStream> {
    /// Connect to `addr` and establish a plain DNS-over-TCP (RFC 7766)
    /// transport. `nameserver` is the configured string used for logging and
    /// for the upstream health-state identity.
    pub(crate) async fn new_tcp(
        nameserver: &str,
        addr: SocketAddr,
        group_name: &str,
    ) -> Result<Self, MudzError> {
        let tcp = timeout_connect(addr).await?;
        tcp.set_nodelay(true).ok();
        Ok(Self::from_stream(addr, nameserver, group_name, "TCP", tcp))
    }
}

impl DnsStreamTransport<DotStream> {
    /// Connect to `addr` and establish a DNS-over-TLS (RFC 7858) transport.
    /// The TLS handshake is both the DoT probe and the working connection; a
    /// refused connect, timeout, handshake failure, or certificate
    /// verification error is returned so the caller can decide whether to
    /// fall back.
    ///
    /// `verify_name` is the name the certificate is verified against: the
    /// configured hostname for `tls://hostname` (also sent as SNI), or the
    /// IP literal for an IP endpoint.
    pub(crate) async fn new_dot(
        nameserver: &str,
        addr: SocketAddr,
        verify_name: &str,
        group_name: &str,
    ) -> Result<Self, MudzError> {
        // `ServerName` accepts both a DNS name and an IP literal and carries
        // no borrowed data, so it is `'static`-compatible as
        // `TlsConnector::connect` requires.
        let server_name = ServerName::try_from(verify_name.to_string())
            .map_err(|_| {
                MudzError::new(
                    ErrorKind::InvalidConfig,
                    format!("Invalid DoT server name '{verify_name}'"),
                )
            })?;
        let tcp = timeout_connect(addr).await?;
        tcp.set_nodelay(true).ok();
        let tls_stream = timeout_handshake(server_name, tcp).await?;
        Ok(Self::from_stream(
            addr, nameserver, group_name, "TLS", tls_stream,
        ))
    }
}

/// Read one length-prefixed DNS message (RFC 7766 section 8, RFC 7858
/// section 3.3) from an `AsyncRead`. Any read error (including a clean EOF)
/// means the stream is over and is surfaced to the caller to tear the
/// transport down. Generic so the framing decode can be exercised against an
/// in-memory reader in tests.
async fn read_frame<R>(read_half: &mut R) -> Result<Vec<u8>, std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_prefix = [0u8; 2];
    read_half.read_exact(&mut len_prefix).await?;
    let len = u16::from_be_bytes(len_prefix) as usize;
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "zero-length DNS stream frame",
        ));
    }
    let mut message = vec![0u8; len];
    read_half.read_exact(&mut message).await?;
    Ok(message)
}

/// Bounded TCP connect shared by the plain-TCP and DoT transports.
async fn timeout_connect(addr: SocketAddr) -> Result<TcpStream, MudzError> {
    match tokio::time::timeout(STREAM_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(MudzError::new(
            ErrorKind::Bug,
            format!("TCP connect to {addr} failed: {e}"),
        )),
        Err(_elapsed) => Err(MudzError::new(
            ErrorKind::Timeout,
            format!("TCP connect to {addr} timed out"),
        )),
    }
}

/// Bounded TLS handshake with webpki bundled roots and the server name pinned
/// to the IP address (RFC 7858 clients verify the server cert as usual).
async fn timeout_handshake(
    server_name: ServerName<'static>,
    tcp: TcpStream,
) -> Result<DotStream, MudzError> {
    let connector = TlsConnector::from(dot_client_config());
    match tokio::time::timeout(
        DOT_HANDSHAKE_TIMEOUT,
        connector.connect(server_name, tcp),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(MudzError::new(
            ErrorKind::Bug,
            format!("DoT TLS handshake failed: {e}"),
        )),
        Err(_elapsed) => Err(MudzError::new(
            ErrorKind::Timeout,
            "DoT TLS handshake timed out",
        )),
    }
}

/// Build the rustls client config.
///
/// Same trust policy as the DoH client: webpki bundled roots (no OS trust
/// store, so the daemon works in minimal environments). The crypto provider
/// is the crate's default (ring, per the `rustls` features in Cargo.toml),
/// which the plain `ClientConfig::builder()` installs/resolves. No client
/// authentication — RFC 7858 does not require it for a public DNS query.
fn dot_client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(Arc::new(roots))
            .with_no_client_auth(),
    )
}

#[cfg(test)]
#[path = "unit_tests/stream.rs"]
mod tests;
