// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, sync::Arc};

use mudz::{DnsPacket, ErrorKind, MudzError};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, oneshot},
};

use super::{
    config::MudzConfig,
    doh::{self, DohResolvCache},
    host::HostsFile,
    listener::{DnsTcpListener, DnsUdpListener},
    resolver::DnsResolver,
};

/// Where to deliver a resolved reply: back over the UDP socket that carried
/// the query, or over the client's TCP connection (RFC 1035 §4.2.2). TCP
/// replies are handed to the connection task through a oneshot, which frames
/// them with the 2-byte length prefix.
pub(crate) enum DnsReplyTarget {
    Udp(SocketAddr),
    Tcp {
        reply: oneshot::Sender<Vec<u8>>,
        peer: SocketAddr,
    },
}

impl DnsReplyTarget {
    pub(crate) fn is_tcp(&self) -> bool {
        matches!(self, DnsReplyTarget::Tcp { .. })
    }

    /// Deliver `buf` to the client. UDP replies are sent as one datagram;
    /// TCP replies are sent into the connection task's oneshot.
    pub(crate) async fn send(self, socket: &UdpSocket, buf: Vec<u8>) {
        match self {
            DnsReplyTarget::Udp(addr) => {
                if let Err(e) = socket.send_to(&buf, addr).await {
                    log::warn!("Failed to send DNS reply to {}: {e}", addr);
                }
            }
            DnsReplyTarget::Tcp { reply, peer } => {
                if reply.send(buf).is_err() {
                    log::debug!("TCP client {peer} closed before reply");
                }
            }
        }
    }
}

pub(crate) struct DnsQueryPacket {
    pub(crate) packet: DnsPacket,
    pub(crate) reply: DnsReplyTarget,
}

pub(crate) struct DnsUdpServer {
    socket: Arc<UdpSocket>,
    tcp_listener: Option<Arc<TcpListener>>,
    config: MudzConfig,
    hosts: Arc<HostsFile>,
    /// DoH hostname-to-IP mapping resolved before the server starts. `None`
    /// when no DoH nameserver is configured.
    doh_cache: Option<Arc<DohResolvCache>>,
}

impl DnsUdpServer {
    pub(crate) async fn new(config: MudzConfig) -> Result<Self, MudzError> {
        for (name, group) in &config.groups {
            log::info!(
                "Domain group '{}': {:?} -> {:?}",
                name,
                group.domains,
                group.nameservers
            );
        }

        // DoH server hostnames are resolved once here, through the plain-IP
        // [doh] nameservers, and pinned for the process lifetime. A failure
        // is fatal: reqwest uses the pinned mapping instead of the system
        // resolver, so no DoH query could ever succeed without it.
        let hosts = Arc::new(HostsFile::new());
        let doh_cache = doh::bootstrap_doh_cache(&config, &hosts).await?;

        let socket_addr =
            config.main.udp_bind.parse::<SocketAddr>().map_err(|e| {
                MudzError::new(
                    ErrorKind::InvalidConfig,
                    format!("Invalid UDP bind address: {e}"),
                )
            })?;

        let socket =
            Arc::new(UdpSocket::bind(&socket_addr).await.map_err(|e| {
                MudzError::new(
                    ErrorKind::InvalidConfig,
                    format!("Failed to bind UDP socket: {e}"),
                )
            })?);
        log::info!("DNS UDP server listening on {}", socket_addr);

        // DNS over TCP (RFC 7766): same address as UDP by default. A TCP
        // bind failure is not fatal — the daemon keeps serving UDP — but is
        // logged loudly because clients with truncated UDP replies (such as
        // bind-utils `host`) will fail their TCP fallback.
        let tcp_bind = config
            .main
            .tcp_bind
            .as_deref()
            .unwrap_or(&config.main.udp_bind);
        let tcp_listener = match TcpListener::bind(&tcp_bind).await {
            Ok(listener) => {
                log::info!("DNS TCP server listening on {}", tcp_bind);
                Some(Arc::new(listener))
            }
            Err(e) => {
                log::warn!(
                    "Failed to bind TCP socket {tcp_bind}: {e}; continuing \
                     UDP-only"
                );
                None
            }
        };

        Ok(Self {
            socket,
            tcp_listener,
            config,
            hosts,
            doh_cache,
        })
    }

    pub(crate) async fn run(&self) -> Result<(), MudzError> {
        self.run_with_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    }

    /// Run the server until a spawned task exits or `shutdown` resolves.
    /// [`Self::run`] wires `shutdown` to Ctrl-C; tests supply their own signal
    /// so they can stop the server deterministically.
    pub(crate) async fn run_with_shutdown<F>(
        &self,
        shutdown: F,
    ) -> Result<(), MudzError>
    where
        F: std::future::Future<Output = ()>,
    {
        let (sender, receiver) = mpsc::unbounded_channel::<DnsQueryPacket>();

        let socket = self.socket.clone();
        let udp_sender = sender.clone();
        let udp_listener_handle = tokio::spawn(async move {
            DnsUdpListener::run(udp_sender, socket).await
        });

        // The TCP listener shares the same query channel; replies are
        // routed back over each client's connection via `DnsReplyTarget`.
        let tcp_listener_handle = self.tcp_listener.as_ref().map(|listener| {
            let sender = sender.clone();
            let listener = Arc::clone(listener);
            tokio::spawn(
                async move { DnsTcpListener::run(sender, listener).await },
            )
        });

        let config = self.config.clone();
        let socket = self.socket.clone();
        let hosts = Arc::clone(&self.hosts);
        let doh_cache = self.doh_cache.clone();
        let resolver_handle = tokio::spawn(async move {
            DnsResolver::run(receiver, config, socket, hosts, doh_cache).await
        });

        tokio::select! {
            result = udp_listener_handle => {
                match result {
                    Ok(()) => log::info!("DNS listener task exited"),
                    Err(e) => log::error!(
                        "DNS listener task panicked: {e}"
                    ),
                }
            }
            result = async {
                match tcp_listener_handle {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Ok(()) => log::info!("DNS TCP listener task exited"),
                    Err(e) => log::error!(
                        "DNS TCP listener task panicked: {e}"
                    ),
                }
            }
            result = resolver_handle => {
                match result {
                    Ok(()) => log::info!("DNS resolver task exited"),
                    Err(e) => log::error!(
                        "DNS resolver task panicked: {e}"
                    ),
                }
            }
            _ = shutdown => {
                log::info!("Received shutdown signal");
            }
        }

        log::info!("Shutting down");
        Ok(())
    }
}
