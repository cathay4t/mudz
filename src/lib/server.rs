// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, net::SocketAddr, sync::Arc};

use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, oneshot},
    task::JoinSet,
};

use super::{
    config::MudzConfig,
    doh::{self, DohResolvCache},
    host::HostsFile,
    listener::{DnsTcpListener, DnsUdpListener},
    resolver::DnsResolver,
};
use crate::{DnsPacket, ErrorKind, MudzError};

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

/// The embeddable DNS cache server.
///
/// [`MudzServer::new`] validates the configuration, binds the listening
/// sockets and resolves the DoH bootstrap addresses, so a returned server is
/// ready to serve. The server owns its sockets: once the future returned by
/// [`MudzServer::run`] or [`MudzServer::run_with_shutdown`] finishes, the
/// bound addresses are free again.
pub struct MudzServer {
    socket: Arc<UdpSocket>,
    tcp_listener: Option<Arc<TcpListener>>,
    config: MudzConfig,
    hosts: Arc<HostsFile>,
    /// DoH hostname-to-IP mapping resolved before the server starts. `None`
    /// when no DoH nameserver is configured.
    doh_cache: Option<Arc<DohResolvCache>>,
}

impl MudzServer {
    /// Bind the listening sockets and resolve the configured DoH server
    /// hostnames.
    ///
    /// The configuration is validated first, so an invalid one fails before
    /// any socket is bound. A failure to bind the UDP socket is fatal, while
    /// a TCP bind failure is logged and only disables DNS over TCP
    /// (RFC 7766 §6.1).
    pub async fn new(config: MudzConfig) -> Result<Self, MudzError> {
        config.validate()?;

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
        // is fatal: the DoH client uses the pinned mapping instead of the
        // system resolver, so no DoH query could ever succeed without it.
        let hosts = Arc::new(if config.main.load_etc_hosts {
            HostsFile::new()
        } else {
            HostsFile::empty()
        });
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

    /// Serve DNS queries until the process receives `SIGINT` or `SIGTERM`.
    ///
    /// This blocks the caller until the server is told to exit, which is the
    /// behaviour a standalone daemon wants. Embedders that manage shutdown
    /// themselves use [`MudzServer::run_with_shutdown`].
    pub async fn run(self) -> Result<(), MudzError> {
        self.run_with_shutdown(shutdown_signal()).await
    }

    /// Serve DNS queries until `shutdown` resolves or a serving task exits.
    ///
    /// All tasks spawned by the server are aborted and joined before this
    /// returns, so no socket is left bound once it resolves. A task panic is
    /// reported as an [`ErrorKind::Bug`] error.
    pub async fn run_with_shutdown<F>(
        self,
        shutdown: F,
    ) -> Result<(), MudzError>
    where
        F: Future<Output = ()> + Send,
    {
        let (sender, receiver) = mpsc::unbounded_channel::<DnsQueryPacket>();

        let mut tasks = JoinSet::new();
        tasks.spawn(DnsUdpListener::run(
            sender.clone(),
            Arc::clone(&self.socket),
        ));

        // The TCP listener shares the same query channel; replies are
        // routed back over each client's connection via `DnsReplyTarget`.
        if let Some(listener) = self.tcp_listener.as_ref() {
            tasks.spawn(DnsTcpListener::run(
                sender.clone(),
                Arc::clone(listener),
            ));
        }

        tasks.spawn(DnsResolver::run(
            receiver,
            self.config.clone(),
            Arc::clone(&self.socket),
            Arc::clone(&self.hosts),
            self.doh_cache.clone(),
        ));

        let mut result = Ok(());
        tokio::select! {
            _ = shutdown => {
                log::debug!("Shutdown requested by the embedder");
            }
            task = tasks.join_next() => {
                match task {
                    Some(Ok(())) => log::info!("DNS serving task exited"),
                    Some(Err(e)) => {
                        log::error!("DNS serving task failed: {e}");
                        result = Err(MudzError::new(
                            ErrorKind::Bug,
                            format!("DNS serving task failed: {e}"),
                        ));
                    }
                    None => {
                        log::error!("All DNS serving tasks exited");
                    }
                }
            }
        }

        // Abort the remaining tasks and wait until they are dropped, so the
        // listening sockets are released before this function returns.
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}

        log::info!("Shutting down");
        result
    }
}

/// Resolves when the process is asked to terminate: `SIGINT` (Ctrl-C) or, on
/// Unix, `SIGTERM` (the signal `systemctl stop` and `kill` send).
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                log::warn!("Failed to install SIGTERM handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => log::info!("Received SIGINT"),
        _ = terminate => log::info!("Received SIGTERM"),
    }
}
