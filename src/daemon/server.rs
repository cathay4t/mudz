// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, sync::Arc};

use mudz::{DnsPacket, ErrorKind, MudzError};
use tokio::{net::UdpSocket, sync::mpsc};

use super::{
    config::MudzConfig, listener::DnsUdpListener, resolver::DnsResolver,
};

pub(crate) struct DnsQueryPacket {
    pub(crate) packet: DnsPacket,
    pub(crate) cli_addr: SocketAddr,
}

pub(crate) struct DnsUdpServer {
    socket: Arc<UdpSocket>,
    config: MudzConfig,
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

        Ok(Self { socket, config })
    }

    pub(crate) async fn run(&self) -> Result<(), MudzError> {
        let (sender, receiver) = mpsc::unbounded_channel::<DnsQueryPacket>();

        let socket = self.socket.clone();
        let listener_handle =
            tokio::spawn(
                async move { DnsUdpListener::run(sender, socket).await },
            );

        let config = self.config.clone();
        let socket = self.socket.clone();
        let resolver_handle = tokio::spawn(async move {
            DnsResolver::run(receiver, config, socket).await
        });

        tokio::select! {
            result = listener_handle => {
                match result {
                    Ok(()) => log::info!("DNS listener task exited"),
                    Err(e) => log::error!(
                        "DNS listener task panicked: {e}"
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
            _ = tokio::signal::ctrl_c() => {
                log::info!("Received shutdown signal");
            }
        }

        log::info!("Shutting down");
        Ok(())
    }
}
