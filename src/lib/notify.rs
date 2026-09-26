// SPDX-License-Identifier: Apache-2.0

//! Host environment changes reported by the embedder.
//!
//! The server only observes its own sockets, so events it cannot see —
//! such as the default gateway changing after a DHCP lease or a route
//! apply — are reported through a [`MudzNotifier`] handle created from
//! the [`MudzServer`](crate::MudzServer).

use tokio::sync::mpsc;

use crate::{ErrorKind, MudzError};

/// Host environment change an embedder reports to a running
/// [`MudzServer`](crate::MudzServer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MudzServerEvent {
    /// The network path to the configured upstreams changed, for example
    /// because the default gateway was replaced by a route apply or by a
    /// new DHCP lease.
    ///
    /// The server keeps its DNS cache, but clears the upstream
    /// failure/cooldown state and drops the pooled transports, so
    /// upstream groups that were marked dead are retried by the next
    /// query instead of failing fast until their retry backoff elapsed.
    NetworkChange,
}

/// Handle used by the embedder to report host environment changes to a
/// running [`MudzServer`](crate::MudzServer).
///
/// The handle is cheap to clone and can be used from another task than
/// the one running the server. Delivery fails only when the server is
/// not running: either it was not started yet or it already exited.
#[derive(Debug, Clone)]
pub struct MudzNotifier {
    sender: mpsc::UnboundedSender<MudzServerEvent>,
}

impl MudzNotifier {
    pub(crate) fn new(sender: mpsc::UnboundedSender<MudzServerEvent>) -> Self {
        Self { sender }
    }

    /// Report that the host's network environment changed, so the server
    /// clears the upstream failure state and retries the upstream groups
    /// which were marked dead.
    ///
    /// See [`MudzServerEvent::NetworkChange`] for the exact behaviour.
    pub fn notify_network_change(&self) -> Result<(), MudzError> {
        self.sender
            .send(MudzServerEvent::NetworkChange)
            .map_err(|_| {
                MudzError::new(
                    ErrorKind::Bug,
                    "Failed to deliver MudzServerEvent::NetworkChange: DNS \
                     server is not running",
                )
            })
    }
}
