// SPDX-License-Identifier: Apache-2.0

//! DNS over HTTPS (DoH) client implementation per RFC 8484.

use std::{
    collections::{BTreeSet, HashMap},
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use data_encoding::BASE64URL_NOPAD;
use futures_util::{StreamExt, future::join_all, stream::FuturesUnordered};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Uri, body::Bytes, header};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::Client as HttpClient,
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::RwLock,
};
use tower_service::Service;

use super::{
    config::{MudzConfig, MudzDohConfig},
    endpoint::{NameserverAddress, NameserverEndpoint},
    host::HostsFile,
};
use crate::{DnsPacket, DnsResponseCode, DnsType, ErrorKind, MudzError};

/// Overall budget for one DoH lookup, including any retry.
const DEFAULT_TIMEOUT_SEC: Duration = Duration::from_secs(5);
const DEFAULT_RETRIES: usize = 1;
/// The first attempt gets only part of the overall budget so that a request
/// landing on a stale pooled connection fails fast and can be retried on a
/// fresh connection pool within the same budget.
const FIRST_ATTEMPT_TIMEOUT_SEC: Duration = Duration::from_secs(2);
/// Recycle idle connections instead of keeping them until the next suspend
/// or network change turns them into half-open black holes.
const POOL_IDLE_TIMEOUT_SEC: Duration = Duration::from_secs(60);
const HTTP2_KEEP_ALIVE_INTERVAL_SEC: Duration = Duration::from_secs(20);
const HTTP2_KEEP_ALIVE_TIMEOUT_SEC: Duration = Duration::from_secs(5);
/// Per-address TCP connect timeout. A pinned DoH hostname can have several
/// addresses, and a blackholed address must not consume the whole attempt.
const CONNECT_TIMEOUT_PER_IP: Duration = Duration::from_millis(1500);
/// Upper bound on honouring an HTTP `Retry-After` header before retrying.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3);
const BOOTSTRAP_TIMEOUT_SEC: Duration = Duration::from_secs(5);
const DOH_NAMESERVER_PORT: u16 = 53;
const DOH_HTTPS_PORT: u16 = 443;
const DNS_MEDIA_TYPE: &str = "application/dns-message";

/// Per-client DoH retry and connection-liveness policy.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DohOptions {
    /// Overall budget for one lookup, including retries.
    pub(crate) timeout: Duration,
    /// Retries after the first attempt.
    pub(crate) retries: usize,
    /// HTTP/2 keepalive ping interval; zero disables keepalive.
    pub(crate) keepalive_interval: Duration,
    /// How long to wait for a keepalive acknowledgement.
    pub(crate) keepalive_timeout: Duration,
    /// How long an idle pooled connection may stay open.
    pub(crate) idle_timeout: Duration,
}

impl Default for DohOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT_SEC,
            retries: DEFAULT_RETRIES,
            keepalive_interval: HTTP2_KEEP_ALIVE_INTERVAL_SEC,
            keepalive_timeout: HTTP2_KEEP_ALIVE_TIMEOUT_SEC,
            idle_timeout: POOL_IDLE_TIMEOUT_SEC,
        }
    }
}

impl DohOptions {
    pub(crate) fn from_config(config: &MudzDohConfig) -> Self {
        Self {
            timeout: Duration::from_secs(config.timeout),
            retries: config.retries,
            keepalive_interval: Duration::from_secs(config.keepalive_interval),
            keepalive_timeout: Duration::from_secs(config.keepalive_timeout),
            idle_timeout: Duration::from_secs(config.idle_timeout),
        }
    }
}

type DohHttpClient =
    HttpClient<HttpsConnector<PinnedTcpConnector>, Empty<Bytes>>;

/// Builds a DoH HTTP client with connection-pool liveness settings.
///
/// Without an idle timeout and HTTP/2 keep-alive, a pooled connection that
/// becomes half-open (for example after suspend while the network changes)
/// stays in the pool and every request sent over it hangs until the DoH
/// timeout.
fn build_http_client(
    cache: &Arc<DohResolvCache>,
    options: &DohOptions,
) -> DohHttpClient {
    // `hyper-rustls` performs the TLS handshake (including ALPN-based
    // HTTP/2 negotiation) on top of the pinned-IP TCP connector.
    let https_connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .wrap_connector(PinnedTcpConnector::new(Arc::clone(cache)));
    let keepalive_interval = if options.keepalive_interval.is_zero() {
        None
    } else {
        Some(options.keepalive_interval)
    };
    HttpClient::builder(TokioExecutor::new())
        .timer(TokioTimer::new())
        .pool_idle_timeout(options.idle_timeout)
        .http2_keep_alive_interval(keepalive_interval)
        .http2_keep_alive_timeout(options.keepalive_timeout)
        .http2_keep_alive_while_idle(true)
        .build(https_connector)
}

#[derive(Clone)]
pub(crate) struct DohClient {
    url_prefix: String,
    /// Shared connection pool. Clones of `DohClient` share it, and a failed
    /// request replaces it so the retry cannot reuse dead connections.
    http_client: Arc<RwLock<DohHttpClient>>,
    /// Incremented whenever `http_client` is replaced. An attempt that
    /// observed an older pool uses this to avoid overwriting a pool that
    /// another request already replaced.
    client_generation: Arc<AtomicU64>,
    cache: Arc<DohResolvCache>,
    options: DohOptions,
}

impl DohClient {
    pub(crate) fn new(
        server_url: &str,
        cache: Arc<DohResolvCache>,
        options: DohOptions,
    ) -> Result<Self, MudzError> {
        if !server_url.starts_with("https://") {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                "DoH server URL must use https:// scheme",
            ));
        }

        let url_prefix = if server_url.contains('?') {
            format!("{server_url}&dns=")
        } else {
            format!("{server_url}?dns=")
        };

        Ok(Self {
            url_prefix,
            http_client: Arc::new(RwLock::new(build_http_client(
                &cache, &options,
            ))),
            client_generation: Arc::new(AtomicU64::new(0)),
            cache,
            options,
        })
    }

    pub(crate) async fn request(
        &self,
        packet: &DnsPacket,
    ) -> Result<DnsPacket, MudzError> {
        let dns_param = BASE64URL_NOPAD.encode(&packet.to_bytes());

        let url = format!("{}{}", self.url_prefix, dns_param);
        let uri = Uri::try_from(url).map_err(|e| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!("Invalid DoH server URL: {e}"),
            )
        })?;

        let deadline = tokio::time::Instant::now() + self.options.timeout;
        let max_attempts = self.options.retries + 1;
        let mut last_error = None;

        for attempt in 1..=max_attempts {
            let remaining =
                deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let attempt_timeout = if attempt == 1 {
                remaining.min(FIRST_ATTEMPT_TIMEOUT_SEC)
            } else {
                remaining
            };
            let request = Request::builder()
                .method(hyper::Method::GET)
                .uri(uri.clone())
                .header(header::ACCEPT, DNS_MEDIA_TYPE)
                .body(Empty::<Bytes>::new())
                .map_err(|e| {
                    MudzError::new(
                        ErrorKind::Bug,
                        format!("Failed to build DoH request: {e}"),
                    )
                })?;

            let (http_client, generation) = self.snapshot_client().await;
            let result = tokio::time::timeout(
                attempt_timeout,
                send_request(&http_client, request),
            )
            .await;

            match result {
                Ok(Ok(packet)) => return Ok(packet),
                Ok(Err(failure)) => {
                    if !failure.retryable {
                        return Err(failure.error);
                    }
                    log::debug!(
                        "DoH request attempt {attempt}/{max_attempts} failed: \
                         {}; rebuilding connection pool",
                        failure.error
                    );
                    let retry_after = failure.retry_after;
                    last_error = Some(failure.error);
                    if attempt < max_attempts
                        && let Some(delay) = retry_after
                    {
                        let remaining = deadline.saturating_duration_since(
                            tokio::time::Instant::now(),
                        );
                        let delay = delay.min(MAX_RETRY_AFTER);
                        if delay < remaining {
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
                Err(_) => {
                    log::debug!(
                        "DoH request attempt {attempt}/{max_attempts} timed \
                         out after {attempt_timeout:?}; rebuilding connection \
                         pool"
                    );
                    last_error = Some(MudzError::new(
                        ErrorKind::Timeout,
                        "DoH request timed out",
                    ));
                }
            }
            // Never leave the failed pool in place: the next attempt (or the
            // next lookup) must not reuse a half-open connection.
            self.rebuild_client(generation).await;
        }

        Err(last_error.unwrap_or_else(|| {
            MudzError::new(ErrorKind::Timeout, "DoH request timed out")
        }))
    }

    async fn snapshot_client(&self) -> (DohHttpClient, u64) {
        let client = self.http_client.read().await.clone();
        (client, self.client_generation.load(Ordering::SeqCst))
    }

    async fn rebuild_client(&self, observed_generation: u64) {
        let mut client = self.http_client.write().await;
        if self.client_generation.load(Ordering::SeqCst) != observed_generation
        {
            return;
        }
        *client = build_http_client(&self.cache, &self.options);
        self.client_generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Drop and rebuild the shared connection pool. Used after resume from
    /// suspend, when every pooled network connection is likely stale.
    pub(crate) async fn invalidate_pool(&self) {
        let generation = self.client_generation.load(Ordering::SeqCst);
        self.rebuild_client(generation).await;
    }

    #[cfg(test)]
    pub(crate) fn pool_generation(&self) -> u64 {
        self.client_generation.load(Ordering::SeqCst)
    }
}

/// Failure of one DoH attempt plus how the caller must react.
struct DohAttemptError {
    error: MudzError,
    retryable: bool,
    retry_after: Option<Duration>,
}

impl DohAttemptError {
    fn transport(error: MudzError) -> Self {
        Self {
            error,
            retryable: true,
            retry_after: None,
        }
    }

    fn protocol(error: MudzError) -> Self {
        Self {
            error,
            retryable: false,
            retry_after: None,
        }
    }

    /// RFC 8484 §4.2.1 leaves non-2xx handling to normal HTTP semantics:
    /// rate limiting and server errors are retryable, while a server that
    /// cannot represent our queries (406/415) or rejects the request
    /// permanently is not.
    fn http(status: hyper::StatusCode, retry_after: Option<Duration>) -> Self {
        let retryable = status == hyper::StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error();
        let kind = if retryable {
            ErrorKind::Timeout
        } else {
            ErrorKind::InvalidPacket
        };
        Self {
            error: MudzError::new(
                kind,
                format!(
                    "DoH server returned HTTP status {}: {}",
                    status,
                    status.canonical_reason().unwrap_or("Unknown")
                ),
            ),
            retryable,
            retry_after,
        }
    }
}

/// Whether a DoH failure is a transport/service failure that should count
/// towards the upstream's health, rather than a protocol-level error.
pub(crate) fn is_transport_error(error: &MudzError) -> bool {
    matches!(error.kind, ErrorKind::Timeout | ErrorKind::Bug)
}

/// Parse an integer-seconds `Retry-After` header; HTTP-date forms are
/// ignored and treated as no delay.
fn parse_retry_after(headers: &hyper::HeaderMap) -> Option<Duration> {
    headers
        .get(header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// Sends one DoH request over the given connection pool and validates the
/// response.
async fn send_request(
    http_client: &DohHttpClient,
    request: Request<Empty<Bytes>>,
) -> Result<DnsPacket, DohAttemptError> {
    let response = http_client.request(request).await.map_err(|e| {
        DohAttemptError::transport(MudzError::new(
            ErrorKind::Bug,
            format!("Failed to send DoH request: {e}"),
        ))
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(DohAttemptError::http(
            status,
            parse_retry_after(response.headers()),
        ));
    }

    let response_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|_| {
            DohAttemptError::transport(MudzError::new(
                ErrorKind::Bug,
                "Failed to read DoH response body",
            ))
        })?
        .to_bytes();

    if response_bytes.len() > DnsPacket::MAX_DOH_PACKET_SIZE {
        return Err(DohAttemptError::protocol(MudzError::new(
            ErrorKind::InvalidPacket,
            format!(
                "DoH response exceeds maximum(65535) DNS message size: {} \
                 bytes",
                response_bytes.len()
            ),
        )));
    }

    let packet =
        DnsPacket::parse(&response_bytes).map_err(DohAttemptError::protocol)?;

    match packet.header.rcode {
        DnsResponseCode::FormErr => {
            Err(DohAttemptError::protocol(MudzError::new(
                ErrorKind::InvalidPacket,
                "DNS server returned error code: FormErr",
            )))
        }
        DnsResponseCode::ServFail => {
            Err(DohAttemptError::protocol(MudzError::new(
                ErrorKind::InvalidPacket,
                "DNS server returned error code: ServFail",
            )))
        }
        _ => Ok(packet),
    }
}

/// Startup-pinned resolver for upstream hostnames (DoH URLs and
/// `tls://hostname` DoT endpoints).
///
/// The mapping is resolved once before the daemon starts serving (see
/// [`bootstrap_doh_cache`]) and never changes, so no lock or refresh task is
/// involved. `[doh]` bootstrap nameservers exist precisely because the
/// system resolver cannot be used for these hostnames.
pub(crate) struct DohResolvCache {
    store: HashMap<String, Vec<IpAddr>>,
}

impl DohResolvCache {
    pub(crate) fn new(store: HashMap<String, Vec<IpAddr>>) -> Self {
        Self { store }
    }

    /// Pinned addresses of `hostname`, if the hostname was resolved during
    /// bootstrap.
    pub(crate) fn lookup(&self, hostname: &str) -> Option<&[IpAddr]> {
        self.store.get(hostname).map(Vec::as_slice)
    }
}

/// TCP connector that connects only to addresses pinned in
/// [`DohResolvCache`].
///
/// The system resolver is never consulted: DoH hostnames are resolved once at
/// startup through the plain-IP `[doh]` nameservers, and the resulting
/// addresses are used for the lifetime of the process.
#[derive(Clone)]
struct PinnedTcpConnector {
    cache: Arc<DohResolvCache>,
    /// Rotates the first pinned address tried, so a fault with one address
    /// does not prevent the next connection from reaching a healthy one.
    next_address: Arc<AtomicUsize>,
}

impl PinnedTcpConnector {
    fn new(cache: Arc<DohResolvCache>) -> Self {
        Self {
            cache,
            next_address: Arc::new(AtomicUsize::new(0)),
        }
    }
}

fn rotated_address_index(start: usize, offset: usize, len: usize) -> usize {
    debug_assert!(len > 0);
    start.wrapping_add(offset) % len
}

impl Service<Uri> for PinnedTcpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = std::io::Error;
    type Future = Pin<
        Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let Some(host) = uri.host().map(str::to_ascii_lowercase) else {
            return Box::pin(async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "DoH URL has no hostname",
                ))
            });
        };
        let port = uri.port_u16().unwrap_or(DOH_HTTPS_PORT);
        let cache = Arc::clone(&self.cache);
        let next_address = Arc::clone(&self.next_address);

        Box::pin(async move {
            let ips = cache.lookup(&host).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "DoH hostname {host} is not in the pinned DNS registry"
                    ),
                )
            })?;
            if ips.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No pinned address for DoH hostname {host}"),
                ));
            }

            let mut last_error = None;
            let start = next_address.fetch_add(1, Ordering::Relaxed);
            for offset in 0..ips.len() {
                let index = rotated_address_index(start, offset, ips.len());
                let ip = ips[index];
                let addr = SocketAddr::new(ip, port);
                match tokio::time::timeout(
                    CONNECT_TIMEOUT_PER_IP,
                    TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(stream)) => return Ok(TokioIo::new(stream)),
                    Ok(Err(e)) => {
                        log::debug!(
                            "Failed to connect to DoH server {host} at {ip}: \
                             {e}"
                        );
                        last_error = Some(e);
                    }
                    Err(_) => {
                        log::debug!(
                            "Timed out connecting to DoH server {host} at \
                             {ip} after {CONNECT_TIMEOUT_PER_IP:?}"
                        );
                        last_error = Some(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "connect to DoH server {host} at {addr} timed \
                                 out"
                            ),
                        ));
                    }
                }
            }

            Err(last_error.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No pinned address for DoH hostname {host}"),
                )
            }))
        })
    }
}

/// Collect the unique DoH server hostnames from the fallback and named group
/// nameserver lists.
fn doh_hostnames(config: &MudzConfig) -> Result<BTreeSet<String>, MudzError> {
    let mut hostnames = BTreeSet::new();
    let nameservers = config
        .fallback
        .nameservers
        .iter()
        .chain(config.groups.values().flat_map(|g| g.nameservers.iter()));
    for srv in nameservers {
        if !srv.starts_with("https://") {
            continue;
        }
        let hostname =
            super::config::extract_doh_hostname(srv).ok_or_else(|| {
                MudzError::new(
                    ErrorKind::InvalidConfig,
                    format!("Invalid DoH URL: {srv}"),
                )
            })?;
        hostnames.insert(hostname);
    }
    Ok(hostnames)
}

/// Collect the unique `tls://hostname` DoT server hostnames from the fallback
/// and named group nameserver lists.
fn dot_hostnames(config: &MudzConfig) -> BTreeSet<String> {
    let mut hostnames = BTreeSet::new();
    let nameservers = config
        .fallback
        .nameservers
        .iter()
        .chain(config.groups.values().flat_map(|g| g.nameservers.iter()));
    for srv in nameservers {
        if let Ok(endpoint) = NameserverEndpoint::parse(srv)
            && let NameserverAddress::Hostname(hostname) = endpoint.address
        {
            hostnames.insert(hostname);
        }
    }
    hostnames
}

/// Every hostname that must be resolved before the daemon starts serving:
/// DoH URLs and `tls://hostname` DoT endpoints.
fn bootstrap_hostnames(
    config: &MudzConfig,
) -> Result<BTreeSet<String>, MudzError> {
    let mut hostnames = doh_hostnames(config)?;
    hostnames.extend(dot_hostnames(config));
    Ok(hostnames)
}

/// Resolve every configured DoH/DoT hostname and pin it for the process
/// lifetime.
///
/// Called before the daemon starts serving. Failure aborts startup: the DoH
/// client and `tls://hostname` DoT endpoints use [`DohResolvCache`] instead
/// of the system resolver, so without the bootstrap addresses neither could
/// connect. Returns `None` when no hostname nameserver is configured.
pub(crate) async fn bootstrap_doh_cache(
    config: &MudzConfig,
    hosts: &HostsFile,
) -> Result<Option<Arc<DohResolvCache>>, MudzError> {
    let hostnames = bootstrap_hostnames(config)?;
    if hostnames.is_empty() {
        return Ok(None);
    }

    let doh_cfg = config.doh.as_ref().ok_or_else(|| {
        MudzError::new(
            ErrorKind::InvalidConfig,
            "DoH/DoT hostnames are configured but no [doh] section found",
        )
    })?;
    if doh_cfg.nameservers.is_empty() {
        return Err(MudzError::new(
            ErrorKind::InvalidConfig,
            "[doh] section must have at least one nameserver",
        ));
    }
    let nameservers: Vec<SocketAddr> = doh_cfg
        .nameservers
        .iter()
        .map(|ip| SocketAddr::new(*ip, DOH_NAMESERVER_PORT))
        .collect();

    let hostnames: Vec<String> = hostnames.into_iter().collect();
    let results = join_all(hostnames.iter().map(|hostname| {
        resolve_hostname(hostname, &nameservers, doh_cfg.disable_ipv6, hosts)
    }))
    .await;

    let mut store = HashMap::with_capacity(hostnames.len());
    for (hostname, result) in hostnames.into_iter().zip(results) {
        let ips = result?;
        log::info!("Bootstrap hostname {} resolved to {:?}", hostname, ips);
        store.insert(hostname, ips);
    }

    Ok(Some(Arc::new(DohResolvCache::new(store))))
}

/// Resolve one bootstrap hostname (a DoH URL or a `tls://` DoT endpoint)
/// through the plain-IP `[doh]` nameservers.
///
/// `/etc/hosts` entries win over DNS, mirroring the resolver's own query
/// handling. AAAA queries are skipped when `disable_ipv6` is set.
async fn resolve_hostname(
    host_name: &str,
    nameservers: &[SocketAddr],
    disable_ipv6: bool,
    hosts: &HostsFile,
) -> Result<Vec<IpAddr>, MudzError> {
    log::info!("Resolving bootstrap hostname {}", host_name);

    let hosts_ips = hosts.lookup_ips(host_name);
    if !hosts_ips.is_empty() {
        log::info!(
            "Resolved bootstrap hostname {} from /etc/hosts: {:?}",
            host_name,
            hosts_ips
        );
        return Ok(hosts_ips);
    }

    let mut ret = Vec::new();

    let query_packet = DnsPacket::new_query(host_name, DnsType::A)?;
    match send_request_and_wait_first_reply(nameservers, &query_packet).await {
        Ok(ips) => ret.extend_from_slice(&ips),
        Err(e) => {
            log::debug!(
                "Failed to resolve bootstrap hostname {} to A record: {e}",
                host_name
            );
        }
    }

    if disable_ipv6 {
        if ret.is_empty() {
            return Err(MudzError::new(
                ErrorKind::InvalidConfig,
                format!(
                    "Failed to resolve bootstrap hostname {} to A record",
                    host_name
                ),
            ));
        }
        return Ok(ret);
    }

    let query_packet = DnsPacket::new_query(host_name, DnsType::AAAA)?;
    match send_request_and_wait_first_reply(nameservers, &query_packet).await {
        Ok(ips) => ret.extend_from_slice(&ips),
        Err(e) => {
            log::debug!(
                "Failed to resolve bootstrap hostname {} to AAAA record: {e}",
                host_name
            );
        }
    }

    if ret.is_empty() {
        Err(MudzError::new(
            ErrorKind::InvalidConfig,
            format!("Failed to resolve bootstrap hostname {}", host_name),
        ))
    } else {
        Ok(ret)
    }
}

async fn send_request_and_wait_first_reply(
    nameservers: &[SocketAddr],
    query_packet: &DnsPacket,
) -> Result<Vec<IpAddr>, MudzError> {
    let mut sockets = Vec::new();
    let mut ret = Vec::new();

    for nameserver in nameservers {
        let bind_addr = if nameserver.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            MudzError::new(
                ErrorKind::Bug,
                format!("Failed to bind UDP socket: {e}"),
            )
        })?;
        log::debug!("Connecting to UDP nameserver {}", nameserver);
        socket.connect(*nameserver).await.map_err(|e| {
            MudzError::new(
                ErrorKind::InvalidConfig,
                format!("Failed to connect to nameserver {}: {e}", nameserver),
            )
        })?;
        sockets.push(socket);
    }

    // Send queries with a timeout so a stuck UDP socket cannot block
    // startup (or a refresh) indefinitely.
    for socket in &sockets {
        let send_bytes = query_packet.to_bytes();
        match tokio::time::timeout(
            BOOTSTRAP_TIMEOUT_SEC,
            socket.send(&send_bytes),
        )
        .await
        {
            Ok(Ok(_n)) => {}
            Ok(Err(e)) => {
                log::warn!("Failed to send DNS query to nameserver: {e}");
            }
            Err(_) => {
                log::warn!("Timed out sending DNS query to nameserver");
            }
        }
    }

    let mut futures = FuturesUnordered::new();
    for socket in &sockets {
        futures.push(get_udp_dns_reply(socket));
    }
    while let Some(result) = futures.next().await {
        let packet = match result {
            Ok(packet) => packet,
            Err(e) => {
                log::debug!("Failed to get DNS reply: {e}");
                continue;
            }
        };
        log::debug!("Received DNS reply: {}", packet.display_brief());

        if packet.header.id != query_packet.header.id {
            log::debug!(
                "DNS reply TXID mismatch: expected {:#06x}, got {:#06x}",
                query_packet.header.id,
                packet.header.id,
            );
            continue;
        }
        if !packet.header.qr {
            log::debug!("Ignoring non-response DNS packet");
            continue;
        }
        if packet.header.rcode != DnsResponseCode::NoError {
            log::debug!("DNS reply rcode {:?}, ignoring", packet.header.rcode,);
            continue;
        }

        for record in packet
            .answers
            .into_iter()
            .filter(|r| r.kind == DnsType::A || r.kind == DnsType::AAAA)
        {
            if record.kind == DnsType::A
                && record.rdata.len() >= Ipv4Addr::BITS as usize / 8
            {
                ret.push(IpAddr::V4(Ipv4Addr::new(
                    record.rdata[0],
                    record.rdata[1],
                    record.rdata[2],
                    record.rdata[3],
                )));
            } else if record.kind == DnsType::AAAA
                && record.rdata.len() >= Ipv6Addr::BITS as usize / 8
            {
                ret.push(IpAddr::V6(Ipv6Addr::from([
                    record.rdata[0],
                    record.rdata[1],
                    record.rdata[2],
                    record.rdata[3],
                    record.rdata[4],
                    record.rdata[5],
                    record.rdata[6],
                    record.rdata[7],
                    record.rdata[8],
                    record.rdata[9],
                    record.rdata[10],
                    record.rdata[11],
                    record.rdata[12],
                    record.rdata[13],
                    record.rdata[14],
                    record.rdata[15],
                ])));
            }
        }
        if !ret.is_empty() {
            break;
        }
    }

    Ok(ret)
}

async fn get_udp_dns_reply(socket: &UdpSocket) -> Result<DnsPacket, MudzError> {
    let mut buf = [0u8; DnsPacket::MAX_UDP_EDNS_PACKET_SIZE];
    match tokio::time::timeout(BOOTSTRAP_TIMEOUT_SEC, socket.recv(&mut buf))
        .await
    {
        Ok(Ok(len)) => {
            let packet = DnsPacket::parse(&buf[..len])?;
            Ok(packet)
        }
        Ok(Err(e)) => Err(MudzError::new(
            ErrorKind::Bug,
            format!("Error receiving DNS response: {e}"),
        )),
        Err(_) => Err(MudzError::new(
            ErrorKind::Timeout,
            "Timed out waiting for DNS response",
        )),
    }
}

#[cfg(test)]
#[path = "unit_tests/doh.rs"]
mod tests;
