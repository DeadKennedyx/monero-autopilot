//! All remote node HTTP traffic goes through this explicit SOCKS5h transport.
use crate::{policy::RoutePlan, Denial, Result};
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

pub const MAX_RESPONSE: usize = 32 * 1024 * 1024;
pub const HEALTH_RESPONSE: usize = 64 * 1024;

/// No OS DNS resolver is reachable through this client's connector. Only the
/// already-validated numeric proxy address can be resolved locally.
#[derive(Default)]
struct NoSystemDns {
    denied: AtomicUsize,
}
impl reqwest::dns::Resolve for NoSystemDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let parsed = name.as_str().parse::<IpAddr>();
        if parsed.is_err() {
            self.denied.fetch_add(1, Ordering::Relaxed);
        }
        Box::pin(async move {
            match parsed {
                Ok(ip) => {
                    Ok(Box::new(std::iter::once(SocketAddr::new(ip, 0))) as reqwest::dns::Addrs)
                }
                Err(_) => Err(Box::new(std::io::Error::other(
                    "Local DNS is prohibited by Privacy Guard",
                ))
                    as Box<dyn std::error::Error + Send + Sync>),
            }
        })
    }
}
fn tls_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig> {
    // Static roots avoid Windows/platform AIA or revocation network fetches
    // escaping the selected SOCKS route. No custom certificate verifier.
    rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Denial::InvalidConfiguration)
    .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}
/// Closed set of daemon paths. Reject absolute URLs, redirects and arbitrary RPC.
#[derive(Clone, Copy, Debug)]
pub struct DaemonPath(&'static str);
impl DaemonPath {
    pub fn parse(value: &str) -> Result<Self> {
        const ALLOWED: &[&str] = &[
            "/json_rpc",
            "/get_height",
            "/getheight",
            "/get_info",
            "/getblocks.bin",
            "/get_blocks.bin",
            "/gethashes.bin",
            "/get_hashes.bin",
            "/get_o_indexes.bin",
            "/get_outs.bin",
            "/get_outs",
            "/get_transactions",
            "/gettransactions",
            "/get_output_distribution.bin",
            "/get_transaction_pool_hashes.bin",
            "/get_transaction_pool_hashes",
            "/get_transaction_pool",
            "/get_txpool_backlog",
            "/is_key_image_spent",
            "/sendrawtransaction",
            "/send_raw_transaction",
            "/getblocks_by_height.bin",
            "/get_blocks_by_height.bin",
        ];
        ALLOWED
            .iter()
            .find(|&&p| p == value)
            .copied()
            .map(Self)
            .ok_or(Denial::PathForbidden)
    }
    pub fn as_str(self) -> &'static str {
        self.0
    }
    fn bulk_read(self, body: &[u8]) -> bool {
        matches!(
            self.0,
            "/getblocks.bin"
                | "/get_blocks.bin"
                | "/gethashes.bin"
                | "/get_hashes.bin"
                | "/getblocks_by_height.bin"
                | "/get_blocks_by_height.bin"
                | "/gettransactions"
                | "/get_transactions"
                | "/get_output_distribution.bin"
        ) || (self.0 == "/json_rpc"
            && body.len() <= 1024 * 1024
            && serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .is_some_and(|value| {
                    value.get("method").and_then(serde_json::Value::as_str)
                        == Some("get_output_distribution")
                }))
    }
}
/// A test double implements the same bounded request contract as real transport.
pub trait NodeTransport: Send + Sync {
    fn request(
        &self,
        path: DaemonPath,
        body: Vec<u8>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send;
}
#[derive(Clone)]
pub struct RoutedClient {
    client: reqwest::Client,
    plan: Arc<RoutePlan>,
    cancel: CancellationToken,
    deadline: Duration,
    bulk_deadline: Duration,
    resolver: Arc<NoSystemDns>,
}
impl RoutedClient {
    pub fn new(plan: RoutePlan, cancel: CancellationToken) -> Result<Self> {
        let mut client = Self::with_deadline(plan, cancel, Duration::from_secs(25))?;
        // Catch-up block batches can exceed ninety seconds over Tor. Cutting
        // each attempt off at that point discards the same partial batch and
        // prevents any scan progress. Keep a bounded three-minute bulk budget;
        // health probes and broadcasts retain their short deadlines, and the
        // gateway still cancels on expired/revoked health independently.
        client.bulk_deadline = Duration::from_secs(180);
        Ok(client)
    }
    pub fn with_deadline(
        plan: RoutePlan,
        cancel: CancellationToken,
        deadline: Duration,
    ) -> Result<Self> {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let builder = reqwest::Client::builder().tls_backend_preconfigured(tls_config(roots)?);
        Self::build(builder, plan, cancel, deadline)
    }
    fn build(
        builder: reqwest::ClientBuilder,
        plan: RoutePlan,
        cancel: CancellationToken,
        deadline: Duration,
    ) -> Result<Self> {
        plan.proxy().validate()?;
        let proxy = reqwest::Proxy::all(plan.proxy().socks_url())
            .map_err(|_| Denial::InvalidConfiguration)?;
        let resolver = Arc::new(NoSystemDns::default());
        let client = builder
            .no_proxy()
            .proxy(proxy)
            .dns_resolver(resolver.clone())
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(deadline.min(Duration::from_secs(15)))
            .timeout(deadline)
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|_| Denial::InvalidConfiguration)?;
        Ok(Self {
            client,
            plan: Arc::new(plan),
            cancel,
            deadline,
            bulk_deadline: deadline,
            resolver,
        })
    }
    pub fn plan(&self) -> &RoutePlan {
        &self.plan
    }
    pub fn revoke(&self) {
        self.cancel.cancel();
    }
    pub fn denied_dns_lookups(&self) -> usize {
        self.resolver.denied.load(Ordering::Relaxed)
    }
    /// A greeting only tests SOCKS compatibility; it must never produce a
    /// Connected/anonymous status without a successful permitted node request.
    pub async fn check_socks(&self) -> Result<()> {
        tokio::select! {biased;_ = self.cancel.cancelled()=>Err(Denial::Cancelled),result=tokio::time::timeout(self.deadline,async {
            let mut stream=tokio::net::TcpStream::connect(self.plan.proxy().address()).await.map_err(|_|Denial::ProxyUnavailable)?;
            stream.write_all(&[5,1,0]).await.map_err(|_|Denial::ProxyUnavailable)?;let mut answer=[0;2];stream.read_exact(&mut answer).await.map_err(|_|Denial::ProxyUnavailable)?;
            if answer!=[5,0]{return Err(Denial::ProxyUnavailable);}Ok(())
        })=>result.map_err(|_|Denial::Timeout)?}
    }
    async fn perform(
        &self,
        path: DaemonPath,
        body: Vec<u8>,
        limit: usize,
        deadline: Duration,
    ) -> Result<Vec<u8>> {
        if limit == 0 || limit > MAX_RESPONSE || body.len() > 1024 * 1024 {
            return Err(Denial::TooLarge);
        }
        let url = format!(
            "{}{}",
            self.plan.endpoint().canonical().trim_end_matches('/'),
            path.as_str()
        );
        let mut response = self
            .client
            .post(url)
            .timeout(deadline)
            .header(
                reqwest::header::CONTENT_TYPE,
                if path.as_str().ends_with(".bin") {
                    "application/octet-stream"
                } else {
                    "application/json"
                },
            )
            .body(body)
            .send()
            .await
            .map_err(classify)?;
        if response.status().is_redirection() {
            return Err(Denial::Redirect);
        }
        if !response.status().is_success() {
            return Err(Denial::HttpStatus);
        }
        // HTTPS success is reachable only after the client's certificate and
        // hostname checks. No builder option can disable TLS verification here.
        self.plan
            .validate_transport_evidence(self.plan.endpoint().uses_tls())?;
        if response.content_length().is_some_and(|n| n > limit as u64) {
            return Err(Denial::TooLarge);
        }
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(classify)? {
            if data.len().saturating_add(chunk.len()) > limit {
                return Err(Denial::TooLarge);
            }
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }
}
impl NodeTransport for RoutedClient {
    async fn request(&self, path: DaemonPath, body: Vec<u8>, limit: usize) -> Result<Vec<u8>> {
        let deadline = if path.bulk_read(&body) {
            self.bulk_deadline
        } else {
            self.deadline
        };
        tokio::select! {biased;_ = self.cancel.cancelled()=>Err(Denial::Cancelled),result=tokio::time::timeout(deadline,self.perform(path,body,limit,deadline))=>result.map_err(|_|Denial::Timeout)?}
    }
}
fn classify(error: reqwest::Error) -> Denial {
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        if cause
            .downcast_ref::<rustls::Error>()
            .is_some_and(|e| matches!(e, rustls::Error::InvalidCertificate(_)))
        {
            return Denial::InvalidTls;
        }
        source = cause.source();
    }
    if error.is_timeout() {
        Denial::Timeout
    } else {
        Denial::TransportFailure
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
pub(crate) mod tests;
