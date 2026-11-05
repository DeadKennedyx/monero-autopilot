//! Private authenticated adapter for an official local wallet process.
//!
//! A gateway has exactly one validated upstream for its entire lifetime. Revoke
//! it before changing nodes. Credentials and request bodies are never logged.
//! This is not a general forward proxy or a light-wallet/scanning service.
use crate::{
    node::{NodeHealth, NodeManager, VerifiedConnection},
    transport::{DaemonPath, NodeTransport, RoutedClient, MAX_RESPONSE},
    Denial, Result,
};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use digest_auth::{Algorithm, AuthContext, AuthorizationHeader, Qop};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const REALM: &str = "AutoPilot private daemon";
const NONCE_TTL: Duration = Duration::from_secs(120);
const FRESH: Duration = Duration::from_secs(crate::NODE_HEALTH_FRESH_SECS);
const REQUEST_LIMIT: usize = 1024 * 1024;
struct Nonce {
    issued: Instant,
    // The native client rotates cnonce on every request, while incrementing nc.
    // One watermark per server nonce bounds memory without limiting its calls.
    last_count: u32,
}
#[derive(Debug, PartialEq, Eq)]
enum AuthVerdict {
    Accepted,
    Stale,
    Rejected,
}
struct Auth {
    user: String,
    password: Zeroizing<String>,
    nonces: Mutex<HashMap<String, Nonce>>,
}
impl Auth {
    fn new() -> Self {
        Self {
            user: uuid::Uuid::new_v4().simple().to_string(),
            password: Zeroizing::new(format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )),
            nonces: Mutex::new(HashMap::new()),
        }
    }
    fn challenge(&self, stale: bool) -> Response {
        let Ok(mut nonces) = self.nonces.lock() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        nonces.retain(|_, n| n.issued.elapsed() < NONCE_TTL);
        if nonces.len() >= 128 {
            if let Some(oldest) = nonces
                .iter()
                .min_by_key(|(_, n)| n.issued)
                .map(|(id, _)| id.clone())
            {
                nonces.remove(&oldest);
            }
        }
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        nonces.insert(
            nonce.clone(),
            Nonce {
                issued: Instant::now(),
                last_count: 0,
            },
        );
        // MD5 with high-entropy ephemeral credentials is retained for native
        // Monero digest compatibility; this service is strictly loopback-only.
        let stale = if stale { ", stale=true" } else { "" };
        (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, format!("Digest realm=\"{REALM}\", nonce=\"{nonce}\", algorithm=MD5, qop=\"auth,auth-int\"{stale}"))]).into_response()
    }
    fn verify(&self, value: &str, path: &str, body: &[u8]) -> AuthVerdict {
        if value.len() > 4096 {
            return AuthVerdict::Rejected;
        }
        let Ok(mut answer) = AuthorizationHeader::parse(value) else {
            return AuthVerdict::Rejected;
        };
        if answer.realm != REALM
            || answer.username != self.user
            || answer.uri != path
            || answer.userhash
            || answer.opaque.is_some()
            || answer.algorithm != Algorithm::default()
            || !matches!(answer.qop, Some(Qop::AUTH | Qop::AUTH_INT))
            || answer.nc == 0
        {
            return AuthVerdict::Rejected;
        }
        if !answer
            .cnonce
            .as_ref()
            .is_some_and(|n| !n.is_empty() && n.len() <= 128)
        {
            return AuthVerdict::Rejected;
        }
        let supplied = Zeroizing::new(answer.response.clone());
        answer.digest(&AuthContext::new_post(
            &self.user,
            self.password.as_str(),
            path,
            Some(body),
        ));
        if !bool::from(supplied.as_bytes().ct_eq(answer.response.as_bytes())) {
            return AuthVerdict::Rejected;
        }
        let Ok(mut nonces) = self.nonces.lock() else {
            return AuthVerdict::Rejected;
        };
        // Only a correctly signed request may request nonce renewal. Monero
        // treats a subsequent 401 without stale=true as a bad password.
        let Some(nonce) = nonces.get_mut(&answer.nonce) else {
            return AuthVerdict::Stale;
        };
        if nonce.issued.elapsed() >= NONCE_TTL {
            return AuthVerdict::Stale;
        }
        if answer.nc <= nonce.last_count {
            return AuthVerdict::Rejected;
        }
        nonce.last_count = answer.nc;
        AuthVerdict::Accepted
    }
}

#[derive(Clone, Serialize)]
pub struct GatewayStatus {
    pub node: NodeHealth,
    pub blocked: Option<Denial>,
    pub forwarded_requests: u64,
    pub broadcast_attempts: u64,
}
struct Lease {
    status: GatewayStatus,
    expires: Instant,
    broadcast: Option<(uuid::Uuid, Instant)>,
}
struct Shared {
    client: RoutedClient,
    auth: Auth,
    host: String,
    lease: Mutex<Lease>,
    slots: Semaphore,
    stop: CancellationToken,
}
impl Shared {
    async fn wait_for_unhealthy(&self) -> Denial {
        loop {
            let expires = {
                let Ok(lease) = self.lease.lock() else {
                    return Denial::Cancelled;
                };
                if let Some(reason) = lease.status.blocked {
                    return reason;
                }
                if Instant::now() >= lease.expires {
                    return Denial::Stale;
                }
                lease.expires
            };
            tokio::select! { biased;
                _ = self.stop.cancelled() => return Denial::Cancelled,
                _ = tokio::time::sleep_until(expires.into()) => {}
            }
            // A completed health probe may have renewed the lease while this
            // request was in flight. Recheck it, without extending freshness
            // merely because wallet traffic is still flowing.
        }
    }
    fn block(&self, reason: Denial) {
        self.client.revoke();
        if let Ok(mut lease) = self.lease.lock() {
            if lease.status.blocked.is_none() {
                lease.status.blocked = Some(reason);
            }
            lease.broadcast = None;
        }
    }
}

/// Scoped, one-use permission, issued only after durable send authorization.
/// Dropping it cancels an unused permission. It never survives a route switch.
pub struct BroadcastPermit {
    shared: Arc<Shared>,
    id: uuid::Uuid,
}
impl Drop for BroadcastPermit {
    fn drop(&mut self) {
        if let Ok(mut lease) = self.shared.lease.lock() {
            if lease.broadcast.is_some_and(|(id, _)| id == self.id) {
                lease.broadcast = None;
            }
        }
    }
}
pub struct Gateway {
    address: SocketAddr,
    shared: Arc<Shared>,
    server: JoinHandle<()>,
    monitor: JoinHandle<()>,
}
impl Gateway {
    /// Requires evidence from NodeManager, not just a SOCKS greeting or config.
    pub async fn start(connection: VerifiedConnection) -> Result<Self> {
        if !connection.fresh() {
            connection.revoke();
            return Err(Denial::Stale);
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| Denial::TransportFailure)?;
        let address = listener
            .local_addr()
            .map_err(|_| Denial::TransportFailure)?;
        let shared = Arc::new(Shared {
            client: connection.client().clone(),
            auth: Auth::new(),
            host: address.to_string(),
            lease: Mutex::new(Lease {
                status: GatewayStatus {
                    node: connection.health().clone(),
                    blocked: None,
                    forwarded_requests: 0,
                    broadcast_attempts: 0,
                },
                expires: Instant::now() + FRESH,
                broadcast: None,
            }),
            slots: Semaphore::new(8),
            stop: CancellationToken::new(),
        });
        let app = Router::new().fallback(handle).with_state(shared.clone());
        let shutdown = shared.stop.clone();
        let server_state = shared.clone();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await;
            server_state.block(Denial::BackendExited);
        });
        let monitor_state = shared.clone();
        let monitor = tokio::spawn(async move { monitor(connection, monitor_state).await });
        Ok(Self {
            address,
            shared,
            server,
            monitor,
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    /// For the native supervisor's private config only; never frontend/status.
    pub fn credentials(&self) -> (&str, &str) {
        (&self.shared.auth.user, self.shared.auth.password.as_str())
    }
    pub fn status(&self) -> Result<GatewayStatus> {
        let mut lease = self.shared.lease.lock().map_err(|_| Denial::Cancelled)?;
        if Instant::now() >= lease.expires && lease.status.blocked.is_none() {
            lease.status.blocked = Some(Denial::Stale);
        }
        Ok(lease.status.clone())
    }
    pub fn authorize_one_broadcast(&self) -> Result<BroadcastPermit> {
        let mut lease = self.shared.lease.lock().map_err(|_| Denial::Cancelled)?;
        if let Some(e) = lease.status.blocked {
            return Err(e);
        }
        if Instant::now() >= lease.expires {
            return Err(Denial::Stale);
        }
        if lease.broadcast.is_some() {
            return Err(Denial::PathForbidden);
        }
        let id = uuid::Uuid::new_v4();
        lease.broadcast = Some((id, Instant::now() + Duration::from_secs(30)));
        Ok(BroadcastPermit {
            shared: self.shared.clone(),
            id,
        })
    }
    pub fn revoke(&self) {
        self.shared.block(Denial::PolicyChanged);
        self.shared.stop.cancel();
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.revoke();
        self.server.abort();
        self.monitor.abort();
    }
}
async fn monitor(mut connection: VerifiedConnection, shared: Arc<Shared>) {
    let mut manager = NodeManager::default();
    let mut timer = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(5),
        Duration::from_secs(5),
    );
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { biased; _ = shared.stop.cancelled() => break, _ = timer.tick() => {} }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let result = tokio::select! { biased; _ = shared.stop.cancelled() => break, value = manager.refresh(&mut connection, now) => value };
        if let Err(e) = result {
            shared.block(e);
            break;
        }
        let Ok(mut lease) = shared.lease.lock() else {
            shared.block(Denial::Cancelled);
            break;
        };
        if lease.status.blocked.is_some() {
            break;
        }
        if Instant::now() >= lease.expires {
            drop(lease);
            shared.block(Denial::Stale);
            break;
        }
        lease.status.node = connection.health().clone();
        lease.expires = Instant::now() + FRESH;
    }
}

/// Match the official 0.18.5.4 full-wallet read methods, never light-wallet or
/// daemon administration methods. Unknown/batch JSON-RPC envelopes fail closed.
fn operation(path: &str, body: &[u8]) -> Result<(DaemonPath, bool)> {
    let path = DaemonPath::parse(path)?;
    if path.as_str() == "/json_rpc" {
        let request: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| Denial::PathForbidden)?;
        if request["jsonrpc"] != "2.0"
            || !request.is_object()
            || !matches!(
                request["method"].as_str(),
                Some(
                    "get_info"
                        | "get_version"
                        | "get_block_header_by_height"
                        | "getblockheaderbyheight"
                        | "get_last_block_header"
                        | "getlastblockheader"
                        | "get_block_headers_range"
                        | "getblockheadersrange"
                        | "hard_fork_info"
                        | "get_fee_estimate"
                        | "get_output_histogram"
                        | "get_output_distribution"
                        | "get_txpool_backlog"
                )
            )
        {
            return Err(Denial::PathForbidden);
        }
    } else if !path.as_str().ends_with(".bin") {
        let value: serde_json::Value =
            serde_json::from_slice(body).map_err(|_| Denial::PathForbidden)?;
        if !value.is_object() {
            return Err(Denial::PathForbidden);
        }
    }
    Ok((
        path,
        matches!(
            path.as_str(),
            "/sendrawtransaction" | "/send_raw_transaction"
        ),
    ))
}
async fn handle(State(shared): State<Arc<Shared>>, request: Request) -> Response {
    let response = forward(shared, request).await;
    let (mut parts, body) = response.into_parts();
    parts.headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    parts.headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    Response::from_parts(parts, body)
}
async fn forward(shared: Arc<Shared>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    // Monero's epee HTTP client emits its numeric host without the port.
    // Accept only that exact loopback spelling in addition to our authority;
    // browser origins, arbitrary hosts/ports and unauthenticated RPC stay denied.
    let host_allowed = host == Some(shared.host.as_str()) || host == Some("127.0.0.1");
    if parts.method != Method::POST
        || parts.uri.scheme().is_some()
        || parts.uri.authority().is_some()
        || parts.uri.query().is_some()
        || parts.headers.contains_key(header::ORIGIN)
        || !host_allowed
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(_slot) = shared.slots.try_acquire() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let body =
        match tokio::time::timeout(Duration::from_secs(5), to_bytes(body, REQUEST_LIMIT)).await {
            Ok(Ok(body)) => body,
            _ => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        };
    let Some(auth) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return shared.auth.challenge(false);
    };
    match shared.auth.verify(auth, parts.uri.path(), &body) {
        AuthVerdict::Accepted => {}
        AuthVerdict::Stale => return shared.auth.challenge(true),
        AuthVerdict::Rejected => return shared.auth.challenge(false),
    }
    let Ok((path, broadcast)) = operation(parts.uri.path(), &body) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    {
        let Ok(mut lease) = shared.lease.lock() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        if lease.status.blocked.is_some() || Instant::now() >= lease.expires {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        if broadcast {
            if !lease
                .broadcast
                .take()
                .is_some_and(|(_, expiry)| Instant::now() < expiry)
            {
                return StatusCode::FORBIDDEN.into_response();
            }
            lease.status.broadcast_attempts += 1;
        }
        lease.status.forwarded_requests += 1;
    }
    let result = tokio::select! { biased;
        reason = shared.wait_for_unhealthy() => Err(reason),
        value = shared.client.request(path, body.to_vec(), MAX_RESPONSE) => value,
    };
    match result {
        Ok(bytes) => (
            [(
                header::CONTENT_TYPE,
                if path.as_str().ends_with(".bin") {
                    "application/octet-stream"
                } else {
                    "application/json"
                },
            )],
            Body::from(bytes),
        )
            .into_response(),
        Err(e) => {
            // Bounded diagnostics: allowed method path and denial code only.
            // Never log request bodies, addresses, credentials or wallet data.
            eprintln!("AUTOPILOT_GATEWAY_FAILURE {} {:?}", path.as_str(), e);
            // A slow read is not evidence that the independent health lease
            // failed. Let the wallet retry it on this same validated route.
            // An uncertain broadcast always revokes its one-use permission.
            if broadcast || e != Denial::Timeout {
                shared.block(e);
            }
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
pub(crate) mod tests;
