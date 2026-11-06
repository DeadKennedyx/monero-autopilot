use super::*;
use crate::{
    config::Network,
    endpoint::onion,
    transport::tests::{plan, proxy, Harness},
};
use axum::{body::Bytes, routing::post, Json};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Clone, Default)]
pub(crate) struct FixtureState {
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) fail: Arc<AtomicBool>,
    pub(crate) headers: Arc<Mutex<Vec<axum::http::HeaderMap>>>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    pub(crate) wrong_host: Arc<Mutex<Option<String>>>,
    response_delay: Arc<Mutex<Duration>>,
}
async fn fixture(
    State(state): State<FixtureState>,
    headers: axum::http::HeaderMap,
    bytes: Bytes,
) -> Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let delay = *state.response_delay.lock().unwrap();
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let wrong = state
        .wrong_host
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|host| {
            headers
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .is_some_and(|h| h.starts_with(host))
        });
    state.headers.lock().unwrap().push(headers);
    state.bodies.lock().unwrap().push(bytes.to_vec());
    if state.fail.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let request: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    let result = match request["method"].as_str().unwrap_or("") {
        "get_info" if wrong => {
            json!({"status":"OK","nettype":"mainnet","mainnet":true,"stagenet":false,"testnet":false})
        }
        "get_info" => {
            json!({"status":"OK","nettype":"stagenet","mainnet":false,"stagenet":true,"testnet":false,"height":1000,"target_height":0,"synchronized":true,"busy_syncing":false,"offline":false,"top_block_hash":"a".repeat(64)})
        }
        "get_block_header_by_height" => {
            json!({"status":"OK","block_header":{"height":0,"hash":format!("76ee3cc98646292206cd3e86f74d88b4{}", "0".repeat(32)),"prev_hash":"0".repeat(64),"orphan_status":false}})
        }
        "get_last_block_header" => {
            json!({"status":"OK","block_header":{"height":999,"timestamp":100,"hash":"a".repeat(64),"orphan_status":false}})
        }
        _ => json!({"status":"OK"}),
    };
    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result})).into_response()
}
pub(crate) struct TestGateway {
    pub(crate) gateway: Gateway,
    pub(crate) state: FixtureState,
    pub(crate) _proxy: Harness,
    node: JoinHandle<()>,
}
impl Drop for TestGateway {
    fn drop(&mut self) {
        self.node.abort();
    }
}
pub(crate) async fn setup() -> TestGateway {
    setup_with_deadline(Duration::from_secs(25)).await
}
async fn setup_with_deadline(deadline: Duration) -> TestGateway {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = FixtureState::default();
    let proxy = proxy(listener.local_addr().unwrap(), false).await;
    let app = Router::new()
        .fallback(post(fixture))
        .with_state(state.clone());
    let node = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut manager = NodeManager::default();
    let connection = manager
        .validate(
            RoutedClient::with_deadline(
                plan(proxy.address, format!("http://{}:38081", onion(2))),
                CancellationToken::new(),
                deadline,
            )
            .unwrap(),
            Network::Stagenet,
            1000,
        )
        .await
        .unwrap();
    let gateway = Gateway::start(connection).await.unwrap();
    TestGateway {
        gateway,
        state,
        _proxy: proxy,
        node,
    }
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
}
async fn signed(g: &Gateway, path: &str, body: impl AsRef<[u8]>) -> String {
    let response = client()
        .post(format!("http://{}{path}", g.address()))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let mut challenge = digest_auth::parse(
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let (user, password) = g.credentials();
    challenge
        .respond(&AuthContext::new_post(
            user,
            password,
            path,
            Some(body.as_ref()),
        ))
        .unwrap()
        .to_string()
}
async fn call(g: &Gateway, path: &str, body: impl AsRef<[u8]>) -> reqwest::Response {
    let auth = signed(g, path, body.as_ref()).await;
    client()
        .post(format!("http://{}{path}", g.address()))
        .header(header::AUTHORIZATION, auth)
        .body(body.as_ref().to_vec())
        .send()
        .await
        .unwrap()
}
fn info() -> String {
    json!({"jsonrpc":"2.0","id":1,"method":"get_info","params":{}}).to_string()
}

#[tokio::test]
async fn authenticated_native_requests_forward_without_local_credentials_and_replays_fail() {
    let test = setup().await;
    let g = &test.gateway;
    let body = info();
    let auth = signed(g, "/json_rpc", &body).await;
    let response = client()
        .post(format!("http://{}/json_rpc", g.address()))
        .header(header::AUTHORIZATION, &auth)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.json::<Value>().await.unwrap()["result"]["height"],
        1000
    );
    let replay = client()
        .post(format!("http://{}/json_rpc", g.address()))
        .header(header::AUTHORIZATION, &auth)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    let headers = test.state.headers.lock().unwrap();
    assert!(headers
        .iter()
        .all(|h| !h.contains_key(header::AUTHORIZATION) && !h.contains_key(header::COOKIE)));
    assert_eq!(test.state.calls.load(Ordering::SeqCst), 4);
    assert_eq!(g.shared.client.denied_dns_lookups(), 0);
}

#[tokio::test]
async fn native_monero_host_without_port_still_requires_authentication() {
    let test = setup().await;
    let g = &test.gateway;
    let url = format!("http://{}/json_rpc", g.address());
    let body = info();
    let challenge = client()
        .post(&url)
        .header(header::HOST, "127.0.0.1")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(test.state.calls.load(Ordering::SeqCst), 3);
    let mut digest = digest_auth::parse(
        challenge.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let (user, password) = g.credentials();
    let auth = digest
        .respond(&AuthContext::new_post(
            user,
            password,
            "/json_rpc",
            Some(body.as_bytes()),
        ))
        .unwrap()
        .to_string();
    // A wrong explicit port and another loopback spelling remain forbidden,
    // even with valid credentials. Neither consumes the valid nonce count.
    for host in ["127.0.0.1:1", "127.0.0.2", "localhost", "attacker.invalid"] {
        assert_eq!(
            client()
                .post(&url)
                .header(header::HOST, host)
                .header(header::AUTHORIZATION, &auth)
                .body(body.clone())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        client()
            .post(&url)
            .header(header::HOST, "127.0.0.1")
            .header(header::AUTHORIZATION, &auth)
            .body(body.clone())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client()
            .post(&url)
            .header(header::HOST, "127.0.0.1")
            .header(header::AUTHORIZATION, &auth)
            .body(body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(test.state.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn browser_origins_hosts_methods_and_admin_or_light_wallet_paths_are_blocked() {
    let test = setup().await;
    let g = &test.gateway;
    for (path, body) in [("/json_rpc", json!({"jsonrpc":"2.0","id":1,"method":"set_daemon","params":{"address":"http://leak.invalid"}}).to_string()), ("/json_rpc", json!([{"method":"get_info"}]).to_string()), ("/login", "{}".into()), ("/import_wallet_request", "{}".into()), ("/stop_daemon", "{}".into())] {
        assert_eq!(call(g, path, &body).await.status(), StatusCode::FORBIDDEN);
    }
    for headers in [
        [("origin", "http://attacker.invalid"), ("host", "127.0.0.1")],
        [("host", "attacker.invalid"), ("accept", "*/*")],
    ] {
        let response = client()
            .post(format!("http://{}/json_rpc", g.address()))
            .headers(
                headers
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                            v.parse().unwrap(),
                        )
                    })
                    .collect(),
            )
            .body(info())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(
        client()
            .get(format!("http://{}/json_rpc", g.address()))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(test.state.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn broadcasting_requires_a_scoped_one_use_permission_and_never_retries() {
    let test = setup().await;
    let g = &test.gateway;
    let body = r#"{"tx_as_hex":"00"}"#;
    assert_eq!(
        call(g, "/sendrawtransaction", body).await.status(),
        StatusCode::FORBIDDEN
    );
    {
        let _unused = g.authorize_one_broadcast().unwrap();
    }
    assert_eq!(
        call(g, "/sendrawtransaction", body).await.status(),
        StatusCode::FORBIDDEN
    );
    let _permit = g.authorize_one_broadcast().unwrap();
    assert_eq!(
        call(g, "/sendrawtransaction", body).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        call(g, "/sendrawtransaction", body).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(g.status().unwrap().broadcast_attempts, 1);
    let _permit = g.authorize_one_broadcast().unwrap();
    test.state.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        call(g, "/sendrawtransaction", body).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(g.status().unwrap().blocked.is_some());
    assert!(g.authorize_one_broadcast().is_err());
    assert_eq!(
        call(g, "/sendrawtransaction", body).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        test.state.calls.load(Ordering::SeqCst),
        5,
        "No automatic retry of an uncertain broadcast"
    );
}

#[tokio::test]
async fn read_timeout_preserves_healthy_route_but_broadcast_timeout_revokes_it() {
    let test = setup_with_deadline(Duration::from_millis(250)).await;
    let g = &test.gateway;
    *test.state.response_delay.lock().unwrap() = Duration::from_millis(750);
    assert_eq!(
        call(g, "/getblocks.bin", crate::block_batch::tests::request())
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(g.status().unwrap().blocked.is_none());
    *test.state.response_delay.lock().unwrap() = Duration::ZERO;
    assert_eq!(call(g, "/json_rpc", &info()).await.status(), StatusCode::OK);
    *test.state.response_delay.lock().unwrap() = Duration::from_millis(750);
    let _permit = g.authorize_one_broadcast().unwrap();
    assert_eq!(
        call(g, "/sendrawtransaction", r#"{"tx_as_hex":"00"}"#)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(g.status().unwrap().blocked, Some(Denial::Timeout));
    assert!(g.authorize_one_broadcast().is_err());
    assert_eq!(g.status().unwrap().broadcast_attempts, 1);
    assert_eq!(
        test.state.calls.load(Ordering::SeqCst),
        6,
        "No automatic retries"
    );
}

#[tokio::test]
async fn authenticated_block_reads_are_bounded_and_malformed_bodies_never_forward() {
    let test = setup().await;
    let original = crate::block_batch::tests::request();
    let expected = crate::block_batch::bounded_request(&original).unwrap();
    for path in ["/getblocks.bin", "/get_blocks.bin"] {
        assert_eq!(
            call(&test.gateway, path, &original).await.status(),
            StatusCode::OK
        );
        assert_eq!(test.state.bodies.lock().unwrap().last(), Some(&expected));
    }
    let before = test.state.calls.load(Ordering::SeqCst);
    assert_eq!(
        call(&test.gateway, "/getblocks.bin", "{}").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(test.state.calls.load(Ordering::SeqCst), before);
    assert!(test.gateway.status().unwrap().blocked.is_none());
    assert_eq!(test.gateway.status().unwrap().broadcast_attempts, 0);
}

#[tokio::test]
async fn monitor_accepts_slow_valid_checks_and_revokes_on_failed_probe() {
    let test = setup().await;
    let g = &test.gateway;
    // Three ordered Tor round trips take 18 seconds, plus a five-second initial
    // interval. The former 15-second lease expired before this valid check.
    *test.state.response_delay.lock().unwrap() = Duration::from_secs(6);
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            let status = g.status().unwrap();
            assert!(status.blocked.is_none());
            if status.node.latency_ms >= 18000 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    test.state.fail.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(reason) = g.status().unwrap().blocked {
                assert_eq!(reason, Denial::HttpStatus);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert!(g.authorize_one_broadcast().is_err());
}

#[tokio::test]
async fn in_flight_read_uses_renewed_health_but_cannot_survive_actual_expiration() {
    let test = setup().await;
    let g = &test.gateway;
    *test.state.response_delay.lock().unwrap() = Duration::from_millis(750);
    g.shared.lease.lock().unwrap().expires = Instant::now() + Duration::from_millis(500);
    let shared = g.shared.clone();
    let calls = test.state.calls.clone();
    let renewal = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(2), async {
            while calls.load(Ordering::SeqCst) < 4 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        // Represents a successful probe completing during the pending read.
        shared.lease.lock().unwrap().expires = Instant::now() + Duration::from_secs(3);
    });
    assert_eq!(call(g, "/json_rpc", &info()).await.status(), StatusCode::OK);
    renewal.await.unwrap();
    assert!(g.status().unwrap().blocked.is_none());
    // A second slow read has no successful renewal and must fail closed.
    g.shared.lease.lock().unwrap().expires = Instant::now() + Duration::from_millis(100);
    assert_eq!(
        call(g, "/json_rpc", &info()).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(g.status().unwrap().blocked, Some(Denial::Stale));
    assert!(g.authorize_one_broadcast().is_err());
}

#[tokio::test]
async fn stale_route_and_explicit_revoke_cannot_forward_or_reuse_send_permission() {
    let test = setup().await;
    let _permit = test.gateway.authorize_one_broadcast().unwrap();
    test.gateway.shared.lease.lock().unwrap().expires = Instant::now() - Duration::from_millis(1);
    assert_eq!(
        call(&test.gateway, "/json_rpc", &info()).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(test.gateway.status().unwrap().blocked, Some(Denial::Stale));
    test.gateway.revoke();
    assert!(test.gateway.authorize_one_broadcast().is_err());
    assert_eq!(test.state.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn auth_integrity_expiration_and_nonce_capacity_are_bounded() {
    let auth = Auth::new();
    let response = auth.challenge(false);
    let mut prompt = digest_auth::parse(
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let answer = prompt
        .respond(&AuthContext::new_post(
            &auth.user,
            auth.password.as_str(),
            "/json_rpc",
            Some(b"{}"),
        ))
        .unwrap()
        .to_string();
    assert_eq!(
        auth.verify(&answer, "/json_rpc", b"changed"),
        AuthVerdict::Rejected
    );
    assert_eq!(
        auth.verify(&answer, "/sendrawtransaction", b"{}"),
        AuthVerdict::Rejected
    );
    assert_eq!(
        auth.verify(&answer, "/json_rpc", b"{}"),
        AuthVerdict::Accepted
    );
    assert_eq!(
        auth.verify(&answer, "/json_rpc", b"{}"),
        AuthVerdict::Rejected
    );
    for _ in 0..200 {
        auth.challenge(false);
    }
    assert_eq!(auth.nonces.lock().unwrap().len(), 128);
    assert_eq!(auth.verify(&answer, "/json_rpc", b"{}"), AuthVerdict::Stale);
}

#[tokio::test]
async fn native_rotating_client_nonce_and_expiration_renew_without_replay() {
    let test = setup().await;
    let g = &test.gateway;
    let body = info();
    let mut answer = AuthorizationHeader::parse(&signed(g, "/json_rpc", &body).await).unwrap();
    let (user, password) = g.credentials();
    answer.qop = Some(Qop::AUTH); // Monero uses auth, not auth-int.
    let context = AuthContext::new_post(user, password, "/json_rpc", Some(body.as_bytes()));
    for count in 1..=32 {
        answer.nc = count;
        answer.cnonce = Some(format!("native-request-{count}"));
        answer.digest(&context);
        assert_eq!(
            g.shared
                .auth
                .verify(&answer.to_string(), "/json_rpc", body.as_bytes()),
            AuthVerdict::Accepted
        );
    }
    // Rotating cnonce alone cannot reuse an old nc, even with a valid signature.
    answer.cnonce = Some("different-client-nonce".into());
    answer.digest(&context);
    assert_eq!(
        g.shared
            .auth
            .verify(&answer.to_string(), "/json_rpc", body.as_bytes()),
        AuthVerdict::Rejected
    );
    g.shared
        .auth
        .nonces
        .lock()
        .unwrap()
        .get_mut(&answer.nonce)
        .unwrap()
        .issued = Instant::now() - NONCE_TTL;
    answer.nc += 1;
    answer.digest(&context);
    let url = format!("http://{}/json_rpc", g.address());
    let response = client()
        .post(&url)
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, answer.to_string())
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(test.state.calls.load(Ordering::SeqCst), 3);
    let header = response.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap();
    assert!(header.contains("stale=true"));
    let renewed = digest_auth::parse(header)
        .unwrap()
        .respond(&context)
        .unwrap()
        .to_string();
    assert_eq!(
        client()
            .post(&url)
            .header(header::AUTHORIZATION, &renewed)
            .body(body.clone())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client()
            .post(&url)
            .header(header::AUTHORIZATION, renewed)
            .body(body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(test.state.calls.load(Ordering::SeqCst), 4);
}
