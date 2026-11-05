//! Real TCP/SOCKS/TLS fixtures. No external network destinations are contacted.
use super::*;
use crate::{
    config::{ApprovedNode, Config, Ownership},
    endpoint::{onion, ProxyEndpoint},
    policy::{PolicyEngine, ProposedTransport},
};
use std::sync::Mutex;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

pub(crate) struct Harness {
    pub(crate) address: SocketAddr,
    pub(crate) requests: Arc<AtomicUsize>,
    pub(crate) targets: Arc<Mutex<Vec<(String, u16)>>>,
    task: JoinHandle<()>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(crate) async fn proxy(target: SocketAddr, refuse: bool) -> Harness {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let targets = Arc::new(Mutex::new(Vec::new()));
    let counter = requests.clone();
    let observed = targets.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut incoming, _)) = listener.accept().await else {
                break;
            };
            let observed = observed.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut greeting = [0; 2];
                if incoming.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                assert_eq!(greeting[0], 5);
                let mut methods = vec![0; greeting[1] as usize];
                incoming.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&0));
                incoming.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 4];
                if incoming.read_exact(&mut request).await.is_err() {
                    return;
                }
                assert_eq!(
                    request,
                    [5, 1, 0, 3],
                    "Only SOCKS domain-name CONNECT is permitted; no client-side destination DNS"
                );
                let length = incoming.read_u8().await.unwrap();
                let mut domain = vec![0; length as usize];
                incoming.read_exact(&mut domain).await.unwrap();
                let port = incoming.read_u16().await.unwrap();
                observed
                    .lock()
                    .unwrap()
                    .push((String::from_utf8(domain).unwrap(), port));
                counter.fetch_add(1, Ordering::SeqCst);
                if refuse {
                    incoming
                        .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    return;
                }
                let mut upstream = TcpStream::connect(target).await.unwrap();
                incoming
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut incoming, &mut upstream).await;
            });
        }
    });
    Harness {
        address,
        requests,
        targets,
        task,
    }
}
async fn read_request<S: AsyncReadExt + Unpin>(stream: &mut S) -> bool {
    let mut bytes = vec![];
    loop {
        let Ok(byte) = stream.read_u8().await else {
            return false;
        };
        bytes.push(byte);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
        if bytes.len() > 16384 {
            return false;
        }
    }
    let text = String::from_utf8_lossy(&bytes);
    let size = text
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|s| s.parse::<usize>().ok())
        })
        .unwrap_or(0);
    if size > 1024 * 1024 {
        return false;
    }
    let mut body = vec![0; size];
    stream.read_exact(&mut body).await.is_ok()
}
async fn http(response: String) -> Harness {
    delayed_http(response, Duration::ZERO).await
}
async fn delayed_http(response: String, delay: Duration) -> Harness {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let response = response.clone();
            let count = count.clone();
            tokio::spawn(async move {
                if read_request(&mut stream).await {
                    count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            });
        }
    });
    Harness {
        address,
        requests,
        targets: Default::default(),
        task,
    }
}
fn response(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
}
pub(crate) fn plan(address: SocketAddr, endpoint: String) -> RoutePlan {
    let c = Config {
        managed_tor: false,
        tor_proxy: Some(ProxyEndpoint::parse(&address.to_string()).unwrap()),
        nodes: vec![ApprovedNode {
            id: "a".repeat(32),
            label: "Controlled fixture".into(),
            endpoint,
            ownership: Ownership::Personal,
            approved: true,
            enabled: true,
        }],
        ..Default::default()
    };
    PolicyEngine::plan(&c, &"a".repeat(32), ProposedTransport::Tor).unwrap()
}
fn client(proxy: SocketAddr) -> RoutedClient {
    RoutedClient::with_deadline(
        plan(proxy, format!("http://{}:38081", onion(8))),
        CancellationToken::new(),
        Duration::from_secs(2),
    )
    .unwrap()
}
async fn request(c: &RoutedClient) -> Result<Vec<u8>> {
    c.request(
        DaemonPath::parse("/json_rpc").unwrap(),
        b"{}".to_vec(),
        HEALTH_RESPONSE,
    )
    .await
}

#[tokio::test]
async fn bulk_download_budget_does_not_extend_health_or_broadcast_deadlines() {
    let target = delayed_http(response("{}"), Duration::from_millis(300)).await;
    let socks = proxy(target.address, false).await;
    let mut c = client(socks.address);
    c.deadline = Duration::from_millis(100);
    c.bulk_deadline = Duration::from_secs(2);
    for (path, body) in [
        ("/getblocks.bin", ""),
        ("/get_output_distribution.bin", ""),
        (
            "/json_rpc",
            r#"{"jsonrpc":"2.0","method":"get_output_distribution","params":{"amounts":[0]}}"#,
        ),
    ] {
        assert_eq!(
            c.request(
                DaemonPath::parse(path).unwrap(),
                body.as_bytes().to_vec(),
                1024
            )
            .await
            .unwrap(),
            b"{}",
            "Bulk read must outlive the short deadline: {path}"
        );
    }
    for body in [
        r#"{"method":"get_info"}"#,
        r#"{"method":"get_fee_estimate"}"#,
        r#"{"method":"other","params":{"method":"get_output_distribution"}}"#,
        r#"[{"method":"get_output_distribution"}]"#,
        "{}",
    ] {
        assert_eq!(
            c.request(
                DaemonPath::parse("/json_rpc").unwrap(),
                body.as_bytes().to_vec(),
                1024
            )
            .await,
            Err(Denial::Timeout),
            "Only the exact distribution method receives the bulk budget"
        );
    }
    assert_eq!(
        c.request(
            DaemonPath::parse("/sendrawtransaction").unwrap(),
            vec![],
            1024
        )
        .await,
        Err(Denial::Timeout)
    );
    let cancel = c.clone();
    let stop = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.revoke();
    });
    assert_eq!(
        c.request(
            DaemonPath::parse("/get_output_distribution.bin").unwrap(),
            vec![],
            1024
        )
        .await,
        Err(Denial::Cancelled)
    );
    stop.await.unwrap();
    assert_eq!(c.denied_dns_lookups(), 0);
    assert!(socks
        .targets
        .lock()
        .unwrap()
        .iter()
        .all(|target| target == &(onion(8), 38081)));
}

#[tokio::test]
async fn distribution_bulk_read_preserves_stream_and_request_size_limits() {
    // No Content-Length: enforce the limit while streaming the delayed body.
    let chunked = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n400\r\n{}\r\n0\r\n\r\n", "x".repeat(1024));
    let target = delayed_http(chunked, Duration::from_millis(300)).await;
    let socks = proxy(target.address, false).await;
    let mut c = client(socks.address);
    c.deadline = Duration::from_millis(100);
    c.bulk_deadline = Duration::from_secs(2);
    let path = DaemonPath::parse("/get_output_distribution.bin").unwrap();
    assert_eq!(c.request(path, vec![], 10).await, Err(Denial::TooLarge));
    assert_eq!(target.requests.load(Ordering::SeqCst), 1);
    for (body, limit) in [
        (vec![], 0),
        (vec![], MAX_RESPONSE + 1),
        (vec![0; 1024 * 1024 + 1], 1024),
    ] {
        assert_eq!(c.request(path, body, limit).await, Err(Denial::TooLarge));
    }
    assert_eq!(
        target.requests.load(Ordering::SeqCst),
        1,
        "Invalid bounds must not reach the node"
    );
    assert_eq!(socks.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn actual_socks_capture_proves_remote_hostname_resolution() {
    let target = http(response("{\"status\":\"OK\"}")).await;
    let socks = proxy(target.address, false).await;
    let c = client(socks.address);
    c.check_socks().await.unwrap();
    assert_eq!(
        socks.requests.load(Ordering::SeqCst),
        0,
        "Greeting does not establish a node route"
    );
    assert_eq!(request(&c).await.unwrap(), b"{\"status\":\"OK\"}");
    assert_eq!(target.requests.load(Ordering::SeqCst), 1);
    assert_eq!(*socks.targets.lock().unwrap(), vec![(onion(8), 38081)]);
    assert_eq!(c.denied_dns_lookups(), 0);
}
#[tokio::test]
async fn unavailable_and_refusing_proxies_never_connect_to_target() {
    let target = http(response("{}")).await;
    let socks = proxy(target.address, true).await;
    let c = client(socks.address);
    assert!(request(&c).await.is_err());
    assert_eq!(socks.requests.load(Ordering::SeqCst), 1);
    assert_eq!(target.requests.load(Ordering::SeqCst), 0);
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let unavailable = client(address);
    assert!(matches!(
        unavailable.check_socks().await,
        Err(Denial::ProxyUnavailable | Denial::Timeout)
    ));
    assert!(request(&unavailable).await.is_err());
    assert_eq!(target.requests.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn redirects_and_arbitrary_paths_cannot_open_direct_connections() {
    let trap = http(response("{}")).await;
    let target=http(format!("HTTP/1.1 302 Found\r\nLocation: http://{}/json_rpc\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",trap.address)).await;
    let socks = proxy(target.address, false).await;
    let c = client(socks.address);
    assert_eq!(request(&c).await, Err(Denial::Redirect));
    for path in [
        "//127.0.0.1/json_rpc",
        "https://example.org/json_rpc",
        "/stop_daemon",
        "/json_rpc?target=evil",
        "/../get_info",
    ] {
        assert!(DaemonPath::parse(path).is_err());
    }
    assert_eq!(trap.requests.load(Ordering::SeqCst), 0);
    assert_eq!(socks.requests.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn revoked_route_and_oversized_response_fail_closed() {
    let target = http(response(&"x".repeat(1024))).await;
    let socks = proxy(target.address, false).await;
    let c = client(socks.address);
    assert_eq!(
        c.request(DaemonPath::parse("/json_rpc").unwrap(), vec![], 10)
            .await,
        Err(Denial::TooLarge)
    );
    c.revoke();
    assert_eq!(request(&c).await, Err(Denial::Cancelled));
    assert_eq!(socks.requests.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn resolver_refuses_system_dns_without_resolving() {
    use reqwest::dns::Resolve;
    let resolver = NoSystemDns::default();
    assert!(resolver
        .resolve("must-not-resolve.example.org".parse().unwrap())
        .await
        .is_err());
    assert_eq!(resolver.denied.load(Ordering::SeqCst), 1);
    assert_eq!(
        resolver
            .resolve("127.0.0.1".parse().unwrap())
            .await
            .unwrap()
            .next()
            .unwrap()
            .ip(),
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
}

async fn tls_server() -> (Harness, rustls::pki_types::CertificateDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["node.example.org".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der.clone()], key.into())
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let count = count.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    if read_request(&mut tls).await {
                        count.fetch_add(1, Ordering::SeqCst);
                        let _ = tls.write_all(response("{}").as_bytes()).await;
                    }
                }
            });
        }
    });
    (
        Harness {
            address,
            requests,
            targets: Default::default(),
            task,
        },
        der,
    )
}
#[tokio::test]
async fn tls_certificate_and_hostname_are_verified_over_socks() {
    let (target, cert) = tls_server().await;
    let socks = proxy(target.address, false).await;
    let p = plan(socks.address, "https://node.example.org:38081".into());
    let c = RoutedClient::new(p.clone(), CancellationToken::new()).unwrap();
    assert!(request(&c).await.is_err());
    assert_eq!(target.requests.load(Ordering::SeqCst), 0);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let builder =
        reqwest::Client::builder().tls_backend_preconfigured(tls_config(roots.clone()).unwrap());
    let verified =
        RoutedClient::build(builder, p, CancellationToken::new(), Duration::from_secs(3)).unwrap();
    assert_eq!(request(&verified).await.unwrap(), b"{}");
    let wrong = plan(socks.address, "https://wrong.example.org:38081".into());
    let builder = reqwest::Client::builder().tls_backend_preconfigured(tls_config(roots).unwrap());
    let mismatch = RoutedClient::build(
        builder,
        wrong,
        CancellationToken::new(),
        Duration::from_secs(3),
    )
    .unwrap();
    assert!(request(&mismatch).await.is_err());
    assert_eq!(target.requests.load(Ordering::SeqCst), 1);
    assert_eq!(verified.denied_dns_lookups(), 0);
}
