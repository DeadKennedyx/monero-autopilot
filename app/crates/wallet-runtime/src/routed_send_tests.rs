//! Observed loopback sockets: official wallet RPC is simulated here. No real
//! transaction, wallet key, public node, DNS lookup or Tor circuit is involved.
use super::*;
use crate::security::{Security, SecurityCommand};
use autopilot_privacy::{
    config::{ApprovedNode, Config, Ownership},
    endpoint::ProxyEndpoint,
    runtime::{BackendEndpoint, RouteManager},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

fn onion(seed: u8) -> String {
    use sha3::{Digest, Sha3_256};
    let mut bytes = vec![seed; 32];
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(&bytes);
    h.update([3]);
    bytes.extend_from_slice(&h.finalize()[..2]);
    bytes.push(3);
    format!(
        "{}.onion",
        data_encoding::BASE32_NOPAD
            .encode(&bytes)
            .to_ascii_lowercase()
    )
}

#[derive(Clone)]
struct NodeState {
    broadcasts: Arc<AtomicUsize>,
    network: Network,
}
async fn node(
    State(s): State<NodeState>,
    uri: Uri,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    assert!(
        !headers.contains_key("authorization"),
        "Local credentials must not leave the gateway"
    );
    if uri.path() == "/send_raw_transaction" {
        s.broadcasts.fetch_add(1, Ordering::SeqCst);
        // Node may accept the transfer; the wallet will lose the resulting reply.
        return Json(json!({"status":"OK"})).into_response();
    }
    let value = match body["method"].as_str().unwrap_or("") {
        "get_info" => {
            json!({"status":"OK","nettype":s.network.as_str(),"mainnet":s.network==Network::Mainnet,"stagenet":s.network==Network::Stagenet,"testnet":false,"height":1000,"target_height":0,"synchronized":true,"busy_syncing":false,"offline":false,"top_block_hash":"a".repeat(64)})
        }
        "get_block_header_by_height" => {
            let prefix = match s.network {
                Network::Mainnet => "418015bb9ae982a1975da7d79277c270",
                Network::Stagenet => "76ee3cc98646292206cd3e86f74d88b4",
                Network::Testnet => panic!("Testnet is not enabled"),
            };
            json!({"status":"OK","block_header":{"height":0,"hash":format!("{prefix}{}","0".repeat(32)),"prev_hash":"0".repeat(64),"orphan_status":false}})
        }
        "get_last_block_header" => {
            json!({"status":"OK","block_header":{"height":999,"timestamp":100,"hash":"a".repeat(64),"orphan_status":false}})
        }
        other => panic!("Unexpected node method: {other}"),
    };
    Json(json!({"jsonrpc":"2.0","id":body["id"],"result":value})).into_response()
}
struct Fixture {
    config: Config,
    node: NodeState,
    targets: Arc<Mutex<Vec<String>>>,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
async fn fixture() -> Fixture {
    fixture_for(Network::Stagenet).await
}
async fn fixture_for(network: Network) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let state = NodeState {
        broadcasts: Arc::new(AtomicUsize::new(0)),
        network,
    };
    let app = Router::new().fallback(post(node)).with_state(state.clone());
    let node_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let seen = targets.clone();
    let proxy_task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let Ok((mut incoming, _)) = proxy.accept().await else {
                break;
            };
            let seen = seen.clone();
            connections.spawn(async move {
                let mut greeting = [0; 2];
                if incoming.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                assert_eq!(greeting[0], 5);
                let mut methods = vec![0; greeting[1] as usize];
                incoming.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&0));
                incoming.write_all(&[5, 0]).await.unwrap();
                let mut connect = [0; 4];
                if incoming.read_exact(&mut connect).await.is_err() {
                    return;
                }
                assert_eq!(
                    connect,
                    [5, 1, 0, 3],
                    "Only remote hostname resolution is permitted"
                );
                let len = incoming.read_u8().await.unwrap();
                let mut host = vec![0; len as usize];
                incoming.read_exact(&mut host).await.unwrap();
                assert_eq!(incoming.read_u16().await.unwrap(), 38081);
                seen.lock().unwrap().push(String::from_utf8(host).unwrap());
                let mut upstream = TcpStream::connect(target).await.unwrap();
                incoming
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut incoming, &mut upstream).await;
            });
            while connections.try_join_next().is_some() {}
        }
    });
    let config = Config {
        network,
        managed_tor: false,
        tor_proxy: Some(ProxyEndpoint::parse(&proxy_address.to_string()).unwrap()),
        nodes: (1..=2)
            .map(|i| ApprovedNode {
                id: format!("{i:032x}"),
                label: "Controlled fixture".into(),
                endpoint: format!("http://{}:38081", onion(i)),
                ownership: Ownership::Personal,
                approved: true,
                enabled: true,
            })
            .collect(),
        ..Default::default()
    };
    Fixture {
        config,
        node: state,
        targets,
        tasks: vec![node_task, proxy_task],
    }
}
async fn broadcast(endpoint: &BackendEndpoint) -> reqwest::StatusCode {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();
    let body = "{\"tx_as_hex\":\"deadbeef\",\"do_not_relay\":false}";
    let url = format!("http://{}/send_raw_transaction", endpoint.address());
    let response = client.post(&url).body(body).send().await.unwrap();
    let mut challenge =
        digest_auth::parse(response.headers()["www-authenticate"].to_str().unwrap()).unwrap();
    let _ = response.bytes().await.unwrap();
    let auth = challenge
        .respond(&digest_auth::AuthContext::new_post(
            endpoint.username(),
            endpoint.password(),
            "/send_raw_transaction",
            Some(body.as_bytes()),
        ))
        .unwrap()
        .to_string();
    client
        .post(url)
        .header("authorization", auth)
        .body(body)
        .send()
        .await
        .unwrap()
        .status()
}
#[derive(Clone)]
struct WalletState {
    endpoint: Arc<BackendEndpoint>,
    journal: PathBuf,
    relays: Arc<AtomicUsize>,
    security: Security,
    address: String,
}
async fn wallet(
    State(s): State<WalletState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !headers.contains_key("authorization") {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                "www-authenticate",
                "Digest realm=\"fixture\", nonce=\"abcdef1234567890\", qop=\"auth\", algorithm=MD5",
            )],
            "",
        )
            .into_response();
    }
    let result = match body["method"].as_str().unwrap() {
        "relay_tx" => {
            assert!(s
                .journal
                .join(format!("{}.attempt", "b".repeat(32)))
                .is_file());
            s.relays.fetch_add(1, Ordering::SeqCst);
            assert_eq!(broadcast(&s.endpoint).await, StatusCode::OK);
            assert_eq!(
                broadcast(&s.endpoint).await,
                StatusCode::FORBIDDEN,
                "A permission can never broadcast twice"
            );
            s.security.lock().await;
            return "simulated lost wallet response after node acceptance".into_response();
        }
        "store" => json!({}),
        "get_transfers" => {
            assert_eq!(body["params"]["pool"], false);
            assert_eq!(body["params"]["out"], true);
            json!({"pending":[{"txid":"c".repeat(64),"amount":100,"fee":10,"double_spend_seen":false,"unlock_time":0,"destinations":[{"address":s.address,"amount":100}],"type":"pending","height":0}]})
        }
        other => panic!("Unexpected wallet operation: {other}"),
    };
    Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response()
}
#[tokio::test]
async fn durable_pin_attempt_crosses_gateway_once_and_survives_node_switch_and_restart() {
    routed_attempt_survives_restart(Network::Stagenet).await;
}
#[tokio::test]
async fn mainnet_requires_pin_and_same_network_route_and_never_repeats_ambiguous_relay() {
    routed_attempt_survives_restart(Network::Mainnet).await;
}
async fn routed_attempt_survives_restart(network: Network) {
    let fixture = fixture_for(network).await;
    let mut route = RouteManager::new(fixture.config.clone()).unwrap();
    route.start();
    route.tick().await.unwrap();
    let endpoint = Arc::new(route.endpoint().unwrap());
    let generation = endpoint.generation();
    assert_eq!(broadcast(&endpoint).await, StatusCode::FORBIDDEN);
    let mut sender = tests::journal_for(network);
    let root = sender.root.clone();
    let security = Security::open(root.join("security")).await.unwrap();
    // Keep the PIN store outside the payment directory's strict journal format.
    let journal = root.join("payments");
    fs::create_dir(&journal).unwrap();
    fs::rename(
        sender.marker(&"b".repeat(32), "dpapi"),
        journal.join(format!("{}.dpapi", "b".repeat(32))),
    )
    .unwrap();
    sender.root = journal.clone();
    let session = security
        .execute(
            SecurityCommand::Configure {
                pin: "824619".into(),
                confirm_pin: "824619".into(),
            },
            None,
        )
        .await
        .unwrap()
        .session
        .clone()
        .unwrap();
    let epoch = Some(security.permit(Some(&session)).await.unwrap());
    let state = WalletState {
        endpoint: endpoint.clone(),
        journal: journal.clone(),
        relays: Arc::new(AtomicUsize::new(0)),
        security: security.clone(),
        address: sender.records[0].payment.address.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc = Rpc::new(
        listener.local_addr().unwrap(),
        "fixture".into(),
        "fixture".into(),
    )
    .unwrap();
    let app = Router::new()
        .route("/json_rpc", post(wallet))
        .with_state(state.clone());
    let wallet_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let identity = "a".repeat(64);
    let id = "b".repeat(32);
    if network == Network::Mainnet {
        assert!(sender
            .confirm_routed(
                &rpc,
                &identity,
                &id,
                1000,
                2,
                None,
                Some((&route, generation))
            )
            .await
            .is_err());
        let authorization = security
            .authorize_payment(epoch, Some(&"824619".into()), &identity, &id)
            .await
            .unwrap();
        assert!(sender
            .confirm_authorized(&rpc, &identity, &id, 1000, 2, Some(authorization))
            .await
            .is_err());
        let mut wrong_config = fixture.config.clone();
        wrong_config.network = Network::Stagenet;
        let wrong_route = RouteManager::new(wrong_config).unwrap();
        let authorization = security
            .authorize_payment(epoch, Some(&"824619".into()), &identity, &id)
            .await
            .unwrap();
        assert!(sender
            .confirm_routed(
                &rpc,
                &identity,
                &id,
                1000,
                2,
                Some(authorization),
                Some((&wrong_route, generation))
            )
            .await
            .is_err());
        assert!(!sender.marker(&id, "attempt").exists());
        assert_eq!(state.relays.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.node.broadcasts.load(Ordering::SeqCst), 0);
    }
    let authorization = security
        .authorize_payment(epoch, Some(&"824619".into()), &identity, &id)
        .await
        .unwrap();
    sender
        .confirm_routed(
            &rpc,
            &identity,
            &id,
            1000,
            2,
            Some(authorization),
            Some((&route, generation)),
        )
        .await
        .unwrap();
    assert_eq!(sender.snapshot.payments[0].status, "Checking outcome");
    assert!(security.locked().await);
    route.backend_exited();
    assert!(endpoint.revoked());
    assert!(!route.snapshot().operations_allowed);
    let mut switched = fixture.config.clone();
    switched.nodes[0].enabled = false;
    route
        .save_configuration(&root.join("privacy"), switched, true)
        .unwrap();
    route.start();
    route.tick().await.unwrap();
    assert_eq!(route.snapshot().node_id, Some(format!("{:032x}", 2)));
    drop(sender);
    let mut reopened = Sender::open_for(journal, network);
    assert_eq!(reopened.snapshot.payments[0].status, "Checking outcome");
    assert!(reopened
        .confirm_routed(
            &rpc,
            &identity,
            &id,
            1000,
            3,
            None,
            Some((&route, route.endpoint().unwrap().generation()))
        )
        .await
        .is_err());
    reopened.reconcile(&rpc, &identity, 4).await.unwrap();
    assert_eq!(reopened.snapshot.payments[0].status, "Pending");
    assert_eq!(state.relays.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.node.broadcasts.load(Ordering::SeqCst), 1);
    assert!(fixture
        .targets
        .lock()
        .unwrap()
        .iter()
        .all(|s| s == &onion(1) || s == &onion(2)));
    route.stop();
    wallet_task.abort();
    let _ = wallet_task.await;
    tests::cleanup(&root);
}

#[tokio::test]
async fn revoked_route_cannot_create_an_attempt_marker_or_reach_wallet_rpc() {
    let fixture = fixture().await;
    let mut route = RouteManager::new(fixture.config.clone()).unwrap();
    route.start();
    route.tick().await.unwrap();
    let generation = route.endpoint().unwrap().generation();
    route.backend_exited();
    let mut sender = tests::journal();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc = Rpc::new(
        listener.local_addr().unwrap(),
        "fixture".into(),
        "fixture".into(),
    )
    .unwrap();
    assert!(sender
        .confirm_routed(
            &rpc,
            &"a".repeat(64),
            &"b".repeat(32),
            1000,
            2,
            None,
            Some((&route, generation))
        )
        .await
        .is_err());
    assert!(!sender.marker(&"b".repeat(32), "attempt").exists());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(fixture.node.broadcasts.load(Ordering::SeqCst), 0);
    tests::cleanup(&sender.root);
}
