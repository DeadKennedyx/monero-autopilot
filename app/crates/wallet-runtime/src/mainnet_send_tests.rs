//! Deterministic loopback fixtures. No native wallet or public network is used.
use super::*;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

#[derive(Clone)]
struct Settings {
    nettype: &'static str,
    valid: bool,
    integrated: bool,
    owned: bool,
    fee: u64,
    prepare_delay_ms: u64,
    history: Option<Value>,
}
#[derive(Clone)]
struct StateData {
    settings: Arc<Mutex<Settings>>,
    prepares: Arc<AtomicUsize>,
    priorities: Arc<Mutex<Vec<u64>>>,
    reads: Arc<AtomicUsize>,
}
async fn rpc_handler(
    State(s): State<StateData>,
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
    let settings = s.settings.lock().unwrap().clone();
    let result = match body["method"].as_str().unwrap() {
        "validate_address" => {
            assert_eq!(body["params"]["allow_openalias"], false);
            json!({"valid":settings.valid,"nettype":settings.nettype,"integrated":settings.integrated})
        }
        "get_address" => {
            assert_eq!(body["params"]["account_index"], 0);
            json!({"addresses":[{"address":if settings.owned {"8".repeat(95)} else {"4".repeat(95)},"address_index":1}]})
        }
        "transfer" => {
            assert_eq!(body["params"]["do_not_relay"], true);
            assert_eq!(body["params"]["account_index"], 0);
            assert_eq!(body["params"]["unlock_time"], 0);
            let priority = body["params"]["priority"].as_u64().unwrap();
            assert!(matches!(priority, 0 | 1));
            s.priorities.lock().unwrap().push(priority);
            s.prepares.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(settings.prepare_delay_ms)).await;
            json!({"amount":body["params"]["destinations"][0]["amount"],"fee":settings.fee,"tx_hash":"c".repeat(64),"tx_metadata":"deadbeef"})
        }
        "get_transfers" => {
            assert_eq!(body["params"]["account_index"], 0);
            assert_eq!(body["params"]["pool"], false);
            assert_eq!(body["params"]["out"], true);
            assert_eq!(body["params"]["pending"], true);
            assert_eq!(body["params"]["failed"], true);
            s.reads.fetch_add(1, Ordering::SeqCst);
            match settings.history {
                Some(value) => value,
                None => return Json(json!({"jsonrpc":"2.0","id":body["id"],"error":{"code":-1,"message":"fixture temporarily busy"}})).into_response(),
            }
        }
        other => panic!("Unexpected wallet operation; no relay permitted: {other}"),
    };
    Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response()
}
struct Fixture {
    root: PathBuf,
    rpc: Rpc,
    state: StateData,
    task: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn start() -> Self {
        let root =
            std::env::temp_dir().join(format!("autopilot-send-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let state = StateData {
            settings: Arc::new(Mutex::new(Settings {
                nettype: "mainnet",
                valid: true,
                integrated: false,
                owned: false,
                fee: 10,
                prepare_delay_ms: 0,
                history: Some(json!({})),
            })),
            prepares: Arc::new(AtomicUsize::new(0)),
            priorities: Arc::new(Mutex::new(Vec::new())),
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc = Rpc::new(
            listener.local_addr().unwrap(),
            "fixture".into(),
            "fixture".into(),
        )
        .unwrap();
        let app = Router::new()
            .route("/json_rpc", post(rpc_handler))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            root,
            rpc,
            state,
            task,
        }
    }
    fn sender(&self) -> Sender {
        Sender::open_for(self.root.join("payments"), Network::Mainnet)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
        tests::cleanup(&self.root);
    }
}

#[tokio::test]
async fn slow_construction_preserves_the_full_preview_review_window() {
    let f = Fixture::start().await;
    f.state.settings.lock().unwrap().prepare_delay_ms = 1100;
    let mut sender = f.sender();
    sender
        .prepare(
            &f.rpc,
            &"a".repeat(64),
            &"8".repeat(95),
            "0.0000000001",
            1000,
            1,
        )
        .await
        .unwrap();
    let payment = &sender.snapshot.payments[0];
    assert!(payment.created_at >= 2);
    assert_eq!(payment.expires_at - payment.created_at, 120);
    assert_eq!(payment.status, "Preview");
    assert_eq!(f.state.prepares.load(Ordering::SeqCst), 1);
    assert!(!sender.marker(&payment.id, "attempt").exists());
    assert_eq!(*f.state.priorities.lock().unwrap(), vec![0]);
}

#[tokio::test]
async fn mainnet_rejects_wrong_network_integrated_invalid_and_unspendable_before_prepare() {
    let f = Fixture::start().await;
    let mut sender = f.sender();
    for network in ["stagenet", "testnet"] {
        f.state.settings.lock().unwrap().nettype = network;
        assert!(sender
            .prepare(
                &f.rpc,
                &"a".repeat(64),
                &"8".repeat(95),
                "0.0001",
                1_000_000_000,
                1
            )
            .await
            .is_err());
    }
    f.state.settings.lock().unwrap().nettype = "mainnet";
    f.state.settings.lock().unwrap().integrated = true;
    assert!(sender
        .prepare(
            &f.rpc,
            &"a".repeat(64),
            &"8".repeat(95),
            "0.0001",
            1_000_000_000,
            1
        )
        .await
        .is_err());
    f.state.settings.lock().unwrap().integrated = false;
    f.state.settings.lock().unwrap().valid = false;
    assert!(sender
        .prepare(
            &f.rpc,
            &"a".repeat(64),
            &"8".repeat(95),
            "0.0001",
            1_000_000_000,
            1
        )
        .await
        .is_err());
    f.state.settings.lock().unwrap().valid = true;
    for (amount, spendable) in [
        ("0.010000000001", u64::MAX),
        ("0.0001", 0),
        ("0.0001", 100_000_000),
    ] {
        assert!(sender
            .prepare(
                &f.rpc,
                &"a".repeat(64),
                &"8".repeat(95),
                amount,
                spendable,
                1
            )
            .await
            .is_err());
    }
    assert_eq!(f.state.prepares.load(Ordering::SeqCst), 0);
    assert!(sender.snapshot.payments.is_empty());
    assert_eq!(fs::read_dir(&sender.root).unwrap().count(), 0);
}

#[tokio::test]
async fn mainnet_fee_ceiling_is_exact_and_fee_must_fit_current_spendable_balance() {
    let f = Fixture::start().await;
    let mut sender = f.sender();
    for (fee, spendable) in [(0, u64::MAX), (MAINNET_MAX_FEE + 1, u64::MAX), (10, 109)] {
        f.state.settings.lock().unwrap().fee = fee;
        assert!(sender
            .prepare(
                &f.rpc,
                &"a".repeat(64),
                &"8".repeat(95),
                "0.0000000001",
                spendable,
                1
            )
            .await
            .is_err());
        assert!(sender.snapshot.payments.is_empty());
        if fee > MAINNET_MAX_FEE {
            let rejected = sender.snapshot.rejected_fee.as_ref().unwrap();
            assert_eq!(rejected.fee_atomic, fee.to_string());
            assert_eq!(rejected.maximum_fee_atomic, MAINNET_MAX_FEE.to_string());
            let public = serde_json::to_value(&sender.snapshot).unwrap();
            assert_eq!(public["rejected_fee"].as_object().unwrap().len(), 2);
            assert!(!public.to_string().contains("deadbeef"));
        } else {
            assert!(sender.snapshot.rejected_fee.is_none());
        }
        assert_eq!(fs::read_dir(&sender.root).unwrap().count(), 0);
    }
    f.state.settings.lock().unwrap().fee = MAINNET_MAX_FEE;
    sender
        .prepare(
            &f.rpc,
            &"a".repeat(64),
            &"8".repeat(95),
            "0.0000000001",
            MAINNET_MAX_FEE + 100,
            1,
        )
        .await
        .unwrap();
    let payment = &sender.snapshot.payments[0];
    assert!(sender.snapshot.rejected_fee.is_none());
    assert_eq!(payment.fee_atomic, MAINNET_MAX_FEE.to_string());
    assert_eq!(payment.total_atomic, (MAINNET_MAX_FEE + 100).to_string());
    assert!(!payment.self_transfer);
    assert!(!sender.marker(&payment.id, "attempt").exists());
    assert_eq!(*f.state.priorities.lock().unwrap(), vec![0, 0, 0, 0]);
}

#[test]
fn fee_priority_is_constrained_and_legacy_commands_default_to_automatic() {
    let base = json!({"action":"prepare","address":"8".repeat(95),"amount":"0.0001"});
    assert!(matches!(
        serde_json::from_value::<SendCommand>(base.clone()).unwrap(),
        SendCommand::Prepare {
            priority: TransferPriority::Automatic,
            ..
        }
    ));
    for choice in [json!("economy"), json!("automatic")] {
        let mut value = base.clone();
        value["priority"] = choice;
        assert!(serde_json::from_value::<SendCommand>(value).is_ok());
    }
    for choice in [json!("fast"), json!("1"), json!(1), json!(null)] {
        let mut value = base.clone();
        value["priority"] = choice;
        assert!(serde_json::from_value::<SendCommand>(value).is_err());
    }
}

#[tokio::test]
async fn economy_is_explicit_persisted_non_relaying_and_cannot_bypass_the_fee_cap() {
    let f = Fixture::start().await;
    let mut sender = f.sender();
    f.state.settings.lock().unwrap().fee = MAINNET_MAX_FEE + 1;
    assert!(sender
        .prepare_with_priority(
            &f.rpc,
            &"a".repeat(64),
            &"8".repeat(95),
            "0.0001",
            u64::MAX,
            1,
            TransferPriority::Economy
        )
        .await
        .is_err());
    assert_eq!(
        sender.snapshot.rejected_fee.as_ref().unwrap().fee_atomic,
        (MAINNET_MAX_FEE + 1).to_string()
    );
    assert!(sender.snapshot.payments.is_empty());
    assert_eq!(fs::read_dir(&sender.root).unwrap().count(), 0);
    f.state.settings.lock().unwrap().fee = 10;
    sender
        .prepare_with_priority(
            &f.rpc,
            &"a".repeat(64),
            &"8".repeat(95),
            "0.0001",
            u64::MAX,
            1,
            TransferPriority::Economy,
        )
        .await
        .unwrap();
    assert!(sender.snapshot.rejected_fee.is_none());
    assert_eq!(
        sender.snapshot.payments[0].priority,
        TransferPriority::Economy
    );
    assert_eq!(
        serde_json::to_value(&sender.snapshot.payments[0]).unwrap()["priority"],
        "economy"
    );
    let id = sender.snapshot.payments[0].id.clone();
    assert!(!sender.marker(&id, "attempt").exists());
    let reopened = f.sender();
    assert_eq!(
        reopened.snapshot.payments[0].priority,
        TransferPriority::Economy
    );
    assert_eq!(reopened.snapshot.payments[0].status, "Cancelled");
    assert_eq!(*f.state.priorities.lock().unwrap(), vec![1, 1]);
    assert_eq!(f.state.prepares.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn verified_self_transfer_flag_and_network_survive_protected_journal_restart() {
    let f = Fixture::start().await;
    f.state.settings.lock().unwrap().owned = true;
    let mut sender = f.sender();
    sender
        .prepare(
            &f.rpc,
            &"a".repeat(64),
            &"8".repeat(95),
            "0.0000000001",
            1000,
            1,
        )
        .await
        .unwrap();
    assert!(sender.snapshot.payments[0].self_transfer);
    let wrong = Sender::open_for(sender.root.clone(), Network::Stagenet);
    assert!(wrong.snapshot.blocked);
    assert!(wrong.snapshot.payments.is_empty());
    assert!(
        !sender
            .marker(&sender.snapshot.payments[0].id, "cancel")
            .exists(),
        "Wrong-network open cannot mutate valid records"
    );
    let reopened = f.sender();
    assert!(!reopened.snapshot.blocked);
    assert!(reopened.snapshot.payments[0].self_transfer);
    assert_eq!(reopened.snapshot.payments[0].status, "Cancelled");
}

#[test]
fn mainnet_journal_rejects_wrong_network_and_over_limit_persisted_fee() {
    let mut sender = tests::journal_for(Network::Mainnet);
    assert!(Sender::open(sender.root.clone()).snapshot.blocked);
    assert!(!sender.marker(&"b".repeat(32), "cancel").exists());
    sender.records[0].payment.fee_atomic = (MAINNET_MAX_FEE + 1).to_string();
    sender.records[0].payment.total_atomic = (MAINNET_MAX_FEE + 101).to_string();
    fs::write(
        sender.marker(&"b".repeat(32), "dpapi"),
        platform::protect(&serde_json::to_vec(&sender.records[0]).unwrap()).unwrap(),
    )
    .unwrap();
    assert!(
        Sender::open_for(sender.root.clone(), Network::Mainnet)
            .snapshot
            .blocked
    );
    assert!(
        Sender::open_for(sender.root.clone(), Network::Testnet)
            .snapshot
            .blocked
    );
    tests::cleanup(&sender.root);
}

#[tokio::test]
async fn confirmed_self_transfer_retains_stale_evidence_on_read_failure_but_blocks_contradiction() {
    let f = Fixture::start().await;
    f.state.settings.lock().unwrap().owned = true;
    let mut sender = f.sender();
    let identity = "a".repeat(64);
    sender
        .prepare(&f.rpc, &identity, &"8".repeat(95), "0.0000000001", 1000, 1)
        .await
        .unwrap();
    let id = sender.snapshot.payments[0].id.clone();
    durable(
        &sender.marker(&id, "attempt"),
        b"fixture only; no broadcast",
    )
    .unwrap();
    f.state.settings.lock().unwrap().history = Some(
        json!({"out":[{"txid":"c".repeat(64),"amount":0,"fee":10,"double_spend_seen":false,"unlock_time":0,"destinations":[{"address":"8".repeat(95),"amount":100}],"type":"out","height":10,"confirmations":2}]}),
    );
    sender.reconcile(&f.rpc, &identity, 2).await.unwrap();
    assert_eq!(sender.snapshot.payments[0].status, "Confirmed");
    assert_eq!(sender.snapshot.payments[0].checked_at, Some(2));
    f.state.settings.lock().unwrap().history = None;
    sender.reconcile(&f.rpc, &identity, 3).await.unwrap();
    assert_eq!(sender.snapshot.payments[0].status, "Confirmed");
    assert_eq!(sender.snapshot.payments[0].confirmations, 2);
    assert_eq!(sender.snapshot.payments[0].checked_at, None);
    assert!(sender.snapshot.error.is_some());
    f.state.settings.lock().unwrap().history = Some(json!({"out":"invalid"}));
    sender.reconcile(&f.rpc, &identity, 4).await.unwrap();
    assert_eq!(sender.snapshot.payments[0].status, "Checking outcome");
    assert_eq!(sender.snapshot.payments[0].confirmations, 0);
    assert!(sender.snapshot.blocked);
    f.state.settings.lock().unwrap().history = Some(json!({}));
    sender.reconcile(&f.rpc, &identity, 5).await.unwrap();
    assert_eq!(sender.snapshot.payments[0].status, "Checking outcome");
    assert!(sender.snapshot.blocked);
    assert!(sender
        .confirm(&f.rpc, &identity, &id, 1000, 6)
        .await
        .is_err());
    assert_eq!(f.state.reads.load(Ordering::SeqCst), 4);
    assert_eq!(f.state.prepares.load(Ordering::SeqCst), 1);
}
