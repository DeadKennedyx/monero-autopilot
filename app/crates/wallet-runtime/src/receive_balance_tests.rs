//! Mainnet confirmed totals and pending-spend availability from local RPC only.
use super::*;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use std::sync::{Arc, Mutex};

fn funds(total: u64, unlocked: u64, blocks: u64) -> Value {
    json!({"balance":total,"unlocked_balance":unlocked,"blocks_to_unlock":blocks,"multisig_import_needed":false})
}

#[test]
fn pending_send_keeps_confirmed_total_but_cannot_count_committed_inputs_as_spendable() {
    let before = 9_007_199_254_740_993_u64;
    let result = parse_confirmed_balance(
        &funds(before, before, 0),
        &funds(before - 10, 0, 0),
        &json!({}),
        100,
        120,
    )
    .unwrap();
    assert_eq!(result.confirmed_atomic, before.to_string());
    assert_eq!(result.spendable_atomic, "0");
    assert_eq!(result.locked_atomic, before.to_string());
    // Pending inputs have no mined output unlock countdown yet.
    assert_eq!(result.blocks_to_unlock, 0);
    assert_eq!(result.pending_atomic, None);
}

#[test]
fn availability_is_conservative_and_never_adds_pending_totals_to_confirmed_money() {
    // The non-strict total includes unconfirmed change/incoming funds.
    let b = parse_confirmed_balance(
        &funds(1000, 600, 9),
        &funds(3000, 800, 4),
        &json!({}),
        100,
        120,
    )
    .unwrap();
    assert_eq!(b.confirmed_atomic, "1000");
    assert_eq!(b.spendable_atomic, "600");
    assert_eq!(b.locked_atomic, "400");
    assert_eq!(b.blocks_to_unlock, 4);
    let b = parse_confirmed_balance(&funds(990, 0, 9), &funds(990, 0, 9), &json!({}), 101, 121)
        .unwrap();
    assert_eq!(
        (
            b.confirmed_atomic.as_str(),
            b.spendable_atomic.as_str(),
            b.locked_atomic.as_str()
        ),
        ("990", "0", "990")
    );
    let b = parse_confirmed_balance(
        &funds(990, 990, 0),
        &funds(990, 990, 0),
        &json!({}),
        110,
        130,
    )
    .unwrap();
    assert_eq!(
        (b.spendable_atomic.as_str(), b.locked_atomic.as_str()),
        ("990", "0")
    );
}

#[test]
fn malformed_available_evidence_is_rejected_instead_of_hidden_by_the_minimum() {
    let confirmed = funds(1000, 1000, 0);
    for (field, value) in [
        ("balance", json!(1)),
        ("unlocked_balance", json!("100")),
        ("blocks_to_unlock", json!(-1)),
        ("multisig_import_needed", json!(true)),
    ] {
        let mut available = funds(1000, 100, 0);
        available[field] = value;
        assert!(
            parse_confirmed_balance(&confirmed, &available, &json!({}), 100, 120).is_err(),
            "Invalid field: {field}"
        );
    }
}

#[derive(Clone)]
struct FixtureState {
    calls: Arc<Mutex<Vec<Value>>>,
    advance: bool,
}
async fn rpc_handler(
    State(state): State<FixtureState>,
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
    let mut calls = state.calls.lock().unwrap();
    let result = match body["method"].as_str().unwrap() {
        "get_height" => {
            json!({"height":if state.advance && calls.iter().any(|call| call["method"] == "get_height") {101} else {100}})
        }
        "get_transfers" => {
            assert_eq!(body["params"]["account_index"], 0);
            json!({})
        }
        "get_balance" => {
            assert_eq!(body["params"]["account_index"], 0);
            if body["params"]["strict"] == true {
                funds(1000, 1000, 0)
            } else {
                assert_eq!(body["params"]["strict"], false);
                funds(990, 0, 0)
            }
        }
        other => panic!("Only local read operations permitted: {other}"),
    };
    calls.push(body.clone());
    Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response()
}

#[tokio::test]
async fn mainnet_combines_local_reads_inside_height_bracket_without_pool_refresh() {
    for (mainnet, advance) in [(true, false), (true, true), (false, false)] {
        let state = FixtureState {
            calls: Default::default(),
            advance,
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
        let result = if mainnet {
            read_confirmed_balance(&rpc, 120).await
        } else {
            read_balance(&rpc, 120).await
        };
        task.abort();
        let _ = task.await;
        if advance {
            assert!(
                result.is_err(),
                "A block advance invalidates the combined sample"
            );
        } else {
            let balance = result.unwrap();
            assert_eq!(balance.confirmed_atomic, "1000");
            assert_eq!(balance.spendable_atomic, if mainnet { "0" } else { "1000" });
            assert_eq!(
                balance.pending_atomic,
                if mainnet { None } else { Some("0".into()) }
            );
        }
        let calls = state.calls.lock().unwrap();
        let methods: Vec<_> = calls
            .iter()
            .map(|call| call["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            methods,
            if mainnet {
                vec![
                    "get_height",
                    "get_transfers",
                    "get_balance",
                    "get_balance",
                    "get_height",
                ]
            } else {
                vec!["get_height", "get_transfers", "get_balance", "get_height"]
            }
        );
        assert_eq!(calls[1]["params"]["pool"], !mainnet);
        assert_eq!(calls[2]["params"]["strict"], true);
        if mainnet {
            assert_eq!(calls[3]["params"]["strict"], false);
        }
    }
}
