//! Actual authenticated HTTP host checks with isolated private storage. Native
//! binaries are intentionally absent, so forbidden routes cannot launch them.
use crate::{
    api::{router, ApiState},
    runner::Runtime,
};
use autopilot_privacy::config::Config;
use serde_json::{json, Value};
use std::{fs, path::Path};

fn cleanup(root: &Path) {
    let path = fs::canonicalize(root).unwrap();
    assert_eq!(
        path.parent(),
        Some(fs::canonicalize(std::env::temp_dir()).unwrap().as_path())
    );
    assert!(path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("autopilot-private-host-test-"));
    fs::remove_dir_all(path).unwrap();
}
#[tokio::test]
async fn private_host_requires_session_pin_consent_and_never_bootstraps_a_direct_node() {
    let root = std::env::temp_dir().join(format!(
        "autopilot-private-host-test-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let binaries = root.join("no-binaries");
    let runtime = Runtime::start_with_privacy(root.clone(), binaries.clone())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let url = format!("http://{authority}");
    let host_client = runtime.client.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router(ApiState {
                client: host_client,
                token: "isolated-host-token".into(),
                authority,
                html: String::new(),
            }),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let send = |path: &str, body: Value, session: &str| {
        client
            .post(format!("{url}/api/{path}"))
            .header("x-lab-token", "isolated-host-token")
            .header("x-wallet-session", session)
            .json(&body)
            .send()
    };
    let initial = client
        .get(format!("{url}/api/snapshot"))
        .header("x-lab-token", "isolated-host-token")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(initial["phase"], "Locked");
    assert!(initial.get("privacy_config").is_none());
    assert_eq!(
        send("privacy", json!({"action":"connect"}), "")
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let session = send(
        "security",
        json!({"action":"configure","pin":"824619","confirm_pin":"824619"}),
        "",
    )
    .await
    .unwrap()
    .json::<Value>()
    .await
    .unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();
    let refused = send("privacy", json!({"action":"connect"}), &session)
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::CONFLICT);
    let refused = send(
        "wallet",
        json!({"action":"create","name":"No hidden fallback","network":"stagenet"}),
        &session,
    )
    .await
    .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::CONFLICT);
    assert!(!root.join("node.conf").exists());
    assert!(!root.join("wallet.conf").exists());
    assert!(!root.join("wallets/disposable-stagenet.keys").exists());
    let mut local = serde_json::to_value(Config::default()).unwrap();
    local["profile"] = json!("local_node");
    local["local_direct_consent"] = json!(true);
    assert_eq!(
        send(
            "privacy",
            json!({"action":"save","config":local,"consent":false,"pin":"824619"}),
            &session
        )
        .await
        .unwrap()
        .status(),
        reqwest::StatusCode::CONFLICT
    );
    assert_eq!(
        send(
            "privacy",
            json!({"action":"save","config":local,"consent":true,"pin":"999999"}),
            &session
        )
        .await
        .unwrap()
        .status(),
        reqwest::StatusCode::CONFLICT
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        send(
            "privacy",
            json!({"action":"save","config":local,"consent":true,"pin":"824619"}),
            &session
        )
        .await
        .unwrap()
        .status(),
        reqwest::StatusCode::OK
    );
    // More than the normal 1 KiB request limit: only this route accepts the
    // bounded approved-node configuration, while maintaining auth and validation.
    let mut approved = serde_json::to_value(Config::default()).unwrap();
    approved["nodes"] = json!((0..8).map(|i| json!({"id":format!("{i:032x}"),"label":"Owned node configuration fixture","endpoint":format!("https://owned-{i}.invalid"),"ownership":"personal","approved":true,"enabled":true})).collect::<Vec<_>>());
    assert!(serde_json::to_vec(&approved).unwrap().len() > 1024);
    assert_eq!(
        send(
            "privacy",
            json!({"action":"save","config":approved,"consent":true,"pin":"824619"}),
            &session
        )
        .await
        .unwrap()
        .status(),
        reqwest::StatusCode::OK
    );
    let lock = send("security", json!({"action":"lock"}), &session)
        .await
        .unwrap();
    assert!(lock.status().is_success());
    assert_eq!(
        send("relationship", json!({"name":"Private customer"}), &session)
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send("privacy", json!({"action":"disconnect"}), &session)
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let saved = autopilot_privacy::config::ConfigStore::new(root.join("privacy"))
        .load()
        .unwrap();
    assert_eq!(saved.profile, autopilot_privacy::config::Profile::Balanced);
    assert_eq!(saved.nodes.len(), 8);
    // Shut down the actor before dropping its HTTP host and reopening storage.
    send("shutdown", json!({}), "").await.unwrap();
    runtime.stop().await;
    server.abort();
    let _ = server.await;
    let reopened = Runtime::start_with_privacy(root.clone(), binaries.clone())
        .await
        .unwrap();
    assert!(reopened.client.security.as_ref().unwrap().locked().await);
    assert_eq!(
        autopilot_privacy::config::ConfigStore::new(root.join("privacy"))
            .load()
            .unwrap(),
        saved
    );
    reopened.stop().await;
    cleanup(&root);
}
