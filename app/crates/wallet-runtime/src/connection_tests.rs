//! Connect is a state request, not a hidden restart button. These checks use
//! isolated native storage but no wallet binaries, Tor or external destinations.
use super::*;

async fn fixture() -> (Actor, PathBuf, Option<u64>) {
    let root = std::env::temp_dir().join(format!(
        "autopilot-connect-test-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let supervisor = Supervisor::new_guarded(root.clone(), root.join("no-binaries"))
        .await
        .unwrap();
    let security = Security::open(root.join("security")).await.unwrap();
    let access = security
        .execute(
            SecurityCommand::Configure {
                pin: "824619".into(),
                confirm_pin: "824619".into(),
            },
            None,
        )
        .await
        .unwrap();
    let permit = Some(security.permit(access.session.as_deref()).await.unwrap());
    let (sender, receiver) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let client = Client {
        state: Arc::new(RwLock::new(Snapshot::default())),
        sender,
        cancel: Arc::new(Mutex::new(cancel.clone())),
        busy: Arc::new(AtomicBool::new(false)),
        shutdown: CancellationToken::new(),
        finished: CancellationToken::new(),
        receive_enabled: true,
        send_enabled: false,
        setup_enabled: true,
        managing: Arc::new(AtomicBool::new(false)),
        security: Some(security),
        privacy_enabled: true,
        network: Network::Stagenet,
    };
    let mut privacy = RouteManager::new(PrivacyConfig::default()).unwrap();
    privacy.start();
    let mut actor = Actor {
        managed_tor: ManagedTor::new(root.join("managed-tor")),
        supervisor,
        client,
        receiver,
        cancel,
        policy: LocalRecovery::default(),
        wallet_liveness: WalletLiveness::default(),
        state: Snapshot::default(),
        clock: Instant::now(),
        expected_identity: Some("saved-wallet-identity".into()),
        next_save: Instant::now(),
        hold: false,
        next_receive: Instant::now(),
        payments: None,
        test_wallet: None,
        setup: None,
        privacy: Some(privacy),
        relationships: None,
        selected_relationship: None,
    };
    actor.policy.start(0);
    actor.policy.attempts = 2;
    actor.publish().await;
    (actor, root, permit)
}

fn cleanup(root: PathBuf) {
    let path = std::fs::canonicalize(root).unwrap();
    assert_eq!(
        path.parent(),
        Some(
            std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .as_path()
        )
    );
    assert!(path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("autopilot-connect-test-"));
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn repeated_connect_preserves_busy_work_and_the_active_route_generation() {
    let (mut actor, root, permit) = fixture().await;
    let generation = actor.privacy_status().unwrap().recovery.generation;
    let retry = actor.policy.retry_at;
    let before_tor = actor.managed_tor.snapshot();
    actor.client.busy.store(true, Ordering::SeqCst);
    for state in [
        ConnectionState::InitializingTransport,
        ConnectionState::Connecting,
        ConnectionState::Validating,
        ConnectionState::Connected,
        ConnectionState::Degraded,
        ConnectionState::Recovering,
    ] {
        actor
            .client
            .state
            .write()
            .await
            .privacy
            .as_mut()
            .unwrap()
            .recovery
            .state = state;
        let reply = actor
            .client
            .privacy_authorized(PrivacyCommand::Connect, permit)
            .await
            .unwrap();
        assert_eq!(reply.status.recovery.generation, generation);
        assert_eq!(reply.status.recovery.state, state);
        assert!(
            actor.receiver.try_recv().is_err(),
            "Repeated Connect must not queue a restart"
        );
        assert!(
            actor.client.busy.load(Ordering::SeqCst),
            "Do not release another operation's busy guard"
        );
        assert!(!actor.cancel.is_cancelled());
    }
    // A request that was queued before the snapshot became active is checked
    // again against the actor's real route, not just the published status.
    let reply = actor
        .privacy_action(PrivacyCommand::Connect, permit)
        .await
        .unwrap();
    assert_eq!(reply.status.recovery.generation, generation);
    assert_eq!(actor.policy.attempts, 2);
    assert_eq!(actor.policy.retry_at, retry);
    assert!(actor.state.events.is_empty());
    assert_eq!(actor.managed_tor.snapshot().starts, before_tor.starts);
    assert_eq!(actor.managed_tor.snapshot().pid, before_tor.pid);
    assert_eq!(
        actor.expected_identity.as_deref(),
        Some("saved-wallet-identity")
    );
    assert!(actor
        .client
        .privacy_authorized(PrivacyCommand::Connect, None)
        .await
        .is_err());
    actor.client.security.as_ref().unwrap().lock().await;
    assert!(actor
        .client
        .privacy_authorized(PrivacyCommand::Connect, permit)
        .await
        .is_err());
    drop(actor);
    cleanup(root);
}

#[tokio::test]
async fn explicit_pause_and_terminal_retry_are_not_swallowed_by_connect_acknowledgement() {
    let (mut actor, root, permit) = fixture().await;
    let paused = actor
        .privacy_action(PrivacyCommand::Disconnect, permit)
        .await
        .unwrap();
    assert_eq!(paused.status.recovery.state, ConnectionState::Disconnected);
    actor.publish().await;
    // This fixture deliberately has no permitted nodes. Connect must execute a
    // real attempt, return its failure and allow another explicit terminal retry.
    for _ in 0..2 {
        let before = actor.privacy_status().unwrap().recovery.generation;
        let client = actor.client.clone();
        let request = tokio::spawn(async move {
            client
                .privacy_authorized(PrivacyCommand::Connect, permit)
                .await
        });
        let queued = tokio::time::timeout(Duration::from_secs(2), actor.receiver.recv())
            .await
            .unwrap()
            .unwrap();
        actor.handle(queued).await;
        assert!(request.await.unwrap().is_err());
        let status = actor.privacy_status().unwrap();
        assert_eq!(status.recovery.state, ConnectionState::PrivacyBlocked);
        assert!(status.recovery.generation > before);
        assert!(!actor.client.busy.load(Ordering::SeqCst));
    }
    // A wallet-level terminal failure also needs an explicit retry even if the
    // network snapshot itself still says Connected.
    let mut status = actor.privacy_status().unwrap();
    status.recovery.state = ConnectionState::Connected;
    assert!(!connect_is_active("Needs attention", &status));
    assert!(!connect_is_active("Stopping", &status));
    assert!(!connect_is_active("Locked", &status));
    drop(actor);
    cleanup(root);
}

#[test]
fn wallet_watchdog_ignores_invalid_responses_and_defers_unhealthy_routes() {
    let mut watch = WalletLiveness::default();
    watch.bind(1, 1, 0);
    watch.synchronized(0);
    for value in [
        json!({}),
        json!({"height":"1000"}),
        json!({"height":-1}),
        json!({"height":1003}),
        json!({"height":u64::MAX}),
    ] {
        assert_eq!(observed_wallet_height(&value, Some(1000)), None);
    }
    let missing = watch.missing_response(180_000);
    assert_eq!(missing, MissingResponse::Unresponsive);
    assert_eq!(wallet_observation(false, true, false, missing, true), None);
    assert_eq!(
        wallet_observation(true, true, false, missing, true),
        Some(false)
    );
    assert_eq!(
        wallet_observation(true, false, false, missing, true),
        Some(false)
    );
    assert_eq!(wallet_observation(false, true, true, missing, true), None);
    assert_eq!(
        wallet_observation(false, true, false, missing, false),
        Some(false)
    );
    assert_eq!(
        observed_wallet_height(&json!({"height":1000}), Some(1000)),
        Some(1000)
    );
    watch.responded(180_001);
    assert_eq!(watch.missing_response(180_002), MissingResponse::Waiting);
    assert_eq!(
        wallet_observation(true, true, true, missing, true),
        Some(true)
    );
    assert_eq!(
        wallet_observation(true, true, false, MissingResponse::InitialScanNotice, true),
        None
    );
}

#[tokio::test]
async fn wallet_recovery_preserves_pending_and_unknown_attempt_records() {
    let (mut actor, root, _) = fixture().await;
    let directory = root.join("payments");
    std::fs::create_dir(&directory).unwrap();
    let mut originals = Vec::new();
    for (index, status) in ["Pending", "Checking outcome"].into_iter().enumerate() {
        let id = format!("{index:032x}");
        let record = json!({
            "schema":1,"network":"stagenet","wallet_identity":"a".repeat(64),
            "payment":{"id":id,"address":"7".repeat(95),"priority":"automatic","self_transfer":false,
                "amount_atomic":"100","fee_atomic":"10","total_atomic":"110","txid":"b".repeat(64),
                "created_at":1,"expires_at":120,"status":status,"confirmations":0,"checked_at":null},
            "metadata":"synthetic"
        });
        let bytes =
            autopilot_wallet_lab::platform::protect(&serde_json::to_vec(&record).unwrap()).unwrap();
        let path = directory.join(format!("{id}.dpapi"));
        std::fs::write(&path, &bytes).unwrap();
        let marker = directory.join(format!("{id}.attempt"));
        std::fs::write(&marker, b"synthetic attempted broadcast").unwrap();
        originals.push((path, bytes, marker));
    }
    actor.payments = Some(Sender::open(directory.clone()));
    let before = serde_json::to_value(&actor.payments.as_ref().unwrap().snapshot).unwrap();
    assert!(before["blocked"].as_bool().unwrap());
    assert_eq!(before["payments"].as_array().unwrap().len(), 2);
    // Reopening a journal treats both attempted states as unconfirmed until
    // reconciliation. Recovery must never turn either back into a preview.
    assert!(before["payments"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["status"] == "Checking outcome"));
    actor.hold = true; // Stop before native startup; no binaries, RPC, or relay.
    assert_eq!(
        actor.recover().await,
        Err("Lab fault is holding node startup offline.")
    );
    assert_eq!(
        serde_json::to_value(&actor.payments.as_ref().unwrap().snapshot).unwrap(),
        before
    );
    actor.policy.fail_closed();
    actor.state.node_synced = true;
    actor.state.wallet_status = "Synchronized".into();
    actor.stop_exhausted_wallet().await;
    assert_eq!(actor.policy.phase, Phase::Attention);
    assert!(!actor.state.node_synced);
    assert_eq!(actor.state.wallet_status, "Stopped");
    assert!(actor.supervisor.wallet.is_none());
    assert_eq!(
        serde_json::to_value(&actor.payments.as_ref().unwrap().snapshot).unwrap(),
        before
    );
    for (path, bytes, marker) in originals {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert_eq!(
            std::fs::read(marker).unwrap(),
            b"synthetic attempted broadcast"
        );
    }
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 4);
    drop(actor);
    cleanup(root);
}
