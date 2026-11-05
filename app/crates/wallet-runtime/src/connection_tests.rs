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
