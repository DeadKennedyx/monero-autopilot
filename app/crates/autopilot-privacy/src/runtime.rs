//! Host adapter for the pure policy and recovery controller. The host serializes
//! calls with wallet lifecycle actions. No keys, spending, or wallet recreation
//! occur here. A new gateway generation always requires a safe backend reopen.
use crate::{
    config::{Config, ConfigStore, Profile},
    gateway::{BroadcastPermit, Gateway},
    node::{NodeHealth, NodeManager},
    policy::RouteKind,
    recovery::{ConnectionState, RecoveryController, RecoveryStatus},
    transport::RoutedClient,
    Denial, Result,
};
use serde::Serialize;
use std::{
    net::SocketAddr,
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportStatus {
    Unavailable,
    Checking,
    Ready,
}
#[derive(Clone, Serialize)]
pub struct PrivacyStatus {
    pub profile: Profile,
    pub recovery: RecoveryStatus,
    pub transport: TransportStatus,
    pub route: Option<RouteKind>,
    pub node_id: Option<String>,
    pub health: Option<NodeHealth>,
    pub operations_allowed: bool,
}
/// Private native-process connection material. Do not serialize or log this.
pub struct BackendEndpoint {
    network: crate::config::Network,
    address: SocketAddr,
    username: String,
    password: Zeroizing<String>,
    generation: u64,
    issued: Instant,
    cancellation: CancellationToken,
}
impl BackendEndpoint {
    pub fn network(&self) -> crate::config::Network {
        self.network
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> &str {
        self.password.as_str()
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn current(&self) -> bool {
        !self.cancellation.is_cancelled()
            && self.issued.elapsed() < std::time::Duration::from_secs(15)
    }
    pub fn revoked(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}
pub struct RouteManager {
    managed_proxy: Option<crate::endpoint::ProxyEndpoint>,
    controller: RecoveryController,
    nodes: NodeManager,
    gateway: Option<Gateway>,
    clock: Instant,
    cancellation: CancellationToken,
    updates: watch::Sender<PrivacyStatus>,
}
impl RouteManager {
    pub fn new(config: Config) -> Result<Self> {
        let controller = RecoveryController::new(config)?;
        let (updates, _) = watch::channel(PrivacyStatus {
            profile: controller.config().profile,
            recovery: controller.status().clone(),
            transport: TransportStatus::Unavailable,
            route: None,
            node_id: None,
            health: None,
            operations_allowed: false,
        });
        Ok(Self {
            managed_proxy: None,
            controller,
            nodes: NodeManager::default(),
            gateway: None,
            clock: Instant::now(),
            cancellation: CancellationToken::new(),
            updates,
        })
    }
    /// Unknown or damaged settings never fall back to a permissive default.
    pub fn open(directory: &Path) -> Result<Self> {
        let store = ConfigStore::new(directory);
        let config = store.load()?;
        store.save(&config)?;
        Self::new(config)
    }
    pub fn config(&self) -> &Config {
        self.controller.config()
    }
    pub fn subscribe(&self) -> watch::Receiver<PrivacyStatus> {
        self.updates.subscribe()
    }
    pub fn snapshot(&self) -> PrivacyStatus {
        let status = self.gateway.as_ref().and_then(|g| g.status().ok());
        let healthy = status.as_ref().is_some_and(|g| g.blocked.is_none());
        let mut recovery = self.controller.status().clone();
        // Consumers must see stale/failed routes immediately, even between host ticks.
        if recovery.state == ConnectionState::Connected && !healthy {
            recovery.state = ConnectionState::Degraded;
            recovery.last_error = status
                .as_ref()
                .and_then(|g| g.blocked)
                .or(Some(Denial::Stale));
            recovery.last_action = "Connection lost; privacy settings are unchanged";
        }
        PrivacyStatus {
            profile: self.config().profile,
            transport: if healthy {
                TransportStatus::Ready
            } else if matches!(
                recovery.state,
                ConnectionState::InitializingTransport
                    | ConnectionState::Connecting
                    | ConnectionState::Validating
            ) {
                TransportStatus::Checking
            } else {
                TransportStatus::Unavailable
            },
            operations_allowed: healthy && self.controller.operations_allowed(self.millis()),
            recovery,
            route: self.controller.active().map(|p| p.route()),
            node_id: self.controller.active().map(|p| p.node_id().to_owned()),
            health: status.map(|g| g.node),
        }
    }
    fn publish(&self) {
        self.updates.send_replace(self.snapshot());
    }
    fn millis(&self) -> u64 {
        self.clock.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    fn revoke(&mut self) {
        self.cancellation.cancel();
        if let Some(gateway) = self.gateway.take() {
            gateway.revoke();
        }
    }
    pub fn start(&mut self) {
        self.revoke();
        self.cancellation = CancellationToken::new();
        self.controller.start(self.millis());
        self.publish();
    }
    pub fn stop(&mut self) {
        self.revoke();
        self.controller.disconnect();
        self.publish();
    }
    /// Revoke the old route before exposing a replacement owned Tor process.
    pub fn set_managed_proxy(&mut self, proxy: Option<crate::endpoint::ProxyEndpoint>) {
        if self.managed_proxy == proxy {
            return;
        }
        self.managed_proxy = proxy;
        if self.gateway.is_some() {
            self.fail(Denial::ProxyUnavailable);
        }
    }
    pub fn block_transport(&mut self) {
        self.revoke();
        self.controller.block(Denial::ProxyUnavailable);
        self.publish();
    }
    /// UI/host must authenticate this action and obtain explicit consent where
    /// required. Validate and persist before adopting the new intent. Stay offline.
    pub fn save_configuration(
        &mut self,
        directory: &Path,
        next: Config,
        consent: bool,
    ) -> Result<()> {
        self.config().validate_change(&next, consent)?;
        self.revoke();
        if let Err(e) = ConfigStore::new(directory).save(&next) {
            self.controller.block(e);
            self.publish();
            return Err(e);
        }
        self.controller.replace_config(next, consent)?;
        self.nodes.clear();
        self.publish();
        Ok(())
    }
    pub fn backend_exited(&mut self) {
        if matches!(
            self.controller.status().state,
            ConnectionState::Disconnected | ConnectionState::PrivacyBlocked
        ) {
            return;
        }
        self.fail(Denial::BackendExited);
    }
    fn fail(&mut self, error: Denial) {
        self.revoke();
        self.controller.degrade(error);
        self.publish();
        let jitter = uuid::Uuid::new_v4().as_u128() as u64;
        self.controller.failed(error, self.millis(), jitter);
        self.publish();
    }
    /// Call periodically while enabled. Six bounded attempts, then explicit retry.
    /// A caller cancelling this future must call stop() before reusing the manager.
    pub async fn tick(&mut self) -> Result<()> {
        if let Some(gateway) = &self.gateway {
            match gateway.status()? {
                status if status.blocked.is_none() => {
                    self.controller.healthy(self.millis());
                    self.publish();
                    return Ok(());
                }
                status => {
                    self.fail(status.blocked.unwrap_or(Denial::Stale));
                    return Ok(());
                }
            }
        }
        if self.config().profile != Profile::Balanced {
            self.controller.block(Denial::LocalEgressUnverified);
            self.publish();
            return Err(Denial::LocalEgressUnverified);
        }
        let plan = match self
            .controller
            .begin_due_with_managed_proxy(self.millis(), self.managed_proxy)
        {
            Ok(Some(plan)) => plan,
            Ok(None) => return Ok(()),
            Err(e) => {
                self.publish();
                return Err(e);
            }
        };
        self.cancellation = CancellationToken::new();
        self.publish();
        let result = self.connect(plan).await;
        if let Err(error) = result {
            self.fail(error);
            return Err(error);
        }
        self.publish();
        Ok(())
    }
    async fn connect(&mut self, plan: crate::policy::RoutePlan) -> Result<()> {
        let generation = self.controller.status().generation;
        let client = RoutedClient::new(plan, self.cancellation.clone())?;
        client.check_socks().await?;
        self.controller.transport_ready(generation)?;
        self.publish();
        self.controller.validating(generation)?;
        self.publish();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let connection = self
            .nodes
            .validate(client, self.config().network, now)
            .await?;
        self.gateway = Some(Gateway::start(connection).await?);
        self.controller.connected(generation, self.millis())?;
        Ok(())
    }
    pub fn endpoint(&self) -> Result<BackendEndpoint> {
        if !self.snapshot().operations_allowed {
            return Err(Denial::Stale);
        }
        let gateway = self.gateway.as_ref().ok_or(Denial::NodeNotReady)?;
        let (username, password) = gateway.credentials();
        Ok(BackendEndpoint {
            network: self.config().network,
            address: gateway.address(),
            username: username.to_owned(),
            password: Zeroizing::new(password.to_owned()),
            generation: self.controller.status().generation,
            issued: Instant::now(),
            cancellation: self.cancellation.clone(),
        })
    }
    /// The caller first persists the send attempt after checking its PIN/session.
    /// This permit only enables the already-authorized relay call, never spending.
    pub fn authorize_one_broadcast(&self, generation: u64) -> Result<BroadcastPermit> {
        if self.controller.status().generation != generation {
            return Err(Denial::PolicyChanged);
        }
        if !self.snapshot().operations_allowed {
            return Err(Denial::Stale);
        }
        self.gateway
            .as_ref()
            .ok_or(Denial::NodeNotReady)?
            .authorize_one_broadcast()
    }
}
impl Drop for RouteManager {
    fn drop(&mut self) {
        self.revoke();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn default_cannot_connect_without_approved_routes_and_restart_keeps_policy() {
        let directory = tempfile::tempdir().unwrap();
        let mut router = RouteManager::open(directory.path()).unwrap();
        router.start();
        assert_eq!(router.tick().await, Err(Denial::NoPermittedNodes));
        assert_eq!(
            router.snapshot().recovery.state,
            ConnectionState::PrivacyBlocked
        );
        assert!(!router.snapshot().operations_allowed);
        assert!(router.endpoint().is_err());
        assert!(router.authorize_one_broadcast(0).is_err());
        drop(router);
        let router = RouteManager::open(directory.path()).unwrap();
        assert_eq!(router.config().profile, Profile::Balanced);
        assert_eq!(
            router.snapshot().recovery.state,
            ConnectionState::Disconnected
        );
        assert!(!router.snapshot().operations_allowed);
    }
    #[tokio::test]
    async fn actual_failover_excludes_wrong_network_and_never_contacts_unapproved_nodes() {
        use crate::{
            config::{ApprovedNode, Ownership},
            endpoint::{onion, ProxyEndpoint},
            gateway::tests::setup,
        };
        use std::sync::atomic::Ordering;
        let fixture = setup().await;
        *fixture.state.wrong_host.lock().unwrap() = Some(onion(3));
        let node = |id: char, host: u8, approved| ApprovedNode {
            id: id.to_string().repeat(32),
            label: "Controlled fixture".into(),
            endpoint: format!("http://{}:38081", onion(host)),
            ownership: Ownership::Personal,
            approved,
            enabled: true,
        };
        let config = Config {
            managed_tor: false,
            tor_proxy: Some(ProxyEndpoint::parse(&fixture._proxy.address.to_string()).unwrap()),
            nodes: vec![node('a', 3, true), node('b', 2, true), node('c', 4, false)],
            ..Config::default()
        };
        let mut router = RouteManager::new(config).unwrap();
        router.start();
        assert_eq!(router.tick().await, Err(Denial::WrongNetwork));
        assert_eq!(
            router.snapshot().recovery.state,
            ConnectionState::Recovering
        );
        assert!(router.endpoint().is_err());
        router.clock -= std::time::Duration::from_secs(3);
        router.tick().await.unwrap();
        assert_eq!(router.snapshot().node_id, Some("b".repeat(32)));
        assert!(router.snapshot().operations_allowed);
        assert_eq!(router.snapshot().transport, TransportStatus::Ready);
        let endpoint = router.endpoint().unwrap();
        let _permission = router
            .authorize_one_broadcast(endpoint.generation())
            .unwrap();
        router.backend_exited();
        assert!(endpoint.revoked());
        assert!(router
            .authorize_one_broadcast(endpoint.generation())
            .is_err());
        assert!(!router.snapshot().operations_allowed);
        assert_eq!(router.config().profile, Profile::Balanced);
        let targets = fixture._proxy.targets.lock().unwrap();
        assert!(targets
            .iter()
            .all(|(host, _)| host == &onion(2) || host == &onion(3)));
        assert!(fixture.state.calls.load(Ordering::SeqCst) >= 7);
        drop(targets);
        router.stop();
        assert_eq!(
            router.snapshot().recovery.state,
            ConnectionState::Disconnected
        );
    }
    #[tokio::test]
    async fn configured_i2p_requires_a_working_socks_tunnel_and_full_node_validation() {
        use crate::{
            config::{ApprovedNode, Ownership},
            endpoint::ProxyEndpoint,
            gateway::tests::setup,
        };
        let fixture = setup().await;
        let endpoint = format!("http://{}.b32.i2p:38081", "a".repeat(52));
        let config = Config {
            i2p_proxy: Some(ProxyEndpoint::parse(&fixture._proxy.address.to_string()).unwrap()),
            nodes: vec![ApprovedNode {
                id: "d".repeat(32),
                label: "Configured I2P fixture".into(),
                endpoint,
                ownership: Ownership::Personal,
                approved: true,
                enabled: true,
            }],
            ..Default::default()
        };
        let mut router = RouteManager::new(config).unwrap();
        router.start();
        router.tick().await.unwrap();
        assert_eq!(router.snapshot().route, Some(RouteKind::I2p));
        assert_eq!(router.snapshot().transport, TransportStatus::Ready);
        assert!(router.endpoint().is_ok());
        assert!(fixture
            ._proxy
            .targets
            .lock()
            .unwrap()
            .iter()
            .any(|(host, _)| host.ends_with(".b32.i2p")));
        router.stop();
        let mut config = router.config().clone();
        config.i2p_proxy = None;
        let mut disabled = RouteManager::new(config).unwrap();
        disabled.start();
        assert_eq!(disabled.tick().await, Err(Denial::NoPermittedNodes));
        assert_eq!(disabled.snapshot().transport, TransportStatus::Unavailable);
    }
}
