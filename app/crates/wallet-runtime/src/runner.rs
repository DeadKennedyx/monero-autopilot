use crate::privacy::{PrivacyCommand, PrivacyReply, RelationshipCommand};
use crate::receive::{self, ReceiveSnapshot};
use crate::relationships::{Relationship, RelationshipBook};
use crate::security::{Security, SecurityCommand, SecurityReply, SecuritySnapshot};
use crate::send::{SendCommand, SendSnapshot, Sender};
use crate::setup::{Catalog, SetupCommand, SetupReply, WalletSetup};
use autopilot_privacy::{
    config::{Config as PrivacyConfig, Network, Profile},
    node::NodeHealth,
    policy::RouteKind,
    recovery::{ConnectionState, RecoveryStatus},
    runtime::{PrivacyStatus, RouteManager, TransportStatus},
};
use autopilot_wallet_lab::{
    supervisor::Supervisor,
    tor::{ManagedTor, TorSnapshot, TorState},
    LabResult, VERSION,
};
use monero_autopilot_core::local_recovery::{LocalRecovery, Phase};
use monero_autopilot_core::wallet_liveness::{MissingResponse, WalletLiveness};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, oneshot, RwLock},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
#[path = "connection_tests.rs"]
mod connection_tests;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    Start,
    Stop,
    Retry,
    CrashNode,
    HoldNodeOffline,
    NewAddress,
    RefreshBalance,
    TestRecipient,
}
#[derive(Clone, Serialize)]
pub struct Event {
    pub seq: u64,
    pub time: u64,
    pub message: String,
}
#[derive(Clone, Serialize)]
pub struct Snapshot {
    pub version: &'static str,
    pub network: &'static str,
    pub phase: String,
    pub busy: bool,
    pub operation: String,
    pub attempts: u8,
    pub recoveries: u32,
    pub retry_in_ms: Option<u64>,
    pub fault_held: bool,
    pub error: Option<String>,
    pub last_issue: Option<String>,
    pub node_pid: Option<u32>,
    pub wallet_pid: Option<u32>,
    pub node_height: Option<u64>,
    pub node_target: Option<u64>,
    pub node_synced: bool,
    pub peers: u64,
    pub wallet_height: Option<u64>,
    pub wallet_id: Option<String>,
    pub wallet_status: String,
    pub node_sample_at: Option<u64>,
    pub wallet_sample_at: Option<u64>,
    pub saved_height: Option<u64>,
    pub saved_at: Option<u64>,
    pub database_bytes: u64,
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive: Option<ReceiveSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send: Option<SendSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_recipient: Option<ReceiveSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<Catalog>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<SecuritySnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy: Option<PrivacyStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_config: Option<PrivacyConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundled_tor: Option<TorSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<Vec<Relationship>>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            version: VERSION,
            network: "stagenet",
            phase: "Stopped".into(),
            busy: false,
            operation: String::new(),
            attempts: 0,
            recoveries: 0,
            retry_in_ms: None,
            fault_held: false,
            error: None,
            last_issue: None,
            node_pid: None,
            wallet_pid: None,
            node_height: None,
            node_target: None,
            node_synced: false,
            peers: 0,
            wallet_height: None,
            wallet_id: None,
            wallet_status: "Stopped".into(),
            node_sample_at: None,
            wallet_sample_at: None,
            saved_height: None,
            saved_at: None,
            database_bytes: 0,
            events: vec![],
            receive: None,
            send: None,
            test_recipient: None,
            setup: None,
            security: None,
            privacy: None,
            privacy_config: None,
            bundled_tor: None,
            relationships: None,
        }
    }
}
impl Snapshot {
    pub fn refresh_receive_status(&mut self) {
        if let Some(privacy) = &mut self.privacy {
            let fresh = privacy.health.as_ref().is_some_and(|h| {
                unix_time() >= h.checked_at
                    && unix_time() - h.checked_at <= autopilot_privacy::NODE_HEALTH_FRESH_SECS
            });
            if privacy.operations_allowed && !fresh {
                privacy.operations_allowed = false;
                privacy.recovery.state = ConnectionState::Degraded;
                privacy.recovery.last_error = Some(autopilot_privacy::Denial::Stale);
                privacy.transport = TransportStatus::Unavailable;
            }
        }
        if let Some(data) = &mut self.receive {
            data.current = receive::is_current(
                self.phase == "Connected"
                    && self.wallet_status == "Synchronized"
                    && self.node_synced
                    && self.privacy.as_ref().is_none_or(|p| p.operations_allowed),
                self.node_height,
                self.wallet_height,
                self.node_sample_at,
                self.wallet_sample_at,
                data,
                unix_time(),
            );
        }
    }
}
fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn verify_wallet_resume(
    expected: Option<&str>,
    actual: &str,
    saved_height: Option<u64>,
    height: u64,
) -> LabResult<()> {
    if expected.is_some_and(|value| value != actual) {
        return Err("Wallet identity changed. Recovery stopped for review.");
    }
    if saved_height.is_some_and(|floor| height < floor) {
        return Err("Wallet opened below the confirmed saved height. Recovery stopped for review.");
    }
    Ok(())
}
struct Request {
    action: Action,
    cancel: CancellationToken,
    permit: Option<u64>,
}
enum Action {
    Lifecycle(Command),
    Send(SendCommand),
    Setup(SetupCommand, oneshot::Sender<LabResult<SetupReply>>),
    Privacy(PrivacyCommand, oneshot::Sender<LabResult<PrivacyReply>>),
    Relationship(
        RelationshipCommand,
        oneshot::Sender<LabResult<Relationship>>,
    ),
}
impl Action {
    fn reject(self, error: &'static str) {
        match self {
            Self::Setup(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Privacy(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Relationship(_, reply) => {
                let _ = reply.send(Err(error));
            }
            _ => (),
        }
    }
}
#[derive(Clone)]
pub struct Client {
    pub state: Arc<RwLock<Snapshot>>,
    pub shutdown: CancellationToken,
    pub finished: CancellationToken,
    sender: mpsc::Sender<Request>,
    cancel: Arc<Mutex<CancellationToken>>,
    busy: Arc<AtomicBool>,
    receive_enabled: bool,
    send_enabled: bool,
    setup_enabled: bool,
    managing: Arc<AtomicBool>,
    pub security: Option<Security>,
    privacy_enabled: bool,
    network: Network,
}
impl Client {
    async fn enqueue_private(&self, action: Action, permit: Option<u64>) -> LabResult<()> {
        self.check_permit(permit).await?;
        if !self.privacy_enabled || self.security.is_none() || self.shutdown.is_cancelled() {
            return Err("Privacy controls are unavailable here.");
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("Wait for the current wallet operation to finish.");
        }
        if self
            .sender
            .try_send(Request {
                action,
                permit,
                cancel: CancellationToken::new(),
            })
            .is_err()
        {
            self.busy.store(false, Ordering::SeqCst);
            return Err("The control queue is unavailable.");
        }
        Ok(())
    }
    pub async fn privacy_authorized(
        &self,
        command: PrivacyCommand,
        permit: Option<u64>,
    ) -> LabResult<PrivacyReply> {
        // Connect expresses the desired state; it is not a request to restart
        // an already active wallet/Tor session. Acknowledge repeated clicks even
        // while the actor is occupied by a bounded startup or recovery call.
        self.check_permit(permit).await?;
        if !self.privacy_enabled || self.security.is_none() || self.shutdown.is_cancelled() {
            return Err("Privacy controls are unavailable here.");
        }
        if matches!(command, PrivacyCommand::Connect)
            && !self.managing.load(Ordering::SeqCst)
            && !self
                .cancel
                .lock()
                .map_err(|_| "Control state is unavailable.")?
                .is_cancelled()
        {
            let existing = {
                let state = self.state.read().await;
                state
                    .privacy
                    .as_ref()
                    .filter(|status| connect_is_active(&state.phase, status))
                    .zip(state.privacy_config.as_ref())
                    .map(|(status, config)| PrivacyReply {
                        status: status.clone(),
                        config: config.clone(),
                    })
            };
            if let Some(reply) = existing {
                // Taking the snapshot must not outlive a PIN/session revocation.
                self.check_permit(permit).await?;
                return Ok(reply);
            }
        }
        let (reply, result) = oneshot::channel();
        self.enqueue_private(Action::Privacy(command, reply), permit)
            .await?;
        result
            .await
            .map_err(|_| "Privacy settings operation was interrupted.")?
    }
    pub async fn relationship_authorized(
        &self,
        command: RelationshipCommand,
        permit: Option<u64>,
    ) -> LabResult<Relationship> {
        if self.network == Network::Mainnet {
            return Err("Address relationships are outside this setup prototype.");
        }
        if command.name.chars().count() > 60 {
            return Err("Relationship name is too long.");
        }
        let (reply, result) = oneshot::channel();
        self.enqueue_private(Action::Relationship(command, reply), permit)
            .await?;
        result
            .await
            .map_err(|_| "Address operation was interrupted. Retry the same relationship name.")?
    }
    pub async fn command(&self, command: Command) -> LabResult<()> {
        self.command_authorized(command, None).await
    }
    pub async fn authorize(&self, session: Option<&str>) -> LabResult<Option<u64>> {
        match &self.security {
            Some(s) => s.permit(session).await.map(Some),
            None => Ok(None),
        }
    }
    async fn check_permit(&self, permit: Option<u64>) -> LabResult<()> {
        if let Some(s) = &self.security {
            s.check(permit).await?;
        }
        Ok(())
    }
    pub async fn security_command(
        &self,
        command: SecurityCommand,
        session: Option<&str>,
    ) -> LabResult<SecurityReply> {
        if self.shutdown.is_cancelled() {
            return Err("The app is closing.");
        }
        self.security
            .as_ref()
            .ok_or("PIN protection is not enabled in this application.")?
            .execute(command, session)
            .await
    }
    pub async fn command_authorized(&self, command: Command, permit: Option<u64>) -> LabResult<()> {
        self.check_permit(permit).await?;
        if self.network == Network::Mainnet
            && matches!(
                command,
                Command::TestRecipient | Command::CrashNode | Command::HoldNodeOffline
            )
        {
            return Err("That action is outside this mainnet setup prototype.");
        }
        if self.managing.load(Ordering::SeqCst) {
            return Err("Wallet setup is in progress.");
        }
        if matches!(command, Command::Start | Command::Retry)
            && self.setup_enabled
            && self
                .state
                .read()
                .await
                .setup
                .as_ref()
                .is_some_and(|s| s.active.is_none())
        {
            return Err("Create or restore a wallet first.");
        }
        if self.shutdown.is_cancelled() {
            return Err("The application is closing.");
        }
        if matches!(command, Command::Stop) {
            self.cancel
                .lock()
                .map_err(|_| "Control state unavailable.")?
                .cancel();
            return Ok(());
        }
        let s = self.state.read().await;
        let allowed = match command {
            Command::TestRecipient => self.send_enabled && s.phase == "Connected",
            Command::NewAddress | Command::RefreshBalance => {
                self.receive_enabled && s.phase == "Connected" && s.wallet_id.is_some()
            }
            Command::Start => s.phase == "Stopped",
            Command::Retry => s.phase == "Needs attention",
            Command::CrashNode | Command::HoldNodeOffline => {
                s.phase == "Connected" && s.node_pid.is_some() && s.wallet_id.is_some()
            }
            Command::Stop => true,
        };
        if !allowed {
            return Err("That action is not available in the current state.");
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("A process operation is already pending.");
        }
        drop(s);
        let mut current = self
            .cancel
            .lock()
            .map_err(|_| "Control state unavailable.")?;
        if matches!(command, Command::Start | Command::Retry) {
            *current = CancellationToken::new();
        }
        let request = Request {
            action: Action::Lifecycle(command),
            cancel: current.clone(),
            permit,
        };
        if self.sender.try_send(request).is_err() {
            self.busy.store(false, Ordering::SeqCst);
            return Err("The control queue is unavailable.");
        }
        Ok(())
    }
    pub async fn send(&self, command: SendCommand) -> LabResult<()> {
        self.send_authorized(command, None).await
    }
    pub async fn send_authorized(
        &self,
        command: SendCommand,
        permit: Option<u64>,
    ) -> LabResult<()> {
        self.check_permit(permit).await?;
        if self.managing.load(Ordering::SeqCst) {
            return Err("Wallet setup is in progress.");
        }
        if !self.send_enabled || self.shutdown.is_cancelled() {
            return Err("Sending is unavailable in this application.");
        }
        let mut snapshot = self.state.read().await.clone();
        snapshot.refresh_receive_status();
        if snapshot.phase != "Connected" || !snapshot.receive.as_ref().is_some_and(|r| r.current) {
            return Err("Wait for the wallet to connect and show a current balance.");
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("Another wallet operation is in progress.");
        }
        let cancel = self
            .cancel
            .lock()
            .map_err(|_| "Control state unavailable.")?
            .clone();
        if self
            .sender
            .try_send(Request {
                action: Action::Send(command),
                cancel,
                permit,
            })
            .is_err()
        {
            self.busy.store(false, Ordering::SeqCst);
            return Err("The control queue is unavailable.");
        }
        Ok(())
    }
    pub async fn setup(&self, command: SetupCommand) -> LabResult<SetupReply> {
        self.setup_authorized(command, None).await
    }
    pub async fn setup_authorized(
        &self,
        command: SetupCommand,
        permit: Option<u64>,
    ) -> LabResult<SetupReply> {
        self.check_permit(permit).await?;
        if !self.setup_enabled || self.shutdown.is_cancelled() {
            return Err("Wallet setup is unavailable here.");
        }
        command.validate_for(self.network)?;
        if self
            .managing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("Wallet setup is already in progress.");
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.managing.store(false, Ordering::SeqCst);
            return Err("Wait for the current wallet operation to finish.");
        }
        let (sender, receiver) = oneshot::channel();
        if self
            .sender
            .try_send(Request {
                action: Action::Setup(command, sender),
                cancel: CancellationToken::new(),
                permit,
            })
            .is_err()
        {
            self.busy.store(false, Ordering::SeqCst);
            self.managing.store(false, Ordering::SeqCst);
            return Err("The control queue is unavailable.");
        }
        receiver.await.map_err(|_| {
            "Wallet setup was interrupted. Check your saved wallets before retrying."
        })?
    }
}
fn connect_is_active(phase: &str, status: &PrivacyStatus) -> bool {
    !matches!(phase, "Needs attention" | "Stopping" | "Locked")
        && !matches!(
            status.recovery.state,
            ConnectionState::Disconnected | ConnectionState::PrivacyBlocked
        )
}
fn observed_wallet_height(value: &serde_json::Value, node_height: Option<u64>) -> Option<u64> {
    value["height"].as_u64().filter(|height| {
        *height <= 100_000_000 && node_height.is_none_or(|node| *height <= node.saturating_add(2))
    })
}
fn wallet_observation(
    node_ok: bool,
    wallet_alive: bool,
    wallet_responded: bool,
    missing: MissingResponse,
    remote_route: bool,
) -> Option<bool> {
    if !wallet_alive {
        Some(false)
    } else if !node_ok {
        // The remote route has its own bounded recovery controller. Its outage
        // must not be charged as a wallet responsiveness failure as well.
        if remote_route {
            None
        } else {
            Some(false)
        }
    } else if wallet_responded {
        Some(true)
    } else if missing == MissingResponse::Unresponsive {
        Some(false)
    } else {
        None
    }
}
pub struct Runtime {
    pub client: Client,
    task: Option<JoinHandle<()>>,
}
impl Runtime {
    pub async fn start(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::start_inner(root, binaries, false, false, false, None, false).await
    }
    pub async fn start_with_receive(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::start_inner(root, binaries, true, false, false, None, false).await
    }
    pub async fn start_with_send(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::start_inner(root, binaries, true, true, false, None, false).await
    }
    pub async fn start_with_setup(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::start_inner(root, binaries, true, true, true, None, false).await
    }
    pub async fn start_with_security(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::start_inner(root, binaries, true, true, true, Some("security"), false).await
    }
    pub async fn start_with_privacy(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::start_inner(root, binaries, true, true, true, Some("security"), true).await
    }
    /// Isolated mainnet prototype with PIN-authorized payments over the pinned owned route.
    pub async fn start_mainnet(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::start_network(
            root,
            binaries,
            true,
            true,
            true,
            Some("security"),
            true,
            Network::Mainnet,
        )
        .await
    }
    pub async fn start_security_prototype(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        if root.join("security/configured").exists() || root.join("security/pin.dpapi").exists() {
            return Err("Use the PIN-protected main app for this wallet. The development prototype cannot bypass its PIN.");
        }
        Self::start_inner(
            root,
            binaries,
            true,
            true,
            true,
            Some("security-prototype"),
            false,
        )
        .await
    }
    async fn start_inner(
        root: PathBuf,
        binaries: PathBuf,
        receive_enabled: bool,
        send_enabled: bool,
        setup_enabled: bool,
        security_directory: Option<&str>,
        privacy_enabled: bool,
    ) -> LabResult<Self> {
        Self::start_network(
            root,
            binaries,
            receive_enabled,
            send_enabled,
            setup_enabled,
            security_directory,
            privacy_enabled,
            Network::Stagenet,
        )
        .await
    }
    async fn start_network(
        root: PathBuf,
        binaries: PathBuf,
        receive_enabled: bool,
        send_enabled: bool,
        setup_enabled: bool,
        security_directory: Option<&str>,
        privacy_enabled: bool,
        network: Network,
    ) -> LabResult<Self> {
        let mut supervisor = if network == Network::Mainnet {
            Supervisor::new_mainnet(root, binaries, crate::mainnet::config()).await?
        } else if privacy_enabled {
            Supervisor::new_guarded(root, binaries).await?
        } else if security_directory.is_some() {
            Supervisor::new_secured(root, binaries).await?
        } else {
            Supervisor::new(root, binaries).await?
        };
        let security = if let Some(directory) = security_directory {
            Some(Security::open(supervisor.root.join(directory)).await?)
        } else {
            None
        };
        let privacy = if privacy_enabled {
            Some(RouteManager::open(&supervisor.root.join("privacy")).map_err(|e| e.message())?)
        } else {
            None
        };
        let setup = if setup_enabled {
            Some(WalletSetup::load_for(&supervisor.root, network)?)
        } else {
            None
        };
        if let Some(manager) = &setup {
            supervisor.wallet_root = manager.active_root();
        }
        let state = Arc::new(RwLock::new(Snapshot {
            network: network.as_str(),
            database_bytes: supervisor.database_bytes(),
            setup: setup.as_ref().map(|m| m.catalog.clone()),
            ..Snapshot::default()
        }));
        let (sender, receiver) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let client = Client {
            state,
            sender,
            cancel: Arc::new(Mutex::new(cancel.clone())),
            busy: Arc::new(AtomicBool::new(false)),
            shutdown: CancellationToken::new(),
            finished: CancellationToken::new(),
            receive_enabled,
            send_enabled,
            setup_enabled,
            managing: Arc::new(AtomicBool::new(false)),
            security,
            privacy_enabled,
            network,
        };
        let payments = send_enabled
            .then(|| Sender::open_for(supervisor.wallet_root.join("payments"), network));
        let managed_tor = ManagedTor::new(supervisor.root.join("managed-tor"));
        let actor = Actor {
            managed_tor,
            supervisor,
            client: client.clone(),
            receiver,
            cancel,
            policy: LocalRecovery::default(),
            wallet_liveness: WalletLiveness::default(),
            state: Snapshot {
                network: network.as_str(),
                receive: receive_enabled.then(ReceiveSnapshot::default),
                ..Snapshot::default()
            },
            clock: Instant::now(),
            expected_identity: None,
            next_save: Instant::now(),
            hold: false,
            next_receive: Instant::now(),
            payments,
            test_wallet: None,
            setup,
            privacy,
            relationships: None,
            selected_relationship: None,
        };
        let task = tokio::spawn(actor.run());
        Ok(Self {
            client,
            task: Some(task),
        })
    }
    pub async fn stop(mut self) {
        self.client.shutdown.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.client.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
struct Actor {
    managed_tor: ManagedTor,
    supervisor: Supervisor,
    client: Client,
    receiver: mpsc::Receiver<Request>,
    cancel: CancellationToken,
    policy: LocalRecovery,
    wallet_liveness: WalletLiveness,
    state: Snapshot,
    clock: Instant,
    expected_identity: Option<String>,
    next_save: Instant,
    hold: bool,
    next_receive: Instant,
    payments: Option<Sender>,
    test_wallet: Option<Supervisor>,
    setup: Option<WalletSetup>,
    privacy: Option<RouteManager>,
    relationships: Option<RelationshipBook>,
    selected_relationship: Option<Relationship>,
}
struct Finished(CancellationToken);
impl Drop for Finished {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn interruptible<T>(
    cancel: CancellationToken,
    shutdown: CancellationToken,
    future: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! { biased;
        _ = shutdown.cancelled() => None,
        _ = cancel.cancelled() => None,
        result = future => Some(result),
    }
}
impl Actor {
    fn uses_managed_tor(&self) -> bool {
        self.privacy.as_ref().is_some_and(|r| {
            r.config().profile == Profile::Balanced
                && r.config().managed_tor
                && r.config().nodes.iter().any(|n| {
                    n.approved
                        && n.enabled
                        && n.validate().is_ok_and(|e| {
                            e.kind() != autopilot_privacy::endpoint::EndpointKind::I2p
                        })
                })
        })
    }
    fn remote_privacy(&self) -> bool {
        self.privacy
            .as_ref()
            .is_some_and(|r| r.config().profile == Profile::Balanced)
    }
    fn remote_route_active(&self) -> bool {
        self.remote_privacy()
            && self
                .privacy
                .as_ref()
                .is_some_and(|r| r.snapshot().recovery.state != ConnectionState::Disconnected)
    }
    fn privacy_status(&self) -> Option<PrivacyStatus> {
        let router = self.privacy.as_ref()?;
        if router.config().profile == Profile::Balanced {
            let mut status = router.snapshot();
            if self.uses_managed_tor()
                && matches!(
                    self.managed_tor.snapshot().state,
                    TorState::Starting | TorState::Restarting
                )
                && !matches!(
                    status.recovery.state,
                    ConnectionState::Disconnected | ConnectionState::PrivacyBlocked
                )
            {
                status.recovery.state = ConnectionState::InitializingTransport;
                status.recovery.last_action="Starting built-in Tor; wallet operations remain offline until the node is validated";
                status.transport = TransportStatus::Checking;
                status.operations_allowed = false;
            }
            return Some(status);
        }
        let fresh = self
            .state
            .node_sample_at
            .is_some_and(|at| unix_time() >= at && unix_time() - at <= 15);
        let state = match self.policy.phase {
            Phase::Stopped if self.supervisor.daemon.is_some() => {
                if !fresh {
                    ConnectionState::Degraded
                } else if self.state.node_synced {
                    ConnectionState::Connected
                } else {
                    ConnectionState::Validating
                }
            }
            Phase::Stopped => ConnectionState::Disconnected,
            Phase::Monitoring => ConnectionState::Connected,
            Phase::Suspect => ConnectionState::Degraded,
            Phase::Waiting | Phase::Recovering => ConnectionState::Recovering,
            Phase::Attention => ConnectionState::PrivacyBlocked,
        };
        Some(PrivacyStatus {
            profile: Profile::LocalNode,
            recovery: RecoveryStatus {
                state,
                attempts: self.policy.attempts,
                retry_at_ms: self.policy.retry_at,
                last_error: if state == ConnectionState::PrivacyBlocked {
                    Some(autopilot_privacy::Denial::NodeNotReady)
                } else {
                    None
                },
                generation: 0,
                last_action: "Using the explicitly selected local node; its peer traffic is direct",
            },
            transport: TransportStatus::Unavailable,
            route: Some(RouteKind::LocalDirect),
            node_id: None,
            health: self.state.node_height.map(|height| NodeHealth {
                network: self.supervisor.network,
                height,
                target_height: self.state.node_target.unwrap_or(height),
                latency_ms: 0,
                checked_at: self.state.node_sample_at.unwrap_or(0),
                synchronized: self.state.node_synced,
                compared_with_other_node: false,
                top_hash: String::new(),
            }),
            operations_allowed: state == ConnectionState::Connected
                && fresh
                && self.state.node_synced,
        })
    }
    fn start_privacy(&mut self) {
        if self.remote_privacy() {
            if let Some(router) = &mut self.privacy {
                router.start();
            }
            if self.uses_managed_tor() {
                self.managed_tor.begin();
            }
        }
    }
    async fn tick_privacy(&mut self) -> autopilot_privacy::Result<()> {
        if self.uses_managed_tor() {
            self.managed_tor.tick();
            let proxy = self.managed_tor.proxy();
            let state = self.managed_tor.snapshot().state;
            if let Some(router) = &mut self.privacy {
                router.set_managed_proxy(proxy);
                if state == TorState::Failed {
                    router.block_transport();
                    return Err(autopilot_privacy::Denial::ProxyUnavailable);
                }
            }
            if proxy.is_none() {
                return Ok(());
            }
        }
        match &mut self.privacy {
            Some(router) => router.tick().await,
            None => Ok(()),
        }
    }
    async fn install_current_route(&mut self) -> LabResult<()> {
        let Some(router) = &self.privacy else {
            return Ok(());
        };
        if router.config().profile == Profile::LocalNode {
            self.supervisor.authorize_local_node(router.config())
        } else {
            self.supervisor
                .install_gateway(router.endpoint().map_err(|e| e.message())?)
        }
    }
    async fn wait_for_private_route(&mut self) -> LabResult<()> {
        if !self.remote_privacy() {
            return self.install_current_route().await;
        }
        self.start_privacy();
        // Keep setup requests inside the UI's 180-second request deadline.
        // Connect bootstraps Tor asynchronously before create/restore is needed.
        let deadline = Instant::now() + Duration::from_secs(150);
        loop {
            if self.client.shutdown.is_cancelled() || self.security_locked().await {
                return Err("Connection was cancelled while the wallet was locked or closing.");
            }
            let result = self.tick_privacy().await;
            let router = self
                .privacy
                .as_mut()
                .ok_or("Privacy Guard is unavailable.")?;
            let status = router.snapshot();
            self.publish().await;
            if status.operations_allowed {
                return self.install_current_route().await;
            }
            if status.recovery.state == ConnectionState::PrivacyBlocked {
                return Err(status
                    .recovery
                    .last_error
                    .unwrap_or(autopilot_privacy::Denial::NoPermittedNodes)
                    .message());
            }
            if Instant::now() >= deadline {
                return Err(
                    "Private connection setup exceeded its deadline. Your policy is unchanged.",
                );
            }
            if let Err(e) = result {
                self.state.last_issue = Some(e.message().into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    async fn privacy_action(
        &mut self,
        command: PrivacyCommand,
        permit: Option<u64>,
    ) -> LabResult<PrivacyReply> {
        match command {
            PrivacyCommand::Save {
                config,
                consent,
                pin,
            } => {
                if config.network != self.supervisor.network {
                    return Err("Network switching is not allowed in this data directory.");
                }
                if self.supervisor.network == Network::Mainnet {
                    return Err("This mainnet prototype uses only its pinned owned node through built-in Tor.");
                }
                let current = self
                    .privacy
                    .as_ref()
                    .ok_or("Privacy Guard is unavailable.")?;
                current
                    .config()
                    .validate_change(&config, consent)
                    .map_err(|e| e.message())?;
                self.client
                    .security
                    .as_ref()
                    .ok_or("PIN protection is required.")?
                    .verify_sensitive(permit, Some(&pin))
                    .await?;
                self.stop_session().await;
                self.client.check_permit(permit).await?;
                let directory = self.supervisor.root.join("privacy");
                self.privacy
                    .as_mut()
                    .ok_or("Privacy Guard is unavailable.")?
                    .save_configuration(&directory, config, consent)
                    .map_err(|e| e.message())?;
                self.event(
                    "Privacy settings saved. All future connections use the selected policy.",
                );
            }
            PrivacyCommand::Connect => {
                if let Some(status) = self.privacy_status() {
                    if self.policy.phase != Phase::Attention
                        && connect_is_active(&self.state.phase, &status)
                        && !self.cancel.is_cancelled()
                    {
                        return Ok(PrivacyReply {
                            status,
                            config: self
                                .privacy
                                .as_ref()
                                .ok_or("Privacy Guard is unavailable.")?
                                .config()
                                .clone(),
                        });
                    }
                }
                self.stop_session().await;
                self.client.check_permit(permit).await?;
                self.cancel = CancellationToken::new();
                if let Ok(mut token) = self.client.cancel.lock() {
                    *token = self.cancel.clone();
                }
                self.start_privacy();
                if self
                    .setup
                    .as_ref()
                    .is_some_and(|s| s.catalog.active.is_some())
                {
                    self.policy.start(self.millis());
                } else if self.uses_managed_tor() {
                    // Start asynchronously; bootstrap must not hold the API/UI.
                    let _ = self.tick_privacy().await;
                } else {
                    self.wait_for_private_route().await?;
                    if !self.remote_privacy() {
                        self.supervisor.start_node().await?;
                        let _ = self.observe().await;
                        self.state.last_issue = None;
                        self.state.wallet_status = "Choose or create a wallet".into();
                    }
                }
            }
            PrivacyCommand::Disconnect => self.stop_session().await,
        }
        Ok(PrivacyReply {
            status: self
                .privacy_status()
                .ok_or("Privacy Guard is unavailable.")?,
            config: self
                .privacy
                .as_ref()
                .ok_or("Privacy Guard is unavailable.")?
                .config()
                .clone(),
        })
    }
    async fn relationship_action(
        &mut self,
        command: RelationshipCommand,
    ) -> LabResult<Relationship> {
        if self.policy.phase != Phase::Monitoring {
            return Err("Unlock and connect the selected wallet before creating an address.");
        }
        let rpc = self
            .supervisor
            .wallet
            .as_ref()
            .ok_or("Wallet is unavailable.")?
            .rpc
            .clone();
        let book = self
            .relationships
            .as_mut()
            .ok_or("Relationship records are unavailable.")?;
        let address = book.assign(&rpc, &command.name).await?;
        if let Some(receive) = &mut self.state.receive {
            receive.address = address.address.clone();
            receive.address_index = address.address_index;
        }
        self.selected_relationship = Some(address.clone());
        Ok(address)
    }
    fn millis(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }
    fn event(&mut self, message: impl Into<String>) {
        let seq = self.state.events.last().map_or(1, |e| e.seq + 1);
        if self.state.events.len() == 80 {
            self.state.events.remove(0);
        }
        self.state.events.push(Event {
            seq,
            time: unix_time(),
            message: message.into(),
        });
    }
    async fn publish(&mut self) {
        self.state.phase = match self.policy.phase {
            Phase::Stopped => "Stopped",
            Phase::Monitoring => "Connected",
            Phase::Suspect => "Checking connection",
            Phase::Waiting => "Waiting to retry",
            Phase::Recovering => "Recovering",
            Phase::Attention => "Needs attention",
        }
        .into();
        self.state.busy = self.client.busy.load(Ordering::SeqCst);
        self.state.attempts = self.policy.attempts;
        self.state.recoveries = self.policy.recoveries;
        self.state.retry_in_ms = self
            .policy
            .retry_at
            .map(|at| at.saturating_sub(self.millis()));
        self.state.fault_held = self.hold;
        self.state.node_pid = self.supervisor.daemon_pid();
        self.state.wallet_pid = self.supervisor.wallet_pid();
        self.state.database_bytes = self.supervisor.database_bytes();
        self.state.privacy = self.privacy_status();
        self.state.privacy_config = self.privacy.as_ref().map(|r| r.config().clone());
        self.state.bundled_tor = self
            .privacy
            .as_ref()
            .filter(|r| r.config().managed_tor)
            .map(|_| self.managed_tor.snapshot());
        self.state.relationships = self.relationships.as_ref().map(|r| r.completed());
        self.state.refresh_receive_status();
        self.state.send = self.payments.as_ref().map(|p| p.snapshot.clone());
        self.state.setup = self.setup.as_ref().map(|m| m.catalog.clone());
        *self.client.state.write().await = self.state.clone();
    }
    async fn operation(&mut self, label: &str) {
        self.client.busy.store(true, Ordering::SeqCst);
        self.state.operation = label.into();
        self.event(label);
        self.publish().await;
    }
    async fn run(mut self) {
        let _finished = Finished(self.client.finished.clone());
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        self.event("Wallet ready. Connect to open the selected wallet.");
        self.publish().await;
        let security = self.client.security.clone();
        loop {
            tokio::select! { biased;
                _ = self.client.shutdown.cancelled() => break,
                _ = async {match &security {Some(s)=>s.changed.notified().await,None=>std::future::pending::<()>().await}} => {
                    self.security_transition().await;
                },
                _ = self.cancel.cancelled(), if self.policy.phase != Phase::Stopped => {
                    self.stop_session().await;
                },
                request = self.receiver.recv() => {
                    let Some(request) = request else { break; };
                    self.handle(request).await;
                },
                _ = timer.tick() => {
                    let result = interruptible(self.cancel.clone(), self.client.shutdown.clone(), self.tick()).await;
                    if result.is_none() && self.policy.phase != Phase::Stopped { self.stop_session().await; }
                    if self.security_locked().await && (self.supervisor.wallet.is_some() || self.policy.phase!=Phase::Stopped || self.remote_route_active()) {self.lock_session().await;}
                },
            }
        }
        self.cancel.cancel();
        self.stop_session().await;
        self.event("Wallet saved and owned processes stopped. Closing the host.");
        self.publish().await;
    }
    async fn handle(&mut self, request: Request) {
        if let Err(error) = self.client.check_permit(request.permit).await {
            request.action.reject(error);
            self.client.busy.store(false, Ordering::SeqCst);
            self.client.managing.store(false, Ordering::SeqCst);
            self.publish().await;
            return;
        }
        if request.cancel.is_cancelled() {
            request.action.reject("Queued operation was cancelled.");
            self.client.busy.store(false, Ordering::SeqCst);
            self.event("Queued action cancelled before execution.");
            self.publish().await;
            return;
        }
        let command = match request.action {
            Action::Privacy(command, reply) => {
                let mut result = self.privacy_action(command, request.permit).await;
                if let Err(e) = self.client.check_permit(request.permit).await {
                    result = Err(e);
                }
                if self.security_locked().await {
                    self.lock_session().await;
                }
                self.client.busy.store(false, Ordering::SeqCst);
                self.state.operation.clear();
                self.publish().await;
                let _ = reply.send(result);
                return;
            }
            Action::Relationship(command, reply) => {
                let mut result = self.relationship_action(command).await;
                if let Err(e) = self.client.check_permit(request.permit).await {
                    result = Err(e);
                }
                if self.security_locked().await {
                    self.lock_session().await;
                }
                self.client.busy.store(false, Ordering::SeqCst);
                self.state.operation.clear();
                self.publish().await;
                let _ = reply.send(result);
                return;
            }
            Action::Lifecycle(command) => command,
            Action::Setup(command, reply) => {
                let mut result = async {
                    if let (Some(security), SetupCommand::Reveal { pin, .. }) =
                        (&self.client.security, &command)
                    {
                        security
                            .verify_sensitive(request.permit, pin.as_ref())
                            .await?;
                    }
                    self.setup_action(&command).await
                }
                .await;
                if let Err(error) = self.client.check_permit(request.permit).await {
                    result = Err(error);
                }
                if self.security_locked().await {
                    self.lock_session().await;
                }
                self.client.busy.store(false, Ordering::SeqCst);
                self.client.managing.store(false, Ordering::SeqCst);
                self.state.operation.clear();
                self.publish().await;
                let _ = reply.send(result);
                return;
            }
            Action::Send(command) => {
                if let Some(payments) = &mut self.payments {
                    payments.clear_action_error();
                }
                if matches!(&command, SendCommand::Prepare { .. }) {
                    if let Some(payments) = &mut self.payments {
                        payments.clear_rejected_fee();
                    }
                }
                self.operation("Checking payment details").await;
                // A broadcast is bounded but is never cancelled halfway and replayed.
                // Stop waits for its durable outcome marker, then performs cleanup.
                if let Err(error) = self.send_action(command, request.permit).await {
                    if let Some(payments) = &mut self.payments {
                        payments.set_error(error);
                    }
                    self.event(error);
                }
                self.client.busy.store(false, Ordering::SeqCst);
                self.state.operation.clear();
                if self.security_locked().await {
                    self.lock_session().await;
                }
                self.publish().await;
                return;
            }
        };
        match command {
            Command::TestRecipient => {
                self.operation("Opening the controlled second stagenet test wallet")
                    .await;
                if let Err(error) = self.test_recipient().await {
                    self.state.error = Some(error.into());
                    self.event(error);
                }
            }
            Command::NewAddress | Command::RefreshBalance => {
                if self.client.receive_enabled && self.policy.phase == Phase::Monitoring {
                    let create = matches!(command, Command::NewAddress);
                    self.operation(if create {
                        "Creating and saving a new receiving address"
                    } else {
                        "Checking incoming payments and balances"
                    })
                    .await;
                    let result = interruptible(
                        self.cancel.clone(),
                        self.client.shutdown.clone(),
                        self.receive_action(create),
                    )
                    .await;
                    match result {
                        Some(Ok(())) => (),
                        Some(Err(error)) => {
                            if let Some(data) = &mut self.state.receive {
                                data.error = Some(error.into());
                            }
                            self.event(error);
                        }
                        None => {
                            self.stop_session().await;
                            return;
                        }
                    }
                }
            }
            Command::Start | Command::Retry => {
                self.cancel = request.cancel;
                self.hold = false;
                self.state.error = None;
                self.state.last_issue = None;
                self.policy.start(self.millis());
                self.start_privacy();
                self.event("Automatic recovery enabled for the selected wallet connection.");
            }
            Command::CrashNode | Command::HoldNodeOffline => {
                if self.policy.phase == Phase::Monitoring {
                    let hold = matches!(command, Command::HoldNodeOffline);
                    self.operation("Saving a wallet checkpoint before the deliberate node failure")
                        .await;
                    let result = interruptible(
                        self.cancel.clone(),
                        self.client.shutdown.clone(),
                        self.inject(hold),
                    )
                    .await;
                    match result {
                        Some(Ok(())) => (),
                        Some(Err(error)) => {
                            self.state.error = Some(error.into());
                            self.event(error);
                        }
                        None => {
                            self.stop_session().await;
                            return;
                        }
                    }
                }
            }
            Command::Stop => unreachable!(),
        }
        self.client.busy.store(false, Ordering::SeqCst);
        self.state.operation.clear();
        self.publish().await;
    }
    async fn inject(&mut self, hold: bool) -> LabResult<()> {
        self.checkpoint().await?;
        let node = self
            .supervisor
            .daemon
            .as_mut()
            .ok_or("The owned node is not running.")?;
        node.child
            .kill()
            .await
            .map_err(|_| "Could not terminate the owned test node.")?;
        self.supervisor.check_exits();
        self.hold = hold;
        self.state.node_synced = false;
        self.event(if hold {
            "Lab fault: owned node terminated; restart is deliberately held offline."
        } else {
            "Lab fault: owned node process terminated. The watchdog will detect the failure."
        });
        Ok(())
    }
    async fn checkpoint(&mut self) -> LabResult<()> {
        let rpc = self
            .supervisor
            .wallet
            .as_ref()
            .ok_or("Wallet is not running.")?
            .rpc
            .clone();
        // Observe before storing: the confirmed saved floor can never be newer
        // than the state that was actually written by the official backend.
        let value = rpc.call("get_height", json!({}), 3).await?;
        let height = value["height"].as_u64().ok_or("Invalid wallet height.")?;
        rpc.call("store", json!({}), 8).await?;
        self.state.saved_height = Some(self.state.saved_height.unwrap_or(0).max(height));
        self.state.saved_at = Some(unix_time());
        self.next_save = Instant::now() + Duration::from_secs(60);
        Ok(())
    }
    async fn stop_session(&mut self) {
        if let Some(router) = &mut self.privacy {
            router.stop();
            router.set_managed_proxy(None);
        }
        self.managed_tor.stop().await;
        if let Some(manager) = &mut self.setup {
            manager.forget_phrase();
        }
        if let Some(receiver) = &mut self.test_wallet {
            receiver.stop_wallet().await;
        }
        if let Some(payments) = &mut self.payments {
            if let Err(e) = payments.invalidate_previews() {
                payments.set_error(e);
            }
        }
        self.operation("Saving wallet and stopping owned processes; automatic recovery is off")
            .await;
        self.policy.stop();
        // Publish explicit stopping state while the server remains reachable.
        self.state.phase = "Stopping".into();
        *self.client.state.write().await = self.state.clone();
        if self.supervisor.wallet.is_some() && self.checkpoint().await.is_err() {
            self.event("Checkpoint was unavailable; requesting the backend's normal save-on-exit.");
        }
        let clean = self.supervisor.stop_node().await;
        self.relationships = None;
        self.selected_relationship = None;
        if clean {
            self.event("Owned processes exited. Manual stop will not trigger recovery.");
        } else {
            self.event("Cleanup required forced termination. Only the last confirmed saved progress is guaranteed.");
        }
        self.state.node_synced = false;
        self.state.wallet_status = "Stopped".into();
        self.state.operation.clear();
        self.hold = false;
        self.client.busy.store(false, Ordering::SeqCst);
        self.publish().await;
    }
    async fn tick(&mut self) {
        if self.security_locked().await {
            if self.policy.phase != Phase::Stopped
                || self.supervisor.wallet.is_some()
                || self.remote_route_active()
            {
                self.lock_session().await;
            }
            self.publish().await;
            return;
        }
        if let Some(manager) = &mut self.setup {
            manager.expire();
        }
        if self.policy.phase == Phase::Stopped || self.policy.phase == Phase::Attention {
            if self.policy.phase == Phase::Stopped && self.remote_route_active() {
                let _ = self.tick_privacy().await;
            }
            if self.policy.phase == Phase::Stopped
                && !self.remote_privacy()
                && self.supervisor.daemon.is_some()
            {
                if self
                    .supervisor
                    .available_bytes()
                    .is_some_and(|n| n < 10 * 1024 * 1024 * 1024)
                {
                    self.stop_session().await;
                    self.state.error =
                        Some("Stopped to preserve 10 GiB of free disk space.".into());
                } else {
                    let _ = self.observe().await;
                    self.state.last_issue = None;
                    self.state.wallet_status = "Choose or create a wallet".into();
                }
            }
            self.publish().await;
            return;
        }
        if self.remote_privacy() {
            let result = self.tick_privacy().await;
            let Some(router) = self.privacy.as_ref() else {
                return;
            };
            let status = router.snapshot();
            if !status.operations_allowed {
                self.policy.defer_observation();
                if let Err(e) = result {
                    self.state.error = Some(e.message().into());
                }
                self.state.node_synced = false;
                self.state.wallet_status = "Waiting for a permitted connection".into();
                if self.supervisor.wallet.is_some() {
                    let _ = self.checkpoint().await;
                    self.supervisor.stop_wallet().await;
                }
                if let Some(payments) = &mut self.payments {
                    if let Err(e) = payments.invalidate_previews() {
                        payments.set_error(e);
                    }
                }
                if status.recovery.state == ConnectionState::PrivacyBlocked {
                    self.policy.fail_closed();
                }
                self.publish().await;
                return;
            }
            if self.supervisor.route_generation() != Some(status.recovery.generation)
                && self.policy.phase == Phase::Monitoring
            {
                self.policy.reconnect(self.millis());
                if self.policy.phase == Phase::Attention {
                    self.stop_exhausted_wallet().await;
                    self.state.error = Some("Repeated wallet restarts exhausted the recovery budget. Try again when the connection is stable.".into());
                    self.publish().await;
                    return;
                }
            }
        }
        if self
            .supervisor
            .available_bytes()
            .is_some_and(|bytes| bytes < 10 * 1024 * 1024 * 1024)
        {
            self.stop_session().await;
            self.policy.fail_closed();
            self.state.error = Some(
                "Stopped to preserve 10 GiB of free disk space. Explicit retry is required.".into(),
            );
            self.event("Low disk space: automatic restart disabled.");
            self.publish().await;
            return;
        }
        if self.policy.begin_due(self.millis()) {
            let label = if self.expected_identity.is_none() && self.policy.attempts == 1 {
                "Opening your saved wallet".to_string()
            } else {
                format!("Recovery attempt {} of 3", self.policy.attempts)
            };
            self.operation(&label).await;
            let result = tokio::time::timeout(Duration::from_secs(90), self.recover())
                .await
                .unwrap_or(Err("Recovery exceeded its deadline."));
            let success = result.is_ok();
            if let Err(error) = result {
                self.state.error = Some(error.into());
                self.event(error);
                self.supervisor.stop_node().await;
                self.state.node_synced = false;
                self.state.wallet_status = "Stopped".into();
            } else {
                self.state.error = None;
                self.state.last_issue = None;
                self.event("Actual wallet reopened; identity and saved scan height verified.");
            }
            self.policy.complete(success, self.millis());
            self.client.busy.store(false, Ordering::SeqCst);
            self.state.operation.clear();
            if self.policy.phase == Phase::Attention {
                self.event(
                    "Automatic recovery stopped. Review the error before an explicit retry.",
                );
            }
            self.publish().await;
            return;
        }
        if matches!(self.policy.phase, Phase::Monitoring | Phase::Suspect) {
            let observation = self.observe().await;
            let restart = match observation {
                Some(healthy) => self.policy.observe(healthy, self.millis()),
                None => {
                    self.policy.defer_observation();
                    false
                }
            };
            if restart {
                self.operation("Failure confirmed. Saving and closing the old wallet connection")
                    .await;
                if self.supervisor.wallet.is_some() && self.checkpoint().await.is_err() {
                    self.event("Using the last confirmed wallet checkpoint during recovery.");
                }
                self.supervisor.stop_wallet().await;
                self.state.wallet_status = "Stopped for recovery".into();
                self.client.busy.store(false, Ordering::SeqCst);
                self.state.operation.clear();
                if self.policy.phase == Phase::Attention {
                    self.stop_exhausted_wallet().await;
                    self.state.error = Some("Repeated failures exhausted the restart budget. Explicit retry is required.".into());
                    self.event("Crash-loop limit reached; no more automatic restarts.");
                } else {
                    self.event("Bounded recovery scheduled. Stop can cancel the pending retry.");
                }
            } else if observation == Some(true) && Instant::now() >= self.next_save {
                if self.checkpoint().await.is_ok() {
                    self.event("Periodic wallet checkpoint saved.");
                } else {
                    self.next_save = Instant::now() + Duration::from_secs(30);
                    self.event("Periodic save unavailable; previous checkpoint retained.");
                }
            }
        }
        if self.client.receive_enabled
            && self.policy.phase == Phase::Monitoring
            && Instant::now() >= self.next_receive
        {
            if let Err(error) = self.collect_receive().await {
                if let Some(data) = &mut self.state.receive {
                    data.error = Some(error.into());
                }
            }
            if let (Some(payments), Some(wallet), Some(identity)) = (
                &mut self.payments,
                &self.supervisor.wallet,
                &self.expected_identity,
            ) {
                if let Err(e) = payments.reconcile(&wallet.rpc, identity, unix_time()).await {
                    payments.set_error(e);
                }
            }
            if self
                .test_wallet
                .as_ref()
                .is_some_and(|s| s.wallet.is_some())
            {
                let _ = self.collect_test_recipient().await;
            }
            self.next_receive = Instant::now() + Duration::from_secs(5);
        }
        self.publish().await;
    }
    async fn stop_exhausted_wallet(&mut self) {
        // Terminal attention must quiesce an old backend even if the route
        // changed directly between two usable snapshots. Submitted payments
        // retain their durable attempt markers; only unused previews expire.
        if let Some(payments) = &mut self.payments {
            if let Err(error) = payments.invalidate_previews() {
                payments.set_error(error);
            }
        }
        if self.supervisor.wallet.is_some() {
            let _ = self.checkpoint().await;
        }
        self.supervisor.stop_node().await;
        self.state.node_synced = false;
        self.state.wallet_status = "Stopped".into();
    }
    async fn recover(&mut self) -> LabResult<()> {
        if let Some(receiver) = &mut self.test_wallet {
            receiver.stop_wallet().await;
        }
        if let Some(payments) = &mut self.payments {
            if let Err(e) = payments.invalidate_previews() {
                payments.set_error(e);
            }
        }
        // Closing the old wallet before starting a new daemon avoids retaining
        // stale RPC credentials or an old endpoint. The wallet file is reused.
        if !self.supervisor.stop_node().await {
            self.event(
                "Previous process needed forced cleanup; checking the last saved wallet state.",
            );
        }
        self.state.wallet_id = None;
        self.state.wallet_sample_at = None;
        if self.hold {
            return Err("Lab fault is holding node startup offline.");
        }
        if !self.supervisor.wallet_exists() {
            return Err(
                "The saved Prototype 03A wallet is missing. No replacement wallet will be created.",
            );
        }
        self.install_current_route().await?;
        self.supervisor.start_node().await?;
        self.supervisor.open_saved_wallet().await?;
        let wallet = self
            .supervisor
            .wallet
            .as_ref()
            .ok_or("Wallet did not start.")?
            .rpc
            .clone();
        let address = wallet
            .call("get_address", json!({"account_index":0}), 5)
            .await?;
        let address = address["address"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("Wallet identity is unavailable.")?;
        let identity = format!("{:x}", Sha256::digest(address.as_bytes()));
        if self
            .setup
            .as_ref()
            .and_then(|s| s.catalog.active_profile())
            .and_then(|p| p.address.as_deref())
            .is_some_and(|a| a != address)
        {
            self.policy.fail_closed();
            return Err("Saved wallet address does not match its catalog. Recovery stopped.");
        }
        let height = wallet.call("get_height", json!({}), 5).await?["height"]
            .as_u64()
            .ok_or("Wallet height is unavailable.")?;
        if let Err(error) = verify_wallet_resume(
            self.expected_identity.as_deref(),
            &identity,
            self.state.saved_height,
            height,
        ) {
            self.policy.fail_closed();
            return Err(error);
        }
        self.expected_identity = Some(identity.clone());
        if self.privacy.is_some() {
            self.relationships = Some(RelationshipBook::open(
                self.supervisor.wallet_root.join("relationships"),
                &identity,
            )?);
        }
        self.state.wallet_id = Some(identity[..12].to_owned());
        self.state.wallet_height = Some(height);
        self.state.wallet_sample_at = Some(unix_time());
        if self.observe().await != Some(true) {
            return Err("Reopened processes did not pass their live health check.");
        }
        self.checkpoint().await?;
        // auto_refresh starts work on Monero's next idle tick. Enable it only
        // after every mandatory startup RPC has completed; normal observation
        // already treats a refresh-busy wallet as alive rather than restarting it.
        self.supervisor.resume_wallet_refresh().await?;
        self.next_receive = Instant::now();
        Ok(())
    }
    async fn security_locked(&self) -> bool {
        match &self.client.security {
            Some(s) => s.locked().await,
            None => false,
        }
    }
    async fn security_transition(&mut self) {
        if self.security_locked().await {
            if self.supervisor.wallet.is_some()
                || self.policy.phase != Phase::Stopped
                || self.remote_route_active()
            {
                self.lock_session().await;
            }
        } else if self.policy.phase == Phase::Stopped
            && self
                .setup
                .as_ref()
                .is_some_and(|s| s.catalog.active.is_some())
        {
            self.cancel = CancellationToken::new();
            if let Ok(mut cancel) = self.client.cancel.lock() {
                *cancel = self.cancel.clone();
            }
            self.state.error = None;
            self.state.last_issue = None;
            self.hold = false;
            self.policy.start(self.millis());
            self.start_privacy();
            self.event("Wallet unlocked. Opening the selected saved wallet.");
        }
        self.publish().await;
    }
    async fn lock_session(&mut self) {
        if let Some(router) = &mut self.privacy {
            router.stop();
            router.set_managed_proxy(None);
        }
        self.managed_tor.stop().await;
        self.relationships = None;
        self.selected_relationship = None;
        // Revoke API access first (Security does that before waking this actor).
        // A relay past its durable authorization marker is allowed to finish once.
        if let Some(manager) = &mut self.setup {
            manager.forget_phrase();
        }
        if let Some(receiver) = &mut self.test_wallet {
            receiver.stop_wallet().await;
        }
        if let Some(payments) = &mut self.payments {
            if let Err(e) = payments.invalidate_previews() {
                payments.set_error(e);
            }
        }
        if self.supervisor.wallet.is_some() {
            let _ = self.checkpoint().await;
            self.supervisor.stop_wallet().await;
        }
        self.policy.stop();
        self.state.wallet_status = "Locked".into();
        self.state.wallet_id = None;
        self.state.wallet_sample_at = None;
        self.state.receive = Some(ReceiveSnapshot::default());
        self.state.test_recipient = None;
        self.state.operation.clear();
        self.client.busy.store(false, Ordering::SeqCst);
        self.event(
            "Wallet locked and wallet process closed. The local node may keep synchronizing.",
        );
        self.publish().await;
    }
    async fn setup_action(&mut self, command: &SetupCommand) -> LabResult<SetupReply> {
        let changes = command.changes_wallet();
        if self.privacy.is_some()
            && !self.remote_privacy()
            && matches!(
                command,
                SetupCommand::Create { .. } | SetupCommand::Restore { .. }
            )
            && self.supervisor.daemon.is_some()
            && !self.state.node_synced
        {
            return Err("Your local node is still synchronizing. Leave it connected, then create or restore your wallet when synchronization finishes.");
        }
        if changes && self.payments.as_ref().is_some_and(|p| p.snapshot.blocked) {
            return Err("Finish or cancel the current payment before changing wallets.");
        }
        if !changes
            && !matches!(command, SetupCommand::Hide)
            && self.policy.phase != Phase::Monitoring
        {
            return Err("Connect your wallet before checking its backup.");
        }
        if changes {
            self.stop_session().await;
        }
        self.operation(if changes {
            "Opening the selected wallet on this device"
        } else {
            "Checking your wallet backup"
        })
        .await;
        if changes
            && self.privacy.is_some()
            && matches!(
                command,
                SetupCommand::Create { .. } | SetupCommand::Restore { .. }
            )
        {
            self.wait_for_private_route().await?;
        }
        let mut manager = self.setup.take().ok_or("Wallet setup is unavailable.")?;
        let result = manager.execute(&mut self.supervisor, command).await;
        if changes {
            // A failed import never changes the saved selection. Failed candidate files
            // stay isolated for inspection; they are never opened by automatic recovery.
            self.supervisor.stop_node().await;
            self.supervisor.wallet_root = manager.active_root();
            self.expected_identity = None;
            self.wallet_liveness = WalletLiveness::default();
            self.state.wallet_id = None;
            self.state.wallet_height = None;
            self.state.wallet_sample_at = None;
            self.state.saved_height = None;
            self.state.saved_at = None;
            self.state.receive = Some(ReceiveSnapshot::default());
            self.state.test_recipient = None;
            self.state.error = None;
            self.payments = self.client.send_enabled.then(|| {
                Sender::open_for(
                    self.supervisor.wallet_root.join("payments"),
                    self.supervisor.network,
                )
            });
            self.cancel = CancellationToken::new();
            if let Ok(mut token) = self.client.cancel.lock() {
                *token = self.cancel.clone();
            }
            if manager.catalog.active.is_some() && !self.client.shutdown.is_cancelled() {
                self.policy.start(self.millis());
                self.start_privacy();
            }
        }
        self.setup = Some(manager);
        // Never log request bodies or replies: they can contain a recovery phrase.
        result
    }
    async fn test_recipient(&mut self) -> LabResult<()> {
        if self.privacy.is_some() {
            return Err("The development recipient is unavailable in the wallet app.");
        }
        if self.test_wallet.is_none() {
            self.test_wallet = Some(
                Supervisor::new(
                    self.supervisor.root.join("test-recipient"),
                    self.supervisor.binaries.clone(),
                )
                .await?,
            );
        }
        let daemon = self
            .supervisor
            .daemon
            .as_ref()
            .ok_or("Local node is unavailable.")?
            .rpc
            .clone();
        self.test_wallet
            .as_mut()
            .ok_or("Test wallet is unavailable.")?
            .start_wallet_against(&daemon, true)
            .await?;
        self.collect_test_recipient().await?;
        self.test_wallet
            .as_ref()
            .ok_or("Test wallet is unavailable.")?
            .resume_wallet_refresh()
            .await
    }
    async fn collect_test_recipient(&mut self) -> LabResult<()> {
        let rpc = &self
            .test_wallet
            .as_ref()
            .and_then(|s| s.wallet.as_ref())
            .ok_or("Test receiver is not running.")?
            .rpc;
        let (address, index) = receive::read_address(rpc).await?;
        let balance = receive::read_balance(rpc, unix_time()).await?;
        self.state.test_recipient = Some(ReceiveSnapshot {
            address: Some(address),
            address_index: Some(index),
            balance: Some(balance),
            current: true,
            error: None,
        });
        Ok(())
    }
    async fn send_action(&mut self, command: SendCommand, permit: Option<u64>) -> LabResult<()> {
        if self.policy.phase != Phase::Monitoring
            || self.cancel.is_cancelled()
            || self.client.shutdown.is_cancelled()
        {
            return Err("Payment action cancelled while the connection changed.");
        }
        if self.observe().await != Some(true) {
            return Err("The selected node is unavailable. Nothing new was sent.");
        }
        self.collect_receive().await?;
        self.state.refresh_receive_status();
        if !self.state.receive.as_ref().is_some_and(|r| r.current) {
            return Err("A current synchronized balance is required.");
        }
        let rpc = self
            .supervisor
            .wallet
            .as_ref()
            .ok_or("Wallet is unavailable.")?
            .rpc
            .clone();
        let identity = self
            .expected_identity
            .as_deref()
            .ok_or("Wallet identity is unavailable.")?;
        let spendable = self
            .state
            .receive
            .as_ref()
            .and_then(|r| r.balance.as_ref())
            .and_then(|b| b.spendable_atomic.parse::<u64>().ok())
            .ok_or("Spendable balance is unavailable.")?;
        if self.cancel.is_cancelled() || self.client.shutdown.is_cancelled() {
            return Err("Payment action cancelled before broadcast.");
        }
        self.client.check_permit(permit).await?;
        let payments = self.payments.as_mut().ok_or("Sending is disabled.")?;
        match command {
            SendCommand::Prepare {
                address,
                amount,
                priority,
            } => {
                payments
                    .prepare_with_priority(
                        &rpc,
                        identity,
                        &address,
                        &amount,
                        spendable,
                        unix_time(),
                        priority,
                    )
                    .await?
            }
            SendCommand::Confirm { id, pin } => {
                let authorization = if let Some(security) = &self.client.security {
                    Some(
                        security
                            .authorize_payment(permit, pin.as_ref(), identity, &id)
                            .await?,
                    )
                } else {
                    None
                };
                payments
                    .confirm_routed(
                        &rpc,
                        identity,
                        &id,
                        spendable,
                        unix_time(),
                        authorization,
                        match &self.privacy {
                            Some(router) if router.config().profile == Profile::Balanced => Some((
                                router,
                                self.supervisor
                                    .route_generation()
                                    .ok_or("The active wallet has no validated route.")?,
                            )),
                            _ => None,
                        },
                    )
                    .await?
            }
            SendCommand::Cancel { id } => payments.cancel(&id)?,
            SendCommand::Check => payments.reconcile(&rpc, identity, unix_time()).await?,
        }
        self.next_receive = Instant::now();
        Ok(())
    }
    async fn receive_action(&mut self, create: bool) -> LabResult<()> {
        if create {
            self.selected_relationship = None;
        }
        let rpc = self
            .supervisor
            .wallet
            .as_ref()
            .ok_or("Wallet is not running.")?
            .rpc
            .clone();
        if create {
            let (_, index) = receive::read_address_for(&rpc, self.supervisor.network).await?;
            if index >= 100 {
                return Err("This wallet has reached the limit of 100 receiving addresses.");
            }
            // Never automatically repeat this mutating call after an ambiguous
            // timeout. Re-reading the saved address list reconciles the result.
            rpc.call(
                "create_address",
                json!({"account_index":0,"count":1,"label":"Receiving address"}),
                8,
            )
            .await?;
            if let Some(data) = &mut self.state.receive {
                data.address = None;
                data.address_index = None;
            }
        }
        self.collect_receive().await
    }
    async fn collect_receive(&mut self) -> LabResult<()> {
        let rpc = self
            .supervisor
            .wallet
            .as_ref()
            .ok_or("Wallet is not running.")?
            .rpc
            .clone();
        let (address, index) = match self
            .selected_relationship
            .as_ref()
            .and_then(|r| r.address.clone().zip(r.address_index))
        {
            Some(selected) => selected,
            None => receive::read_address_for(&rpc, self.supervisor.network).await?,
        };
        let changed = self
            .state
            .receive
            .as_ref()
            .is_none_or(|d| d.address.as_deref() != Some(&address));
        if changed {
            self.checkpoint().await?;
            let data = self
                .state
                .receive
                .as_mut()
                .ok_or("Receive feature is disabled.")?;
            data.address = Some(address);
            data.address_index = Some(index);
            self.event("Receiving address verified for this network and saved locally.");
        }
        let balance = if self.supervisor.network == Network::Mainnet {
            receive::read_confirmed_balance(&rpc, unix_time()).await?
        } else {
            receive::read_balance(&rpc, unix_time()).await?
        };
        if let Some(pid) = self.supervisor.wallet_pid() {
            let now = self.millis();
            self.wallet_liveness
                .bind(pid, self.supervisor.route_generation().unwrap_or(0), now);
            self.wallet_liveness.responded(now);
            if self.state.node_synced
                && self
                    .state
                    .node_height
                    .is_some_and(|height| balance.wallet_height >= height)
                && self
                    .privacy_status()
                    .is_none_or(|status| status.operations_allowed)
            {
                self.wallet_liveness.synchronized(now);
            }
        }
        self.state.wallet_height = Some(balance.wallet_height);
        self.state.wallet_sample_at = Some(balance.sampled_at);
        if self.state.node_synced
            && self
                .state
                .node_height
                .is_some_and(|height| balance.wallet_height >= height)
        {
            self.state.wallet_status = "Synchronized".into();
        }
        let data = self
            .state
            .receive
            .as_mut()
            .ok_or("Receive feature is disabled.")?;
        data.balance = Some(balance);
        data.error = None;
        Ok(())
    }
    /// None means a live wallet is temporarily busy. It must not count as a
    /// healthy observation, earn restart budget, or immediately force a restart.
    async fn observe(&mut self) -> Option<bool> {
        let (node_exit, wallet_exit) = self.supervisor.check_exits();
        if node_exit {
            self.event("The owned node exited unexpectedly.");
        }
        if wallet_exit {
            self.event("The owned wallet backend exited unexpectedly.");
            if self.remote_privacy() {
                if let Some(router) = &mut self.privacy {
                    router.backend_exited();
                }
            }
        }
        let mut node_ok = false;
        if self.remote_privacy() {
            if let Some(status) = self.privacy_status() {
                node_ok = status.operations_allowed
                    && self.supervisor.route_generation() == Some(status.recovery.generation);
                self.state.node_synced = node_ok;
                self.state.peers = 0;
                if let Some(health) = status.health {
                    self.state.node_height = Some(health.height);
                    self.state.node_target = Some(health.target_height.max(health.height));
                    self.state.node_sample_at = Some(health.checked_at);
                }
            }
        } else if let Some(node) = &self.supervisor.daemon {
            match node.rpc.call("get_info", json!({}), 3).await {
                Ok(info)
                    if info["nettype"] == self.supervisor.network.as_str()
                        && info["status"] == "OK"
                        && info["height"].as_u64().is_some_and(|h| h > 0) =>
                {
                    self.state.node_height = info["height"].as_u64();
                    self.state.peers = info["outgoing_connections_count"].as_u64().unwrap_or(0);
                    self.state.node_synced =
                        info["synchronized"].as_bool().unwrap_or(false) && self.state.peers > 0;
                    self.state.node_target = info["target_height"].as_u64().filter(|h| *h > 0).or(
                        if self.state.node_synced {
                            self.state.node_height
                        } else {
                            None
                        },
                    );
                    self.state.node_sample_at = Some(unix_time());
                    node_ok = true;
                }
                _ => {
                    self.state.node_synced = false;
                }
            }
        } else {
            self.state.node_synced = false;
            self.state.peers = 0;
        }
        let wallet_alive = self.supervisor.wallet.is_some();
        if let Some(pid) = self.supervisor.wallet_pid() {
            self.wallet_liveness.bind(
                pid,
                self.supervisor.route_generation().unwrap_or(0),
                self.millis(),
            );
        }
        let mut wallet_responded = false;
        if let Some(wallet) = &self.supervisor.wallet {
            match wallet.rpc.call("get_height", json!({}), 3).await {
                Ok(value) if observed_wallet_height(&value, self.state.node_height).is_some() => {
                    self.state.wallet_height =
                        observed_wallet_height(&value, self.state.node_height);
                    self.state.wallet_sample_at = Some(unix_time());
                    self.wallet_liveness.responded(self.millis());
                    wallet_responded = true;
                    self.state.wallet_status = if self.state.node_synced
                        && self.state.wallet_height >= self.state.node_height
                    {
                        "Synchronized"
                    } else if node_ok {
                        "Scanning / waiting for blocks"
                    } else {
                        "Waiting for recovery"
                    }
                    .into();
                }
                _ => self.state.wallet_status = "Wallet RPC busy; waiting".into(),
            }
        } else {
            self.state.wallet_status = "Stopped".into();
        }
        let missing = self.wallet_liveness.missing_response(self.millis());
        self.state.last_issue = if !node_ok {
            Some("The node connection is unavailable or its response is invalid.".into())
        } else if !wallet_alive {
            Some("The wallet backend is no longer running.".into())
        } else if !wallet_responded && missing == MissingResponse::Unresponsive {
            Some("The wallet has not responded for three minutes. Checking again before safely reopening it.".into())
        } else if !wallet_responded && missing == MissingResponse::InitialScanNotice {
            Some("The first scan has not answered for fifteen minutes. It may still be scanning; AutoPilot will keep checking. You can pause and resume the connection if it remains stuck.".into())
        } else {
            None
        };
        // Initial scans continue without an automatic deadline-based kill.
        // Foreground RPC actions are serialized by the actor, so this check
        // never interrupts preparation, a broadcast, setup, or backup work.
        wallet_observation(
            node_ok,
            wallet_alive,
            wallet_responded,
            missing,
            self.remote_privacy(),
        )
    }
}
