use crate::{supervisor::Supervisor, LabResult, VERSION, WALLET_NAME};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, RwLock},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    StartNode,
    StartWallet,
    StopWallet,
    StopNode,
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
    pub busy: bool,
    pub operation: String,
    pub error: Option<String>,
    pub node_pid: Option<u32>,
    pub wallet_pid: Option<u32>,
    pub node_status: String,
    pub wallet_status: String,
    pub node_height: Option<u64>,
    pub node_target: Option<u64>,
    pub node_synced: bool,
    pub peers: u64,
    pub database_bytes: u64,
    pub available_bytes: Option<u64>,
    pub wallet_height: Option<u64>,
    pub wallet_exists: bool,
    pub wallet_name: &'static str,
    pub wallet_id: Option<String>,
    pub wallet_sample_at: Option<u64>,
    pub node_sample_at: Option<u64>,
    pub wallet_starts: u32,
    pub graceful_stops: u32,
    pub events: Vec<Event>,
    pub daemon_available: bool,
    pub wallet_available: bool,
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl Snapshot {
    fn new(s: &Supervisor) -> Self {
        Self {
            version: VERSION,
            network: "stagenet",
            busy: false,
            operation: String::new(),
            error: None,
            node_pid: None,
            wallet_pid: None,
            node_status: "Stopped".into(),
            wallet_status: "Stopped".into(),
            node_height: None,
            node_target: None,
            node_synced: false,
            peers: 0,
            database_bytes: s.database_bytes(),
            available_bytes: s.available_bytes(),
            wallet_height: None,
            wallet_exists: s.wallet_exists(),
            wallet_name: WALLET_NAME,
            wallet_id: None,
            wallet_sample_at: None,
            node_sample_at: None,
            wallet_starts: 0,
            graceful_stops: 0,
            events: vec![],
            daemon_available: s.binaries.join("monerod.exe").exists(),
            wallet_available: s.binaries.join("monero-wallet-rpc.exe").exists(),
        }
    }
    fn event(&mut self, message: impl Into<String>) {
        let seq = self.events.last().map_or(1, |e| e.seq + 1);
        if self.events.len() == 80 {
            self.events.remove(0);
        }
        self.events.push(Event {
            seq,
            time: now(),
            message: message.into(),
        });
    }
}
#[derive(Clone)]
pub struct Client {
    pub state: Arc<RwLock<Snapshot>>,
    sender: mpsc::Sender<Command>,
    busy: Arc<AtomicBool>,
    pub shutdown: CancellationToken,
}
impl Client {
    pub fn command(&self, command: Command) -> LabResult<()> {
        if self.shutdown.is_cancelled() {
            return Err("The lab is shutting down.");
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("A process operation is already in progress.");
        }
        if self.sender.try_send(command).is_err() {
            self.busy.store(false, Ordering::SeqCst);
            return Err("The lab is unavailable.");
        }
        Ok(())
    }
}
pub struct Runtime {
    pub client: Client,
    task: Option<JoinHandle<()>>,
}
impl Runtime {
    pub async fn start(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        let mut supervisor = Supervisor::new(root, binaries).await?;
        let state = Arc::new(RwLock::new(Snapshot::new(&supervisor)));
        let shutdown = CancellationToken::new();
        let busy = Arc::new(AtomicBool::new(false));
        let (sender, mut receive) = mpsc::channel(1);
        let client = Client {
            state: state.clone(),
            sender,
            busy: busy.clone(),
            shutdown: shutdown.clone(),
        };
        let task = tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(2));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {biased;
                    _=shutdown.cancelled()=>break,
                    command=receive.recv()=>{
                        let Some(command)=command else{break;};
                        {let mut s=state.write().await;s.busy=true;s.error=None;s.operation=match command{Command::StartNode=>"Starting the local stagenet node",Command::StartWallet=>"Opening the disposable stagenet wallet",Command::StopWallet=>"Saving and stopping wallet RPC",Command::StopNode=>"Saving and stopping both processes"}.into();let op=s.operation.clone();s.event(op);}
                        let result=match command{
                            Command::StartNode=>supervisor.start_node().await,
                            Command::StartWallet=>{state.write().await.wallet_id=None;supervisor.start_wallet().await},
                            Command::StopWallet=>{let existed=supervisor.wallet.is_some();let clean=supervisor.stop_wallet().await;let mut s=state.write().await;s.wallet_status="Stopped".into();if clean&&existed{s.graceful_stops+=1;}else if !clean{s.event("Wallet RPC required forced termination; last stored state is retained.");}Ok(())},
                            Command::StopNode=>{let clean=supervisor.stop_node().await;let mut s=state.write().await;s.node_status="Stopped".into();s.wallet_status="Stopped".into();s.node_synced=false;if !clean{s.event("Node required forced termination; LMDB recovery will run on restart.");}Ok(())}
                        };
                        {let mut s=state.write().await;if let Err(error)=result{s.error=Some(error.into());s.event(error);}else{if matches!(command,Command::StartWallet){s.wallet_starts+=1;}s.event("Process operation completed.");}s.operation.clear();s.busy=false;s.node_pid=supervisor.daemon_pid();s.wallet_pid=supervisor.wallet_pid();}
                        busy.store(false,Ordering::SeqCst);
                    },
                    _=timer.tick()=>poll(&mut supervisor,&state).await,
                }
            }
            {
                let mut s = state.write().await;
                s.busy = true;
                s.operation = "Saving wallets and stopping owned processes".into();
            }
            supervisor.stop_node().await;
        });
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
async fn poll(supervisor: &mut Supervisor, state: &Arc<RwLock<Snapshot>>) {
    if supervisor.daemon.is_some()
        && supervisor
            .available_bytes()
            .is_some_and(|bytes| bytes < 10 * 1024 * 1024 * 1024)
    {
        supervisor.stop_node().await;
        let mut s = state.write().await;
        s.error = Some("Synchronization stopped to preserve 10 GiB of free disk space.".into());
        s.node_status = "Stopped".into();
        s.wallet_status = "Stopped".into();
        s.node_synced = false;
        s.event("Low disk space: owned Monero processes stopped.");
    }
    let (node_exit, wallet_exit) = supervisor.check_exits();
    {
        let mut s = state.write().await;
        if node_exit {
            s.node_status = "Exited".into();
            s.node_synced = false;
            s.event("Local node exited. Automatic restart is disabled in this prototype.");
        }
        if wallet_exit {
            s.wallet_status = "Exited".into();
            s.event("Wallet RPC exited. Reopen explicitly to continue from its stored state.");
        }
        s.node_pid = supervisor.daemon_pid();
        s.wallet_pid = supervisor.wallet_pid();
        s.wallet_exists = supervisor.wallet_exists();
        s.database_bytes = supervisor.database_bytes();
        s.available_bytes = supervisor.available_bytes();
        s.daemon_available = supervisor.binaries.join("monerod.exe").exists();
        s.wallet_available = supervisor.binaries.join("monero-wallet-rpc.exe").exists();
    }
    if let Some(process) = &supervisor.daemon {
        match process.rpc.call("get_info", json!({}), 3).await {
            Ok(value) => {
                let mut s = state.write().await;
                if value["nettype"] != "stagenet" {
                    s.error = Some("Unexpected node network. Wallet startup is blocked.".into());
                    s.node_synced = false;
                    return;
                }
                s.node_height = value["height"].as_u64();
                s.node_target = value["target_height"]
                    .as_u64()
                    .filter(|h| *h > 0)
                    .or_else(|| {
                        if value["synchronized"].as_bool() == Some(true) {
                            s.node_height
                        } else {
                            None
                        }
                    });
                s.peers = value["outgoing_connections_count"].as_u64().unwrap_or(0);
                s.node_synced = value["synchronized"].as_bool().unwrap_or(false) && s.peers > 0;
                s.node_status = if s.node_synced {
                    "Synchronized"
                } else if s.peers == 0 {
                    "Finding peers"
                } else {
                    "Synchronizing"
                }
                .into();
                s.node_sample_at = Some(now());
            }
            Err(_) => {
                let mut s = state.write().await;
                s.node_status = "RPC unavailable".into();
                s.node_synced = false;
            }
        }
    }
    if let Some(process) = &supervisor.wallet {
        match process.rpc.call("get_height", json!({}), 4).await {
            Ok(value) => {
                let mut s = state.write().await;
                s.wallet_height = value["height"].as_u64();
                s.wallet_sample_at = Some(now());
                s.wallet_status = if !s.node_synced {
                    "Waiting for node"
                } else if matches!((s.wallet_height,s.node_height),(Some(wallet),Some(node)) if wallet>=node) {
                    "Synchronized"
                } else {
                    "Scanning"
                }
                .into();
            }
            Err(_) => {
                state.write().await.wallet_status = "RPC busy or unavailable".into();
            }
        }
        if state.read().await.wallet_id.is_none() {
            if let Ok(value) = process
                .rpc
                .call("get_address", json!({"account_index":0}), 4)
                .await
            {
                if let Some(address) = value["address"].as_str() {
                    let digest = format!("{:x}", Sha256::digest(address.as_bytes()));
                    state.write().await.wallet_id = Some(digest[..12].into());
                }
            }
        }
    }
}
