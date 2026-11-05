use crate::{
    platform::{self, Job, HIDDEN},
    rpc::Rpc,
    LabResult, DAEMON_SHA256, WALLET_NAME, WALLET_SHA256,
};
use autopilot_privacy::{
    config::{Config, ConfigStore, Network, Profile},
    runtime::BackendEndpoint,
};
use fs2::FileExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::{Child, Command};
use zeroize::Zeroizing;

pub struct OwnedProcess {
    pub child: Child,
    pub rpc: Rpc,
    config: PathBuf,
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_file(&self.config);
    }
}
pub struct Supervisor {
    pub network: Network,
    pub root: PathBuf,
    pub wallet_root: PathBuf,
    pub binaries: PathBuf,
    pub daemon: Option<OwnedProcess>,
    pub wallet: Option<OwnedProcess>,
    node_access: NodeAccess,
    job: Job,
    _lock: File,
}
enum NodeAccess {
    LegacyLocal,
    Blocked,
    ConsentedLocal,
    Gateway {
        rpc: Rpc,
        capability: BackendEndpoint,
    },
}
pub fn wallet_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet-wallet",
        _ => WALLET_NAME,
    }
}
pub fn verify_binary(path: &Path, expected: &str) -> LabResult<()> {
    let mut file=File::open(path).map_err(|_|"The verified Monero executable is missing or blocked by Windows Security. Review the specific detection before continuing.")?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "Could not read the Monero executable.")?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if format!("{:x}", digest.finalize()) != expected {
        return Err("Monero executable hash mismatch. Execution refused.");
    }
    Ok(())
}
fn free_address() -> LabResult<SocketAddr> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .map_err(|_| "Could not reserve a local port.")
}
fn random_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}
fn config_path(path: &Path) -> LabResult<String> {
    let value = path.to_str().ok_or("Unsupported local path.")?;
    if value.contains(['\r', '\n', '"', '#']) {
        return Err("Unsupported characters in local path.");
    }
    Ok(value
        .strip_prefix(r"\\?\")
        .unwrap_or(value)
        .replace('\\', "/"))
}

async fn check_daemon_network(
    daemon: &Rpc,
    network: Network,
    through_gateway: bool,
) -> LabResult<()> {
    // The gateway is on loopback, but this request still makes a Tor round trip.
    // Give it the same bounded budget as the routed small-request transport.
    // A local daemon keeps its short responsiveness check.
    let seconds = if through_gateway { 25 } else { 3 };
    let info = daemon.call("get_info", json!({}), seconds).await?;
    if info.get("nettype").and_then(|v| v.as_str()) != Some(network.as_str()) {
        return Err("Daemon network does not match this wallet.");
    }
    Ok(())
}

impl Supervisor {
    pub async fn new(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::new_inner(root, binaries, false, false, Network::Stagenet, None).await
    }
    pub async fn new_secured(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::new_inner(root, binaries, true, false, Network::Stagenet, None).await
    }
    /// Privacy-aware hosts must explicitly install a validated gateway or an
    /// authenticated, consented local-node policy before starting any backend.
    pub async fn new_guarded(root: PathBuf, binaries: PathBuf) -> LabResult<Self> {
        Self::new_inner(root, binaries, true, true, Network::Stagenet, None).await
    }
    /// Mainnet is opt-in through a separate host, with a pinned owned route.
    pub async fn new_mainnet(
        root: PathBuf,
        binaries: PathBuf,
        bootstrap: Config,
    ) -> LabResult<Self> {
        if bootstrap.network != Network::Mainnet {
            return Err("Invalid mainnet bootstrap policy.");
        }
        bootstrap.validate().map_err(|e| e.message())?;
        Self::new_inner(
            root,
            binaries,
            true,
            true,
            Network::Mainnet,
            Some(bootstrap),
        )
        .await
    }
    pub fn wallet_name(&self) -> &'static str {
        wallet_name(self.network)
    }
    async fn new_inner(
        root: PathBuf,
        binaries: PathBuf,
        secured: bool,
        guarded: bool,
        network: Network,
        bootstrap: Option<Config>,
    ) -> LabResult<Self> {
        if !guarded
            && (root.join("privacy/privacy-required").exists()
                || root.join("privacy/privacy.json").exists())
        {
            return Err(
                "This wallet requires the Privacy Guard app. Older connection paths are disabled.",
            );
        }
        if !secured
            && (root.join("security/configured").exists()
                || root.join("security/pin.dpapi").exists())
        {
            return Err(
                "This wallet requires the PIN-protected app. Older wallet labs cannot open it.",
            );
        }
        platform::private_directory(&root).await?;
        let root = std::fs::canonicalize(root)
            .map_err(|_| "Could not resolve the private data directory.")?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("host.lock"))
            .map_err(|_| "Could not open the lab lock.")?;
        lock.try_lock_exclusive()
            .map_err(|_| "Another wallet lab already owns this data directory.")?;
        let marker = root.join("network.json");
        let fresh = !marker.exists();
        if !fresh {
            let saved: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&marker).map_err(|_| "Cannot read the wallet network boundary.")?,
            )
            .map_err(|_| "Invalid wallet network boundary.")?;
            if saved != json!({"schema":1,"network":network.as_str()}) {
                return Err(
                    "This data directory belongs to a different network. Use a separate directory.",
                );
            }
        } else if network == Network::Mainnet
            && std::fs::read_dir(&root)
                .map_err(|_| "Cannot inspect the mainnet data directory.")?
                .any(|entry| entry.map_or(true, |e| e.file_name() != "host.lock"))
        {
            return Err(
                "Mainnet requires a new empty data directory. Existing files are preserved.",
            );
        }
        if guarded {
            let store = ConfigStore::new(root.join("privacy"));
            let config = if network == Network::Mainnet && fresh {
                bootstrap
                    .clone()
                    .ok_or("Mainnet bootstrap policy is missing.")?
            } else {
                store.load().map_err(|e| e.message())?
            };
            if config.network != network
                || bootstrap
                    .as_ref()
                    .is_some_and(|expected| expected != &config)
            {
                return Err(
                    "Saved privacy policy does not match this prototype's network and owned node.",
                );
            }
            store.save(&config).map_err(|e| e.message())?;
        }
        if fresh {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)
                .map_err(|_| "Cannot save the wallet network boundary.")?;
            file.write_all(
                serde_json::to_string(&json!({"schema":1,"network":network.as_str()}))
                    .unwrap()
                    .as_bytes(),
            )
            .and_then(|_| file.sync_all())
            .map_err(|_| "Cannot flush the wallet network boundary.")?;
        }
        std::fs::create_dir_all(root.join("wallets"))
            .map_err(|_| "Could not create the wallet directory.")?;
        std::fs::create_dir_all(root.join("chain"))
            .map_err(|_| "Could not create the chain directory.")?;
        Ok(Self {
            network,
            wallet_root: root.clone(),
            root,
            binaries,
            daemon: None,
            wallet: None,
            node_access: if guarded {
                NodeAccess::Blocked
            } else {
                NodeAccess::LegacyLocal
            },
            job: Job::new()?,
            _lock: lock,
        })
    }
    /// Call only after authenticating and persisting explicit user consent.
    pub fn authorize_local_node(&mut self, config: &Config) -> LabResult<()> {
        config.validate().map_err(|e| e.message())?;
        if config.profile != Profile::LocalNode
            || !config.local_direct_consent
            || config.network != self.network
            || self.network != Network::Stagenet
        {
            return Err("Direct local-node peer traffic requires the Local node profile and explicit consent.");
        }
        if self.wallet.is_some()
            || self.daemon.is_some()
            || matches!(self.node_access, NodeAccess::LegacyLocal)
        {
            return Err("Stop the previous guarded connection before changing its policy.");
        }
        self.node_access = NodeAccess::ConsentedLocal;
        Ok(())
    }
    pub fn install_gateway(&mut self, capability: BackendEndpoint) -> LabResult<()> {
        if self.wallet.is_some()
            || self.daemon.is_some()
            || matches!(self.node_access, NodeAccess::LegacyLocal)
            || !capability.current()
            || capability.network() != self.network
        {
            return Err("A fresh validated route and a stopped wallet are required.");
        }
        let rpc = Rpc::new(
            capability.address(),
            capability.username().to_owned(),
            capability.password().to_owned(),
        )?;
        self.node_access = NodeAccess::Gateway { rpc, capability };
        Ok(())
    }
    pub fn daemon_rpc(&self) -> LabResult<Rpc> {
        match &self.node_access {
            NodeAccess::Blocked => Err("Privacy Guard has not established a permitted connection."),
            NodeAccess::Gateway { rpc, capability } if !capability.revoked() => Ok(rpc.clone()),
            NodeAccess::Gateway { .. } => {
                Err("The private route was revoked. Reconnect before using the wallet.")
            }
            _ => self
                .daemon
                .as_ref()
                .map(|p| p.rpc.clone())
                .ok_or("The local node is unavailable."),
        }
    }
    pub fn route_generation(&self) -> Option<u64> {
        match &self.node_access {
            NodeAccess::Gateway { capability, .. } => Some(capability.generation()),
            _ => None,
        }
    }
    fn check_wallet_daemon(&self, daemon: &Rpc) -> LabResult<()> {
        match &self.node_access {
            NodeAccess::LegacyLocal => Ok(()),
            NodeAccess::Blocked => Err("Privacy Guard has not authorized a node for this wallet."),
            _ if self.daemon_rpc()?.address() == daemon.address() => Ok(()),
            _ => Err("The requested wallet daemon is outside the current privacy route."),
        }
    }
    pub fn wallet_exists(&self) -> bool {
        self.wallet_root
            .join("wallets")
            .join(format!("{}.keys", self.wallet_name()))
            .exists()
    }
    pub fn database_bytes(&self) -> u64 {
        std::fs::metadata(self.root.join("chain/stagenet/lmdb/data.mdb")).map_or(0, |m| m.len())
    }
    pub fn available_bytes(&self) -> Option<u64> {
        fs2::available_space(&self.root).ok()
    }
    pub fn p2p_port(&self) -> LabResult<u16> {
        // Monero separates its peer cache by non-default P2P port. Persist the
        // first random port so restarting can reuse discovered peers.
        let path = self.root.join("p2p-port.txt");
        if path.exists() {
            return std::fs::read_to_string(path)
                .ok()
                .and_then(|value| value.trim().parse::<u16>().ok())
                .filter(|port| *port >= 1024)
                .ok_or("The saved P2P port is invalid. Node startup was refused.");
        }
        let port = free_address()?.port();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|_| "Could not save the local P2P port.")?;
        write!(file, "{port}")
            .and_then(|_| file.sync_all())
            .map_err(|_| "Could not save the local P2P port.")?;
        Ok(port)
    }
    pub fn wallet_pid(&self) -> Option<u32> {
        self.wallet.as_ref().and_then(|p| p.child.id())
    }
    pub fn daemon_pid(&self) -> Option<u32> {
        self.daemon.as_ref().and_then(|p| p.child.id())
    }
    pub fn check_exits(&mut self) -> (bool, bool) {
        let node_exited = self
            .daemon
            .as_mut()
            .is_some_and(|p| p.child.try_wait().ok().flatten().is_some());
        let wallet_exited = self
            .wallet
            .as_mut()
            .is_some_and(|p| p.child.try_wait().ok().flatten().is_some());
        if node_exited {
            self.daemon = None;
        }
        if wallet_exited {
            self.wallet = None;
        }
        (node_exited, wallet_exited)
    }
    pub async fn start_node(&mut self) -> LabResult<()> {
        if self.network == Network::Mainnet
            && !matches!(self.node_access, NodeAccess::Gateway { .. })
        {
            return Err("This mainnet prototype requires its validated owned Tor route.");
        }
        match &self.node_access {
            NodeAccess::Blocked => {
                return Err("Privacy Guard has not established a permitted connection.")
            }
            NodeAccess::Gateway { .. } => return self.daemon_rpc().map(|_| ()),
            _ => (),
        }
        if self.daemon.is_some() {
            return Ok(());
        }
        if self
            .available_bytes()
            .is_some_and(|bytes| bytes < 10 * 1024 * 1024 * 1024)
        {
            return Err("Keep at least 10 GiB free before starting synchronization.");
        }
        let binary = self.binaries.join("monerod.exe");
        verify_binary(&binary, DAEMON_SHA256)?;
        let address = free_address()?;
        let p2p_port = self.p2p_port()?;
        let password = Zeroizing::new(random_secret());
        let config=Zeroizing::new(format!("stagenet=1\ndata-dir={}\nrpc-bind-ip=127.0.0.1\nrpc-bind-port={}\nrpc-login=autopilot:{}\nrpc-ssl=disabled\np2p-bind-ip=127.0.0.1\np2p-bind-port={}\nin-peers=0\nout-peers=8\nno-zmq=1\nprune-blockchain=1\nsync-pruned-blocks=1\nlimit-rate-down=8192\nlimit-rate-up=256\nmax-concurrency=8\nprep-blocks-threads=8\ncheck-updates=disabled\nlog-file={}\nlog-level=0\nmax-log-file-size=1048576\nmax-log-files=1\n",config_path(&self.root.join("chain"))?,address.port(),password.as_str(),p2p_port,config_path(&self.root.join("daemon.log"))?));
        self.daemon = Some(
            self.spawn(
                &binary,
                "node.conf",
                &config,
                Rpc::new(address, "autopilot".into(), password.to_string())?,
            )
            .await?,
        );
        let result = self.wait_ready(false).await;
        if result.is_err() {
            self.stop_node().await;
        }
        result
    }
    async fn spawn(
        &self,
        binary: &Path,
        name: &str,
        config: &str,
        rpc: Rpc,
    ) -> LabResult<OwnedProcess> {
        let path = self.root.join(name);
        std::fs::write(&path, config)
            .map_err(|_| "Could not write the private process configuration.")?;
        let result = Command::new(binary)
            .arg("--config-file")
            .arg(&path)
            .current_dir(&self.root)
            .creation_flags(HIDDEN)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let mut child = match result {
            Ok(child) => child,
            Err(_) => {
                let _ = std::fs::remove_file(path);
                return Err("Windows could not start the verified Monero executable. Check its Windows Security detection.");
            }
        };
        if let Err(error) = self.job.assign(&child) {
            let _ = child.kill().await;
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        Ok(OwnedProcess {
            child,
            rpc,
            config: path,
        })
    }
    async fn wait_ready(&mut self, wallet: bool) -> LabResult<()> {
        let mut last_error = "Monero did not become ready within the startup deadline.";
        for _ in 0..30 {
            let process = if wallet {
                self.wallet.as_mut()
            } else {
                self.daemon.as_mut()
            }
            .ok_or("Monero process did not start.")?;
            if process
                .child
                .try_wait()
                .map_err(|_| "Could not inspect child process.")?
                .is_some()
            {
                return Err("Monero exited during startup. Check the local diagnostic log.");
            }
            let method = if wallet { "get_version" } else { "get_info" };
            let response = process.rpc.call(method, json!({}), 2).await;
            if let Err(error) = response {
                last_error = error;
            }
            if let Ok(result) = response {
                if !wallet
                    && result.get("nettype").and_then(|v| v.as_str()) != Some(self.network.as_str())
                {
                    return Err("Daemon network does not match this wallet. Connection refused.");
                }
                let _ = std::fs::remove_file(&process.config);
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(last_error)
    }
    fn wallet_password(&self) -> LabResult<Zeroizing<String>> {
        let path = self.wallet_root.join("wallet-password.dpapi");
        if path.exists() {
            let protected = std::fs::read(path)
                .map_err(|_| "Could not read the protected wallet credential.")?;
            let bytes = platform::unprotect(&protected)?;
            return String::from_utf8(bytes.to_vec())
                .map(Zeroizing::new)
                .map_err(|_| "Protected credential has an invalid format.");
        }
        if self.wallet_exists() {
            return Err("Existing wallet credential is missing. The wallet will not be replaced.");
        }
        let password = Zeroizing::new(random_secret());
        let protected = platform::protect(password.as_bytes())?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|_| "Could not save the protected wallet credential.")?;
        file.write_all(&protected)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Could not save the protected wallet credential.")?;
        Ok(password)
    }
    pub async fn start_wallet(&mut self) -> LabResult<()> {
        self.start_wallet_inner(true).await
    }
    /// Recovery may only reopen existing wallet files, never create a replacement.
    pub async fn open_saved_wallet(&mut self) -> LabResult<()> {
        self.start_wallet_inner(false).await
    }
    async fn start_wallet_inner(&mut self, allow_create: bool) -> LabResult<()> {
        if self.wallet.is_some() {
            return Ok(());
        }
        if !allow_create && !self.wallet_exists() {
            return Err("The saved wallet is missing. It will not be replaced.");
        }
        let daemon = self.daemon_rpc()?;
        self.start_wallet_against(&daemon, allow_create).await
    }
    /// Used by the controlled second test wallet; no second blockchain is started.
    pub async fn start_wallet_against(
        &mut self,
        daemon: &Rpc,
        allow_create: bool,
    ) -> LabResult<()> {
        self.open_or_restore(daemon, allow_create, None).await
    }
    /// Restore only into an empty, separately selected wallet directory.
    pub async fn restore_wallet_against(
        &mut self,
        daemon: &Rpc,
        seed: &str,
        height: u64,
    ) -> LabResult<()> {
        if self.wallet.is_some()
            || self.wallet_exists()
            || self
                .wallet_root
                .join("wallets")
                .join(self.wallet_name())
                .exists()
        {
            return Err(
                "Restore requires a new empty wallet directory. Existing files are never replaced.",
            );
        }
        self.open_or_restore(daemon, false, Some((seed, height)))
            .await
    }
    async fn open_or_restore(
        &mut self,
        daemon: &Rpc,
        allow_create: bool,
        restore: Option<(&str, u64)>,
    ) -> LabResult<()> {
        self.check_wallet_daemon(daemon)?;
        if self.wallet.is_some() {
            return Ok(());
        }
        if !allow_create && restore.is_none() && !self.wallet_exists() {
            return Err("The saved wallet is missing.");
        }
        check_daemon_network(
            daemon,
            self.network,
            matches!(self.node_access, NodeAccess::Gateway { .. }),
        )
        .await?;
        let binary = self.binaries.join("monero-wallet-rpc.exe");
        verify_binary(&binary, WALLET_SHA256)?;
        // Reuse the daemon's authenticated context through a private serialized configuration.
        let daemon_login = daemon.credentials();
        let address = free_address()?;
        let login = Zeroizing::new(random_secret());
        let password = self.wallet_password()?;
        let config=Zeroizing::new(format!("{}wallet-dir={}\nrpc-bind-ip=127.0.0.1\nrpc-bind-port={}\nrpc-login=autopilot:{}\nrpc-ssl=disabled\ndaemon-address=http://{}\ndaemon-login={}\ndaemon-ssl=disabled\nuntrusted-daemon=1\nno-dns=1\nlog-file={}\nlog-level=0\nmax-log-file-size=1048576\nmax-log-files=1\n",if self.network == Network::Mainnet { "" } else { "stagenet=1\n" },config_path(&self.wallet_root.join("wallets"))?,address.port(),login.as_str(),daemon.address(),daemon_login.as_str(),config_path(&self.wallet_root.join("wallet.log"))?));
        self.wallet = Some(
            self.spawn(
                &binary,
                "wallet.conf",
                &config,
                Rpc::new(address, "autopilot".into(), login.to_string())?,
            )
            .await?,
        );
        let result=async {
            self.wait_ready(true).await?;
            let rpc=&self.wallet.as_ref().ok_or("Wallet process is missing.")?.rpc;
            if let Some((seed,height)) = restore { rpc.restore_wallet(self.wallet_name(), password.as_str(), seed, height).await?; }
            else if self.wallet_exists(){rpc.call("open_wallet",json!({"filename":self.wallet_name(),"password":password.as_str(),"autosave_current":true}),30).await?;}
            else if allow_create{rpc.call("create_wallet",json!({"filename":self.wallet_name(),"password":password.as_str(),"language":"English"}),30).await?;}
            else{return Err("The saved wallet is missing. It will not be replaced.");}
            rpc.call("auto_refresh",json!({"enable":true,"period":5}),10).await?;
            rpc.call("store",json!({}),15).await?;
            Ok(())
        }.await;
        if result.is_err() {
            self.stop_wallet().await;
        }
        result
    }
    pub async fn stop_wallet(&mut self) -> bool {
        let Some(mut wallet) = self.wallet.take() else {
            return true;
        };
        let _ = wallet
            .rpc
            .call("auto_refresh", json!({"enable":false}), 4)
            .await;
        let _ = wallet.rpc.call("stop_wallet", json!({}), 10).await;
        let graceful = matches!(
            tokio::time::timeout(Duration::from_secs(8), wallet.child.wait()).await,
            Ok(Ok(_))
        );
        if !graceful {
            let _ = wallet.child.kill().await;
        }
        graceful
    }
    pub async fn stop_node(&mut self) -> bool {
        let wallet_clean = self.stop_wallet().await;
        if matches!(self.node_access, NodeAccess::Gateway { .. }) {
            self.node_access = NodeAccess::Blocked;
        }
        let Some(mut daemon) = self.daemon.take() else {
            return wallet_clean;
        };
        let _ = daemon.rpc.stop_daemon().await;
        let graceful = matches!(
            tokio::time::timeout(Duration::from_secs(10), daemon.child.wait()).await,
            Ok(Ok(_))
        );
        if !graceful {
            let _ = daemon.child.kill().await;
        }
        graceful && wallet_clean
    }
}

#[cfg(test)]
mod privacy_tests {
    use super::*;

    async fn delayed_daemon(
        delay: Duration,
        network: &'static str,
    ) -> (Rpc, tokio::task::JoinHandle<()>) {
        use axum::{
            http::{header, HeaderMap, StatusCode},
            response::{IntoResponse, Response},
            routing::post,
            Json, Router,
        };
        use serde_json::Value;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handler = move |headers: HeaderMap, Json(request): Json<Value>| async move {
            if !headers.contains_key(header::AUTHORIZATION) {
                return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE,
                    "Digest realm=\"fixture\", nonce=\"fixture-nonce\", algorithm=MD5, qop=\"auth\"")]).into_response();
            }
            tokio::time::sleep(delay).await;
            let response: Response =
                Json(json!({"jsonrpc":"2.0","id":request["id"],"result":{"nettype":network}}))
                    .into_response();
            response
        };
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/json_rpc", post(handler)))
                .await
                .unwrap();
        });
        (
            Rpc::new(address, "fixture".into(), "fixture".into()).unwrap(),
            server,
        )
    }

    #[tokio::test]
    async fn routed_preflight_tolerates_tor_latency_but_keeps_local_and_network_checks() {
        let (remote, remote_server) = delayed_daemon(Duration::from_millis(3500), "stagenet").await;
        let (local, local_server) = delayed_daemon(Duration::from_millis(3500), "stagenet").await;
        let (routed, direct) = tokio::join!(
            check_daemon_network(&remote, Network::Stagenet, true),
            check_daemon_network(&local, Network::Stagenet, false)
        );
        remote_server.abort();
        local_server.abort();
        assert!(
            routed.is_ok(),
            "A slow valid gateway response must not prevent wallet startup"
        );
        assert_eq!(direct, Err("Local RPC operation exceeded its deadline."));

        let (wrong, wrong_server) = delayed_daemon(Duration::ZERO, "mainnet").await;
        let refused = check_daemon_network(&wrong, Network::Stagenet, true).await;
        wrong_server.abort();
        assert_eq!(refused, Err("Daemon network does not match this wallet."));
    }

    #[tokio::test]
    async fn guarded_backend_rejects_unreviewed_daemons_and_legacy_reopen() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path().join("isolated-wallet");
        let binaries = folder.path().join("intentionally-no-binaries");
        let mut supervisor = Supervisor::new_guarded(root.clone(), binaries.clone())
            .await
            .unwrap();
        assert!(supervisor.start_node().await.is_err());
        assert!(supervisor.daemon.is_none());
        let unauthorized = Rpc::new(
            "127.0.0.1:38081".parse().unwrap(),
            "fixture".into(),
            "fixture".into(),
        )
        .unwrap();
        assert!(supervisor
            .start_wallet_against(&unauthorized, true)
            .await
            .is_err());
        assert!(supervisor.wallet.is_none());
        assert!(!supervisor.wallet_exists());
        assert!(supervisor.authorize_local_node(&Config::default()).is_err());
        let without_consent = Config {
            profile: Profile::LocalNode,
            ..Config::default()
        };
        assert!(supervisor.authorize_local_node(&without_consent).is_err());
        // Exposing no generic set_daemon/light-wallet RPC prevents a UI caller
        // from switching the native backend around the gateway.
        assert!(unauthorized
            .call(
                "set_daemon",
                json!({"address":"https://unapproved.invalid"}),
                1
            )
            .await
            .is_err());
        assert!(unauthorized
            .call("query_key", json!({"key_type":"view_key"}), 1)
            .await
            .is_err());
        drop(supervisor);
        assert!(Supervisor::new_secured(root.clone(), binaries.clone())
            .await
            .is_err());
        assert!(Supervisor::new(root, binaries).await.is_err());
    }
}
