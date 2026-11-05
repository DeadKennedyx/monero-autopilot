//! App-owned Tor runtime. No system installation, existing proxy adoption or
//! direct fallback. The Windows job also terminates Tor if the host crashes.
use crate::{
    platform::{Job, HIDDEN},
    LabResult,
};
use autopilot_privacy::endpoint::ProxyEndpoint;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    task::JoinHandle,
};

pub const TOR_SHA256: &str = "1607d98f5d13859077b1b349c55beba76b09acc788f0431fd824d11966fb1074";
const TOR_BYTES: &[u8] = include_bytes!("../../../.tools/tor/release/tor/tor.exe");
const LICENSES: &[(&str, &[u8])] = &[
    (
        "tor.txt",
        include_bytes!("../../../.tools/tor/release/docs/tor.txt"),
    ),
    (
        "openssl.txt",
        include_bytes!("../../../.tools/tor/release/docs/openssl.txt"),
    ),
    (
        "libevent.txt",
        include_bytes!("../../../.tools/tor/release/docs/libevent.txt"),
    ),
    (
        "zlib.txt",
        include_bytes!("../../../.tools/tor/release/docs/zlib.txt"),
    ),
];
const BOOTSTRAP_LIMIT: Duration = Duration::from_secs(240);
const MAX_STARTS: u8 = 3;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TorState {
    Stopped,
    Starting,
    Ready,
    Restarting,
    Failed,
}
#[derive(Clone, Debug, Serialize)]
pub struct TorSnapshot {
    pub state: TorState,
    pub bootstrap_percent: u8,
    pub starts: u8,
    pub pid: Option<u32>,
    pub error: Option<&'static str>,
}
pub struct ManagedTor {
    root: PathBuf,
    child: Option<Child>,
    job: Option<Job>,
    reader: Option<JoinHandle<()>>,
    progress: Arc<AtomicU8>,
    state: TorState,
    starts: u8,
    started: Option<Instant>,
    retry_at: Option<Instant>,
    proxy: Option<ProxyEndpoint>,
    error: Option<&'static str>,
    enabled: bool,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn checked_path(path: &Path) -> LabResult<String> {
    let value = path.to_str().ok_or("Tor cannot use this local path.")?;
    if value.contains(['\r', '\n', '"', '#']) {
        return Err("Tor cannot use this local path.");
    }
    Ok(value
        .strip_prefix(r"\\?\")
        .unwrap_or(value)
        .replace('\\', "/"))
}
/// Existing modified binaries are refused, never silently repaired or executed.
pub fn unpack(directory: &Path) -> LabResult<PathBuf> {
    if digest(TOR_BYTES) != TOR_SHA256 {
        return Err("Bundled Tor verification failed. Rebuild from the verified release.");
    }
    fs::create_dir_all(directory).map_err(|_| "Could not prepare the bundled Tor directory.")?;
    let binary = directory.join("tor.exe");
    if !binary.exists() {
        let temp = directory.join(format!("tor-{}.tmp", uuid::Uuid::new_v4().simple()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
                .map_err(|_| "Could not unpack bundled Tor.")?;
            file.write_all(TOR_BYTES)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Could not save bundled Tor.")?;
            fs::rename(&temp, &binary).map_err(|_| "Could not finish unpacking bundled Tor.")
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result?;
    }
    let bytes = fs::read(&binary).map_err(|_| {
        "Bundled Tor is missing or blocked. Review the app installation and Windows Security."
    })?;
    if digest(&bytes) != TOR_SHA256 {
        return Err("Bundled Tor has changed. Execution refused.");
    }
    for (name, bytes) in LICENSES {
        fs::write(directory.join(name), bytes)
            .map_err(|_| "Could not save bundled Tor license notices.")?;
    }
    Ok(binary)
}
impl ManagedTor {
    /// `root` must be inside the host's current-user-only data directory.
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            child: None,
            job: None,
            reader: None,
            progress: Arc::new(AtomicU8::new(0)),
            state: TorState::Stopped,
            starts: 0,
            started: None,
            retry_at: None,
            proxy: None,
            error: None,
            enabled: false,
        }
    }
    pub fn begin(&mut self) {
        self.enabled = true;
        self.starts = 0;
        self.error = None;
        self.retry_at = None;
        if self.child.is_none() {
            self.state = TorState::Starting;
        }
    }
    pub fn snapshot(&self) -> TorSnapshot {
        TorSnapshot {
            state: self.state,
            bootstrap_percent: self.progress.load(Ordering::Relaxed),
            starts: self.starts,
            pid: self.child.as_ref().and_then(Child::id),
            error: self.error,
        }
    }
    pub fn proxy(&self) -> Option<ProxyEndpoint> {
        if self.state == TorState::Ready {
            self.proxy
        } else {
            None
        }
    }
    fn start(&mut self) -> LabResult<()> {
        let bundle = self.root.join("bundle-0.4.9.15");
        let binary = unpack(&bundle)?;
        let data = self.root.join("data");
        fs::create_dir_all(&data).map_err(|_| "Could not prepare Tor state.")?;
        let address = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|l| l.local_addr())
            .map_err(|_| "Could not allocate Tor's private port.")?;
        let config = self.root.join("torrc");
        let defaults = self.root.join("defaults-empty");
        fs::write(&defaults, b"").map_err(|_| "Could not write Tor defaults.")?;
        fs::write(&config, format!("ClientOnly 1\nDataDirectory \"{}\"\nSocksPort {}\nSocksPolicy accept 127.0.0.1\nSocksPolicy reject *\nSafeSocks 1\nAvoidDiskWrites 1\nLog notice stdout\n", checked_path(&data)?, address)).map_err(|_| "Could not save Tor configuration.")?;
        let job = Job::new()?;
        let mut child = Command::new(&binary)
            .args(["--defaults-torrc"])
            .arg(&defaults)
            .arg("-f")
            .arg(&config)
            .current_dir(&bundle)
            .creation_flags(HIDDEN)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| {
                "Bundled Tor could not start. Review Windows Security if it was blocked."
            })?;
        if let Err(error) = job.assign(&child) {
            let _ = child.start_kill();
            return Err(error);
        }
        let output = child
            .stdout
            .take()
            .ok_or("Tor startup status is unavailable.")?;
        self.progress.store(0, Ordering::Relaxed);
        let progress = self.progress.clone();
        self.reader = Some(tokio::spawn(async move {
            let mut lines = BufReader::new(output).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(part) = line.split("Bootstrapped ").nth(1) {
                    if let Some(percent) = part
                        .split('%')
                        .next()
                        .and_then(|v| v.parse::<u8>().ok())
                        .filter(|v| *v <= 100)
                    {
                        progress.store(percent, Ordering::Relaxed);
                    }
                }
                // Never store or forward raw Tor log lines to the app.
            }
        }));
        self.child = Some(child);
        self.job = Some(job);
        self.proxy = Some(
            ProxyEndpoint::parse(&address.to_string())
                .map_err(|_| "Invalid managed Tor endpoint.")?,
        );
        self.starts += 1;
        self.started = Some(Instant::now());
        self.state = TorState::Starting;
        self.error = None;
        Ok(())
    }
    fn clear_process(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        self.job = None;
        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
        self.proxy = None;
        self.started = None;
        self.progress.store(0, Ordering::Relaxed);
    }
    /// Fast periodic check. Bootstrap never blocks the host actor or its lock UI.
    pub fn tick(&mut self) {
        if !self.enabled || self.state == TorState::Failed {
            return;
        }
        if let Some(child) = &mut self.child {
            if !matches!(child.try_wait(), Ok(None)) {
                self.clear_process();
                self.error =
                    Some("Built-in Tor stopped. Your wallet stays offline while it restarts.");
                if self.starts >= MAX_STARTS {
                    self.state = TorState::Failed;
                    self.error=Some("Built-in Tor could not stay running. Select Retry connection to try again.");
                } else {
                    self.state = TorState::Restarting;
                    self.retry_at = Some(
                        Instant::now() + Duration::from_secs(2u64.pow(u32::from(self.starts))),
                    );
                }
                return;
            }
            if self.progress.load(Ordering::Relaxed) == 100 {
                self.state = TorState::Ready;
                self.error = None;
            } else if self
                .started
                .is_some_and(|at| at.elapsed() >= BOOTSTRAP_LIMIT)
            {
                self.clear_process();
                self.state = TorState::Failed;
                self.error=Some("Built-in Tor could not connect within four minutes. Check your connection, then retry.");
            }
            return;
        }
        if self.retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }
        if let Err(error) = self.start() {
            self.clear_process();
            self.state = TorState::Failed;
            self.error = Some(error);
        }
    }
    pub async fn stop(&mut self) {
        self.enabled = false;
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        }
        self.clear_process();
        self.state = TorState::Stopped;
        self.error = None;
        self.retry_at = None;
    }
}
impl Drop for ManagedTor {
    fn drop(&mut self) {
        self.clear_process();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_bundle_is_extracted_and_modified_runtime_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let exe = unpack(directory.path()).unwrap();
        assert_eq!(digest(&fs::read(&exe).unwrap()), TOR_SHA256);
        fs::write(&exe, b"changed").unwrap();
        assert_eq!(
            unpack(directory.path()).unwrap_err(),
            "Bundled Tor has changed. Execution refused."
        );
        assert_eq!(fs::read(exe).unwrap(), b"changed");
    }
    #[tokio::test]
    async fn missing_or_modified_runtime_fails_without_a_proxy_capability() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("bundle-0.4.9.15");
        fs::create_dir_all(&bundle).unwrap();
        fs::write(bundle.join("tor.exe"), b"changed").unwrap();
        let mut tor = ManagedTor::new(directory.path().into());
        tor.begin();
        tor.tick();
        assert_eq!(tor.snapshot().state, TorState::Failed);
        assert!(tor.proxy().is_none());
        assert!(tor.snapshot().pid.is_none());
        tor.stop().await;
        assert_eq!(tor.snapshot().state, TorState::Stopped);
    }
}
