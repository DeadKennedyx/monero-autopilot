//! Shared native/review host. Failed initialization serves only a redacted
//! explanation and shutdown; it never substitutes default privacy settings.
use crate::{
    api::{self, ApiState, LocalApiGuard},
    runner::Runtime,
};
use autopilot_privacy::Denial;
use axum::{
    extract::DefaultBodyLimit,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::json;
use std::{net::Ipv4Addr, path::PathBuf, time::Duration};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Serialize)]
pub struct StartupIssue {
    pub code: &'static str,
    pub message: &'static str,
    pub next_step: &'static str,
}
impl StartupIssue {
    fn from_error(error: &'static str) -> Self {
        if error == Denial::UnknownVersion.message() {
            Self { code: "unknown_policy_version", message: "Your saved privacy policy uses a version this app cannot read.", next_step: "Close AutoPilot and use an app version that supports the saved policy. Keep your wallet and settings files in place." }
        } else if [
            Denial::CorruptConfiguration,
            Denial::InvalidConfiguration,
            Denial::InvalidEndpoint,
            Denial::InvalidOnion,
            Denial::InvalidI2p,
            Denial::TlsRequired,
            Denial::ConsentRequired,
        ]
        .iter()
        .any(|d| d.message() == error)
        {
            Self { code: "invalid_privacy_configuration", message: "Your saved privacy settings are missing, damaged, or inconsistent.", next_step: "Close AutoPilot and review the saved privacy configuration or recover a known-good copy. Your policy will not be reset automatically." }
        } else if error == "Another wallet lab already owns this data directory." {
            Self {
                code: "data_directory_in_use",
                message: "Another AutoPilot process is already using this wallet directory.",
                next_step:
                    "Return to the open wallet app, or close it normally before opening this one.",
            }
        } else if error
            == "This data directory belongs to a different network. Use a separate directory."
        {
            Self {
                code: "network_mismatch",
                message: "This wallet directory belongs to another network.",
                next_step: "Open the mainnet profile with this app. Keep your existing test-network wallet files in their separate directory.",
            }
        } else {
            // Never reflect raw runtime errors or filesystem content into the UI.
            Self { code: "initialization_failed", message: "AutoPilot could not open the saved wallet configuration.", next_step: "Close AutoPilot and check local file access and the saved settings before trying again. Keep the existing wallet files in place." }
        }
    }
}

pub struct Host {
    pub url: String,
    pub startup_issue: Option<StartupIssue>,
    pub shutdown: CancellationToken,
    pub finished: CancellationToken,
    runtime: Option<Runtime>,
    server: JoinHandle<()>,
}
impl Host {
    /// Port zero reserves a new loopback-only port. Initialization failure does
    /// not expose the wallet API, configuration writes, or a PIN reset path.
    pub async fn start(
        root: PathBuf,
        binaries: PathBuf,
        html: String,
        port: u16,
    ) -> std::io::Result<Self> {
        Self::start_network(root, binaries, html, port, false).await
    }
    /// Main desktop entry. Reuses the prototype's pinned mainnet runtime and
    /// profile lease, with no fallback to the older stagenet host.
    pub async fn start_mainnet(
        root: PathBuf,
        binaries: PathBuf,
        html: String,
        port: u16,
    ) -> std::io::Result<Self> {
        Self::start_network(root, binaries, html, port, true).await
    }
    async fn start_network(
        root: PathBuf,
        binaries: PathBuf,
        html: String,
        port: u16,
        mainnet: bool,
    ) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let address = listener.local_addr()?;
        let token = uuid::Uuid::new_v4().simple().to_string();
        let authority = address.to_string();
        let initialized = if mainnet {
            Runtime::start_mainnet(root, binaries).await
        } else {
            Runtime::start_with_privacy(root, binaries).await
        };
        let (runtime, startup_issue, router, shutdown, finished) = match initialized {
            Ok(runtime) => {
                let router = api::router(ApiState {
                    client: runtime.client.clone(),
                    token,
                    authority,
                    html,
                });
                let shutdown = runtime.client.shutdown.clone();
                let finished = runtime.client.finished.clone();
                (Some(runtime), None, router, shutdown, finished)
            }
            Err(error) => {
                let issue = StartupIssue::from_error(error);
                let shutdown = CancellationToken::new();
                // No actor or owned backend exists in this branch.
                let finished = shutdown.clone();
                let page = html.replace("__LAB_TOKEN__", &token);
                let snapshot = json!({"startup": &issue});
                let close = shutdown.clone();
                let router = Router::new()
                    .route(
                        "/",
                        get(move || {
                            let page = page.clone();
                            async { Html(page) }
                        }),
                    )
                    .route(
                        "/api/snapshot",
                        get(move || {
                            let snapshot = snapshot.clone();
                            async { Json(snapshot) }
                        }),
                    )
                    .route(
                        "/api/shutdown",
                        post(move || {
                            close.cancel();
                            async { Json(json!({"stopping":true})) }
                        }),
                    )
                    .layer(DefaultBodyLimit::max(1024));
                let router = api::protect_local_api(router, LocalApiGuard { token, authority });
                (None, Some(issue), router, shutdown, finished)
            }
        };
        let stop = finished.clone();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await;
        });
        Ok(Self {
            url: format!("http://{address}/"),
            runtime,
            startup_issue,
            shutdown,
            finished,
            server,
        })
    }
    pub async fn stop(mut self) {
        self.shutdown.cancel();
        if let Some(runtime) = self.runtime.take() {
            runtime.stop().await;
        }
        self.finished.cancel();
        if tokio::time::timeout(Duration::from_secs(2), &mut self.server)
            .await
            .is_err()
        {
            self.server.abort();
        }
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.server.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityCommand;
    use autopilot_wallet_lab::supervisor::Supervisor;

    fn root() -> PathBuf {
        std::env::current_dir()
            .unwrap()
            .join(".runtime/desktop-host-tests")
            .join(uuid::Uuid::new_v4().simple().to_string())
    }

    #[tokio::test]
    async fn mainnet_desktop_reuses_profile_after_prototype_exit_and_shares_its_exclusive_lease() {
        let dir = root();
        let prototype = Runtime::start_mainnet(dir.clone(), dir.join("no-binaries"))
            .await
            .unwrap();
        prototype
            .client
            .security_command(
                SecurityCommand::Configure {
                    pin: "584239".into(),
                    confirm_pin: "584239".into(),
                },
                None,
            )
            .await
            .unwrap();
        let cache = dir.join("wallets/preserved-wallet-cache");
        std::fs::write(&cache, b"isolated preservation fixture").unwrap();
        let pin_before = std::fs::read(dir.join("security/pin.dpapi")).unwrap();
        let policy_before = std::fs::read(dir.join("privacy/privacy.json")).unwrap();
        let blocked = Host::start_mainnet(
            dir.clone(),
            dir.join("no-binaries"),
            "__LAB_TOKEN__".into(),
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            blocked.startup_issue.as_ref().unwrap().code,
            "data_directory_in_use"
        );
        assert!(blocked.runtime.is_none());
        blocked.stop().await;
        assert!(!prototype.client.finished.is_cancelled());
        prototype.stop().await;

        let desktop = Host::start_mainnet(
            dir.clone(),
            dir.join("no-binaries"),
            "__LAB_TOKEN__".into(),
            0,
        )
        .await
        .unwrap();
        assert!(desktop.startup_issue.is_none());
        let client = &desktop.runtime.as_ref().unwrap().client;
        assert_eq!(client.state.read().await.network, "mainnet");
        let security = client.security.as_ref().unwrap().snapshot(None).await;
        assert!(security.configured && security.locked);
        assert_eq!(
            std::fs::read(dir.join("security/pin.dpapi")).unwrap(),
            pin_before
        );
        assert_eq!(
            std::fs::read(dir.join("privacy/privacy.json")).unwrap(),
            policy_before
        );
        assert_eq!(
            std::fs::read(&cache).unwrap(),
            b"isolated preservation fixture"
        );
        assert!(Runtime::start_mainnet(dir.clone(), dir.join("no-binaries"))
            .await
            .is_err());
        desktop.stop().await;
        let reopened = Runtime::start_mainnet(dir.clone(), dir.join("no-binaries"))
            .await
            .unwrap();
        reopened.stop().await;
    }

    #[tokio::test]
    async fn mainnet_desktop_refuses_a_stagenet_profile_without_rewriting_it() {
        let dir = root();
        drop(
            Supervisor::new_guarded(dir.clone(), dir.join("no-binaries"))
                .await
                .unwrap(),
        );
        let marker = std::fs::read(dir.join("network.json")).unwrap();
        let policy = std::fs::read(dir.join("privacy/privacy.json")).unwrap();
        let cache = dir.join("wallets/preserved-stagenet-cache");
        std::fs::write(&cache, b"keep test wallet in place").unwrap();
        let desktop = Host::start_mainnet(
            dir.clone(),
            dir.join("no-binaries"),
            "__LAB_TOKEN__".into(),
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            desktop.startup_issue.as_ref().unwrap().code,
            "network_mismatch"
        );
        assert!(desktop.runtime.is_none());
        assert_eq!(std::fs::read(dir.join("network.json")).unwrap(), marker);
        assert_eq!(
            std::fs::read(dir.join("privacy/privacy.json")).unwrap(),
            policy
        );
        assert_eq!(std::fs::read(cache).unwrap(), b"keep test wallet in place");
        assert!(!dir.join("security/pin.dpapi").exists());
        desktop.stop().await;
    }
}
