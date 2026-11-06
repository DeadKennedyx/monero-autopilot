//! Restricted local JSON-RPC client. Never exposes arbitrary RPC forwarding to the UI.
use crate::LabResult;
use autopilot_privacy::config::Network;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

/// Deliberate fee policy, never an arbitrary native RPC priority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPriority {
    #[default]
    Automatic,
    Economy,
}

#[cfg(test)]
mod backup_tests {
    use super::*;
    use axum::{
        http::{header, HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
        Json, Router,
    };

    #[tokio::test]
    async fn backup_read_waits_for_in_flight_refresh_without_retrying() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let observed = calls.clone();
        let handler = move |headers: HeaderMap, Json(request): Json<Value>| {
            let calls = calls.clone();
            async move {
                if !headers.contains_key(header::AUTHORIZATION) {
                    return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE,
                        "Digest realm=\"fixture\", nonce=\"fixture-nonce\", algorithm=MD5, qop=\"auth\"")]).into_response();
                }
                assert_eq!(request["method"], "query_key");
                assert_eq!(request["params"], json!({"key_type":"mnemonic"}));
                calls.fetch_add(1, Ordering::SeqCst);
                // Simulate Monero's shared RPC/refresh thread exceeding the old
                // ten-second deadline. This is a synthetic, unfunded phrase.
                tokio::time::sleep(Duration::from_secs(11)).await;
                Json(json!({"jsonrpc":"2.0","id":request["id"],"result":{"key":vec!["fixture";25].join(" ")}})).into_response()
            }
        };
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/json_rpc", post(handler)))
                .await
                .unwrap();
        });
        let rpc = Rpc::new(address, "fixture".into(), "fixture".into()).unwrap();
        let result = rpc.recovery_phrase().await;
        server.abort();
        assert_eq!(result.unwrap().split_whitespace().count(), 25);
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        assert!(rpc
            .call("query_key", json!({"key_type":"mnemonic"}), 1)
            .await
            .is_err());
    }
}

fn wipe(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => (),
    }
}

fn deadline_error(method: &str) -> &'static str {
    // Only fixed operation names appear in diagnostics. Never interpolate
    // request arguments, credentials, wallet names, addresses or recovery words.
    match method {
        "get_info" => "Local RPC get_info exceeded its deadline.",
        "get_version" => "Local RPC get_version exceeded its deadline.",
        "create_wallet" => "Local RPC create_wallet exceeded its deadline.",
        "open_wallet" => "Local RPC open_wallet exceeded its deadline.",
        "restore_deterministic_wallet" => {
            "Local RPC restore_deterministic_wallet exceeded its deadline."
        }
        "get_height" => "Local RPC get_height exceeded its deadline.",
        "get_address" => "Local RPC get_address exceeded its deadline.",
        "create_address" => "Local RPC create_address exceeded its deadline.",
        "validate_address" => "Local RPC validate_address exceeded its deadline.",
        "get_balance" => "Local RPC get_balance exceeded its deadline.",
        "get_transfers" => "Local RPC get_transfers exceeded its deadline.",
        "get_transfer_by_txid" => "Local RPC get_transfer_by_txid exceeded its deadline.",
        "auto_refresh" => "Local RPC auto_refresh exceeded its deadline.",
        "store" => "Local RPC store exceeded its deadline.",
        "stop_wallet" => "Local RPC stop_wallet exceeded its deadline.",
        "transfer" => "Local RPC transfer exceeded its deadline.",
        "relay_tx" => "Local RPC relay_tx exceeded its deadline.",
        "query_key" => "Local RPC query_key exceeded its deadline.",
        _ => "Local RPC operation exceeded its deadline.",
    }
}

#[derive(Clone)]
pub struct Rpc {
    client: reqwest::Client,
    address: SocketAddr,
    user: Arc<str>,
    password: Arc<Zeroizing<String>>,
    sequence: Arc<AtomicU64>,
    session: Arc<tokio::sync::Mutex<()>>,
}
impl Rpc {
    pub fn new(address: SocketAddr, user: String, password: String) -> LabResult<Self> {
        if address.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
            return Err("Only explicit loopback RPC endpoints are allowed.");
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(1)
            .connect_timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| "Could not initialize local RPC transport.")?;
        Ok(Self {
            client,
            address,
            user: user.into(),
            password: Arc::new(Zeroizing::new(password)),
            sequence: Arc::new(AtomicU64::new(1)),
            session: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub(crate) fn credentials(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{}:{}", self.user, self.password.as_str()))
    }
    pub async fn call(&self, method: &str, params: Value, seconds: u64) -> LabResult<Value> {
        if !matches!(
            method,
            "get_info"
                | "get_version"
                | "create_wallet"
                | "open_wallet"
                | "get_height"
                | "get_address"
                | "create_address"
                | "validate_address"
                | "get_balance"
                | "get_transfers"
                | "get_transfer_by_txid"
                | "auto_refresh"
                | "store"
                | "stop_wallet"
        ) {
            return Err("This wallet operation is not permitted.");
        }
        self.call_inner(method, params, seconds).await
    }
    /// The only transaction construction path always disables broadcast.
    pub async fn prepare_transfer(&self, address: &str, amount: u64) -> LabResult<Value> {
        self.prepare_transfer_for(address, amount, Network::Stagenet)
            .await
    }
    /// Mainnet ring selection may need a bounded bulk response through Tor.
    /// This changes only the construction deadline, never relay or retry policy.
    pub async fn prepare_transfer_for(
        &self,
        address: &str,
        amount: u64,
        network: Network,
    ) -> LabResult<Value> {
        self.prepare_transfer_with_priority(address, amount, network, TransferPriority::Automatic)
            .await
    }
    pub async fn prepare_transfer_with_priority(
        &self,
        address: &str,
        amount: u64,
        network: Network,
        priority: TransferPriority,
    ) -> LabResult<Value> {
        let seconds = match network {
            Network::Mainnet => 120,
            Network::Stagenet => 30,
            Network::Testnet => {
                return Err("Testnet payments are not supported by this prototype.")
            }
        };
        let native_priority = match priority {
            TransferPriority::Automatic => 0,
            TransferPriority::Economy => 1,
        };
        self.call_inner("transfer", json!({"destinations":[{"address":address,"amount":amount}],"account_index":0,"priority":native_priority,"unlock_time":0,"do_not_relay":true,"get_tx_metadata":true,"get_tx_key":false,"get_tx_hex":false}), seconds).await
    }
    /// Call only after durably recording the user's confirmation. Never retry automatically.
    pub async fn relay_prepared(&self, metadata: &str) -> LabResult<Value> {
        if metadata.is_empty()
            || metadata.len() > 60000
            || !metadata.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err("Invalid prepared transaction.");
        }
        self.call_inner("relay_tx", json!({"hex":metadata}), 25)
            .await
    }
    /// Deliberate backup only. Never included in status, events, or generic RPC forwarding.
    pub async fn recovery_phrase(&self) -> LabResult<Zeroizing<String>> {
        // Monero serves RPC on the same thread as background refresh. A local
        // read can therefore wait for an in-flight Tor scan even though it does
        // not itself use the network. Keep the wait bounded, but allow that scan
        // to finish instead of failing after ten seconds. Never retry the read.
        let mut result = self
            .call_inner("query_key", json!({"key_type":"mnemonic"}), 60)
            .await?;
        let phrase = match result["key"].take() {
            Value::String(s) => Zeroizing::new(s),
            _ => return Err("A recovery phrase is unavailable for this wallet."),
        };
        wipe(&mut result);
        if phrase.split_whitespace().count() != 25 {
            return Err("This wallet requires a standard 25-word recovery phrase.");
        }
        Ok(phrase)
    }
    pub(crate) async fn restore_wallet(
        &self,
        filename: &str,
        password: &str,
        seed: &str,
        height: u64,
    ) -> LabResult<()> {
        let mut result = self
            .call_inner(
                "restore_deterministic_wallet",
                json!({
                    "filename":filename,"password":password,"seed":seed,
                    "restore_height":height,"language":"English","autosave_current":true,
                    "enable_multisig_experimental":false
                }),
                45,
            )
            .await?;
        wipe(&mut result);
        Ok(())
    }
    async fn call_inner(&self, method: &str, mut params: Value, seconds: u64) -> LabResult<Value> {
        let id = self.sequence.fetch_add(1, Ordering::Relaxed).to_string();
        let body = Zeroizing::new(
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":&params}))
                .map_err(|_| "Could not encode RPC request.")?,
        );
        wipe(&mut params);
        let mut value = self
            .send("/json_rpc", &body, seconds)
            .await
            .map_err(|error| {
                if error == "Local RPC operation exceeded its deadline." {
                    deadline_error(method)
                } else {
                    error
                }
            })?;
        if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || value.get("id").and_then(Value::as_str) != Some(id.as_str())
        {
            wipe(&mut value);
            return Err("RPC response identity did not match the request.");
        }
        if value.get("error").is_some() {
            wipe(&mut value);
            return Err("The Monero backend rejected the operation.");
        }
        let result = value
            .get_mut("result")
            .map(Value::take)
            .ok_or("RPC result is missing.");
        wipe(&mut value);
        result
    }
    pub async fn stop_daemon(&self) -> LabResult<()> {
        self.send("/stop_daemon", b"{}", 15).await.map(|_| ())
    }
    async fn send(&self, path: &str, body: &[u8], seconds: u64) -> LabResult<Value> {
        tokio::time::timeout(Duration::from_secs(seconds), async {
            // Monero's digest nonce belongs to its TCP session. Serialize the
            // challenge/response pair and drain the 401 body to reuse that socket.
            let _session = self.session.lock().await;
            let url = format!("http://{}{path}", self.address);
            let mut first = self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .body("{}")
                .send()
                .await
                .map_err(|_| "Local RPC is unavailable or timed out.")?;
            if first.status() != reqwest::StatusCode::UNAUTHORIZED {
                return Err("RPC authentication was not enforced as expected.");
            }
            let challenge = first
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .filter(|v| v.len() < 4096)
                .ok_or("RPC authentication challenge is missing.")?;
            let mut challenge = digest_auth::parse(challenge)
                .map_err(|_| "RPC authentication challenge is invalid.")?;
            let context = digest_auth::AuthContext::new_post(
                self.user.as_ref(),
                self.password.as_str(),
                path,
                Some(body),
            );
            let answer = Zeroizing::new(
                challenge
                    .respond(&context)
                    .map_err(|_| "RPC digest authentication failed.")?
                    .to_string(),
            );
            let mut challenge_bytes = 0;
            while let Some(chunk) = first
                .chunk()
                .await
                .map_err(|_| "RPC challenge was interrupted.")?
            {
                challenge_bytes += chunk.len();
                if challenge_bytes > 4096 {
                    return Err("RPC challenge exceeded the size limit.");
                }
            }
            drop(first);
            let mut response = self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .header(reqwest::header::AUTHORIZATION, answer.as_str())
                .body(body.to_vec())
                .send()
                .await
                .map_err(|_| "Local RPC is unavailable or timed out.")?;
            if !response.status().is_success() {
                return Err("Authenticated RPC request was refused.");
            }
            if response.content_length().is_some_and(|n| n > 65536) {
                return Err("RPC response exceeded the size limit.");
            }
            let mut data = Zeroizing::new(Vec::new());
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| "RPC response was interrupted.")?
            {
                if data.len() + chunk.len() > 65536 {
                    return Err("RPC response exceeded the size limit.");
                }
                data.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&data).map_err(|_| "RPC response was not valid JSON.")
        })
        .await
        .map_err(|_| "Local RPC operation exceeded its deadline.")?
    }
}
