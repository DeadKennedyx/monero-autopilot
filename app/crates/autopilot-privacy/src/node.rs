//! Bounded node observations. Height and genesis checks do not establish honesty.
use crate::{
    config::Network,
    policy::RoutePlan,
    transport::{DaemonPath, NodeTransport, RoutedClient, HEALTH_RESPONSE},
    Denial, Result,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

// Tor health validation can take several round trips. The lease must outlast
// one bounded probe plus the five-second monitor interval. Failed probes revoke
// immediately; this limit also covers a stalled monitor or suspended host.
const PROBE_DEADLINE: Duration = Duration::from_secs(45);

/// Published CAIP-2 Monero chain identifiers (128-bit genesis-hash prefixes).
/// Also require a complete 32-byte hash, height zero and matching network flags.
/// https://namespaces.chainagnostic.org/monero/caip2
fn genesis_prefix(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "418015bb9ae982a1975da7d79277c270",
        Network::Stagenet => "76ee3cc98646292206cd3e86f74d88b4",
        Network::Testnet => "48ca7cd3c8de5b6a4d53d2861fbdaedc",
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct NodeHealth {
    pub network: Network,
    pub height: u64,
    pub target_height: u64,
    pub latency_ms: u64,
    pub checked_at: u64,
    pub synchronized: bool,
    pub compared_with_other_node: bool,
    #[serde(skip)]
    pub top_hash: String,
}
fn hash(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(Denial::InvalidResponse)
}
fn number(value: &Value) -> Result<u64> {
    value.as_u64().ok_or(Denial::InvalidResponse)
}

async fn rpc<T: NodeTransport>(
    transport: &T,
    method: &str,
    params: Value,
    sequence: u8,
) -> Result<Value> {
    let id = format!("privacy-{}-{sequence}", uuid::Uuid::new_v4().simple());
    let body =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .map_err(|_| Denial::InvalidResponse)?;
    let bytes = transport
        .request(DaemonPath::parse("/json_rpc")?, body, HEALTH_RESPONSE)
        .await?;
    let mut envelope: Value =
        serde_json::from_slice(&bytes).map_err(|_| Denial::InvalidResponse)?;
    if envelope["id"] != id
        || envelope["jsonrpc"] != "2.0"
        || envelope.get("error").is_some()
        || !envelope["result"].is_object()
        || envelope["result"]["status"] != "OK"
    {
        return Err(Denial::InvalidResponse);
    }
    if envelope["result"]["untrusted"] == true {
        return Err(Denial::NodeNotReady);
    }
    Ok(envelope["result"].take())
}
/// Validate real responses, with optional previous/independent approved samples.
pub async fn probe<T: NodeTransport>(
    transport: &T,
    network: Network,
    now: u64,
    previous: Option<&NodeHealth>,
    reference: Option<&NodeHealth>,
) -> Result<NodeHealth> {
    tokio::time::timeout(
        PROBE_DEADLINE,
        probe_inner(transport, network, now, previous, reference),
    )
    .await
    .map_err(|_| Denial::Timeout)?
}
async fn probe_inner<T: NodeTransport>(
    transport: &T,
    network: Network,
    now: u64,
    previous: Option<&NodeHealth>,
    reference: Option<&NodeHealth>,
) -> Result<NodeHealth> {
    let start = Instant::now();
    let info = rpc(transport, "get_info", json!({}), 1).await?;
    if info["nettype"] != network.as_str()
        || info["mainnet"] != (network == Network::Mainnet)
        || info["stagenet"] != (network == Network::Stagenet)
        || info["testnet"] != (network == Network::Testnet)
    {
        return Err(Denial::WrongNetwork);
    }
    let height = number(&info["height"])?;
    let target = number(&info["target_height"])?;
    if height == 0
        || height > 100_000_000
        || target > 100_000_000
        || (target > height && target - height > 5)
    {
        return Err(Denial::HeightInconsistent);
    }
    if info["synchronized"] != true || info["busy_syncing"] != false || info["offline"] != false {
        return Err(Denial::NodeNotReady);
    }
    let top = hash(&info["top_block_hash"])?;
    let genesis = rpc(
        transport,
        "get_block_header_by_height",
        json!({"height":0}),
        2,
    )
    .await?;
    let genesis = &genesis["block_header"];
    let genesis_hash = hash(&genesis["hash"])?;
    if number(&genesis["height"])? != 0
        || genesis["orphan_status"] != false
        || !genesis_hash.starts_with(genesis_prefix(network))
        || hash(&genesis["prev_hash"])? != "0".repeat(64)
    {
        return Err(Denial::WrongNetwork);
    }
    let tip = rpc(transport, "get_last_block_header", json!({}), 3).await?;
    let tip = &tip["block_header"];
    let tip_height = number(&tip["height"])?;
    let tip_count = tip_height
        .checked_add(1)
        .filter(|h| *h <= 100_000_000)
        .ok_or(Denial::HeightInconsistent)?;
    let timestamp = number(&tip["timestamp"])?;
    let tip_hash = hash(&tip["hash"])?;
    if tip["orphan_status"] != false
        || tip_count < height
        || tip_count > height.saturating_add(5)
        || (tip_count == height && tip_hash != top)
        || timestamp > now.saturating_add(7200)
    {
        return Err(Denial::HeightInconsistent);
    }
    if let Some(last) = previous {
        let elapsed = now.saturating_sub(last.checked_at);
        if now >= last.checked_at
            && (last.height.saturating_sub(height) > 10
                || height.saturating_sub(last.height) > elapsed / 60 + 120)
        {
            return Err(Denial::HeightInconsistent);
        }
    }
    let reference = reference
        .filter(|r| r.network == network && now >= r.checked_at && now - r.checked_at <= 60);
    if reference.is_some_and(|r| height.abs_diff(r.height) > 10) {
        return Err(Denial::HeightInconsistent);
    }
    Ok(NodeHealth {
        network,
        height: tip_count,
        target_height: target,
        latency_ms: start.elapsed().as_millis().min(u64::MAX as u128) as u64,
        // A completed validation, not the time before its Tor round trips.
        checked_at: now.saturating_add(start.elapsed().as_secs()),
        synchronized: true,
        compared_with_other_node: reference.is_some(),
        top_hash: tip_hash.into(),
    })
}

/// Constructed only after the complete permitted-node validation succeeds.
pub struct VerifiedConnection {
    client: RoutedClient,
    health: NodeHealth,
    checked: Instant,
}
impl VerifiedConnection {
    pub fn client(&self) -> &RoutedClient {
        &self.client
    }
    pub fn health(&self) -> &NodeHealth {
        &self.health
    }
    pub fn fresh(&self) -> bool {
        self.checked.elapsed() <= Duration::from_secs(crate::NODE_HEALTH_FRESH_SECS)
    }
    pub fn revoke(&self) {
        self.client.revoke();
    }
}
#[derive(Default)]
pub struct NodeManager {
    observations: HashMap<String, NodeHealth>,
}
impl NodeManager {
    pub async fn connect(
        &mut self,
        plan: RoutePlan,
        network: Network,
        cancel: CancellationToken,
        now: u64,
    ) -> Result<VerifiedConnection> {
        let client = RoutedClient::new(plan, cancel)?;
        client.check_socks().await?;
        self.validate(client, network, now).await
    }
    /// Validate a policy-created transport after the caller checked SOCKS.
    /// No ready-node capability is issued until all node checks pass.
    pub async fn validate(
        &mut self,
        client: RoutedClient,
        network: Network,
        now: u64,
    ) -> Result<VerifiedConnection> {
        let id = client.plan().node_id().to_string();
        let reference = self
            .observations
            .iter()
            .find(|(other, h)| **other != id && now >= h.checked_at && now - h.checked_at <= 60)
            .map(|(_, h)| h);
        let health = probe(&client, network, now, self.observations.get(&id), reference).await?;
        if self.observations.len() >= 16 && !self.observations.contains_key(&id) {
            self.observations.clear();
        }
        self.observations.insert(id, health.clone());
        Ok(VerifiedConnection {
            client,
            health,
            checked: Instant::now(),
        })
    }
    pub async fn refresh(&mut self, connection: &mut VerifiedConnection, now: u64) -> Result<()> {
        let id = connection.client.plan().node_id().to_string();
        let reference = self
            .observations
            .iter()
            .find(|(other, h)| **other != id && now >= h.checked_at && now - h.checked_at <= 60)
            .map(|(_, h)| h);
        match probe(
            &connection.client,
            connection.health.network,
            now,
            Some(&connection.health),
            reference,
        )
        .await
        {
            Ok(health) => {
                self.observations.insert(id, health.clone());
                connection.health = health;
                connection.checked = Instant::now();
                Ok(())
            }
            Err(e) => {
                connection.revoke();
                Err(e)
            }
        }
    }
    pub fn clear(&mut self) {
        self.observations.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        wrong_network: bool,
        bad_genesis: bool,
        tip_shift: u64,
        malformed: bool,
        disconnect: bool,
    }
    impl NodeTransport for Fake {
        async fn request(&self, _: DaemonPath, body: Vec<u8>, _: usize) -> Result<Vec<u8>> {
            if self.disconnect {
                return Err(Denial::TransportFailure);
            }
            if self.malformed {
                return Ok(b"not json".to_vec());
            }
            let request: Value = serde_json::from_slice(&body).unwrap();
            let result = match request["method"].as_str().unwrap() {
                "get_info" => {
                    json!({"status":"OK","nettype":if self.wrong_network{"mainnet"}else{"stagenet"},"mainnet":false,"stagenet":true,"testnet":false,"height":1000,"target_height":0,"synchronized":true,"busy_syncing":false,"offline":false,"top_block_hash":"a".repeat(64)})
                }
                "get_block_header_by_height" => {
                    json!({"status":"OK","block_header":{"height":0,"hash":if self.bad_genesis{"b".repeat(64)}else{format!("{}{}",genesis_prefix(Network::Stagenet),"0".repeat(32))},"prev_hash":"0".repeat(64),"orphan_status":false}})
                }
                _ => {
                    json!({"status":"OK","block_header":{"height":999+self.tip_shift,"timestamp":100,"hash":"a".repeat(64),"orphan_status":false}})
                }
            };
            Ok(
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
                    .unwrap(),
            )
        }
    }
    fn fake() -> Fake {
        Fake {
            wrong_network: false,
            bad_genesis: false,
            tip_shift: 0,
            malformed: false,
            disconnect: false,
        }
    }
    #[tokio::test]
    async fn freshness_starts_when_validation_finishes() {
        struct Delayed(Fake);
        impl NodeTransport for Delayed {
            async fn request(
                &self,
                path: DaemonPath,
                body: Vec<u8>,
                limit: usize,
            ) -> Result<Vec<u8>> {
                tokio::time::sleep(Duration::from_millis(550)).await;
                self.0.request(path, body, limit).await
            }
        }
        let health = probe(&Delayed(fake()), Network::Stagenet, 1000, None, None)
            .await
            .unwrap();
        assert!(health.latency_ms >= 1650);
        assert_eq!(health.checked_at, 1000 + health.latency_ms / 1000);
    }
    #[tokio::test]
    async fn node_identity_genesis_and_tip_must_agree() {
        let f = fake();
        assert!(probe(&f, Network::Stagenet, 1000, None, None).await.is_ok());
        let f = Fake {
            wrong_network: true,
            ..fake()
        };
        assert_eq!(
            probe(&f, Network::Stagenet, 1000, None, None)
                .await
                .unwrap_err(),
            Denial::WrongNetwork
        );
        let f = Fake {
            bad_genesis: true,
            ..fake()
        };
        assert_eq!(
            probe(&f, Network::Stagenet, 1000, None, None)
                .await
                .unwrap_err(),
            Denial::WrongNetwork
        );
        let f = Fake {
            tip_shift: 100,
            ..fake()
        };
        assert_eq!(
            probe(&f, Network::Stagenet, 1000, None, None)
                .await
                .unwrap_err(),
            Denial::HeightInconsistent
        );
    }
    #[tokio::test]
    async fn disconnect_malformed_and_inconsistent_responses_fail_closed() {
        for f in [
            Fake {
                malformed: true,
                ..fake()
            },
            Fake {
                disconnect: true,
                ..fake()
            },
        ] {
            assert!(probe(&f, Network::Stagenet, 1000, None, None)
                .await
                .is_err());
        }
        let mut reference = probe(&fake(), Network::Stagenet, 1000, None, None)
            .await
            .unwrap();
        reference.height += 500;
        assert_eq!(
            probe(&fake(), Network::Stagenet, 1001, None, Some(&reference))
                .await
                .unwrap_err(),
            Denial::HeightInconsistent
        );
        assert_eq!(
            probe(&fake(), Network::Stagenet, 1001, Some(&reference), None)
                .await
                .unwrap_err(),
            Denial::HeightInconsistent
        );
    }
}
