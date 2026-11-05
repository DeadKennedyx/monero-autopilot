use crate::{
    config::{ApprovedNode, Config, Ownership, Profile},
    endpoint::{Endpoint, EndpointKind, ProxyEndpoint},
    Denial, Result,
};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    TorOnion,
    TorHttps,
    I2p,
    LocalDirect,
    LocalTor,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposedTransport {
    Tor,
    I2p,
    Direct,
}
/// Only the policy engine can create a remote routing grant.
#[derive(Clone, Debug)]
pub struct RoutePlan {
    node_id: String,
    endpoint: Endpoint,
    proxy: ProxyEndpoint,
    route: RouteKind,
    policy_version: u32,
}
impl RoutePlan {
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    pub fn proxy(&self) -> ProxyEndpoint {
        self.proxy
    }
    pub fn route(&self) -> RouteKind {
        self.route
    }
    pub fn policy_version(&self) -> u32 {
        self.policy_version
    }
    /// Health/TLS evidence comes from the transport, not from a UI request.
    pub fn validate_transport_evidence(&self, tls_verified: bool) -> Result<()> {
        if self.endpoint.uses_tls() && !tls_verified {
            Err(Denial::InvalidTls)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalEgressEvidence {
    pub peer_traffic_over_tor: bool,
    pub wallet_broadcast_over_tor: bool,
    pub dns_direct_disabled: bool,
    pub transport_usable: bool,
}

pub struct PolicyEngine;
impl PolicyEngine {
    pub fn plan(config: &Config, node_id: &str, transport: ProposedTransport) -> Result<RoutePlan> {
        config.validate()?;
        // The caller supplies an ID, never a replacement unreviewed endpoint.
        let node = config
            .nodes
            .iter()
            .find(|n| n.id == node_id)
            .ok_or(Denial::UnapprovedNode)?;
        if !node.approved || !node.enabled {
            return Err(Denial::UnapprovedNode);
        }
        if config.profile != Profile::Balanced || transport == ProposedTransport::Direct {
            return Err(Denial::DirectForbidden);
        }
        let endpoint = node.validate()?;
        let (proxy, route) = match (endpoint.kind(), transport) {
            (EndpointKind::Onion, ProposedTransport::Tor) => (
                config.tor_proxy.ok_or(Denial::MissingProxy)?,
                RouteKind::TorOnion,
            ),
            (EndpointKind::Https, ProposedTransport::Tor) => (
                config.tor_proxy.ok_or(Denial::MissingProxy)?,
                RouteKind::TorHttps,
            ),
            (EndpointKind::I2p, ProposedTransport::I2p) => {
                (config.i2p_proxy.ok_or(Denial::I2pDisabled)?, RouteKind::I2p)
            }
            _ => return Err(Denial::DirectForbidden),
        };
        Ok(RoutePlan {
            node_id: node.id.clone(),
            endpoint,
            proxy,
            route,
            policy_version: config.policy_version,
        })
    }
    /// Preference is independent of a node's claimed height/latency/trustworthiness.
    pub fn candidates(config: &Config) -> Result<Vec<RoutePlan>> {
        config.validate()?;
        let mut nodes: Vec<&ApprovedNode> = config
            .nodes
            .iter()
            .filter(|n| n.approved && n.enabled)
            .collect();
        nodes.sort_by_key(|n| match Endpoint::parse(&n.endpoint).map(|e| e.kind()) {
            Ok(EndpointKind::Onion) if n.ownership == Ownership::Personal => 0,
            Ok(EndpointKind::Onion) => 1,
            Ok(EndpointKind::I2p) => 2,
            _ => 3,
        });
        Ok(nodes
            .into_iter()
            .filter_map(|n| {
                let transport = if Endpoint::parse(&n.endpoint).ok()?.kind() == EndpointKind::I2p {
                    ProposedTransport::I2p
                } else {
                    ProposedTransport::Tor
                };
                Self::plan(config, &n.id, transport).ok()
            })
            .collect())
    }
    pub fn managed_local(config: &Config, evidence: LocalEgressEvidence) -> Result<RouteKind> {
        config.validate()?;
        if config.profile == Profile::LocalNode && config.local_direct_consent {
            return Ok(RouteKind::LocalDirect);
        }
        if config.tor_proxy.is_some()
            && evidence.peer_traffic_over_tor
            && evidence.wallet_broadcast_over_tor
            && evidence.dns_direct_disabled
            && evidence.transport_usable
        {
            Ok(RouteKind::LocalTor)
        } else {
            Err(Denial::LocalEgressUnverified)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::onion;
    pub(crate) fn config() -> Config {
        Config {
            managed_tor: false,
            tor_proxy: Some(ProxyEndpoint::parse("127.0.0.1:9050").unwrap()),
            nodes: vec![ApprovedNode {
                id: "a".repeat(32),
                label: "Own node".into(),
                endpoint: format!("http://{}:38081", onion(1)),
                ownership: Ownership::Personal,
                approved: true,
                enabled: true,
            }],
            ..Default::default()
        }
    }
    #[test]
    fn approved_onion_accepted_direct_and_unapproved_denied() {
        let mut c = config();
        assert_eq!(
            PolicyEngine::plan(&c, &"a".repeat(32), ProposedTransport::Tor)
                .unwrap()
                .route(),
            RouteKind::TorOnion
        );
        assert_eq!(
            PolicyEngine::plan(&c, &"a".repeat(32), ProposedTransport::Direct).unwrap_err(),
            Denial::DirectForbidden
        );
        c.nodes[0].approved = false;
        assert_eq!(
            PolicyEngine::plan(&c, &"a".repeat(32), ProposedTransport::Tor).unwrap_err(),
            Denial::UnapprovedNode
        );
    }
    #[test]
    fn missing_proxy_and_invalid_tls_denied() {
        let mut c = config();
        c.tor_proxy = None;
        assert_eq!(
            PolicyEngine::plan(&c, &"a".repeat(32), ProposedTransport::Tor).unwrap_err(),
            Denial::MissingProxy
        );
        c.tor_proxy = config().tor_proxy;
        c.nodes[0].endpoint = "https://node.example.org:38081".into();
        let plan = PolicyEngine::plan(&c, &"a".repeat(32), ProposedTransport::Tor).unwrap();
        assert_eq!(
            plan.validate_transport_evidence(false),
            Err(Denial::InvalidTls)
        );
        assert!(plan.validate_transport_evidence(true).is_ok());
        assert_eq!(
            PolicyEngine::plan(&c, &"a".repeat(32), ProposedTransport::Direct).unwrap_err(),
            Denial::DirectForbidden
        );
    }
    #[test]
    fn disabled_i2p_and_unverified_local_daemon_are_denied() {
        let mut c = config();
        c.nodes[0].endpoint = format!("http://{}.b32.i2p:38081", "a".repeat(52));
        assert_eq!(
            PolicyEngine::plan(&c, &"a".repeat(32), ProposedTransport::I2p).unwrap_err(),
            Denial::I2pDisabled
        );
        c.i2p_proxy = Some(ProxyEndpoint::parse("127.0.0.1:4447").unwrap());
        assert_eq!(
            PolicyEngine::plan(&c, &"a".repeat(32), ProposedTransport::I2p)
                .unwrap()
                .route(),
            RouteKind::I2p
        );
        assert_eq!(
            PolicyEngine::managed_local(
                &c,
                LocalEgressEvidence {
                    peer_traffic_over_tor: false,
                    wallet_broadcast_over_tor: false,
                    dns_direct_disabled: true,
                    transport_usable: true
                }
            ),
            Err(Denial::LocalEgressUnverified)
        );
    }
    #[test]
    fn failover_candidates_are_approved_and_ordered() {
        let mut c = config();
        let mut https = c.nodes[0].clone();
        https.id = "b".repeat(32);
        https.endpoint = "https://node.example.org:38081".into();
        let mut unapproved = https.clone();
        unapproved.id = "c".repeat(32);
        unapproved.endpoint = "https://unapproved.example.org".into();
        unapproved.approved = false;
        c.nodes.insert(0, https);
        c.nodes.push(unapproved);
        let candidates = PolicyEngine::candidates(&c).unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].route(), RouteKind::TorOnion);
        assert!(candidates.iter().all(|p| p.node_id() != "c".repeat(32)));
    }
}
