//! Pure recovery transitions. The host performs effects and supplies monotonic time/jitter.
use crate::{
    config::Config,
    policy::{PolicyEngine, RoutePlan},
    Denial, Result,
};
use serde::Serialize;
use std::collections::HashSet;

pub const MAX_ATTEMPTS: u8 = 6;
pub const FRESH_MS: u64 = 15_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    InitializingTransport,
    Connecting,
    Validating,
    Connected,
    Degraded,
    Recovering,
    PrivacyBlocked,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecoveryStatus {
    pub state: ConnectionState,
    pub attempts: u8,
    pub retry_at_ms: Option<u64>,
    pub last_error: Option<Denial>,
    pub generation: u64,
    pub last_action: &'static str,
}
pub struct RecoveryController {
    config: Config,
    status: RecoveryStatus,
    active: Option<RoutePlan>,
    excluded: HashSet<String>,
    last_healthy: Option<u64>,
    stable_since: Option<u64>,
}
impl RecoveryController {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            status: RecoveryStatus {
                state: ConnectionState::Disconnected,
                attempts: 0,
                retry_at_ms: None,
                last_error: None,
                generation: 0,
                last_action: "Waiting to connect",
            },
            active: None,
            excluded: HashSet::new(),
            last_healthy: None,
            stable_since: None,
        })
    }
    pub fn status(&self) -> &RecoveryStatus {
        &self.status
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn active(&self) -> Option<&RoutePlan> {
        self.active.as_ref()
    }
    pub fn operations_allowed(&self, now: u64) -> bool {
        self.status.state == ConnectionState::Connected
            && self.last_healthy.is_some_and(|last| {
                now >= last && now - last <= crate::NODE_HEALTH_FRESH_SECS * 1000
            })
    }
    pub fn wallet_synced(
        &self,
        now: u64,
        wallet_sample: u64,
        wallet_height: u64,
        node_height: u64,
    ) -> bool {
        self.operations_allowed(now)
            && now >= wallet_sample
            && now - wallet_sample <= FRESH_MS
            && wallet_height > 0
            && node_height > 0
            && wallet_height.abs_diff(node_height) <= 2
    }
    pub fn start(&mut self, now: u64) {
        self.status.generation = self.status.generation.wrapping_add(1);
        self.status.attempts = 0;
        self.status.state = ConnectionState::Recovering;
        self.status.retry_at_ms = Some(now);
        self.status.last_error = None;
        self.status.last_action = "Checking a private connection";
        self.active = None;
        self.excluded.clear();
        self.last_healthy = None;
        self.stable_since = None;
    }
    pub fn disconnect(&mut self) {
        self.status.generation = self.status.generation.wrapping_add(1);
        self.status.state = ConnectionState::Disconnected;
        self.status.retry_at_ms = None;
        self.active = None;
        self.last_healthy = None;
        self.stable_since = None;
        self.status.last_action = "Wallet connection paused";
    }
    pub fn replace_config(&mut self, next: Config, consent: bool) -> Result<()> {
        self.config.validate_change(&next, consent)?;
        self.disconnect();
        self.config = next;
        Ok(())
    }
    /// Claims at most one attempt. Repeated polls cannot dispatch duplicates.
    pub fn begin_due(&mut self, now: u64) -> Result<Option<RoutePlan>> {
        self.begin_due_with_managed_proxy(now, None)
    }
    /// A host supplies its verified owned process endpoint only for this session.
    /// Stored intent and approved destinations remain unchanged.
    pub fn begin_due_with_managed_proxy(
        &mut self,
        now: u64,
        proxy: Option<crate::endpoint::ProxyEndpoint>,
    ) -> Result<Option<RoutePlan>> {
        if self.status.state != ConnectionState::Recovering
            || self.status.retry_at_ms.is_none_or(|at| now < at)
        {
            return Ok(None);
        }
        let mut effective = self.config.clone();
        if effective.managed_tor {
            effective.managed_tor = false;
            effective.tor_proxy = proxy;
        }
        let candidates: Vec<_> = PolicyEngine::candidates(&effective)?
            .into_iter()
            .filter(|c| !self.excluded.contains(c.node_id()))
            .collect();
        if candidates.is_empty() {
            self.block(Denial::NoPermittedNodes);
            return Err(Denial::NoPermittedNodes);
        }
        if self.status.attempts >= MAX_ATTEMPTS {
            self.block(Denial::RecoveryExhausted);
            return Err(Denial::RecoveryExhausted);
        }
        let plan = candidates[self.status.attempts as usize % candidates.len()].clone();
        self.status.attempts += 1;
        self.status.retry_at_ms = None;
        self.status.state = ConnectionState::InitializingTransport;
        self.status.last_action = "Initializing the selected anonymous transport";
        self.active = Some(plan.clone());
        Ok(Some(plan))
    }
    pub fn transport_ready(&mut self, generation: u64) -> Result<()> {
        self.expect(generation, ConnectionState::InitializingTransport)?;
        self.status.state = ConnectionState::Connecting;
        self.status.last_action = "Connecting only to an approved node";
        Ok(())
    }
    pub fn validating(&mut self, generation: u64) -> Result<()> {
        self.expect(generation, ConnectionState::Connecting)?;
        self.status.state = ConnectionState::Validating;
        self.status.last_action = "Validating node network and synchronization";
        Ok(())
    }
    pub fn connected(&mut self, generation: u64, now: u64) -> Result<()> {
        self.expect(generation, ConnectionState::Validating)?;
        self.status.state = ConnectionState::Connected;
        self.status.last_error = None;
        self.status.last_action = "Approved connection validated";
        self.last_healthy = Some(now);
        self.stable_since = Some(now);
        Ok(())
    }
    pub fn healthy(&mut self, now: u64) {
        if self.status.state == ConnectionState::Connected {
            self.last_healthy = Some(now);
            if self
                .stable_since
                .is_some_and(|since| now.saturating_sub(since) >= 60_000)
            {
                self.status.attempts = 0;
            }
        }
    }
    /// Immediately suppress operations; scheduling recovery is a separate transition.
    pub fn degrade(&mut self, reason: Denial) {
        self.status.state = ConnectionState::Degraded;
        self.status.last_error = Some(reason);
        self.status.last_action = "Connection lost; privacy settings are unchanged";
        self.last_healthy = None;
        self.stable_since = None;
        self.status.generation = self.status.generation.wrapping_add(1);
    }
    pub fn failed(&mut self, reason: Denial, now: u64, jitter: u64) {
        if self.status.state == ConnectionState::Disconnected
            || self.status.state == ConnectionState::PrivacyBlocked
        {
            return;
        }
        if matches!(
            reason,
            Denial::WrongNetwork
                | Denial::HeightInconsistent
                | Denial::InvalidTls
                | Denial::InvalidResponse
        ) {
            if let Some(active) = &self.active {
                self.excluded.insert(active.node_id().to_string());
            }
        }
        self.status.generation = self.status.generation.wrapping_add(1);
        self.last_healthy = None;
        self.stable_since = None;
        self.status.last_error = Some(reason);
        self.active = None;
        if self.status.attempts >= MAX_ATTEMPTS {
            self.block(Denial::RecoveryExhausted);
            return;
        }
        self.status.state = ConnectionState::Recovering;
        self.status.retry_at_ms =
            Some(now.saturating_add(backoff_ms(self.status.attempts, jitter)));
        self.status.last_action = "Retrying only permitted routes";
    }
    pub fn block(&mut self, reason: Denial) {
        self.status.generation = self.status.generation.wrapping_add(1);
        self.status.state = ConnectionState::PrivacyBlocked;
        self.status.last_error = Some(reason);
        self.status.retry_at_ms = None;
        self.active = None;
        self.last_healthy = None;
        self.stable_since = None;
        self.status.last_action = "No compliant connection; wallet remains offline";
    }
    fn expect(&self, generation: u64, state: ConnectionState) -> Result<()> {
        if self.status.generation != generation || self.status.state != state {
            Err(Denial::PolicyChanged)
        } else {
            Ok(())
        }
    }
}
pub fn backoff_ms(attempt: u8, jitter: u64) -> u64 {
    let base = (1000u64 << attempt.min(5)).min(30_000);
    let spread = base / 4;
    base - spread + jitter % (spread * 2 + 1)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{ApprovedNode, Ownership, Profile},
        endpoint::{onion, ProxyEndpoint},
        policy::RouteKind,
    };
    fn config() -> Config {
        Config {
            managed_tor: false,
            tor_proxy: Some(ProxyEndpoint::parse("127.0.0.1:9050").unwrap()),
            nodes: vec![ApprovedNode {
                id: "a".repeat(32),
                label: "Approved".into(),
                endpoint: format!("http://{}", onion(2)),
                ownership: Ownership::Personal,
                approved: true,
                enabled: true,
            }],
            ..Default::default()
        }
    }
    #[test]
    fn tor_failure_recovers_without_downgrade_and_exhaustion_blocks() {
        let mut r = RecoveryController::new(config()).unwrap();
        r.start(0);
        let mut now = 0;
        for _ in 0..MAX_ATTEMPTS {
            let plan = r.begin_due(now).unwrap().unwrap();
            assert_eq!(plan.route(), RouteKind::TorOnion);
            assert!(r.begin_due(now).unwrap().is_none());
            r.failed(Denial::ProxyUnavailable, now, 17);
            assert_eq!(r.config().profile, Profile::Balanced);
            now = r.status.retry_at_ms.unwrap_or(now);
        }
        assert_eq!(r.status.state, ConnectionState::PrivacyBlocked);
        assert!(!r.operations_allowed(now));
        assert!(r.begin_due(u64::MAX).unwrap().is_none());
    }
    #[test]
    fn managed_proxy_is_ephemeral_and_never_reuses_an_external_port() {
        let mut intent = config();
        intent.managed_tor = true;
        intent.tor_proxy = None;
        let mut r = RecoveryController::new(intent.clone()).unwrap();
        r.start(0);
        assert_eq!(r.begin_due(0).unwrap_err(), Denial::NoPermittedNodes);
        r.start(1);
        let owned = ProxyEndpoint::parse("127.0.0.1:32123").unwrap();
        let plan = r
            .begin_due_with_managed_proxy(1, Some(owned))
            .unwrap()
            .unwrap();
        assert_eq!(plan.proxy(), owned);
        assert_eq!(r.config(), &intent);
        assert!(r.config().tor_proxy.is_none());
        r.failed(Denial::ProxyUnavailable, 2, 17);
        let due = r.status.retry_at_ms.unwrap();
        assert_eq!(
            r.begin_due_with_managed_proxy(due, None).unwrap_err(),
            Denial::NoPermittedNodes
        );
        assert!(!r.operations_allowed(due));
        assert_eq!(r.config(), &intent);
    }
    #[test]
    fn stale_wallet_never_appears_synced_and_late_completion_cannot_revive() {
        let mut r = RecoveryController::new(config()).unwrap();
        r.start(0);
        r.begin_due(0).unwrap();
        let g = r.status.generation;
        r.transport_ready(g).unwrap();
        r.validating(g).unwrap();
        r.connected(g, 100).unwrap();
        assert!(r.wallet_synced(200, 100, 400, 400));
        assert!(!r.wallet_synced(20_000, 100, 400, 400));
        r.degrade(Denial::BackendExited);
        assert_eq!(r.status.state, ConnectionState::Degraded);
        assert!(!r.operations_allowed(200));
        r.disconnect();
        assert_eq!(r.connected(g, 300), Err(Denial::PolicyChanged));
    }
    #[test]
    fn restart_while_recovering_keeps_policy_and_approved_set() {
        let mut r = RecoveryController::new(config()).unwrap();
        r.start(0);
        r.begin_due(0).unwrap();
        r.failed(Denial::TransportFailure, 1, 30);
        let mut restarted = RecoveryController::new(r.config().clone()).unwrap();
        assert_eq!(restarted.status.state, ConnectionState::Disconnected);
        restarted.start(10);
        assert_eq!(
            restarted.begin_due(10).unwrap().unwrap().route(),
            RouteKind::TorOnion
        );
    }
    #[test]
    fn jitter_is_bounded_and_missing_routes_block() {
        for attempt in 0..=20 {
            let low = backoff_ms(attempt, 0);
            let high = backoff_ms(attempt, u64::MAX);
            assert!(low >= 750 && high <= 37500);
        }
        let mut r = RecoveryController::new(Config::default()).unwrap();
        r.start(0);
        assert_eq!(r.begin_due(0).unwrap_err(), Denial::NoPermittedNodes);
        assert_eq!(r.status.state, ConnectionState::PrivacyBlocked);
    }
}
