//! Pure policy for one owned local node and wallet. The host performs every
//! effect asynchronously, then reports its actual outcome. No simulated attach.
use crate::MAX_ATTEMPTS;

pub const STABLE_MS: u64 = 30_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Stopped,
    Monitoring,
    Suspect,
    Waiting,
    Recovering,
    Attention,
}
pub struct LocalRecovery {
    pub phase: Phase,
    pub attempts: u8,
    pub recoveries: u32,
    pub retry_at: Option<u64>,
    failures: u8,
    stable_since: Option<u64>,
    connected_before: bool,
}
impl Default for LocalRecovery {
    fn default() -> Self {
        Self {
            phase: Phase::Stopped,
            attempts: 0,
            recoveries: 0,
            retry_at: None,
            failures: 0,
            stable_since: None,
            connected_before: false,
        }
    }
}
impl LocalRecovery {
    pub fn start(&mut self, now: u64) {
        self.attempts = 0;
        self.failures = 0;
        self.stable_since = None;
        self.phase = Phase::Waiting;
        self.retry_at = Some(now);
    }
    pub fn stop(&mut self) {
        self.phase = Phase::Stopped;
        self.connected_before = false;
        self.retry_at = None;
        self.failures = 0;
        self.stable_since = None;
    }
    pub fn fail_closed(&mut self) {
        self.phase = Phase::Attention;
        self.retry_at = None;
        self.stable_since = None;
    }
    fn schedule(&mut self, now: u64) {
        self.stable_since = None;
        if self.attempts >= MAX_ATTEMPTS {
            self.fail_closed();
        } else {
            self.phase = Phase::Waiting;
            self.retry_at = Some(now.saturating_add(2_000_u64 << self.attempts));
        }
    }
    /// Two consecutive failed observations confirm a fault. Healthy idle wallets
    /// stay healthy: lack of newly mined blocks is not a reason to restart.
    /// Returns true exactly when the host must quiesce the existing backend.
    pub fn observe(&mut self, healthy: bool, now: u64) -> bool {
        if !matches!(self.phase, Phase::Monitoring | Phase::Suspect) {
            return false;
        }
        if healthy {
            self.failures = 0;
            self.phase = Phase::Monitoring;
            let since = *self.stable_since.get_or_insert(now);
            if now.saturating_sub(since) >= STABLE_MS {
                self.attempts = 0;
            }
            return false;
        }
        self.stable_since = None;
        self.failures = self.failures.saturating_add(1);
        self.phase = Phase::Suspect;
        if self.failures < 2 {
            return false;
        }
        self.failures = 0;
        self.schedule(now);
        true
    }
    /// Claims one attempt; repeated polls cannot dispatch duplicate work.
    pub fn begin_due(&mut self, now: u64) -> bool {
        if self.phase != Phase::Waiting || self.retry_at.is_none_or(|at| now < at) {
            return false;
        }
        self.phase = Phase::Recovering;
        self.retry_at = None;
        self.attempts += 1;
        true
    }
    pub fn complete(&mut self, success: bool, now: u64) {
        // A late completion after Stop must not revive the user's session.
        if self.phase != Phase::Recovering {
            return;
        }
        if success {
            if self.connected_before {
                self.recoveries = self.recoveries.saturating_add(1);
            }
            self.connected_before = true;
            self.phase = Phase::Monitoring;
            self.failures = 0;
            self.stable_since = Some(now);
        } else {
            self.schedule(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn connected() -> LocalRecovery {
        let mut p = LocalRecovery::default();
        p.start(0);
        assert!(p.begin_due(0));
        p.complete(true, 1);
        p
    }
    #[test]
    fn one_timeout_recovers_without_restart() {
        let mut p = connected();
        assert!(!p.observe(false, 10));
        assert_eq!(p.phase, Phase::Suspect);
        assert!(!p.observe(true, 20));
        assert_eq!(p.phase, Phase::Monitoring);
        assert!(!p.begin_due(100_000));
    }
    #[test]
    fn idle_healthy_chain_never_triggers_recovery() {
        let mut p = connected();
        for t in (2..180_000).step_by(1_000) {
            assert!(!p.observe(true, t));
        }
        assert_eq!(p.phase, Phase::Monitoring);
        assert_eq!(p.attempts, 0);
    }
    #[test]
    fn failures_have_backoff_and_exactly_three_attempts() {
        let mut p = LocalRecovery::default();
        p.start(0);
        assert!(p.begin_due(0));
        assert!(!p.begin_due(0));
        p.complete(false, 0);
        assert!(!p.begin_due(3999));
        assert!(p.begin_due(4000));
        p.complete(false, 4000);
        assert!(!p.begin_due(11999));
        assert!(p.begin_due(12000));
        p.complete(false, 12000);
        assert_eq!(p.phase, Phase::Attention);
        assert_eq!(p.attempts, 3);
        assert!(!p.begin_due(u64::MAX));
    }
    #[test]
    fn stop_invalidates_pending_and_late_completions() {
        let mut p = connected();
        p.observe(false, 2);
        assert!(p.observe(false, 3));
        p.stop();
        assert!(!p.begin_due(u64::MAX));
        p.complete(true, 10);
        assert_eq!(p.phase, Phase::Stopped);
        p.start(20);
        assert!(p.begin_due(20));
        p.stop();
        p.complete(true, 21);
        assert_eq!(p.phase, Phase::Stopped);
    }
    #[test]
    fn repeated_crash_loops_do_not_reset_retry_budget() {
        let mut p = connected();
        let mut t = 10;
        for expected in [2, 3] {
            p.observe(false, t);
            assert!(p.observe(false, t + 1));
            t = p.retry_at.unwrap();
            assert!(p.begin_due(t));
            assert_eq!(p.attempts, expected);
            p.complete(true, t);
            t += 1;
        }
        p.observe(false, t);
        assert!(p.observe(false, t + 1));
        assert_eq!(p.phase, Phase::Attention);
    }
    #[test]
    fn stable_session_earns_fresh_budget_and_explicit_retry_is_required() {
        let mut p = connected();
        p.observe(true, STABLE_MS + 1);
        assert_eq!(p.attempts, 0);
        p.observe(false, 31_000);
        assert!(p.observe(false, 32_000));
        assert_eq!(p.retry_at, Some(34_000));
        p.fail_closed();
        assert!(!p.begin_due(100_000));
        p.start(100_000);
        assert!(p.begin_due(100_000));
        assert_eq!(p.attempts, 1);
    }
}
