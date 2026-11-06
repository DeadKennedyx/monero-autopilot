//! RPC responsiveness is independent of process existence and node health.
//! The host supplies monotonic time and only schema-validated wallet observations.

pub const UNRESPONSIVE_MS: u64 = 180_000;
pub const INITIAL_SCAN_NOTICE_MS: u64 = 900_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingResponse {
    Waiting,
    InitialScanNotice,
    Unresponsive,
}

#[derive(Default)]
pub struct WalletLiveness {
    session: Option<(u32, u64)>,
    last_response: Option<u64>,
    synchronized: bool,
}

impl WalletLiveness {
    /// New processes/routes get a fresh response baseline for the same wallet.
    /// The host replaces this policy when wallet identity changes; automatic
    /// restarts must not turn a proven mature wallet back into an unlimited scan.
    pub fn bind(&mut self, pid: u32, generation: u64, now: u64) {
        let session = Some((pid, generation));
        if self.session != session {
            self.session = session;
            self.last_response = Some(now);
        }
    }

    pub fn responded(&mut self, now: u64) {
        self.last_response = Some(now);
    }

    /// Arm automatic recovery only after a fully checked, synchronized balance.
    pub fn synchronized(&mut self, now: u64) {
        self.responded(now);
        self.synchronized = true;
    }

    pub fn missing_response(&self, now: u64) -> MissingResponse {
        let elapsed = self
            .last_response
            .map(|at| now.saturating_sub(at))
            .unwrap_or(0);
        if self.synchronized && elapsed >= UNRESPONSIVE_MS {
            MissingResponse::Unresponsive
        } else if !self.synchronized && elapsed >= INITIAL_SCAN_NOTICE_MS {
            // A first scan can legitimately occupy Monero's RPC thread for a
            // long time. Keep polling; a notice must not terminate that scan.
            MissingResponse::InitialScanNotice
        } else {
            MissingResponse::Waiting
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_recovery::{LocalRecovery, Phase, STABLE_MS};

    #[test]
    fn mature_wallet_gets_three_minutes_and_two_failed_observations() {
        let mut watch = WalletLiveness::default();
        watch.bind(10, 3, 0);
        watch.synchronized(0);
        let mut recovery = LocalRecovery::default();
        recovery.start(0);
        assert!(recovery.begin_due(0));
        recovery.complete(true, 0);
        for now in [1_000, STABLE_MS, UNRESPONSIVE_MS - 1] {
            assert_eq!(watch.missing_response(now), MissingResponse::Waiting);
            recovery.defer_observation();
            assert_eq!(
                recovery.attempts, 1,
                "A busy process earns no restart budget"
            );
        }
        assert_eq!(
            watch.missing_response(UNRESPONSIVE_MS),
            MissingResponse::Unresponsive
        );
        assert!(!recovery.observe(false, UNRESPONSIVE_MS));
        assert!(recovery.observe(false, UNRESPONSIVE_MS + 1_000));
        assert_eq!(recovery.phase, Phase::Waiting);
    }

    #[test]
    fn first_scan_notice_keeps_polling_without_arming_restart() {
        let mut watch = WalletLiveness::default();
        watch.bind(10, 3, 0);
        assert_eq!(
            watch.missing_response(INITIAL_SCAN_NOTICE_MS - 1),
            MissingResponse::Waiting
        );
        for now in [INITIAL_SCAN_NOTICE_MS, 3_600_000, u64::MAX] {
            assert_eq!(
                watch.missing_response(now),
                MissingResponse::InitialScanNotice
            );
        }
        watch.responded(3_600_000);
        assert_eq!(watch.missing_response(3_600_001), MissingResponse::Waiting);
        assert_eq!(
            watch.missing_response(3_600_000 + UNRESPONSIVE_MS),
            MissingResponse::Waiting
        );
    }

    #[test]
    fn valid_responses_reset_time_and_restarts_cannot_disarm_a_mature_wallet() {
        let mut watch = WalletLiveness::default();
        watch.bind(10, 3, 0);
        watch.synchronized(0);
        watch.bind(10, 3, 170_000); // Merely seeing the same live process is not progress.
        assert_eq!(
            watch.missing_response(180_000),
            MissingResponse::Unresponsive
        );
        watch.responded(180_001);
        assert_eq!(watch.missing_response(360_000), MissingResponse::Waiting);
        assert_eq!(
            watch.missing_response(360_001),
            MissingResponse::Unresponsive
        );
        watch.bind(11, 3, 360_002);
        assert_eq!(watch.missing_response(540_001), MissingResponse::Waiting);
        assert_eq!(
            watch.missing_response(540_002),
            MissingResponse::Unresponsive
        );
        watch.synchronized(540_003);
        watch.bind(11, 4, 540_004);
        assert_eq!(watch.missing_response(720_003), MissingResponse::Waiting);
        assert_eq!(
            watch.missing_response(720_004),
            MissingResponse::Unresponsive
        );
        watch = WalletLiveness::default(); // The actor selected a different wallet.
        watch.bind(12, 4, 720_005);
        assert_eq!(watch.missing_response(900_005), MissingResponse::Waiting);
    }
}
