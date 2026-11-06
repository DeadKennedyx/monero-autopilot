//! Decision engine only. No sockets, keys, transaction operations, or persistence.
//! All time is supplied as monotonic logical ticks by the host.

pub mod local_recovery;
pub mod wallet_liveness;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privacy {
    Easy,
    Private,
    TorOnly,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Local,
    Direct,
    Tor,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Stagenet,
    Mainnet,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub id: usize,
    pub route: Route,
    pub approved: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Timeout,
    Disconnected,
    HeightMismatch,
    WrongNetwork,
    BackendExited,
    AttachFailed,
    Stalled,
}
#[derive(Clone, Copy, Debug)]
pub struct Health {
    pub latency_ms: u32,
    pub height: u64,
    pub network: Network,
}

/// Implementations must return a cached, bounded observation; never block the engine.
/// A production host must enforce transport deadlines outside this decision loop.
pub trait NodeAdapter {
    fn probe(&mut self, node: Node) -> Result<Health, Fault>;
}
#[derive(Clone, Copy, Debug)]
pub struct WalletStatus {
    pub alive: bool,
    pub height: u64,
}
/// Deliberately excludes spend, sign, seed, rescan, and restore-height operations.
pub trait WalletAdapter {
    fn status(&self) -> WalletStatus;
    /// Quiesce scanning and daemon I/O, retaining only the connection identity.
    /// A real adapter must cancel outstanding work before reporting this as complete.
    fn pause(&mut self);
    fn attach(&mut self, node: Node) -> Result<(), Fault>;
    fn resume(&mut self);
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Connected,
    Suspect,
    Evaluating,
    Connecting,
    Backoff,
    Exhausted,
    BackendStopped,
}
#[derive(Clone, Debug)]
pub struct Event {
    pub tick: u64,
    pub code: &'static str,
    pub node: Option<usize>,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Reliability {
    pub successes: u32,
    pub failures: u32,
}

pub struct Engine {
    pub mode: Privacy,
    pub state: State,
    pub active: Option<usize>,
    pub candidate: Option<usize>,
    pub tick: u64,
    pub attempts: u8,
    pub next_retry: u64,
    pub events: Vec<Event>,
    pub stats: Vec<Reliability>,
    pub last_fault: Option<Fault>,
    pub recoveries: u32,
    nodes: Vec<Node>,
    reference_height: u64,
    failures: u8,
    stalled: u8,
    last_height: u64,
    recovery_pending: bool,
    no_progress_recoveries: u8,
}

pub const MAX_ATTEMPTS: u8 = 3;
pub const STALL_TICKS: u8 = 4;

impl Privacy {
    pub fn permits(self, node: Node) -> bool {
        node.approved
            && match self {
                Self::Easy => node.route != Route::Tor,
                Self::Private => node.route == Route::Local,
                Self::TorOnly => node.route == Route::Tor,
            }
    }
}

impl Engine {
    pub fn new(mode: Privacy, nodes: Vec<Node>, reference_height: u64, wallet_height: u64) -> Self {
        // IDs are indexes at this prototype boundary. Reject malformed catalogs early.
        assert!(nodes.iter().enumerate().all(|(i, n)| i == n.id));
        let stats = vec![Reliability::default(); nodes.len()];
        let mut engine = Self {
            mode,
            state: State::Evaluating,
            active: None,
            candidate: None,
            tick: 0,
            attempts: 0,
            next_retry: 0,
            events: vec![],
            stats,
            last_fault: None,
            recoveries: 0,
            nodes,
            reference_height,
            failures: 0,
            stalled: 0,
            last_height: wallet_height,
            recovery_pending: false,
            no_progress_recoveries: 0,
        };
        engine.log("session_started", None);
        engine
    }
    fn log(&mut self, code: &'static str, node: Option<usize>) {
        if self.events.len() == 80 {
            self.events.remove(0);
        }
        self.events.push(Event {
            tick: self.tick,
            code,
            node,
        });
    }
    fn check<N: NodeAdapter>(&mut self, index: usize, adapter: &mut N) -> Result<Health, Fault> {
        let health = adapter.probe(self.nodes[index]).and_then(|h| {
            if h.network != Network::Stagenet {
                Err(Fault::WrongNetwork)
            } else if h.height.abs_diff(self.reference_height) > 3 {
                Err(Fault::HeightMismatch)
            } else {
                Ok(h)
            }
        });
        let stats = &mut self.stats[index];
        match health {
            Ok(_) => stats.successes = stats.successes.saturating_add(1),
            Err(_) => stats.failures = stats.failures.saturating_add(1),
        }
        health
    }
    fn begin_recovery<W: WalletAdapter>(&mut self, wallet: &mut W, fault: Fault) {
        self.last_fault = Some(fault);
        if fault == Fault::Stalled && self.no_progress_recoveries >= MAX_ATTEMPTS {
            wallet.pause();
            self.active = None;
            self.candidate = None;
            self.state = State::Exhausted;
            self.attempts = MAX_ATTEMPTS;
            self.log("stall_recovery_exhausted", None);
            return;
        }
        if fault == Fault::Stalled {
            self.no_progress_recoveries += 1;
        }
        self.recovery_pending = true;
        self.log("recovery_started", self.active);
        self.active = None;
        self.candidate = None;
        self.attempts = 0;
        self.state = State::Evaluating;
        wallet.pause();
    }
    fn backoff(&mut self) {
        self.candidate = None;
        if self.attempts >= MAX_ATTEMPTS {
            self.state = State::Exhausted;
            self.log("retry_exhausted", None);
        } else {
            self.state = State::Backoff;
            self.next_retry = self.tick + (1_u64 << self.attempts);
            self.log("retry_scheduled", None);
        }
    }
    /// Explicit user retry. It cannot relax privacy or restart a wallet process.
    pub fn retry(&mut self) {
        if self.state == State::Exhausted {
            self.attempts = 0;
            self.no_progress_recoveries = 0;
            self.state = State::Evaluating;
            self.log("manual_retry", None);
        }
    }
    /// The nonblocking host collects one fresh observation for each planned node,
    /// then supplies those observations to `step`. No network access occurs here.
    pub fn planned_probes(&self) -> Vec<Node> {
        let ids: Vec<usize> = match self.state {
            State::Connected | State::Suspect => self.active.into_iter().collect(),
            State::Connecting => self.candidate.into_iter().collect(),
            State::Evaluating | State::BackendStopped => (0..self.nodes.len()).collect(),
            State::Backoff | State::Exhausted => vec![],
        };
        ids.into_iter()
            .map(|id| self.nodes[id])
            .filter(|node| self.mode.permits(*node))
            .collect()
    }
    /// Immediately quiesce daemon I/O before adopting a policy; revalidate candidates.
    pub fn set_policy<W: WalletAdapter>(&mut self, mode: Privacy, wallet: &mut W) {
        wallet.pause();
        self.mode = mode;
        self.active = None;
        self.candidate = None;
        self.attempts = 0;
        self.failures = 0;
        self.stalled = 0;
        self.last_fault = None;
        self.recovery_pending = false;
        self.no_progress_recoveries = 0;
        self.state = State::Evaluating;
        self.log("policy_changed", None);
    }
    pub fn step<N: NodeAdapter, W: WalletAdapter>(&mut self, adapter: &mut N, wallet: &mut W) {
        self.tick = self.tick.saturating_add(1);
        let status = wallet.status();
        if !status.alive {
            if self.state != State::BackendStopped {
                wallet.pause();
                self.active = None;
                self.candidate = None;
                self.state = State::BackendStopped;
                self.recovery_pending = true;
                self.last_fault = Some(Fault::BackendExited);
                self.log("backend_exited", None);
            }
            return;
        }
        if self.state == State::BackendStopped {
            self.state = State::Evaluating;
            self.attempts = 0;
            self.log("backend_available", None);
        }
        match self.state {
            State::Connected | State::Suspect => {
                let Some(id) = self.active else {
                    self.state = State::Evaluating;
                    return;
                };
                if !self.mode.permits(self.nodes[id]) {
                    self.begin_recovery(wallet, Fault::Disconnected);
                    return;
                }
                match self.check(id, adapter) {
                    Err(fault) => {
                        wallet.pause();
                        self.last_fault = Some(fault);
                        self.failures += 1;
                        self.state = State::Suspect;
                        self.log(fault_code(fault), Some(id));
                        if self.failures >= 2 {
                            self.begin_recovery(wallet, fault);
                        }
                    }
                    Ok(_) => {
                        if self.state == State::Suspect {
                            self.log("transient_recovered", Some(id));
                            wallet.resume();
                        }
                        self.state = State::Connected;
                        self.failures = 0;
                        self.last_fault = None;
                        if status.height < self.reference_height
                            && status.height <= self.last_height
                        {
                            self.stalled = self.stalled.saturating_add(1);
                        } else {
                            self.stalled = 0;
                        }
                        if status.height > self.last_height {
                            self.no_progress_recoveries = 0;
                        }
                        self.last_height = status.height;
                        if self.stalled >= STALL_TICKS {
                            self.begin_recovery(wallet, Fault::Stalled);
                        }
                    }
                }
            }
            State::Evaluating => {
                self.attempts += 1;
                self.log("evaluating_permitted_nodes", None);
                let mut choices = Vec::new();
                for id in 0..self.nodes.len() {
                    if !self.mode.permits(self.nodes[id]) {
                        self.log("policy_blocked", Some(id));
                        continue;
                    }
                    match self.check(id, adapter) {
                        Ok(h) => {
                            let s = self.stats[id];
                            // Laplace-smoothed observed failure rate, then latency.
                            let risk = (u64::from(s.failures) + 1) * 1000
                                / (u64::from(s.failures) + u64::from(s.successes) + 2);
                            choices.push((risk, h.latency_ms, id));
                            self.log("candidate_healthy", Some(id));
                        }
                        Err(f) => {
                            self.last_fault = Some(f);
                            self.log(fault_code(f), Some(id));
                        }
                    }
                }
                choices.sort_unstable();
                if let Some(&(_, _, id)) = choices.first() {
                    self.candidate = Some(id);
                    self.state = State::Connecting;
                    self.log("candidate_selected", Some(id));
                } else {
                    self.backoff();
                }
            }
            State::Connecting => {
                let Some(id) = self.candidate else {
                    self.backoff();
                    return;
                };
                // Recheck policy and health at commit time, not only selection time.
                if !self.mode.permits(self.nodes[id]) {
                    self.backoff();
                    return;
                }
                if let Err(f) = self.check(id, adapter) {
                    self.last_fault = Some(f);
                    self.log(fault_code(f), Some(id));
                    self.backoff();
                    return;
                }
                match wallet.attach(self.nodes[id]) {
                    Ok(()) => {
                        self.active = Some(id);
                        self.candidate = None;
                        self.state = State::Connected;
                        self.failures = 0;
                        self.stalled = 0;
                        self.last_height = wallet.status().height;
                        if self.recovery_pending {
                            self.recoveries += 1;
                        }
                        self.recovery_pending = false;
                        self.last_fault = None;
                        wallet.resume();
                        self.log("connected", Some(id));
                    }
                    Err(f) => {
                        self.last_fault = Some(f);
                        self.log(fault_code(f), Some(id));
                        self.backoff();
                    }
                }
            }
            State::Backoff => {
                if self.tick >= self.next_retry {
                    self.state = State::Evaluating;
                }
            }
            State::Exhausted | State::BackendStopped => {}
        }
    }
}
pub fn fault_code(f: Fault) -> &'static str {
    match f {
        Fault::Timeout => "node_timeout",
        Fault::Disconnected => "node_disconnected",
        Fault::HeightMismatch => "height_rejected",
        Fault::WrongNetwork => "network_rejected",
        Fault::BackendExited => "backend_exited",
        Fault::AttachFailed => "attach_failed",
        Fault::Stalled => "sync_stalled",
    }
}
