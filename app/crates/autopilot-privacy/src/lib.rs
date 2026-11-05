//! Wallet-independent privacy decisions and anonymous node transport.
//!
//! This crate does not handle keys, scanning, signing, transaction construction,
//! or wallet passwords. Policy approval is not proof of node honesty/anonymity.
/// Maximum age of a completed node validation; wallet balances use a shorter window.
pub const NODE_HEALTH_FRESH_SECS: u64 = 60;
pub mod config;
pub mod endpoint;
#[cfg(feature = "transport")]
pub mod gateway;
#[cfg(feature = "transport")]
pub mod node;
pub mod policy;
pub mod recovery;
#[cfg(feature = "transport")]
pub mod runtime;
#[cfg(feature = "transport")]
pub mod transport;

use serde::{Deserialize, Serialize};

/// Stable, redacted diagnostic codes. Never include raw network/credential data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Denial {
    UnknownVersion,
    InvalidConfiguration,
    CorruptConfiguration,
    StorageUnavailable,
    ConsentRequired,
    InvalidEndpoint,
    InvalidOnion,
    InvalidI2p,
    UnapprovedNode,
    DirectForbidden,
    MissingProxy,
    I2pDisabled,
    TlsRequired,
    InvalidTls,
    ProxyUnavailable,
    TransportFailure,
    Timeout,
    Cancelled,
    Redirect,
    HttpStatus,
    TooLarge,
    InvalidResponse,
    WrongNetwork,
    HeightInconsistent,
    NodeNotReady,
    Stale,
    PolicyChanged,
    LocalEgressUnverified,
    NoPermittedNodes,
    RecoveryExhausted,
    BackendExited,
    PathForbidden,
}
impl Denial {
    /// Safe user-facing explanation, independent of untrusted response strings.
    pub const fn message(self) -> &'static str {
        match self {
            Self::UnknownVersion => "This privacy policy version is not supported. Connections are paused.",
            Self::InvalidConfiguration => "Check the privacy settings. No connection settings were changed.",
            Self::CorruptConfiguration => "Saved privacy settings need attention. Connections remain blocked.",
            Self::StorageUnavailable => "Privacy settings could not be saved. Connections remain blocked.",
            Self::ConsentRequired => "This change needs your explicit approval before it can take effect.",
            Self::InvalidEndpoint => "Enter a supported node address without credentials, a path, or a query.",
            Self::InvalidOnion => "This is not a valid Tor v3 onion address.",
            Self::InvalidI2p => "Use a supported 52-character base32 I2P address.",
            Self::UnapprovedNode => "This node has not been approved for use.",
            Self::DirectForbidden => "The selected policy does not permit a direct remote connection.",
            Self::MissingProxy | Self::ProxyUnavailable => "The required anonymous proxy is unavailable. Your wallet stays offline.",
            Self::I2pDisabled => "Configure an I2P SOCKS tunnel before using this node.",
            Self::TlsRequired => "Clearnet nodes require HTTPS through Tor.",
            Self::InvalidTls => "The node certificate could not be verified. The connection was refused.",
            Self::TransportFailure => "Connection lost. Your privacy settings are still enforced.",
            Self::Timeout => "The private connection did not respond in time.",
            Self::Cancelled | Self::PolicyChanged => "The old connection was cancelled before applying the current privacy policy.",
            Self::Redirect => "The node tried to redirect the connection. The redirect was refused.",
            Self::HttpStatus | Self::InvalidResponse => "The node returned an unsupported response.",
            Self::TooLarge => "The node response exceeded the permitted size.",
            Self::WrongNetwork => "The node is on a different Monero network.",
            Self::HeightInconsistent => "The node's chain information is inconsistent. It will not be used.",
            Self::NodeNotReady => "The node is still synchronizing or is unavailable for wallet requests.",
            Self::Stale => "The wallet's synchronization status is out of date.",
            Self::LocalEgressUnverified => "The local node's peer and broadcast routes have not been verified for this policy.",
            Self::NoPermittedNodes => "Add an approved node with a permitted anonymous route to connect.",
            Self::RecoveryExhausted => "AutoPilot could not establish a permitted connection. Your wallet is offline.",
            Self::BackendExited => "The local wallet process stopped. Reopening it will preserve your privacy settings.",
            Self::PathForbidden => "This node operation is not permitted by Privacy Guard.",
        }
    }
}
impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}
impl std::error::Error for Denial {}
pub type Result<T> = std::result::Result<T, Denial>;
