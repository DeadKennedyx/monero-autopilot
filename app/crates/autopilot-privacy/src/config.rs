use crate::{
    endpoint::{Endpoint, ProxyEndpoint},
    Denial, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const SCHEMA_VERSION: u32 = 1;
pub const POLICY_VERSION: u32 = 1;
pub const MAX_NODES: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Balanced,
    LocalNode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Stagenet,
    Testnet,
}
impl Network {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Stagenet => "stagenet",
            Self::Testnet => "testnet",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    Personal,
    ThirdParty,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedNode {
    pub id: String,
    pub label: String,
    pub endpoint: String,
    pub ownership: Ownership,
    pub approved: bool,
    pub enabled: bool,
}
impl ApprovedNode {
    pub fn validate(&self) -> Result<Endpoint> {
        if self.id.len() != 32
            || !self.id.bytes().all(|c| c.is_ascii_hexdigit())
            || self.label.trim() != self.label
            || self.label.is_empty()
            || self.label.chars().count() > 60
            || self.label.chars().any(char::is_control)
        {
            return Err(Denial::InvalidConfiguration);
        }
        Endpoint::parse(&self.endpoint)
    }
}
/// Persisted user intent, never observed health or a session's temporary state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub policy_version: u32,
    pub profile: Profile,
    pub network: Network,
    /// Older configurations retain their explicitly configured external proxy.
    /// Fresh installations use the app-owned runtime; its port is never saved.
    #[serde(default)]
    pub managed_tor: bool,
    pub tor_proxy: Option<ProxyEndpoint>,
    pub i2p_proxy: Option<ProxyEndpoint>,
    pub nodes: Vec<ApprovedNode>,
    /// An explicit migration/user choice, never set by recovery.
    pub local_direct_consent: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            policy_version: POLICY_VERSION,
            profile: Profile::Balanced,
            network: Network::Stagenet,
            managed_tor: true,
            tor_proxy: None,
            i2p_proxy: None,
            nodes: vec![],
            local_direct_consent: false,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA_VERSION || self.policy_version != POLICY_VERSION {
            return Err(Denial::UnknownVersion);
        }
        if self.profile == Profile::LocalNode && !self.local_direct_consent {
            return Err(Denial::ConsentRequired);
        }
        if self.managed_tor && self.tor_proxy.is_some() {
            return Err(Denial::InvalidConfiguration);
        }
        if self.nodes.len() > MAX_NODES {
            return Err(Denial::InvalidConfiguration);
        }
        if let Some(p) = self.tor_proxy {
            p.validate()?;
        }
        if let Some(p) = self.i2p_proxy {
            p.validate()?;
        }
        let mut ids = HashSet::new();
        let mut endpoints = HashSet::new();
        for node in &self.nodes {
            let endpoint = node.validate()?;
            if !ids.insert(&node.id) || !endpoints.insert(endpoint.canonical().to_owned()) {
                return Err(Denial::InvalidConfiguration);
            }
        }
        Ok(())
    }
    /// All newly approved endpoints and weaker-profile changes require consent.
    /// Callers must additionally authenticate the user's settings action.
    pub fn validate_change(&self, next: &Self, consent: bool) -> Result<()> {
        self.validate()?;
        next.validate()?;
        let weaker = self.profile != Profile::LocalNode && next.profile == Profile::LocalNode;
        let added = next.nodes.iter().any(|n| {
            n.approved
                && !self.nodes.iter().any(|old| {
                    old.approved
                        && old.id == n.id
                        && old.endpoint == n.endpoint
                        && old.ownership == n.ownership
                })
        });
        if (weaker || added) && !consent {
            return Err(Denial::ConsentRequired);
        }
        Ok(())
    }
}

/// Atomic configuration storage. Parent directory permissions belong to the host.
pub struct ConfigStore {
    root: PathBuf,
}
impl ConfigStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn path(&self) -> PathBuf {
        self.root.join("privacy.json")
    }
    pub fn load(&self) -> Result<Config> {
        let path = self.path();
        let required = self.root.join("privacy-required");
        if !path.exists() && !required.exists() {
            return Ok(Config::default());
        }
        if !required.is_file() || !path.is_file() {
            return Err(Denial::CorruptConfiguration);
        }
        if fs::metadata(&path)
            .map_err(|_| Denial::StorageUnavailable)?
            .len()
            > 65536
        {
            return Err(Denial::CorruptConfiguration);
        }
        let bytes = fs::read(path).map_err(|_| Denial::StorageUnavailable)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Denial::CorruptConfiguration)?;
        if value["schema"].as_u64() != Some(SCHEMA_VERSION as u64)
            || value["policy_version"].as_u64() != Some(POLICY_VERSION as u64)
        {
            return Err(Denial::UnknownVersion);
        }
        let config: Config =
            serde_json::from_value(value).map_err(|_| Denial::CorruptConfiguration)?;
        config.validate()?;
        Ok(config)
    }
    pub fn save(&self, config: &Config) -> Result<()> {
        config.validate()?;
        fs::create_dir_all(&self.root).map_err(|_| Denial::StorageUnavailable)?;
        let marker = self.root.join("privacy-required");
        if !marker.exists() {
            write_new(&marker, b"Versioned privacy policy required; do not remove")?;
        }
        let data = serde_json::to_vec(config).map_err(|_| Denial::InvalidConfiguration)?;
        let temporary = self
            .root
            .join(format!("privacy-{}.tmp", uuid::Uuid::new_v4().simple()));
        write_new(&temporary, &data)?;
        fs::rename(&temporary, self.path()).map_err(|_| Denial::StorageUnavailable)?;
        #[cfg(unix)]
        {
            fs::File::open(&self.root)
                .and_then(|f| f.sync_all())
                .map_err(|_| Denial::StorageUnavailable)?;
        }
        Ok(())
    }
}
fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path).map_err(|_| Denial::StorageUnavailable)?;
    f.write_all(data)
        .and_then(|_| f.sync_all())
        .map_err(|_| Denial::StorageUnavailable)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_persists_and_corruption_never_resets_to_default() {
        let directory = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(directory.path());
        let mut c = store.load().unwrap();
        assert_eq!(c.profile, Profile::Balanced);
        c.managed_tor = false;
        c.tor_proxy = Some(ProxyEndpoint::parse("127.0.0.1:9050").unwrap());
        store.save(&c).unwrap();
        assert_eq!(store.load().unwrap(), c);
        c.i2p_proxy = Some(ProxyEndpoint::parse("127.0.0.1:4447").unwrap());
        store.save(&c).unwrap();
        assert_eq!(store.load().unwrap(), c);
        fs::write(store.path(), b"broken").unwrap();
        assert_eq!(store.load(), Err(Denial::CorruptConfiguration));
        fs::remove_file(store.path()).unwrap();
        assert_eq!(store.load(), Err(Denial::CorruptConfiguration));
    }
    #[test]
    fn unknown_policy_and_configuration_changes_fail_closed() {
        let mut c = Config::default();
        c.policy_version += 1;
        assert_eq!(c.validate(), Err(Denial::UnknownVersion));
        let c = Config::default();
        let mut next = c.clone();
        next.profile = Profile::LocalNode;
        assert_eq!(next.validate(), Err(Denial::ConsentRequired));
        next.local_direct_consent = true;
        assert_eq!(
            c.validate_change(&next, false),
            Err(Denial::ConsentRequired)
        );
        assert!(c.validate_change(&next, true).is_ok());
        let bad: ProxyEndpoint = serde_json::from_str("\"8.8.8.8:9050\"").unwrap();
        next.tor_proxy = Some(bad);
        assert_eq!(next.validate(), Err(Denial::InvalidConfiguration));
    }
    #[test]
    fn new_apps_bundle_tor_but_legacy_explicit_proxies_are_preserved() {
        let fresh = Config::default();
        assert!(fresh.managed_tor);
        assert!(fresh.tor_proxy.is_none());
        let mut legacy = serde_json::to_value(&fresh).unwrap();
        legacy.as_object_mut().unwrap().remove("managed_tor");
        legacy["tor_proxy"] = serde_json::json!("127.0.0.1:9050");
        let legacy: Config = serde_json::from_value(legacy).unwrap();
        assert!(!legacy.managed_tor);
        legacy.validate().unwrap();
        let mut invalid = legacy.clone();
        invalid.managed_tor = true;
        assert_eq!(invalid.validate(), Err(Denial::InvalidConfiguration));
    }
}
