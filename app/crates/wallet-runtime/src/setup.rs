//! Wallet lifecycle component. The catalog contains public metadata only.
//! Seeds are used only by explicit, serialized requests and never by snapshots.
use autopilot_privacy::config::Network;
use autopilot_wallet_lab::{
    platform,
    supervisor::{wallet_name, Supervisor},
    LabResult,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SetupCommand {
    Create {
        name: String,
        network: String,
    },
    Restore {
        name: String,
        network: String,
        seed: String,
        restore_height: u64,
        expected_address: String,
    },
    Open {
        id: String,
    },
    Reveal {
        acknowledged: bool,
        #[serde(default)]
        pin: Option<crate::security::Secret>,
    },
    Verify {
        challenge: String,
        words: Vec<String>,
    },
    Hide,
}
impl Drop for SetupCommand {
    fn drop(&mut self) {
        match self {
            Self::Restore { seed, .. } => seed.zeroize(),
            Self::Verify { words, .. } => words.zeroize(),
            _ => (),
        }
    }
}
impl SetupCommand {
    pub fn changes_wallet(&self) -> bool {
        matches!(
            self,
            Self::Create { .. } | Self::Restore { .. } | Self::Open { .. }
        )
    }
    pub fn validate(&self) -> LabResult<()> {
        self.validate_for(Network::Stagenet)
    }
    pub fn validate_for(&self, selected: Network) -> LabResult<()> {
        match self {
            Self::Create { name, network } | Self::Restore { name, network, .. } => {
                if network != selected.as_str() {
                    return Err("The wallet must match the selected network.");
                }
                if name.trim().is_empty()
                    || name.chars().count() > 48
                    || name.chars().any(char::is_control)
                {
                    return Err("Choose a wallet name between 1 and 48 characters.");
                }
                if let Self::Restore {
                    seed,
                    expected_address,
                    ..
                } = self
                {
                    let _ = normalized_seed(seed)?;
                    if !expected_address.is_empty()
                        && (expected_address.len() != 95
                            || !expected_address.bytes().all(|b| b.is_ascii_alphanumeric()))
                    {
                        return Err(
                            "Enter the complete original primary address, or leave it blank.",
                        );
                    }
                }
            }
            Self::Open { id } if !valid_id(id) => return Err("Unknown wallet selection."),
            Self::Reveal {
                acknowledged: false,
                ..
            } => return Err("Acknowledge that the recovery phrase controls this wallet first."),
            Self::Verify { words, .. }
                if words.len() != 3 || words.iter().any(|s| s.len() > 40) =>
            {
                return Err("Enter the three requested words.")
            }
            _ => (),
        }
        Ok(())
    }
}
fn normalized_seed(seed: &str) -> LabResult<Zeroizing<String>> {
    if seed.len() > 600 {
        return Err("Enter a standard 25-word English recovery phrase.");
    }
    let words: Vec<_> = seed.split_whitespace().collect();
    if words.len() != 25
        || words
            .iter()
            .any(|w| w.len() > 30 || !w.bytes().all(|b| b.is_ascii_alphabetic()))
    {
        return Err("Enter a standard 25-word English recovery phrase.");
    }
    Ok(Zeroizing::new(words.join(" ").to_ascii_lowercase()))
}
fn valid_id(id: &str) -> bool {
    id == "legacy"
        || (id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletProfile {
    pub id: String,
    pub name: String,
    pub address: Option<String>,
    pub restore_height: u64,
    pub backup_verified: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: u8,
    pub network: String,
    pub active: Option<String>,
    pub wallets: Vec<WalletProfile>,
}
impl Catalog {
    pub fn active_profile(&self) -> Option<&WalletProfile> {
        self.wallets
            .iter()
            .find(|p| Some(&p.id) == self.active.as_ref())
    }
}
#[derive(Default, Serialize)]
pub struct SetupReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phrase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub positions: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restore_height: Option<u64>,
}
impl Drop for SetupReply {
    fn drop(&mut self) {
        if let Some(s) = &mut self.phrase {
            s.zeroize();
        }
    }
}
struct Challenge {
    id: String,
    wallet: String,
    answers: Vec<Zeroizing<String>>,
    expires: Instant,
}
pub struct WalletSetup {
    root: PathBuf,
    pub catalog: Catalog,
    challenge: Option<Challenge>,
}

impl WalletSetup {
    pub fn load(root: &Path) -> LabResult<Self> {
        Self::load_for(root, Network::Stagenet)
    }
    pub fn load_for(root: &Path, network: Network) -> LabResult<Self> {
        let path = root.join("wallet-catalog.json");
        let catalog: Catalog = if path.exists() {
            let data = std::fs::read(&path).map_err(|_| "Could not read wallet catalog.")?;
            if data.len() > 32768 {
                return Err("Wallet catalog exceeds its limit.");
            }
            serde_json::from_slice(&data)
                .map_err(|_| "Wallet catalog is damaged. Existing files have been preserved.")?
        } else {
            let exists = root
                .join("wallets")
                .join(format!("{}.keys", wallet_name(network)))
                .exists();
            Catalog {
                schema: 1,
                network: network.as_str().into(),
                active: exists.then(|| "legacy".into()),
                wallets: if exists {
                    vec![WalletProfile {
                        id: "legacy".into(),
                        name: "My original wallet".into(),
                        address: None,
                        restore_height: 0,
                        backup_verified: false,
                    }]
                } else {
                    vec![]
                },
            }
        };
        let mut ids = std::collections::HashSet::new();
        if catalog.schema != 1
            || catalog.network != network.as_str()
            || catalog.wallets.len() > 20
            || catalog
                .wallets
                .iter()
                .any(|p| !valid_id(&p.id) || !ids.insert(&p.id))
            || (catalog.active.is_some() && catalog.active_profile().is_none())
        {
            return Err("Invalid wallet catalog. Existing files have been preserved.");
        }
        Ok(Self {
            root: root.into(),
            catalog,
            challenge: None,
        })
    }
    pub fn active_root(&self) -> PathBuf {
        self.catalog
            .active
            .as_ref()
            .map_or_else(|| self.root.clone(), |id| self.profile_root(id))
    }
    fn profile_root(&self, id: &str) -> PathBuf {
        if id == "legacy" {
            self.root.clone()
        } else {
            self.root.join("profiles").join(id)
        }
    }
    fn commit(&mut self, catalog: Catalog) -> LabResult<()> {
        let temp = self
            .root
            .join(format!("catalog-{}.tmp", uuid::Uuid::new_v4().simple()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .map_err(|_| "Could not save wallet catalog.")?;
            file.write_all(
                &serde_json::to_vec(&catalog).map_err(|_| "Could not encode wallet catalog.")?,
            )
            .and_then(|_| file.sync_all())
            .map_err(|_| "Could not flush wallet catalog.")?;
            drop(file);
            std::fs::rename(&temp, self.root.join("wallet-catalog.json"))
                .map_err(|_| "Could not commit wallet selection.")
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
        }
        result?;
        self.catalog = catalog;
        Ok(())
    }
    pub fn forget_phrase(&mut self) {
        self.challenge = None;
    }
    pub fn expire(&mut self) {
        if self
            .challenge
            .as_ref()
            .is_some_and(|c| Instant::now() >= c.expires)
        {
            self.challenge = None;
        }
    }
    pub async fn execute(
        &mut self,
        supervisor: &mut Supervisor,
        command: &SetupCommand,
    ) -> LabResult<SetupReply> {
        let network = supervisor.network;
        if self.catalog.network != network.as_str() {
            return Err("Wallet catalog network mismatch.");
        }
        command.validate_for(network)?;
        self.expire();
        let mut reply = SetupReply::default();
        reply.ok = true;
        match command {
            SetupCommand::Create { name, .. } | SetupCommand::Restore { name, .. } => {
                self.forget_phrase();
                if self.catalog.wallets.len() >= 20 {
                    return Err("You can store up to 20 wallets on this device.");
                }
                if supervisor.wallet.is_some() {
                    return Err("Close the active wallet before creating or restoring another.");
                }
                supervisor.start_node().await?;
                let daemon = supervisor.daemon_rpc()?;
                // A saved node can answer RPC before its first peer/sync check.
                // Wait for that check instead of rejecting a normal cold start.
                let mut info = daemon.call("get_info", json!({}), 5).await?;
                for _ in 0..30 {
                    if info["synchronized"] == true {
                        break;
                    }
                    if info["nettype"] != network.as_str() {
                        return Err("Node network does not match this wallet.");
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    info = daemon.call("get_info", json!({}), 5).await?;
                }
                let height = info["height"]
                    .as_u64()
                    .ok_or("Local node height is unavailable.")?;
                if info["nettype"] != network.as_str() || info["synchronized"] != true {
                    return Err("Wait for the selected node to finish synchronizing.");
                }
                let restore_height = match command {
                    SetupCommand::Restore { restore_height, .. } if *restore_height > height => {
                        return Err("Restore height cannot be ahead of the local blockchain.")
                    }
                    SetupCommand::Restore { restore_height, .. } => *restore_height,
                    _ => height.saturating_sub(20),
                };
                let id = uuid::Uuid::new_v4().simple().to_string();
                let folder = self.profile_root(&id);
                platform::private_directory(&folder).await?;
                std::fs::create_dir(folder.join("wallets"))
                    .map_err(|_| "Could not create a new empty wallet folder.")?;
                supervisor.wallet_root = folder;
                if let SetupCommand::Restore { seed, .. } = command {
                    let seed = normalized_seed(seed)?;
                    supervisor
                        .restore_wallet_against(&daemon, &seed, restore_height)
                        .await?;
                } else {
                    supervisor.start_wallet_against(&daemon, true).await?;
                }
                let rpc = &supervisor
                    .wallet
                    .as_ref()
                    .ok_or("Wallet did not open.")?
                    .rpc;
                let result = rpc
                    .call("get_address", json!({"account_index":0}), 5)
                    .await?;
                let address = result["address"]
                    .as_str()
                    .filter(|s| s.len() == 95)
                    .ok_or("Wallet address is unavailable.")?
                    .to_string();
                let validation = rpc
                    .call(
                        "validate_address",
                        json!({"address":address,"any_net_type":false,"allow_openalias":false}),
                        5,
                    )
                    .await?;
                if validation["valid"] != true
                    || validation["nettype"] != network.as_str()
                    || validation["integrated"] != false
                    || validation["subaddress"] != false
                {
                    return Err("The wallet primary address did not match its network.");
                }
                if let SetupCommand::Restore {
                    expected_address, ..
                } = command
                {
                    if !expected_address.is_empty() && expected_address != &address {
                        return Err("Recovered address does not match. The previous wallet remains selected.");
                    }
                }
                rpc.call("store", json!({}), 15).await?;
                let mut catalog = self.catalog.clone();
                catalog.wallets.push(WalletProfile {
                    id: id.clone(),
                    name: name.trim().into(),
                    address: Some(address.clone()),
                    restore_height,
                    backup_verified: false,
                });
                catalog.active = Some(id);
                self.commit(catalog)?;
                reply.address = Some(address);
            }
            SetupCommand::Open { id } => {
                self.forget_phrase();
                if !self.catalog.wallets.iter().any(|p| &p.id == id) {
                    return Err("Unknown wallet selection.");
                }
                let folder = self.profile_root(id);
                if !folder
                    .join("wallets")
                    .join(format!("{}.keys", wallet_name(network)))
                    .is_file()
                    || !folder.join("wallet-password.dpapi").is_file()
                {
                    return Err(
                        "Saved wallet files are missing. Restore into a new wallet instead.",
                    );
                }
                let mut catalog = self.catalog.clone();
                catalog.active = Some(id.clone());
                self.commit(catalog)?;
                supervisor.wallet_root = folder;
            }
            SetupCommand::Reveal { .. } => {
                self.forget_phrase();
                let profile = self
                    .catalog
                    .active_profile()
                    .ok_or("Select a wallet first.")?
                    .clone();
                let rpc = &supervisor
                    .wallet
                    .as_ref()
                    .ok_or("Connect your wallet before backing it up.")?
                    .rpc;
                let phrase = rpc.recovery_phrase().await?;
                let address = rpc
                    .call("get_address", json!({"account_index":0}), 5)
                    .await?["address"]
                    .as_str()
                    .ok_or("Wallet address unavailable.")?
                    .to_string();
                if profile.address.as_ref().is_some_and(|a| a != &address) {
                    return Err("Wallet identity mismatch. Backup refused.");
                }
                let mut catalog = self.catalog.clone();
                catalog
                    .wallets
                    .iter_mut()
                    .find(|p| p.id == profile.id)
                    .ok_or("Wallet is missing.")?
                    .address = Some(address.clone());
                self.commit(catalog)?;
                let words: Vec<_> = phrase.split_whitespace().collect();
                let mut positions = Vec::new();
                while positions.len() < 3 {
                    let n = uuid::Uuid::new_v4().as_bytes()[0] as usize % 25;
                    if !positions.contains(&n) {
                        positions.push(n);
                    }
                }
                positions.sort();
                let challenge = uuid::Uuid::new_v4().simple().to_string();
                self.challenge = Some(Challenge {
                    id: challenge.clone(),
                    wallet: profile.id,
                    answers: positions
                        .iter()
                        .map(|n| Zeroizing::new(words[*n].to_owned()))
                        .collect(),
                    expires: Instant::now() + Duration::from_secs(180),
                });
                reply.phrase = Some(phrase.to_string());
                reply.challenge = Some(challenge);
                reply.positions = positions.iter().map(|n| n + 1).collect();
                reply.address = Some(address);
                reply.restore_height = Some(profile.restore_height);
            }
            SetupCommand::Verify { challenge, words } => {
                let pending = self
                    .challenge
                    .take()
                    .ok_or("Backup check expired. Reveal the phrase again.")?;
                if &pending.id != challenge
                    || self.catalog.active.as_ref() != Some(&pending.wallet)
                    || Instant::now() >= pending.expires
                {
                    return Err("Backup check expired. Reveal the phrase again.");
                }
                if pending
                    .answers
                    .iter()
                    .zip(words)
                    .any(|(a, b)| a.as_str() != b.trim().to_ascii_lowercase())
                {
                    return Err("Those words do not match. Reveal the phrase and check your written backup again.");
                }
                let mut catalog = self.catalog.clone();
                catalog
                    .wallets
                    .iter_mut()
                    .find(|p| p.id == pending.wallet)
                    .ok_or("Wallet is missing.")?
                    .backup_verified = true;
                self.commit(catalog)?;
            }
            SetupCommand::Hide => self.forget_phrase(),
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_paths_wrong_network_and_malformed_seeds() {
        for id in ["../wallets", "C:\\wallet", "", "a"] {
            assert!(!valid_id(id));
        }
        assert!(valid_id(&uuid::Uuid::new_v4().simple().to_string()));
        assert!(SetupCommand::Create {
            name: "New wallet".into(),
            network: "mainnet".into()
        }
        .validate()
        .is_err());
        assert!(normalized_seed("too few words").is_err());
        assert!(normalized_seed(&"example ".repeat(25)).is_ok()); // Official backend checks dictionary and checksum.
        assert!(SetupCommand::Reveal {
            acknowledged: false,
            pin: None
        }
        .validate()
        .is_err());
    }
    #[test]
    fn commands_reject_extra_fields_and_cannot_supply_paths_or_rpc_methods() {
        assert!(serde_json::from_str::<SetupCommand>(
            r#"{"action":"open","id":"legacy","path":"C:/other"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<SetupCommand>(
            r#"{"action":"query_key","key_type":"spend_key"}"#
        )
        .is_err());
    }
    #[tokio::test]
    async fn catalog_commits_backup_checks_and_rejects_expired_or_replayed_challenges() {
        let root = std::env::current_dir()
            .unwrap()
            .join(".runtime/setup-tests")
            .join(uuid::Uuid::new_v4().simple().to_string());
        let mut supervisor = Supervisor::new(root.clone(), root.clone()).await.unwrap();
        let mut manager = WalletSetup::load(&root).unwrap();
        assert!(manager.catalog.active.is_none());
        let catalog = Catalog {
            schema: 1,
            network: "stagenet".into(),
            active: Some("legacy".into()),
            wallets: vec![WalletProfile {
                id: "legacy".into(),
                name: "Test".into(),
                address: None,
                restore_height: 0,
                backup_verified: false,
            }],
        };
        manager.commit(catalog).unwrap();
        let challenge = |expires| Challenge {
            id: "test-challenge".into(),
            wallet: "legacy".into(),
            answers: vec![
                Zeroizing::new("one".into()),
                Zeroizing::new("two".into()),
                Zeroizing::new("three".into()),
            ],
            expires,
        };
        let command = SetupCommand::Verify {
            challenge: "test-challenge".into(),
            words: vec!["one".into(), "two".into(), "three".into()],
        };
        manager.challenge = Some(challenge(Instant::now() - Duration::from_secs(1)));
        assert!(manager.execute(&mut supervisor, &command).await.is_err());
        manager.challenge = Some(challenge(Instant::now() + Duration::from_secs(10)));
        let wrong = SetupCommand::Verify {
            challenge: "test-challenge".into(),
            words: vec!["wrong".into(), "two".into(), "three".into()],
        };
        assert!(manager.execute(&mut supervisor, &wrong).await.is_err());
        assert!(!manager.catalog.active_profile().unwrap().backup_verified);
        assert!(manager.execute(&mut supervisor, &command).await.is_err());
        manager.challenge = Some(challenge(Instant::now() + Duration::from_secs(10)));
        assert!(manager.execute(&mut supervisor, &command).await.is_ok());
        assert!(manager.execute(&mut supervisor, &command).await.is_err());
        assert!(
            WalletSetup::load(&root)
                .unwrap()
                .catalog
                .active_profile()
                .unwrap()
                .backup_verified
        );
        let bytes = std::fs::read_to_string(root.join("wallet-catalog.json")).unwrap();
        assert!(
            !bytes.contains("challenge") && !bytes.contains("phrase") && !bytes.contains("seed")
        );
        std::fs::write(root.join("wallet-catalog.json"), b"broken").unwrap();
        assert!(WalletSetup::load(&root).is_err());
    }
}
