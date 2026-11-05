//! Private relationship-to-subaddress assignments. Only official wallet RPC
//! creates/validates addresses; neither this module nor a remote node scans keys.
//! Persist intent before creation, then reconcile its opaque wallet label after
//! interruption. Human relationship names never enter daemon requests or logs.
use autopilot_wallet_lab::{platform, rpc::Rpc, LabResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const VERSION: u32 = 1;
const MAX_RELATIONSHIPS: usize = 128;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    pub id: String,
    pub name: String,
    pub address: Option<String>,
    pub address_index: Option<u32>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    wallet_identity: String,
    relationships: Vec<Relationship>,
}
#[derive(Clone)]
pub struct WalletAddress {
    pub index: u32,
    pub address: String,
    pub label: String,
}
pub trait SubaddressWallet: Sync {
    fn addresses(&self) -> impl Future<Output = LabResult<Vec<WalletAddress>>> + Send;
    fn create(&self, opaque_label: &str) -> impl Future<Output = LabResult<WalletAddress>> + Send;
    fn validate(&self, address: &str) -> impl Future<Output = LabResult<()>> + Send;
    fn save(&self) -> impl Future<Output = LabResult<()>> + Send;
}
fn parse_address(value: &serde_json::Value) -> LabResult<WalletAddress> {
    let index = value["address_index"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("Invalid subaddress index.")?;
    let address = value["address"]
        .as_str()
        .filter(|a| address_shape(a))
        .ok_or("Invalid subaddress response.")?
        .to_owned();
    let label = value["label"].as_str().unwrap_or("").to_owned();
    Ok(WalletAddress {
        index,
        address,
        label,
    })
}
impl SubaddressWallet for Rpc {
    async fn addresses(&self) -> LabResult<Vec<WalletAddress>> {
        let result = self
            .call("get_address", json!({"account_index":0}), 8)
            .await?;
        let entries = result["addresses"]
            .as_array()
            .filter(|a| a.len() <= 256)
            .ok_or("The receiving-address list is unavailable or too large.")?;
        entries.iter().map(parse_address).collect()
    }
    async fn create(&self, opaque_label: &str) -> LabResult<WalletAddress> {
        let result = self
            .call(
                "create_address",
                json!({"account_index":0,"label":opaque_label}),
                10,
            )
            .await?;
        let mut address = parse_address(&result)?;
        address.label = opaque_label.into();
        Ok(address)
    }
    async fn validate(&self, address: &str) -> LabResult<()> {
        let result = self
            .call(
                "validate_address",
                json!({"address":address,"any_net_type":false,"allow_openalias":false}),
                5,
            )
            .await?;
        if result["valid"] != true
            || result["nettype"] != "stagenet"
            || result["integrated"] != false
            || result["subaddress"] != true
        {
            return Err("The wallet did not validate a stagenet subaddress.");
        }
        Ok(())
    }
    async fn save(&self) -> LabResult<()> {
        self.call("store", json!({}), 15).await.map(|_| ())
    }
}
fn address_shape(value: &str) -> bool {
    value.len() == 95
        && value
            .bytes()
            .all(|c| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&c))
}
fn name(value: &str) -> LabResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 60 || value.chars().any(char::is_control) {
        return Err("Choose a relationship name between 1 and 60 characters.");
    }
    Ok(value.to_owned())
}
fn wallet_label(id: &str) -> String {
    format!("autopilot-relationship:{id}")
}
pub struct RelationshipBook {
    root: PathBuf,
    record: Record,
}
impl RelationshipBook {
    pub fn open(root: PathBuf, wallet_identity: &str) -> LabResult<Self> {
        if wallet_identity.len() != 64 || !wallet_identity.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("Wallet identity is unavailable.");
        }
        let marker = root.join("required");
        let path = root.join("relationships.dpapi");
        let record = if !marker.exists() && !path.exists() {
            Record {
                version: VERSION,
                wallet_identity: wallet_identity.into(),
                relationships: vec![],
            }
        } else {
            if !marker.is_file()
                || !path.is_file()
                || fs::metadata(&path)
                    .map_err(|_| "Relationship records are unavailable.")?
                    .len()
                    > 1024 * 1024
            {
                return Err("Relationship records need review; no address will be reassigned.");
            }
            let protected = fs::read(path).map_err(|_| "Relationship records are unavailable.")?;
            let plain = platform::unprotect(&protected)?;
            serde_json::from_slice(&plain)
                .map_err(|_| "Relationship records are damaged; no address will be reassigned.")?
        };
        let book = Self { root, record };
        book.validate(wallet_identity)?;
        Ok(book)
    }
    fn validate(&self, identity: &str) -> LabResult<()> {
        if self.record.version != VERSION
            || self.record.wallet_identity != identity
            || self.record.relationships.len() > MAX_RELATIONSHIPS
        {
            return Err("Relationship records do not match this wallet or version.");
        }
        let (mut ids, mut names, mut indices, mut addresses) = (
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        );
        for item in &self.record.relationships {
            if item.id.len() != 32
                || !item.id.bytes().all(|c| c.is_ascii_hexdigit())
                || !ids.insert(&item.id)
                || name(&item.name)? != item.name
                || !names.insert(item.name.to_lowercase())
            {
                return Err("Relationship records are inconsistent.");
            }
            match (&item.address, item.address_index) {
                (None, None) => (),
                (Some(address), Some(index))
                    if index > 0
                        && address_shape(address)
                        && indices.insert(index)
                        && addresses.insert(address) => {}
                _ => return Err("Receiving-address assignments are inconsistent."),
            }
        }
        Ok(())
    }
    fn commit(&mut self, record: Record) -> LabResult<()> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(&record).map_err(|_| "Could not encode relationship records.")?,
        );
        let protected = platform::protect(&bytes)?;
        fs::create_dir_all(&self.root)
            .map_err(|_| "Could not create private relationship storage.")?;
        let marker = self.root.join("required");
        if !marker.exists() {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(marker)
                .and_then(|mut f| {
                    f.write_all(b"1")?;
                    f.sync_all()
                })
                .map_err(|_| "Could not protect relationship storage.")?;
        }
        let temp = self
            .root
            .join(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
        let result: LabResult<()> = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .map_err(|_| "Could not save relationship records.")?;
            file.write_all(&protected)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Could not save relationship records.")?;
            drop(file);
            fs::rename(&temp, self.root.join("relationships.dpapi"))
                .map_err(|_| "Could not replace relationship records.")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result?;
        self.record = record;
        Ok(())
    }
    /// The app returns these only to an unlocked, authenticated local session.
    pub fn completed(&self) -> Vec<Relationship> {
        self.record
            .relationships
            .iter()
            .filter(|r| r.address.is_some())
            .cloned()
            .collect()
    }
    pub fn path(&self) -> &Path {
        &self.root
    }
    pub async fn assign<W: SubaddressWallet>(
        &mut self,
        wallet: &W,
        relationship_name: &str,
    ) -> LabResult<Relationship> {
        let display_name = name(relationship_name)?;
        let index = match self
            .record
            .relationships
            .iter()
            .position(|r| r.name.to_lowercase() == display_name.to_lowercase())
        {
            Some(index) => index,
            None => {
                if self.record.relationships.len() >= MAX_RELATIONSHIPS {
                    return Err("The relationship address limit has been reached.");
                }
                let mut next = self.record.clone();
                next.relationships.push(Relationship {
                    id: uuid::Uuid::new_v4().simple().to_string(),
                    name: display_name,
                    address: None,
                    address_index: None,
                });
                self.commit(next)?;
                self.record.relationships.len() - 1
            }
        };
        let entry = self.record.relationships[index].clone();
        let label = wallet_label(&entry.id);
        let addresses = wallet.addresses().await?;
        let matches: Vec<_> = addresses.iter().filter(|a| a.label == label).collect();
        if matches.len() > 1 {
            return Err(
                "Multiple wallet addresses share this relationship marker. Review is required.",
            );
        }
        let selected = match matches.first() {
            Some(address) => (*address).clone(),
            None if entry.address.is_some() => return Err("The saved relationship address is missing from this wallet. It will not be reassigned."),
            None => {
                let created = wallet.create(&label).await?;
                if addresses.iter().any(|a| a.index >= created.index || a.address == created.address) {
                    return Err("The wallet did not create a distinct new subaddress.");
                }
                let observed = wallet.addresses().await?;
                if observed.iter().filter(|a| a.label == label && a.index == created.index && a.address == created.address).count() != 1 {
                    return Err("The new subaddress marker could not be verified. Retry to reconcile it.");
                }
                created
            },
        };
        if selected.index == 0
            || !address_shape(&selected.address)
            || (entry
                .address
                .as_ref()
                .is_some_and(|a| a != &selected.address))
            || (entry.address_index.is_some_and(|i| i != selected.index))
            || self.record.relationships.iter().enumerate().any(|(i, r)| {
                i != index
                    && (r.address_index == Some(selected.index)
                        || r.address.as_ref() == Some(&selected.address))
            })
        {
            return Err("This subaddress cannot be assigned to the requested relationship.");
        }
        wallet.validate(&selected.address).await?;
        // Save the official wallet's label/address before committing or exposing
        // it. A lost response leaves a pending intent that can be reconciled.
        wallet.save().await?;
        let mut next = self.record.clone();
        next.relationships[index].address = Some(selected.address);
        next.relationships[index].address_index = Some(selected.index);
        self.commit(next)?;
        Ok(self.record.relationships[index].clone())
    }
}

#[cfg(test)]
#[path = "relationship_tests.rs"]
mod tests;
