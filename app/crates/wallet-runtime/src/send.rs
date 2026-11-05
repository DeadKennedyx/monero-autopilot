//! Explicit prepare/confirm with an immutable, DPAPI-protected journal.
//! An attempt marker is flushed BEFORE relay. No path retries a relay.
#[cfg(test)]
#[path = "mainnet_send_tests.rs"]
mod mainnet_tests;
#[cfg(test)]
#[path = "send_review_tests.rs"]
mod review_tests;
#[cfg(test)]
#[path = "routed_send_tests.rs"]
mod routed_tests;
use autopilot_privacy::config::Network;
use autopilot_wallet_lab::{
    platform,
    rpc::{Rpc, TransferPriority},
    LabResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};
use zeroize::Zeroizing;

pub const MAX_AMOUNT: u64 = 10_000_000_000; // 0.01 XMR, prototype limit on either network
pub const MAX_FEE: u64 = 1_000_000_000; // 0.001 sXMR
pub const MAINNET_MAX_FEE: u64 = 100_000_000; // 0.0001 XMR
#[derive(Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SendCommand {
    Prepare {
        address: String,
        amount: String,
        #[serde(default)]
        priority: TransferPriority,
    },
    Confirm {
        id: String,
        #[serde(default)]
        pin: Option<crate::security::Secret>,
    },
    Cancel {
        id: String,
    },
    Check,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payment {
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub priority: TransferPriority,
    /// Verified against this wallet's account 0 before preparing the transaction.
    #[serde(default)]
    pub self_transfer: bool,
    pub amount_atomic: String,
    pub fee_atomic: String,
    pub total_atomic: String,
    pub txid: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: String,
    pub confirmations: u64,
    pub checked_at: Option<u64>,
}
#[derive(Clone, Default, Serialize)]
pub struct SendSnapshot {
    pub payments: Vec<Payment>,
    pub error: Option<String>,
    /// Fee-only diagnostic for a rejected, unpersisted preparation. No signed
    /// metadata or authorization can be recovered from this public projection.
    pub rejected_fee: Option<RejectedFee>,
    pub blocked: bool,
}
#[derive(Clone, Serialize)]
pub struct RejectedFee {
    pub fee_atomic: String,
    pub maximum_fee_atomic: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u8,
    network: String,
    wallet_identity: String,
    payment: Payment,
    metadata: String,
}
pub struct Sender {
    root: PathBuf,
    network: Network,
    records: Vec<Record>,
    pub snapshot: SendSnapshot,
    failed: bool,
}
pub fn parse_amount(text: &str) -> LabResult<u64> {
    if text.is_empty() || text.len() > 30 {
        return Err("Enter a positive amount with at most 12 decimal places.");
    }
    let mut pieces = text.split('.');
    let whole = pieces.next().unwrap_or("");
    let fraction = pieces.next().unwrap_or("");
    if pieces.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|c| c.is_ascii_digit())
        || !fraction.bytes().all(|c| c.is_ascii_digit())
        || fraction.len() > 12
        || text.ends_with('.')
    {
        return Err("Use a plain decimal amount with at most 12 decimal places.");
    }
    let whole = whole.parse::<u64>().map_err(|_| "Amount is too large.")?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().map_err(|_| "Invalid amount.")?
            * 10u64.pow(12 - fraction.len() as u32)
    };
    let amount = whole
        .checked_mul(1_000_000_000_000)
        .and_then(|v| v.checked_add(fraction))
        .ok_or("Amount is too large.")?;
    if amount == 0 || amount > MAX_AMOUNT {
        return Err("Enter an amount above zero and up to 0.01 XMR.");
    }
    Ok(amount)
}
fn is_hex(s: &str, length: usize) -> bool {
    s.len() == length && s.bytes().all(|c| c.is_ascii_hexdigit())
}
fn valid_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit())
}
fn durable(path: &std::path::Path, bytes: &[u8]) -> LabResult<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| {
            "Payment record already exists or could not be created. Nothing was retried."
        })?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Payment record could not be flushed. Sending stopped for review.")
}
impl Sender {
    pub fn open(root: PathBuf) -> Self {
        Self::open_for(root, Network::Stagenet)
    }
    pub fn open_for(root: PathBuf, network: Network) -> Self {
        let mut sender = Self {
            root,
            network,
            records: vec![],
            snapshot: SendSnapshot::default(),
            failed: false,
        };
        let loaded = if network == Network::Testnet {
            Err("Testnet payments are not supported by this prototype.")
        } else {
            sender.load()
        };
        if let Err(error) = loaded {
            sender.failed = true;
            sender.snapshot.error = Some(error.into());
        }
        sender.project();
        sender
    }
    fn load(&mut self) -> LabResult<()> {
        fs::create_dir_all(&self.root).map_err(|_| "Cannot open the local payment journal.")?;
        for item in fs::read_dir(&self.root).map_err(|_| "Cannot read the payment journal.")? {
            let path = item.map_err(|_| "Cannot read payment record.")?.path();
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("Invalid payment journal filename.")?;
            if !name.ends_with(".dpapi")
                && !name.ends_with(".attempt")
                && !name.ends_with(".cancel")
            {
                return Err("Unexpected payment journal file. Sending is disabled for review.");
            }
            let id = name.split('.').next().unwrap_or("");
            if !valid_id(id)
                || !path.is_file()
                || fs::symlink_metadata(&path)
                    .map_err(|_| "Cannot inspect payment journal.")?
                    .file_type()
                    .is_symlink()
            {
                return Err("Invalid payment journal entry.");
            }
            if !name.ends_with(".dpapi") {
                if !self.root.join(format!("{id}.dpapi")).exists() {
                    return Err("An incomplete payment journal requires review.");
                }
                continue;
            }
            if self.records.len() >= 100
                || fs::metadata(&path)
                    .map_err(|_| "Cannot read payment record.")?
                    .len()
                    > 131072
            {
                return Err("The payment journal has reached its storage limit.");
            }
            let bytes = platform::unprotect(
                &fs::read(&path).map_err(|_| "Cannot read protected payment record.")?,
            )?;
            let mut record: Record = serde_json::from_slice(&bytes)
                .map_err(|_| "Payment record is damaged. Sending is disabled for review.")?;
            if record.schema != 1
                || record.network != self.network.as_str()
                || record.payment.id != id
                || !is_hex(&record.wallet_identity, 64)
                || !is_hex(&record.payment.txid, 64)
                || !self.valid_payment_limits(&record.payment)
            {
                return Err("Payment record identity is invalid.");
            }
            if self.marker(id, "attempt").exists() {
                record.payment.status = "Checking outcome".into();
            } else {
                record.payment.status = "Cancelled".into();
                if !self.marker(id, "cancel").exists() {
                    durable(&self.marker(id, "cancel"), b"restart")?;
                }
            }
            record.payment.checked_at = None;
            self.records.push(record);
        }
        self.records.sort_by_key(|r| r.payment.created_at);
        Ok(())
    }
    fn max_fee(&self) -> u64 {
        match self.network {
            Network::Mainnet => MAINNET_MAX_FEE,
            Network::Stagenet => MAX_FEE,
            Network::Testnet => 0,
        }
    }
    fn valid_payment_limits(&self, payment: &Payment) -> bool {
        match (
            payment.amount_atomic.parse::<u64>(),
            payment.fee_atomic.parse::<u64>(),
            payment.total_atomic.parse::<u64>(),
        ) {
            (Ok(amount), Ok(fee), Ok(total)) => {
                amount > 0
                    && amount <= MAX_AMOUNT
                    && fee > 0
                    && fee <= self.max_fee()
                    && amount.checked_add(fee) == Some(total)
            }
            _ => false,
        }
    }
    fn marker(&self, id: &str, kind: &str) -> PathBuf {
        self.root.join(format!("{id}.{kind}"))
    }
    fn project(&mut self) {
        self.snapshot.payments = self
            .records
            .iter()
            .rev()
            .map(|r| r.payment.clone())
            .collect();
        self.snapshot.blocked = self.failed
            || self.records.iter().any(|r| {
                matches!(
                    r.payment.status.as_str(),
                    "Preview" | "Checking outcome" | "Pending" | "Needs review"
                )
            });
    }
    pub fn set_error(&mut self, error: &str) {
        self.snapshot.error = Some(error.into());
        self.project();
    }
    pub fn clear_rejected_fee(&mut self) {
        self.snapshot.rejected_fee = None;
    }
    pub fn invalidate_previews(&mut self) -> LabResult<()> {
        let ids: Vec<_> = self
            .records
            .iter()
            .filter(|r| r.payment.status == "Preview")
            .map(|r| r.payment.id.clone())
            .collect();
        for id in ids {
            self.cancel(&id)?;
        }
        Ok(())
    }
    pub fn cancel(&mut self, id: &str) -> LabResult<()> {
        if self.failed {
            return Err("Payment journal needs review.");
        }
        let index = self
            .records
            .iter()
            .position(|r| r.payment.id == id)
            .ok_or("Payment preview was not found.")?;
        if self.records[index].payment.status != "Preview" || self.marker(id, "attempt").exists() {
            return Err("A submitted payment cannot be cancelled here.");
        }
        if let Err(e) = durable(&self.marker(id, "cancel"), b"cancelled") {
            self.failed = true;
            self.project();
            return Err(e);
        }
        self.records[index].payment.status = "Cancelled".into();
        self.snapshot.error = None;
        self.clear_rejected_fee();
        self.project();
        Ok(())
    }
    pub async fn prepare(
        &mut self,
        rpc: &Rpc,
        wallet: &str,
        address: &str,
        amount: &str,
        spendable: u64,
        now: u64,
    ) -> LabResult<()> {
        self.prepare_with_priority(
            rpc,
            wallet,
            address,
            amount,
            spendable,
            now,
            TransferPriority::Automatic,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_with_priority(
        &mut self,
        rpc: &Rpc,
        wallet: &str,
        address: &str,
        amount: &str,
        spendable: u64,
        now: u64,
        priority: TransferPriority,
    ) -> LabResult<()> {
        let started = std::time::Instant::now();
        self.clear_rejected_fee();
        self.expire(now)?;
        self.project();
        if self.snapshot.blocked || self.records.len() >= 100 {
            return Err("Finish or review the existing payment before starting another.");
        }
        let amount = parse_amount(amount)?;
        if address.len() != 95
            || !address
                .bytes()
                .all(|c| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&c))
        {
            return Err("Paste a complete standard address or subaddress for this network.");
        }
        let valid = rpc
            .call(
                "validate_address",
                json!({"address":address,"any_net_type":true,"allow_openalias":false}),
                5,
            )
            .await?;
        if valid["valid"] != true
            || valid["nettype"] != self.network.as_str()
            || valid["integrated"] != false
        {
            return Err(
                "The destination must be valid on this wallet's network without a payment ID.",
            );
        }
        if amount >= spendable {
            return Err("Insufficient spendable funds for the amount and network fee.");
        }
        // Only account-0 ownership allows Monero's normalized zero outgoing
        // amount during reconciliation. Do not infer ownership from an address
        // prefix, the UI, or the transaction response.
        let own = rpc
            .call("get_address", json!({"account_index":0}), 5)
            .await?;
        let addresses = own["addresses"]
            .as_array()
            .filter(|entries| !entries.is_empty())
            .ok_or("Cannot verify this wallet's receiving addresses.")?;
        let self_transfer = addresses.iter().any(|entry| {
            entry["address"].as_str() == Some(address)
                && entry["address_index"]
                    .as_u64()
                    .is_some_and(|index| u32::try_from(index).is_ok())
        });
        let value = rpc
            .prepare_transfer_with_priority(address, amount, self.network, priority)
            .await?;
        let fee = value["fee"]
            .as_u64()
            .filter(|fee| *fee > 0)
            .ok_or("The wallet returned an invalid network fee.")?;
        if fee > self.max_fee() {
            self.snapshot.rejected_fee = Some(RejectedFee {
                fee_atomic: fee.to_string(),
                maximum_fee_atomic: self.max_fee().to_string(),
            });
            return Err(match self.network {
                Network::Mainnet => "The network fee exceeds the 0.0001 XMR limit.",
                Network::Stagenet => "The network fee exceeds the 0.001 sXMR limit.",
                Network::Testnet => "Testnet payments are not supported by this prototype.",
            });
        }
        let total = amount
            .checked_add(fee)
            .filter(|v| *v <= spendable)
            .ok_or("Insufficient spendable funds including the network fee.")?;
        let txid = value["tx_hash"]
            .as_str()
            .filter(|s| is_hex(s, 64))
            .ok_or("Prepared transaction identity is invalid.")?;
        let metadata = value["tx_metadata"]
            .as_str()
            .filter(|s| {
                !s.is_empty()
                    && s.len() <= 60000
                    && s.len() % 2 == 0
                    && s.bytes().all(|c| c.is_ascii_hexdigit())
            })
            .ok_or("Prepared transaction data is invalid.")?;
        if value["amount"].as_u64() != Some(amount)
            || !value["unsigned_txset"].as_str().unwrap_or("").is_empty()
            || !value["multisig_txset"].as_str().unwrap_or("").is_empty()
        {
            return Err("Prepared transaction did not match the requested payment.");
        }
        // Construction can legitimately take much of the mainnet deadline.
        // Give the user the full review window once the preview actually exists.
        let prepared_at = now.saturating_add(started.elapsed().as_secs());
        let record = Record {
            schema: 1,
            network: self.network.as_str().into(),
            wallet_identity: wallet.into(),
            metadata: metadata.into(),
            payment: Payment {
                id: uuid::Uuid::new_v4().simple().to_string(),
                address: address.into(),
                priority,
                self_transfer,
                amount_atomic: amount.to_string(),
                fee_atomic: fee.to_string(),
                total_atomic: total.to_string(),
                txid: txid.into(),
                created_at: prepared_at,
                expires_at: prepared_at.saturating_add(120),
                status: "Preview".into(),
                confirmations: 0,
                checked_at: None,
            },
        };
        let plain = Zeroizing::new(
            serde_json::to_vec(&record).map_err(|_| "Cannot encode payment record.")?,
        );
        let protected = platform::protect(&plain)?;
        if let Err(e) = durable(&self.marker(&record.payment.id, "dpapi"), &protected) {
            self.failed = true;
            self.project();
            return Err(e);
        }
        self.records.push(record);
        self.snapshot.error = None;
        self.project();
        Ok(())
    }
    pub fn expire(&mut self, now: u64) -> LabResult<()> {
        let ids: Vec<_> = self
            .records
            .iter()
            .filter(|r| r.payment.status == "Preview" && now >= r.payment.expires_at)
            .map(|r| r.payment.id.clone())
            .collect();
        for id in ids {
            self.cancel(&id)?;
        }
        Ok(())
    }
    pub async fn confirm(
        &mut self,
        rpc: &Rpc,
        wallet: &str,
        id: &str,
        spendable: u64,
        now: u64,
    ) -> LabResult<()> {
        self.confirm_authorized(rpc, wallet, id, spendable, now, None)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn confirm_authorized(
        &mut self,
        rpc: &Rpc,
        wallet: &str,
        id: &str,
        spendable: u64,
        now: u64,
        authorization: Option<crate::security::PaymentAuthorization>,
    ) -> LabResult<()> {
        self.confirm_routed(rpc, wallet, id, spendable, now, authorization, None)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn confirm_routed(
        &mut self,
        rpc: &Rpc,
        wallet: &str,
        id: &str,
        spendable: u64,
        now: u64,
        mut authorization: Option<crate::security::PaymentAuthorization>,
        route: Option<(&autopilot_privacy::runtime::RouteManager, u64)>,
    ) -> LabResult<()> {
        self.expire(now)?;
        if self.failed {
            return Err("Payment journal needs review.");
        }
        let i = self
            .records
            .iter()
            .position(|r| r.payment.id == id)
            .ok_or("Payment preview was not found.")?;
        let r = &self.records[i];
        if r.wallet_identity != wallet
            || r.network != self.network.as_str()
            || !self.valid_payment_limits(&r.payment)
            || r.payment.status != "Preview"
            || r.payment
                .total_atomic
                .parse::<u64>()
                .ok()
                .is_none_or(|v| v > spendable)
            || self.marker(id, "cancel").exists()
        {
            return Err(
                "This preview cannot be confirmed. Check balance and prepare a new preview.",
            );
        }
        if self.network == Network::Mainnet && (authorization.is_none() || route.is_none()) {
            return Err(
                "Mainnet payments require PIN authorization and a permitted private connection.",
            );
        }
        if let Some(permit) = &mut authorization {
            permit.check(wallet, id)?;
        }
        if let Some((router, generation)) = route {
            if router.config().network != self.network
                || router.endpoint().map_err(|e| e.message())?.generation() != generation
            {
                return Err("The node connection changed. Review a new payment preview.");
            }
            if self.network == Network::Mainnet
                && (router.config().profile != autopilot_privacy::config::Profile::Balanced
                    || !router.config().nodes.iter().any(|node| {
                        node.approved
                            && node.enabled
                            && node.ownership == autopilot_privacy::config::Ownership::Personal
                            && router.snapshot().node_id.as_deref() == Some(node.id.as_str())
                    }))
            {
                return Err(
                    "Mainnet payments require an approved owned node over the private connection.",
                );
            }
        }
        // Durable at-most-once boundary. Any failure, including a partial marker,
        // disables the path rather than allowing another relay.
        if let Err(e) = durable(
            &self.marker(id, "attempt"),
            b"user-confirmed; relay may have happened",
        ) {
            self.failed = true;
            self.project();
            return Err(e);
        }
        drop(authorization); // Durable authorization crossed; a later lock cannot undo this payment.
        self.records[i].payment.status = "Checking outcome".into();
        self.project();
        // The durable, PIN-authorized attempt is committed before the gateway
        // can forward one broadcast. Transport loss cannot reopen this marker.
        let _broadcast_permission = match route {
            Some((router, generation)) => Some(
                router
                    .authorize_one_broadcast(generation)
                    .map_err(|e| e.message())?,
            ),
            None => None,
        };
        let result = rpc.relay_prepared(&self.records[i].metadata).await;
        match result {
            Ok(value)
                if value["tx_hash"].as_str() == Some(self.records[i].payment.txid.as_str()) =>
            {
                self.records[i].payment.status = "Pending".into();
                self.snapshot.error = None;
            }
            _ => {
                self.snapshot.error=Some("The broadcast outcome is uncertain. Checking the saved transaction; it will not be sent again automatically.".into());
            }
        }
        let _ = rpc.call("store", json!({}), 8).await;
        self.project();
        Ok(())
    }
    pub async fn reconcile(&mut self, rpc: &Rpc, wallet: &str, now: u64) -> LabResult<()> {
        self.expire(now)?;
        if self.failed {
            return Err("Payment journal needs review.");
        }
        for i in 0..self.records.len() {
            if self.records[i].wallet_identity != wallet
                || self.records[i].network != self.network.as_str()
            {
                self.failed = true;
                self.project();
                return Err(
                    "The payment journal belongs to a different wallet. Sending is disabled.",
                );
            }
        }
        if !self
            .records
            .iter()
            .any(|record| self.marker(&record.payment.id, "attempt").exists())
        {
            self.project();
            return Ok(());
        }
        // get_transfer_by_txid refreshes the remote pool even for a confirmed
        // transaction. Read the wallet's local outgoing history once instead;
        // native background refresh supplies new network evidence.
        let history = rpc
            .call(
                "get_transfers",
                json!({"in":false,"out":true,"pending":true,"failed":true,"pool":false,"account_index":0}),
                8,
            )
            .await
            .map(outgoing_history);
        let mut uncertain = false;
        for i in 0..self.records.len() {
            if !self.marker(&self.records[i].payment.id, "attempt").exists() {
                continue;
            }
            let p = &mut self.records[i].payment;
            let parsed = match &history {
                Ok(parsed) => parsed,
                Err(_) => {
                    // A read failure cannot erase previously observed inclusion.
                    // checked_at=None exposes that this is saved, stale evidence.
                    p.checked_at = None;
                    uncertain = true;
                    continue;
                }
            };
            match parsed
                .as_ref()
                .map_err(|error| *error)
                .and_then(|value| parse_outgoing(value, p))
            {
                Ok((status, confirmations)) => {
                    p.status = status.into();
                    p.confirmations = confirmations;
                    p.checked_at = Some(now);
                }
                Err(_) => {
                    p.status = "Checking outcome".into();
                    p.confirmations = 0;
                    p.checked_at = None;
                    uncertain = true;
                }
            }
        }
        self.snapshot.error = uncertain.then(|| {
            "Payment confirmation is not currently verified. Saved transaction evidence is retained; this payment will not be sent again automatically.".into()
        });
        self.project();
        Ok(())
    }
}
fn outgoing_history(value: Value) -> LabResult<Value> {
    let mut transfers = vec![];
    for kind in ["out", "pending", "failed"] {
        let Some(entries) = value.get(kind) else {
            continue;
        };
        let entries = entries
            .as_array()
            .filter(|entries| entries.len() <= 500)
            .ok_or("Outgoing history is invalid or exceeds the prototype limit.")?;
        for entry in entries {
            if entry["type"].as_str() != Some(kind) {
                return Err("Outgoing history category did not match.");
            }
            transfers.push(entry.clone());
        }
    }
    Ok(json!({"transfers":transfers}))
}
fn parse_outgoing(value: &Value, p: &Payment) -> LabResult<(&'static str, u64)> {
    let v = if let Some(transfers) = value.get("transfers") {
        let transfers = transfers.as_array().ok_or("Outgoing history is invalid.")?;
        let mut matches = transfers.iter().filter(|entry| {
            entry["txid"].as_str() == Some(p.txid.as_str())
                && matches!(entry["type"].as_str(), Some("out" | "pending" | "failed"))
        });
        let only = matches
            .next()
            .ok_or("Outgoing transaction was not found.")?;
        if matches.next().is_some() {
            return Err("Outgoing transaction evidence is ambiguous.");
        }
        only
    } else {
        &value["transfer"]
    };
    let amount = v["amount"].as_u64();
    let expected_amount = p.amount_atomic.parse::<u64>().ok();
    if v["txid"].as_str() != Some(p.txid.as_str())
        || !(amount.is_some() && amount == expected_amount || p.self_transfer && amount == Some(0))
        || v["fee"].as_u64().map(|n| n.to_string()) != Some(p.fee_atomic.clone())
        || v["double_spend_seen"] != false
        || v["unlock_time"].as_u64() != Some(0)
    {
        return Err("Outgoing transaction evidence did not match.");
    }
    let destinations = v["destinations"]
        .as_array()
        .ok_or("Missing outgoing destination.")?;
    if destinations.len() != 1
        || destinations[0]["address"].as_str() != Some(p.address.as_str())
        || destinations[0]["amount"].as_u64().map(|n| n.to_string())
            != Some(p.amount_atomic.clone())
    {
        return Err("Outgoing destination did not match.");
    }
    let confirmations = match v.get("confirmations") {
        None => 0,
        Some(n) => n.as_u64().ok_or("Invalid confirmation count.")?,
    };
    match v["type"].as_str() {
        Some("pending") => Ok(("Pending", 0)),
        Some("out") if v["height"].as_u64().is_some_and(|h| h > 0) && confirmations > 0 => {
            Ok(("Confirmed", confirmations))
        }
        Some("failed") => Ok(("Needs review", 0)),
        _ => Err("Outgoing outcome is not established."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn cleanup(root: &std::path::Path) {
        let resolved = fs::canonicalize(root).unwrap();
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        assert_eq!(resolved.parent(), Some(parent.as_path()));
        assert!(resolved
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("autopilot-send-test-"));
        fs::remove_dir_all(resolved).unwrap();
    }
    #[tokio::test]
    async fn pin_authorized_relay_survives_lock_and_lost_response_without_second_relay() {
        use crate::security::{Security, SecurityCommand};
        use axum::{
            extract::State,
            http::{HeaderMap, StatusCode},
            response::{IntoResponse, Response},
            routing::post,
            Json, Router,
        };
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        #[derive(Clone)]
        struct Fake {
            root: PathBuf,
            security: Security,
            relays: Arc<AtomicUsize>,
            prepares: Arc<AtomicUsize>,
        }
        async fn handler(
            State(s): State<Fake>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> Response {
            if !headers.contains_key("authorization") {
                return (StatusCode::UNAUTHORIZED,[("www-authenticate","Digest realm=\"test\", nonce=\"abcdef1234567890\", qop=\"auth\", algorithm=MD5")],"").into_response();
            }
            let result = match body["method"].as_str().unwrap() {
                "validate_address" => json!({"valid":true,"nettype":"stagenet","integrated":false}),
                "get_address" => {
                    json!({"addresses":[{"address":"5".repeat(95),"address_index":0}]})
                }
                "transfer" => {
                    assert_eq!(body["params"]["do_not_relay"], true);
                    assert_eq!(body["params"]["get_tx_key"], false);
                    assert_eq!(body["params"]["unlock_time"], 0);
                    s.prepares.fetch_add(1, Ordering::SeqCst);
                    json!({"amount":100,"fee":10,"tx_hash":"c".repeat(64),"tx_metadata":"deadbeef"})
                }
                "relay_tx" => {
                    assert!(fs::read_dir(&s.root).unwrap().any(|p| p
                        .unwrap()
                        .path()
                        .extension()
                        .is_some_and(|e| e == "attempt")));
                    s.relays.fetch_add(1, Ordering::SeqCst);
                    // Lock remains responsive after the committed attempt. This
                    // already-authorized transfer still reconciles exactly once.
                    s.security.lock().await;
                    return "deliberately lost success response".into_response();
                }
                "get_transfers" => {
                    assert_eq!(body["params"]["pool"], false);
                    assert_eq!(body["params"]["out"], true);
                    json!({"pending":[{"txid":"c".repeat(64),"amount":100,"fee":10,"double_spend_seen":false,"unlock_time":0,"destinations":[{"address":"7".repeat(95),"amount":100}],"type":"pending","height":0}]})
                }
                "store" => json!({}),
                _ => panic!("Unexpected RPC call"),
            };
            Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response()
        }
        let root =
            std::env::temp_dir().join(format!("autopilot-send-test-{}", uuid::Uuid::new_v4()));
        let security = Security::open(root.join("security")).await.unwrap();
        let session = security
            .execute(
                SecurityCommand::Configure {
                    pin: "824619".into(),
                    confirm_pin: "824619".into(),
                },
                None,
            )
            .await
            .unwrap()
            .session
            .clone()
            .unwrap();
        let epoch = Some(security.permit(Some(&session)).await.unwrap());
        let fake = Fake {
            root: root.join("payments"),
            security: security.clone(),
            relays: Arc::new(AtomicUsize::new(0)),
            prepares: Arc::new(AtomicUsize::new(0)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc = Rpc::new(listener.local_addr().unwrap(), "test".into(), "test".into()).unwrap();
        let router = Router::new()
            .route("/json_rpc", post(handler))
            .with_state(fake.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let mut sender = Sender::open(root.join("payments"));
        let wallet = "a".repeat(64);
        sender
            .prepare(&rpc, &wallet, &"7".repeat(95), "0.0000000001", 1000, 1)
            .await
            .unwrap();
        assert_eq!(fake.relays.load(Ordering::SeqCst), 0);
        let id = sender.snapshot.payments[0].id.clone();
        assert!(security
            .authorize_payment(epoch, None, &wallet, &id)
            .await
            .is_err());
        assert!(security
            .authorize_payment(epoch, Some(&"999999".into()), &wallet, &id)
            .await
            .is_err());
        assert!(!sender.marker(&id, "attempt").exists());
        assert_eq!(fake.relays.load(Ordering::SeqCst), 0);
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let mismatched = security
            .authorize_payment(epoch, Some(&"824619".into()), &wallet, "another-preview")
            .await
            .unwrap();
        assert!(sender
            .confirm_authorized(&rpc, &wallet, &id, 1000, 2, Some(mismatched))
            .await
            .is_err());
        assert!(!sender.marker(&id, "attempt").exists());
        let authorization = security
            .authorize_payment(epoch, Some(&"824619".into()), &wallet, &id)
            .await
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sender.confirm_authorized(&rpc, &wallet, &id, 1000, 2, Some(authorization)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(security.permit(Some(&session)).await.is_err());
        assert_eq!(sender.snapshot.payments[0].status, "Checking outcome");
        let mut reopened = Sender::open(root.join("payments"));
        assert!(reopened.confirm(&rpc, &wallet, &id, 1000, 3).await.is_err());
        reopened.reconcile(&rpc, &wallet, 4).await.unwrap();
        assert_eq!(reopened.snapshot.payments[0].status, "Pending");
        assert!(reopened
            .prepare(&rpc, &wallet, &"7".repeat(95), "0.0000000001", 1000, 5)
            .await
            .is_err());
        assert_eq!(fake.prepares.load(Ordering::SeqCst), 1);
        assert_eq!(fake.relays.load(Ordering::SeqCst), 1);
        server.abort();
        cleanup(&root);
    }
    #[test]
    fn exact_amount_validation() {
        assert_eq!(parse_amount("0.000000000001"), Ok(1));
        assert_eq!(parse_amount("0.001"), Ok(1_000_000_000));
        for v in [
            "0",
            "-1",
            "1e-3",
            "NaN",
            "0.0000000000001",
            ".1",
            "0.1",
            "1.",
            " 0.001",
        ] {
            assert!(parse_amount(v).is_err(), "{v}");
        }
    }
    fn record() -> Record {
        Record {
            schema: 1,
            network: "stagenet".into(),
            wallet_identity: "a".repeat(64),
            metadata: "deadbeef".into(),
            payment: Payment {
                id: "b".repeat(32),
                address: "7".repeat(95),
                priority: TransferPriority::Automatic,
                amount_atomic: "100".into(),
                fee_atomic: "10".into(),
                total_atomic: "110".into(),
                txid: "c".repeat(64),
                created_at: 1,
                expires_at: 121,
                self_transfer: false,
                status: "Preview".into(),
                confirmations: 0,
                checked_at: None,
            },
        }
    }
    pub(super) fn journal() -> Sender {
        journal_for(Network::Stagenet)
    }
    pub(super) fn journal_for(network: Network) -> Sender {
        let root =
            std::env::temp_dir().join(format!("autopilot-send-test-{}", uuid::Uuid::new_v4()));
        let mut s = Sender::open_for(root, network);
        let mut r = record();
        r.network = network.as_str().into();
        if network == Network::Mainnet {
            r.payment.address = "8".repeat(95);
        }
        durable(
            &s.marker(&r.payment.id, "dpapi"),
            &platform::protect(&serde_json::to_vec(&r).unwrap()).unwrap(),
        )
        .unwrap();
        s.records.push(r);
        s.project();
        s
    }
    #[test]
    fn restart_discards_unconfirmed_preview() {
        let s = journal();
        let restored = Sender::open(s.root.clone());
        assert_eq!(restored.snapshot.payments[0].status, "Cancelled");
        assert!(!restored.snapshot.blocked);
        assert!(!fs::read(s.marker(&"b".repeat(32), "dpapi"))
            .unwrap()
            .windows(8)
            .any(|v| v == b"deadbeef"));
        cleanup(&s.root);
    }
    #[test]
    fn durable_attempt_survives_restart_and_cannot_repeat() {
        let s = journal();
        durable(&s.marker(&"b".repeat(32), "attempt"), b"attempt").unwrap();
        assert!(durable(&s.marker(&"b".repeat(32), "attempt"), b"again").is_err());
        let mut restored = Sender::open(s.root.clone());
        assert!(restored.snapshot.blocked);
        assert_eq!(restored.snapshot.payments[0].status, "Checking outcome");
        assert!(restored.cancel(&"b".repeat(32)).is_err());
        cleanup(&s.root);
    }
    #[test]
    fn damaged_journal_fails_closed() {
        let s = journal();
        fs::write(s.marker(&"b".repeat(32), "dpapi"), b"partial").unwrap();
        assert!(Sender::open(s.root.clone()).snapshot.blocked);
        cleanup(&s.root);
    }
    #[test]
    fn expired_preview_cannot_be_used() {
        let mut s = journal();
        s.expire(121).unwrap();
        assert_eq!(s.snapshot.payments[0].status, "Cancelled");
        cleanup(&s.root);
    }
    #[test]
    fn outgoing_evidence_requires_exact_payment() {
        let r = record();
        let mut v = json!({"transfer":{"txid":r.payment.txid,"amount":100,"fee":10,"double_spend_seen":false,"unlock_time":0,"destinations":[{"address":r.payment.address,"amount":100}],"type":"out","height":10,"confirmations":1}});
        assert_eq!(parse_outgoing(&v, &r.payment), Ok(("Confirmed", 1)));
        v["transfer"]["amount"] = json!(101);
        assert!(parse_outgoing(&v, &r.payment).is_err());
    }
}
