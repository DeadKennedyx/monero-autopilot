//! Receive-only projection of the official wallet. Amounts cross JSON as decimal
//! strings so JavaScript cannot round atomic units. No signing or relay methods.
use autopilot_wallet_lab::{rpc::Rpc, LabResult};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;

#[derive(Clone, Default, Serialize)]
pub struct ReceiveSnapshot {
    pub address: Option<String>,
    pub address_index: Option<u32>,
    pub balance: Option<Balance>,
    pub current: bool,
    pub error: Option<String>,
}
#[derive(Clone, Serialize)]
pub struct Balance {
    pub confirmed_atomic: String,
    pub spendable_atomic: String,
    /// Confirmed funds currently unavailable, including pending-spent inputs
    /// when the mainnet confirmed-balance reader is used.
    pub locked_atomic: String,
    /// None when only the locally cached, confirmed balance was requested.
    pub pending_atomic: Option<String>,
    pub blocks_to_unlock: u64,
    pub sampled_at: u64,
    pub wallet_height: u64,
    pub receipts: Vec<Receipt>,
    pub receipt_count: usize,
}
#[derive(Clone, Serialize)]
pub struct Receipt {
    pub txid: String,
    pub address_index: u32,
    pub amount_atomic: String,
    pub confirmations: u64,
    pub height: u64,
    pub timestamp: u64,
    pub status: &'static str,
}
fn uint(value: &Value, field: &str) -> LabResult<u64> {
    value[field]
        .as_u64()
        .ok_or("The wallet returned an invalid numeric field.")
}
pub fn parse_balance(
    balance: &Value,
    transfers: &Value,
    height: u64,
    time: u64,
) -> LabResult<Balance> {
    let total = uint(balance, "balance")?;
    let spendable = uint(balance, "unlocked_balance")?;
    let locked = total
        .checked_sub(spendable)
        .ok_or("Spendable balance exceeded confirmed balance.")?;
    if balance["multisig_import_needed"].as_bool() != Some(false) {
        return Err("The wallet requires multisig information; balance is not ready.");
    }
    let mut receipts = vec![];
    let mut seen = HashSet::new();
    let mut pending = 0_u64;
    for kind in ["in", "pool"] {
        let entries = match transfers.get(kind) {
            None => continue,
            Some(value) => value
                .as_array()
                .ok_or("Incoming transfer list is invalid.")?,
        };
        if entries.len() > 500 {
            return Err("This prototype supports up to 500 incoming entries per response.");
        }
        for entry in entries {
            let txid = entry["txid"]
                .as_str()
                .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or("Invalid incoming transaction identifier.")?;
            if entry["type"].as_str() != Some(kind) || uint(&entry["subaddr_index"], "major")? != 0
            {
                return Err("Incoming transfer belongs to an unexpected account or category.");
            }
            let index = u32::try_from(uint(&entry["subaddr_index"], "minor")?)
                .map_err(|_| "Invalid receiving address index.")?;
            // Multiple subaddresses in one transaction legitimately produce
            // multiple records. Only duplicate (transaction, subaddress) pairs
            // are invalid; do not deduplicate by txid alone.
            if !seen.insert((txid.to_owned(), index)) {
                return Err("Duplicate incoming transfer detected.");
            }
            let amount = uint(entry, "amount")?;
            let block = uint(entry, "height")?;
            // Monero 0.18.5.4 declares this as KV_SERIALIZE_OPT(..., 0).
            // Zero confirmations may therefore be omitted for pool entries.
            let confirmations = if entry.get("confirmations").is_none() {
                0
            } else {
                uint(entry, "confirmations")?
            };
            let conflict = entry["double_spend_seen"]
                .as_bool()
                .ok_or("Missing incoming transfer safety status.")?;
            let is_locked = entry["locked"]
                .as_bool()
                .ok_or("Missing incoming transfer lock status.")?;
            let status = if kind == "pool" {
                if block != 0 {
                    return Err("An unconfirmed receipt had a block height.");
                }
                if conflict {
                    "Needs review"
                } else {
                    pending = pending
                        .checked_add(amount)
                        .ok_or("Pending amount overflow.")?;
                    "Pending"
                }
            } else {
                if block == 0 || block >= height || confirmations == 0 {
                    return Err("Confirmed receipt is inconsistent with the wallet height.");
                }
                if conflict {
                    "Needs review"
                } else if is_locked {
                    "Confirmed · locked"
                } else {
                    "Confirmed · unlocked"
                }
            };
            receipts.push(Receipt {
                txid: txid.into(),
                address_index: index,
                amount_atomic: amount.to_string(),
                confirmations: if kind == "pool" { 0 } else { confirmations },
                height: block,
                timestamp: uint(entry, "timestamp")?,
                status,
            });
        }
    }
    receipts.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then(a.txid.cmp(&b.txid))
            .then(a.address_index.cmp(&b.address_index))
    });
    let receipt_count = receipts.len();
    receipts.truncate(50);
    Ok(Balance {
        confirmed_atomic: total.to_string(),
        spendable_atomic: spendable.to_string(),
        locked_atomic: locked.to_string(),
        pending_atomic: Some(pending.to_string()),
        blocks_to_unlock: uint(balance, "blocks_to_unlock")?,
        sampled_at: time,
        wallet_height: height,
        receipts,
        receipt_count,
    })
}
pub fn is_current(
    ready: bool,
    node: Option<u64>,
    wallet: Option<u64>,
    node_sample: Option<u64>,
    wallet_sample: Option<u64>,
    data: &ReceiveSnapshot,
    now: u64,
) -> bool {
    let fresh = |t: Option<u64>| t.is_some_and(|t| t <= now && now - t <= 15);
    ready
        && data.error.is_none()
        && node_sample
            .is_some_and(|t| t <= now && now - t <= autopilot_privacy::NODE_HEALTH_FRESH_SECS)
        && fresh(wallet_sample)
        && data.balance.as_ref().is_some_and(|b| {
            fresh(Some(b.sampled_at))
                && node.is_some_and(|n| b.wallet_height >= n)
                && wallet.is_some_and(|w| b.wallet_height == w)
        })
}
pub async fn read_address(rpc: &Rpc) -> LabResult<(String, u32)> {
    read_address_for(rpc, autopilot_privacy::config::Network::Stagenet).await
}
pub async fn read_address_for(
    rpc: &Rpc,
    network: autopilot_privacy::config::Network,
) -> LabResult<(String, u32)> {
    let data = rpc
        .call("get_address", json!({"account_index":0}), 5)
        .await?;
    let addresses = data["addresses"]
        .as_array()
        .ok_or("Receiving addresses are unavailable.")?;
    let latest = addresses
        .iter()
        .max_by_key(|a| a["address_index"].as_u64())
        .ok_or("No receiving address was returned.")?;
    let index = u32::try_from(uint(latest, "address_index")?)
        .map_err(|_| "Invalid receiving address index.")?;
    let address = latest["address"]
        .as_str()
        .filter(|s| s.len() == 95)
        .ok_or("Invalid receiving address.")?;
    let check = rpc
        .call(
            "validate_address",
            json!({"address":address,"any_net_type":false,"allow_openalias":false}),
            5,
        )
        .await?;
    if check["valid"] != true
        || check["nettype"] != network.as_str()
        || check["integrated"] != false
    {
        return Err("The backend did not validate a receiving address for this network.");
    }
    Ok((address.into(), index))
}
pub async fn read_balance(rpc: &Rpc, now: u64) -> LabResult<Balance> {
    read_balance_inner(rpc, now, true).await
}
pub async fn read_confirmed_balance(rpc: &Rpc, now: u64) -> LabResult<Balance> {
    read_balance_inner(rpc, now, false).await
}
fn parse_confirmed_balance(
    confirmed: &Value,
    available: &Value,
    transfers: &Value,
    height: u64,
    time: u64,
) -> LabResult<Balance> {
    let mut result = parse_balance(confirmed, transfers, height, time)?;
    let available_total = uint(available, "balance")?;
    let available_unlocked = uint(available, "unlocked_balance")?;
    if available_unlocked > available_total {
        return Err("Available balance exceeded the wallet balance.");
    }
    if available["multisig_import_needed"].as_bool() != Some(false) {
        return Err("The wallet requires multisig information; balance is not ready.");
    }
    // Native strict=true retains inputs whose spend is still unconfirmed.
    // strict=false excludes those inputs from unlocked_balance; its total also
    // includes pending change/receipts, so that total must never be displayed
    // as confirmed money. Both values come directly from the local wallet.
    let spendable = uint(confirmed, "unlocked_balance")?.min(available_unlocked);
    let unavailable = uint(confirmed, "balance")?
        .checked_sub(spendable)
        .ok_or("Spendable balance exceeded confirmed balance.")?;
    result.spendable_atomic = spendable.to_string();
    result.locked_atomic = unavailable.to_string();
    result.blocks_to_unlock = uint(available, "blocks_to_unlock")?;
    result.pending_atomic = None;
    Ok(result)
}
async fn read_balance_inner(rpc: &Rpc, now: u64, pool: bool) -> LabResult<Balance> {
    let started = std::time::Instant::now();
    let before = uint(&rpc.call("get_height", json!({}), 3).await?, "height")?;
    // pool=true forces an upstream network refresh in official wallet RPC.
    // Mainnet polls local confirmed funds; native background refresh supplies
    // network evidence and unobserved incoming pool totals remain unknown.
    let transfers = rpc.call("get_transfers", json!({"in":true,"pool":pool,"out":false,"pending":false,"failed":false,"account_index":0}), 8).await?;
    let balance = rpc
        .call("get_balance", json!({"account_index":0,"strict":true}), 5)
        .await?;
    // Mainnet availability must exclude inputs already used by pending sends.
    // get_balance is a local read; this adds no daemon/pool network request.
    let available = if !pool {
        Some(
            rpc.call("get_balance", json!({"account_index":0,"strict":false}), 5)
                .await?,
        )
    } else {
        None
    };
    let after = uint(&rpc.call("get_height", json!({}), 3).await?, "height")?;
    if before != after {
        return Err("The wallet advanced while reading balances; checking again shortly.");
    }
    let sampled_at = now.saturating_add(started.elapsed().as_secs());
    match available {
        Some(available) => {
            parse_confirmed_balance(&balance, &available, &transfers, after, sampled_at)
        }
        None => parse_balance(&balance, &transfers, after, sampled_at),
    }
}

#[cfg(test)]
#[path = "receive_balance_tests.rs"]
mod balance_tests;

#[cfg(test)]
mod tests {
    use super::*;
    fn funds() -> Value {
        json!({"balance":9007199254740993_u64,"unlocked_balance":1000000000000_u64,"blocks_to_unlock":8,"multisig_import_needed":false})
    }
    fn receipt(kind: &str, minor: u32, amount: u64) -> Value {
        json!({"txid":"a".repeat(64),"type":kind,"subaddr_index":{"major":0,"minor":minor},"amount":amount,"height":if kind == "pool" {0}else{90},"confirmations":if kind == "pool" {0}else{10},"locked":true,"double_spend_seen":false,"timestamp":100})
    }
    #[test]
    fn exact_amounts_and_pending_are_separate() {
        let b = parse_balance(
            &funds(),
            &json!({"in":[receipt("in",0,100)],"pool":[receipt("pool",1,123)]}),
            100,
            120,
        )
        .unwrap();
        assert_eq!(b.confirmed_atomic, "9007199254740993");
        assert_eq!(b.locked_atomic, "9006199254740993");
        assert_eq!(b.pending_atomic.as_deref(), Some("123"));
        assert_eq!(b.receipts[0].status, "Confirmed · locked");
    }
    #[test]
    fn rejects_bad_balance_and_duplicate_but_accepts_multiple_subaddresses() {
        let mut v = funds();
        v["unlocked_balance"] = json!(u64::MAX);
        assert!(parse_balance(&v, &json!({}), 100, 120).is_err());
        let a = receipt("in", 0, 100);
        assert!(parse_balance(&funds(), &json!({"in":[a.clone(),a]}), 100, 120).is_err());
        assert_eq!(
            parse_balance(
                &funds(),
                &json!({"in":[receipt("in",0,100),receipt("in",1,200)]}),
                100,
                120
            )
            .unwrap()
            .receipts
            .len(),
            2
        );
    }
    #[test]
    fn pending_conflicts_never_count_as_pending_money_and_lock_is_backend_driven() {
        let mut conflict = receipt("pool", 0, 10);
        conflict["double_spend_seen"] = json!(true);
        let mut unlocked = receipt("in", 1, 10);
        unlocked["locked"] = json!(false);
        let b = parse_balance(
            &funds(),
            &json!({"pool":[conflict],"in":[unlocked]}),
            100,
            120,
        )
        .unwrap();
        assert_eq!(b.pending_atomic.as_deref(), Some("0"));
        assert!(b.receipts.iter().any(|r| r.status == "Needs review"));
        assert!(b
            .receipts
            .iter()
            .any(|r| r.status == "Confirmed · unlocked"));
    }
    #[test]
    fn stale_unsynced_and_offline_balances_are_never_current() {
        let data = ReceiveSnapshot {
            balance: Some(parse_balance(&funds(), &json!({}), 100, 120).unwrap()),
            ..Default::default()
        };
        let current = |connected, synced, node, now| {
            is_current(
                connected && synced,
                Some(node),
                Some(100),
                Some(120),
                Some(120),
                &data,
                now,
            )
        };
        assert!(current(true, true, 100, 120));
        assert!(!current(false, true, 100, 120));
        assert!(!current(true, false, 100, 120));
        assert!(!current(true, true, 101, 120));
        assert!(!current(true, true, 100, 136));
        // A still-valid Tor node observation does not extend the shorter
        // wallet/balance window. Both boundaries remain independently checked.
        assert!(is_current(
            true,
            Some(100),
            Some(100),
            Some(80),
            Some(120),
            &data,
            120
        ));
        assert!(!is_current(
            true,
            Some(100),
            Some(100),
            Some(59),
            Some(120),
            &data,
            120
        ));
    }
    #[test]
    fn zero_confirmations_may_be_omitted_but_nonzero_values_must_be_valid() {
        let mut entry = receipt("pool", 0, 10);
        entry.as_object_mut().unwrap().remove("confirmations");
        assert_eq!(
            parse_balance(&funds(), &json!({"pool":[entry.clone()]}), 100, 120)
                .unwrap()
                .pending_atomic
                .as_deref(),
            Some("10")
        );
        entry["confirmations"] = json!("not a number");
        assert!(parse_balance(&funds(), &json!({"pool":[entry]}), 100, 120).is_err());
    }
    #[test]
    fn invalid_and_overflowing_receipts_fail_closed() {
        assert!(parse_balance(&funds(), &json!({"in":[receipt("in",0,10)]}), 90, 120).is_err());
        assert!(parse_balance(
            &funds(),
            &json!({"pool":[receipt("pool",0,u64::MAX),receipt("pool",1,1)]}),
            100,
            120
        )
        .is_err());
        let mut missing = receipt("in", 0, 10);
        missing.as_object_mut().unwrap().remove("locked");
        assert!(parse_balance(&funds(), &json!({"in":[missing]}), 100, 120).is_err());
    }
}
