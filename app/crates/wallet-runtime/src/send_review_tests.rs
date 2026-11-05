//! Native Monero self-transfer representation and strict outgoing evidence.
//! Synthetic fixtures only; these tests never construct or broadcast a payment.
use super::*;

fn payment(self_transfer: bool) -> Payment {
    Payment {
        id: "b".repeat(32),
        address: "8".repeat(95),
        priority: TransferPriority::Automatic,
        amount_atomic: "100".into(),
        fee_atomic: "10".into(),
        total_atomic: "110".into(),
        txid: "c".repeat(64),
        created_at: 1,
        expires_at: 121,
        self_transfer,
        status: "Pending".into(),
        confirmations: 0,
        checked_at: None,
    }
}

fn outgoing(p: &Payment, native_amount: u64) -> Value {
    json!({
        "txid":p.txid,"amount":native_amount,"fee":10,
        "double_spend_seen":false,"unlock_time":0,
        "destinations":[{"address":p.address,"amount":100}],
        "type":"out","height":10,"confirmations":1
    })
}

#[test]
fn same_account_self_transfer_accepts_native_zero_net_amount() {
    let p = payment(true);
    // Monero treats all same-account outputs as change after confirmation.
    // The destination still proves the requested transfer amount.
    assert_eq!(
        parse_outgoing(&json!({"transfers":[outgoing(&p, 0)]}), &p),
        Ok(("Confirmed", 1))
    );
    assert_eq!(
        parse_outgoing(&json!({"transfers":[outgoing(&p, 100)]}), &p),
        Ok(("Confirmed", 1))
    );
}

#[test]
fn external_payment_cannot_use_self_transfer_zero_normalization() {
    let p = payment(false);
    assert!(parse_outgoing(&json!({"transfers":[outgoing(&p, 0)]}), &p).is_err());
    assert_eq!(
        parse_outgoing(&json!({"transfers":[outgoing(&p, 100)]}), &p),
        Ok(("Confirmed", 1))
    );
}

#[test]
fn self_transfer_still_requires_exact_destination_fee_and_identity() {
    let p = payment(true);
    for (pointer, value) in [
        ("/destinations/0/address", json!("9".repeat(95))),
        ("/destinations/0/amount", json!(101)),
        ("/fee", json!(11)),
        ("/txid", json!("d".repeat(64))),
        ("/amount", json!(1)),
        ("/unlock_time", json!(1)),
        ("/double_spend_seen", json!(true)),
    ] {
        let mut candidate = outgoing(&p, 0);
        *candidate.pointer_mut(pointer).unwrap() = value;
        assert!(
            parse_outgoing(&json!({"transfers":[candidate]}), &p).is_err(),
            "Unexpected acceptance: {pointer}"
        );
    }
}

#[test]
fn outgoing_evidence_is_selected_instead_of_legacy_incoming_first_entry() {
    let p = payment(false);
    let incoming = json!({"txid":p.txid,"type":"in","amount":100,"height":10,"confirmations":1});
    let mut unrelated = outgoing(&p, 100);
    unrelated["txid"] = json!("d".repeat(64));
    let response = json!({"transfer":incoming,"transfers":[incoming,unrelated,outgoing(&p, 100)]});
    assert_eq!(parse_outgoing(&response, &p), Ok(("Confirmed", 1)));
}

#[test]
fn duplicate_or_conflicting_outgoing_candidates_are_ambiguous() {
    let p = payment(true);
    let confirmed = outgoing(&p, 0);
    let mut pending = outgoing(&p, 100);
    pending["type"] = json!("pending");
    pending["height"] = json!(0);
    pending["confirmations"] = json!(0);
    assert!(parse_outgoing(
        &json!({"transfers":[confirmed.clone(),confirmed.clone()]}),
        &p
    )
    .is_err());
    assert!(parse_outgoing(&json!({"transfers":[confirmed,pending]}), &p).is_err());
}

#[test]
fn present_transfers_field_cannot_fall_back_to_legacy_success() {
    let p = payment(false);
    for transfers in [json!([]), json!(null), json!({}), json!("invalid")] {
        assert!(parse_outgoing(
            &json!({"transfers":transfers,"transfer":outgoing(&p,100)}),
            &p
        )
        .is_err());
    }
    assert_eq!(
        parse_outgoing(&json!({"transfer":outgoing(&p,100)}), &p),
        Ok(("Confirmed", 1))
    );
}

#[test]
fn confirmation_requires_mined_height_and_nonzero_confirmations() {
    let p = payment(true);
    let mut no_height = outgoing(&p, 0);
    no_height["height"] = json!(0);
    assert!(parse_outgoing(&json!({"transfers":[no_height]}), &p).is_err());
    let mut no_confirmations = outgoing(&p, 0);
    no_confirmations["confirmations"] = json!(0);
    assert!(parse_outgoing(&json!({"transfers":[no_confirmations]}), &p).is_err());
}
