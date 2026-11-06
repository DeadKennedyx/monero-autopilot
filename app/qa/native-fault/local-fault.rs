// QA overlay template only. This file is never included in the product build.
// The preparer substitutes an isolated absolute run directory into the copy.
const QA_FAULT_ROOT: &str = "__QA_ROOT__";

fn qa_fault_before(path: DaemonPath) -> Result<bool> {
    qa_claim(std::path::Path::new(QA_FAULT_ROOT), path.as_str())
}
fn qa_claim(root: &std::path::Path, path: &str) -> Result<bool> {
    if root.join("offline").exists() {
        return Err(Denial::TransportFailure);
    }
    if !matches!(path, "/sendrawtransaction" | "/send_raw_transaction") {
        return Ok(false);
    }
    if std::fs::read(root.join("local-mode")).ok().as_deref() != Some(b"drop-next") {
        return Err(Denial::PathForbidden);
    }
    // This durable exclusive claim precedes any upstream I/O. No reset/retry.
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
        .open(root.join("broadcast-claimed")).map_err(|_| Denial::PathForbidden)?;
    file.write_all(b"1").and_then(|_| file.sync_all()).map_err(|_| Denial::TransportFailure)?;
    Ok(true)
}
fn qa_fault_after(drop_reply: bool, bytes: &[u8]) -> Result<()> {
    qa_record_reply(std::path::Path::new(QA_FAULT_ROOT), drop_reply, bytes)
}
fn qa_record_reply(root: &std::path::Path, drop_reply: bool, bytes: &[u8]) -> Result<()> {
    if !drop_reply { return Ok(()); }
    let accepted = serde_json::from_slice::<serde_json::Value>(bytes).ok().is_some_and(|v| {
        v["status"] == "OK" && v.get("error").is_none()
            && v.get("not_relayed").is_none_or(|v| v == false)
            && v.get("double_spend").is_none_or(|v| v == false)
    });
    if !accepted { return Ok(()); }
    use std::io::Write;
    let evidence = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
            .open(root.join("accepted-reply-suppressed"))?;
        file.write_all(b"1")?;
        file.sync_all()
    })();
    eprintln!("QA_FAULT accepted_reply_suppressed evidence_saved={}", evidence.is_ok());
    // The real node accepted. Suppress only that success reply; the gateway
    // reports unavailable to Monero. Signed bytes and route stay unchanged.
    Err(Denial::TransportFailure)
}

#[cfg(test)]
mod qa_local_fault_tests {
    use super::*;
    #[test]
    fn budget_is_durable_and_only_success_is_suppressed() {
        let root = std::env::temp_dir().join(format!("autopilot-qa-fault-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        assert_eq!(qa_claim(&root, "/json_rpc"), Ok(false));
        assert_eq!(qa_claim(&root, "/sendrawtransaction"), Err(Denial::PathForbidden));
        std::fs::write(root.join("local-mode"), b"drop-next").unwrap();
        assert_eq!(qa_claim(&root, "/sendrawtransaction"), Ok(true));
        assert_eq!(qa_claim(&root, "/sendrawtransaction"), Err(Denial::PathForbidden));
        for reply in [br#"{"status":"FAILED"}"#.as_slice(), br#"{"status":"OK","not_relayed":true}"#,
            br#"{"status":"OK","double_spend":true}"#, br#"{"status":"OK","error":{}}"#] {
            assert_eq!(qa_record_reply(&root, true, reply), Ok(()));
            assert!(!root.join("accepted-reply-suppressed").exists());
        }
        assert_eq!(qa_record_reply(&root, true, br#"{"status":"OK","not_relayed":false,"double_spend":false}"#), Err(Denial::TransportFailure));
        assert!(root.join("accepted-reply-suppressed").exists());
        std::fs::write(root.join("offline"), b"1").unwrap();
        assert_eq!(qa_claim(&root, "/json_rpc"), Err(Denial::TransportFailure));
        assert_eq!(qa_claim(&root, "/sendrawtransaction"), Err(Denial::TransportFailure));
        // All test files remain in this unique temporary directory for evidence.
    }
}
