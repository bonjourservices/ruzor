use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use pyzor::engines::FileDatabase;
use pyzor::server::handle_packet;

#[test]
fn report_and_check_round_trip_through_handler() {
    let digest = "7421216f915a87e02da034cc483f5c876e1a1338";
    let path = std::env::temp_dir().join(format!(
        "pyzor-server-protocol-{}-{}.db",
        std::process::id(),
        pyzor::account::now_timestamp()
    ));
    let db = Arc::new(Mutex::new(FileDatabase::open(&path).unwrap()));
    let accounts = HashMap::new();
    let acl = acl(&["report", "check", "whitelist", "info", "ping", "pong"]);

    let report = format!(
        "Op: report\nThread: 2000\nPV: 2.1\nOp-Digest: {}\nUser: anonymous\n\n",
        digest
    );
    let response = handle_packet(report.as_bytes(), &db, &accounts, &acl);
    assert_eq!(response.get("Code"), Some("200"));

    let check = format!(
        "Op: check\nThread: 2001\nPV: 2.1\nOp-Digest: {}\nUser: anonymous\n\n",
        digest
    );
    let response = handle_packet(check.as_bytes(), &db, &accounts, &acl);
    assert_eq!(response.get("Code"), Some("200"));
    assert_eq!(response.get("Count"), Some("1"));
    assert_eq!(response.get("WL-Count"), Some("0"));

    let whitelist = format!(
        "Op: whitelist\nThread: 2002\nPV: 2.1\nOp-Digest: {}\nUser: anonymous\n\n",
        digest
    );
    let response = handle_packet(whitelist.as_bytes(), &db, &accounts, &acl);
    assert_eq!(response.get("Code"), Some("200"));

    let response = handle_packet(check.as_bytes(), &db, &accounts, &acl);
    assert_eq!(response.get("Count"), Some("1"));
    assert_eq!(response.get("WL-Count"), Some("1"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn default_acl_denies_whitelist() {
    let path = std::env::temp_dir().join(format!(
        "pyzor-server-protocol-deny-{}-{}.db",
        std::process::id(),
        pyzor::account::now_timestamp()
    ));
    let db = Arc::new(Mutex::new(FileDatabase::open(&path).unwrap()));
    let accounts = HashMap::new();
    let mut acl = HashMap::new();
    acl.insert(
        "anonymous".to_string(),
        HashSet::from([
            "check".to_string(),
            "report".to_string(),
            "ping".to_string(),
            "pong".to_string(),
            "info".to_string(),
        ]),
    );
    let response = handle_packet(
        b"Op: whitelist\nThread: 3000\nPV: 2.1\nOp-Digest: abc\nUser: anonymous\n\n",
        &db,
        &accounts,
        &acl,
    );
    assert_eq!(response.get("Code"), Some("403"));
    assert!(response.get("Diag").unwrap_or("").starts_with("Forbidden:"));
    let _ = std::fs::remove_file(path);
}

fn acl(ops: &[&str]) -> HashMap<String, HashSet<String>> {
    let mut acl = HashMap::new();
    acl.insert(
        "anonymous".to_string(),
        ops.iter().map(|op| (*op).to_string()).collect(),
    );
    acl
}
