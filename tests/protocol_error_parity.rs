use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use pyzor::engines::FileDatabase;
use pyzor::server::handle_packet;

#[test]
fn unsupported_version_diagnostic_matches_python_server() {
    let db = test_db("unsupported-version");
    let accounts = HashMap::new();
    let acl = acl(&["ping"]);

    let response = handle_packet(
        b"Op: ping\nThread: 4000\nPV: 3.1\nUser: anonymous\n\n",
        &db,
        &accounts,
        &acl,
    );

    assert_eq!(response.get("Code"), Some("505"));
    assert_eq!(response.get("Diag"), Some("Version Not Supported: "));
    assert_eq!(response.get("Thread"), Some("4000"));
}

#[test]
fn unsupported_operation_diagnostic_matches_python_server() {
    let db = test_db("unsupported-op");
    let accounts = HashMap::new();
    let acl = acl(&["bogus"]);

    let response = handle_packet(
        b"Op: bogus\nThread: 4001\nPV: 2.1\nUser: anonymous\n\n",
        &db,
        &accounts,
        &acl,
    );

    assert_eq!(response.get("Code"), Some("501"));
    assert_eq!(
        response.get("Diag"),
        Some("Not implemented: Requested operation is not implemented.")
    );
    assert_eq!(response.get("Thread"), Some("4001"));
}

#[test]
fn missing_operation_is_forbidden_like_python_server() {
    let db = test_db("missing-op");
    let accounts = HashMap::new();
    let acl = acl(&["ping"]);

    let response = handle_packet(
        b"Thread: 4002\nPV: 2.1\nUser: anonymous\n\n",
        &db,
        &accounts,
        &acl,
    );

    assert_eq!(response.get("Code"), Some("403"));
    assert_eq!(
        response.get("Diag"),
        Some("Forbidden: User is not authorized to request the operation.")
    );
    assert_eq!(response.get("Thread"), Some("4002"));
}

#[test]
fn invalid_protocol_version_diagnostic_matches_python_server() {
    let db = test_db("invalid-pv");
    let accounts = HashMap::new();
    let acl = acl(&["ping"]);

    let response = handle_packet(
        b"Op: ping\nThread: 4003\nPV: invalid\nUser: anonymous\n\n",
        &db,
        &accounts,
        &acl,
    );

    assert_eq!(response.get("Code"), Some("400"));
    assert_eq!(
        response.get("Diag"),
        Some("Bad request: Invalid Protocol Version")
    );
    assert_eq!(response.get("Thread"), Some("4003"));
}

fn test_db(name: &str) -> Arc<Mutex<FileDatabase>> {
    let path = std::env::temp_dir().join(format!(
        "pyzor-protocol-error-{name}-{}",
        std::process::id()
    ));
    Arc::new(Mutex::new(FileDatabase::open(path).unwrap()))
}

fn acl(ops: &[&str]) -> HashMap<String, HashSet<String>> {
    let mut acl = HashMap::new();
    acl.insert(
        "anonymous".to_string(),
        ops.iter().map(|op| (*op).to_string()).collect(),
    );
    acl
}
