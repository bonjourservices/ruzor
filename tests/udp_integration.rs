use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use pyzor::client::Client;
use pyzor::config::Address;
use pyzor::engines::FileDatabase;
use pyzor::serve_socket_until_shutdown;

#[test]
fn rust_client_talks_to_rust_udp_server() {
    let digest = "7421216f915a87e02da034cc483f5c876e1a1338";
    let path = temp_db_path("rust-client-rust-server");
    let db = Arc::new(Mutex::new(FileDatabase::open(&path).unwrap()));
    let accounts = Arc::new(HashMap::new());
    let acl = Arc::new(acl(&[
        "report",
        "check",
        "whitelist",
        "info",
        "ping",
        "pong",
    ]));
    let shutdown = Arc::new(AtomicBool::new(false));
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address: Address = ("127.0.0.1".to_string(), socket.local_addr().unwrap().port());
    let server_shutdown = Arc::clone(&shutdown);
    let handle = thread::spawn(move || {
        serve_socket_until_shutdown(socket, db, accounts, acl, false, server_shutdown)
    });

    let client = Client::new(HashMap::new(), Some(2), pyzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.ping(&address).unwrap().is_ok());
    assert!(client.report(digest, &address).unwrap().is_ok());

    let response = client.check(digest, &address).unwrap();
    assert_eq!(response.get("Count"), Some("1"));
    assert_eq!(response.get("WL-Count"), Some("0"));

    assert!(client.whitelist(digest, &address).unwrap().is_ok());
    let response = client.check(digest, &address).unwrap();
    assert_eq!(response.get("Count"), Some("1"));
    assert_eq!(response.get("WL-Count"), Some("1"));

    shutdown.store(true, Ordering::Relaxed);
    handle.join().unwrap().unwrap();
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

fn temp_db_path(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("pyzor-{name}-{}-{nanos}.db", std::process::id()))
}
