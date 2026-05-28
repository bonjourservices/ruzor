use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyzor::client::{BatchClient, Client};
use pyzor::config::Address;
use pyzor::engines::FileDatabase;
use pyzor::serve_socket_until_shutdown;

#[test]
fn batched_report_matches_python_functional_test() {
    let mut server = TestServer::start("batched-report");
    let digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    let client = test_client();
    let mut batch = BatchClient::new(client.clone(), 10);

    for _ in 0..9 {
        batch.report(digest, &server.address()).unwrap();
    }
    assert_digest_counts(&client, &server.address(), digest, (0, 0));

    batch.report(digest, &server.address()).unwrap();
    assert_digest_counts(&client, &server.address(), digest, (10, 0));

    server.stop();
}

#[test]
fn batched_whitelist_matches_python_functional_test() {
    let mut server = TestServer::start("batched-whitelist");
    let digest = "da39a3ee5e6b4b0d3255bfef95601890afd80708";
    let client = test_client();
    let mut batch = BatchClient::new(client.clone(), 10);

    for _ in 0..9 {
        batch.whitelist(digest, &server.address()).unwrap();
    }
    assert_digest_counts(&client, &server.address(), digest, (0, 0));

    batch.whitelist(digest, &server.address()).unwrap();
    assert_digest_counts(&client, &server.address(), digest, (0, 10));

    server.stop();
}

#[test]
fn batched_combined_report_and_whitelist_matches_python_functional_test() {
    let mut server = TestServer::start("batched-combined");
    let digest = "da39a3ee5e6b4b0d3255bfef95601890afd80707";
    let client = test_client();
    let mut batch = BatchClient::new(client.clone(), 10);

    for _ in 0..9 {
        batch.report(digest, &server.address()).unwrap();
        batch.whitelist(digest, &server.address()).unwrap();
    }
    assert_digest_counts(&client, &server.address(), digest, (0, 0));

    batch.report(digest, &server.address()).unwrap();
    assert_digest_counts(&client, &server.address(), digest, (10, 0));

    batch.whitelist(digest, &server.address()).unwrap();
    assert_digest_counts(&client, &server.address(), digest, (10, 10));

    server.stop();
}

#[test]
fn batched_multiple_report_digests_match_python_functional_test() {
    let mut server = TestServer::start("batched-multiple-report");
    let client = test_client();
    let mut batch = BatchClient::new(client.clone(), 10);
    let digests = numbered_digests("a39a3ee5e6b4b0d3255bfef95601890afd80706");

    for digest in &digests {
        batch.report(digest, &server.address()).unwrap();
    }

    for digest in &digests {
        assert_digest_counts(&client, &server.address(), digest, (1, 0));
    }

    server.stop();
}

#[test]
fn batched_multiple_whitelist_digests_match_python_functional_test() {
    let mut server = TestServer::start("batched-multiple-whitelist");
    let client = test_client();
    let mut batch = BatchClient::new(client.clone(), 10);
    let digests = numbered_digests("a39a3ee5e6b4b0d3255bfef95601890afd80705");

    for digest in &digests {
        batch.whitelist(digest, &server.address()).unwrap();
    }

    for digest in &digests {
        assert_digest_counts(&client, &server.address(), digest, (0, 1));
    }

    server.stop();
}

#[test]
fn batched_report_to_multiple_addresses_matches_python_functional_test() {
    let mut server1 = TestServer::start("batched-multi-address-report-1");
    let mut server2 = TestServer::start("batched-multi-address-report-2");
    let digest1 = "da39a3ee5e6b4b0d3255bfef95601890afd80704";
    let digest2 = "da39a3ee5e6b4b0d3255bfef95601890afd80703";
    let client = test_client();
    let mut batch = BatchClient::new(client.clone(), 10);

    for _ in 0..9 {
        batch.report(digest1, &server1.address()).unwrap();
        batch.report(digest2, &server2.address()).unwrap();
    }
    assert_digest_counts(&client, &server1.address(), digest1, (0, 0));
    assert_digest_counts(&client, &server2.address(), digest2, (0, 0));

    batch.report(digest1, &server1.address()).unwrap();
    assert_digest_counts(&client, &server1.address(), digest1, (10, 0));
    assert_digest_counts(&client, &server2.address(), digest2, (0, 0));

    batch.report(digest2, &server2.address()).unwrap();
    assert_digest_counts(&client, &server2.address(), digest2, (10, 0));

    server1.stop();
    server2.stop();
}

#[test]
fn batched_whitelist_to_multiple_addresses_matches_python_functional_test() {
    let mut server1 = TestServer::start("batched-multi-address-whitelist-1");
    let mut server2 = TestServer::start("batched-multi-address-whitelist-2");
    let digest1 = "da39a3ee5e6b4b0d3255bfef95601890afd80702";
    let digest2 = "da39a3ee5e6b4b0d3255bfef95601890afd80701";
    let client = test_client();
    let mut batch = BatchClient::new(client.clone(), 10);

    for _ in 0..9 {
        batch.whitelist(digest1, &server1.address()).unwrap();
        batch.whitelist(digest2, &server2.address()).unwrap();
    }
    assert_digest_counts(&client, &server1.address(), digest1, (0, 0));
    assert_digest_counts(&client, &server2.address(), digest2, (0, 0));

    batch.whitelist(digest1, &server1.address()).unwrap();
    assert_digest_counts(&client, &server1.address(), digest1, (0, 10));
    assert_digest_counts(&client, &server2.address(), digest2, (0, 0));

    batch.whitelist(digest2, &server2.address()).unwrap();
    assert_digest_counts(&client, &server2.address(), digest2, (0, 10));

    server1.stop();
    server2.stop();
}

struct TestServer {
    address: Address,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<pyzor::Result<()>>>,
    db_path: PathBuf,
}

impl TestServer {
    fn start(name: &str) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let db_path = temp_dir(name).join("pyzord.db");
        let db = Arc::new(Mutex::new(FileDatabase::open(&db_path).unwrap()));
        let accounts = Arc::new(HashMap::new());
        let acl = Arc::new(acl(&["report", "check", "whitelist"]));
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            serve_socket_until_shutdown(socket, db, accounts, acl, false, server_shutdown)
        });
        Self {
            address: ("127.0.0.1".to_string(), port),
            shutdown,
            handle: Some(handle),
            db_path,
        }
    }

    fn address(&self) -> Address {
        self.address.clone()
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap().unwrap();
        }
        let _ = std::fs::remove_file(&self.db_path);
        if let Some(parent) = self.db_path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn assert_digest_counts(client: &Client, address: &Address, digest: &str, expected: (i64, i64)) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut last = None;
    while std::time::Instant::now() < deadline {
        let response = client.check(digest, address).unwrap();
        let counts = (
            response.get("Count").unwrap().parse::<i64>().unwrap(),
            response.get("WL-Count").unwrap().parse::<i64>().unwrap(),
        );
        if counts == expected {
            return;
        }
        last = Some(counts);
        thread::sleep(Duration::from_millis(20));
    }
    panic!("digest {digest} at {address:?} had counts {last:?}, expected {expected:?}");
}

fn test_client() -> Client {
    Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec())
}

fn numbered_digests(suffix: &str) -> Vec<String> {
    (0..10).map(|index| format!("{index}{suffix}")).collect()
}

fn acl(ops: &[&str]) -> HashMap<String, HashSet<String>> {
    let mut acl = HashMap::new();
    acl.insert(
        "anonymous".to_string(),
        ops.iter().map(|op| (*op).to_string()).collect(),
    );
    acl
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pyzor-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}
