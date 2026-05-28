use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use pyzor::Result;
use pyzor::account::{Account, sign_for_account};
use pyzor::engines::{DigestDatabase, Record};
use pyzor::error::PyzorError;
use pyzor::message::Message;
use pyzor::server::handle_packet;

const DIGEST: &str = "2aedaac999d71421c9ee49b9d81f627a7bc570aa";

#[derive(Default)]
struct MemoryDatabase {
    records: HashMap<String, Record>,
}

impl DigestDatabase for MemoryDatabase {
    fn get(&mut self, digest: &str) -> Result<Record> {
        Ok(self.records.get(digest).cloned().unwrap_or_default())
    }

    fn set(&mut self, digest: &str, record: Record) -> Result<()> {
        self.records.insert(digest.to_string(), record);
        Ok(())
    }
}

struct FailingDatabase;

impl DigestDatabase for FailingDatabase {
    fn get(&mut self, _digest: &str) -> Result<Record> {
        Err(PyzorError::Comm("test".to_string()))
    }

    fn set(&mut self, _digest: &str, _record: Record) -> Result<()> {
        Err(PyzorError::Comm("test".to_string()))
    }
}

#[test]
fn ping_pong_check_and_info_match_reference_handler() {
    let db = Arc::new(Mutex::new(MemoryDatabase::default()));
    db.lock().unwrap().records.insert(
        DIGEST.to_string(),
        Record {
            r_count: 24,
            wl_count: 42,
            r_entered: Some(1_400_221_786),
            r_updated: Some(1_400_221_794),
            wl_entered: Some(1_400_221_800),
            wl_updated: Some(1_400_221_900),
        },
    );
    let accounts = HashMap::new();
    let acl = acl_for(
        "anonymous",
        &["check", "report", "ping", "pong", "info", "whitelist"],
    );

    let response = handle_packet(request("ping", None, 3597).as_bytes(), &db, &accounts, &acl);
    assert_ok_head(&response, "3597");

    let response = handle_packet(
        request("pong", Some(DIGEST), 3598).as_bytes(),
        &db,
        &accounts,
        &acl,
    );
    assert_ok_head(&response, "3598");
    assert_eq!(response.get("Count"), Some(isize::MAX.to_string().as_str()));
    assert_eq!(response.get("WL-Count"), Some("0"));

    let response = handle_packet(
        request("check", Some(DIGEST), 3599).as_bytes(),
        &db,
        &accounts,
        &acl,
    );
    assert_ok_head(&response, "3599");
    assert_eq!(response.get("Count"), Some("24"));
    assert_eq!(response.get("WL-Count"), Some("42"));

    let response = handle_packet(
        request("info", Some(DIGEST), 3600).as_bytes(),
        &db,
        &accounts,
        &acl,
    );
    assert_ok_head(&response, "3600");
    assert_eq!(response.get("Count"), Some("24"));
    assert_eq!(response.get("WL-Count"), Some("42"));
    assert_eq!(response.get("Entered"), Some("1400221786"));
    assert_eq!(response.get("Updated"), Some("1400221794"));
    assert_eq!(response.get("WL-Entered"), Some("1400221800"));
    assert_eq!(response.get("WL-Updated"), Some("1400221900"));
}

#[test]
fn check_and_info_for_new_digest_match_reference_blank_record() {
    let db = Arc::new(Mutex::new(MemoryDatabase::default()));
    let accounts = HashMap::new();
    let acl = acl_for("anonymous", &["check", "info"]);

    let response = handle_packet(
        request("check", Some(DIGEST), 3601).as_bytes(),
        &db,
        &accounts,
        &acl,
    );
    assert_ok_head(&response, "3601");
    assert_eq!(response.get("Count"), Some("0"));
    assert_eq!(response.get("WL-Count"), Some("0"));

    let response = handle_packet(
        request("info", Some(DIGEST), 3602).as_bytes(),
        &db,
        &accounts,
        &acl,
    );
    assert_ok_head(&response, "3602");
    assert_eq!(response.get("Count"), Some("0"));
    assert_eq!(response.get("WL-Count"), Some("0"));
    assert_eq!(response.get("Entered"), Some("0"));
    assert_eq!(response.get("Updated"), Some("0"));
    assert_eq!(response.get("WL-Entered"), Some("0"));
    assert_eq!(response.get("WL-Updated"), Some("0"));
}

#[test]
fn digest_operations_without_op_digest_match_reference_plain_ok_response() {
    let db = Arc::new(Mutex::new(MemoryDatabase::default()));
    let accounts = HashMap::new();
    let acl = acl_for("anonymous", &["pong", "check", "info"]);

    for (op, thread) in [("pong", 3700), ("check", 3701), ("info", 3702)] {
        let response = handle_packet(request(op, None, thread).as_bytes(), &db, &accounts, &acl);
        assert_ok_head(&response, &thread.to_string());
        assert_eq!(response.get("Count"), None);
        assert_eq!(response.get("WL-Count"), None);
        assert_eq!(response.get("Entered"), None);
        assert_eq!(response.get("Updated"), None);
        assert_eq!(response.get("WL-Entered"), None);
        assert_eq!(response.get("WL-Updated"), None);
    }
}

#[test]
fn report_and_whitelist_mutate_records_like_reference_handler() {
    let db = Arc::new(Mutex::new(MemoryDatabase::default()));
    db.lock().unwrap().records.insert(
        DIGEST.to_string(),
        Record {
            r_count: 24,
            wl_count: 42,
            ..Record::default()
        },
    );
    let accounts = HashMap::new();
    let acl = acl_for("anonymous", &["report", "whitelist"]);

    let response = handle_packet(
        request("report", Some(DIGEST), 3603).as_bytes(),
        &db,
        &accounts,
        &acl,
    );
    assert_ok_head(&response, "3603");
    assert_eq!(db.lock().unwrap().records[DIGEST].r_count, 25);

    let response = handle_packet(
        request("whitelist", Some(DIGEST), 3604).as_bytes(),
        &db,
        &accounts,
        &acl,
    );
    assert_ok_head(&response, "3604");
    assert_eq!(db.lock().unwrap().records[DIGEST].wl_count, 43);

    let fresh = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let response = handle_packet(
        request("report", Some(fresh), 3605).as_bytes(),
        &db,
        &accounts,
        &acl,
    );
    assert_ok_head(&response, "3605");
    assert_eq!(db.lock().unwrap().records[fresh].r_count, 1);
}

#[test]
fn reference_error_statuses_are_preserved() {
    let db = Arc::new(Mutex::new(MemoryDatabase::default()));
    let accounts = HashMap::new();
    let acl = acl_for("anonymous", &["ping", "notimplemented"]);

    let response = handle_packet(
        b"Op: ping\nThread: 3606\nUser: anonymous\n\n",
        &db,
        &accounts,
        &acl,
    );
    assert_error_prefix(&response, "3606", "400", "Bad request:");

    let response = handle_packet(
        b"Op: ping\nThread: 3607\nPV: 4.1\nUser: anonymous\n\n",
        &db,
        &accounts,
        &acl,
    );
    assert_error_prefix(&response, "3607", "505", "Version Not Supported:");

    let response = handle_packet(
        b"Op: ping\nThread: 3608\nPV: ab2.13\nUser: anonymous\n\n",
        &db,
        &accounts,
        &acl,
    );
    assert_error_prefix(&response, "3608", "400", "Bad request:");

    let response = handle_packet(
        b"Op: notimplemented\nThread: 3609\nPV: 2.1\nUser: anonymous\n\n",
        &db,
        &accounts,
        &acl,
    );
    assert_error_prefix(&response, "3609", "501", "Not implemented:");

    let restricted_acl = acl_for("anonymous", &["ping", "check"]);
    let response = handle_packet(
        b"Op: report\nThread: 3610\nPV: 2.1\nUser: anonymous\n\n",
        &db,
        &accounts,
        &restricted_acl,
    );
    assert_error_prefix(&response, "3610", "403", "Forbidden:");
}

#[test]
fn authenticated_account_success_and_failures_match_reference_handler() {
    let db = Arc::new(Mutex::new(MemoryDatabase::default()));
    let mut accounts = HashMap::new();
    accounts.insert("testuser".to_string(), "testkey".to_string());
    let acl = acl_for("testuser", &["ping", "check"]);

    let signed = signed_request("ping", 3611, "testuser", "testkey");
    let response = handle_packet(signed.as_bytes(), &db, &accounts, &acl);
    assert_ok_head(&response, "3611");

    let unknown = signed_request("ping", 3612, "unknown", "testkey");
    let response = handle_packet(unknown.as_bytes(), &db, &accounts, &acl);
    assert_error_prefix(&response, "3612", "401", "Unauthorized:");

    let bad_signature = signed_request("ping", 3613, "testuser", "wrongkey");
    let response = handle_packet(bad_signature.as_bytes(), &db, &accounts, &acl);
    assert_error_prefix(&response, "3613", "401", "Unauthorized:");
}

#[test]
fn database_errors_become_internal_server_errors_after_thread_is_set() {
    let db = Arc::new(Mutex::new(FailingDatabase));
    let accounts = HashMap::new();
    let acl = acl_for("anonymous", &["check"]);

    let response = handle_packet(
        request("check", Some(DIGEST), 3614).as_bytes(),
        &db,
        &accounts,
        &acl,
    );
    assert_error_prefix(&response, "3614", "500", "Internal Server Error:");
}

fn request(op: &str, digest: Option<&str>, thread: u16) -> String {
    let mut request = format!("Op: {op}\nThread: {thread}\nPV: 2.1\nUser: anonymous\n");
    if let Some(digest) = digest {
        request.push_str(&format!("Op-Digest: {digest}\n"));
    }
    request.push('\n');
    request
}

fn signed_request(op: &str, thread: u16, user: &str, key: &str) -> String {
    let mut msg = Message::new();
    msg.add_header("Op", op);
    msg.add_header("Thread", thread.to_string());
    msg.add_header("PV", "2.1");
    sign_for_account(
        &mut msg,
        &Account::new(user, None, key),
        pyzor::account::now_timestamp(),
    );
    msg.as_string()
}

fn acl_for(user: &str, ops: &[&str]) -> HashMap<String, HashSet<String>> {
    let mut acl = HashMap::new();
    acl.insert(
        user.to_string(),
        ops.iter().map(|op| (*op).to_string()).collect(),
    );
    acl
}

fn assert_ok_head(response: &Message, thread: &str) {
    assert_eq!(response.get("Code"), Some("200"));
    assert_eq!(response.get("Diag"), Some("OK"));
    assert_eq!(response.get("PV"), Some("2.1"));
    assert_eq!(response.get("Thread"), Some(thread));
}

fn assert_error_prefix(response: &Message, thread: &str, code: &str, diag_prefix: &str) {
    assert_eq!(response.get("Code"), Some(code));
    assert_eq!(response.get("Thread"), Some(thread));
    assert!(
        response.get("Diag").unwrap_or("").starts_with(diag_prefix),
        "unexpected diagnostic: {:?}",
        response.get("Diag")
    );
}
