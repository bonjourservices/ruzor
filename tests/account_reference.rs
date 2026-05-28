use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use pyzor::account::{hash_key, key_from_hexstr, sign_for_account, sign_msg, verify_signature};
use pyzor::config::load_accounts;
use pyzor::error::PyzorError;
use pyzor::message::Message;

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pyzor-account-{name}-{nanos}"));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn sign_msg_and_hash_key_match_reference_vectors() {
    let timestamp = 1_381_219_396;
    let mut msg = Message::new();
    msg.add_header("Op", "ping");
    msg.add_header("Thread", "14941");
    msg.add_header("PV", "2.1");
    msg.add_header("User", "anonymous");
    msg.add_header("Time", timestamp.to_string());

    assert_eq!(
        sign_msg("00942f4668670f34c5943cf52c7ef3139fe2b8d6", timestamp, &msg),
        "2ab1bad2aae6fd80c656a896c82eef0ec1ec38a0"
    );
    assert_eq!(
        hash_key("testkey", "testuser"),
        "0957bd79b58263657127a39762879098286d8477"
    );
}

#[test]
fn verify_signature_matches_reference_success_and_failures() {
    let mut msg = Message::new();
    msg.add_header("Op", "ping");
    msg.add_header("Thread", "14941");
    msg.add_header("PV", "2.1");
    sign_for_account(
        &mut msg,
        &pyzor::account::Account::new("testuser", None, "testkey"),
        pyzor::account::now_timestamp(),
    );
    assert!(verify_signature(&msg, "testkey").is_ok());

    let mut old = Message::new();
    old.add_header("Op", "ping");
    old.add_header("Thread", "14941");
    old.add_header("PV", "2.1");
    sign_for_account(
        &mut old,
        &pyzor::account::Account::new("testuser", None, "testkey"),
        1_381_219_396,
    );
    assert!(
        matches!(verify_signature(&old, "testkey"), Err(PyzorError::Signature(message)) if message == "Timestamp not within allowed range.")
    );

    let mut bad = msg.clone();
    bad.replace_header("Sig", "testsig-bad");
    assert!(
        matches!(verify_signature(&bad, "testkey"), Err(PyzorError::Signature(message)) if message == "Invalid signature.")
    );
}

#[test]
fn key_from_hexstr_matches_reference_split_behavior() {
    assert_eq!(
        key_from_hexstr("123abc,cba321").unwrap(),
        ("123abc".to_string(), "cba321".to_string())
    );
    assert_eq!(
        key_from_hexstr(",").unwrap(),
        ("".to_string(), "".to_string())
    );
    assert_eq!(
        key_from_hexstr("missing-comma").unwrap_err(),
        "Invalid number of parts for key; perhaps you forgot the comma at the beginning for the salt divider?"
    );
    assert_eq!(
        key_from_hexstr("a,b,c").unwrap_err(),
        "Invalid number of parts for key; perhaps you forgot the comma at the beginning for the salt divider?"
    );
}

#[test]
fn load_accounts_matches_reference_valid_and_invalid_cases() {
    let dir = temp_dir("load");
    let accounts = dir.join("accounts");

    assert!(load_accounts(dir.join("missing")).is_empty());

    std::fs::write(
        &accounts,
        concat!(
            "public.pyzor.org : 24441 : test : 123abc,cba321\n",
            "public2.pyzor.org : 24441 : test2 : 123abc,cba321\n",
            "public3.pyzor.org : 24441 ; test3 : 123abc,cba321\n",
            "public4.pyzor.org : a4441 : test4 : 123abc,cba321\n",
            "public5.pyzor.org : 24441 : test5 : ,\n",
            "public6.pyzor.org : 24441 : test6 : 123abccba321\n",
            "#public7.pyzor.org : 24441 : test7 : 123abc,cba321\n",
        ),
    )
    .unwrap();

    let loaded = load_accounts(&accounts);
    assert_eq!(loaded.len(), 2);
    let account = &loaded[&("public.pyzor.org".to_string(), 24441)];
    assert_eq!(account.username, "test");
    assert_eq!(account.salt.as_deref(), Some("123abc"));
    assert_eq!(account.key, "cba321");

    let account = &loaded[&("public2.pyzor.org".to_string(), 24441)];
    assert_eq!(account.username, "test2");
    assert_eq!(account.salt.as_deref(), Some("123abc"));
    assert_eq!(account.key, "cba321");

    assert!(!loaded.contains_key(&("public3.pyzor.org".to_string(), 24441)));
    assert!(!loaded.contains_key(&("public4.pyzor.org".to_string(), 24441)));
    assert!(!loaded.contains_key(&("public5.pyzor.org".to_string(), 24441)));
    assert!(!loaded.contains_key(&("public6.pyzor.org".to_string(), 24441)));
    assert!(!loaded.contains_key(&("public7.pyzor.org".to_string(), 24441)));

    let _ = std::fs::remove_dir_all(dir);
}
