#![cfg(unix)]

use std::collections::HashMap;
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyzor::client::Client;
use pyzor::config::Address;

const DIGEST: &str = "7421216f915a87e02da034cc483f5c876e1a1338";
const STALE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FRESH_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const SIGTERM: i32 = 15;

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
#[test]
fn mysql_cleanup_age_reorganizes_stale_records_on_open() {
    let homedir = temp_dir("mysql-cleanup-age");
    std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    std::fs::write(homedir.join("passwd"), "").unwrap();
    let state_path = homedir.join("fake-mysql-state.json");
    let seeded = format!(
        r#"{{"{stale}":{{"r":24,"wl":0,"r_updated":"2001-01-01 00:00:00"}},"{fresh}":{{"r":42,"wl":1,"r_updated":"2999-01-01 00:00:00"}}}}"#,
        stale = STALE_DIGEST,
        fresh = FRESH_DIGEST
    );
    std::fs::write(&state_path, seeded).unwrap();
    let mysql_bin = write_fake_mysql(&homedir);
    let port = free_udp_port();
    let address: Address = ("127.0.0.1".to_string(), port);
    let dsn = "localhost,pyzor,secret,pyzord,public";

    let mut server = Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .env("PYZOR_MYSQL_BIN", &mysql_bin)
        .env("PYZOR_FAKE_MYSQL_STATE", &state_path)
        .arg("--homedir")
        .arg(&homedir)
        .arg("--password-file")
        .arg("passwd")
        .arg("--access-file")
        .arg("access")
        .arg("-e")
        .arg("mysql")
        .arg("--dsn")
        .arg(dsn)
        .arg("--cleanup-age")
        .arg("1")
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pyzord with MySQL cleanup age");

    wait_for_server(&mut server, &address);
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    let stale = client.check(STALE_DIGEST, &address).unwrap();
    assert_eq!(stale.get("Count"), Some("0"));
    assert_eq!(stale.get("WL-Count"), Some("0"));
    let fresh = client.check(FRESH_DIGEST, &address).unwrap();
    assert_eq!(fresh.get("Count"), Some("42"));
    assert_eq!(fresh.get("WL-Count"), Some("1"));

    stop(server);
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn mysql_cleanup_age_zero_keeps_stale_records_like_python() {
    let homedir = temp_dir("mysql-cleanup-age-zero");
    std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    std::fs::write(homedir.join("passwd"), "").unwrap();
    let state_path = homedir.join("fake-mysql-state.json");
    let seeded = format!(
        r#"{{"{stale}":{{"r":24,"wl":0,"r_updated":"2001-01-01 00:00:00"}}}}"#,
        stale = STALE_DIGEST
    );
    std::fs::write(&state_path, seeded).unwrap();
    let mysql_bin = write_fake_mysql(&homedir);
    let port = free_udp_port();
    let address: Address = ("127.0.0.1".to_string(), port);
    let dsn = "localhost,pyzor,secret,pyzord,public";

    let mut server = Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .env("PYZOR_MYSQL_BIN", &mysql_bin)
        .env("PYZOR_FAKE_MYSQL_STATE", &state_path)
        .arg("--homedir")
        .arg(&homedir)
        .arg("--password-file")
        .arg("passwd")
        .arg("--access-file")
        .arg("access")
        .arg("-e")
        .arg("mysql")
        .arg("--dsn")
        .arg(dsn)
        .arg("--cleanup-age")
        .arg("0")
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pyzord with disabled MySQL cleanup age");

    wait_for_server(&mut server, &address);
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    let stale = client.check(STALE_DIGEST, &address).unwrap();
    assert_eq!(stale.get("Count"), Some("24"));
    assert_eq!(stale.get("WL-Count"), Some("0"));

    stop(server);
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn mysql_process_mode_forks_workers_and_preserves_counts() {
    let homedir = temp_dir("mysql-process-mode");
    std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    std::fs::write(homedir.join("passwd"), "").unwrap();
    let state_path = homedir.join("fake-mysql-state.json");
    let mysql_bin = write_fake_mysql(&homedir);
    let port = free_udp_port();
    let address: Address = ("127.0.0.1".to_string(), port);
    let dsn = "localhost,pyzor,secret,pyzord,public";

    let mut server = Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .env("PYZOR_MYSQL_BIN", &mysql_bin)
        .env("PYZOR_FAKE_MYSQL_STATE", &state_path)
        .arg("--homedir")
        .arg(&homedir)
        .arg("--password-file")
        .arg("passwd")
        .arg("--access-file")
        .arg("access")
        .arg("-e")
        .arg("mysql")
        .arg("--dsn")
        .arg(dsn)
        .arg("--processes")
        .arg("true")
        .arg("--max-processes")
        .arg("2")
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pyzord with MySQL process mode");

    wait_for_server(&mut server, &address);
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..3 {
        assert!(client.report(DIGEST, &address).unwrap().is_ok());
    }
    for _ in 0..2 {
        assert!(client.whitelist(DIGEST, &address).unwrap().is_ok());
    }

    let response = client.check(DIGEST, &address).unwrap();
    assert_eq!(response.get("Count"), Some("3"));
    assert_eq!(response.get("WL-Count"), Some("2"));

    stop(server);
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn mysql_prefork_workers_preserve_counts() {
    let homedir = temp_dir("mysql-prefork-mode");
    std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    std::fs::write(homedir.join("passwd"), "").unwrap();
    let state_path = homedir.join("fake-mysql-state.json");
    let mysql_bin = write_fake_mysql(&homedir);
    let port = free_udp_port();
    let address: Address = ("127.0.0.1".to_string(), port);
    let dsn = "localhost,pyzor,secret,pyzord,public";

    let mut server = Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .env("PYZOR_MYSQL_BIN", &mysql_bin)
        .env("PYZOR_FAKE_MYSQL_STATE", &state_path)
        .arg("--homedir")
        .arg(&homedir)
        .arg("--password-file")
        .arg("passwd")
        .arg("--access-file")
        .arg("access")
        .arg("-e")
        .arg("mysql")
        .arg("--dsn")
        .arg(dsn)
        .arg("--pre-fork")
        .arg("2")
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pyzord with MySQL pre-fork mode");

    wait_for_server(&mut server, &address);
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..4 {
        assert!(client.report(DIGEST, &address).unwrap().is_ok());
    }
    assert!(client.whitelist(DIGEST, &address).unwrap().is_ok());

    let response = client.check(DIGEST, &address).unwrap();
    assert_eq!(response.get("Count"), Some("4"));
    assert_eq!(response.get("WL-Count"), Some("1"));

    terminate(server);
    let _ = std::fs::remove_dir_all(homedir);
}

fn write_fake_mysql(homedir: &Path) -> PathBuf {
    let path = homedir.join("fake-mysql.py");
    let script = r#"#!/usr/bin/python3
import json
import os
import re
import sys

state_path = os.environ["PYZOR_FAKE_MYSQL_STATE"]
try:
    execute_index = sys.argv.index("--execute")
    sql = sys.argv[execute_index + 1]
except (ValueError, IndexError):
    sys.exit(2)

try:
    with open(state_path, "r") as state_file:
        state = json.load(state_file)
except FileNotFoundError:
    state = {}

def save():
    tmp = state_path + ".tmp"
    with open(tmp, "w") as state_file:
        json.dump(state, state_file, sort_keys=True)
    os.replace(tmp, state_path)

def digest_from_values(statement):
    match = re.search(r"VALUES \('([0-9a-f]{40})'", statement)
    if not match:
        sys.exit(3)
    return match.group(1)

for statement in [part.strip() for part in sql.split(";") if part.strip()]:
    if statement == "SELECT 1":
        print("1")
        continue
    if statement.startswith("DELETE FROM "):
        match = re.search(r"WHERE digest='([0-9a-f]{40})'", statement)
        if match:
            state.pop(match.group(1), None)
            continue
        match = re.search(r"WHERE r_updated<'([^']+)'", statement)
        if match:
            cutoff = match.group(1)
            for digest in [digest for digest, record in state.items() if record.get("r_updated") and record["r_updated"] < cutoff]:
                state.pop(digest, None)
            continue
        sys.exit(6)

    if statement.startswith("SELECT r_count, wl_count"):
        match = re.search(r"WHERE digest='([0-9a-f]{40})'", statement)
        if not match:
            sys.exit(4)
        record = state.get(match.group(1))
        if record:
            r_updated = record.get("r_updated", "NULL")
            print("%d\t%d\tNULL\t%s\tNULL\tNULL" % (record["r"], record["wl"], r_updated))

        continue
    if "r_count=r_count+1" in statement:
        digest = digest_from_values(statement)
        record = state.setdefault(digest, {"r": 0, "wl": 0})
        record["r"] += 1
        continue
    if "wl_count=wl_count+1" in statement:
        digest = digest_from_values(statement)
        record = state.setdefault(digest, {"r": 0, "wl": 0})
        record["wl"] += 1
        continue
    sys.exit(5)

save()
"#;
    std::fs::write(&path, script).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).unwrap();
    path
}

fn wait_for_server(server: &mut Child, address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..100 {
        if let Some(status) = server.try_wait().expect("poll pyzord") {
            panic!("pyzord exited before readiness: {status}");
        }
        if client
            .ping(address)
            .map(|response| response.is_ok())
            .unwrap_or(false)
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("pyzord did not become ready on {}:{}", address.0, address.1);
}

fn terminate(mut child: Child) {
    let _ = unsafe { kill(child.id() as i32, SIGTERM) };
    for _ in 0..50 {
        if child.try_wait().expect("poll pyzord exit").is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
