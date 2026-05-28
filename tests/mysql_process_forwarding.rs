#![cfg(unix)]

use std::collections::{HashMap, HashSet};
use std::io::Read;

use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyzor::client::Client;
use pyzor::config::Address;
use pyzor::engines::FileDatabase;
use pyzor::serve_socket_until_shutdown;

const DIGEST: &str = "7421216f915a87e02da034cc483f5c876e1a1338";
const SIGTERM: i32 = 15;

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[test]
fn mysql_process_mode_forwards_reports_to_remote_servers() {
    let mut remote = TestServer::start("mysql-process-forward-remote");
    let forward_homedir = temp_dir("mysql-process-forward-client-home");
    std::fs::write(
        forward_homedir.join("servers"),
        format!("127.0.0.1:{}\n", remote.port),
    )
    .unwrap();

    let homedir = temp_dir("mysql-process-forward-local");
    std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    std::fs::write(homedir.join("passwd"), "").unwrap();
    let state_path = homedir.join("fake-mysql-state.json");
    let mysql_bin = write_fake_mysql(&homedir);
    let port = free_udp_port();
    let local_address: Address = ("127.0.0.1".to_string(), port);
    let remote_address: Address = ("127.0.0.1".to_string(), remote.port);
    let dsn = "localhost,pyzor,secret,pyzord,public";

    let mut local = Command::new(env!("CARGO_BIN_EXE_pyzord"))
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
        .arg("--forward-client-homedir")
        .arg(&forward_homedir)
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pyzord with MySQL process forwarding");

    wait_for_server(&mut local, &local_address);
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..10 {
        assert!(client.report(DIGEST, &local_address).unwrap().is_ok());
    }

    wait_for_count(&client, &remote_address, "10", "0");

    terminate(local);
    remote.stop();
    let _ = std::fs::remove_dir_all(forward_homedir);
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn mysql_prefork_mode_flushes_forwarded_reports_to_remote_servers_on_shutdown() {
    let mut remote = TestServer::start("mysql-prefork-forward-remote");
    let forward_homedir = temp_dir("mysql-prefork-forward-client-home");
    std::fs::write(
        forward_homedir.join("servers"),
        format!("127.0.0.1:{}\n", remote.port),
    )
    .unwrap();

    let homedir = temp_dir("mysql-prefork-forward-local");
    std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    std::fs::write(homedir.join("passwd"), "").unwrap();
    let state_path = homedir.join("fake-mysql-state.json");
    let mysql_bin = write_fake_mysql(&homedir);
    let port = free_udp_port();
    let local_address: Address = ("127.0.0.1".to_string(), port);
    let remote_address: Address = ("127.0.0.1".to_string(), remote.port);
    let dsn = "localhost,pyzor,secret,pyzord,public";

    let mut local = Command::new(env!("CARGO_BIN_EXE_pyzord"))
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
        .arg("--forward-client-homedir")
        .arg(&forward_homedir)
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pyzord with MySQL pre-fork forwarding");

    wait_for_server(&mut local, &local_address);
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..4 {
        assert!(client.report(DIGEST, &local_address).unwrap().is_ok());
    }

    terminate(local);
    wait_for_count(&client, &remote_address, "4", "0");

    remote.stop();
    let _ = std::fs::remove_dir_all(forward_homedir);
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
    if statement.startswith("SELECT r_count, wl_count"):
        match = re.search(r"WHERE digest='([0-9a-f]{40})'", statement)
        if not match:
            sys.exit(4)
        record = state.get(match.group(1))
        if record:
            print("%d\t%d\tNULL\tNULL\tNULL\tNULL" % (record["r"], record["wl"]))
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
            let mut stderr = String::new();
            if let Some(mut pipe) = server.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("pyzord exited before readiness: {status}\n{stderr}");
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

fn wait_for_count(client: &Client, address: &Address, count: &str, wl_count: &str) {
    let mut last = None;
    for _ in 0..100 {
        match client.check(DIGEST, address) {
            Ok(response)
                if response.get("Count") == Some(count)
                    && response.get("WL-Count") == Some(wl_count) =>
            {
                return;
            }
            Ok(response) => {
                last = Some((
                    response.get("Count").unwrap_or("").to_string(),
                    response.get("WL-Count").unwrap_or("").to_string(),
                ));
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                last = Some((format!("error: {error}"), String::new()));
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    panic!("forwarded count was {last:?}, expected {count}/{wl_count}");
}

fn terminate(mut child: Child) {
    // SAFETY: Calls POSIX kill with a child pid owned by this test process.
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

struct TestServer {
    port: u16,
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
        let acl = Arc::new(acl(&[
            "report",
            "check",
            "whitelist",
            "info",
            "ping",
            "pong",
        ]));
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            serve_socket_until_shutdown(socket, db, accounts, acl, false, server_shutdown)
        });
        Self {
            port,
            shutdown,
            handle: Some(handle),
            db_path,
        }
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

fn acl(ops: &[&str]) -> HashMap<String, HashSet<String>> {
    let mut acl = HashMap::new();
    acl.insert(
        "anonymous".to_string(),
        ops.iter().map(|op| (*op).to_string()).collect(),
    );
    acl
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
