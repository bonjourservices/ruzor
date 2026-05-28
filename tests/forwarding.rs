use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
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

#[cfg(unix)]
const SIGTERM: i32 = 15;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[test]
fn pyzord_forwards_report_batches_to_remote_servers() {
    let mut remote = TestServer::start("forward-remote");
    let forward_homedir = temp_dir("forward-client-home");
    std::fs::write(
        forward_homedir.join("servers"),
        format!("127.0.0.1:{}\n", remote.port),
    )
    .unwrap();

    let local_homedir = temp_dir("forward-local-home");
    std::fs::write(local_homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    std::fs::write(local_homedir.join("passwd"), "").unwrap();
    let local_port = free_udp_port();
    let local_address: Address = ("127.0.0.1".to_string(), local_port);
    let mut local = spawn_forwarding_pyzord(
        &local_homedir,
        &forward_homedir,
        local_homedir.join("pyzord.db").as_path(),
        local_port,
    );
    wait_for_process_server(&mut local, &local_address);

    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..10 {
        assert!(client.report(DIGEST, &local_address).unwrap().is_ok());
    }

    let remote_address: Address = ("127.0.0.1".to_string(), remote.port);
    wait_for_count(&client, &remote_address, "10", "0");

    terminate(local);
    remote.stop();
    let _ = std::fs::remove_dir_all(forward_homedir);
    let _ = std::fs::remove_dir_all(local_homedir);
}

fn spawn_forwarding_pyzord(
    homedir: &Path,
    forward_homedir: &Path,
    db_path: &Path,
    port: u16,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .arg("--homedir")
        .arg(homedir)
        .arg("--password-file")
        .arg("passwd")
        .arg("--access-file")
        .arg("access")
        .arg("--dsn")
        .arg(db_path)
        .arg("--forward-client-homedir")
        .arg(forward_homedir)
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn forwarding pyzord")
}

fn wait_for_process_server(server: &mut Child, address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..50 {
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

fn wait_for_count(client: &Client, address: &Address, count: &str, wl_count: &str) {
    for _ in 0..50 {
        match client.check(DIGEST, address) {
            Ok(response)
                if response.get("Count") == Some(count)
                    && response.get("WL-Count") == Some(wl_count) =>
            {
                return;
            }
            _ => thread::sleep(Duration::from_millis(50)),
        }
    }
    panic!("forwarded count did not reach {count}/{wl_count}");
}

fn terminate(mut child: Child) {
    #[cfg(unix)]
    {
        // SAFETY: Calls POSIX kill with a child pid owned by this test process.
        let _ = unsafe { kill(child.id() as i32, SIGTERM) };
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
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
