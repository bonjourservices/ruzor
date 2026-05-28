use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyzor::client::Client;
use pyzor::config::Address;
use pyzor::engines::FileDatabase;
use pyzor::serve_socket_until_shutdown;

const MSG: &str = "This is a test message for the forwading feature";

#[cfg(unix)]
const SIGTERM: i32 = 15;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[test]
fn cli_forward_report_workflow_matches_python_functional_test() {
    let mut remote = TestServer::start("forwarder-functional-remote");
    let fwdclient_homedir = temp_dir("forwarder-functional-client");
    std::fs::write(
        fwdclient_homedir.join("servers"),
        format!("127.0.0.1:{}\n", remote.port),
    )
    .unwrap();

    let local_homedir = temp_dir("forwarder-functional-local");
    let local_port = free_udp_port();
    std::fs::write(
        local_homedir.join("servers"),
        format!("127.0.0.1:{local_port}\n"),
    )
    .unwrap();
    std::fs::write(local_homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    std::fs::write(local_homedir.join("passwd"), "").unwrap();
    let mut local = spawn_forwarding_pyzord(&local_homedir, &fwdclient_homedir, local_port);
    let local_address = ("127.0.0.1".to_string(), local_port);
    wait_for_process_server(&mut local, &local_address);

    for _ in 0..10 {
        let report = run_pyzor(&local_homedir, &["report"], MSG);
        assert!(report.status.success(), "{report:?}");
        assert_status_code(&report, 200);
    }

    assert_cli_counts(&local_homedir, "check", (10, 0));
    wait_for_cli_counts(&fwdclient_homedir, (10, 0));

    let remote_report = run_pyzor(&fwdclient_homedir, &["report"], MSG);
    assert!(remote_report.status.success(), "{remote_report:?}");
    assert_status_code(&remote_report, 200);
    assert_cli_counts(&fwdclient_homedir, "check", (11, 0));
    assert_cli_counts(&local_homedir, "check", (10, 0));

    terminate(&mut local);
    remote.stop();
    let _ = std::fs::remove_dir_all(fwdclient_homedir);
    let _ = std::fs::remove_dir_all(local_homedir);
}

fn spawn_forwarding_pyzord(homedir: &Path, forward_homedir: &Path, port: u16) -> Child {
    Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .arg("--homedir")
        .arg(homedir)
        .arg("--password-file")
        .arg("passwd")
        .arg("--access-file")
        .arg("access")
        .arg("--dsn")
        .arg(homedir.join("pyzord.db"))
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

fn wait_for_cli_counts(homedir: &Path, expected: (i64, i64)) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut last = None;
    while std::time::Instant::now() < deadline {
        let output = run_pyzor(homedir, &["check"], MSG);
        let counts = count_pair(&output);
        if counts == expected {
            return;
        }
        last = Some(counts);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("forwarded count was {last:?}, expected {expected:?}");
}

fn assert_cli_counts(homedir: &Path, command: &str, expected: (i64, i64)) {
    let output = run_pyzor(homedir, &[command], MSG);
    assert_status_code(&output, 200);
    assert_eq!(count_pair(&output), expected, "{output:?}");
}

fn run_pyzor(homedir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pyzor"))
        .arg("--homedir")
        .arg(homedir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Rust pyzor client");
    child
        .stdin
        .as_mut()
        .expect("Rust client stdin")
        .write_all(input.as_bytes())
        .expect("write Rust client stdin");
    child.wait_with_output().expect("wait Rust client")
}

fn assert_status_code(output: &Output, expected_code: i64) {
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let line = stdout.lines().next().expect("pyzor status line");
    let status = line.split('\t').nth(1).expect("status tuple field");
    let code = status
        .trim_start_matches('(')
        .split(',')
        .next()
        .expect("status code")
        .parse::<i64>()
        .unwrap();
    assert_eq!(code, expected_code, "{stdout:?}");
}

fn count_pair(output: &Output) -> (i64, i64) {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let line = stdout.lines().next().expect("pyzor count line");
    let parts = line.split('\t').collect::<Vec<_>>();
    assert!(parts.len() >= 4, "unexpected pyzor output line: {line:?}");
    (
        parts[parts.len() - 2].parse::<i64>().unwrap(),
        parts[parts.len() - 1].parse::<i64>().unwrap(),
    )
}

fn terminate(child: &mut Child) {
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
