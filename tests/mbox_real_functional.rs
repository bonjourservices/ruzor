use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use pyzor::engines::FileDatabase;
use pyzor::serve_socket_until_shutdown;

#[test]
fn cli_real_mbox_fixture_matches_python_functional_test() {
    let mut server = TestServer::start("cli-real-mbox");
    let homedir = temp_dir("cli-real-mbox-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();
    let input = latin1_file_as_utf8_bytes("tests/fixtures/test.mbx");

    let pong = run_pyzor(&homedir, &["-s", "mbox", "pong"], &input);
    assert!(pong.status.success(), "{pong:?}");
    assert_count_pairs(&pong, &[(isize::MAX as i64, 0)]);

    let initial_check = run_pyzor(&homedir, &["-s", "mbox", "check"], &input);
    assert!(!initial_check.status.success(), "{initial_check:?}");
    assert_count_pairs(&initial_check, &[(0, 0)]);

    let report = run_pyzor(&homedir, &["-s", "mbox", "report"], &input);
    assert!(report.status.success(), "{report:?}");
    assert_status_code(&report, 200);
    let after_report = run_pyzor(&homedir, &["-s", "mbox", "check"], &input);
    assert!(after_report.status.success(), "{after_report:?}");
    assert_count_pairs(&after_report, &[(1, 0)]);

    let whitelist = run_pyzor(&homedir, &["-s", "mbox", "whitelist"], &input);
    assert!(whitelist.status.success(), "{whitelist:?}");
    assert_status_code(&whitelist, 200);
    let after_whitelist = run_pyzor(&homedir, &["-s", "mbox", "check"], &input);
    assert!(!after_whitelist.status.success(), "{after_whitelist:?}");
    assert_count_pairs(&after_whitelist, &[(1, 1)]);

    let info = run_pyzor(&homedir, &["-s", "mbox", "info"], &input);
    assert!(info.status.success(), "{info:?}");
    assert_stdout_contains(&info, "\tCount: 1");
    assert_stdout_contains(&info, "\tWL-Count: 1");

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
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

fn run_pyzor(homedir: &std::path::Path, args: &[&str], input: &[u8]) -> Output {
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
        .write_all(input)
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

fn assert_stdout_contains(output: &Output, expected: &str) {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.contains(expected), "{stdout:?}");
}

fn assert_count_pairs(output: &Output, expected: &[(i64, i64)]) {
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    let pairs = String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| {
            let parts = line.split('\t').collect::<Vec<_>>();
            assert!(parts.len() >= 4, "unexpected pyzor output line: {line:?}");
            let count = parts[parts.len() - 2].parse::<i64>().unwrap();
            let wl_count = parts[parts.len() - 1].parse::<i64>().unwrap();
            (count, wl_count)
        })
        .collect::<Vec<_>>();
    assert_eq!(pairs, expected);
}

fn latin1_file_as_utf8_bytes(path: &str) -> Vec<u8> {
    std::fs::read(path)
        .unwrap()
        .into_iter()
        .map(char::from)
        .collect::<String>()
        .into_bytes()
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
