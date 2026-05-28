use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ruzor::client::Client;
use ruzor::config::Address;
use ruzor::engines::FileDatabase;
use ruzor::serve_socket_until_shutdown;

const MSG: &str = "Newsgroups:
Date: Wed, 10 Apr 2002 22:23:51 -0400 (EDT)
From: Frank Tobin <ftobin@neverending.org>
Fcc: sent-mail
Message-ID: <20020410222350.E16178@palanthas.neverending.org>
X-Our-Headers: X-Bogus,Anon-To
X-Bogus: aaron7@neverending.org
MIME-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII

Test Email
";

#[test]
fn cli_account_auth_matrix_matches_python_functional_test() {
    let mut server = TestServer::start(
        "account-functional-auth",
        reference_passwd(),
        reference_access(),
    );
    let homedir = temp_dir("account-functional-auth-home");
    write_common_homedir(&homedir, server.port);

    for command in ["ping", "pong", "check", "report", "whitelist", "info"] {
        assert_command(
            &homedir,
            Some("bob"),
            command,
            200,
            success_for(command, true),
        );
    }

    for command in ["ping", "pong", "check", "report", "whitelist", "info"] {
        assert_command(&homedir, Some("alice"), command, 403, Some(false));
    }

    for command in ["ping", "pong", "check", "report", "whitelist", "info"] {
        assert_command(&homedir, Some("chuck"), command, 401, Some(false));
    }

    assert_command(&homedir, Some("dan"), "ping", 200, Some(true));
    assert_command(&homedir, Some("dan"), "pong", 403, Some(false));
    assert_command(&homedir, Some("dan"), "check", 200, None);
    assert_command(&homedir, Some("dan"), "report", 200, Some(true));
    assert_command(&homedir, Some("dan"), "whitelist", 403, Some(false));
    assert_command(&homedir, Some("dan"), "info", 403, Some(false));

    for command in ["ping", "pong", "check", "report", "whitelist", "info"] {
        assert_command(&homedir, None, command, 403, Some(false));
    }

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_account_auth_matrix_matches_python_functional_process_test() {
    let homedir = temp_dir("account-functional-process-home");
    let port = free_udp_port();
    write_common_homedir(&homedir, port);
    std::fs::write(homedir.join("ruzord.passwd"), reference_passwd_file()).unwrap();
    std::fs::write(homedir.join("ruzord.access"), reference_access_file()).unwrap();
    let mut server = spawn_pyzord_process(&homedir, port);
    let address: Address = ("127.0.0.1".to_string(), port);
    wait_for_process_server(&mut server, &address);

    for command in ["ping", "pong", "check", "report", "whitelist", "info"] {
        assert_command(
            &homedir,
            Some("bob"),
            command,
            200,
            success_for(command, true),
        );
    }

    for command in ["ping", "pong", "check", "report", "whitelist", "info"] {
        assert_command(&homedir, Some("alice"), command, 403, Some(false));
    }

    for command in ["ping", "pong", "check", "report", "whitelist", "info"] {
        assert_command(&homedir, Some("chuck"), command, 401, Some(false));
    }

    assert_command(&homedir, Some("dan"), "ping", 200, Some(true));
    assert_command(&homedir, Some("dan"), "pong", 403, Some(false));
    assert_command(&homedir, Some("dan"), "check", 200, None);
    assert_command(&homedir, Some("dan"), "report", 200, Some(true));
    assert_command(&homedir, Some("dan"), "whitelist", 403, Some(false));
    assert_command(&homedir, Some("dan"), "info", 403, Some(false));

    for command in ["ping", "pong", "check", "report", "whitelist", "info"] {
        assert_command(&homedir, None, command, 403, Some(false));
    }

    stop_process(server);
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_default_anonymous_access_matches_python_functional_test() {
    let mut server = TestServer::start(
        "account-functional-anonymous",
        HashMap::new(),
        default_anonymous_access(),
    );
    let homedir = temp_dir("account-functional-anonymous-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();

    assert_command(&homedir, None, "ping", 200, Some(true));
    assert_command(&homedir, None, "pong", 200, Some(true));
    assert_command(&homedir, None, "check", 200, None);
    assert_command(&homedir, None, "report", 200, Some(true));
    assert_command(&homedir, None, "whitelist", 403, Some(false));
    assert_command(&homedir, None, "info", 200, Some(true));

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_default_anonymous_access_matches_python_functional_process_test() {
    let homedir = temp_dir("account-functional-anonymous-process-home");
    let port = free_udp_port();
    std::fs::write(homedir.join("servers"), format!("127.0.0.1:{port}\n")).unwrap();
    let mut server = spawn_pyzord_process(&homedir, port);
    let address: Address = ("127.0.0.1".to_string(), port);
    wait_for_process_server(&mut server, &address);

    assert_command(&homedir, None, "ping", 200, Some(true));
    assert_command(&homedir, None, "pong", 200, Some(true));
    assert_command(&homedir, None, "check", 200, None);
    assert_command(&homedir, None, "report", 200, Some(true));
    assert_command(&homedir, None, "whitelist", 403, Some(false));
    assert_command(&homedir, None, "info", 200, Some(true));

    stop_process(server);
    let _ = std::fs::remove_dir_all(homedir);
}

struct TestServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<ruzor::Result<()>>>,
    db_path: PathBuf,
}

impl TestServer {
    fn start(
        name: &str,
        accounts: HashMap<String, String>,
        acl: HashMap<String, HashSet<String>>,
    ) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let db_path = temp_dir(name).join("ruzord.db");
        let db = Arc::new(Mutex::new(FileDatabase::open(&db_path).unwrap()));
        let accounts = Arc::new(accounts);
        let acl = Arc::new(acl);
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

fn assert_command(
    homedir: &Path,
    account_file: Option<&str>,
    command: &str,
    expected_code: i64,
    expected_success: Option<bool>,
) {
    let mut args = Vec::new();
    if let Some(account_file) = account_file {
        args.push("--accounts-file");
        args.push(account_file);
    }
    args.push(command);
    let input = if command == "ping" { "" } else { MSG };
    let output = run_pyzor(homedir, &args, input);
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    assert_status_code(&output, expected_code);
    if let Some(expected_success) = expected_success {
        assert_eq!(output.status.success(), expected_success, "{output:?}");
    }
}

fn success_for(command: &str, success: bool) -> Option<bool> {
    if command == "check" {
        None
    } else {
        Some(success)
    }
}

fn run_pyzor(homedir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruzor"))
        .arg("--homedir")
        .arg(homedir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Rust ruzor client");
    child
        .stdin
        .as_mut()
        .expect("Rust client stdin")
        .write_all(input.as_bytes())
        .expect("write Rust client stdin");
    child.wait_with_output().expect("wait Rust client")
}

fn assert_status_code(output: &Output, expected_code: i64) {
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

fn spawn_pyzord_process(homedir: &Path, port: u16) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ruzord"))
        .arg("--homedir")
        .arg(homedir)
        .arg("--password-file")
        .arg("ruzord.passwd")
        .arg("--access-file")
        .arg("ruzord.access")
        .arg("--dsn")
        .arg(homedir.join("ruzord.db"))
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Rust pyzord process")
}

fn wait_for_process_server(server: &mut Child, address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..50 {
        if let Some(status) = server.try_wait().expect("poll ruzord process") {
            panic!("ruzord exited before readiness: {status}");
        }
        if client.ping(address).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("ruzord did not become ready on {}:{}", address.0, address.1);
}

fn stop_process(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn write_common_homedir(homedir: &Path, port: u16) {
    std::fs::write(homedir.join("servers"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(
        homedir.join("alice"),
        format!(
            "127.0.0.1 : {port} : alice : d28f86151e80a9accba4a4eba81c460532384cd6,fc7f1cad729b5f3862b2ef192e2d9e0d0d4bd515\n"
        ),
    )
    .unwrap();
    std::fs::write(
        homedir.join("bob"),
        format!(
            "127.0.0.1 : {port} : bob : de6ef568787256bf5f55909dc0c398e49b5c9808,cf88277c5d4abdc0a3f56f416011966d04a3f462\n"
        ),
    )
    .unwrap();
    std::fs::write(
        homedir.join("chuck"),
        format!(
            "127.0.0.1 : {port} : bob : de6ef568787256bf5f55909dc0c398e49b5c9808,af88277c5d4abdc0a3f56f416011966d04a3f462\n"
        ),
    )
    .unwrap();
    std::fs::write(
        homedir.join("dan"),
        format!(
            "127.0.0.1 : {port} : dan : 1cc2efa77d8833d83556e0cc4fa617c64eebc7fb,c1a50281fc43e860fe78c16c73b9618ada59f959\n"
        ),
    )
    .unwrap();
}

fn reference_passwd_file() -> &'static str {
    "alice : fc7f1cad729b5f3862b2ef192e2d9e0d0d4bd515
     bob : cf88277c5d4abdc0a3f56f416011966d04a3f462
     dan : c1a50281fc43e860fe78c16c73b9618ada59f959
"
}

fn reference_access_file() -> &'static str {
    "check report ping pong info whitelist : alice : deny
     check report ping pong info whitelist : bob : allow
     ALL : dan : allow
     pong info whitelist : dan : deny
"
}

fn reference_passwd() -> HashMap<String, String> {
    HashMap::from([
        (
            "alice".to_string(),
            "fc7f1cad729b5f3862b2ef192e2d9e0d0d4bd515".to_string(),
        ),
        (
            "bob".to_string(),
            "cf88277c5d4abdc0a3f56f416011966d04a3f462".to_string(),
        ),
        (
            "dan".to_string(),
            "c1a50281fc43e860fe78c16c73b9618ada59f959".to_string(),
        ),
    ])
}

fn reference_access() -> HashMap<String, HashSet<String>> {
    let all = all_ops();
    let mut acl = HashMap::new();
    acl.insert("alice".to_string(), HashSet::new());
    acl.insert("bob".to_string(), all.clone());
    acl.insert(
        "dan".to_string(),
        ["check", "report", "ping"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    );
    acl
}

fn default_anonymous_access() -> HashMap<String, HashSet<String>> {
    let mut acl = HashMap::new();
    acl.insert(
        "anonymous".to_string(),
        ["check", "report", "ping", "pong", "info"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    );
    acl
}

fn all_ops() -> HashSet<String> {
    ["check", "report", "ping", "pong", "info", "whitelist"]
        .into_iter()
        .map(str::to_string)
        .collect()
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
