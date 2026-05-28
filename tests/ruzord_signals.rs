#![cfg(unix)]

use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ruzor::client::Client;
use ruzor::config::Address;

const DIGEST: &str = "7421216f915a87e02da034cc483f5c876e1a1338";
const SIGTERM: i32 = 15;
#[cfg(target_os = "macos")]
const SIGUSR1: i32 = 30;
#[cfg(not(target_os = "macos"))]
const SIGUSR1: i32 = 10;

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[test]
fn sigusr1_reloads_access_file() {
    let homedir = temp_homedir("sigusr1-reload");
    let access = homedir.join("access");
    std::fs::write(&access, "check report ping pong info : anonymous : allow\n").unwrap();
    std::fs::write(homedir.join("passwd"), "").unwrap();
    let port = free_udp_port();
    let db_path = homedir.join("ruzord.db");
    let address: Address = ("127.0.0.1".to_string(), port);
    let mut server = spawn_server(&homedir, &access, &db_path, port, false);
    wait_for_server(&mut server, &address);

    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    let denied = client.whitelist(DIGEST, &address).unwrap();
    assert_eq!(denied.get("Code"), Some("403"));

    std::fs::write(&access, "ALL : anonymous : allow\n").unwrap();
    send_signal(server.id(), SIGUSR1);
    wait_for_whitelist_allowed(&client, &address);

    terminate(server);
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn sigterm_shuts_down_and_removes_detach_pidfile() {
    let homedir = temp_homedir("sigterm-pidfile");
    let access = homedir.join("access");
    std::fs::write(&access, "ALL : anonymous : allow\n").unwrap();
    std::fs::write(homedir.join("passwd"), "").unwrap();
    let port = free_udp_port();
    let db_path = homedir.join("ruzord.db");
    let pidfile = homedir.join("ruzord.pid");
    let log_path = homedir.join("ruzord.log");
    let address: Address = ("127.0.0.1".to_string(), port);
    let mut launcher = spawn_server(&homedir, &access, &db_path, port, true);
    let launcher_pid = launcher.id();
    let launcher_status = wait_for_exit(&mut launcher);
    assert!(launcher_status.success(), "{launcher_status}");

    let daemon_pid = wait_for_pidfile(&pidfile);
    assert_ne!(daemon_pid, launcher_pid);
    wait_for_server_detached(&address);
    wait_for_log_contains(&log_path, "listening on 127.0.0.1");

    send_signal(daemon_pid, SIGTERM);
    wait_for_pidfile_removed(&pidfile);

    let _ = std::fs::remove_dir_all(homedir);
}

fn spawn_server(homedir: &Path, access: &Path, db_path: &Path, port: u16, detach: bool) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ruzord"));
    command
        .arg("--homedir")
        .arg(homedir)
        .arg("--password-file")
        .arg("passwd")
        .arg("--access-file")
        .arg(access)
        .arg("--dsn")
        .arg(db_path)
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if detach {
        command.arg("--detach").arg(homedir.join("ruzord.log"));
    }
    command.spawn().expect("spawn Rust pyzord")
}

fn wait_for_server(server: &mut Child, address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..50 {
        if let Some(status) = server.try_wait().expect("poll ruzord") {
            panic!("ruzord exited before readiness: {status}");
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
    panic!("ruzord did not become ready on {}:{}", address.0, address.1);
}

fn wait_for_server_detached(address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..50 {
        if client
            .ping(address)
            .map(|response| response.is_ok())
            .unwrap_or(false)
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "detached ruzord did not become ready on {}:{}",
        address.0, address.1
    );
}

fn wait_for_pidfile(pidfile: &Path) -> u32 {
    for _ in 0..50 {
        if let Ok(text) = std::fs::read_to_string(pidfile) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                return pid;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("pidfile was not written: {}", pidfile.display());
}

fn wait_for_pidfile_removed(pidfile: &Path) {
    for _ in 0..50 {
        if !pidfile.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("pidfile was not removed: {}", pidfile.display());
}

fn wait_for_log_contains(path: &Path, needle: &str) {
    for _ in 0..50 {
        if std::fs::read_to_string(path)
            .map(|text| text.contains(needle))
            .unwrap_or(false)
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("log did not contain {needle:?}: {}", path.display());
}

fn wait_for_whitelist_allowed(client: &Client, address: &Address) {
    for _ in 0..50 {
        if client
            .whitelist(DIGEST, address)
            .map(|response| response.is_ok())
            .unwrap_or(false)
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("pyzord did not reload ACL after SIGUSR1");
}

fn terminate(mut child: Child) {
    send_signal(child.id(), SIGTERM);
    if wait_for_exit(&mut child).success() {
        return;
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    for _ in 0..50 {
        if let Some(status) = child.try_wait().expect("poll ruzord exit") {
            return status;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("pyzord did not exit after SIGTERM");
}

fn send_signal(pid: u32, signal: i32) {
    // SAFETY: Calls POSIX kill with a child pid owned by this test process.
    let result = unsafe { kill(pid as i32, signal) };
    assert_eq!(result, 0, "kill({pid}, {signal}) failed");
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn temp_homedir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pyzor-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}
