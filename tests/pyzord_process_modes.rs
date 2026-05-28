use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyzor::client::Client;
use pyzor::config::Address;

const DIGEST: &str = "7421216f915a87e02da034cc483f5c876e1a1338";

#[test]
fn gdbm_thread_modes_match_python_functional_matrix() {
    for (name, args) in [
        ("gdbm-threads", vec!["--threads", "true"]),
        (
            "gdbm-max-threads",
            vec!["--threads", "true", "--max-threads", "10"],
        ),
    ] {
        let homedir = temp_homedir(name);
        std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
        std::fs::write(homedir.join("passwd"), "").unwrap();
        let port = free_udp_port();
        let address: Address = ("127.0.0.1".to_string(), port);
        let mut command = Command::new(env!("CARGO_BIN_EXE_pyzord"));
        command
            .arg("--homedir")
            .arg(&homedir)
            .arg("--password-file")
            .arg("passwd")
            .arg("--access-file")
            .arg("access")
            .arg("--dsn")
            .arg(homedir.join("pyzord.db"))
            .arg("-a")
            .arg("127.0.0.1")
            .arg("-p")
            .arg(port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for arg in args {
            command.arg(arg);
        }
        let mut server = command.spawn().expect("spawn threaded pyzord");

        wait_for_server(&mut server, &address);
        let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
        assert!(client.ping(&address).unwrap().is_ok());
        assert!(client.report(DIGEST, &address).unwrap().is_ok());
        assert!(client.report(DIGEST, &address).unwrap().is_ok());
        assert!(client.whitelist(DIGEST, &address).unwrap().is_ok());
        let response = client.check(DIGEST, &address).unwrap();
        assert_eq!(response.get("Count"), Some("2"));
        assert_eq!(response.get("WL-Count"), Some("1"));

        stop(server);
        let _ = std::fs::remove_dir_all(homedir);
    }
}

#[test]
fn processes_option_falls_back_for_file_backend_like_python() {
    let homedir = temp_homedir("process-fallback");
    std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    std::fs::write(homedir.join("passwd"), "").unwrap();
    let port = free_udp_port();
    let address: Address = ("127.0.0.1".to_string(), port);
    let mut server = Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .arg("--homedir")
        .arg(&homedir)
        .arg("--password-file")
        .arg("passwd")
        .arg("--access-file")
        .arg("access")
        .arg("--dsn")
        .arg(homedir.join("pyzord.db"))
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
        .expect("spawn pyzord with process option fallback");

    wait_for_server(&mut server, &address);
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.report(DIGEST, &address).unwrap().is_ok());
    let response = client.check(DIGEST, &address).unwrap();
    assert_eq!(response.get("Count"), Some("1"));
    assert_eq!(response.get("WL-Count"), Some("0"));

    stop(server);
    let _ = std::fs::remove_dir_all(homedir);
}

fn wait_for_server(server: &mut Child, address: &Address) {
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

fn temp_homedir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pyzor-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}
