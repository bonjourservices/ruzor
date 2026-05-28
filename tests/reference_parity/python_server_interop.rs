use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ruzor::client::Client;
use ruzor::config::Address;

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn rust_client_talks_to_python_server_process() {
    let digest = "7421216f915a87e02da034cc483f5c876e1a1338";
    let homedir = temp_homedir("rust-client-python-server");
    let access = homedir.join("pyzord.access");
    let passwd = homedir.join("pyzord.passwd");
    std::fs::write(&access, "ALL : anonymous : allow\n").unwrap();
    std::fs::write(&passwd, "").unwrap();
    let port = free_udp_port();
    let address: Address = ("127.0.0.1".to_string(), port);

    let mut server = Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .arg("-c")
        .arg(PYTHON_SERVER)
        .arg(port.to_string())
        .arg(&passwd)
        .arg(&access)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Python pyzord server");

    wait_for_python_server(&mut server, &address);

    let client = Client::new(HashMap::new(), Some(2), ruzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.report(digest, &address).unwrap().is_ok());
    let response = client.check(digest, &address).unwrap();
    assert_eq!(response.get("Count"), Some("1"));
    assert_eq!(response.get("WL-Count"), Some("0"));

    assert!(client.whitelist(digest, &address).unwrap().is_ok());
    let response = client.check(digest, &address).unwrap();
    assert_eq!(response.get("Count"), Some("1"));
    assert_eq!(response.get("WL-Count"), Some("1"));

    stop(server);
    let _ = std::fs::remove_dir_all(homedir);
}

const PYTHON_SERVER: &str = r#"
import sys
import pyzor.server

port = int(sys.argv[1])
passwd = sys.argv[2]
access = sys.argv[3]
server = pyzor.server.Server(("127.0.0.1", port), {}, passwd, access)
server.serve_forever()
"#;

fn wait_for_python_server(server: &mut Child, address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..50 {
        if let Some(status) = server.try_wait().expect("poll Python pyzord") {
            panic!("Python pyzord exited before readiness: {status}");
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
    panic!(
        "Python pyzord did not become ready on {}:{}",
        address.0, address.1
    );
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
