use std::collections::HashMap;
use std::io::Write;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyzor::client::Client;
use pyzor::config::Address;

const MSG: &str = "Newsgroups:
Date: Wed, 10 Apr 2002 22:23:51 -0400 (EDT)
From: Frank Tobin <ftobin@neverending.org>
MIME-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII

Test Email
";

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn python_client_talks_to_rust_server_process() {
    let homedir = temp_homedir("python-client-rust-server");
    std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
    let port = free_udp_port();
    std::fs::write(homedir.join("servers"), format!("127.0.0.1:{port}\n")).unwrap();
    let db_path = homedir.join("pyzord.db");

    let mut server = Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .arg("--homedir")
        .arg(&homedir)
        .arg("--access-file")
        .arg("access")
        .arg("--dsn")
        .arg(&db_path)
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Rust pyzord");

    let address = ("127.0.0.1".to_string(), port);
    wait_for_server(&mut server, &address);

    let report = run_python_client(&homedir, "report", MSG);
    assert!(report.status.success(), "report failed: {report:?}");
    assert_eq!(String::from_utf8(report.stderr).unwrap(), "");
    let report_stdout = String::from_utf8(report.stdout).unwrap();
    assert!(report_stdout.contains("(200, 'OK')"), "{report_stdout:?}");

    let check = run_python_client(&homedir, "check", MSG);
    assert!(check.status.success(), "check failed: {check:?}");
    assert_eq!(String::from_utf8(check.stderr).unwrap(), "");
    let check_stdout = String::from_utf8(check.stdout).unwrap();
    assert!(
        check_stdout.contains("(200, 'OK')\t1\t0"),
        "{check_stdout:?}"
    );

    let python_info = run_python_client(&homedir, "info", MSG);
    assert!(
        python_info.status.success(),
        "python info failed: {python_info:?}"
    );
    assert_eq!(String::from_utf8(python_info.stderr.clone()).unwrap(), "");
    let rust_info = run_rust_client(&homedir, "info", MSG);
    assert!(
        rust_info.status.success(),
        "rust info failed: {rust_info:?}"
    );
    assert_eq!(String::from_utf8(rust_info.stderr.clone()).unwrap(), "");
    assert_eq!(rust_info.stdout, python_info.stdout);

    stop(server);
    let _ = std::fs::remove_dir_all(homedir);
}

fn run_python_client(
    homedir: &std::path::Path,
    command: &str,
    input: &str,
) -> std::process::Output {
    let mut child = Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .arg("reference/pyzor/scripts/pyzor")
        .arg("--homedir")
        .arg(homedir)
        .arg("-t")
        .arg("2")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Python pyzor client");
    child
        .stdin
        .as_mut()
        .expect("Python client stdin")
        .write_all(input.as_bytes())
        .expect("write Python client stdin");
    child.wait_with_output().expect("wait Python client")
}

fn run_rust_client(homedir: &std::path::Path, command: &str, input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pyzor"))
        .arg("--homedir")
        .arg(homedir)
        .arg("-t")
        .arg("2")
        .arg(command)
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
