#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const MSG: &str = "Subject: umask parity\n\nTest message\n";

#[test]
fn pyzor_creates_homedir_and_local_whitelist_with_private_permissions_like_python() {
    let root = temp_dir("client");
    let homedir = root.join("client-home");

    let mut child = Command::new(env!("CARGO_BIN_EXE_pyzor"))
        .arg("--homedir")
        .arg(&homedir)
        .arg("local_whitelist")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pyzor");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(MSG.as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("wait pyzor");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(mode(&homedir), 0o700);
    assert_eq!(mode(&homedir.join("whitelist")), 0o600);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pyzord_creates_homedir_with_private_permissions_like_python_before_config_errors() {
    let root = temp_dir("server");
    let homedir = root.join("server-home");

    let output = Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .arg("--homedir")
        .arg(&homedir)
        .args(["-e", "bogus"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run pyzord");

    assert!(!output.status.success(), "{output:?}");
    assert_eq!(mode(&homedir), 0o700);

    let _ = std::fs::remove_dir_all(root);
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("pyzor-umask-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}
