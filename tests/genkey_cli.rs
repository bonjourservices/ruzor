use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn genkey_generates_hex_salt_and_key_after_confirmation() {
    let homedir = temp_homedir("genkey-success");
    let output = run_pyzor_genkey(&homedir, "secret\nsecret\n");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "Enter passphrase: Enter passphrase again: "
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "salt,key:");
    let (salt, key) = lines[1].split_once(',').unwrap();
    assert_is_sha1_hex(salt);
    assert_is_sha1_hex(key);

    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn genkey_rejects_mismatched_confirmation() {
    let homedir = temp_homedir("genkey-mismatch");
    let output = run_pyzor_genkey(&homedir, "secret\nother\n");

    assert!(!output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "Enter passphrase: Enter passphrase again: Passwords do not match.\n"
    );

    let _ = std::fs::remove_dir_all(homedir);
}

fn run_pyzor_genkey(homedir: &std::path::Path, input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pyzor"))
        .arg("--homedir")
        .arg(homedir)
        .arg("genkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Rust pyzor genkey");
    child
        .stdin
        .as_mut()
        .expect("genkey stdin")
        .write_all(input.as_bytes())
        .expect("write genkey stdin");
    child.wait_with_output().expect("wait genkey")
}

fn assert_is_sha1_hex(value: &str) {
    assert_eq!(value.len(), 40);
    assert!(value.chars().all(|ch| ch.is_ascii_hexdigit()));
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
