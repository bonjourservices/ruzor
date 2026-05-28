use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn pyzord_help_matches_python_optparse_and_exits_before_homedir() {
    let root = temp_dir("help");
    let homedir = root.join("server-home");

    let output = run_pyzord(&homedir, &["--help"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("Usage: ruzord [options]\n\nListen for and process"));
    assert!(stdout.contains("  -h, --help            show this help message and exit"));
    assert!(stdout.contains("  --detach=DETACH       daemonizes the server"));
    assert!(stdout.contains("  -V, --version         print version and exit"));
    assert!(
        !homedir.exists(),
        "pyzord help should exit before creating homedir"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pyzord_unknown_option_uses_optparse_error_status_and_does_not_create_homedir() {
    let root = temp_dir("unknown-option");
    let homedir = root.join("server-home");

    let output = run_pyzord(&homedir, &["--bogus"]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "Usage: ruzord [options]\n\nruzord: error: no such option: --bogus\n"
    );
    assert!(
        !homedir.exists(),
        "pyzord parse errors should exit before creating homedir"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pyzord_version_prints_invoked_program_to_stderr_like_python() {
    let root = temp_dir("version");
    let homedir = root.join("server-home");

    let output = run_pyzord(&homedir, &["--version"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("{} {}\n", env!("CARGO_BIN_EXE_ruzord"), ruzor::VERSION)
    );
    assert!(
        !homedir.exists(),
        "pyzord should exit before creating homedir"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pyzord_positional_args_print_help_and_exit_success_like_python() {
    let root = temp_dir("positional-args");
    let homedir = root.join("server-home");

    let output = run_pyzord(&homedir, &["unexpected"]);

    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: ruzord [options]"));
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    assert!(
        !homedir.exists(),
        "pyzord should exit before creating homedir"
    );

    let _ = std::fs::remove_dir_all(root);
}

fn run_pyzord(homedir: &Path, extra_args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ruzord"))
        .arg("--homedir")
        .arg(homedir)
        .args(extra_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run Rust pyzord")
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "pyzor-pyzord-cli-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
