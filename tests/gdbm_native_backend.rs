#![cfg(feature = "backend-gdbm")]

use std::collections::HashMap;
use std::env;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ruzor::client::Client;
use ruzor::config::Address;
use ruzor::engines::DigestDatabase;
use ruzor::gdbm_engine::GdbmDatabase;

const DIGEST: &str = "7421216f915a87e02da034cc483f5c876e1a1338";

#[test]
fn native_gdbm_reads_python_dbm_gnu_records_and_writes_python_record_strings() {
    let path = temp_database_path("interop");
    python_gdbm_set(
        &path,
        DIGEST,
        "1,24,2014-05-16 06:29:46,2014-05-16 06:29:54,42,None,None",
    );

    crate_utc(|| {
        let mut db = GdbmDatabase::open(&path).unwrap();
        let record = db.get(DIGEST).unwrap();
        assert_eq!(record.r_count, 24);
        assert_eq!(record.wl_count, 42);
        db.report(&[DIGEST.to_string()]).unwrap();
    });

    let value = python_gdbm_get(&path, DIGEST);
    assert!(
        value.starts_with("1,25,2014-05-16 06:29:46,"),
        "unexpected gdbm value: {value}"
    );
    assert!(
        value.contains(",42,None,None"),
        "unexpected gdbm value: {value}"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn pyzord_uses_native_gdbm_backend_file() {
    let path = temp_database_path("server");
    let mut server = PyzordProcess::start("native-gdbm", &path);
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    assert!(client.whitelist(DIGEST, &server.address).unwrap().is_ok());

    let response = client.check(DIGEST, &server.address).unwrap();
    assert_eq!(response.get("Count"), Some("2"));
    assert_eq!(response.get("WL-Count"), Some("1"));

    drop(server);
    let value = python_gdbm_get(&path, DIGEST);
    assert!(value.starts_with("1,2,"), "unexpected gdbm value: {value}");
    assert!(value.contains(",1,"), "unexpected gdbm value: {value}");
    let _ = std::fs::remove_file(path);
}

#[test]
fn pyzord_preserves_existing_python_gdbm_database_file() {
    let path = temp_database_path("existing-python-db");
    python_gdbm_set(&path, DIGEST, "1,7,None,None,0,None,None");

    let mut server = PyzordProcess::start("native-gdbm-existing", &path);
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());

    drop(server);
    let value = python_gdbm_get(&path, DIGEST);
    assert!(
        value.starts_with("1,8,"),
        "unexpected gdbm value after report: {value}"
    );
    let _ = std::fs::remove_file(path);
}

fn python_gdbm_set(path: &Path, digest: &str, value: &str) {
    let script = r#"
import dbm.gnu
import sys
db = dbm.gnu.open(sys.argv[1], "c")
db[sys.argv[2]] = sys.argv[3].encode("utf8")
db.close()
"#;
    run_python(script, &[path.to_string_lossy().as_ref(), digest, value]);
}

fn python_gdbm_get(path: &Path, digest: &str) -> String {
    let script = r#"
import dbm.gnu
import sys
db = dbm.gnu.open(sys.argv[1], "r")
sys.stdout.write(db[sys.argv[2]].decode("utf8"))
db.close()
"#;
    run_python(script, &[path.to_string_lossy().as_ref(), digest])
}

fn run_python(script: &str, args: &[&str]) -> String {
    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run python dbm.gnu helper");
    assert!(
        output.status.success(),
        "python dbm.gnu helper failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

static TZ_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn crate_utc(run: impl FnOnce()) {
    let _guard = TZ_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let old_tz = env::var_os("TZ");
    // SAFETY: crate_utc serializes TZ mutation with TZ_TEST_LOCK for this test binary.
    unsafe {
        env::set_var("TZ", "UTC");
    }
    run();
    if let Some(value) = old_tz {
        // SAFETY: crate_utc serializes TZ mutation with TZ_TEST_LOCK for this test binary.
        unsafe { env::set_var("TZ", value) };
    } else {
        // SAFETY: crate_utc serializes TZ mutation with TZ_TEST_LOCK for this test binary.
        unsafe { env::remove_var("TZ") };
    }
}

struct PyzordProcess {
    child: Child,
    address: Address,
    homedir: PathBuf,
}

impl PyzordProcess {
    fn start(name: &str, db_path: &Path) -> Self {
        let homedir = temp_dir(name);
        std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
        std::fs::write(homedir.join("passwd"), "").unwrap();
        let port = free_udp_port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_ruzord"));
        command
            .arg("--homedir")
            .arg(&homedir)
            .arg("--password-file")
            .arg("passwd")
            .arg("--access-file")
            .arg("access")
            .arg("-e")
            .arg("gdbm")
            .arg("--dsn")
            .arg(db_path)
            .arg("-a")
            .arg("127.0.0.1")
            .arg("-p")
            .arg(port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().expect("spawn ruzord with native gdbm");
        Self {
            child,
            address: ("127.0.0.1".to_string(), port),
            homedir,
        }
    }
}

impl Drop for PyzordProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.homedir);
    }
}

fn wait_for_process_server(server: &mut Child, address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..100 {
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

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn temp_dir(name: &str) -> PathBuf {
    let path = env::temp_dir().join(format!(
        "pyzor-{name}-{}-{}",
        std::process::id(),
        unique_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn temp_database_path(name: &str) -> PathBuf {
    env::temp_dir().join(format!(
        "pyzor-native-gdbm-{name}-{}-{}.db",
        std::process::id(),
        unique_nanos()
    ))
}

fn unique_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
