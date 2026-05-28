use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyzor::client::{BatchClient, Client};

use pyzor::config::Address;
#[cfg(unix)]
const SIGTERM: i32 = 15;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

const DIGEST: &str = "7421216f915a87e02da034cc483f5c876e1a1338";
const PONG_DIGEST: &str = "0000000000000000000000000000000000000201";
const CHECK_DIGEST: &str = "0000000000000000000000000000000000000202";
const REPORT_UPDATE_DIGEST: &str = "0000000000000000000000000000000000000203";
const WHITELIST_UPDATE_DIGEST: &str = "0000000000000000000000000000000000000204";
const COMBINED_UPDATE_DIGEST: &str = "0000000000000000000000000000000000000205";

#[test]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_uses_redis_v1_backend() {
    let redis = RedisContainer::start("v1");
    let mut server = PyzordProcess::start("redis-v1", "redis", &redis.dsn());
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    assert!(client.whitelist(DIGEST, &server.address).unwrap().is_ok());

    let response = client.check(DIGEST, &server.address).unwrap();
    assert_eq!(response.get("Count"), Some("2"));
    assert_eq!(response.get("WL-Count"), Some("1"));
}

#[test]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_redis_core_functional_mixin_matches_python() {
    let redis = RedisContainer::start("core-functional");
    let mut server = PyzordProcess::start("redis-core-functional", "redis", &redis.dsn());
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.ping(&server.address).unwrap().is_ok());

    let pong = client.pong(PONG_DIGEST, &server.address).unwrap();
    assert!(pong.is_ok());
    assert_message_counts(&pong, (isize::MAX as i64, 0));

    let fresh_check = client.check(CHECK_DIGEST, &server.address).unwrap();
    assert!(fresh_check.is_ok());
    assert_message_counts(&fresh_check, (0, 0));
    let fresh_info = client.info(CHECK_DIGEST, &server.address).unwrap();
    assert_message_counts(&fresh_info, (0, 0));

    assert!(
        client
            .report(REPORT_UPDATE_DIGEST, &server.address)
            .unwrap()
            .is_ok()
    );
    assert_digest_counts(&client, &server.address, REPORT_UPDATE_DIGEST, (1, 0));
    thread::sleep(Duration::from_millis(1_100));
    assert!(
        client
            .report(REPORT_UPDATE_DIGEST, &server.address)
            .unwrap()
            .is_ok()
    );
    assert_digest_counts(&client, &server.address, REPORT_UPDATE_DIGEST, (2, 0));
    let report_info = client.info(REPORT_UPDATE_DIGEST, &server.address).unwrap();
    assert_message_counts(&report_info, (2, 0));
    assert_distinct_info_timestamps(&report_info, "Entered", "Updated");

    assert!(
        client
            .whitelist(WHITELIST_UPDATE_DIGEST, &server.address)
            .unwrap()
            .is_ok()
    );
    assert_digest_counts(&client, &server.address, WHITELIST_UPDATE_DIGEST, (0, 1));
    thread::sleep(Duration::from_millis(1_100));
    assert!(
        client
            .whitelist(WHITELIST_UPDATE_DIGEST, &server.address)
            .unwrap()
            .is_ok()
    );
    assert_digest_counts(&client, &server.address, WHITELIST_UPDATE_DIGEST, (0, 2));
    let whitelist_info = client
        .info(WHITELIST_UPDATE_DIGEST, &server.address)
        .unwrap();
    assert_message_counts(&whitelist_info, (0, 2));
    assert_distinct_info_timestamps(&whitelist_info, "WL-Entered", "WL-Updated");

    assert!(
        client
            .whitelist(COMBINED_UPDATE_DIGEST, &server.address)
            .unwrap()
            .is_ok()
    );
    assert!(
        client
            .report(COMBINED_UPDATE_DIGEST, &server.address)
            .unwrap()
            .is_ok()
    );
    assert_digest_counts(&client, &server.address, COMBINED_UPDATE_DIGEST, (1, 1));
    thread::sleep(Duration::from_millis(1_100));
    assert!(
        client
            .whitelist(COMBINED_UPDATE_DIGEST, &server.address)
            .unwrap()
            .is_ok()
    );
    assert!(
        client
            .report(COMBINED_UPDATE_DIGEST, &server.address)
            .unwrap()
            .is_ok()
    );
    assert_digest_counts(&client, &server.address, COMBINED_UPDATE_DIGEST, (2, 2));
    let combined_info = client
        .info(COMBINED_UPDATE_DIGEST, &server.address)
        .unwrap();
    assert_message_counts(&combined_info, (2, 2));
    assert_distinct_info_timestamps(&combined_info, "Entered", "Updated");
    assert_distinct_info_timestamps(&combined_info, "WL-Entered", "WL-Updated");
}

#[test]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_uses_redis_v0_backend() {
    let redis = RedisContainer::start("v0");
    let mut server = PyzordProcess::start("redis-v0", "redis_v0", &redis.dsn());
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    assert!(client.whitelist(DIGEST, &server.address).unwrap().is_ok());

    let response = client.check(DIGEST, &server.address).unwrap();
    assert_eq!(response.get("Count"), Some("1"));
    assert_eq!(response.get("WL-Count"), Some("1"));
}

#[test]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_threads_use_redis_backend_workers() {
    assert_redis_worker_mode("redis-threads", &["--threads", "true"]);
}

#[test]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_max_threads_use_redis_backend_workers() {
    assert_redis_worker_mode(
        "redis-max-threads",
        &["--threads", "true", "--max-threads", "10"],
    );
}

#[test]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_redis_batched_functional_matrix_matches_python() {
    let redis = RedisContainer::start("batched");
    let mut server1 = PyzordProcess::start("redis-batched-primary", "redis", &redis.dsn());
    let mut server2 = PyzordProcess::start("redis-batched-secondary", "redis", &redis.dsn());
    wait_for_process_server(&mut server1.child, &server1.address);
    wait_for_process_server(&mut server2.child, &server2.address);

    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());

    let report_digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    let mut batch = BatchClient::new(client.clone(), 10);
    for _ in 0..9 {
        batch.report(report_digest, &server1.address).unwrap();
    }
    assert_digest_counts(&client, &server1.address, report_digest, (0, 0));
    batch.report(report_digest, &server1.address).unwrap();
    assert_digest_counts(&client, &server1.address, report_digest, (10, 0));

    let whitelist_digest = "da39a3ee5e6b4b0d3255bfef95601890afd80708";
    let mut batch = BatchClient::new(client.clone(), 10);
    for _ in 0..9 {
        batch.whitelist(whitelist_digest, &server1.address).unwrap();
    }
    assert_digest_counts(&client, &server1.address, whitelist_digest, (0, 0));
    batch.whitelist(whitelist_digest, &server1.address).unwrap();
    assert_digest_counts(&client, &server1.address, whitelist_digest, (0, 10));

    let combined_digest = "da39a3ee5e6b4b0d3255bfef95601890afd80707";
    let mut batch = BatchClient::new(client.clone(), 10);
    for _ in 0..9 {
        batch.report(combined_digest, &server1.address).unwrap();
        batch.whitelist(combined_digest, &server1.address).unwrap();
    }
    assert_digest_counts(&client, &server1.address, combined_digest, (0, 0));
    batch.report(combined_digest, &server1.address).unwrap();
    assert_digest_counts(&client, &server1.address, combined_digest, (10, 0));
    batch.whitelist(combined_digest, &server1.address).unwrap();
    assert_digest_counts(&client, &server1.address, combined_digest, (10, 10));

    let report_digests = numbered_digests("a39a3ee5e6b4b0d3255bfef95601890afd80706");
    let mut batch = BatchClient::new(client.clone(), 10);
    for digest in &report_digests {
        batch.report(digest, &server1.address).unwrap();
    }
    for digest in &report_digests {
        assert_digest_counts(&client, &server1.address, digest, (1, 0));
    }

    let whitelist_digests = numbered_digests("a39a3ee5e6b4b0d3255bfef95601890afd80705");
    let mut batch = BatchClient::new(client.clone(), 10);
    for digest in &whitelist_digests {
        batch.whitelist(digest, &server1.address).unwrap();
    }
    for digest in &whitelist_digests {
        assert_digest_counts(&client, &server1.address, digest, (0, 1));
    }

    let address_report_digest1 = "da39a3ee5e6b4b0d3255bfef95601890afd80704";
    let address_report_digest2 = "da39a3ee5e6b4b0d3255bfef95601890afd80703";
    let mut batch = BatchClient::new(client.clone(), 10);
    for _ in 0..9 {
        batch
            .report(address_report_digest1, &server1.address)
            .unwrap();
        batch
            .report(address_report_digest2, &server2.address)
            .unwrap();
    }
    assert_digest_counts(&client, &server1.address, address_report_digest1, (0, 0));
    assert_digest_counts(&client, &server2.address, address_report_digest2, (0, 0));
    batch
        .report(address_report_digest1, &server1.address)
        .unwrap();
    assert_digest_counts(&client, &server1.address, address_report_digest1, (10, 0));
    assert_digest_counts(&client, &server2.address, address_report_digest2, (0, 0));
    batch
        .report(address_report_digest2, &server2.address)
        .unwrap();
    assert_digest_counts(&client, &server2.address, address_report_digest2, (10, 0));

    let address_whitelist_digest1 = "da39a3ee5e6b4b0d3255bfef95601890afd80702";
    let address_whitelist_digest2 = "da39a3ee5e6b4b0d3255bfef95601890afd80701";
    let mut batch = BatchClient::new(client.clone(), 10);
    for _ in 0..9 {
        batch
            .whitelist(address_whitelist_digest1, &server1.address)
            .unwrap();
        batch
            .whitelist(address_whitelist_digest2, &server2.address)
            .unwrap();
    }
    assert_digest_counts(&client, &server1.address, address_whitelist_digest1, (0, 0));
    assert_digest_counts(&client, &server2.address, address_whitelist_digest2, (0, 0));
    batch
        .whitelist(address_whitelist_digest1, &server1.address)
        .unwrap();
    assert_digest_counts(
        &client,
        &server1.address,
        address_whitelist_digest1,
        (0, 10),
    );
    assert_digest_counts(&client, &server2.address, address_whitelist_digest2, (0, 0));
    batch
        .whitelist(address_whitelist_digest2, &server2.address)
        .unwrap();
    assert_digest_counts(
        &client,
        &server2.address,
        address_whitelist_digest2,
        (0, 10),
    );
}

fn numbered_digests(suffix: &str) -> Vec<String> {
    (0..10).map(|i| format!("{i}{suffix}")).collect()
}

fn assert_redis_worker_mode(name: &str, extra_args: &[&str]) {
    let redis = RedisContainer::start(name);
    let mut server = PyzordProcess::start_with_args(name, "redis", &redis.dsn(), extra_args);
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..3 {
        assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    }
    assert!(client.whitelist(DIGEST, &server.address).unwrap().is_ok());
    assert_digest_counts(&client, &server.address, DIGEST, (3, 1));
}

fn assert_digest_counts(client: &Client, address: &Address, digest: &str, expected: (i64, i64)) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut last = None;
    while std::time::Instant::now() < deadline {
        let response = client.check(digest, address).unwrap();
        let counts = (
            response.get("Count").unwrap().parse::<i64>().unwrap(),
            response.get("WL-Count").unwrap().parse::<i64>().unwrap(),
        );
        if counts == expected {
            return;
        }
        last = Some(counts);
        thread::sleep(Duration::from_millis(20));
    }
    panic!("digest {digest} at {address:?} had counts {last:?}, expected {expected:?}");
}

fn assert_message_counts(response: &pyzor::message::Message, expected: (i64, i64)) {
    assert_eq!(
        (
            response.get("Count").unwrap().parse::<i64>().unwrap(),
            response.get("WL-Count").unwrap().parse::<i64>().unwrap(),
        ),
        expected
    );
}

fn assert_distinct_info_timestamps(
    response: &pyzor::message::Message,
    entered_key: &str,
    updated_key: &str,
) {
    let entered = response.get(entered_key).unwrap();
    let updated = response.get(updated_key).unwrap();

    assert_ne!(entered, "0");
    assert_ne!(updated, "0");
    assert_ne!(entered, updated);
}

#[test]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_redis_v1_cleanup_age_expires_records() {
    assert_cleanup_age_expires("redis-cleanup-v1", "redis");
}

#[test]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_redis_v0_cleanup_age_expires_records() {
    assert_cleanup_age_expires("redis-cleanup-v0", "redis_v0");
}

fn assert_cleanup_age_expires(name: &str, engine: &str) {
    let redis = RedisContainer::start(name);
    let mut server =
        PyzordProcess::start_with_args(name, engine, &redis.dsn(), &["--cleanup-age", "1"]);
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    let response = client.check(DIGEST, &server.address).unwrap();
    assert_eq!(response.get("Count"), Some("1"));

    thread::sleep(Duration::from_secs(2));

    let response = client.check(DIGEST, &server.address).unwrap();
    assert_eq!(response.get("Count"), Some("0"));
    assert_eq!(response.get("WL-Count"), Some("0"));
}

#[test]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_redis_v1_cleanup_age_zero_keeps_records_like_python() {
    let redis = RedisContainer::start("cleanup-zero-v1");
    let mut server = PyzordProcess::start_with_args(
        "redis-cleanup-zero-v1",
        "redis",
        &redis.dsn(),
        &["--cleanup-age", "0"],
    );
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    thread::sleep(Duration::from_secs(1));
    assert_digest_counts(&client, &server.address, DIGEST, (1, 0));
}

#[test]
#[cfg(unix)]
#[ignore = "requires Docker and a Redis image"]
fn pyzord_prefork_uses_redis_backend_workers() {
    let redis = RedisContainer::start("prefork");
    let mut server = PyzordProcess::start_with_args(
        "redis-prefork",
        "redis",
        &redis.dsn(),
        &["--pre-fork", "4"],
    );
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..6 {
        assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    }

    let response = client.check(DIGEST, &server.address).unwrap();
    assert_eq!(response.get("Count"), Some("6"));
    assert_eq!(response.get("WL-Count"), Some("0"));
}

struct PyzordProcess {
    child: Child,
    address: Address,
    homedir: PathBuf,
}

impl PyzordProcess {
    fn start(name: &str, engine: &str, dsn: &str) -> Self {
        Self::start_with_args(name, engine, dsn, &[])
    }

    fn start_with_args(name: &str, engine: &str, dsn: &str, extra_args: &[&str]) -> Self {
        let homedir = temp_dir(name);
        std::fs::write(homedir.join("access"), "ALL : anonymous : allow\n").unwrap();
        std::fs::write(homedir.join("passwd"), "").unwrap();
        let port = free_udp_port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_pyzord"));
        command
            .arg("--homedir")
            .arg(&homedir)
            .arg("--password-file")
            .arg("passwd")
            .arg("--access-file")
            .arg("access")
            .arg("-e")
            .arg(engine)
            .arg("--dsn")
            .arg(dsn)
            .arg("-a")
            .arg("127.0.0.1")
            .arg("-p")
            .arg(port.to_string())
            .args(extra_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().expect("spawn pyzord with Redis backend");
        Self {
            child,
            address: ("127.0.0.1".to_string(), port),
            homedir,
        }
    }
}
impl Drop for PyzordProcess {
    fn drop(&mut self) {
        terminate(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.homedir);
    }
}

struct RedisContainer {
    name: String,
    port: u16,
}

impl RedisContainer {
    fn start(name: &str) -> Self {
        let image =
            std::env::var("PYZOR_REDIS_IMAGE").unwrap_or_else(|_| "redis:8.4.0-alpine".to_string());
        let mut last_error = None;

        for _ in 0..10 {
            let port = free_tcp_port();
            let container_name = format!(
                "pyzor-redis-{name}-{}-{}",
                std::process::id(),
                unique_nanos()
            );
            let publish = format!("127.0.0.1:{port}:6379");
            let output = Command::new("docker")
                .arg("run")
                .arg("--rm")
                .arg("-d")
                .arg("--name")
                .arg(&container_name)
                .arg("-p")
                .arg(publish)
                .arg(&image)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("run Redis container");

            if output.status.success() {
                wait_for_redis(port);
                return Self {
                    name: container_name,
                    port,
                };
            }

            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            let _ = Command::new("docker")
                .arg("rm")
                .arg("-f")
                .arg(&container_name)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let retryable = stderr.contains("address already in use")
                || stderr.contains("port is already allocated");
            last_error = Some(format!("stdout={stdout:?} stderr={stderr:?}"));
            if !retryable {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        panic!(
            "docker run failed after retries: {}",
            last_error.unwrap_or_else(|| "no docker attempts were made".to_string())
        );
    }

    fn dsn(&self) -> String {
        format!("127.0.0.1,{},,0", self.port)
    }
}

impl Drop for RedisContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .arg("rm")
            .arg("-f")
            .arg(&self.name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn wait_for_process_server(server: &mut Child, address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..100 {
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

fn wait_for_redis(port: u16) {
    for _ in 0..100 {
        if redis_ping(port).unwrap_or(false) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("Redis did not become ready on 127.0.0.1:{port}");
}

fn redis_ping(port: u16) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
    stream.write_all(b"*1\r\n$4\r\nPING\r\n")?;
    let mut buf = [0u8; 16];
    let len = stream.read(&mut buf)?;
    Ok(buf[..len].starts_with(b"+PONG"))
}

fn terminate(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = unsafe { kill(child.id() as i32, SIGTERM) };
        for _ in 0..50 {
            if child.try_wait().expect("poll pyzord exit").is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
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

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pyzor-{name}-{}-{}",
        std::process::id(),
        unique_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn unique_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
