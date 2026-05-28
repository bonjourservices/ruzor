#![cfg(feature = "backend-mysql")]

use std::collections::HashMap;
use std::env;
use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mysql::OptsBuilder;
use mysql::prelude::Queryable;
use ruzor::client::{BatchClient, Client};
use ruzor::config::Address;
use ruzor::mysql_engine::MySqlDsn;

const DIGEST: &str = "7421216f915a87e02da034cc483f5c876e1a1338";
const PONG_DIGEST: &str = "0000000000000000000000000000000000000101";
const CHECK_DIGEST: &str = "0000000000000000000000000000000000000102";
const REPORT_UPDATE_DIGEST: &str = "0000000000000000000000000000000000000103";
const WHITELIST_UPDATE_DIGEST: &str = "0000000000000000000000000000000000000104";
const COMBINED_UPDATE_DIGEST: &str = "0000000000000000000000000000000000000105";
const BATCH_REPORT_DIGEST: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
const BATCH_WHITELIST_DIGEST: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80708";
const STALE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FRESH_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static MYSQL_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(unix)]
const SIGTERM: i32 = 15;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[test]
#[ignore = "requires Docker mysql:8.4 or PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_uses_docker_mysql_backend() {
    let _guard = mysql_test_guard();
    let mysql = MySqlFixture::start("basic");
    mysql.delete_digests(&[DIGEST]);

    let mut server = PyzordProcess::start("mysql-docker-basic", mysql.dsn_value(), &[]);
    wait_for_process_server(&mut server.child, &server.address);

    let client = test_client();
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    assert!(client.whitelist(DIGEST, &server.address).unwrap().is_ok());
    assert_digest_counts(&client, &server.address, DIGEST, (2, 1));
}

#[test]
#[ignore = "requires Docker mysql:8.4 or PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_docker_mysql_core_functional_mixin_matches_python() {
    let _guard = mysql_test_guard();
    let mysql = MySqlFixture::start("core-functional");
    mysql.delete_digests(&[
        PONG_DIGEST,
        CHECK_DIGEST,
        REPORT_UPDATE_DIGEST,
        WHITELIST_UPDATE_DIGEST,
        COMBINED_UPDATE_DIGEST,
    ]);

    let mut server = PyzordProcess::start("mysql-docker-core-functional", mysql.dsn_value(), &[]);
    wait_for_process_server(&mut server.child, &server.address);

    let client = test_client();
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
#[ignore = "requires Docker mysql:8.4 or PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_threads_use_docker_mysql_backend_workers() {
    let _guard = mysql_test_guard();
    let mysql = MySqlFixture::start("threads");
    mysql.delete_digests(&[DIGEST]);

    let mut server = PyzordProcess::start(
        "mysql-docker-threads",
        mysql.dsn_value(),
        &["--threads", "true", "--max-threads", "4"],
    );
    wait_for_process_server(&mut server.child, &server.address);

    let client = test_client();
    for _ in 0..6 {
        assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    }
    for _ in 0..2 {
        assert!(client.whitelist(DIGEST, &server.address).unwrap().is_ok());
    }
    assert_digest_counts(&client, &server.address, DIGEST, (6, 2));
}

#[test]
#[ignore = "requires Docker mysql:8.4 or PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_threads_db_connections_use_docker_mysql_backend_workers() {
    let _guard = mysql_test_guard();
    let mysql = MySqlFixture::start("threads-db-connections");
    mysql.delete_digests(&[DIGEST]);

    let mut server = PyzordProcess::start(
        "mysql-docker-threads-db-connections",
        mysql.dsn_value(),
        &["--threads", "true", "--db-connections", "2"],
    );
    wait_for_process_server(&mut server.child, &server.address);

    send_parallel_reports(server.address.clone(), 7, false);
    send_parallel_reports(server.address.clone(), 2, true);

    let client = test_client();
    assert_digest_counts(&client, &server.address, DIGEST, (7, 2));
}

#[test]
#[ignore = "requires Docker mysql:8.4 or PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_max_threads_and_db_connections_use_docker_mysql_backend_workers() {
    let _guard = mysql_test_guard();
    let mysql = MySqlFixture::start("max-threads-db-connections");
    mysql.delete_digests(&[DIGEST]);

    let mut server = PyzordProcess::start(
        "mysql-docker-max-threads-db-connections",
        mysql.dsn_value(),
        &[
            "--threads",
            "true",
            "--max-threads",
            "4",
            "--db-connections",
            "2",
        ],
    );
    wait_for_process_server(&mut server.child, &server.address);

    send_parallel_reports(server.address.clone(), 10, false);
    send_parallel_reports(server.address.clone(), 4, true);

    let client = test_client();
    assert_digest_counts(&client, &server.address, DIGEST, (10, 4));
}

#[test]
#[ignore = "requires Docker mysql:8.4 or PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_docker_mysql_batched_functional_matrix_matches_python() {
    let _guard = mysql_test_guard();
    let mysql = MySqlFixture::start("batched");
    let report_digests = numbered_digests("a39a3ee5e6b4b0d3255bfef95601890afd80706");
    let whitelist_digests = numbered_digests("a39a3ee5e6b4b0d3255bfef95601890afd80705");
    mysql.delete_digests(&[
        BATCH_REPORT_DIGEST,
        BATCH_WHITELIST_DIGEST,
        "da39a3ee5e6b4b0d3255bfef95601890afd80707",
        "da39a3ee5e6b4b0d3255bfef95601890afd80704",
        "da39a3ee5e6b4b0d3255bfef95601890afd80703",
        "da39a3ee5e6b4b0d3255bfef95601890afd80702",
        "da39a3ee5e6b4b0d3255bfef95601890afd80701",
    ]);
    mysql.delete_digest_strings(&report_digests);
    mysql.delete_digest_strings(&whitelist_digests);

    let mut server1 = PyzordProcess::start("mysql-docker-batched-primary", mysql.dsn_value(), &[]);
    let mut server2 =
        PyzordProcess::start("mysql-docker-batched-secondary", mysql.dsn_value(), &[]);
    wait_for_process_server(&mut server1.child, &server1.address);
    wait_for_process_server(&mut server2.child, &server2.address);

    let client = test_client();

    let mut batch = BatchClient::new(client.clone(), 10);
    for _ in 0..9 {
        batch.report(BATCH_REPORT_DIGEST, &server1.address).unwrap();
    }
    assert_digest_counts(&client, &server1.address, BATCH_REPORT_DIGEST, (0, 0));
    batch.report(BATCH_REPORT_DIGEST, &server1.address).unwrap();
    assert_digest_counts(&client, &server1.address, BATCH_REPORT_DIGEST, (10, 0));

    let mut batch = BatchClient::new(client.clone(), 10);
    for _ in 0..9 {
        batch
            .whitelist(BATCH_WHITELIST_DIGEST, &server1.address)
            .unwrap();
    }
    assert_digest_counts(&client, &server1.address, BATCH_WHITELIST_DIGEST, (0, 0));
    batch
        .whitelist(BATCH_WHITELIST_DIGEST, &server1.address)
        .unwrap();
    assert_digest_counts(&client, &server1.address, BATCH_WHITELIST_DIGEST, (0, 10));

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

    let mut batch = BatchClient::new(client.clone(), 10);
    for digest in &report_digests {
        batch.report(digest, &server1.address).unwrap();
    }
    for digest in &report_digests {
        assert_digest_counts(&client, &server1.address, digest, (1, 0));
    }

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

#[test]
#[ignore = "requires Docker mysql:8.4 or PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_docker_mysql_cleanup_age_removes_stale_records() {
    let _guard = mysql_test_guard();
    let mysql = MySqlFixture::start("cleanup");
    mysql.delete_digests(&[STALE_DIGEST, FRESH_DIGEST]);
    mysql.seed_record(STALE_DIGEST, 24, 0, "2001-01-01 00:00:00");
    mysql.seed_record(FRESH_DIGEST, 42, 1, "2999-01-01 00:00:00");

    let mut server = PyzordProcess::start(
        "mysql-docker-cleanup",
        mysql.dsn_value(),
        &["--cleanup-age", "1"],
    );
    wait_for_process_server(&mut server.child, &server.address);

    let client = test_client();
    assert_digest_counts(&client, &server.address, STALE_DIGEST, (0, 0));
    assert_digest_counts(&client, &server.address, FRESH_DIGEST, (42, 1));
}

#[test]
#[cfg(unix)]
#[ignore = "requires Docker mysql:8.4 or PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_process_mode_uses_docker_mysql_backend() {
    let _guard = mysql_test_guard();
    let mysql = MySqlFixture::start("process");
    mysql.delete_digests(&[DIGEST]);

    let mut server = PyzordProcess::start(
        "mysql-docker-process",
        mysql.dsn_value(),
        &["--processes", "true", "--max-processes", "4"],
    );
    wait_for_process_server(&mut server.child, &server.address);

    send_parallel_reports(server.address.clone(), 12, false);
    send_parallel_reports(server.address.clone(), 3, true);

    let client = test_client();
    assert_digest_counts(&client, &server.address, DIGEST, (12, 3));
}

#[test]
#[cfg(unix)]
#[ignore = "requires Docker mysql:8.4 or PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_prefork_uses_docker_mysql_backend() {
    let _guard = mysql_test_guard();
    let mysql = MySqlFixture::start("prefork");
    mysql.delete_digests(&[DIGEST]);

    let mut server = PyzordProcess::start(
        "mysql-docker-prefork",
        mysql.dsn_value(),
        &["--pre-fork", "4"],
    );
    wait_for_process_server(&mut server.child, &server.address);

    let client = test_client();
    for _ in 0..8 {
        assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    }
    for _ in 0..2 {
        assert!(client.whitelist(DIGEST, &server.address).unwrap().is_ok());
    }
    assert_digest_counts(&client, &server.address, DIGEST, (8, 2));
}

fn numbered_digests(suffix: &str) -> Vec<String> {
    (0..10).map(|i| format!("{i}{suffix}")).collect()
}

fn mysql_test_guard() -> MutexGuard<'static, ()> {
    MYSQL_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn test_client() -> Client {
    Client::new(HashMap::new(), Some(5), ruzor::digest::DIGEST_SPEC.to_vec())
}

fn send_parallel_reports(address: Address, count: usize, whitelist: bool) {
    let handles = (0..count)
        .map(|_| {
            let address = address.clone();
            thread::spawn(move || {
                let client = test_client();
                let result = if whitelist {
                    client.whitelist(DIGEST, &address)
                } else {
                    client.report(DIGEST, &address)
                };
                assert!(result.unwrap().is_ok());
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }
}

fn assert_message_counts(response: &ruzor::message::Message, expected: (i64, i64)) {
    assert_eq!(
        (
            response.get("Count").unwrap().parse::<i64>().unwrap(),
            response.get("WL-Count").unwrap().parse::<i64>().unwrap(),
        ),
        expected
    );
}

fn assert_distinct_info_timestamps(
    response: &ruzor::message::Message,
    entered_key: &str,
    updated_key: &str,
) {
    let entered = response.get(entered_key).unwrap();
    let updated = response.get(updated_key).unwrap();

    assert_ne!(entered, "0");
    assert_ne!(updated, "0");
    assert_ne!(entered, updated);
}

fn assert_digest_counts(client: &Client, address: &Address, digest: &str, expected: (i64, i64)) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
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
        thread::sleep(Duration::from_millis(50));
    }
    panic!("digest {digest} at {address:?} had counts {last:?}, expected {expected:?}");
}

struct MySqlFixture {
    dsn_value: String,
    dsn: MySqlDsn,
    _container: Option<MySqlContainer>,
}

impl MySqlFixture {
    fn start(name: &str) -> Self {
        if let Ok(dsn_value) = env::var("PYZOR_MYSQL_DSN") {
            let dsn = MySqlDsn::parse(&dsn_value).unwrap();
            let fixture = Self {
                dsn_value,
                dsn,
                _container: None,
            };
            fixture.ensure_schema();
            return fixture;
        }

        let container = MySqlContainer::start(name);
        let dsn_value = "127.0.0.1,pyzor,secret,pyzord,public".to_string();
        let dsn = MySqlDsn::parse(&dsn_value).unwrap();
        wait_for_mysql(&dsn, Some(&container.name));
        let fixture = Self {
            dsn_value,
            dsn,
            _container: Some(container),
        };
        fixture.ensure_schema();
        fixture
    }

    fn dsn_value(&self) -> &str {
        &self.dsn_value
    }

    fn ensure_schema(&self) {
        execute_sql(&self.dsn, &create_schema_sql(&self.dsn.table))
            .expect("create Pyzor MySQL schema");
    }

    fn delete_digests(&self, digests: &[&str]) {
        for digest in digests {
            execute_sql(&self.dsn, &delete_digest_sql(&self.dsn.table, digest))
                .expect("delete MySQL digest");
        }
    }

    fn delete_digest_strings(&self, digests: &[String]) {
        for digest in digests {
            execute_sql(&self.dsn, &delete_digest_sql(&self.dsn.table, digest))
                .expect("delete MySQL digest");
        }
    }

    fn seed_record(&self, digest: &str, r_count: i64, wl_count: i64, updated: &str) {
        let sql = format!(
            "INSERT INTO {table} (digest, r_count, wl_count, r_entered, r_updated, wl_entered, wl_updated) VALUES ('{digest}', {r_count}, {wl_count}, '{updated}', '{updated}', '{updated}', '{updated}') ON DUPLICATE KEY UPDATE r_count={r_count}, wl_count={wl_count}, r_entered='{updated}', r_updated='{updated}', wl_entered='{updated}', wl_updated='{updated}'",
            table = self.dsn.table
        );
        execute_sql(&self.dsn, &sql).expect("seed MySQL record");
    }
}

struct MySqlContainer {
    name: String,
}

impl MySqlContainer {
    fn start(name: &str) -> Self {
        assert_standard_mysql_port_is_free();
        let container_name = format!(
            "pyzor-mysql-{name}-{}-{}",
            std::process::id(),
            unique_nanos()
        );
        let image = env::var("PYZOR_MYSQL_IMAGE").unwrap_or_else(|_| "mysql:8.4".to_string());
        let output = Command::new("docker")
            .arg("run")
            .arg("--rm")
            .arg("-d")
            .arg("--name")
            .arg(&container_name)
            .arg("-p")
            .arg("127.0.0.1:3306:3306")
            .arg("-e")
            .arg("MYSQL_ROOT_PASSWORD=pyzor-root")
            .arg("-e")
            .arg("MYSQL_DATABASE=pyzord")
            .arg("-e")
            .arg("MYSQL_USER=pyzor")
            .arg("-e")
            .arg("MYSQL_PASSWORD=secret")
            .arg(image)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run MySQL container");
        assert!(
            output.status.success(),
            "docker run failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            name: container_name,
        }
    }
}

impl Drop for MySqlContainer {
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

fn assert_standard_mysql_port_is_free() {
    TcpListener::bind("127.0.0.1:3306").unwrap_or_else(|error| {
        panic!(
            "Docker MySQL tests need 127.0.0.1:3306, but it is unavailable ({error}). Set PYZOR_MYSQL_DSN to use an existing MySQL server instead."
        )
    });
}

fn wait_for_mysql(dsn: &MySqlDsn, container_name: Option<&str>) {
    let mut last_error = None;
    for _ in 0..120 {
        match execute_sql(dsn, "SELECT 1") {
            Ok(()) => return,
            Err(error) => {
                last_error = Some(error.to_string());
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
    let logs = container_name
        .and_then(docker_logs)
        .unwrap_or_else(|| "no docker logs available".to_string());
    panic!("MySQL did not become ready on 127.0.0.1:3306, last error={last_error:?}\n{logs}");
}

fn docker_logs(name: &str) -> Option<String> {
    let output = Command::new("docker")
        .arg("logs")
        .arg(name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    let mut logs = String::from_utf8_lossy(&output.stdout).to_string();
    logs.push_str(&String::from_utf8_lossy(&output.stderr));
    Some(logs)
}

fn create_schema_sql(table: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {table} (
            digest char(40) NOT NULL,
            r_count int default NULL,
            wl_count int default NULL,
            r_entered datetime default NULL,
            wl_entered datetime default NULL,
            r_updated datetime default NULL,
            wl_updated datetime default NULL,
            PRIMARY KEY (digest)
        )"
    )
}

fn delete_digest_sql(table: &str, digest: &str) -> String {
    format!("DELETE FROM {table} WHERE digest='{digest}'")
}

fn execute_sql(dsn: &MySqlDsn, sql: &str) -> mysql::Result<()> {
    let mut conn = mysql::Pool::new(opts_from_dsn(dsn))?.get_conn()?;
    conn.query_drop(sql)
}

fn opts_from_dsn(dsn: &MySqlDsn) -> OptsBuilder {
    let mut opts = OptsBuilder::new()
        .user(non_empty(&dsn.user))
        .pass(non_empty(&dsn.password))
        .db_name(non_empty(&dsn.database));
    if dsn.host.starts_with('/') {
        opts = opts.socket(Some(dsn.host.clone())).prefer_socket(true);
    } else if !dsn.host.is_empty() {
        opts = opts
            .ip_or_hostname(Some(dsn.host.clone()))
            .prefer_socket(false);
    }
    opts
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

struct PyzordProcess {
    child: Child,
    address: Address,
    homedir: PathBuf,
}

impl PyzordProcess {
    fn start(name: &str, dsn: &str, extra_args: &[&str]) -> Self {
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
            .arg("mysql")
            .arg("--dsn")
            .arg(dsn)
            .arg("-a")
            .arg("127.0.0.1")
            .arg("-p")
            .arg(port.to_string())
            .args(extra_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let child = command.spawn().expect("spawn ruzord with MySQL backend");
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

fn wait_for_process_server(server: &mut Child, address: &Address) {
    let client = test_client();
    for _ in 0..100 {
        if let Some(status) = server.try_wait().expect("poll ruzord") {
            let mut stderr = String::new();
            if let Some(mut pipe) = server.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("ruzord exited before readiness: {status}\n{stderr}");
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

fn terminate(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = unsafe { kill(child.id() as i32, SIGTERM) };
        for _ in 0..50 {
            if child.try_wait().expect("poll ruzord exit").is_some() {
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

fn temp_dir(name: &str) -> PathBuf {
    let path = env::temp_dir().join(format!(
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
