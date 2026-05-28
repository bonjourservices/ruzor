#![cfg(feature = "backend-mysql")]

use std::collections::HashMap;
use std::env;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mysql::OptsBuilder;
use mysql::prelude::Queryable;
use ruzor::client::Client;
use ruzor::config::Address;
use ruzor::mysql_engine::MySqlDsn;

const DIGEST: &str = "7421216f915a87e02da034cc483f5c876e1a1338";

#[test]
#[ignore = "requires a MySQL server and PYZOR_MYSQL_DSN=host,user,password,db,table"]
fn pyzord_uses_mysql_backend() {
    let dsn_value = env::var("PYZOR_MYSQL_DSN")
        .expect("set PYZOR_MYSQL_DSN=host,user,password,db,table for the MySQL backend test");
    let dsn = MySqlDsn::parse(&dsn_value).unwrap();
    execute_sql(&dsn, &create_schema_sql(&dsn.table)).expect("create Pyzor MySQL schema");
    execute_sql(&dsn, &delete_digest_sql(&dsn.table, DIGEST))
        .expect("delete stale MySQL digest before test");

    let mut server = PyzordProcess::start("mysql", &dsn_value);
    wait_for_process_server(&mut server.child, &server.address);

    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    assert!(client.report(DIGEST, &server.address).unwrap().is_ok());
    assert!(client.whitelist(DIGEST, &server.address).unwrap().is_ok());

    let response = client.check(DIGEST, &server.address).unwrap();
    assert_eq!(response.get("Count"), Some("2"));
    assert_eq!(response.get("WL-Count"), Some("1"));

    execute_sql(&dsn, &delete_digest_sql(&dsn.table, DIGEST))
        .expect("delete MySQL digest after test");
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
    fn start(name: &str, dsn: &str) -> Self {
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
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
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
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = env::temp_dir().join(format!("pyzor-mysql-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}
