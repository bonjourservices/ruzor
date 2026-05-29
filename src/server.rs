use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use crate::account::{self, now_timestamp};
use crate::client::Client;
use crate::config::Address;
use crate::engines::{DigestDatabase, FileDatabase, Record};
use crate::error::PyzorError;
use crate::forwarder::Forwarder;
#[cfg(feature = "backend-gdbm")]
use crate::gdbm_engine::GdbmDatabase;
use crate::logging::Logger;
use crate::message::{self, Message};
#[cfg(feature = "backend-mysql")]
use crate::mysql_cli::MySqlCommandExecutor;
#[cfg(feature = "backend-mysql")]
use crate::mysql_engine::MySqlDatabase;
#[cfg(feature = "backend-mysql")]
use crate::mysql_native::MySqlNativeExecutor;
use crate::python_repr;
use crate::redis_engine::{RedisV0Database, RedisV1Database};
use crate::{ANONYMOUS_USER, MAX_PACKET_SIZE, PROTO_MAJOR, PROTO_VERSION, Result};

pub const DEFAULT_CLEANUP_AGE: i64 = 60 * 60 * 24 * 30 * 4;

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub address: Address,
    pub database_path: String,
    pub engine: String,
    pub passwd_path: String,
    pub access_path: String,
    pub threads: bool,
    pub max_threads: usize,
    pub db_connections: usize,
    pub cleanup_age: Option<i64>,
    pub proxy_sources: Vec<Address>,
    pub forwarder: Option<Forwarder>,
    pub logger: Option<Logger>,
    pub usage_logger: Option<Logger>,
}

pub fn serve(options: ServerOptions) -> Result<()> {
    serve_with_shutdown(options, Arc::new(AtomicBool::new(false)))
}

pub fn serve_with_shutdown(options: ServerOptions, shutdown: Arc<AtomicBool>) -> Result<()> {
    serve_with_control(options, shutdown, Arc::new(AtomicBool::new(false)))
}

pub fn serve_with_control(
    options: ServerOptions,
    shutdown: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
) -> Result<()> {
    let socket = UdpSocket::bind((options.address.0.as_str(), options.address.1))?;
    serve_bound_socket_with_control(socket, options, shutdown, reload)
}

pub fn serve_bound_socket_with_control(
    socket: UdpSocket,
    options: ServerOptions,
    shutdown: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
) -> Result<()> {
    let db_connections = if options.threads {
        options.db_connections
    } else {
        0
    };
    let db = Arc::new(Mutex::new(open_database_with_db_connections(
        &options.engine,
        &options.database_path,
        options.cleanup_age,
        db_connections,
    )?));
    let auth = Arc::new(RwLock::new(load_auth_state(
        &options.passwd_path,
        &options.access_path,
        options.logger.as_ref(),
    )));
    serve_socket_with_control(socket, db, auth, options, shutdown, reload)
}

pub fn serve_socket_until_shutdown(
    socket: UdpSocket,
    db: Arc<Mutex<FileDatabase>>,
    accounts: Arc<HashMap<String, String>>,
    acl: Arc<HashMap<String, HashSet<String>>>,
    threads: bool,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    while !shutdown.load(Ordering::Relaxed) {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => return Err(PyzorError::from(error)),
        };
        let packet = buf[..len].to_vec();
        let socket = socket.try_clone()?;
        let db = Arc::clone(&db);
        let accounts = Arc::clone(&accounts);
        let acl = Arc::clone(&acl);
        if threads {
            thread::spawn(move || {
                let response = handle_packet(&packet, &db, &accounts, &acl);
                let _ = socket.send_to(response.as_string().as_bytes(), peer);
            });
        } else {
            let response = handle_packet(&packet, &db, &accounts, &acl);
            socket.send_to(response.as_string().as_bytes(), peer)?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct AuthState {
    accounts: HashMap<String, String>,
    acl: HashMap<String, HashSet<String>>,
}
fn load_auth_state(passwd_path: &str, access_path: &str, logger: Option<&Logger>) -> AuthState {
    let accounts = crate::config::load_passwd_file_with_logger(passwd_path, logger);
    let acl = crate::config::load_access_file_with_logger(access_path, &accounts, logger);
    AuthState { accounts, acl }
}

pub fn open_database(
    engine: &str,
    database_path: &str,
    cleanup_age: Option<i64>,
) -> Result<Box<dyn DigestDatabase>> {
    open_database_with_db_connections(engine, database_path, cleanup_age, 0)
}

fn open_database_with_db_connections(
    engine: &str,
    database_path: &str,
    cleanup_age: Option<i64>,
    db_connections: usize,
) -> Result<Box<dyn DigestDatabase>> {
    match engine {
        "gdbm" => open_gdbm_database(database_path, cleanup_age),
        "redis" => Ok(Box::new(RedisV1Database::connect_with_max_age(
            database_path,
            cleanup_age,
        )?)),
        "redis_v0" => Ok(Box::new(RedisV0Database::connect_with_max_age(
            database_path,
            cleanup_age,
        )?)),
        "mysql" => open_mysql_database(database_path, cleanup_age, db_connections),
        other => Err(PyzorError::Comm(format!(
            "Unknown database engine: {other}"
        ))),
    }
}

#[cfg(feature = "backend-gdbm")]
fn open_gdbm_database(
    database_path: &str,
    cleanup_age: Option<i64>,
) -> Result<Box<dyn DigestDatabase>> {
    Ok(Box::new(GdbmDatabase::open_with_cleanup_age(
        database_path,
        cleanup_age,
    )?))
}

#[cfg(not(feature = "backend-gdbm"))]
fn open_gdbm_database(
    _database_path: &str,
    _cleanup_age: Option<i64>,
) -> Result<Box<dyn DigestDatabase>> {
    Err(PyzorError::Comm("GDBM backend is disabled.".to_string()))
}

#[cfg(feature = "backend-mysql")]
fn open_mysql_database(
    database_path: &str,
    cleanup_age: Option<i64>,
    db_connections: usize,
) -> Result<Box<dyn DigestDatabase>> {
    if std::env::var_os("PYZOR_MYSQL_BIN").is_some() {
        Ok(Box::new(
            MySqlDatabase::<MySqlCommandExecutor>::connect_with_max_age_and_db_connections(
                database_path,
                cleanup_age,
                db_connections,
            )?,
        ))
    } else {
        Ok(Box::new(
            MySqlDatabase::<MySqlNativeExecutor>::connect_with_max_age_and_db_connections(
                database_path,
                cleanup_age,
                db_connections,
            )?,
        ))
    }
}

#[cfg(not(feature = "backend-mysql"))]
fn open_mysql_database(
    _database_path: &str,
    _cleanup_age: Option<i64>,
    _db_connections: usize,
) -> Result<Box<dyn DigestDatabase>> {
    Err(PyzorError::Comm("MySQL backend is disabled.".to_string()))
}

#[derive(Debug)]
struct ThreadLimiter {
    max: usize,
    active: Mutex<usize>,
    available: Condvar,
}

impl ThreadLimiter {
    fn new(max: usize) -> Self {
        Self {
            max,
            active: Mutex::new(0),
            available: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> ThreadPermit {
        let mut active = self.active.lock().expect("thread limiter poisoned");
        while *active >= self.max {
            active = self
                .available
                .wait(active)
                .expect("thread limiter poisoned");
        }
        *active += 1;
        ThreadPermit {
            limiter: Arc::clone(self),
        }
    }

    #[cfg(test)]
    fn active_count(&self) -> usize {
        *self.active.lock().expect("thread limiter poisoned")
    }
}

#[derive(Debug)]
struct ThreadPermit {
    limiter: Arc<ThreadLimiter>,
}

impl Drop for ThreadPermit {
    fn drop(&mut self) {
        let mut active = self.limiter.active.lock().expect("thread limiter poisoned");
        *active = active.saturating_sub(1);
        self.limiter.available.notify_one();
    }
}

fn serve_socket_with_control(
    socket: UdpSocket,
    db: Arc<Mutex<Box<dyn DigestDatabase>>>,
    auth: Arc<RwLock<AuthState>>,
    options: ServerOptions,
    shutdown: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
) -> Result<()> {
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    if let Some(logger) = &options.logger {
        logger.debug(format!(
            "Listening on ({}, {})",
            python_repr::string(&options.address.0),
            options.address.1
        ));
    }
    let thread_limiter = if options.threads && options.max_threads > 0 {
        Some(Arc::new(ThreadLimiter::new(options.max_threads)))
    } else {
        None
    };
    while !shutdown.load(Ordering::Relaxed) {
        if reload.swap(false, Ordering::Relaxed) {
            if let Some(logger) = &options.logger {
                logger.info("SIGUSR1 received. Reloading configuration.");
            }
            let new_auth = load_auth_state(
                &options.passwd_path,
                &options.access_path,
                options.logger.as_ref(),
            );
            *auth.write().expect("auth state poisoned") = new_auth;
        }

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => return Err(PyzorError::from(error)),
        };
        let packet = buf[..len].to_vec();
        let socket = socket.try_clone()?;
        let db = Arc::clone(&db);
        let auth = Arc::clone(&auth);
        let forwarder = options.forwarder.clone();
        let proxy_sources = options.proxy_sources.clone();
        let logger = options.logger.clone();
        let usage_logger = options.usage_logger.clone();
        if options.threads {
            let permit = thread_limiter.as_ref().map(|limiter| limiter.acquire());
            thread::spawn(move || {
                let _permit = permit;
                let peer_ip = peer.ip().to_string();
                if let Some(logger) = &logger {
                    logger.debug(format!("Received: {}", python_repr::bytes(&packet)));
                }
                let auth = auth.read().expect("auth state poisoned");
                let debug = logger.as_ref().map(|logger| RequestDebugContext {
                    logger,
                    peer_ip: peer_ip.as_str(),
                });
                let response = handle_packet_with_forwarder(
                    &packet,
                    &db,
                    &auth.accounts,
                    &auth.acl,
                    forwarder.as_ref(),
                    &proxy_sources,
                    debug,
                );
                log_usage_for_response(&packet, &peer_ip, &response, usage_logger.as_ref());
                let response_packet = response.as_string();
                if let Some(logger) = &logger {
                    logger.debug(format!(
                        "Sending: {}",
                        python_repr::string(&response_packet)
                    ));
                }
                let _ = socket.send_to(response_packet.as_bytes(), peer);
            });
        } else {
            let peer_ip = peer.ip().to_string();
            if let Some(logger) = &logger {
                logger.debug(format!("Received: {}", python_repr::bytes(&packet)));
            }
            let auth = auth.read().expect("auth state poisoned");
            let debug = logger.as_ref().map(|logger| RequestDebugContext {
                logger,
                peer_ip: peer_ip.as_str(),
            });
            let response = handle_packet_with_forwarder(
                &packet,
                &db,
                &auth.accounts,
                &auth.acl,
                forwarder.as_ref(),
                &options.proxy_sources,
                debug,
            );
            log_usage_for_response(&packet, &peer_ip, &response, usage_logger.as_ref());
            let response_packet = response.as_string();
            if let Some(logger) = &logger {
                logger.debug(format!(
                    "Sending: {}",
                    python_repr::string(&response_packet)
                ));
            }
            socket.send_to(response_packet.as_bytes(), peer)?;
        }
    }
    Ok(())
}

pub fn log_usage_for_response(
    packet: &[u8],
    peer_ip: &str,
    response: &Message,
    logger: Option<&Logger>,
) {
    let Some(logger) = logger else {
        return;
    };
    let code = response.get("Code").unwrap_or("0");
    if code != "200" {
        logger.error(format!("{}: {}", code, response.get("Diag").unwrap_or("")));
        return;
    }

    let cleaned = clean_legacy_packet(packet);
    let request = Message::parse(&cleaned);
    let user = request.get("User").unwrap_or(ANONYMOUS_USER);
    let opcode = request.get("Op").unwrap_or("");
    let digests = request.get_all("Op-Digest");
    logger.info(format!(
        "{},{},{},{},{}",
        user,
        peer_ip,
        opcode,
        format_digests_repr(&digests),
        code
    ));
}

fn format_digests_repr(digests: &[&str]) -> String {
    if digests.is_empty() {
        return "None".to_string();
    }
    let values = digests
        .iter()
        .map(|digest| format!("'{}'", python_repr::single_quoted(digest)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

pub fn handle_packet<D: DigestDatabase + ?Sized>(
    packet: &[u8],
    db: &Arc<Mutex<D>>,
    accounts: &HashMap<String, String>,
    acl: &HashMap<String, HashSet<String>>,
) -> Message {
    handle_packet_with_forwarder(packet, db, accounts, acl, None, &[], None)
}

pub fn handle_packet_with_proxy_sources<D: DigestDatabase + ?Sized>(
    packet: &[u8],
    db: &Arc<Mutex<D>>,
    accounts: &HashMap<String, String>,
    acl: &HashMap<String, HashSet<String>>,
    proxy_sources: &[Address],
) -> Message {
    handle_packet_with_forwarder(packet, db, accounts, acl, None, proxy_sources, None)
}

#[derive(Clone, Copy)]
struct RequestDebugContext<'a> {
    logger: &'a Logger,
    peer_ip: &'a str,
}

struct HandlerContext<'a, D: DigestDatabase + ?Sized> {
    db: &'a Arc<Mutex<D>>,
    accounts: &'a HashMap<String, String>,
    acl: &'a HashMap<String, HashSet<String>>,
    forwarder: Option<&'a Forwarder>,
    proxy_sources: &'a [Address],
    debug: Option<RequestDebugContext<'a>>,
}

fn handle_packet_with_forwarder<D: DigestDatabase + ?Sized>(
    packet: &[u8],
    db: &Arc<Mutex<D>>,
    accounts: &HashMap<String, String>,
    acl: &HashMap<String, HashSet<String>>,
    forwarder: Option<&Forwarder>,
    proxy_sources: &[Address],
    debug: Option<RequestDebugContext<'_>>,
) -> Message {
    let cleaned = clean_legacy_packet(packet);
    let request = Message::parse(&cleaned);
    let mut response = message::response(request.get("Thread"));

    let context = HandlerContext {
        db,
        accounts,
        acl,
        forwarder,
        proxy_sources,
        debug,
    };

    match panic::catch_unwind(AssertUnwindSafe(|| {
        really_handle(&request, &mut response, &context)
    })) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => apply_error(&mut response, error),
        Err(payload) => {
            apply_unexpected_error(&mut response, panic_payload_message(payload.as_ref()))
        }
    }
    response
}

fn really_handle<D: DigestDatabase + ?Sized>(
    request: &Message,
    response: &mut Message,
    context: &HandlerContext<'_, D>,
) -> Result<()> {
    let user = request.get("User").unwrap_or(ANONYMOUS_USER);
    if user != ANONYMOUS_USER {
        let key = context
            .accounts
            .get(user)
            .ok_or_else(|| PyzorError::Signature("Unknown user.".to_string()))?;
        account::verify_signature(request, key)?;
    }

    let Some(pv) = request.get("PV") else {
        return Err(PyzorError::Protocol(
            "Protocol Version not specified in request".to_string(),
        ));
    };
    let major = protocol_major(pv)?;
    if major != PROTO_MAJOR {
        return Err(PyzorError::UnsupportedVersion(String::new()));
    }

    let opcode = request.get("Op").unwrap_or("");
    if !context
        .acl
        .get(user)
        .map(|ops| ops.contains(opcode))
        .unwrap_or(false)
    {
        return Err(PyzorError::Authorization(
            "User is not authorized to request the operation.".to_string(),
        ));
    }
    if let Some(debug) = context.debug {
        debug
            .logger
            .debug(format!("Got a {opcode} command from {}", debug.peer_ip));
    }

    let digests: Vec<String> = request
        .get_all("Op-Digest")
        .into_iter()
        .map(str::to_string)
        .collect();

    match opcode {
        "ping" => {}
        "pong" => {
            if let Some(digest) = digests.first() {
                if let Some(debug) = context.debug {
                    debug.logger.debug(format!("Request pong for {digest}"));
                }
                response.add_header("Count", isize::MAX.to_string());
                response.add_header("WL-Count", "0");
            }
        }
        "check" => {
            if let Some(digest) = digests.first() {
                let mut record = with_database(context.db, |database| database.get(digest))?;
                if let Some(debug) = context.debug {
                    debug
                        .logger
                        .debug(format!("Request to check digest {digest}"));
                }
                if !record_has_match(&record)
                    && let Some(proxy_record) =
                        proxy_check_miss(digest, context.proxy_sources, context.debug)
                {
                    with_database(context.db, |database| {
                        database.set(digest, proxy_record.clone())
                    })?;
                    record = proxy_record;
                }
                response.add_header("Count", record.r_count.to_string());
                response.add_header("WL-Count", record.wl_count.to_string());
            }
        }
        "info" => {
            if let Some(digest) = digests.first() {
                let record = with_database(context.db, |database| database.get(digest))?;
                if let Some(debug) = context.debug {
                    debug
                        .logger
                        .debug(format!("Request for information about digest {digest}"));
                }
                response.add_header("Entered", record.r_entered.unwrap_or(0).to_string());
                response.add_header("Updated", record.r_updated.unwrap_or(0).to_string());
                response.add_header("WL-Entered", record.wl_entered.unwrap_or(0).to_string());
                response.add_header("WL-Updated", record.wl_updated.unwrap_or(0).to_string());
                response.add_header("Count", record.r_count.to_string());
                response.add_header("WL-Count", record.wl_count.to_string());
            }
        }
        "report" => {
            if !digests.is_empty() {
                if let Some(debug) = context.debug {
                    let digest_refs = digests.iter().map(String::as_str).collect::<Vec<_>>();
                    debug.logger.debug(format!(
                        "Request to report digests {}",
                        format_digests_repr(&digest_refs)
                    ));
                }
                with_database(context.db, |database| database.report(&digests))?;
                if let Some(forwarder) = context.forwarder {
                    for digest in &digests {
                        forwarder.queue_forward_request(digest, false);
                    }
                }
            }
        }
        "whitelist" => {
            if !digests.is_empty() {
                if let Some(debug) = context.debug {
                    let digest_refs = digests.iter().map(String::as_str).collect::<Vec<_>>();
                    debug.logger.debug(format!(
                        "Request to whitelist digests {}",
                        format_digests_repr(&digest_refs)
                    ));
                }
                with_database(context.db, |database| database.whitelist(&digests))?;
                if let Some(forwarder) = context.forwarder {
                    for digest in &digests {
                        forwarder.queue_forward_request(digest, true);
                    }
                }
            }
        }
        _ => {
            return Err(PyzorError::Comm(
                "Not implemented: Requested operation is not implemented.".to_string(),
            ));
        }
    }
    Ok(())
}

fn proxy_check_miss(
    digest: &str,
    proxy_sources: &[Address],
    debug: Option<RequestDebugContext<'_>>,
) -> Option<Record> {
    if proxy_sources.is_empty() {
        return None;
    }
    let client = Client::default();
    for source in proxy_sources {
        if let Some(debug) = debug {
            debug.logger.debug(format!(
                "Proxying check miss for digest {digest} to {}:{}",
                source.0, source.1
            ));
        }
        match client.check(digest, source) {
            Ok(response) => {
                if let Some(record) = record_from_proxy_response(&response) {
                    return Some(record);
                }
            }
            Err(error) => {
                if let Some(debug) = debug {
                    debug.logger.debug(format!(
                        "Proxy source {}:{} failed for digest {digest}: {error}",
                        source.0, source.1
                    ));
                }
            }
        }
    }
    None
}

fn record_from_proxy_response(response: &Message) -> Option<Record> {
    if !response.is_ok() {
        return None;
    }
    let r_count = parse_i64_header(response, "Count");
    let wl_count = parse_i64_header(response, "WL-Count");
    if r_count <= 0 && wl_count <= 0 {
        return None;
    }
    let now = now_timestamp();
    Some(Record {
        r_count,
        wl_count,
        r_entered: proxy_time_or_now(response, "Entered", r_count, now),
        r_updated: proxy_time_or_now(response, "Updated", r_count, now),
        wl_entered: proxy_time_or_now(response, "WL-Entered", wl_count, now),
        wl_updated: proxy_time_or_now(response, "WL-Updated", wl_count, now),
    })
}

fn parse_i64_header(response: &Message, name: &str) -> i64 {
    response
        .get(name)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn proxy_time_or_now(response: &Message, name: &str, count: i64, now: i64) -> Option<i64> {
    response
        .get(name)
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .or_else(|| (count > 0).then_some(now))
}

fn record_has_match(record: &Record) -> bool {
    record.r_count > 0 || record.wl_count > 0
}

fn protocol_major(value: &str) -> Result<i64> {
    let value: f64 = value
        .parse()
        .map_err(|_| PyzorError::Protocol("Invalid Protocol Version".to_string()))?;
    Ok(value as i64)
}

fn with_database<D, T>(db: &Arc<Mutex<D>>, action: impl FnOnce(&mut D) -> Result<T>) -> Result<T>
where
    D: DigestDatabase + ?Sized,
{
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let mut database = db.lock().expect("database poisoned");
        action(&mut *database)
    })) {
        Ok(result) => result,
        Err(payload) => Err(PyzorError::Comm(panic_payload_message(payload.as_ref()))),
    }
}

fn apply_unexpected_error(response: &mut Message, message: String) {
    response.replace_header("Code", "500");
    response.replace_header("Diag", format!("Internal Server Error: {message}"));
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "panic".to_string()
}

fn apply_error(response: &mut Message, error: PyzorError) {
    let (code, diag) = match error {
        PyzorError::UnsupportedVersion(message) => {
            (505, format!("Version Not Supported: {}", message))
        }
        PyzorError::Protocol(message) | PyzorError::IncompleteMessage(message) => {
            (400, format!("Bad request: {}", message))
        }
        PyzorError::Signature(message) => {
            (401, format!("Unauthorized: Signature Error: {}", message))
        }
        PyzorError::Authorization(message) => (403, format!("Forbidden: {}", message)),
        PyzorError::Comm(message) if message.starts_with("Not implemented:") => (501, message),
        other => (500, format!("Internal Server Error: {}", other)),
    };
    response.replace_header("Code", code.to_string());
    response.replace_header("Diag", diag);
}

fn clean_legacy_packet(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + 1);
    let mut i = 0;
    while i < packet.len() {
        if i + 1 < packet.len() && packet[i] == b'\n' && packet[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(packet[i]);
            i += 1;
        }
    }
    out.push(b'\n');
    out
}

pub fn default_options(homedir: &str) -> ServerOptions {
    ServerOptions {
        address: ("0.0.0.0".to_string(), 24441),
        database_path: crate::config::expand_homefile(homedir, "ruzord.db"),
        engine: "gdbm".to_string(),
        passwd_path: crate::config::expand_homefile(homedir, "ruzord.passwd"),
        access_path: crate::config::expand_homefile(homedir, "ruzord.access"),
        threads: false,
        max_threads: 0,
        db_connections: 0,
        cleanup_age: Some(DEFAULT_CLEANUP_AGE),
        proxy_sources: Vec::new(),
        forwarder: None,
        logger: None,
        usage_logger: None,
    }
}

#[allow(dead_code)]
fn _protocol_version() -> &'static str {
    PROTO_VERSION
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    use super::{handle_packet, handle_packet_with_proxy_sources};
    use crate::engines::FileDatabase;

    #[test]
    fn ping_response() {
        let path = std::env::temp_dir().join(format!("ruzor-test-{}.db", std::process::id()));
        let db = Arc::new(Mutex::new(FileDatabase::open(&path).unwrap()));
        let mut acl = HashMap::new();
        acl.insert("anonymous".to_string(), HashSet::from(["ping".to_string()]));
        let response = handle_packet(
            b"Op: ping\nThread: 1234\nPV: 2.1\nUser: anonymous\n\n",
            &db,
            &HashMap::new(),
            &acl,
        );
        assert_eq!(response.get("Code"), Some("200"));
        assert_eq!(response.get("Thread"), Some("1234"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn check_miss_queries_proxy_source_and_caches_positive_response() {
        let path = std::env::temp_dir().join(format!("ruzor-proxy-test-{}.db", std::process::id()));
        let db = Arc::new(Mutex::new(FileDatabase::open(&path).unwrap()));
        let mut acl = HashMap::new();
        acl.insert(
            "anonymous".to_string(),
            HashSet::from(["check".to_string()]),
        );
        let digest = "dc5451ed15efee48b5257e1df2d12318";
        let (proxy_source, proxy) = start_check_proxy(7, 2);

        let response = handle_packet_with_proxy_sources(
            format!("Op: check\nThread: 1234\nPV: 2.1\nUser: anonymous\nOp-Digest: {digest}\n\n")
                .as_bytes(),
            &db,
            &HashMap::new(),
            &acl,
            &[proxy_source],
        );

        assert_eq!(response.get("Code"), Some("200"));
        assert_eq!(response.get("Count"), Some("7"));
        assert_eq!(response.get("WL-Count"), Some("2"));
        proxy.join().unwrap();

        let stored = db.lock().unwrap().get(digest);
        assert_eq!(stored.r_count, 7);
        assert_eq!(stored.wl_count, 2);
        assert!(stored.r_entered.is_some());
        assert!(stored.r_updated.is_some());
        assert!(stored.wl_entered.is_some());
        assert!(stored.wl_updated.is_some());
        let _ = std::fs::remove_file(path);
    }

    fn start_check_proxy(
        count: i64,
        wl_count: i64,
    ) -> (crate::config::Address, thread::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; crate::MAX_PACKET_SIZE];
            let (len, peer) = socket.recv_from(&mut buf).unwrap();
            let request = crate::message::Message::parse(&buf[..len]);
            assert_eq!(request.get("Op"), Some("check"));
            let thread = request.get("Thread").unwrap_or("1234");
            let response = format!(
                "Code: 200\nDiag: OK\nThread: {thread}\nPV: 2.1\nCount: {count}\nWL-Count: {wl_count}\n\n"
            );
            socket.send_to(response.as_bytes(), peer).unwrap();
        });
        (("127.0.0.1".to_string(), port), handle)
    }

    #[test]
    fn thread_limiter_blocks_until_permit_is_released() {
        let limiter = Arc::new(super::ThreadLimiter::new(1));
        let first = limiter.acquire();
        assert_eq!(limiter.active_count(), 1);

        let (tx, rx) = mpsc::channel();
        let worker_limiter = Arc::clone(&limiter);
        let worker = thread::spawn(move || {
            let _permit = worker_limiter.acquire();
            tx.send(()).unwrap();
        });

        thread::sleep(Duration::from_millis(50));
        assert!(rx.try_recv().is_err());
        drop(first);
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert_eq!(limiter.active_count(), 0);
    }
}
