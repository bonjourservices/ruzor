use std::env;
use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::net::UdpSocket;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::raw::{c_char, c_int, c_uint};
#[cfg(unix)]
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
#[cfg(unix)]
static RECEIVED_TERM: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
static RECEIVED_RELOAD: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(all(unix, target_os = "macos"))]
const SIGUSR1: i32 = 30;
#[cfg(unix)]
const WNOHANG: i32 = 1;
#[cfg(all(unix, not(target_os = "macos")))]
const SIGUSR1: i32 = 10;

#[cfg(unix)]
#[path = "ruzord/process_mode.rs"]
mod process_mode;
use ruzor::server::{self, ServerOptions};

#[derive(Debug, Default)]
struct ServerOverrides {
    address: bool,
    port: bool,
    engine: bool,
    digest_db: bool,
    passwd_file: bool,
    access_file: bool,
    log_file: bool,
    usage_log_file: bool,
    pid_file: bool,
    threads: bool,
    max_threads: bool,
    db_connections: bool,
    processes: bool,
    max_processes: bool,
    pre_fork: bool,
    cleanup_age: bool,
    forward_client_homedir: bool,
}

#[derive(Debug)]
struct ServerConfig {
    homedir: String,
    address: String,
    port: u16,
    engine: String,
    digest_db: String,
    passwd_file: String,
    access_file: String,
    log_file: String,
    usage_log_file: String,
    processes: bool,
    max_processes: usize,
    pre_fork: usize,
    pid_file: String,
    threads: bool,
    max_threads: usize,
    db_connections: usize,
    cleanup_age: Option<i64>,
    forward_client_homedir: String,
    detach: Option<String>,
    debug: bool,
    nice: i32,
    show_version: bool,
    show_help: bool,
    overrides: ServerOverrides,
}

#[derive(Debug)]
struct CliParseError(String);

impl std::fmt::Display for CliParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliParseError {}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{}", error);
            1
        }
    };
    std::process::exit(code);
}

#[cfg(unix)]
unsafe extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    fn fork() -> c_int;
    fn setsid() -> c_int;
    fn chdir(path: *const c_char) -> c_int;
    fn umask(mask: c_uint) -> c_uint;
    fn nice(increment: c_int) -> c_int;
    fn dup2(oldfd: c_int, newfd: c_int) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
}

#[cfg(unix)]
extern "C" fn handle_signal(signum: i32) {
    if signum == SIGTERM {
        RECEIVED_TERM.store(true, Ordering::Relaxed);
    } else if signum == SIGUSR1 {
        RECEIVED_RELOAD.store(true, Ordering::Relaxed);
    }
}

#[cfg(unix)]
fn install_signal_handlers() {
    // SAFETY: The handlers only set lock-free atomics and return.
    unsafe {
        signal(SIGTERM, handle_signal);
        signal(SIGUSR1, handle_signal);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

#[cfg(unix)]
fn set_private_umask() {
    // SAFETY: umask has no Rust preconditions. Python pyzord sets 0o077 at startup.
    unsafe {
        umask(0o077);
    }
}

#[cfg(not(unix))]
fn set_private_umask() {}

#[cfg(unix)]
fn apply_nice(increment: i32) -> io::Result<()> {
    if increment == 0 {
        return Ok(());
    }
    // SAFETY: nice changes only the current process priority, matching Python os.nice.
    let result = unsafe { nice(increment as c_int) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn apply_nice(_increment: i32) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn daemonize(stdout_path: &str, pid_file: &str) -> io::Result<()> {
    fork_or_exit_parent("Fork #1")?;
    // SAFETY: setsid has no Rust preconditions and is called in the first child.
    if unsafe { setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: chdir receives a static C string literal path.
    if unsafe { chdir(c"/".as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: umask has no Rust preconditions. Python pyzord uses umask(0) after setsid.
    unsafe {
        umask(0);
    }
    fork_or_exit_parent("Fork #2")?;

    let stdin = OpenOptions::new().read(true).open("/dev/null")?;
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(stdout_path)?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(stdout_path)?;

    fs::write(pid_file, format!("{}\n", process::id()))?;
    dup2_checked(stdin.as_raw_fd(), 0)?;
    dup2_checked(stdout.as_raw_fd(), 1)?;
    dup2_checked(stderr.as_raw_fd(), 2)?;
    Ok(())
}

#[cfg(unix)]
fn fork_or_exit_parent(stage: &str) -> io::Result<()> {
    // SAFETY: fork is called before starting background Rust threads in this process.
    match unsafe { fork() } {
        pid if pid < 0 => Err(io::Error::other(format!(
            "{} failed: {}",
            stage,
            io::Error::last_os_error()
        ))),
        0 => Ok(()),
        _ => process::exit(0),
    }
}

#[cfg(unix)]
fn dup2_checked(oldfd: c_int, newfd: c_int) -> io::Result<()> {
    // SAFETY: dup2 operates on valid file descriptors from open files above.
    if unsafe { dup2(oldfd, newfd) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn spawn_signal_monitor(
    shutdown: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !shutdown.load(Ordering::Relaxed) {
            if RECEIVED_TERM.swap(false, Ordering::Relaxed) {
                shutdown.store(true, Ordering::Relaxed);
            }
            if RECEIVED_RELOAD.swap(false, Ordering::Relaxed) {
                reload.store(true, Ordering::Relaxed);
            }
            thread::sleep(Duration::from_millis(50));
        }
    })
}

#[cfg(not(unix))]
fn spawn_signal_monitor(
    shutdown: Arc<AtomicBool>,
    _reload: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !shutdown.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(50));
        }
    })
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    set_private_umask();
    let mut args = env::args().collect::<Vec<_>>();
    let program = args.remove(0);
    let mut config = match parse_args(args) {
        Ok(config) => config,
        Err(error) => {
            print_parse_error("ruzord", &error);
            return Ok(2);
        }
    };
    if config.show_help {
        print_help();
        return Ok(0);
    }
    if config.show_version {
        eprintln!("{} {}", program, ruzor::VERSION);
        return Ok(0);
    }
    apply_nice(config.nice)?;
    fs::create_dir_all(&config.homedir)?;
    apply_config_file(&mut config);
    if config.engine != "gdbm"
        && config.engine != "redis"
        && config.engine != "redis_v0"
        && config.engine != "mysql"
    {
        return Err(format!("Unknown database engine: {}", config.engine).into());
    }
    if config.threads && config.processes {
        println!("You cannot use both processes and threads at the same time");
        return Ok(1);
    }
    if config.pre_fork == 1 {
        return Err("Pre-fork value cannot be lower than 2.".into());
    }
    if config.pre_fork > 0 && !supports_prefork(&config.engine) {
        return Err(format!(
            "Pre-fork mode is not supported by the {} backend.",
            config.engine
        )
        .into());
    }
    expand_config_paths(&mut config);
    let logger =
        ruzor::logging::Logger::new("ruzord", optional_path(&config.log_file), config.debug)?;
    let usage_logger = ruzor::logging::Logger::new(
        "ruzord-usage",
        optional_path(&config.usage_log_file),
        config.debug,
    )?;
    let detach_log = config.detach.clone();
    let cleanup_pidfile = detach_log.is_some();
    let pid_file = config.pid_file.clone();
    #[cfg(unix)]
    if let Some(log_path) = detach_log.as_deref() {
        daemonize(log_path, &pid_file)?;
    }

    #[cfg(not(unix))]
    if cleanup_pidfile {
        fs::write(&pid_file, format!("{}\n", std::process::id()))?;
    }
    #[cfg(unix)]
    if config.pre_fork > 0 {
        install_signal_handlers();
        eprintln!(
            "{} {} listening on {}:{}",
            program,
            ruzor::VERSION,
            config.address,
            config.port
        );
        logger.info("Starting ruzord server.");
        let result = run_prefork_server(&config, Some(logger.clone()), Some(usage_logger.clone()));
        if cleanup_pidfile {
            let _ = fs::remove_file(pid_file);
        }
        logger.info("Server shutdown.");
        result?;
        return Ok(0);
    }
    #[cfg(unix)]
    if config.processes && process_mode::supports_processes(&config.engine) {
        install_signal_handlers();
        eprintln!(
            "{} {} listening on {}:{}",
            program,
            ruzor::VERSION,
            config.address,
            config.port
        );
        logger.info(format!(
            "Starting bounded ({}) multi-processing ruzord server.",
            config.max_processes
        ));
        let result = process_mode::run_process_server(
            &config,
            Some(logger.clone()),
            Some(usage_logger.clone()),
        );
        if cleanup_pidfile {
            let _ = fs::remove_file(pid_file);
        }
        logger.info("Server shutdown.");
        result?;
        return Ok(0);
    }

    #[cfg(not(unix))]
    if config.pre_fork > 0 {
        return Err("Pre-fork mode is only supported on Unix.".into());
    }

    #[cfg(not(unix))]
    if config.processes && config.engine == "mysql" {
        return Err("Multi-processing mode is only supported on Unix.".into());
    }

    let mut forwarder_handle = if config.forward_client_homedir.is_empty() {
        None
    } else {
        Some(initialize_forwarding(&config.forward_client_homedir)?)
    };
    let server_forwarder = forwarder_handle.as_ref().map(|handle| handle.forwarder());
    install_signal_handlers();
    eprintln!(
        "{} {} listening on {}:{}",
        program,
        ruzor::VERSION,
        config.address,
        config.port
    );

    log_normal_starting(&logger, &config);
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));
    let signal_monitor = spawn_signal_monitor(Arc::clone(&shutdown), Arc::clone(&reload));
    let result = server::serve_with_control(
        ServerOptions {
            address: (config.address, config.port),
            database_path: config.digest_db,
            engine: config.engine,
            passwd_path: config.passwd_file,
            access_path: config.access_file,
            threads: config.threads,
            max_threads: config.max_threads,
            db_connections: config.db_connections,
            cleanup_age: config.cleanup_age,
            forwarder: server_forwarder,
            logger: Some(logger.clone()),
            usage_logger: Some(usage_logger.clone()),
        },
        Arc::clone(&shutdown),
        reload,
    );
    shutdown.store(true, Ordering::Relaxed);
    let _ = signal_monitor.join();
    if let Some(handle) = forwarder_handle.as_mut() {
        handle.stop();
    }
    if cleanup_pidfile {
        let _ = fs::remove_file(pid_file);
    }
    logger.info("Server shutdown.");
    result?;
    Ok(0)
}

fn supports_prefork(engine: &str) -> bool {
    matches!(engine, "redis" | "redis_v0" | "mysql")
}

fn server_options(
    config: &ServerConfig,
    forwarder: Option<ruzor::forwarder::Forwarder>,
    logger: Option<ruzor::logging::Logger>,
    usage_logger: Option<ruzor::logging::Logger>,
) -> ServerOptions {
    ServerOptions {
        address: (config.address.clone(), config.port),
        database_path: config.digest_db.clone(),
        engine: config.engine.clone(),
        passwd_path: config.passwd_file.clone(),
        access_path: config.access_file.clone(),
        threads: config.threads,
        max_threads: config.max_threads,
        db_connections: config.db_connections,
        cleanup_age: config.cleanup_age,
        forwarder,
        logger,
        usage_logger,
    }
}

#[cfg(unix)]
fn run_prefork_server(
    config: &ServerConfig,
    logger: Option<ruzor::logging::Logger>,
    usage_logger: Option<ruzor::logging::Logger>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind((config.address.as_str(), config.port))?;
    let mut pids = Vec::with_capacity(config.pre_fork);
    for _ in 0..config.pre_fork {
        let worker_socket = socket.try_clone()?;
        match unsafe { fork() } {
            pid if pid < 0 => {
                signal_children(&pids, SIGTERM);
                wait_for_children(&mut pids);
                return Err(io::Error::last_os_error().into());
            }
            0 => {
                RECEIVED_TERM.store(false, Ordering::Relaxed);
                RECEIVED_RELOAD.store(false, Ordering::Relaxed);
                install_signal_handlers();

                let mut forwarder_handle = if config.forward_client_homedir.is_empty() {
                    None
                } else {
                    match initialize_forwarding(&config.forward_client_homedir) {
                        Ok(handle) => Some(handle),
                        Err(error) => {
                            eprintln!("{error}");
                            process::exit(1);
                        }
                    }
                };
                let mut options = server_options(
                    config,
                    forwarder_handle.as_ref().map(|handle| handle.forwarder()),
                    logger.clone(),
                    usage_logger.clone(),
                );
                options.threads = false;
                options.max_threads = 0;
                let shutdown = Arc::new(AtomicBool::new(false));
                let reload = Arc::new(AtomicBool::new(false));
                let signal_monitor =
                    spawn_signal_monitor(Arc::clone(&shutdown), Arc::clone(&reload));
                let result = server::serve_bound_socket_with_control(
                    worker_socket,
                    options,
                    Arc::clone(&shutdown),
                    reload,
                );
                shutdown.store(true, Ordering::Relaxed);
                let _ = signal_monitor.join();
                if let Some(handle) = forwarder_handle.as_mut() {
                    handle.stop();
                }
                process::exit(if result.is_ok() { 0 } else { 1 });
            }
            pid => pids.push(pid),
        }
    }
    drop(socket);
    monitor_prefork_parent(&mut pids);
    Ok(())
}

#[cfg(unix)]
fn monitor_prefork_parent(pids: &mut Vec<c_int>) {
    while !pids.is_empty() {
        if RECEIVED_TERM.swap(false, Ordering::Relaxed) {
            signal_children(pids, SIGTERM);
            wait_for_children(pids);
            return;
        }
        if RECEIVED_RELOAD.swap(false, Ordering::Relaxed) {
            signal_children(pids, SIGUSR1);
        }
        reap_exited_children(pids);
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn signal_children(pids: &[c_int], signal: c_int) {
    for pid in pids {
        let _ = unsafe { kill(*pid, signal) };
    }
}

#[cfg(unix)]
fn reap_exited_children(pids: &mut Vec<c_int>) {
    pids.retain(|pid| {
        let mut status = 0;
        let result = unsafe { waitpid(*pid, &mut status, WNOHANG) };
        result == 0
    });
}

#[cfg(unix)]
fn wait_for_children(pids: &mut Vec<c_int>) {
    for pid in pids.drain(..) {
        let mut status = 0;
        loop {
            let result = unsafe { waitpid(pid, &mut status, 0) };
            if result == pid || result < 0 {
                break;
            }
        }
    }
}

#[derive(Clone, Debug)]
struct ForwardingConfig {
    client: ruzor::client::Client,
    servers: Vec<ruzor::config::Address>,
}

fn load_forwarding_config(
    client_config_dir: &str,
) -> Result<ForwardingConfig, Box<dyn std::error::Error>> {
    let values = ruzor::config::read_ini_section(format!("{}/config", client_config_dir), "client");
    let servers_file = values
        .get("serversfile")
        .cloned()
        .unwrap_or_else(|| "servers".to_string());
    let accounts_file = values
        .get("accountsfile")
        .cloned()
        .unwrap_or_else(|| "accounts".to_string());
    let timeout = values
        .get("timeout")
        .and_then(|value| value.parse().ok())
        .unwrap_or(5);

    let servers_path = ruzor::config::expand_homefile(client_config_dir, &servers_file);
    let accounts_path = ruzor::config::expand_homefile(client_config_dir, &accounts_file);
    let servers = ruzor::config::load_servers(servers_path);
    let accounts = ruzor::config::load_accounts(accounts_path);
    let client =
        ruzor::client::Client::new(accounts, Some(timeout), ruzor::digest::DIGEST_SPEC.to_vec());
    Ok(ForwardingConfig { client, servers })
}

fn initialize_forwarding(
    client_config_dir: &str,
) -> Result<ruzor::forwarder::ForwarderHandle, Box<dyn std::error::Error>> {
    let config = load_forwarding_config(client_config_dir)?;
    let batch_client = ruzor::client::BatchClient::new(config.client, 10);
    Ok(ruzor::forwarder::ForwarderHandle::start(
        batch_client,
        config.servers,
        10_000,
    ))
}

const PYZORD_LONG_OPTIONS: &[&str] = &[
    "--help",
    "--nice",
    "--debug",
    "--homedir",
    "--address",
    "--port",
    "--database-engine",
    "--dsn",
    "--gevent",
    "--threads",
    "--max-threads",
    "--processes",
    "--max-processes",
    "--db-connections",
    "--pre-fork",
    "--password-file",
    "--access-file",
    "--cleanup-age",
    "--log-file",
    "--usage-log-file",
    "--pid-file",
    "--forward-client-homedir",
    "--detach",
    "--version",
];

fn parse_args(args: Vec<String>) -> Result<ServerConfig, CliParseError> {
    let default_home = env::var("HOME")
        .map(|home| format!("{}/.ruzor", home))
        .unwrap_or_else(|_| "/etc/ruzor".to_string());
    let mut config = ServerConfig {
        homedir: default_home,
        address: "0.0.0.0".to_string(),
        port: 24441,
        engine: "gdbm".to_string(),
        digest_db: "ruzord.db".to_string(),
        passwd_file: "ruzord.passwd".to_string(),
        access_file: "ruzord.access".to_string(),
        log_file: String::new(),
        usage_log_file: String::new(),
        processes: false,
        max_processes: 40,
        pre_fork: 0,
        pid_file: "ruzord.pid".to_string(),
        threads: false,
        max_threads: 0,
        db_connections: 0,
        cleanup_age: Some(server::DEFAULT_CLEANUP_AGE),
        forward_client_homedir: String::new(),
        detach: None,
        debug: false,
        nice: 0,
        show_version: false,
        show_help: false,
        overrides: ServerOverrides::default(),
    };
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            config.show_help = iter.next().is_some();
            break;
        }
        let (option, inline_value) = parse_option_arg(&arg, PYZORD_LONG_OPTIONS)?;
        let option = option.as_str();
        match option {
            "-h" | "--help" => {
                reject_unexpected_value(option, inline_value)?;
                config.show_help = true;
            }
            "-V" | "--version" => {
                reject_unexpected_value(option, inline_value)?;
                config.show_version = true;
            }
            "-d" | "--debug" => {
                reject_unexpected_value(option, inline_value)?;
                config.debug = true;
            }
            "-n" | "--nice" => {
                config.nice =
                    parse_integer(option, option_value(option, inline_value, &mut iter)?)?;
            }
            "--homedir" => config.homedir = option_value(option, inline_value, &mut iter)?,
            "-a" | "--address" => {
                config.address = option_value(option, inline_value, &mut iter)?;
                config.overrides.address = true;
            }
            "-p" | "--port" => {
                config.port =
                    parse_integer(option, option_value(option, inline_value, &mut iter)?)?;
                config.overrides.port = true;
            }
            "-e" | "--database-engine" => {
                config.engine = option_value(option, inline_value, &mut iter)?;
                config.overrides.engine = true;
            }
            "--dsn" => {
                config.digest_db = option_value(option, inline_value, &mut iter)?;
                config.overrides.digest_db = true;
            }
            "--gevent" => {
                let _ = option_value(option, inline_value, &mut iter)?;
            }
            "--threads" => {
                config.threads =
                    option_value(option, inline_value, &mut iter)?.eq_ignore_ascii_case("true");
                config.overrides.threads = true;
            }
            "--max-threads" => {
                config.max_threads =
                    parse_integer(option, option_value(option, inline_value, &mut iter)?)?;
                config.overrides.max_threads = true;
            }

            "--processes" => {
                config.processes =
                    option_value(option, inline_value, &mut iter)?.eq_ignore_ascii_case("true");
                config.overrides.processes = true;
            }
            "--max-processes" => {
                config.max_processes =
                    parse_integer(option, option_value(option, inline_value, &mut iter)?)?;
                config.overrides.max_processes = true;
            }
            "--pre-fork" => {
                config.pre_fork =
                    parse_integer(option, option_value(option, inline_value, &mut iter)?)?;
                config.overrides.pre_fork = true;
            }
            "--cleanup-age" => {
                config.cleanup_age = Some(parse_integer(
                    option,
                    option_value(option, inline_value, &mut iter)?,
                )?);
                config.overrides.cleanup_age = true;
            }
            "--db-connections" => {
                config.db_connections =
                    parse_integer(option, option_value(option, inline_value, &mut iter)?)?;
                config.overrides.db_connections = true;
            }
            "--log-file" => {
                config.log_file = option_value(option, inline_value, &mut iter)?;
                config.overrides.log_file = true;
            }
            "--usage-log-file" => {
                config.usage_log_file = option_value(option, inline_value, &mut iter)?;
                config.overrides.usage_log_file = true;
            }
            "--forward-client-homedir" => {
                config.forward_client_homedir = option_value(option, inline_value, &mut iter)?;
                config.overrides.forward_client_homedir = true;
            }
            "--password-file" => {
                config.passwd_file = option_value(option, inline_value, &mut iter)?;
                config.overrides.passwd_file = true;
            }
            "--access-file" => {
                config.access_file = option_value(option, inline_value, &mut iter)?;
                config.overrides.access_file = true;
            }
            "--pid-file" => {
                config.pid_file = option_value(option, inline_value, &mut iter)?;
                config.overrides.pid_file = true;
            }
            "--detach" => config.detach = Some(option_value(option, inline_value, &mut iter)?),

            _ if !arg.starts_with('-') => config.show_help = true,
            _ => return Err(CliParseError(format!("no such option: {}", option))),
        }
    }
    Ok(config)
}

fn parse_option_arg(
    arg: &str,
    long_options: &[&str],
) -> Result<(String, Option<String>), CliParseError> {
    if arg.starts_with("--") {
        let (option, inline_value) = split_long_option(arg);
        return Ok((resolve_long_option(option, long_options)?, inline_value));
    }
    if arg.starts_with('-') && arg.len() > 2 {
        return Ok((arg[..2].to_string(), Some(arg[2..].to_string())));
    }
    Ok((arg.to_string(), None))
}

fn split_long_option(arg: &str) -> (&str, Option<String>) {
    if let Some((option, value)) = arg.split_once('=') {
        return (option, Some(value.to_string()));
    }
    (arg, None)
}

fn resolve_long_option(option: &str, long_options: &[&str]) -> Result<String, CliParseError> {
    if long_options.contains(&option) {
        return Ok(option.to_string());
    }
    let mut matches = long_options
        .iter()
        .copied()
        .filter(|candidate| candidate.starts_with(option))
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(CliParseError(format!("no such option: {}", option))),
        1 => Ok(matches.pop().unwrap().to_string()),
        _ => {
            matches.sort_unstable();
            Err(CliParseError(format!(
                "ambiguous option: {} ({}?)",
                option,
                matches.join(", ")
            )))
        }
    }
}

fn option_value(
    option: &str,
    inline_value: Option<String>,
    iter: &mut std::iter::Peekable<std::vec::IntoIter<String>>,
) -> Result<String, CliParseError> {
    inline_value
        .or_else(|| iter.next())
        .ok_or_else(|| CliParseError(format!("{} option requires 1 argument", option)))
}

fn reject_unexpected_value(
    option: &str,
    inline_value: Option<String>,
) -> Result<(), CliParseError> {
    if let Some(value) = inline_value {
        if option.starts_with('-')
            && !option.starts_with("--")
            && let Some(ch) = value.chars().next()
        {
            return Err(CliParseError(format!("no such option: -{}", ch)));
        }
        Err(CliParseError(format!(
            "{} option does not take a value",
            option
        )))
    } else {
        Ok(())
    }
}

fn parse_integer<T>(option: &str, value: String) -> Result<T, CliParseError>
where
    T: std::str::FromStr,
{
    value.parse().map_err(|_| {
        CliParseError(format!(
            "option {}: invalid integer value: '{}'",
            option, value
        ))
    })
}

const PYZORD_HELP: &str = r#"Usage: ruzord [options]

Listen for and process incoming Pyzor connections.

Options:
  -h, --help            show this help message and exit
  -n NICE, --nice=NICE  'nice' level
  -d, --debug           enable debugging output
  --homedir=HOMEDIR     configuration directory
  -a LISTENADDRESS, --address=LISTENADDRESS
                        listen on this IP
  -p PORT, --port=PORT  listen on this port
  -e ENGINE, --database-engine=ENGINE
                        select database backend
  --dsn=DIGESTDB        data source name (filename for gdbm,
                        host,user,password,database,table for MySQL)
  --gevent=GEVENT       set to true to use the gevent library
  --threads=THREADS     set to true if multi-threading should be used (this
                        may not apply to all engines)
  --max-threads=MAXTHREADS
                        the maximum number of concurrent threads (defaults to
                        0 which is unlimited)
  --processes=PROCESSES
                        set to true if multi-processing should be used (this
                        may not apply to all engines)
  --max-processes=MAXPROCESSES
                        the maximum number of concurrent processes (defaults
                        to 40)
  --db-connections=DBCONNECTIONS
                        the number of db connections that will be kept by the
                        server. This only applies if threads are used.
                        Defaults to 0 which means a new connection is used for
                        every thread. (this may not apply all engines)
  --pre-fork=PREFORK    
  --password-file=PASSWDFILE
                        name of password file
  --access-file=ACCESSFILE
                        name of ACL file
  --cleanup-age=CLEANUPAGE
                        time before digests expire (in seconds)
  --log-file=LOGFILE    name of the log file
  --usage-log-file=USAGELOGFILE
                        name of the usage log file
  --pid-file=PIDFILE    save the pid in this file after the server is
                        daemonized
  --forward-client-homedir=FORWARDCLIENTHOMEDIR
                        Specify a Ruzor client configuration directory to
                        forward received digests to a remote Pyzor-compatible server
  --detach=DETACH       daemonizes the server and redirects any output to the
                        specified file
  -V, --version         print version and exit
"#;

fn print_help() {
    print!("{}", PYZORD_HELP);
}

fn print_parse_error(program: &str, error: &CliParseError) {
    eprintln!("Usage: {} [options]\n", program);
    eprintln!("{}: error: {}", program, error);
}

fn apply_config_file(config: &mut ServerConfig) {
    let values = ruzor::config::read_ini_section(format!("{}/config", config.homedir), "server");
    for (key, value) in values {
        let key = key.to_ascii_lowercase();
        match key.as_str() {
            "port" if !config.overrides.port => config.port = value.parse().unwrap_or(config.port),
            "listenaddress" if !config.overrides.address => config.address = value,
            "engine" if !config.overrides.engine => config.engine = value,
            "digestdb" if !config.overrides.digest_db => config.digest_db = value,
            "threads" if !config.overrides.threads => {
                config.threads = value.eq_ignore_ascii_case("true")
            }
            "maxthreads" if !config.overrides.max_threads => {
                config.max_threads = value.parse().unwrap_or(config.max_threads)
            }
            "dbconnections" if !config.overrides.db_connections => {
                config.db_connections = value.parse().unwrap_or(config.db_connections)
            }
            "passwdfile" if !config.overrides.passwd_file => config.passwd_file = value,
            "accessfile" if !config.overrides.access_file => config.access_file = value,
            "logfile" if !config.overrides.log_file => config.log_file = value,
            "usagelogfile" if !config.overrides.usage_log_file => config.usage_log_file = value,
            "pidfile" if !config.overrides.pid_file => config.pid_file = value,
            "forwardclienthomedir" if !config.overrides.forward_client_homedir => {
                config.forward_client_homedir = value
            }
            "processes" if !config.overrides.processes => {
                config.processes = value.eq_ignore_ascii_case("true")
            }
            "maxprocesses" if !config.overrides.max_processes => {
                config.max_processes = value.parse().unwrap_or(config.max_processes)
            }
            "prefork" if !config.overrides.pre_fork => {
                config.pre_fork = value.parse().unwrap_or(config.pre_fork)
            }
            "cleanupage" if !config.overrides.cleanup_age => {
                config.cleanup_age = value.parse().ok()
            }

            _ => {}
        }
    }
}

fn expand_config_paths(config: &mut ServerConfig) {
    if config.engine == "gdbm" {
        config.digest_db = ruzor::config::expand_homefile(&config.homedir, &config.digest_db);
    }
    config.passwd_file = ruzor::config::expand_homefile(&config.homedir, &config.passwd_file);
    config.access_file = ruzor::config::expand_homefile(&config.homedir, &config.access_file);
    if !config.log_file.is_empty() {
        config.log_file = ruzor::config::expand_homefile(&config.homedir, &config.log_file);
    }
    if !config.usage_log_file.is_empty() {
        config.usage_log_file =
            ruzor::config::expand_homefile(&config.homedir, &config.usage_log_file);
    }
    config.pid_file = ruzor::config::expand_homefile(&config.homedir, &config.pid_file);
}

fn optional_path(path: &str) -> Option<String> {
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

fn log_normal_starting(logger: &ruzor::logging::Logger, config: &ServerConfig) {
    if config.threads && config.max_threads == 0 {
        logger.info("Starting multi-threaded ruzord server.");
    } else if config.threads {
        logger.info(format!(
            "Starting bounded ({}) multi-threaded ruzord server.",
            config.max_threads
        ));
    } else {
        logger.info("Starting ruzord server.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_homedir(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!("ruzord-server-{name}-{nanos}"));
        std::fs::create_dir_all(&path).unwrap();
        path.to_string_lossy().to_string()
    }

    #[test]
    fn config_file_overrides_defaults() {
        let homedir = temp_homedir("config-defaults");
        std::fs::write(
            format!("{homedir}/config"),
            "[server]\nPort = 9999\nListenAddress = 127.0.0.1\nEngine = redis\nDigestDB = configdb\n",
        )
        .unwrap();
        let mut config = parse_args(vec!["--homedir".into(), homedir.clone()]).unwrap();
        apply_config_file(&mut config);
        assert_eq!(config.port, 9999);
        assert_eq!(config.address, "127.0.0.1");
        assert_eq!(config.engine, "redis");
        assert_eq!(config.digest_db, "configdb");
        let _ = std::fs::remove_dir_all(homedir);
    }

    #[test]
    fn config_file_option_names_are_case_insensitive_like_python() {
        let homedir = temp_homedir("config-case-insensitive");
        std::fs::write(
            format!("{homedir}/config"),
            "[server]
port = 9999
listenaddress = 127.0.0.1
engine = redis
digestdb = configdb
threads = True
maxthreads = 5
dbconnections = 7
passwdfile = config.passwd
accessfile = config.access
pidfile = config.pid
forwardclienthomedir = forward-home
processes = True
maxprocesses = 6
prefork = 3
cleanupage = 9
",
        )
        .unwrap();
        let mut config = parse_args(vec!["--homedir".into(), homedir.clone()]).unwrap();
        apply_config_file(&mut config);
        assert_eq!(config.port, 9999);
        assert_eq!(config.address, "127.0.0.1");
        assert_eq!(config.engine, "redis");
        assert_eq!(config.digest_db, "configdb");
        assert!(config.threads);
        assert_eq!(config.max_threads, 5);
        assert_eq!(config.db_connections, 7);
        assert_eq!(config.passwd_file, "config.passwd");
        assert_eq!(config.access_file, "config.access");
        assert_eq!(config.pid_file, "config.pid");
        assert_eq!(config.forward_client_homedir, "forward-home");
        assert!(config.processes);
        assert_eq!(config.max_processes, 6);
        assert_eq!(config.pre_fork, 3);
        assert_eq!(config.cleanup_age, Some(9));
        let _ = std::fs::remove_dir_all(homedir);
    }

    #[test]
    fn command_line_overrides_config_file() {
        let homedir = temp_homedir("cli-overrides");
        std::fs::write(
            format!("{homedir}/config"),
            "[server]\nPort = 9999\nListenAddress = 127.0.0.1\nEngine = redis\nDigestDB = configdb\n",
        )
        .unwrap();
        let mut config = parse_args(vec![
            "--homedir".into(),
            homedir.clone(),
            "-p".into(),
            "1111".into(),
            "-a".into(),
            "0.0.0.0".into(),
            "-e".into(),
            "gdbm".into(),
            "--dsn".into(),
            "clidb".into(),
        ])
        .unwrap();
        apply_config_file(&mut config);
        assert_eq!(config.port, 1111);
        assert_eq!(config.address, "0.0.0.0");
        assert_eq!(config.engine, "gdbm");
        assert_eq!(config.digest_db, "clidb");
        let _ = std::fs::remove_dir_all(homedir);
    }

    #[test]
    fn forwarding_client_config_option_names_are_case_insensitive_like_python() {
        let homedir = temp_homedir("forward-client-config-case");
        std::fs::write(
            format!("{homedir}/config"),
            "[client]
serversfile = custom_servers
accountsfile = custom_accounts
timeout = 1
",
        )
        .unwrap();
        std::fs::write(
            format!("{homedir}/custom_servers"),
            "127.0.0.1:24441
",
        )
        .unwrap();
        std::fs::write(format!("{homedir}/custom_accounts"), "").unwrap();

        let config = load_forwarding_config(&homedir).unwrap();

        assert_eq!(config.servers, vec![("127.0.0.1".to_string(), 24441)]);
        let _ = std::fs::remove_dir_all(homedir);
    }

    #[test]
    fn redis_dsn_is_not_expanded_as_homefile() {
        let homedir = temp_homedir("redis-dsn");
        let dsn = "127.0.0.1,6379,,0";
        let mut config = parse_args(vec![
            "--homedir".into(),
            homedir.clone(),
            "-e".into(),
            "redis".into(),
            "--dsn".into(),
            dsn.into(),
        ])
        .unwrap();
        expand_config_paths(&mut config);
        assert_eq!(config.digest_db, dsn);
        assert!(config.passwd_file.starts_with(&homedir));
        let _ = std::fs::remove_dir_all(homedir);
    }

    #[test]
    fn process_options_are_parsed_for_python_fallback_path() {
        let config = parse_args(vec![
            "--processes".into(),
            "true".into(),
            "--max-processes".into(),
            "7".into(),
            "--pre-fork".into(),
            "0".into(),
        ])
        .unwrap();
        assert!(config.processes);
        assert_eq!(config.max_processes, 7);
        assert_eq!(config.pre_fork, 0);
    }

    #[test]
    fn db_connections_is_parsed_and_config_override_matches_python() {
        let config = parse_args(vec!["--db-connections".into(), "3".into()]).unwrap();
        assert_eq!(config.db_connections, 3);
        assert_eq!(server_options(&config, None, None, None).db_connections, 3);

        let homedir = temp_homedir("db-connections");
        std::fs::write(format!("{homedir}/config"), "[server]\nDBConnections = 9\n").unwrap();

        let mut config = parse_args(vec!["--homedir".into(), homedir.clone()]).unwrap();
        apply_config_file(&mut config);
        assert_eq!(config.db_connections, 9);

        let mut config = parse_args(vec![
            "--homedir".into(),
            homedir.clone(),
            "--db-connections".into(),
            "4".into(),
        ])
        .unwrap();
        apply_config_file(&mut config);
        assert_eq!(config.db_connections, 4);
        let _ = std::fs::remove_dir_all(homedir);
    }

    #[test]
    fn cleanup_age_is_parsed_and_applied_to_server_options() {
        let default_config = parse_args(vec![]).unwrap();
        assert_eq!(
            default_config.cleanup_age,
            Some(server::DEFAULT_CLEANUP_AGE)
        );

        let config = parse_args(vec!["--cleanup-age".into(), "3".into()]).unwrap();
        assert_eq!(config.cleanup_age, Some(3));
        let options = server_options(&config, None, None, None);
        assert_eq!(options.cleanup_age, Some(3));
        assert_eq!(options.db_connections, 0);
    }

    #[test]
    fn cleanup_age_config_respects_command_line_override() {
        let homedir = temp_homedir("cleanup-age");
        std::fs::write(format!("{homedir}/config"), "[server]\nCleanupAge = 9\n").unwrap();

        let mut config = parse_args(vec!["--homedir".into(), homedir.clone()]).unwrap();
        apply_config_file(&mut config);
        assert_eq!(config.cleanup_age, Some(9));

        let mut config = parse_args(vec![
            "--homedir".into(),
            homedir.clone(),
            "--cleanup-age".into(),
            "4".into(),
        ])
        .unwrap();
        apply_config_file(&mut config);
        assert_eq!(config.cleanup_age, Some(4));
        let _ = std::fs::remove_dir_all(homedir);
    }
}
