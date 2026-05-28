use std::env;
use std::fs;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::raw::{c_char, c_int, c_long, c_uint};

use pyzor::client::Client;
use pyzor::config::{self, Address};
use pyzor::digest;
use pyzor::message::Message;

#[derive(Debug, Default)]
struct ClientOverrides {
    servers_file: bool,
    accounts_file: bool,
    local_whitelist: bool,
    log_file: bool,
    timeout: bool,
    style: bool,
    report_threshold: bool,
    whitelist_threshold: bool,
}

#[derive(Debug)]
struct ClientConfig {
    homedir: String,
    servers_file: String,
    accounts_file: String,
    local_whitelist: String,
    log_file: String,
    timeout: u64,
    style: String,
    report_threshold: i64,
    whitelist_threshold: i64,
    debug: bool,
    nice: i32,
    show_version: bool,
    show_help: bool,
    overrides: ClientOverrides,
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

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    set_private_umask();
    let mut args = env::args().collect::<Vec<_>>();
    let program = args.remove(0);
    let (mut config, commands) = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            print_parse_error("pyzor", &error);
            return Ok(2);
        }
    };
    if config.show_help {
        print_help();
        return Ok(0);
    }
    if config.show_version {
        println!("{} {}", program, pyzor::VERSION);
        return Ok(0);
    }
    if commands.is_empty() {
        print_help();
        return Ok(0);
    }

    apply_nice(config.nice)?;
    fs::create_dir_all(&config.homedir)?;
    apply_config_file(&mut config);
    expand_config_paths(&mut config);
    let logger =
        pyzor::logging::Logger::new("pyzor", optional_path(&config.log_file), config.debug)?;
    if !servers_file_has_entries(&config.servers_file) {
        logger.info("No servers specified, defaulting to public.pyzor.org.");
    }
    let servers = config::load_servers(&config.servers_file);
    let accounts = config::load_accounts_with_logger(&config.accounts_file, Some(&logger));
    let client = Client::new(accounts, Some(config.timeout), digest::DIGEST_SPEC.to_vec())
        .with_logger(logger.clone());

    let mut stdin = io::stdin();
    let mut exit_code = 0;
    for command in commands {
        let mut input = Vec::new();
        if command_reads_stdin(&command) {
            stdin.read_to_end(&mut input)?;
        }
        let command_ok = execute(&command, &client, &servers, &config, &input, &logger)?;
        if !command_ok {
            exit_code = 1;
        }
    }
    Ok(exit_code)
}

#[cfg(unix)]
unsafe extern "C" {
    fn umask(mask: c_uint) -> c_uint;
    fn nice(increment: c_int) -> c_int;
}

#[cfg(unix)]
fn set_private_umask() {
    // SAFETY: umask has no Rust preconditions. Python pyzor sets 0o077 at startup.
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

const PYZOR_LONG_OPTIONS: &[&str] = &[
    "--help",
    "--nice",
    "--debug",
    "--homedir",
    "--style",
    "--log-file",
    "--servers-file",
    "--accounts-file",
    "--local-whitelist",
    "--timeout",
    "--report-threshold",
    "--whitelist-threshold",
    "--version",
];

fn parse_args(args: Vec<String>) -> Result<(ClientConfig, Vec<String>), CliParseError> {
    let default_home = env::var("HOME")
        .map(|home| format!("{}/.pyzor", home))
        .unwrap_or_else(|_| "/etc/pyzor".to_string());
    let mut config = ClientConfig {
        homedir: default_home,
        servers_file: "servers".to_string(),
        accounts_file: "accounts".to_string(),
        local_whitelist: "whitelist".to_string(),
        log_file: String::new(),
        timeout: 5,
        style: "msg".to_string(),
        report_threshold: 0,
        whitelist_threshold: 0,
        debug: false,
        nice: 0,
        show_version: false,
        show_help: false,
        overrides: ClientOverrides::default(),
    };
    let mut commands = Vec::new();
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            commands.extend(iter);
            break;
        }
        let (option, inline_value) = parse_option_arg(&arg, PYZOR_LONG_OPTIONS)?;
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
            "-s" | "--style" => {
                config.style = option_value(option, inline_value, &mut iter)?;
                config.overrides.style = true;
            }

            "--log-file" => {
                config.log_file = option_value(option, inline_value, &mut iter)?;
                config.overrides.log_file = true;
            }
            "--servers-file" => {
                config.servers_file = option_value(option, inline_value, &mut iter)?;
                config.overrides.servers_file = true;
            }
            "--accounts-file" => {
                config.accounts_file = option_value(option, inline_value, &mut iter)?;
                config.overrides.accounts_file = true;
            }
            "--local-whitelist" => {
                config.local_whitelist = option_value(option, inline_value, &mut iter)?;
                config.overrides.local_whitelist = true;
            }
            "-t" | "--timeout" => {
                config.timeout =
                    parse_integer(option, option_value(option, inline_value, &mut iter)?)?;
                config.overrides.timeout = true;
            }
            "-r" | "--report-threshold" => {
                config.report_threshold =
                    parse_integer(option, option_value(option, inline_value, &mut iter)?)?;
                config.overrides.report_threshold = true;
            }
            "-w" | "--whitelist-threshold" => {
                config.whitelist_threshold =
                    parse_integer(option, option_value(option, inline_value, &mut iter)?)?;
                config.overrides.whitelist_threshold = true;
            }

            _ if arg.starts_with('-') => {
                return Err(CliParseError(format!("no such option: {}", option)));
            }
            _ => commands.push(arg),
        }
    }
    Ok((config, commands))
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

fn apply_config_file(config: &mut ClientConfig) {
    let values = config::read_ini_section(format!("{}/config", config.homedir), "client");
    for (key, value) in values {
        let key = key.to_ascii_lowercase();
        match key.as_str() {
            "serversfile" if !config.overrides.servers_file => config.servers_file = value,
            "accountsfile" if !config.overrides.accounts_file => config.accounts_file = value,
            "localwhitelist" if !config.overrides.local_whitelist => config.local_whitelist = value,
            "logfile" if !config.overrides.log_file => config.log_file = value,
            "timeout" if !config.overrides.timeout => {
                config.timeout = value.parse().unwrap_or(config.timeout)
            }
            "style" if !config.overrides.style => config.style = value,
            "reportthreshold" if !config.overrides.report_threshold => {
                config.report_threshold = value.parse().unwrap_or(config.report_threshold);
            }
            "whitelistthreshold" if !config.overrides.whitelist_threshold => {
                config.whitelist_threshold = value.parse().unwrap_or(config.whitelist_threshold);
            }
            _ => {}
        }
    }
}

fn command_reads_stdin(command: &str) -> bool {
    matches!(
        command,
        "pong"
            | "check"
            | "info"
            | "report"
            | "whitelist"
            | "digest"
            | "predigest"
            | "local_whitelist"
            | "local_unwhitelist"
    )
}

fn expand_config_paths(config: &mut ClientConfig) {
    config.servers_file = config::expand_homefile(&config.homedir, &config.servers_file);
    config.accounts_file = config::expand_homefile(&config.homedir, &config.accounts_file);
    config.local_whitelist = config::expand_homefile(&config.homedir, &config.local_whitelist);
    if !config.log_file.is_empty() {
        config.log_file = config::expand_homefile(&config.homedir, &config.log_file);
    }
}

fn optional_path(path: &str) -> Option<String> {
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

fn servers_file_has_entries(path: &str) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    text.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        let Some((host, port)) = line.rsplit_once(':') else {
            return false;
        };
        !host.is_empty()
            && host
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ".-".contains(ch))
            && port.parse::<u16>().is_ok()
    })
}

fn execute(
    command: &str,
    client: &Client,
    servers: &[Address],
    config: &ClientConfig,
    input: &[u8],
    logger: &pyzor::logging::Logger,
) -> Result<bool, Box<dyn std::error::Error>> {
    match command {
        "ping" => command_ping(client, servers),
        "pong" => command_check_like(client, servers, config, input, "pong"),
        "check" => command_check_like(client, servers, config, input, "check"),
        "info" => command_info(client, servers, config, input),
        "report" => command_simple_digest(client, servers, config, input, "report"),
        "whitelist" => command_simple_digest(client, servers, config, input, "whitelist"),
        "digest" => {
            for digest in input_digests(&config.style, input)? {
                if !digest.is_empty() {
                    println!("{}", digest);
                }
            }
            Ok(true)
        }
        "predigest" => {
            for line in digest::predigest_message(input) {
                println!("{}", line);
            }
            Ok(true)
        }
        "local_whitelist" => command_local_whitelist(config, input, true, logger),
        "local_unwhitelist" => command_local_whitelist(config, input, false, logger),
        "genkey" => command_genkey(),
        _ => {
            logger.critical(format!("Unknown command: {}", command));
            Ok(true)
        }
    }
}

fn command_ping(client: &Client, servers: &[Address]) -> Result<bool, Box<dyn std::error::Error>> {
    let mut all_ok = true;
    for server in servers {
        match client.ping(server) {
            Ok(response) => {
                if !response.is_ok() {
                    all_ok = false;
                }
                print_status(server, &response);
            }
            Err(error) => {
                all_ok = false;
                println!("{}:{}\t({}, '{}')", server.0, server.1, error.code(), error);
            }
        }
    }
    Ok(all_ok)
}

fn command_simple_digest(
    client: &Client,
    servers: &[Address],
    config: &ClientConfig,
    input: &[u8],
    command: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut all_ok = true;
    for digest in input_digests(&config.style, input)? {
        if digest.is_empty() {
            continue;
        }
        for server in servers {
            let result = match command {
                "report" => client.report(&digest, server),
                "whitelist" => client.whitelist(&digest, server),
                _ => unreachable!(),
            };
            match result {
                Ok(response) => {
                    if !response.is_ok() {
                        all_ok = false;
                    }
                    print_status(server, &response);
                }
                Err(error) => {
                    all_ok = false;
                    println!("{}:{}\t({}, '{}')", server.0, server.1, error.code(), error);
                }
            }
        }
    }
    Ok(all_ok)
}

fn command_check_like(
    client: &Client,
    servers: &[Address],
    config: &ClientConfig,
    input: &[u8],
    command: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut all_ok = true;
    let mut found_hit = false;
    let mut whitelisted = false;
    let local = if command == "check" {
        config::load_local_whitelist(&config.local_whitelist)
    } else {
        Default::default()
    };
    let mut local_results = Vec::new();
    let mut remote_results = Vec::new();

    for digest in input_digests(&config.style, input)? {
        if digest.is_empty() {
            continue;
        }
        for server in servers {
            let local_match = command == "check" && local.contains(&digest);
            let response = if local_match {
                mock_check_response()
            } else if command == "pong" {
                client.pong(&digest, server)
            } else {
                client.check(&digest, server)
            };
            match response {
                Ok(response) => {
                    if !local_match && !response.is_ok() {
                        all_ok = false;
                        remote_results.push(format!(
                            "{}:{}\t{}\t",
                            server.0,
                            server.1,
                            response.head_tuple()
                        ));
                        continue;
                    }

                    let count = response
                        .get("Count")
                        .unwrap_or("0")
                        .parse::<i64>()
                        .unwrap_or(0);
                    let wl_count = response
                        .get("WL-Count")
                        .unwrap_or("0")
                        .parse::<i64>()
                        .unwrap_or(0);
                    if !local_match {
                        if wl_count > config.whitelist_threshold {
                            whitelisted = true;
                        } else if count > config.report_threshold {
                            found_hit = true;
                        }
                        remote_results.push(format!(
                            "{}:{}\t{}\t{}\t{}",
                            server.0,
                            server.1,
                            response.head_tuple(),
                            count,
                            wl_count
                        ));
                    } else {
                        local_results.push(format!(
                            "{}:{}\t{}\t{}\t{}",
                            server.0,
                            server.1,
                            response.head_tuple(),
                            count,
                            wl_count
                        ));
                    }
                }
                Err(error) => {
                    all_ok = false;
                    remote_results.push(format!(
                        "{}:{}\t({}, '{}')",
                        server.0,
                        server.1,
                        error.code(),
                        error
                    ));
                }
            }
        }
    }

    for line in local_results.iter().chain(remote_results.iter()) {
        println!("{}", line);
    }
    Ok(all_ok && found_hit && !whitelisted)
}

fn command_info(
    client: &Client,
    servers: &[Address],
    config: &ClientConfig,
    input: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut all_ok = true;
    for digest in input_digests(&config.style, input)? {
        if digest.is_empty() {
            continue;
        }
        for server in servers {
            match client.info(&digest, server) {
                Ok(response) => {
                    if !response.is_ok() {
                        all_ok = false;
                    }
                    println!("{}:{}\t{}", server.0, server.1, response.head_tuple());
                    if response.is_ok() {
                        for key in [
                            "Count",
                            "Entered",
                            "Updated",
                            "WL-Count",
                            "WL-Entered",
                            "WL-Updated",
                        ] {
                            if let Some(value) = response.get(key) {
                                println!("\t{}: {}", key, format_info_value(key, value));
                            }
                        }
                    }
                    println!();
                }
                Err(error) => {
                    all_ok = false;
                    println!("{}:{}\t({}, '{}')", server.0, server.1, error.code(), error);
                }
            }
        }
    }
    Ok(all_ok)
}

fn command_local_whitelist(
    config: &ClientConfig,
    input: &[u8],
    add: bool,
    logger: &pyzor::logging::Logger,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut whitelist = config::load_local_whitelist(&config.local_whitelist);
    for digest in input_digests(&config.style, input)? {
        if add {
            if whitelist.contains(&digest) {
                logger.critical(format!("Digest {digest} already whitelisted locally"));
            }
            whitelist.insert(digest);
        } else if whitelist.contains(&digest) {
            whitelist.remove(&digest);
        } else {
            logger.critical(format!("Digest {digest} is not whitelisted."));
        }
    }
    config::write_local_whitelist(&config.local_whitelist, &whitelist)?;
    Ok(true)
}

fn command_genkey() -> Result<bool, Box<dyn std::error::Error>> {
    let password = read_passphrase("Enter passphrase: ")?;
    let confirmation = read_passphrase("Enter passphrase again: ")?;
    if confirmation != password {
        eprintln!("Passwords do not match.");
        return Ok(false);
    }
    let salt = random_salt()?;
    let (salt_digest, key) = genkey_from_password_and_salt(&password, &salt);
    println!("salt,key:");
    println!("{},{}", salt_digest, key);
    Ok(true)
}

fn read_passphrase(prompt: &str) -> io::Result<String> {
    eprint!("{}", prompt);
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\n', '\r']).to_string())
}

fn random_salt() -> io::Result<[u8; 20]> {
    let mut salt = [0u8; 20];
    fs::File::open("/dev/urandom")?.read_exact(&mut salt)?;
    Ok(salt)
}

fn genkey_from_password_and_salt(password: &str, salt: &[u8]) -> (String, String) {
    let salt_digest_bytes = pyzor::sha1::digest(salt);
    let salt_digest = pyzor::sha1::hexdigest(salt);
    let mut key_input = Vec::with_capacity(salt_digest_bytes.len() + password.len());
    key_input.extend_from_slice(&salt_digest_bytes);
    key_input.extend_from_slice(password.as_bytes());
    (salt_digest, pyzor::sha1::hexdigest(&key_input))
}

fn input_digests(style: &str, input: &[u8]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    match style {
        "digests" => Ok(String::from_utf8_lossy(input)
            .lines()
            .map(|line| line.trim().to_string())
            .collect()),
        "mbox" => Ok(digest::digest_mbox(input)),
        "msg" => Ok(vec![digest::digest_message(input)]),
        _ => Err("Unknown input style.".into()),
    }
}

fn print_status(server: &Address, response: &Message) {
    println!("{}:{}\t{}", server.0, server.1, response.head_tuple());
}

fn mock_check_response() -> pyzor::Result<Message> {
    Ok(Message::parse(
        b"Code: 200\nDiag: OK\nPV: 2.1\nThread: 1024\nCount: 0\nWL-Count: 0\n\n",
    ))
}

const PYZOR_HELP: &str = r#"Usage: pyzor [options]

Read data from stdin and execute the requested command (one of 'check',
'report', 'ping', 'pong', 'digest', 'predigest', 'genkey', 'local_whitelist',
'local_unwhitelist').

Options:
  -h, --help            show this help message and exit
  -n NICE, --nice=NICE  'nice' level
  -d, --debug           enable debugging output
  --homedir=HOMEDIR     configuration directory
  -s STYLE, --style=STYLE
                        input style: 'msg' (individual RFC5321 message),
                        'mbox' (mbox file of messages), 'digests' (Pyzor
                        digests, one per line).
  --log-file=LOGFILE    name of log file
  --servers-file=SERVERSFILE
                        name of servers file
  --accounts-file=ACCOUNTSFILE
                        name of accounts file
  --local-whitelist=LOCALWHITELIST
                        name of the local whitelist file
  -t TIMEOUT, --timeout=TIMEOUT
                        timeout (in seconds)
  -r REPORTTHRESHOLD, --report-threshold=REPORTTHRESHOLD
                        threshold for number of reports
  -w WHITELISTTHRESHOLD, --whitelist-threshold=WHITELISTTHRESHOLD
                        threshold for number of whitelist
  -V, --version         print version and exit
"#;

fn print_help() {
    print!("{}", PYZOR_HELP);
}

fn print_parse_error(program: &str, error: &CliParseError) {
    eprintln!("Usage: {} [options]\n", program);
    eprintln!("{}: error: {}", program, error);
}
fn format_info_value(key: &str, value: &str) -> String {
    let value = value.parse::<i64>().unwrap_or(0);
    if key.contains("Count") {
        value.to_string()
    } else if value == -1 {
        "Never".to_string()
    } else {
        ctime_python(value)
    }
}

#[cfg(unix)]
#[repr(C)]
struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: *const c_char,
}

#[cfg(unix)]
type TimeT = i64;
#[cfg(unix)]
static TZ_INIT: std::sync::Once = std::sync::Once::new();

#[cfg(unix)]
fn initialize_local_timezone() {
    TZ_INIT.call_once(|| {
        if std::env::var_os("TZ").is_none()
            && let Ok(path) = std::fs::read_link("/etc/localtime")
            && let Some(zone) = timezone_name_from_localtime_path(&path)
        {
            // SAFETY: this one-time initialization runs before formatting through libc;
            // no pyzor worker threads are active in the client process at this point.
            unsafe {
                std::env::set_var("TZ", zone);
                tzset();
            }
        }
    });
}

#[cfg(unix)]
fn timezone_name_from_localtime_path(path: &std::path::Path) -> Option<String> {
    let text = path.to_string_lossy();
    text.split_once("zoneinfo/")
        .map(|(_, zone)| zone.to_string())
        .filter(|zone| !zone.is_empty())
}

#[cfg(unix)]
unsafe extern "C" {
    fn localtime_r(timep: *const TimeT, result: *mut Tm) -> *mut Tm;
    fn tzset();
}

#[cfg(unix)]
fn ctime_python(timestamp: i64) -> String {
    initialize_local_timezone();
    let time = timestamp as TimeT;
    let mut tm = std::mem::MaybeUninit::<Tm>::uninit();
    let tm = unsafe {
        if localtime_r(&time, tm.as_mut_ptr()).is_null() {
            return ctime_utc(timestamp);
        }
        tm.assume_init()
    };
    let weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let weekday = weekdays.get(tm.tm_wday as usize).unwrap_or(&"???");
    let month = months.get(tm.tm_mon as usize).unwrap_or(&"???");
    format!(
        "{} {} {:>2} {:02}:{:02}:{:02} {}",
        weekday,
        month,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        tm.tm_year + 1900
    )
}

#[cfg(not(unix))]
fn ctime_python(timestamp: i64) -> String {
    initialize_local_timezone();
    ctime_utc(timestamp)
}

fn ctime_utc(timestamp: i64) -> String {
    let (year, month, day, hour, minute, second, weekday) = unix_to_utc(timestamp);
    let weekdays = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{} {} {:>2} {:02}:{:02}:{:02} {}",
        weekdays[weekday as usize],
        months[(month - 1) as usize],
        day,
        hour,
        minute,
        second,
        year
    )
}

fn unix_to_utc(timestamp: i64) -> (i64, i64, i64, i64, i64, i64, i64) {
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3600;
    let minute = (seconds % 3600) / 60;
    let second = seconds % 60;
    let weekday = days.rem_euclid(7);
    (year, month, day, hour, minute, second, weekday)
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    #[cfg(unix)]
    static TZ_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn temp_homedir(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!("pyzor-client-{name}-{nanos}"));
        std::fs::create_dir_all(&path).unwrap();
        path.to_string_lossy().to_string()
    }

    #[test]
    fn config_file_overrides_defaults() {
        let homedir = temp_homedir("config-defaults");
        std::fs::write(
            format!("{homedir}/config"),
            "[client]\nStyle = mbox\nTimeout = 12\nServersFile = config_servers\n",
        )
        .unwrap();
        let (mut config, commands) =
            parse_args(vec!["--homedir".into(), homedir.clone(), "digest".into()]).unwrap();
        apply_config_file(&mut config);
        assert_eq!(commands, vec!["digest"]);
        assert_eq!(config.style, "mbox");
        assert_eq!(config.timeout, 12);
        assert_eq!(config.servers_file, "config_servers");
        let _ = std::fs::remove_dir_all(homedir);
    }

    #[test]
    fn config_file_option_names_are_case_insensitive_like_python() {
        let homedir = temp_homedir("config-case-insensitive");
        std::fs::write(
            format!("{homedir}/config"),
            "[client]
style = mbox
timeout = 12
serversfile = config_servers
accountsfile = config_accounts
localwhitelist = config_whitelist
reportthreshold = 7
whitelistthreshold = 8
",
        )
        .unwrap();
        let (mut config, commands) =
            parse_args(vec!["--homedir".into(), homedir.clone(), "digest".into()]).unwrap();
        apply_config_file(&mut config);
        assert_eq!(commands, vec!["digest"]);
        assert_eq!(config.style, "mbox");
        assert_eq!(config.timeout, 12);
        assert_eq!(config.servers_file, "config_servers");
        assert_eq!(config.accounts_file, "config_accounts");
        assert_eq!(config.local_whitelist, "config_whitelist");
        assert_eq!(config.report_threshold, 7);
        assert_eq!(config.whitelist_threshold, 8);
        let _ = std::fs::remove_dir_all(homedir);
    }

    #[test]
    fn command_line_overrides_config_file() {
        let homedir = temp_homedir("cli-overrides");
        std::fs::write(
            format!("{homedir}/config"),
            "[client]\nStyle = mbox\nTimeout = 12\nServersFile = config_servers\n",
        )
        .unwrap();
        let (mut config, _) = parse_args(vec![
            "--homedir".into(),
            homedir.clone(),
            "-s".into(),
            "digests".into(),
            "-t".into(),
            "2".into(),
            "--servers-file".into(),
            "cli_servers".into(),
            "digest".into(),
        ])
        .unwrap();
        apply_config_file(&mut config);
        assert_eq!(config.style, "digests");
        assert_eq!(config.timeout, 2);
        assert_eq!(config.servers_file, "cli_servers");
        let _ = std::fs::remove_dir_all(homedir);
    }

    #[test]
    fn genkey_uses_python_salt_and_password_hashing() {
        let (salt, key) = genkey_from_password_and_salt("secret", b"01234567890123456789");
        assert_eq!(salt, "88a7b59d2e9172960b72b65f7839b9da2453f3e9");
        assert_eq!(key, "b17bc41487c2b6c7d193560852ba3164cef31a79");
    }

    #[test]
    fn info_values_match_python_runner_rules() {
        assert_eq!(format_info_value("Count", "4"), "4");
        assert_eq!(format_info_value("WL-Entered", "-1"), "Never");
    }

    #[test]
    #[cfg(unix)]
    fn extracts_system_timezone_name_from_zoneinfo_symlink() {
        assert_eq!(
            timezone_name_from_localtime_path(std::path::Path::new(
                "/var/db/timezone/zoneinfo/Europe/Paris"
            )),
            Some("Europe/Paris".to_string())
        );
    }

    #[test]
    #[cfg(unix)]
    fn ctime_matches_python_time_ctime_under_utc() {
        let _guard = TZ_TEST_LOCK.lock().unwrap();
        let previous = std::env::var_os("TZ");
        // SAFETY: this test holds TZ_TEST_LOCK while mutating TZ and refreshing libc timezone state.
        unsafe {
            std::env::set_var("TZ", "UTC");
            tzset();
        }
        assert_eq!(
            format_info_value("Entered", "1400221786"),
            "Fri May 16 06:29:46 2014"
        );
        match previous {
            Some(value) => {
                // SAFETY: this test holds TZ_TEST_LOCK while restoring TZ.
                unsafe { std::env::set_var("TZ", value) }
            }
            None => {
                // SAFETY: this test holds TZ_TEST_LOCK while restoring TZ.
                unsafe { std::env::remove_var("TZ") }
            }
        }
        unsafe {
            tzset();
        }
    }
}
