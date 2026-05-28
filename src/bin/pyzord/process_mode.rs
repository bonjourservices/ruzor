#[cfg(unix)]
use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::net::UdpSocket;
#[cfg(unix)]
use std::process;
#[cfg(unix)]
use std::sync::atomic::Ordering;
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use super::{
    RECEIVED_RELOAD, RECEIVED_TERM, SIGTERM, ServerConfig, fork, reap_exited_children,
    signal_children, wait_for_children,
};

#[cfg(unix)]
pub(super) fn supports_processes(engine: &str) -> bool {
    engine == "mysql"
}

#[cfg(unix)]
pub(super) fn run_process_server(
    config: &ServerConfig,
    logger: Option<pyzor::logging::Logger>,
    usage_logger: Option<pyzor::logging::Logger>,
) -> Result<(), Box<dyn std::error::Error>> {
    let forwarding = if config.forward_client_homedir.is_empty() {
        None
    } else {
        Some(super::load_forwarding_config(
            &config.forward_client_homedir,
        )?)
    };

    let socket = UdpSocket::bind((config.address.as_str(), config.port))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut auth = load_auth(config, logger.as_ref());
    drop(pyzor::server::open_database(
        &config.engine,
        &config.digest_db,
        config.cleanup_age,
    )?);
    let mut pids = Vec::new();

    loop {
        if RECEIVED_TERM.swap(false, Ordering::Relaxed) {
            signal_children(&pids, SIGTERM);
            wait_for_children(&mut pids);
            return Ok(());
        }
        if RECEIVED_RELOAD.swap(false, Ordering::Relaxed) {
            auth = load_auth(config, logger.as_ref());
        }
        reap_exited_children(&mut pids);

        let mut buf = [0u8; pyzor::MAX_PACKET_SIZE];
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => {
                signal_children(&pids, SIGTERM);
                wait_for_children(&mut pids);
                return Err(error.into());
            }
        };
        wait_for_child_slot(&mut pids, config.max_processes);

        let packet = buf[..len].to_vec();
        let accounts = auth.accounts.clone();
        let acl = auth.acl.clone();
        let engine = config.engine.clone();
        let database_path = config.digest_db.clone();
        let usage_logger = usage_logger.clone();

        match unsafe { fork() } {
            pid if pid < 0 => {
                signal_children(&pids, SIGTERM);
                wait_for_children(&mut pids);
                return Err(io::Error::last_os_error().into());
            }
            0 => {
                let forwarded = forwarded_request(&packet);
                let db = match pyzor::server::open_database(&engine, &database_path, None) {
                    Ok(db) => Arc::new(Mutex::new(db)),
                    Err(error) => {
                        let response = database_open_error_response(&packet, error);
                        pyzor::server::log_usage_for_response(
                            &packet,
                            &peer.ip().to_string(),
                            &response,
                            usage_logger.as_ref(),
                        );
                        let _ = socket.send_to(response.as_string().as_bytes(), peer);
                        process::exit(0);
                    }
                };
                let response = pyzor::server::handle_packet(&packet, &db, &accounts, &acl);
                let response_ok = response.is_ok();
                pyzor::server::log_usage_for_response(
                    &packet,
                    &peer.ip().to_string(),
                    &response,
                    usage_logger.as_ref(),
                );
                let _ = socket.send_to(response.as_string().as_bytes(), peer);
                if response_ok {
                    forward_process_request(forwarding.as_ref(), forwarded.as_ref());
                }
                process::exit(0);
            }

            pid => pids.push(pid),
        }
    }
}

#[cfg(unix)]
fn database_open_error_response(
    packet: &[u8],
    error: pyzor::error::PyzorError,
) -> pyzor::message::Message {
    let cleaned = clean_legacy_packet(packet);
    let request = pyzor::message::Message::parse(&cleaned);
    let mut response = pyzor::message::response(request.get("Thread"));
    response.replace_header("Code", "500");
    response.replace_header("Diag", format!("Internal Server Error: {error}"));
    response
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct AuthSnapshot {
    accounts: HashMap<String, String>,
    acl: HashMap<String, HashSet<String>>,
}

#[cfg(unix)]
fn load_auth(config: &ServerConfig, logger: Option<&pyzor::logging::Logger>) -> AuthSnapshot {
    let accounts = pyzor::config::load_passwd_file_with_logger(&config.passwd_file, logger);
    let acl = pyzor::config::load_access_file_with_logger(&config.access_file, &accounts, logger);
    AuthSnapshot { accounts, acl }
}

#[cfg(unix)]
fn wait_for_child_slot(pids: &mut Vec<i32>, max_processes: usize) {
    if max_processes == 0 {
        return;
    }
    while pids.len() >= max_processes {
        reap_exited_children(pids);
        if pids.len() < max_processes {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct ForwardedRequest {
    whitelist: bool,
    digests: Vec<String>,
}

#[cfg(unix)]
fn forwarded_request(packet: &[u8]) -> Option<ForwardedRequest> {
    let cleaned = clean_legacy_packet(packet);
    let request = pyzor::message::Message::parse(&cleaned);
    let whitelist = match request.get("Op")? {
        "report" => false,
        "whitelist" => true,
        _ => return None,
    };
    let digests = request
        .get_all("Op-Digest")
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if digests.is_empty() {
        None
    } else {
        Some(ForwardedRequest { whitelist, digests })
    }
}

#[cfg(unix)]
fn clean_legacy_packet(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + 1);
    let mut index = 0;
    while index < packet.len() {
        if index + 1 < packet.len() && packet[index] == b'\n' && packet[index + 1] == b'\n' {
            out.push(b'\n');
            index += 2;
        } else {
            out.push(packet[index]);
            index += 1;
        }
    }
    out.push(b'\n');
    out
}

#[cfg(unix)]
fn forward_process_request(
    forwarding: Option<&super::ForwardingConfig>,
    request: Option<&ForwardedRequest>,
) {
    let (Some(forwarding), Some(request)) = (forwarding, request) else {
        return;
    };
    let mut client = pyzor::client::BatchClient::new(forwarding.client.clone(), 10);
    for digest in &request.digests {
        for server in &forwarding.servers {
            let result = if request.whitelist {
                client.whitelist(digest, server)
            } else {
                client.report(digest, server)
            };
            let _ = result;
        }
    }
    client.force();
}
