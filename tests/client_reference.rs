use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use pyzor::account::Account;
use pyzor::client::{BatchClient, Client};
use pyzor::config::Address;
use pyzor::error::PyzorError;
use pyzor::message::{Message, ThreadId};

const DIGEST: &str = "2aedaac999d71421c9ee49b9d81f627a7bc570aa";

#[derive(Copy, Clone)]
enum Command {
    Ping,
    Pong,
    Check,
    Info,
    Report,
    Whitelist,
}

impl Command {
    fn op(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Check => "check",
            Self::Info => "info",
            Self::Report => "report",
            Self::Whitelist => "whitelist",
        }
    }

    fn has_digest(self) -> bool {
        !matches!(self, Self::Ping)
    }

    fn has_spec(self) -> bool {
        matches!(self, Self::Report | Self::Whitelist)
    }

    fn run(self, client: &Client, address: &Address) -> pyzor::Result<Message> {
        match self {
            Self::Ping => client.ping(address),
            Self::Pong => client.pong(DIGEST, address),
            Self::Check => client.check(DIGEST, address),
            Self::Info => client.info(DIGEST, address),
            Self::Report => client.report(DIGEST, address),
            Self::Whitelist => client.whitelist(DIGEST, address),
        }
    }
}

#[derive(Copy, Clone)]
enum ReplyMode {
    EchoThread,
    UnexpectedOkThread,
}

#[test]
fn client_requests_match_reference_headers_for_all_commands() {
    for command in [
        Command::Ping,
        Command::Pong,
        Command::Check,
        Command::Info,
        Command::Report,
        Command::Whitelist,
    ] {
        let (request, response) = capture_round_trip(ReplyMode::EchoThread, |address| {
            let client = Client::default();
            command.run(&client, address)
        });
        assert!(response.unwrap().is_ok());
        assert_common_request_headers(&request, command.op(), "anonymous");
        if command.has_digest() {
            assert_eq!(request.get("Op-Digest"), Some(DIGEST));
        } else {
            assert_eq!(request.get("Op-Digest"), None);
        }
        if command.has_spec() {
            assert_eq!(request.get("Op-Spec"), Some("20,3,60,3"));
        } else {
            assert_eq!(request.get("Op-Spec"), None);
        }
    }
}

#[test]
fn client_uses_matching_account_for_server_address() {
    let (request, response) = capture_round_trip(ReplyMode::EchoThread, |address| {
        let accounts = HashMap::from([(
            address.clone(),
            Account::new("TestUser", Some("TestSalt".to_string()), "TestKey"),
        )]);
        let client = Client::new(accounts, Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
        client.ping(address)
    });

    assert!(response.unwrap().is_ok());
    assert_common_request_headers(&request, "ping", "TestUser");
}

#[test]
fn client_rejects_unexpected_ok_range_thread_like_reference() {
    let (request, response) = capture_round_trip(ReplyMode::UnexpectedOkThread, |address| {
        let client = Client::default();
        client.ping(address)
    });

    assert_common_request_headers(&request, "ping", "anonymous");
    assert!(
        matches!(response, Err(PyzorError::Protocol(message)) if message.contains("received unexpected thread id"))
    );
}

#[test]
fn client_timeout_maps_to_reference_timeout_error() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    let result = client.ping(&("127.0.0.1".to_string(), address.port()));

    assert!(
        matches!(result, Err(PyzorError::Timeout(message)) if message == "Reading response timed-out.")
    );
}

#[test]
fn batch_client_sends_report_and_whitelist_at_batch_size() {
    for (command, expected_op) in [("report", "report"), ("whitelist", "whitelist")] {
        let request = capture_optional_batch(|address| {
            let client = Client::default();
            let mut batch = BatchClient::new(client, 10);
            for _ in 0..10 {
                match command {
                    "report" => batch.report(DIGEST, address).unwrap(),
                    "whitelist" => batch.whitelist(DIGEST, address).unwrap(),
                    _ => unreachable!(),
                }
            }
        })
        .expect("batch should send at size 10");

        assert_common_request_headers(&request, expected_op, "anonymous");
        assert_eq!(request.get_all("Op-Digest"), vec![DIGEST; 10]);
        assert_eq!(request.get("Op-Spec"), Some("20,3,60,3"));
    }
}

#[test]
fn batch_client_does_not_send_before_batch_size_or_after_flush() {
    for command in ["report", "whitelist"] {
        assert_no_batch_send_while_alive(command, 9, false);
        assert_no_batch_send_while_alive(command, 1, true);
    }
}

#[test]
fn batch_client_drop_sends_partial_report_and_whitelist_batches_like_python_del() {
    for (command, expected_op) in [("report", "report"), ("whitelist", "whitelist")] {
        let request = capture_batch_on_drop(|address, batch| {
            for _ in 0..9 {
                match command {
                    "report" => batch.report(DIGEST, address).unwrap(),
                    "whitelist" => batch.whitelist(DIGEST, address).unwrap(),
                    _ => unreachable!(),
                }
            }
        });

        assert_common_request_headers(&request, expected_op, "anonymous");
        assert_eq!(request.get_all("Op-Digest"), vec![DIGEST; 9]);
        assert_eq!(request.get("Op-Spec"), Some("20,3,60,3"));
    }
}

#[test]
fn batch_client_force_sends_partial_report_and_whitelist_batches() {
    for (command, expected_op) in [("report", "report"), ("whitelist", "whitelist")] {
        let request = capture_optional_batch(|address| {
            let client = Client::default();
            let mut batch = BatchClient::new(client, 10);
            for _ in 0..9 {
                match command {
                    "report" => batch.report(DIGEST, address).unwrap(),
                    "whitelist" => batch.whitelist(DIGEST, address).unwrap(),
                    _ => unreachable!(),
                }
            }
            batch.force();
        })
        .expect("force should send partial batch");

        assert_common_request_headers(&request, expected_op, "anonymous");
        assert_eq!(request.get_all("Op-Digest"), vec![DIGEST; 9]);
        assert_eq!(request.get("Op-Spec"), Some("20,3,60,3"));
    }
}

fn capture_round_trip<F>(reply_mode: ReplyMode, action: F) -> (Message, pyzor::Result<Message>)
where
    F: FnOnce(&Address) -> pyzor::Result<Message>,
{
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let address = ("127.0.0.1".to_string(), socket.local_addr().unwrap().port());
    let handle = thread::spawn(move || {
        let mut buf = [0u8; pyzor::MAX_PACKET_SIZE];
        let (len, peer) = socket.recv_from(&mut buf).unwrap();
        let request = Message::parse(&buf[..len]);
        let request_thread = request.thread().unwrap().0;
        let reply_thread = match reply_mode {
            ReplyMode::EchoThread => request_thread,
            ReplyMode::UnexpectedOkThread => {
                if request_thread == ThreadId::OK_MIN {
                    ThreadId::OK_MIN + 1
                } else {
                    ThreadId::OK_MIN
                }
            }
        };
        let response = format!("Code: 200\nDiag: OK\nPV: 2.1\nThread: {reply_thread}\n\n");
        socket.send_to(response.as_bytes(), peer).unwrap();
        request
    });

    let result = action(&address);
    (handle.join().unwrap(), result)
}

fn assert_no_batch_send_while_alive(command: &str, count: usize, flush_before_count: bool) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let address = ("127.0.0.1".to_string(), socket.local_addr().unwrap().port());
    let client = Client::default();
    let mut batch = BatchClient::new(client, 10);
    if flush_before_count {
        for _ in 0..9 {
            add_batch_digest(&mut batch, command, &address);
        }
        batch.flush();
    }
    for _ in 0..count {
        add_batch_digest(&mut batch, command, &address);
    }
    let mut buf = [0u8; pyzor::MAX_PACKET_SIZE];
    let error = socket
        .recv_from(&mut buf)
        .expect_err("partial live batch should not send yet");
    assert!(
        error.kind() == std::io::ErrorKind::TimedOut
            || error.kind() == std::io::ErrorKind::WouldBlock,
        "unexpected UDP receive error: {error}"
    );
    batch.flush();
}

fn capture_batch_on_drop<F>(action: F) -> Message
where
    F: FnOnce(&Address, &mut BatchClient),
{
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let address = ("127.0.0.1".to_string(), socket.local_addr().unwrap().port());
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut buf = [0u8; pyzor::MAX_PACKET_SIZE];
        let (len, _peer) = socket
            .recv_from(&mut buf)
            .expect("batch drop should force partial send");
        tx.send(Message::parse(&buf[..len])).unwrap();
    });
    let client = Client::default();
    let mut batch = BatchClient::new(client, 10);
    action(&address, &mut batch);
    drop(batch);
    handle.join().unwrap();
    rx.recv().unwrap()
}

fn add_batch_digest(batch: &mut BatchClient, command: &str, address: &Address) {
    match command {
        "report" => batch.report(DIGEST, address).unwrap(),
        "whitelist" => batch.whitelist(DIGEST, address).unwrap(),
        _ => unreachable!(),
    }
}

fn capture_optional_batch<F>(action: F) -> Option<Message>
where
    F: FnOnce(&Address),
{
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let address = ("127.0.0.1".to_string(), socket.local_addr().unwrap().port());
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut buf = [0u8; pyzor::MAX_PACKET_SIZE];
        let message = match socket.recv_from(&mut buf) {
            Ok((len, _peer)) => Some(Message::parse(&buf[..len])),
            Err(error)
                if error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                None
            }
            Err(error) => panic!("unexpected UDP receive error: {error}"),
        };
        tx.send(message).unwrap();
    });

    action(&address);
    handle.join().unwrap();
    rx.recv().unwrap()
}

fn assert_common_request_headers(request: &Message, op: &str, user: &str) {
    assert_eq!(request.get("Op"), Some(op));
    assert_eq!(request.get("PV"), Some("2.1"));
    assert_eq!(request.get("User"), Some(user));
    assert!(request.thread().unwrap().in_ok_range());
    assert!(request.get("Time").unwrap().parse::<i64>().unwrap() > 0);
    let signature = request.get("Sig").unwrap();
    assert_eq!(signature.len(), 40);
    assert!(signature.chars().all(|ch| ch.is_ascii_hexdigit()));
}
