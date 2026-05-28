use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use pyzor::client::{BatchClient, Client};
use pyzor::config::Address;
use pyzor::forwarder::ForwarderHandle;
use pyzor::message::Message;

const DIGEST: &str = "975422c090e7a43ab7c9bf0065d5b661259e6d74";

#[test]
fn forwarder_sends_report_and_whitelist_to_all_remote_servers() {
    let remote1 = UdpCollector::start();
    let remote2 = UdpCollector::start();
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    let batch = BatchClient::new(client, 10);
    let mut handle = ForwarderHandle::start(batch, vec![remote1.address(), remote2.address()], 10);
    let forwarder = handle.forwarder();

    forwarder.queue_forward_request(DIGEST, false);
    forwarder.queue_forward_request(DIGEST, true);
    handle.stop();

    assert_remote_ops(remote1.receiver, ["report", "whitelist"]);
    assert_remote_ops(remote2.receiver, ["report", "whitelist"]);
}

#[test]
fn forwarder_queue_overload_does_not_block_or_panic() {
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    let batch = BatchClient::new(client, 10);
    let mut handle = ForwarderHandle::start(batch, Vec::new(), 10);
    let forwarder = handle.forwarder();

    for _ in 0..20 {
        forwarder.queue_forward_request(DIGEST, false);
    }
    handle.stop();
}

struct UdpCollector {
    address: Address,
    receiver: Receiver<Message>,
}

impl UdpCollector {
    fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let address = ("127.0.0.1".to_string(), socket.local_addr().unwrap().port());
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for _ in 0..2 {
                let mut buf = [0u8; pyzor::MAX_PACKET_SIZE];
                let (len, _peer) = socket.recv_from(&mut buf).unwrap();
                tx.send(Message::parse(&buf[..len])).unwrap();
            }
        });
        Self {
            address,
            receiver: rx,
        }
    }

    fn address(&self) -> Address {
        self.address.clone()
    }
}

fn assert_remote_ops(receiver: Receiver<Message>, expected: [&str; 2]) {
    let mut seen = Vec::new();
    for _ in 0..2 {
        let msg = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(msg.get("Op-Digest"), Some(DIGEST));
        assert_eq!(msg.get("Op-Spec"), Some("20,3,60,3"));
        assert_eq!(msg.get("User"), Some("anonymous"));
        seen.push(msg.get("Op").unwrap().to_string());
    }
    seen.sort();
    let mut expected = expected.map(str::to_string);
    expected.sort();
    assert_eq!(seen, expected);
}
