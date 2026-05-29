use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::account::{Account, now_timestamp, sign_for_account};
use crate::config::Address;
use crate::error::PyzorError;
use crate::logging::Logger;
use crate::message::{self, Message, ThreadId};
use crate::python_repr;
use crate::{MAX_PACKET_SIZE, Result};

#[derive(Clone, Debug)]
pub struct Client {
    accounts: HashMap<Address, Account>,
    timeout: Duration,
    spec: Vec<(usize, usize)>,
    logger: Option<Logger>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(HashMap::new(), Some(5), crate::digest::DIGEST_SPEC.to_vec())
    }
}

impl Client {
    pub fn new(
        accounts: HashMap<Address, Account>,
        timeout_secs: Option<u64>,
        spec: Vec<(usize, usize)>,
    ) -> Self {
        Self {
            accounts,
            timeout: Duration::from_secs(timeout_secs.unwrap_or(5)),
            spec,
            logger: None,
        }
    }

    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = Some(logger);
        self
    }

    pub fn ping(&self, address: &Address) -> Result<Message> {
        self.round_trip(message::request("ping"), address)
    }

    pub fn pong(&self, digest: &str, address: &Address) -> Result<Message> {
        self.round_trip(message::digest_request("pong", digest), address)
    }

    pub fn check(&self, digest: &str, address: &Address) -> Result<Message> {
        self.round_trip(message::digest_request("check", digest), address)
    }

    pub fn info(&self, digest: &str, address: &Address) -> Result<Message> {
        self.round_trip(message::digest_request("info", digest), address)
    }

    pub fn report(&self, digest: &str, address: &Address) -> Result<Message> {
        self.round_trip(
            message::spec_digest_request("report", digest, &self.spec),
            address,
        )
    }

    pub fn whitelist(&self, digest: &str, address: &Address) -> Result<Message> {
        self.round_trip(
            message::spec_digest_request("whitelist", digest, &self.spec),
            address,
        )
    }

    pub fn send_only(&self, mut msg: Message, address: &Address) -> Result<()> {
        self.sign(&mut msg, address);
        let packet = msg.as_string();
        self.debug(format!("sending: {}", python_repr::string(&packet)));
        let socket = bind_for(address)?;
        let target = resolve(address)?;
        socket
            .send_to(packet.as_bytes(), target)
            .map_err(PyzorError::from)?;
        Ok(())
    }

    fn round_trip(&self, mut msg: Message, address: &Address) -> Result<Message> {
        self.sign(&mut msg, address);
        let expected_id = msg.thread()?;
        let packet = msg.as_string();
        self.debug(format!("sending: {}", python_repr::string(&packet)));
        let socket = bind_for(address)?;
        socket.set_read_timeout(Some(self.timeout))?;
        let target = resolve(address)?;
        socket.send_to(packet.as_bytes(), target).map_err(|error| {
            PyzorError::Comm(format!(
                "Unable to send to {}:{}: {}",
                address.0, address.1, error
            ))
        })?;
        self.read_response(&socket, expected_id)
    }

    fn read_response(&self, socket: &UdpSocket, expected_id: ThreadId) -> Result<Message> {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, peer) = socket.recv_from(&mut buf).map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut
                || error.kind() == std::io::ErrorKind::WouldBlock
            {
                PyzorError::Timeout("Reading response timed-out.".to_string())
            } else {
                PyzorError::Comm(format!("Socket error while reading response: {}", error))
            }
        })?;
        self.debug(format!(
            "received: {}/{}",
            python_repr::bytes(&buf[..len]),
            python_socket_addr_repr(peer)
        ));
        let response = Message::parse(&buf[..len]);
        response.ensure_response()?;
        let thread_id = response.thread()?;
        if thread_id != expected_id {
            if thread_id.in_ok_range() {
                return Err(PyzorError::Protocol(format!(
                    "received unexpected thread id {} (expected {})",
                    thread_id, expected_id
                )));
            }
            self.warning(format!(
                "received error thread id {} (expected {})",
                thread_id, expected_id
            ));
        }
        Ok(response)
    }

    fn sign(&self, msg: &mut Message, address: &Address) {
        message::init_for_sending(msg);
        let account = self
            .accounts
            .get(address)
            .cloned()
            .unwrap_or_else(Account::anonymous);
        sign_for_account(msg, &account, now_timestamp());
    }

    fn debug(&self, message: impl AsRef<str>) {
        if let Some(logger) = &self.logger {
            logger.debug(message);
        }
    }

    fn warning(&self, message: impl AsRef<str>) {
        if let Some(logger) = &self.logger {
            logger.warning(message);
        }
    }
}

#[derive(Clone, Debug)]
pub struct BatchClient {
    client: Client,
    batch_size: usize,
    reports: HashMap<Address, Message>,
    whitelists: HashMap<Address, Message>,
}

impl Drop for BatchClient {
    fn drop(&mut self) {
        self.force();
    }
}

impl BatchClient {
    pub fn new(client: Client, batch_size: usize) -> Self {
        Self {
            client,
            batch_size,
            reports: HashMap::new(),
            whitelists: HashMap::new(),
        }
    }

    pub fn report(&mut self, digest: &str, address: &Address) -> Result<()> {
        Self::add_digest(
            &self.client,
            self.batch_size,
            &mut self.reports,
            "report",
            digest,
            address,
        )
    }

    pub fn whitelist(&mut self, digest: &str, address: &Address) -> Result<()> {
        Self::add_digest(
            &self.client,
            self.batch_size,
            &mut self.whitelists,
            "whitelist",
            digest,
            address,
        )
    }

    pub fn flush(&mut self) {
        self.reports.clear();
        self.whitelists.clear();
    }

    pub fn force(&mut self) {
        for (address, msg) in std::mem::take(&mut self.reports) {
            let _ = self.client.send_only(msg, &address);
        }
        for (address, msg) in std::mem::take(&mut self.whitelists) {
            let _ = self.client.send_only(msg, &address);
        }
    }

    fn add_digest(
        client: &Client,
        batch_size: usize,
        requests: &mut HashMap<Address, Message>,
        op: &str,
        digest: &str,
        address: &Address,
    ) -> Result<()> {
        let msg = requests.entry(address.clone()).or_insert_with(|| {
            let mut msg = message::request(op);
            let flat = client
                .spec
                .iter()
                .flat_map(|(offset, length)| [offset.to_string(), length.to_string()])
                .collect::<Vec<_>>()
                .join(",");
            msg.add_header("Op-Spec", flat);
            msg
        });
        msg.add_header("Op-Digest", digest);
        if msg.get_all("Op-Digest").len() >= batch_size {
            let msg = requests.remove(address).expect("entry just existed");
            client.send_only(msg, address)?;
        }
        Ok(())
    }
}

fn resolve(address: &Address) -> Result<std::net::SocketAddr> {
    (address.0.as_str(), address.1)
        .to_socket_addrs()
        .map_err(PyzorError::from)?
        .next()
        .ok_or_else(|| PyzorError::Comm(format!("Unable to send to {}:{}", address.0, address.1)))
}

fn bind_for(address: &Address) -> Result<UdpSocket> {
    let target = resolve(address)?;
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    UdpSocket::bind(bind).map_err(PyzorError::from)
}
fn python_socket_addr_repr(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(address) => format!("('{}', {})", address.ip(), address.port()),
        SocketAddr::V6(address) => format!(
            "('{}', {}, {}, {})",
            address.ip(),
            address.port(),
            address.flowinfo(),
            address.scope_id()
        ),
    }
}
