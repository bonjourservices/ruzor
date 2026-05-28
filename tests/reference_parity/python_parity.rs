use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use ruzor::engines::{DigestDatabase, Record};

static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

const REFERENCE_MSG: &str = "Newsgroups:
Date: Wed, 10 Apr 2002 22:23:51 -0400 (EDT)
From: Frank Tobin <ftobin@neverending.org>
Fcc: sent-mail
Message-ID: <20020410222350.E16178@palanthas.neverending.org>
X-Our-Headers: X-Bogus,Anon-To
X-Bogus: aaron7@neverending.org
MIME-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII

Test Email
";

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn digest_matches_python_reference_message() {
    let python = python_digest(REFERENCE_MSG.as_bytes());
    let rust = ruzor::digest::digest_message(REFERENCE_MSG.as_bytes());
    assert_eq!(rust, python);
    assert_eq!(rust, "7421216f915a87e02da034cc483f5c876e1a1338");
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn predigest_matches_python_reference_message() {
    let python = python_predigest(REFERENCE_MSG.as_bytes());
    let rust = ruzor::digest::predigest_message(REFERENCE_MSG.as_bytes()).join("\n");
    assert_eq!(rust, python);
    assert_eq!(rust, "TestEmail");
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn digest_corpus_matches_python() {
    let samples = [
        b"That's some good ham right there".as_slice(),
        b"All this message\nShould be included\nIn the predigest".as_slice(),
        b"Test test@example.com Test2".as_slice(),
        b"Test http://example.com Test2".as_slice(),
        b"Content-Type: text/plain; charset=x-unknown-pyzor\n\nCafe caf\xc3\xa9 payload".as_slice(),
        b"Content-Type: text/plain; charset=utf8\n\nCafe caf\xff payload".as_slice(),
        b"Content-Type: text/plain; charset=quopri\n\nThis=20line=20decoded".as_slice(),
    ];
    for sample in samples {
        assert_eq!(ruzor::digest::digest_message(sample), python_digest(sample));
    }
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn account_hash_and_signature_match_python() {
    let python = run_python(
        r#"
import email
import hashlib
from pyzor.account import hash_key, sign_msg
timestamp = 1381219396
msg = email.message_from_string("")
msg["Op"] = "ping"
msg["Thread"] = "14941"
msg["PV"] = "2.1"
msg["User"] = "anonymous"
msg["Time"] = str(timestamp)
hashed_key = hashlib.sha1(b"test_key").hexdigest()
print(hash_key("testkey", "testuser"))
print(sign_msg(hashed_key, timestamp, msg))
"#,
        b"",
    );
    let mut msg = ruzor::message::Message::new();
    msg.add_header("Op", "ping");
    msg.add_header("Thread", "14941");
    msg.add_header("PV", "2.1");
    msg.add_header("User", "anonymous");
    msg.add_header("Time", "1381219396");
    let rust = format!(
        "{}\n{}",
        ruzor::account::hash_key("testkey", "testuser"),
        ruzor::account::sign_msg("00942f4668670f34c5943cf52c7ef3139fe2b8d6", 1381219396, &msg)
    );
    assert_eq!(rust, python);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn server_unexpected_database_exception_matches_python_handler_response() {
    let packet = format!(
        "Op: check\nThread: 4242\nPV: 2.1\nUser: anonymous\nOp-Digest: {}\n\n",
        "2aedaac999d71421c9ee49b9d81f627a7bc570aa"
    );
    let python = run_python(
        r#"
import io
import logging
import sys
try:
    import socketserver as SocketServer
except ImportError:
    import SocketServer
import pyzor
import pyzor.server

class FailingDb:
    def __getitem__(self, digest):
        raise Exception("test")

class MockServer:
    def __init__(self):
        self.log = logging.getLogger("pyzord")
        self.usage_log = logging.getLogger("pyzord-usage")
        self.log.addHandler(logging.NullHandler())
        self.usage_log.addHandler(logging.NullHandler())
        self.database = FailingDb()
        self.accounts = {}
        self.acl = {pyzor.anonymous_user: ("check",)}
        self.forwarder = None
        self.one_step = False

class MockDatagramRequestHandler:
    def __init__(self, *args, **kwargs):
        self.rfile = io.BytesIO(sys.stdin.buffer.read())
        self.wfile = io.BytesIO()
        self.packet = None
        self.client_address = ["127.0.0.1"]
        self.server = MockServer()
        self.handle()
    def handle(self):
        pass

real_base = SocketServer.DatagramRequestHandler
SocketServer.DatagramRequestHandler = MockDatagramRequestHandler
pyzor.server.RequestHandler.__bases__ = (MockDatagramRequestHandler,)
try:
    handler = pyzor.server.RequestHandler()
    handler.wfile.seek(0)
    sys.stdout.write(handler.wfile.read().decode("utf8").replace("\n\n", "\n"))
finally:
    SocketServer.DatagramRequestHandler = real_base
    pyzor.server.RequestHandler.__bases__ = (real_base,)
"#,
        packet.as_bytes(),
    );

    let db = Arc::new(Mutex::new(PanickingDatabase));
    let accounts = HashMap::new();
    let acl = HashMap::from([(
        "anonymous".to_string(),
        HashSet::from(["check".to_string()]),
    )]);
    let rust = {
        let _hook_guard = PANIC_HOOK_LOCK.lock().unwrap();
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let response = ruzor::server::handle_packet(packet.as_bytes(), &db, &accounts, &acl);
        std::panic::set_hook(hook);
        response
    };

    assert_eq!(normalize_response(&rust.as_string()), python);
    assert_eq!(rust.get("Code"), Some("500"));
    assert_eq!(rust.get("Diag"), Some("Internal Server Error: test"));
    assert_eq!(rust.get("Thread"), Some("4242"));
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn server_digest_operations_without_op_digest_match_python_handler_response() {
    let db = Arc::new(Mutex::new(EmptyDatabase));
    let accounts = HashMap::new();
    let acl = HashMap::from([(
        "anonymous".to_string(),
        HashSet::from(["pong".to_string(), "check".to_string(), "info".to_string()]),
    )]);

    for (op, thread) in [("pong", 4300), ("check", 4301), ("info", 4302)] {
        let packet = format!("Op: {op}\nThread: {thread}\nPV: 2.1\nUser: anonymous\n\n");
        let python = python_server_response(packet.as_bytes());
        let rust = ruzor::server::handle_packet(packet.as_bytes(), &db, &accounts, &acl);

        assert_eq!(normalize_response(&rust.as_string()), python, "op {op}");
        assert_eq!(rust.get("Count"), None, "op {op}");
        assert_eq!(rust.get("WL-Count"), None, "op {op}");
        assert_eq!(rust.get("Entered"), None, "op {op}");
        assert_eq!(rust.get("Updated"), None, "op {op}");
        assert_eq!(rust.get("WL-Entered"), None, "op {op}");
        assert_eq!(rust.get("WL-Updated"), None, "op {op}");
    }
}

struct EmptyDatabase;

impl DigestDatabase for EmptyDatabase {
    fn get(&mut self, _digest: &str) -> ruzor::Result<Record> {
        Ok(Record::default())
    }

    fn set(&mut self, _digest: &str, _record: Record) -> ruzor::Result<()> {
        Ok(())
    }
}

struct PanickingDatabase;

impl DigestDatabase for PanickingDatabase {
    fn get(&mut self, _digest: &str) -> ruzor::Result<Record> {
        panic!("test")
    }

    fn set(&mut self, _digest: &str, _record: Record) -> ruzor::Result<()> {
        panic!("test")
    }
}

fn normalize_response(response: &str) -> String {
    response.replace("\n\n", "\n").trim_end().to_string()
}

fn python_server_response(packet: &[u8]) -> String {
    run_python(
        r#"
import io
import logging
import sys
try:
    import socketserver as SocketServer
except ImportError:
    import SocketServer
import pyzor
import pyzor.server

class MockServer:
    def __init__(self):
        self.log = logging.getLogger("pyzord")
        self.usage_log = logging.getLogger("pyzord-usage")
        self.log.addHandler(logging.NullHandler())
        self.usage_log.addHandler(logging.NullHandler())
        self.database = {}
        self.accounts = {}
        self.acl = {pyzor.anonymous_user: ("pong", "check", "info")}
        self.forwarder = None
        self.one_step = False

class MockDatagramRequestHandler:
    def __init__(self, *args, **kwargs):
        self.rfile = io.BytesIO(sys.stdin.buffer.read())
        self.wfile = io.BytesIO()
        self.packet = None
        self.client_address = ["127.0.0.1"]
        self.server = MockServer()
        self.handle()
    def handle(self):
        pass

real_base = SocketServer.DatagramRequestHandler
SocketServer.DatagramRequestHandler = MockDatagramRequestHandler
pyzor.server.RequestHandler.__bases__ = (MockDatagramRequestHandler,)
try:
    handler = pyzor.server.RequestHandler()
    handler.wfile.seek(0)
    sys.stdout.write(handler.wfile.read().decode("utf8").replace("\n\n", "\n"))
finally:
    SocketServer.DatagramRequestHandler = real_base
    pyzor.server.RequestHandler.__bases__ = (real_base,)
"#,
        packet,
    )
}

fn python_digest(input: &[u8]) -> String {
    run_python(
        r#"
import email
import sys
from pyzor.digest import DataDigester
msg = email.message_from_bytes(sys.stdin.buffer.read())
print(DataDigester(msg).value)
"#,
        input,
    )
}

fn python_predigest(input: &[u8]) -> String {
    run_python(
        r#"
import email
import sys
from pyzor.digest import PrintingDataDigester
msg = email.message_from_bytes(sys.stdin.buffer.read())
PrintingDataDigester(msg)
"#,
        input,
    )
}

fn run_python(script: &str, input: &[u8]) -> String {
    let mut child = Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Python reference");
    child
        .stdin
        .as_mut()
        .expect("Python stdin")
        .write_all(input)
        .expect("write Python stdin");
    let output = child.wait_with_output().expect("wait Python reference");
    assert!(
        output.status.success(),
        "Python reference failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Python stdout is utf8")
        .trim_end()
        .to_string()
}
