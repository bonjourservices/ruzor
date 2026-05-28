use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn digest_functional_attachment_and_encoding_fixtures_match_python() {
    for fixture in python_digest_functional_fixtures() {
        assert_eq!(
            pyzor::digest::predigest_message(&fixture.message),
            fixture.predigest,
            "predigest mismatch for {}",
            fixture.name
        );
        assert_eq!(
            pyzor::digest::digest_message(&fixture.message),
            fixture.digest,
            "digest mismatch for {}",
            fixture.name
        );
    }
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn digest_functional_cli_cases_match_python_pyzor_script() {
    for case in python_digest_functional_cli_cases() {
        let root = temp_dir(&case.name);
        let python_home = root.join("python");
        let rust_home = root.join("rust");
        std::fs::create_dir_all(&python_home).unwrap();
        std::fs::create_dir_all(&rust_home).unwrap();

        let python = run_python_pyzor_command(&python_home, &case.command, &case.message);
        let rust = run_rust_pyzor_command(&rust_home, &case.command, &case.message);

        assert_eq!(
            python.status.code(),
            rust.status.code(),
            "status mismatch for {} {}",
            case.command,
            case.name
        );
        assert_eq!(
            python.stderr, rust.stderr,
            "stderr mismatch for {} {}",
            case.command, case.name
        );
        assert_eq!(
            python.stdout, rust.stdout,
            "stdout mismatch for {} {}",
            case.command, case.name
        );
        assert!(
            rust.status.success(),
            "Rust pyzor failed for {} {}: {:?}",
            case.command,
            case.name,
            rust
        );

        let _ = std::fs::remove_dir_all(root);
    }
}

struct PythonDigestCliCase {
    name: String,
    command: String,
    message: Vec<u8>,
}

struct PythonDigestFixture {
    name: String,
    message: Vec<u8>,
    digest: String,
    predigest: Vec<String>,
}

fn python_digest_functional_fixtures() -> Vec<PythonDigestFixture> {
    let output = run_python(
        r#"
import binascii
import email
import sys
import types

util = types.ModuleType("tests.util")
util.PyzorTestBase = object
sys.modules["tests.util"] = util

from pyzor.digest import DataDigester
from tests.functional import test_digest as fixtures

class CapturingDataDigester(DataDigester):
    __slots__ = ["lines"]

    def __init__(self, msg):
        self.lines = []
        super(CapturingDataDigester, self).__init__(msg)

    def handle_line(self, line):
        self.lines.append(line.decode("utf8"))
        super(CapturingDataDigester, self).handle_line(line)

cases = [
    ("TEXT_ATTACHMENT", fixtures.TEXT_ATTACHMENT),
    ("TEXT_ATTACHMENT_W_NULL", fixtures.TEXT_ATTACHMENT_W_NULL),
    ("TEXT_ATTACHMENT_W_MULTIPLE_NULLS", fixtures.TEXT_ATTACHMENT_W_MULTIPLE_NULLS),
    ("TEXT_ATTACHMENT_W_SUBJECT_NULL", fixtures.TEXT_ATTACHMENT_W_SUBJECT_NULL),
    ("TEXT_ATTACHMENT_W_CONTENTTYPE_NULL", fixtures.TEXT_ATTACHMENT_W_CONTENTTYPE_NULL),
    ("ENCODING_TEST_EMAIL", fixtures.ENCODING_TEST_EMAIL),
    ("BAD_ENCODING", fixtures.BAD_ENCODING),
]

for name, message in cases:
    data = message.encode("utf8")
    digester = CapturingDataDigester(email.message_from_bytes(data))
    predigest = ",".join(
        binascii.hexlify(line.encode("utf8")).decode("ascii")
        for line in digester.lines
    )
    print(
        "CASE\t{}\t{}\t{}\t{}".format(
            name,
            binascii.hexlify(data).decode("ascii"),
            digester.value,
            predigest,
        )
    )
"#,
        b"",
    );

    output
        .lines()
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 5, "unexpected fixture line: {line:?}");
            assert_eq!(fields[0], "CASE");
            PythonDigestFixture {
                name: fields[1].to_string(),
                message: decode_hex(fields[2]),
                digest: fields[3].to_string(),
                predigest: if fields[4].is_empty() {
                    Vec::new()
                } else {
                    fields[4]
                        .split(',')
                        .map(|line| String::from_utf8(decode_hex(line)).expect("utf8 predigest"))
                        .collect()
                },
            }
        })
        .collect()
}

fn python_digest_functional_cli_cases() -> Vec<PythonDigestCliCase> {
    let output = run_python(
        r#"
import binascii
import sys
import types

util = types.ModuleType("tests.util")
util.PyzorTestBase = object
sys.modules["tests.util"] = util

from tests.functional import test_digest as fixtures

def emit(name, command, message):
    print(
        "CASE\t{}\t{}\t{}".format(
            name,
            command,
            binascii.hexlify(message.encode("utf8")).decode("ascii"),
        )
    )

emails = ["t@abc.ro", "t1@abc.ro", "t+@abc.ro", "t.@abc.ro"]
for idx, email in enumerate(emails):
    emit("email_{}".format(idx), "predigest", fixtures.TEXT % ("Test %s Test2" % email))
    emit("email_{}".format(idx), "digest", fixtures.TEXT % ("Test %s Test2" % email))

long_tokens = ["0A2D3f%a#S", "3sddkf9jdkd9", "@@#@@@@@@@@@"]
for idx, token in enumerate(long_tokens):
    emit("long_{}".format(idx), "predigest", fixtures.TEXT % ("Test %s Test2" % token))
    emit("long_{}".format(idx), "digest", fixtures.TEXT % ("Test %s Test2" % token))

line_length = "This line is included\nnot this\nThis also"
atomic_predigest = "All this message\nShould be included\nIn the predigest"
atomic_digest = "All this message\nShould be included\nIn the digest"
pieced = "".join("Line%d test test test\n" % i for i in range(100))

emit("line_length", "predigest", fixtures.TEXT % line_length)
emit("line_length", "digest", fixtures.TEXT % line_length)
emit("atomic", "predigest", fixtures.TEXT % atomic_predigest)
emit("atomic", "digest", fixtures.TEXT % atomic_digest)
emit("pieced", "predigest", fixtures.TEXT % pieced)
emit("pieced", "digest", fixtures.TEXT % pieced)
emit("html", "predigest", fixtures.HTML_TEXT)
emit("html", "digest", fixtures.HTML_TEXT)
emit("html_style_script", "predigest", fixtures.HTML_TEXT_STYLE_SCRIPT)
emit("html_style_script", "digest", fixtures.HTML_TEXT_STYLE_SCRIPT)
emit("attachment", "predigest", fixtures.TEXT_ATTACHMENT)

for name in [
    "TEXT_ATTACHMENT",
    "TEXT_ATTACHMENT_W_NULL",
    "TEXT_ATTACHMENT_W_MULTIPLE_NULLS",
    "TEXT_ATTACHMENT_W_SUBJECT_NULL",
    "TEXT_ATTACHMENT_W_CONTENTTYPE_NULL",
    "ENCODING_TEST_EMAIL",
    "BAD_ENCODING",
]:
    emit(name, "digest", getattr(fixtures, name))
"#,
        b"",
    );

    output
        .lines()
        .map(|line| {
            let fields = line.split(char::from(9)).collect::<Vec<_>>();
            assert_eq!(fields.len(), 4, "unexpected CLI case line: {line:?}");
            assert_eq!(fields[0], "CASE");
            PythonDigestCliCase {
                name: fields[1].to_string(),
                command: fields[2].to_string(),
                message: decode_hex(fields[3]),
            }
        })
        .collect()
}

fn run_python_pyzor_command(homedir: &Path, command: &str, input: &[u8]) -> Output {
    let mut child = Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .env("TZ", "UTC")
        .arg("reference/pyzor/scripts/pyzor")
        .arg("--homedir")
        .arg(homedir)
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Python pyzor");
    child
        .stdin
        .as_mut()
        .expect("Python pyzor stdin")
        .write_all(input)
        .expect("write Python pyzor stdin");
    child.wait_with_output().expect("wait Python pyzor")
}

fn run_rust_pyzor_command(homedir: &Path, command: &str, input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pyzor"))
        .env("TZ", "UTC")
        .arg("--homedir")
        .arg(homedir)
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Rust pyzor");
    child
        .stdin
        .as_mut()
        .expect("Rust pyzor stdin")
        .write_all(input)
        .expect("write Rust pyzor stdin");
    child.wait_with_output().expect("wait Rust pyzor")
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "pyzor-python-digest-cli-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
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

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex value has odd length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| hex_nibble(pair[0]) << 4 | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte {byte}"),
    }
}
