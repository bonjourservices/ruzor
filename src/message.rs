use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::PyzorError;
use crate::python_repr;
use crate::{PROTO_VERSION, Result};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    headers: Vec<(String, String)>,
}

impl Message {
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
        }
    }

    pub fn parse(bytes: &[u8]) -> Self {
        let text = String::from_utf8_lossy(bytes);
        let mut msg = Self::new();
        let mut current: Option<usize> = None;
        for raw_line in text.replace("\r\n", "\n").replace('\r', "\n").lines() {
            if raw_line.is_empty() {
                break;
            }
            if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
                if let Some(index) = current {
                    msg.headers[index].1.push('\n');
                    msg.headers[index].1.push_str(raw_line.trim());
                }
                continue;
            }
            let Some((name, value)) = raw_line.split_once(':') else {
                continue;
            };
            msg.headers
                .push((name.trim().to_string(), value.trim_start().to_string()));
            current = Some(msg.headers.len() - 1);
        }
        msg
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn add_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push((name.into(), value.into()));
    }

    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        if let Some((_, existing)) = self
            .headers
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case(&name))
        {
            *existing = value;
        } else {
            self.headers.push((name, value));
        }
    }

    pub fn replace_header(&mut self, name: &str, value: impl Into<String>) {
        self.set_header(name.to_string(), value.into());
    }

    pub fn remove_all(&mut self, name: &str) {
        self.headers
            .retain(|(key, _)| !key.eq_ignore_ascii_case(name));
    }

    pub fn as_string(&self) -> String {
        let mut out = String::new();
        for (name, value) in &self.headers {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push('\n');
        }
        out.push('\n');
        out
    }

    pub fn ensure_threaded(&self) -> Result<()> {
        if !self.contains("PV") || !self.contains("Thread") {
            return Err(PyzorError::IncompleteMessage(
                "Doesn't have fields for a ThreadedMessage.".to_string(),
            ));
        }
        Ok(())
    }

    pub fn ensure_request(&self) -> Result<()> {
        if !self.contains("Op") {
            return Err(PyzorError::IncompleteMessage(
                "doesn't have fields for a Request".to_string(),
            ));
        }
        self.ensure_threaded()
    }

    pub fn ensure_response(&self) -> Result<()> {
        if !self.contains("Code") || !self.contains("Diag") {
            return Err(PyzorError::IncompleteMessage(
                "doesn't have fields for a Response".to_string(),
            ));
        }
        self.ensure_threaded()
    }

    pub fn code(&self) -> Result<u16> {
        self.get("Code")
            .ok_or_else(|| PyzorError::IncompleteMessage("missing Code".to_string()))?
            .parse()
            .map_err(|_| PyzorError::Protocol("Invalid response code".to_string()))
    }

    pub fn diag(&self) -> &str {
        self.get("Diag").unwrap_or("")
    }

    pub fn is_ok(&self) -> bool {
        self.code().is_ok_and(|code| code == 200)
    }

    pub fn thread(&self) -> Result<ThreadId> {
        let value = self
            .get("Thread")
            .ok_or_else(|| PyzorError::IncompleteMessage("missing Thread".to_string()))?;
        value
            .parse::<u16>()
            .map(ThreadId)
            .map_err(|_| PyzorError::Protocol("Invalid thread id".to_string()))
    }

    pub fn head_tuple(&self) -> String {
        let code = self.code().unwrap_or(0);
        format!("({}, '{}')", code, python_repr::single_quoted(self.diag()))
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_string())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ThreadId(pub u16);

impl ThreadId {
    pub const ERROR_VALUE: ThreadId = ThreadId(0);
    pub const OK_MIN: u16 = 1024;

    pub fn generate() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let range = (u16::MAX as u128 + 1) - Self::OK_MIN as u128;
        Self((Self::OK_MIN as u128 + (nanos % range)) as u16)
    }

    pub fn in_ok_range(self) -> bool {
        self.0 >= Self::OK_MIN
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub fn request(op: &str) -> Message {
    let mut msg = Message::new();
    msg.add_header("Op", op);
    msg
}

pub fn digest_request(op: &str, digest: &str) -> Message {
    let mut msg = request(op);
    msg.add_header("Op-Digest", digest);
    msg
}

pub fn spec_digest_request(op: &str, digest: &str, spec: &[(usize, usize)]) -> Message {
    let mut msg = digest_request(op, digest);
    let flat = spec
        .iter()
        .flat_map(|(offset, length)| [offset.to_string(), length.to_string()])
        .collect::<Vec<_>>()
        .join(",");
    msg.add_header("Op-Spec", flat);
    msg
}

pub fn init_for_sending(msg: &mut Message) {
    if !msg.contains("Thread") {
        msg.add_header("Thread", ThreadId::generate().to_string());
    }
    msg.set_header("PV", PROTO_VERSION);
}

pub fn response(thread: Option<&str>) -> Message {
    let mut msg = Message::new();
    msg.add_header("Code", "200");
    msg.add_header("Diag", "OK");
    msg.add_header("PV", PROTO_VERSION);
    if let Some(thread) = thread {
        msg.add_header("Thread", thread);
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::Message;

    #[test]
    fn preserves_duplicate_headers() {
        let msg = Message::parse(b"Op-Digest: a\nOp-Digest: b\n\n");
        assert_eq!(msg.get_all("Op-Digest"), vec!["a", "b"]);
        assert_eq!(msg.as_string(), "Op-Digest: a\nOp-Digest: b\n\n");
    }
}
