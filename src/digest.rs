use crate::sha1::Sha1;
use encoding_rs::Encoding;

pub const DIGEST_SPEC: &[(usize, usize)] = &[(20, 3), (60, 3)];
pub const HASH_SIZE: usize = 40;

#[derive(Clone, Debug)]
struct Part {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Part {
    fn parse(bytes: &[u8]) -> Self {
        let normalized = normalize_message_newlines(bytes);
        let (header_bytes, body) = match find_subslice(&normalized, b"\n\n") {
            Some(index) => (&normalized[..index], normalized[index + 2..].to_vec()),
            None => {
                let text = String::from_utf8_lossy(&normalized);
                if text.lines().next().map(valid_header_line).unwrap_or(false) {
                    (normalized.as_slice(), Vec::new())
                } else {
                    (&[][..], normalized)
                }
            }
        };
        let header_text = String::from_utf8_lossy(header_bytes);
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut current: Option<usize> = None;
        for line in header_text.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                if let Some(index) = current {
                    headers[index].1.push(' ');
                    headers[index].1.push_str(line.trim());
                }
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            headers.push((name.trim().to_string(), value.trim().to_string()));
            current = Some(headers.len() - 1);
        }
        Self { headers, body }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn content_type(&self) -> ContentType {
        ContentType::parse(self.header("Content-Type").unwrap_or("text/plain"))
    }

    fn transfer_encoding(&self) -> &str {
        self.header("Content-Transfer-Encoding")
            .unwrap_or("7bit")
            .trim()
    }
}

fn normalize_message_newlines(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                normalized.push(b'\n');
                index += 1;
                if index < bytes.len() && bytes[index] == b'\n' {
                    index += 1;
                }
            }
            byte => {
                normalized.push(byte);
                index += 1;
            }
        }
    }
    normalized
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn valid_header_line(line: &str) -> bool {
    let Some((name, _)) = line.split_once(':') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

#[derive(Clone, Debug)]
struct ContentType {
    main: String,
    sub: String,
    boundary: Option<String>,
    charset: Option<String>,
}

impl ContentType {
    fn parse(value: &str) -> Self {
        let mut parts = value.split(';');
        let media = parts.next().unwrap_or("text/plain").trim().to_lowercase();
        let (main, sub) = media
            .split_once('/')
            .map(|(main, sub)| (main.trim().to_string(), sub.trim().to_string()))
            .unwrap_or_else(|| ("text".to_string(), "plain".to_string()));
        let mut boundary = None;
        let mut charset = None;
        for part in parts {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            let key = key.trim().to_lowercase();
            let value = value.trim().trim_matches('"').replace('\0', "");
            match key.as_str() {
                "boundary" => boundary = Some(value),
                "charset" => charset = Some(value),
                _ => {}
            }
        }
        Self {
            main,
            sub,
            boundary,
            charset,
        }
    }
}

pub fn digest_message(bytes: &[u8]) -> String {
    digest_with_spec(bytes, DIGEST_SPEC)
}

pub fn digest_with_spec(bytes: &[u8], spec: &[(usize, usize)]) -> String {
    let mut sha = Sha1::new();
    for line in predigest_with_spec(bytes, spec) {
        sha.update(line.as_bytes());
    }
    let value = sha.hexdigest();
    debug_assert_eq!(value.len(), HASH_SIZE);
    value
}

pub fn predigest_message(bytes: &[u8]) -> Vec<String> {
    predigest_with_spec(bytes, DIGEST_SPEC)
}

pub fn predigest_with_spec(bytes: &[u8], spec: &[(usize, usize)]) -> Vec<String> {
    let root = Part::parse(bytes);
    let mut payloads = Vec::new();
    digest_payloads(&root, &mut payloads);

    let mut lines = Vec::new();
    for payload in payloads {
        for line in payload.lines() {
            let normalized = normalize(line);
            if should_handle_line(&normalized) {
                lines.push(normalized);
            }
        }
    }

    if lines.len() <= 4 {
        lines
    } else {
        let mut selected = Vec::new();
        for (offset, length) in spec {
            for i in 0..*length {
                let index = offset * lines.len() / 100 + i;
                if let Some(line) = lines.get(index) {
                    selected.push(line.clone());
                }
            }
        }
        selected
    }
}

pub fn digest_mbox(bytes: &[u8]) -> Vec<String> {
    split_mbox(bytes)
        .into_iter()
        .map(|message| digest_message(&message))
        .collect()
}

pub fn split_mbox(bytes: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut messages = Vec::new();
    let mut current = Vec::new();
    let mut seen_boundary = false;
    for line in text.lines() {
        if line.starts_with("From ") {
            if seen_boundary && !current.is_empty() {
                messages.push(current.join("\n").into_bytes());
                current.clear();
            }
            seen_boundary = true;
            continue;
        }
        current.push(line.to_string());
    }
    if !current.is_empty() || !seen_boundary {
        messages.push(current.join("\n").into_bytes());
    }
    messages
}

fn digest_payloads(part: &Part, out: &mut Vec<String>) {
    let content_type = part.content_type();
    if content_type.main == "multipart" {
        if let Some(boundary) = content_type.boundary {
            for child in split_multipart(&part.body, &boundary) {
                digest_payloads(&Part::parse(&child), out);
            }
        }
        return;
    }

    if content_type.main == "text" {
        let decoded_bytes = decode_transfer(&part.body, part.transfer_encoding());
        let charset = content_type.charset.as_deref().unwrap_or("ascii");
        let payload = decode_charset(&decoded_bytes, charset);
        if content_type.sub == "html" {
            out.push(normalize_html_part(&payload));
        } else {
            out.push(payload);
        }
    } else {
        out.push(String::from_utf8_lossy(&part.body).to_string());
    }
}

fn split_multipart(bytes: &[u8], boundary: &str) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let marker = format!("--{}", boundary);
    let closing = format!("--{}--", boundary);
    let mut parts = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut inside = false;
    let mut closed = false;
    for line in text.lines() {
        if line.trim_end() == marker {
            if inside && !current.is_empty() {
                parts.push(current.join("\n").into_bytes());
                current.clear();
            }
            inside = true;
            continue;
        }
        if line.trim_end() == closing {
            if inside && !current.is_empty() {
                parts.push(current.join("\n").into_bytes());
            }
            closed = true;
            break;
        }
        if inside {
            current.push(line.to_string());
        }
    }
    if inside && !closed && !current.is_empty() {
        parts.push(current.join("\n").into_bytes());
    }
    parts
}

pub fn normalize(input: &str) -> String {
    let without_nuls = input.replace('\0', "");
    let mut out = String::new();
    let mut token = String::new();
    for ch in without_nuls.chars() {
        if ch.is_whitespace() {
            push_normalized_token(&mut out, &token);
            token.clear();
        } else {
            token.push(ch);
        }
    }
    push_normalized_token(&mut out, &token);
    out.trim().to_string()
}

fn push_normalized_token(out: &mut String, token: &str) {
    if token.is_empty() {
        return;
    }
    if token.chars().count() >= 10 {
        return;
    }
    if looks_like_email(token) || looks_like_url(token) {
        return;
    }
    out.push_str(token);
}

fn looks_like_email(token: &str) -> bool {
    let Some(index) = token.find('@') else {
        return false;
    };
    index > 0 && index + 1 < token.len()
}

fn looks_like_url(token: &str) -> bool {
    let Some(index) = token.find(':') else {
        return false;
    };
    index > 0 && token[..index].chars().all(|ch| ch.is_ascii_alphabetic())
}

fn should_handle_line(line: &str) -> bool {
    line.len() >= 8
}

pub fn normalize_html_part(input: &str) -> String {
    let mut data = Vec::new();
    let mut text = String::new();
    let mut tag = String::new();
    let mut in_tag = false;
    let mut collect = true;

    for ch in input.chars() {
        match (in_tag, ch) {
            (false, '<') => {
                push_html_text(&mut data, &text, collect);
                text.clear();
                tag.clear();
                in_tag = true;
            }
            (true, '>') => {
                let name = tag_name(&tag);
                if name == "script" || name == "style" {
                    collect = tag.trim_start().starts_with('/');
                }
                in_tag = false;
            }
            (true, _) => tag.push(ch),
            (false, _) => text.push(ch),
        }
    }
    push_html_text(&mut data, &text, collect);
    data.join(" ")
}

fn push_html_text(data: &mut Vec<String>, text: &str, collect: bool) {
    let text = text.trim();
    if collect && !text.is_empty() {
        data.push(html_unescape(text));
    }
}

fn tag_name(tag: &str) -> String {
    tag.trim_start_matches('/')
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches('/')
        .to_lowercase()
}

fn html_unescape(value: &str) -> String {
    value
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn decode_transfer(bytes: &[u8], encoding: &str) -> Vec<u8> {
    match encoding.trim().to_lowercase().as_str() {
        "quoted-printable" | "quopri" => decode_quoted_printable(bytes),
        "base64" => decode_base64(bytes),
        _ => bytes.to_vec(),
    }
}

fn decode_quoted_printable(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 1 < bytes.len() && (bytes[i + 1] == b'\n' || bytes[i + 1] == b'\r') {
                i += 2;
                if i < bytes.len() && bytes[i - 1] == b'\r' && bytes[i] == b'\n' {
                    i += 1;
                }
                continue;
            }
            if i + 2 < bytes.len()
                && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
            {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn decode_base64(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in bytes.iter().copied().filter(|b| !b.is_ascii_whitespace()) {
        if byte == b'=' {
            break;
        }
        let Some(value) = base64_val(byte) else {
            continue;
        };
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}

fn base64_val(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_charset(bytes: &[u8], charset: &str) -> String {
    let normalized = charset
        .to_lowercase()
        .replace('_', "-")
        .replace(char::from(0), "");

    match normalized.as_str() {
        "ascii" | "us-ascii" => decode_ascii_ignore(bytes),
        "utf8" | "utf-8" => decode_utf8_ignore(bytes),
        "iso-8859-1" | "latin-1" | "latin1" => bytes.iter().map(|byte| *byte as char).collect(),
        "quopri-codec" | "quopri" | "quoted-printable" | "quotedprintable" => {
            decode_ascii_ignore(bytes)
        }
        _ => decode_registered_charset(bytes, &normalized)
            .unwrap_or_else(|| decode_ascii_ignore(bytes)),
    }
}

fn decode_registered_charset(bytes: &[u8], charset: &str) -> Option<String> {
    Encoding::for_label(charset.as_bytes())
        .and_then(|encoding| encoding.decode_without_bom_handling_and_without_replacement(bytes))
        .map(|decoded| decoded.into_owned())
}

fn decode_ascii_ignore(bytes: &[u8]) -> String {
    bytes
        .iter()
        .filter(|byte| byte.is_ascii())
        .map(|byte| *byte as char)
        .collect()
}

fn decode_utf8_ignore(mut bytes: &[u8]) -> String {
    let mut out = String::new();
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(error) => {
                let valid_up_to = error.valid_up_to();
                if valid_up_to > 0 {
                    out.push_str(std::str::from_utf8(&bytes[..valid_up_to]).unwrap());
                }
                let skip = error.error_len().unwrap_or(1);
                bytes = &bytes[valid_up_to + skip..];
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{digest_message, normalize, normalize_html_part, predigest_message};

    #[test]
    fn digest_matches_python_simple() {
        assert_eq!(
            digest_message(b"That's some good ham right there"),
            "0e01d5b816fe609f991576834db4da3c182bcef6"
        );
    }

    #[test]
    fn digest_removes_nulls() {
        assert_eq!(
            digest_message(b"That's some good ham rig\0ht there"),
            "0e01d5b816fe609f991576834db4da3c182bcef6"
        );
    }

    #[test]
    fn predigest_atomic_and_pieced() {
        assert_eq!(
            predigest_message(b"All this message\nShould be included\nIn the predigest"),
            vec!["Allthismessage", "Shouldbeincluded", "Inthepredigest"]
        );
        let mut msg = String::new();
        for i in 0..100 {
            msg.push_str(&format!("Line{} test test test\n", i));
        }
        assert_eq!(
            predigest_message(msg.as_bytes()),
            vec![
                "Line20testtesttest",
                "Line21testtesttest",
                "Line22testtesttest",
                "Line60testtesttest",
                "Line61testtesttest",
                "Line62testtesttest",
            ]
        );
    }

    #[test]
    fn normalizes_tokens() {
        assert_eq!(normalize("Test test@example.com Test2"), "TestTest2");
        assert_eq!(normalize("Test http://example.com Test2"), "TestTest2");
        assert_eq!(normalize("Test 3sddkf9jdkd9 Test2"), "TestTest2");
    }

    #[test]
    fn strips_html_script_and_style() {
        assert_eq!(
            normalize_html_part(
                r#"<html><style>style</style><SCRIPT>script</SCRIPT><body>This is a test.</body></html>"#
            ),
            "This is a test."
        );
    }
}
