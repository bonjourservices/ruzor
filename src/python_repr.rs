pub(crate) fn string(value: &str) -> String {
    quote_bytes("", value.as_bytes())
}

pub(crate) fn bytes(bytes: &[u8]) -> String {
    quote_bytes("b", bytes)
}

pub(crate) fn text(value: &str) -> String {
    let mut output = String::from("'");
    for ch in value.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '\'' => output.push_str("\\'"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch => output.push(ch),
        }
    }
    output.push('\'');
    output
}

pub(crate) fn single_quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn quote_bytes(prefix: &str, bytes: &[u8]) -> String {
    let mut output = String::from(prefix);
    output.push('\'');
    for &byte in bytes {
        push_byte_repr(&mut output, byte);
    }
    output.push('\'');
    output
}

fn push_byte_repr(output: &mut String, byte: u8) {
    match byte {
        b'\\' => output.push_str("\\\\"),
        b'\'' => output.push_str("\\'"),
        b'\n' => output.push_str("\\n"),
        b'\r' => output.push_str("\\r"),
        b'\t' => output.push_str("\\t"),
        b' '..=b'~' => output.push(byte as char),
        _ => output.push_str(&format!("\\x{byte:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{bytes, single_quoted, string, text};

    #[test]
    fn repr_variants_match_existing_legacy_formats() {
        assert_eq!(string("a\n\x7f"), "'a\\n\\x7f'");
        assert_eq!(bytes(b"a\n\xff"), "b'a\\n\\xff'");
        assert_eq!(text("a\n\t'"), "'a\\n\\t\\''");
        assert_eq!(single_quoted("a\\b'c"), "a\\\\b\\'c");
    }
}
