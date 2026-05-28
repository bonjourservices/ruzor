use ruzor::digest::{digest_message, normalize, normalize_html_part, predigest_message};

const HTML_TEXT: &str = r#"<html><head><title>Email spam</title></head><body>
<p><b>Email spam</b>, also known as <b>junk email</b> 
or <b>unsolicited bulk email</b> (<i>UBE</i>), is a subset of 
<a href="/wiki/Spam_(electronic)" title="Spam (electronic)">electronic spam</a> 
involving nearly identical messages sent to numerous recipients by <a href="/wiki/Email" title="Email">
email</a>. Clicking on <a href="/wiki/Html_email#Security_vulnerabilities" title="Html email" class="mw-redirect">
links in spam email</a> may send users to <a href="/wiki/Phishing" title="Phishing">phishing</a> 
web sites or sites that are hosting <a href="/wiki/Malware" title="Malware">malware</a>.</body></html>"#;

const HTML_TEXT_STRIPPED: &str = "Email spam Email spam , also known as junk email or unsolicited bulk email ( UBE ), is a subset of electronic spam involving nearly identical messages sent to numerous recipients by email . Clicking on links in spam email may send users to phishing web sites or sites that are hosting malware .";

#[test]
fn digest_payloads_keep_unterminated_multipart_child_like_reference() {
    assert_eq!(
        predigest_message(
            b"Content-Type: multipart/mixed; boundary=outer\n\n--outer\nContent-Type: multipart/alternative; boundary=inner\n\n--inner\nContent-Type: text/plain; charset=ISO-8859-1\n\nThis is a test ma\0iling\n--outer--"
        ),
        vec!["Thisisatestmailing"]
    );
}

#[test]
fn digest_payloads_decode_cp1258_like_python_codecs() {
    assert_eq!(
        predigest_message(
            b"Content-Type: text/plain; charset=cp1258\nContent-Transfer-Encoding: base64\n\nVGhpcyBpcyBhIHTpc3Qg4qXG\n"
        ),
        vec!["Thisisatéstâ¥Æ"]
    );
}

#[test]
fn html_stripping_matches_reference_cases() {
    assert_eq!(normalize_html_part(HTML_TEXT), HTML_TEXT_STRIPPED);
    assert_eq!(
        normalize_html_part(
            "<html><head></head><sTyle>Some random style</stylE>\n<body>This is a test.</body></html>\n"
        ),
        "This is a test."
    );
    assert_eq!(
        normalize_html_part(
            "<html><head></head><SCRIPT>Some random script</SCRIPT>\n<body>This is a test.</body></html>\n"
        ),
        "This is a test."
    );
}

#[test]
fn predigest_removes_reference_email_url_and_long_tokens() {
    for email in [
        "test@example.com",
        "test123@example.com",
        "test+abc@example.com",
        "test.test2@example.com",
        "test.test2+abc@example.com",
    ] {
        assert_eq!(normalize(&format!("Test {email} Test2")), "TestTest2");
    }

    for url in [
        "http://www.example.com",
        "http://example.com",
        "http://www.example.com/test/http://www.example.com/test/test2",
    ] {
        assert_eq!(normalize(&format!("Test {url} Test2")), "TestTest2");
    }

    for long in ["0A2D3f%a#S", "3sddkf9jdkd9", "@@#@@@@@@@@@"] {
        assert_eq!(normalize(&format!("Test {long} Test2")), "TestTest2");
    }
}

#[test]
fn predigest_line_selection_matches_reference_cases() {
    assert_eq!(
        predigest_message(b"This line is included\nnot this\nThis also"),
        vec!["Thislineisincluded", "Thisalso"]
    );

    assert_eq!(
        predigest_message(b"All this message\nShould be included\nIn the predigest"),
        vec!["Allthismessage", "Shouldbeincluded", "Inthepredigest"]
    );

    let mut message = String::new();
    for i in 0..100 {
        message.push_str(&format!("Line{i} test test test\n"));
    }
    assert_eq!(
        predigest_message(message.as_bytes()),
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
fn digest_matches_reference_simple_and_null_cases() {
    assert_eq!(
        digest_message(b"That's some good ham right there"),
        "0e01d5b816fe609f991576834db4da3c182bcef6"
    );
    assert_eq!(
        digest_message(b"That's some good ham rig\0ht there"),
        "0e01d5b816fe609f991576834db4da3c182bcef6"
    );
}

#[test]
fn digest_payloads_match_reference_message_part_cases() {
    assert_eq!(
        predigest_message(
            b"Content-Type: text/plain; charset=utf8\n\nThat's some good ham right there"
        ),
        vec!["That'ssomegoodhamrightthere"]
    );
    assert_eq!(
        predigest_message(
            b"Content-Type: text/html; charset=utf8\n\n<html><body>This is a test.</body></html>"
        ),
        vec!["Thisisatest."]
    );
    assert_eq!(
        predigest_message(b"Content-Type: application/octet-stream\n\nbin payload ok"),
        vec!["binpayloadok"]
    );
}

#[test]
fn digest_payload_charset_fallbacks_match_reference_cases() {
    assert_eq!(
        predigest_message(
            b"Content-Type: text/plain; charset=x-unknown-pyzor\n\nCafe caf\xc3\xa9 payload"
        ),
        vec!["Cafecafpayload"]
    );
    assert_eq!(
        predigest_message(b"Content-Type: text/plain; charset=utf8\n\nCafe caf\xff payload"),
        vec!["Cafecafpayload"]
    );
    assert_eq!(
        predigest_message(b"Content-Type: text/plain; charset=quopri\n\nThis=20line=20decoded"),
        Vec::<String>::new()
    );
}
