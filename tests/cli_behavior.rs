use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pyzor::client::Client;
use pyzor::config::Address;
use pyzor::engines::FileDatabase;
use pyzor::serve_socket_until_shutdown;

const MSG: &str = "Newsgroups:
Date: Wed, 10 Apr 2002 22:23:51 -0400 (EDT)
From: Frank Tobin <ftobin@neverending.org>
MIME-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII

Test Email
";
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
fn cli_report_check_and_local_whitelist_behave_like_pyzor() {
    let mut server = TestServer::start("cli-report-check-local");
    let homedir = temp_dir("cli-report-check-local-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();

    let first_check = run_pyzor(&homedir, &["check"], MSG);
    assert!(!first_check.status.success(), "{first_check:?}");
    assert_eq!(String::from_utf8_lossy(&first_check.stderr), "");
    assert_stdout_contains(&first_check, "(200, 'OK')\t0\t0");

    let report = run_pyzor(&homedir, &["report"], MSG);
    assert!(report.status.success(), "{report:?}");
    assert_eq!(String::from_utf8_lossy(&report.stderr), "");
    assert_stdout_contains(&report, "(200, 'OK')");

    let second_check = run_pyzor(&homedir, &["check"], MSG);
    assert!(second_check.status.success(), "{second_check:?}");
    assert_stdout_contains(&second_check, "(200, 'OK')\t1\t0");

    let local_whitelist = run_pyzor(&homedir, &["local_whitelist"], MSG);
    assert!(local_whitelist.status.success(), "{local_whitelist:?}");
    assert_eq!(String::from_utf8(local_whitelist.stdout).unwrap(), "");
    let locally_whitelisted = run_pyzor(&homedir, &["check"], MSG);
    assert!(
        !locally_whitelisted.status.success(),
        "{locally_whitelisted:?}"
    );
    assert_stdout_contains(&locally_whitelisted, "(200, 'OK')\t0\t0");

    let local_unwhitelist = run_pyzor(&homedir, &["local_unwhitelist"], MSG);
    assert!(local_unwhitelist.status.success(), "{local_unwhitelist:?}");
    let after_unwhitelist = run_pyzor(&homedir, &["check"], MSG);
    assert!(after_unwhitelist.status.success(), "{after_unwhitelist:?}");
    assert_stdout_contains(&after_unwhitelist, "(200, 'OK')\t1\t0");

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_check_prints_local_whitelist_results_before_remote_results_like_python() {
    let mut server = TestServer::start("cli-local-check-order");
    let homedir = temp_dir("cli-local-check-order-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();
    let remote_digest = "da39a3ee5e6b4b0d3255bfef95601890afd80701";
    let local_digest = "da39a3ee5e6b4b0d3255bfef95601890afd80702";
    std::fs::write(homedir.join("whitelist"), format!("{local_digest}\n")).unwrap();

    let report = run_pyzor(&homedir, &["-s", "digests", "report"], remote_digest);
    assert!(report.status.success(), "{report:?}");

    let check = run_pyzor(
        &homedir,
        &["-s", "digests", "check"],
        &format!("{remote_digest}\n{local_digest}\n"),
    );
    assert!(check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(0, 0), (1, 0)]);

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_thresholds_use_strict_greater_than_counts() {
    let mut server = TestServer::start("cli-thresholds");
    let homedir = temp_dir("cli-thresholds-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();

    for _ in 0..3 {
        let report = run_pyzor(&homedir, &["report"], MSG);
        assert!(report.status.success(), "{report:?}");
    }

    let report_threshold_equal = run_pyzor(&homedir, &["-r", "3", "check"], MSG);
    assert!(
        !report_threshold_equal.status.success(),
        "{report_threshold_equal:?}"
    );
    assert_stdout_contains(&report_threshold_equal, "(200, 'OK')\t3\t0");

    let report_threshold_below = run_pyzor(&homedir, &["-r", "2", "check"], MSG);
    assert!(
        report_threshold_below.status.success(),
        "{report_threshold_below:?}"
    );
    assert_stdout_contains(&report_threshold_below, "(200, 'OK')\t3\t0");

    for _ in 0..3 {
        let whitelist = run_pyzor(&homedir, &["whitelist"], MSG);
        assert!(whitelist.status.success(), "{whitelist:?}");
    }

    let whitelist_threshold_equal = run_pyzor(&homedir, &["-w", "3", "check"], MSG);
    assert!(
        whitelist_threshold_equal.status.success(),
        "{whitelist_threshold_equal:?}"
    );
    assert_stdout_contains(&whitelist_threshold_equal, "(200, 'OK')\t3\t3");

    let whitelist_threshold_below = run_pyzor(&homedir, &["-w", "2", "check"], MSG);
    assert!(
        !whitelist_threshold_below.status.success(),
        "{whitelist_threshold_below:?}"
    );
    assert_stdout_contains(&whitelist_threshold_below, "(200, 'OK')\t3\t3");

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}
#[test]
fn cli_report_and_whitelist_threshold_sequences_match_python_functional_tests() {
    let mut server = TestServer::start("cli-report-whitelist-separate-thresholds");
    let homedir = temp_dir("cli-report-whitelist-separate-thresholds-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();

    let report_input = "Test1 report threshold 1  Test2";
    let report = run_pyzor(&homedir, &["-r", "2", "report"], report_input);
    assert!(report.status.success(), "{report:?}");
    let check = run_pyzor(&homedir, &["-r", "2", "check"], report_input);
    assert!(!check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(1, 0)]);

    let report = run_pyzor(&homedir, &["-r", "2", "report"], report_input);
    assert!(report.status.success(), "{report:?}");
    let check = run_pyzor(&homedir, &["-r", "2", "check"], report_input);
    assert!(!check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(2, 0)]);

    let report = run_pyzor(&homedir, &["-r", "2", "report"], report_input);
    assert!(report.status.success(), "{report:?}");
    let check = run_pyzor(&homedir, &["-r", "2", "check"], report_input);
    assert!(check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(3, 0)]);

    let whitelist_input = "Test1 white list threshold 1  Test2";
    let report = run_pyzor(&homedir, &["-w", "2", "report"], whitelist_input);
    assert!(report.status.success(), "{report:?}");
    let check = run_pyzor(&homedir, &["-w", "2", "check"], whitelist_input);
    assert!(check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(1, 0)]);

    for expected in [(1, 1), (1, 2)] {
        let whitelist = run_pyzor(&homedir, &["-w", "2", "whitelist"], whitelist_input);
        assert!(whitelist.status.success(), "{whitelist:?}");
        let check = run_pyzor(&homedir, &["-w", "2", "check"], whitelist_input);
        assert!(check.status.success(), "{check:?}");
        assert_count_pairs(&check, &[expected]);
    }

    let whitelist = run_pyzor(&homedir, &["-w", "2", "whitelist"], whitelist_input);
    assert!(whitelist.status.success(), "{whitelist:?}");
    let check = run_pyzor(&homedir, &["-w", "2", "check"], whitelist_input);
    assert!(!check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(1, 3)]);

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_report_whitelist_threshold_sequence_matches_python_functional_test() {
    let mut server = TestServer::start("cli-report-whitelist-threshold");
    let homedir = temp_dir("cli-report-whitelist-threshold-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();
    let input = "Test1 report white list threshold 1  Test2";

    let first_report = run_pyzor(&homedir, &["-w", "2", "-r", "1", "report"], input);
    assert!(first_report.status.success(), "{first_report:?}");
    let first_check = run_pyzor(&homedir, &["-w", "2", "-r", "1", "check"], input);
    assert!(!first_check.status.success(), "{first_check:?}");
    assert_count_pairs(&first_check, &[(1, 0)]);

    let second_report = run_pyzor(&homedir, &["-w", "2", "-r", "1", "report"], input);
    assert!(second_report.status.success(), "{second_report:?}");
    let second_check = run_pyzor(&homedir, &["-w", "2", "-r", "1", "check"], input);
    assert!(second_check.status.success(), "{second_check:?}");
    assert_count_pairs(&second_check, &[(2, 0)]);

    for expected in [(2, 1), (2, 2)] {
        let whitelist = run_pyzor(&homedir, &["-w", "2", "-r", "1", "whitelist"], input);
        assert!(whitelist.status.success(), "{whitelist:?}");
        let check = run_pyzor(&homedir, &["-w", "2", "-r", "1", "check"], input);
        assert!(check.status.success(), "{check:?}");
        assert_count_pairs(&check, &[expected]);
    }

    let final_whitelist = run_pyzor(&homedir, &["-w", "2", "-r", "1", "whitelist"], input);
    assert!(final_whitelist.status.success(), "{final_whitelist:?}");
    let final_check = run_pyzor(&homedir, &["-w", "2", "-r", "1", "check"], input);
    assert!(!final_check.status.success(), "{final_check:?}");
    assert_count_pairs(&final_check, &[(2, 3)]);

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_report_and_whitelist_updates_info_timestamps_like_python_functional_test() {
    let mut server = TestServer::start("cli-info-update-timestamps");
    let homedir = temp_dir("cli-info-update-timestamps-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();
    let input = "Test1 white list report update1 Test2";

    let first_whitelist = run_pyzor(&homedir, &["whitelist"], input);
    assert!(first_whitelist.status.success(), "{first_whitelist:?}");
    let first_report = run_pyzor(&homedir, &["report"], input);
    assert!(first_report.status.success(), "{first_report:?}");

    std::thread::sleep(std::time::Duration::from_millis(1_100));

    let second_whitelist = run_pyzor(&homedir, &["whitelist"], input);
    assert!(second_whitelist.status.success(), "{second_whitelist:?}");
    let second_report = run_pyzor(&homedir, &["report"], input);
    assert!(second_report.status.success(), "{second_report:?}");

    let check = run_pyzor(&homedir, &["check"], input);
    assert!(!check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(2, 2)]);

    let info = run_pyzor(&homedir, &["info"], input);
    assert!(info.status.success(), "{info:?}");
    let record = parse_info_record(&info);
    assert_eq!(record.get("Count").map(String::as_str), Some("2"));
    assert_eq!(record.get("WL-Count").map(String::as_str), Some("2"));
    assert_ne!(record["Entered"], record["Updated"]);
    assert_ne!(record["WL-Entered"], record["WL-Updated"]);
    assert_ne!(record["Updated"], "Never");
    assert_ne!(record["WL-Updated"], "Never");

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_process_gdbm_core_functional_mixin_matches_python() {
    let homedir = temp_dir("cli-process-gdbm-core-home");
    let port = free_udp_port();
    std::fs::write(homedir.join("servers"), format!("127.0.0.1:{port}\n")).unwrap();
    std::fs::write(homedir.join("pyzord.passwd"), "").unwrap();
    std::fs::write(homedir.join("pyzord.access"), "ALL : anonymous : allow\n").unwrap();
    let mut server = spawn_pyzord_process(&homedir, port);
    let address: Address = ("127.0.0.1".to_string(), port);
    wait_for_process_server(&mut server, &address);

    let pong = run_pyzor(&homedir, &["pong"], "Test1 pong1 Test2");
    assert!(pong.status.success(), "{pong:?}");
    assert_count_pairs(&pong, &[(isize::MAX as i64, 0)]);

    let fresh_check = run_pyzor(&homedir, &["check"], "Test1 check1 Test2");
    assert!(!fresh_check.status.success(), "{fresh_check:?}");
    assert_count_pairs(&fresh_check, &[(0, 0)]);
    let fresh_record = info_record(&homedir, "Test1 check1 Test2");
    assert_eq!(fresh_record.get("Count").map(String::as_str), Some("0"));

    let report_input = "Test1 report update1 Test2";
    let report = run_pyzor(&homedir, &["report"], report_input);
    assert!(report.status.success(), "{report:?}");
    let check = run_pyzor(&homedir, &["check"], report_input);
    assert!(check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(1, 0)]);
    std::thread::sleep(Duration::from_millis(1_100));
    let report = run_pyzor(&homedir, &["report"], report_input);
    assert!(report.status.success(), "{report:?}");
    let check = run_pyzor(&homedir, &["check"], report_input);
    assert!(check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(2, 0)]);
    let record = info_record(&homedir, report_input);
    assert_eq!(record.get("Count").map(String::as_str), Some("2"));
    assert_ne!(record["Entered"], record["Updated"]);

    let whitelist_input = "Test1 white list update1 Test2";
    let whitelist = run_pyzor(&homedir, &["whitelist"], whitelist_input);
    assert!(whitelist.status.success(), "{whitelist:?}");
    let check = run_pyzor(&homedir, &["check"], whitelist_input);
    assert!(!check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(0, 1)]);
    std::thread::sleep(Duration::from_millis(1_100));
    let whitelist = run_pyzor(&homedir, &["whitelist"], whitelist_input);
    assert!(whitelist.status.success(), "{whitelist:?}");
    let check = run_pyzor(&homedir, &["check"], whitelist_input);
    assert!(!check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(0, 2)]);
    let record = info_record(&homedir, whitelist_input);
    assert_eq!(record.get("WL-Count").map(String::as_str), Some("2"));
    assert_ne!(record["WL-Entered"], record["WL-Updated"]);

    let combined_input = "Test1 white list report update1 Test2";
    let whitelist = run_pyzor(&homedir, &["whitelist"], combined_input);
    assert!(whitelist.status.success(), "{whitelist:?}");
    let report = run_pyzor(&homedir, &["report"], combined_input);
    assert!(report.status.success(), "{report:?}");
    let check = run_pyzor(&homedir, &["check"], combined_input);
    assert!(!check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(1, 1)]);
    std::thread::sleep(Duration::from_millis(1_100));
    let whitelist = run_pyzor(&homedir, &["whitelist"], combined_input);
    assert!(whitelist.status.success(), "{whitelist:?}");
    let report = run_pyzor(&homedir, &["report"], combined_input);
    assert!(report.status.success(), "{report:?}");
    let check = run_pyzor(&homedir, &["check"], combined_input);
    assert!(!check.status.success(), "{check:?}");
    assert_count_pairs(&check, &[(2, 2)]);
    let record = info_record(&homedir, combined_input);
    assert_eq!(record.get("Count").map(String::as_str), Some("2"));
    assert_eq!(record.get("WL-Count").map(String::as_str), Some("2"));
    assert_ne!(record["Entered"], record["Updated"]);
    assert_ne!(record["WL-Entered"], record["WL-Updated"]);

    stop_process(server);
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_digest_and_predigest_commands_match_python_functional_test() {
    let homedir = temp_dir("cli-digest-predigest-home");

    let predigest = run_pyzor(&homedir, &["predigest"], REFERENCE_MSG);
    assert!(predigest.status.success(), "{predigest:?}");
    assert_eq!(String::from_utf8(predigest.stdout).unwrap(), "TestEmail\n");

    let digest = run_pyzor(&homedir, &["digest"], REFERENCE_MSG);
    assert!(digest.status.success(), "{digest:?}");
    assert_eq!(
        String::from_utf8(digest.stdout).unwrap(),
        "7421216f915a87e02da034cc483f5c876e1a1338\n"
    );

    let _ = std::fs::remove_dir_all(homedir);
}
#[test]
fn cli_repeated_input_commands_consume_stdin_like_python() {
    let homedir = temp_dir("cli-repeated-input-consume-home");
    let output = run_pyzor(&homedir, &["digest", "digest"], MSG);
    assert!(output.status.success(), "{output:?}");
    let first = pyzor::digest::digest_message(MSG.as_bytes());
    let second = pyzor::digest::digest_message(b"");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{first}\n{second}\n")
    );

    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_help_matches_python_optparse_and_exits_before_homedir() {
    let root = temp_dir("cli-help-root");
    let homedir = root.join("home");
    let output = run_pyzor(&homedir, &["--help"], "");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("Usage: pyzor [options]\n\nRead data from stdin"));
    assert!(stdout.contains("  -h, --help            show this help message and exit"));
    assert!(stdout.contains("  -V, --version         print version and exit"));
    assert!(
        !homedir.exists(),
        "help should exit before creating homedir"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cli_unknown_option_uses_optparse_error_status_and_does_not_create_homedir() {
    let root = temp_dir("cli-unknown-option-root");
    let homedir = root.join("home");
    let output = run_pyzor(&homedir, &["--bogus"], "");

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "Usage: pyzor [options]\n\npyzor: error: no such option: --bogus\n"
    );
    assert!(
        !homedir.exists(),
        "parse errors should exit before creating homedir"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cli_unknown_command_logs_but_keeps_success_exit_like_python() {
    let homedir = temp_dir("cli-unknown-command-home");
    let output = run_pyzor(&homedir, &["unknown_command"], "");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Unknown command: unknown_command"),
        "{output:?}"
    );

    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_unknown_input_style_is_an_error_like_python() {
    let homedir = temp_dir("cli-unknown-style-home");
    let output = run_pyzor(&homedir, &["-s", "bogus", "digest"], MSG);
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Unknown input style."),
        "{output:?}"
    );

    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_digest_style_single_matches_python_functional_test() {
    let mut server = TestServer::start("cli-digest-style-single");
    let homedir = temp_dir("cli-digest-style-single-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();
    let input = "da39a3ee5e6b4b0d3255bfef95601890afd80700";

    let pong = run_pyzor(&homedir, &["-s", "digests", "pong"], input);
    assert!(pong.status.success(), "{pong:?}");
    assert_count_pairs(&pong, &[(isize::MAX as i64, 0)]);

    let initial_check = run_pyzor(&homedir, &["-s", "digests", "check"], input);
    assert!(!initial_check.status.success(), "{initial_check:?}");
    assert_count_pairs(&initial_check, &[(0, 0)]);

    let report = run_pyzor(&homedir, &["-s", "digests", "report"], input);
    assert!(report.status.success(), "{report:?}");
    let after_report = run_pyzor(&homedir, &["-s", "digests", "check"], input);
    assert!(after_report.status.success(), "{after_report:?}");
    assert_count_pairs(&after_report, &[(1, 0)]);

    let whitelist = run_pyzor(&homedir, &["-s", "digests", "whitelist"], input);
    assert!(whitelist.status.success(), "{whitelist:?}");
    let after_whitelist = run_pyzor(&homedir, &["-s", "digests", "check"], input);
    assert!(!after_whitelist.status.success(), "{after_whitelist:?}");
    assert_count_pairs(&after_whitelist, &[(1, 1)]);

    let info = run_pyzor(&homedir, &["-s", "digests", "info"], input);
    assert!(info.status.success(), "{info:?}");
    assert_stdout_contains(&info, "\tCount: 1");
    assert_stdout_contains(&info, "\tWL-Count: 1");

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_mbox_style_single_matches_python_functional_test() {
    let mut server = TestServer::start("cli-mbox-style-single");
    let homedir = temp_dir("cli-mbox-style-single-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();
    let input = "From MAILER-DAEMON Mon Jan  6 15:13:33 2014\n\nTest1 message 0 Test2\n\n";

    let pong = run_pyzor(&homedir, &["-s", "mbox", "pong"], input);
    assert!(pong.status.success(), "{pong:?}");
    assert_count_pairs(&pong, &[(isize::MAX as i64, 0)]);

    let initial_check = run_pyzor(&homedir, &["-s", "mbox", "check"], input);
    assert!(!initial_check.status.success(), "{initial_check:?}");
    assert_count_pairs(&initial_check, &[(0, 0)]);

    let report = run_pyzor(&homedir, &["-s", "mbox", "report"], input);
    assert!(report.status.success(), "{report:?}");
    let after_report = run_pyzor(&homedir, &["-s", "mbox", "check"], input);
    assert!(after_report.status.success(), "{after_report:?}");
    assert_count_pairs(&after_report, &[(1, 0)]);

    let whitelist = run_pyzor(&homedir, &["-s", "mbox", "whitelist"], input);
    assert!(whitelist.status.success(), "{whitelist:?}");
    let after_whitelist = run_pyzor(&homedir, &["-s", "mbox", "check"], input);
    assert!(!after_whitelist.status.success(), "{after_whitelist:?}");
    assert_count_pairs(&after_whitelist, &[(1, 1)]);

    let info = run_pyzor(&homedir, &["-s", "mbox", "info"], input);
    assert!(info.status.success(), "{info:?}");
    assert_stdout_contains(&info, "\tCount: 1");
    assert_stdout_contains(&info, "\tWL-Count: 1");

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_digest_style_multiple_matches_python_functional_test() {
    let mut server = TestServer::start("cli-digest-style-multiple");
    let homedir = temp_dir("cli-digest-style-multiple-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();
    let input2 =
        "da39a3ee5e6b4b0d3255bfef95601890afd80705\nda39a3ee5e6b4b0d3255bfef95601890afd80706\n";
    let input3 = "da39a3ee5e6b4b0d3255bfef95601890afd80705\nda39a3ee5e6b4b0d3255bfef95601890afd80706\nda39a3ee5e6b4b0d3255bfef95601890afd80707\n";

    let pong = run_pyzor(&homedir, &["-s", "digests", "pong"], input3);
    assert!(pong.status.success(), "{pong:?}");
    assert_count_pairs(
        &pong,
        &[
            (isize::MAX as i64, 0),
            (isize::MAX as i64, 0),
            (isize::MAX as i64, 0),
        ],
    );

    let initial_check = run_pyzor(&homedir, &["-s", "digests", "check"], input3);
    assert!(!initial_check.status.success(), "{initial_check:?}");
    assert_count_pairs(&initial_check, &[(0, 0), (0, 0), (0, 0)]);

    let report = run_pyzor(&homedir, &["-s", "digests", "report"], input2);
    assert!(report.status.success(), "{report:?}");

    let after_report = run_pyzor(&homedir, &["-s", "digests", "check"], input3);
    assert!(after_report.status.success(), "{after_report:?}");
    assert_count_pairs(&after_report, &[(1, 0), (1, 0), (0, 0)]);

    let whitelist = run_pyzor(&homedir, &["-s", "digests", "whitelist"], input3);
    assert!(whitelist.status.success(), "{whitelist:?}");

    let after_whitelist = run_pyzor(&homedir, &["-s", "digests", "check"], input3);
    assert!(!after_whitelist.status.success(), "{after_whitelist:?}");
    assert_count_pairs(&after_whitelist, &[(1, 1), (1, 1), (0, 1)]);

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_mbox_style_multiple_matches_python_functional_test() {
    let mut server = TestServer::start("cli-mbox-style-multiple");
    let homedir = temp_dir("cli-mbox-style-multiple-home");
    std::fs::write(
        homedir.join("servers"),
        format!("127.0.0.1:{}\n", server.port),
    )
    .unwrap();
    let input2 = "From MAILER-DAEMON Mon Jan  6 15:08:02 2014\n\nTest1 message 1 Test2\n\nFrom MAILER-DAEMON Mon Jan  6 15:08:05 2014\n\nTest1 message 2 Test2\n\n";
    let input3 = "From MAILER-DAEMON Mon Jan  6 15:08:02 2014\n\nTest1 message 1 Test2\n\nFrom MAILER-DAEMON Mon Jan  6 15:08:05 2014\n\nTest1 message 2 Test2\n\nFrom MAILER-DAEMON Mon Jan  6 15:08:08 2014\n\nTest1 message 3 Test2\n\n";

    let pong = run_pyzor(&homedir, &["-s", "mbox", "pong"], input3);
    assert!(pong.status.success(), "{pong:?}");
    assert_count_pairs(
        &pong,
        &[
            (isize::MAX as i64, 0),
            (isize::MAX as i64, 0),
            (isize::MAX as i64, 0),
        ],
    );

    let initial_check = run_pyzor(&homedir, &["-s", "mbox", "check"], input3);
    assert!(!initial_check.status.success(), "{initial_check:?}");
    assert_count_pairs(&initial_check, &[(0, 0), (0, 0), (0, 0)]);

    let report = run_pyzor(&homedir, &["-s", "mbox", "report"], input2);
    assert!(report.status.success(), "{report:?}");

    let after_report = run_pyzor(&homedir, &["-s", "mbox", "check"], input3);
    assert!(after_report.status.success(), "{after_report:?}");
    assert_count_pairs(&after_report, &[(1, 0), (1, 0), (0, 0)]);

    let whitelist = run_pyzor(&homedir, &["-s", "mbox", "whitelist"], input3);
    assert!(whitelist.status.success(), "{whitelist:?}");

    let after_whitelist = run_pyzor(&homedir, &["-s", "mbox", "check"], input3);
    assert!(!after_whitelist.status.success(), "{after_whitelist:?}");
    assert_count_pairs(&after_whitelist, &[(1, 1), (1, 1), (0, 1)]);

    server.stop();
    let _ = std::fs::remove_dir_all(homedir);
}

#[test]
fn cli_multiple_servers_match_python_functional_test() {
    let mut servers = [
        TestServer::start("cli-multiple-servers-1"),
        TestServer::start("cli-multiple-servers-2"),
        TestServer::start("cli-multiple-servers-3"),
    ];
    let homedir = temp_dir("cli-multiple-servers-home");
    let servers_file = servers
        .iter()
        .map(|server| format!("127.0.0.1:{}\n", server.port))
        .collect::<String>();
    std::fs::write(homedir.join("servers"), servers_file).unwrap();

    let ping = run_pyzor(&homedir, &["ping"], "");
    assert!(ping.status.success(), "{ping:?}");
    assert_eq!(stdout_lines(&ping).len(), 3);

    let pong = run_pyzor(&homedir, &["pong"], "Test1 multiple pong Test2");
    assert!(pong.status.success(), "{pong:?}");
    assert_count_pairs(
        &pong,
        &[
            (isize::MAX as i64, 0),
            (isize::MAX as i64, 0),
            (isize::MAX as i64, 0),
        ],
    );

    let initial_check = run_pyzor(&homedir, &["check"], "Test1 multiple check Test2");
    assert!(!initial_check.status.success(), "{initial_check:?}");
    assert_count_pairs(&initial_check, &[(0, 0), (0, 0), (0, 0)]);

    let report = run_pyzor(&homedir, &["report"], "Test1 multiple report Test2");
    assert!(report.status.success(), "{report:?}");
    assert_eq!(stdout_lines(&report).len(), 3);

    let after_report = run_pyzor(&homedir, &["check"], "Test1 multiple report Test2");
    assert!(after_report.status.success(), "{after_report:?}");
    assert_count_pairs(&after_report, &[(1, 0), (1, 0), (1, 0)]);

    let whitelist = run_pyzor(&homedir, &["whitelist"], "Test1 multiple whitelist Test2");
    assert!(whitelist.status.success(), "{whitelist:?}");
    assert_eq!(stdout_lines(&whitelist).len(), 3);
    let after_whitelist = run_pyzor(&homedir, &["check"], "Test1 multiple whitelist Test2");
    assert!(!after_whitelist.status.success(), "{after_whitelist:?}");
    assert_count_pairs(&after_whitelist, &[(0, 1), (0, 1), (0, 1)]);

    for server in &mut servers {
        server.stop();
    }
    let _ = std::fs::remove_dir_all(homedir);
}

struct TestServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<pyzor::Result<()>>>,
    db_path: PathBuf,
}

impl TestServer {
    fn start(name: &str) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let db_path = temp_dir(name).join("pyzord.db");
        let db = Arc::new(Mutex::new(FileDatabase::open(&db_path).unwrap()));
        let accounts = Arc::new(HashMap::new());
        let acl = Arc::new(acl(&[
            "report",
            "check",
            "whitelist",
            "info",
            "ping",
            "pong",
        ]));
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            serve_socket_until_shutdown(socket, db, accounts, acl, false, server_shutdown)
        });
        Self {
            port,
            shutdown,
            handle: Some(handle),
            db_path,
        }
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap().unwrap();
        }
        let _ = std::fs::remove_file(&self.db_path);
        if let Some(parent) = self.db_path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn info_record(homedir: &Path, input: &str) -> HashMap<String, String> {
    let info = run_pyzor(homedir, &["info"], input);
    assert!(info.status.success(), "{info:?}");
    parse_info_record(&info)
}

fn spawn_pyzord_process(homedir: &Path, port: u16) -> Child {
    Command::new(env!("CARGO_BIN_EXE_pyzord"))
        .arg("--homedir")
        .arg(homedir)
        .arg("--password-file")
        .arg("pyzord.passwd")
        .arg("--access-file")
        .arg("pyzord.access")
        .arg("--dsn")
        .arg(homedir.join("pyzord.db"))
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Rust pyzord process")
}

fn wait_for_process_server(server: &mut Child, address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), pyzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..50 {
        if let Some(status) = server.try_wait().expect("poll pyzord process") {
            panic!("pyzord exited before readiness: {status}");
        }
        if client
            .ping(address)
            .map(|response| response.is_ok())
            .unwrap_or(false)
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("pyzord did not become ready on {}:{}", address.0, address.1);
}

fn stop_process(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn run_pyzor(homedir: &std::path::Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pyzor"))
        .arg("--homedir")
        .arg(homedir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Rust pyzor client");
    child
        .stdin
        .as_mut()
        .expect("Rust client stdin")
        .write_all(input.as_bytes())
        .expect("write Rust client stdin");
    child.wait_with_output().expect("wait Rust client")
}

fn assert_stdout_contains(output: &Output, expected: &str) {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.contains(expected), "{stdout:?}");
}
fn stdout_lines(output: &Output) -> Vec<String> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn parse_info_record(output: &Output) -> HashMap<String, String> {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (key, value) = line.split_once(": ")?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn assert_count_pairs(output: &Output, expected: &[(i64, i64)]) {
    let pairs = stdout_lines(output)
        .into_iter()
        .map(|line| {
            let parts = line.split('\t').collect::<Vec<_>>();
            assert!(parts.len() >= 4, "unexpected pyzor output line: {line:?}");
            let count = parts[parts.len() - 2].parse::<i64>().unwrap();
            let wl_count = parts[parts.len() - 1].parse::<i64>().unwrap();
            (count, wl_count)
        })
        .collect::<Vec<_>>();
    assert_eq!(pairs, expected);
}

fn acl(ops: &[&str]) -> HashMap<String, HashSet<String>> {
    let mut acl = HashMap::new();
    acl.insert(
        "anonymous".to_string(),
        ops.iter().map(|op| (*op).to_string()).collect(),
    );

    acl
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pyzor-{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}
