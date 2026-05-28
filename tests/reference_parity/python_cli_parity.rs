use std::collections::HashMap;
use std::io::Write;
use std::net::UdpSocket;
#[cfg(unix)]
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ruzor::client::Client;
use ruzor::config::Address;

#[cfg(unix)]
const PRIO_PROCESS: c_int = 0;

#[cfg(unix)]
unsafe extern "C" {
    fn getpriority(which: c_int, who: u32) -> c_int;
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn unknown_command_exit_status_matches_python_pyzor_script() {
    let root = temp_dir("unknown-command");
    let python_home = root.join("python");
    let rust_home = root.join("rust");

    let python = run_python_pyzor(&python_home, "unknown_command", "");
    let rust = run_rust_pyzor(&rust_home, "unknown_command", "");

    assert_eq!(python.status.code(), rust.status.code());
    assert!(rust.status.success(), "{rust:?}");
    assert_eq!(python.stdout, rust.stdout);
    assert!(
        String::from_utf8_lossy(&python.stderr).contains("Unknown command: unknown_command"),
        "{python:?}"
    );
    assert!(
        String::from_utf8_lossy(&rust.stderr).contains("Unknown command: unknown_command"),
        "{rust:?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_log_file_records_unknown_command_like_python_script() {
    let root = temp_dir("pyzor-log-file");
    let python_home = root.join("python");
    let rust_home = root.join("rust");

    let python = run_python_pyzor_args(
        &python_home,
        &["--log-file", "client.log", "unknown_command"],
        "",
    );
    let rust = run_rust_pyzor_args(
        &rust_home,
        &["--log-file", "client.log", "unknown_command"],
        "",
    );

    assert_eq!(python.status.code(), rust.status.code());
    assert_eq!(python.stdout, rust.stdout);
    assert_eq!(
        stable_log_text(&python.stderr),
        stable_log_text(&rust.stderr)
    );
    assert_eq!(
        stable_log_text(&python.stderr),
        "CRITICAL Unknown command: unknown_command\n"
    );
    assert_eq!(
        stable_log_file(&python_home.join("client.log")),
        stable_log_file(&rust_home.join("client.log"))
    );
    assert_eq!(
        stable_log_file(&rust_home.join("client.log")),
        "INFO No servers specified, defaulting to public.pyzor.org.\nWARNING No accounts are setup.  All commands will be executed by the anonymous user.\nCRITICAL Unknown command: unknown_command\n"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_log_file_records_invalid_accounts_like_python_script() {
    let root = temp_dir("pyzor-invalid-accounts-log");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();
    let accounts = concat!(
        "public.pyzor.org : 24441 ; test : 123abc,cba321\n",
        "public.pyzor.org : a4441 : test : 123abc,cba321\n",
        "public.pyzor.org : 24441 : test : 123abccba321\n",
        "public.pyzor.org : 24441 : test : ,\n",
        "public2.pyzor.org : 24441 : test2 : 123abc,cba321\n",
    );
    std::fs::write(python_home.join("accounts"), accounts).unwrap();
    std::fs::write(rust_home.join("accounts"), accounts).unwrap();

    let args = [
        "--log-file",
        "client.log",
        "--accounts-file",
        "accounts",
        "unknown_command",
    ];
    let python = run_python_pyzor_args(&python_home, &args, "");
    let rust = run_rust_pyzor_args(&rust_home, &args, "");

    assert_eq!(python.status.code(), rust.status.code());
    assert_eq!(python.stdout, rust.stdout);
    assert_eq!(
        stable_log_text(&python.stderr),
        stable_log_text(&rust.stderr)
    );
    assert_eq!(
        stable_log_file(&python_home.join("client.log")),
        stable_log_file(&rust_home.join("client.log"))
    );
    let expected = concat!(
        "INFO No servers specified, defaulting to public.pyzor.org.\n",
        "WARNING account file: invalid line 0: wrong number of parts\n",
        "WARNING account file: invalid line 1: invalid literal for int() with base 10: 'a4441'\n",
        "WARNING account file: invalid line 2: Invalid number of parts for key; perhaps you forgot the comma at the beginning for the salt divider?\n",
        "WARNING account file: invalid line 3: keystuff can't be all None's\n",
        "CRITICAL Unknown command: unknown_command\n",
    );
    assert_eq!(stable_log_file(&rust_home.join("client.log")), expected);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_local_whitelist_duplicate_logs_like_python_script() {
    let root = temp_dir("pyzor-local-whitelist-duplicate-log");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();

    let digest = "da39a3ee5e6b4b0d3255bfef95601890afd80700\n";
    let args = [
        "--log-file",
        "client.log",
        "-s",
        "digests",
        "local_whitelist",
    ];
    let python_first = run_python_pyzor_args(&python_home, &args, digest);
    let rust_first = run_rust_pyzor_args(&rust_home, &args, digest);

    assert_eq!(python_first.status.code(), rust_first.status.code());
    assert!(rust_first.status.success(), "{rust_first:?}");
    assert_eq!(python_first.stdout, rust_first.stdout);
    assert_eq!(
        stable_log_text(&python_first.stderr),
        stable_log_text(&rust_first.stderr)
    );

    let python = run_python_pyzor_args(&python_home, &args, digest);
    let rust = run_rust_pyzor_args(&rust_home, &args, digest);

    assert_eq!(python.status.code(), rust.status.code());
    assert!(rust.status.success(), "{rust:?}");
    assert_eq!(python.stdout, rust.stdout);
    assert_eq!(
        stable_log_text(&python.stderr),
        stable_log_text(&rust.stderr)
    );
    assert_eq!(
        stable_log_text(&rust.stderr),
        "CRITICAL Digest da39a3ee5e6b4b0d3255bfef95601890afd80700 already whitelisted locally\n"
    );
    assert_eq!(
        stable_log_file(&python_home.join("client.log")),
        stable_log_file(&rust_home.join("client.log"))
    );
    assert!(stable_log_file(&rust_home.join("client.log")).contains(
        "CRITICAL Digest da39a3ee5e6b4b0d3255bfef95601890afd80700 already whitelisted locally\n"
    ));
    assert_eq!(
        std::fs::read_to_string(python_home.join("whitelist")).unwrap(),
        std::fs::read_to_string(rust_home.join("whitelist")).unwrap()
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_local_unwhitelist_missing_logs_like_python_script() {
    let root = temp_dir("pyzor-local-unwhitelist-missing-log");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();

    let digest = "da39a3ee5e6b4b0d3255bfef95601890afd80700\n";
    let args = [
        "--log-file",
        "client.log",
        "-s",
        "digests",
        "local_unwhitelist",
    ];
    let python = run_python_pyzor_args(&python_home, &args, digest);
    let rust = run_rust_pyzor_args(&rust_home, &args, digest);

    assert_eq!(python.status.code(), rust.status.code());
    assert!(rust.status.success(), "{rust:?}");
    assert_eq!(python.stdout, rust.stdout);
    assert_eq!(
        stable_log_text(&python.stderr),
        stable_log_text(&rust.stderr)
    );
    assert_eq!(
        stable_log_text(&rust.stderr),
        "CRITICAL Digest da39a3ee5e6b4b0d3255bfef95601890afd80700 is not whitelisted.\n"
    );
    assert_eq!(
        stable_log_file(&python_home.join("client.log")),
        stable_log_file(&rust_home.join("client.log"))
    );
    assert!(stable_log_file(&rust_home.join("client.log")).contains(
        "CRITICAL Digest da39a3ee5e6b4b0d3255bfef95601890afd80700 is not whitelisted.\n"
    ));
    assert_eq!(
        std::fs::read_to_string(python_home.join("whitelist")).unwrap(),
        std::fs::read_to_string(rust_home.join("whitelist")).unwrap()
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_debug_log_file_records_protocol_packets_like_python_client() {
    let root = temp_dir("pyzor-client-debug-log");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();
    std::fs::write(python_home.join("accounts"), "").unwrap();
    std::fs::write(rust_home.join("accounts"), "").unwrap();

    let mut server = StaticResponseServer::start(StaticResponse::Basic, 2);
    let servers = format!("127.0.0.1:{}\n", server.port);
    std::fs::write(python_home.join("servers"), &servers).unwrap();
    std::fs::write(rust_home.join("servers"), servers).unwrap();
    let args = ["--debug", "--log-file", "client.log", "ping"];

    let python = run_python_pyzor_args(&python_home, &args, "");
    let rust = run_rust_pyzor_args(&rust_home, &args, "");
    server.stop();

    assert_eq!(python.status.code(), rust.status.code());
    assert!(rust.status.success(), "{rust:?}");
    assert_eq!(python.stdout, rust.stdout);
    assert_eq!(
        stable_protocol_debug_log_text(&python.stderr),
        stable_protocol_debug_log_text(&rust.stderr)
    );

    let python_log = stable_protocol_debug_log_file(&python_home.join("client.log"));
    let rust_log = stable_protocol_debug_log_file(&rust_home.join("client.log"));
    assert_eq!(python_log, rust_log);
    assert!(rust_log.contains("DEBUG sending: "));
    assert!(rust_log.contains("Op: ping"));
    assert!(rust_log.contains("Thread: <thread>"));
    assert!(rust_log.contains("Time: <time>"));
    assert!(rust_log.contains("Sig: <sig>"));
    assert!(rust_log.contains("DEBUG received: b"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg(unix)]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzord_nice_option_adjusts_process_priority_like_python_reference() {
    let root = temp_dir("pyzord-nice");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();

    let baseline_priority = process_priority(std::process::id());
    let python_port = free_udp_port();
    let rust_port = free_udp_port();
    let python_address: Address = ("127.0.0.1".to_string(), python_port);
    let rust_address: Address = ("127.0.0.1".to_string(), rust_port);

    let mut python = spawn_python_nice_server(&python_home, python_port);
    wait_for_logged_ping(&mut python, &python_address);
    let python_priority = process_priority(python.id());

    let mut rust = spawn_rust_nice_server(&rust_home, rust_port);
    wait_for_logged_ping(&mut rust, &rust_address);
    let rust_priority = process_priority(rust.id());

    stop(python);
    stop(rust);

    assert_eq!(python_priority, rust_priority);
    if baseline_priority < 19 {
        assert_eq!(rust_priority, baseline_priority + 1);
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzord_log_file_records_missing_passwd_and_access_like_python_script() {
    let root = temp_dir("pyzord-config-log-defaults");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();
    let python_log = python_home.join("pyzord.log");
    let rust_log = rust_home.join("pyzord.log");
    let python_passwd = python_home.join("missing.passwd");
    let python_access = python_home.join("missing.access");
    let port = free_udp_port();
    let address: Address = ("127.0.0.1".to_string(), port);

    let python = run_python_pyzord_config_log(&python_log, &python_passwd, &python_access);
    assert!(python.status.success(), "{python:?}");

    let mut rust = spawn_rust_config_log_server(
        &rust_home,
        port,
        "missing.passwd",
        "missing.access",
        "pyzord.log",
    );
    wait_for_logged_ping(&mut rust, &address);
    stop(rust);

    assert_eq!(stable_log_file(&python_log), stable_log_file(&rust_log));
    assert_eq!(
        stable_log_file(&rust_log),
        "INFO Starting pyzord server.\nINFO Accounts file does not exist - only the anonymous user will be available.\nINFO Using default ACL: the anonymous user may use the check, report, ping and info commands.\n"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzord_log_file_records_invalid_passwd_and_access_like_python_script() {
    let root = temp_dir("pyzord-config-log-invalid");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();
    let python_log = python_home.join("pyzord.log");
    let rust_log = rust_home.join("pyzord.log");
    let passwd_text = "alice ; alice_key\nbob : bob_key\n";
    let access_text = "all : anonymous ; allow\nping : anonymous : allow\n";
    std::fs::write(python_home.join("passwd"), passwd_text).unwrap();
    std::fs::write(rust_home.join("passwd"), passwd_text).unwrap();
    std::fs::write(python_home.join("access"), access_text).unwrap();
    std::fs::write(rust_home.join("access"), access_text).unwrap();
    let port = free_udp_port();
    let address: Address = ("127.0.0.1".to_string(), port);

    let python = run_python_pyzord_config_log(
        &python_log,
        &python_home.join("passwd"),
        &python_home.join("access"),
    );
    assert!(python.status.success(), "{python:?}");

    let mut rust = spawn_rust_config_log_server(&rust_home, port, "passwd", "access", "pyzord.log");
    wait_for_logged_ping(&mut rust, &address);
    stop(rust);

    assert_eq!(stable_log_file(&python_log), stable_log_file(&rust_log));
    assert_eq!(
        stable_log_file(&rust_log),
        "INFO Starting pyzord server.\nWARNING Invalid accounts line: 'alice ; alice_key\\n'\nINFO Accounts: bob\nWARNING Invalid ACL line: 'all : anonymous ; allow\\n'\nINFO ACL: defaultdict(<class 'set'>, {'anonymous': {'ping'}})\n"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzord_usage_log_file_records_ping_like_python_server() {
    let root = temp_dir("pyzord-usage-log");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();

    let python_usage = python_home.join("usage.log");
    let rust_usage = rust_home.join("usage.log");
    let python_port = free_udp_port();
    let rust_port = free_udp_port();
    let python_address: Address = ("127.0.0.1".to_string(), python_port);
    let rust_address: Address = ("127.0.0.1".to_string(), rust_port);

    let mut python = spawn_python_usage_server(&python_home, python_port, &python_usage);
    wait_for_logged_ping(&mut python, &python_address);
    stop(python);

    let mut rust = spawn_rust_usage_server(&rust_home, rust_port, &rust_usage);
    wait_for_logged_ping(&mut rust, &rust_address);
    stop(rust);

    assert_eq!(stable_log_file(&python_usage), stable_log_file(&rust_usage));
    assert_eq!(
        stable_log_file(&rust_usage),
        "INFO anonymous,127.0.0.1,ping,None,200\n"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzord_debug_log_records_request_exchange_like_python_server() {
    let root = temp_dir("pyzord-debug-log");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();

    let python_log = python_home.join("pyzord.log");
    let rust_log = rust_home.join("pyzord.log");
    let python_port = free_udp_port();
    let rust_port = free_udp_port();
    let python_address: Address = ("127.0.0.1".to_string(), python_port);
    let rust_address: Address = ("127.0.0.1".to_string(), rust_port);
    let digest = "2aedaac999d71421c9ee49b9d81f627a7bc570aa";
    let ping_packet = "Op: ping\nThread: 4242\nPV: 2.1\nUser: anonymous\n\n";
    let check_packet =
        format!("Op: check\nThread: 4243\nPV: 2.1\nUser: anonymous\nOp-Digest: {digest}\n\n");

    let mut python = spawn_python_debug_server(&python_home, python_port, &python_log);
    wait_for_raw_response(&mut python, &python_address, ping_packet);
    let python_check = send_raw_packet(&python_address, &check_packet).unwrap();
    stop(python);

    let mut rust = spawn_rust_debug_server(&rust_home, rust_port, &rust_log);
    wait_for_raw_response(&mut rust, &rust_address, ping_packet);
    let rust_check = send_raw_packet(&rust_address, &check_packet).unwrap();
    stop(rust);

    assert_eq!(python_check, rust_check);
    let python_debug = stable_pyzord_debug_exchange_log_file(&python_log);
    let rust_debug = stable_pyzord_debug_exchange_log_file(&rust_log);
    assert_eq!(python_debug, rust_debug);
    assert_eq!(
        rust_debug,
        concat!(
            "DEBUG Received: b'Op: ping\\nThread: 4242\\nPV: 2.1\\nUser: anonymous\\n\\n'\n",
            "DEBUG Got a ping command from 127.0.0.1\n",
            "DEBUG Sending: 'Code: 200\\nDiag: OK\\nPV: 2.1\\nThread: 4242\\n\\n'\n",
            "DEBUG Received: b'Op: check\\nThread: 4243\\nPV: 2.1\\nUser: anonymous\\nOp-Digest: 2aedaac999d71421c9ee49b9d81f627a7bc570aa\\n\\n'\n",
            "DEBUG Got a check command from 127.0.0.1\n",
            "DEBUG Request to check digest 2aedaac999d71421c9ee49b9d81f627a7bc570aa\n",
            "DEBUG Sending: 'Code: 200\\nDiag: OK\\nPV: 2.1\\nThread: 4243\\nCount: 0\\nWL-Count: 0\\n\\n'\n",
        )
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_help_and_unknown_option_match_python_optparse() {
    let root = temp_dir("pyzor-optparse");
    let python_home = root.join("python");
    let rust_home = root.join("rust");

    for args in [&["--help"][..], &["--bogus"][..]] {
        let python = run_python_pyzor_args(&python_home, args, "");
        let rust = run_rust_pyzor_args(&rust_home, args, "");
        assert_eq!(python.status.code(), rust.status.code(), "args={args:?}");
        assert_eq!(python.stdout, rust.stdout, "args={args:?}");
        assert_eq!(python.stderr, rust.stderr, "args={args:?}");
    }
    assert!(!python_home.exists());
    assert!(!rust_home.exists());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzord_help_and_unknown_option_match_python_optparse() {
    let root = temp_dir("pyzord-optparse");
    let python_home = root.join("python");
    let rust_home = root.join("rust");

    for args in [&["--help"][..], &["--bogus"][..]] {
        let python = run_python_pyzord_args(&python_home, args);
        let rust = run_rust_pyzord_args(&rust_home, args);
        assert_eq!(python.status.code(), rust.status.code(), "args={args:?}");
        assert_eq!(python.stdout, rust.stdout, "args={args:?}");
        assert_eq!(python.stderr, rust.stderr, "args={args:?}");
    }
    assert!(!python_home.exists());
    assert!(!rust_home.exists());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzord_threads_and_processes_conflict_matches_python_script() {
    let root = temp_dir("pyzord-thread-process-conflict");
    let python_home = root.join("python");
    let rust_home = root.join("rust");

    let args = &["--threads", "true", "--processes", "true"];
    let python = run_python_pyzord_args(&python_home, args);
    let rust = run_rust_pyzord_args(&rust_home, args);

    assert_eq!(python.status.code(), rust.status.code());
    assert_eq!(rust.status.code(), Some(1));
    assert_eq!(python.stdout, rust.stdout);
    assert_eq!(
        String::from_utf8_lossy(&rust.stdout),
        "You cannot use both processes and threads at the same time\n"
    );
    assert_eq!(python.stderr, rust.stderr);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_optparse_short_attached_values_and_abbreviations_match_python() {
    let root = temp_dir("pyzor-optparse-forms");
    let python_home = root.join("python");
    let rust_home = root.join("rust");

    for (args, input) in [
        (&["-sdigests", "digest"][..], "abc123\n"),
        (&["--sty=digests", "digest"][..], "abc456\n"),
        (&["-tbad", "digest"][..], ""),
        (&["-nbad", "digest"][..], ""),
        (&["--nice=bad", "digest"][..], ""),
        (&["--lo", "x", "digest"][..], ""),
        (&["-d1", "digest"][..], ""),
    ] {
        let python = run_python_pyzor_args(&python_home, args, input);
        let rust = run_rust_pyzor_args(&rust_home, args, input);
        assert_eq!(python.status.code(), rust.status.code(), "args={args:?}");
        assert_eq!(python.stdout, rust.stdout, "args={args:?}");
        assert_eq!(python.stderr, rust.stderr, "args={args:?}");
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzord_optparse_short_attached_values_and_abbreviations_match_python() {
    let root = temp_dir("pyzord-optparse-forms");
    let python_home = root.join("python");
    let rust_home = root.join("rust");

    for args in [
        &["-p12345", "unexpected"][..],
        &["--addr=127.0.0.1", "unexpected"][..],
        &["-pbad"][..],
        &["-nbad"][..],
        &["--nice=bad"][..],
        &["--max", "1"][..],
        &["--db-connections", "bad"][..],
        &["-d1"][..],
    ] {
        let python = run_python_pyzord_args(&python_home, args);
        let rust = run_rust_pyzord_args(&rust_home, args);
        assert_eq!(python.status.code(), rust.status.code(), "args={args:?}");
        assert_eq!(python.stdout, rust.stdout, "args={args:?}");
        assert_eq!(python.stderr, rust.stderr, "args={args:?}");
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_status_and_check_output_match_python_client_runner() {
    let (python_ping, rust_ping) = run_python_and_rust_against_static_server(
        "client-runner-ping",
        StaticResponse::Basic,
        &["ping"],
        "",
    );
    assert_eq!(python_ping.status.code(), rust_ping.status.code());
    assert!(rust_ping.status.success(), "{rust_ping:?}");
    assert_eq!(python_ping.stderr, rust_ping.stderr);
    assert_eq!(python_ping.stdout, rust_ping.stdout);
    let ping_stdout = String::from_utf8(rust_ping.stdout).unwrap();
    assert!(ping_stdout.ends_with("\t(200, 'OK')\n"));

    let (python_check, rust_check) = run_python_and_rust_against_static_server(
        "client-runner-check",
        StaticResponse::Check {
            count: "2",
            wl_count: "1",
        },
        &["-s", "digests", "check"],
        "2aedaac999d71421c9ee49b9d81f627a7bc570aa\n",
    );
    assert_eq!(python_check.status.code(), rust_check.status.code());
    assert_eq!(python_check.stderr, rust_check.stderr);
    assert_eq!(python_check.stdout, rust_check.stdout);
    let check_stdout = String::from_utf8(rust_check.stdout).unwrap();
    assert!(check_stdout.ends_with("\t(200, 'OK')\t2\t1\n"));
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_check_non_ok_response_omits_counts_like_python_client_runner() {
    let (python, rust) = run_python_and_rust_against_static_server(
        "client-runner-check-error",
        StaticResponse::ErrorEchoThread,
        &["-s", "digests", "check"],
        "2aedaac999d71421c9ee49b9d81f627a7bc570aa\n",
    );

    assert_eq!(python.status.code(), rust.status.code());
    assert_eq!(rust.status.code(), Some(1));
    assert_eq!(python.stderr, rust.stderr);
    assert_eq!(python.stdout, rust.stdout);
    let stdout = String::from_utf8(rust.stdout).unwrap();
    assert!(stdout.ends_with("\t(400, 'Bad request: Invalid Protocol Version')\t\n"));
    assert!(!stdout.ends_with("\t0\t0\n"));
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_error_thread_zero_response_matches_python_client_runner() {
    let (python, rust) = run_python_and_rust_against_static_server(
        "client-runner-error-thread-zero",
        StaticResponse::ErrorThreadZero,
        &["ping"],
        "",
    );

    assert_eq!(python.status.code(), rust.status.code());
    assert_eq!(rust.status.code(), Some(1));
    assert_eq!(python.stderr, rust.stderr);
    assert_eq!(python.stdout, rust.stdout);
    let stdout = String::from_utf8(rust.stdout).unwrap();
    assert!(stdout.ends_with("\t(400, 'Bad request: Invalid Protocol Version')\n"));
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_log_file_records_error_thread_warning_like_python_client() {
    let root = temp_dir("pyzor-error-thread-log");
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();
    std::fs::write(python_home.join("accounts"), "").unwrap();
    std::fs::write(rust_home.join("accounts"), "").unwrap();

    let mut server = StaticResponseServer::start(StaticResponse::ErrorThreadZero, 2);
    let servers = format!("127.0.0.1:{}\n", server.port);
    std::fs::write(python_home.join("servers"), &servers).unwrap();
    std::fs::write(rust_home.join("servers"), servers).unwrap();
    let args = ["--log-file", "client.log", "ping"];

    let python = run_python_pyzor_args(&python_home, &args, "");
    let rust = run_rust_pyzor_args(&rust_home, &args, "");
    server.stop();

    assert_eq!(python.status.code(), rust.status.code());
    assert_eq!(rust.status.code(), Some(1));
    assert_eq!(python.stdout, rust.stdout);
    assert_eq!(python.stderr, rust.stderr);

    let python_log = stable_protocol_debug_log_file(&python_home.join("client.log"));
    let rust_log = stable_protocol_debug_log_file(&rust_home.join("client.log"));
    assert_eq!(python_log, rust_log);
    assert_eq!(
        rust_log,
        "WARNING received error thread id 0 (expected <thread>)\n"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_info_zero_timestamps_match_python_client_runner() {
    let response = StaticInfoResponse {
        entered: "1400221786",
        updated: "1400221794",
        wl_entered: "0",
        wl_updated: "0",
        count: "4",
        wl_count: "0",
    };
    let (python, rust) = run_python_and_rust_info_against_static_server(
        "info-zero-timestamps",
        response,
        "2aedaac999d71421c9ee49b9d81f627a7bc570aa\n",
    );

    assert!(python.status.success(), "{python:?}");
    assert!(rust.status.success(), "{rust:?}");
    assert_eq!(python.stderr, rust.stderr);
    assert_eq!(python.stdout, rust.stdout);
    let stdout = String::from_utf8(rust.stdout).unwrap();
    assert!(stdout.contains("\tWL-Entered: Thu Jan  1 00:00:00 1970\n"));
    assert!(stdout.contains("\tWL-Updated: Thu Jan  1 00:00:00 1970\n"));
}

#[test]
#[ignore = "requires the bundled Python reference implementation"]
fn pyzor_info_negative_one_timestamps_match_python_client_runner() {
    let response = StaticInfoResponse {
        entered: "1400221786",
        updated: "1400221794",
        wl_entered: "-1",
        wl_updated: "-1",
        count: "4",
        wl_count: "0",
    };
    let (python, rust) = run_python_and_rust_info_against_static_server(
        "info-never-timestamps",
        response,
        "2aedaac999d71421c9ee49b9d81f627a7bc570aa\n",
    );

    assert!(python.status.success(), "{python:?}");
    assert!(rust.status.success(), "{rust:?}");
    assert_eq!(python.stderr, rust.stderr);
    assert_eq!(python.stdout, rust.stdout);
    let stdout = String::from_utf8(rust.stdout).unwrap();
    assert!(stdout.contains("\tWL-Entered: Never\n"));
    assert!(stdout.contains("\tWL-Updated: Never\n"));
}

fn run_python_pyzor(homedir: &Path, command: &str, input: &str) -> Output {
    run_python_pyzor_args(homedir, &[command], input)
}

fn run_rust_pyzor(homedir: &Path, command: &str, input: &str) -> Output {
    run_rust_pyzor_args(homedir, &[command], input)
}

fn run_python_pyzor_args(homedir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .env("TZ", "UTC")
        .arg("reference/pyzor/scripts/pyzor")
        .arg("--homedir")
        .arg(homedir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Python pyzor");
    child
        .stdin
        .as_mut()
        .expect("Python pyzor stdin")
        .write_all(input.as_bytes())
        .expect("write Python pyzor stdin");
    child.wait_with_output().expect("wait Python pyzor")
}

fn run_rust_pyzor_args(homedir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ruzor"))
        .env("TZ", "UTC")
        .arg("--homedir")
        .arg(homedir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Rust pyzor");
    child
        .stdin
        .as_mut()
        .expect("Rust pyzor stdin")
        .write_all(input.as_bytes())
        .expect("write Rust pyzor stdin");
    child.wait_with_output().expect("wait Rust pyzor")
}

#[derive(Clone, Copy)]
struct StaticInfoResponse {
    entered: &'static str,
    updated: &'static str,
    wl_entered: &'static str,
    wl_updated: &'static str,
    count: &'static str,
    wl_count: &'static str,
}

fn run_python_and_rust_info_against_static_server(
    name: &str,
    response: StaticInfoResponse,
    input: &str,
) -> (Output, Output) {
    run_python_and_rust_against_static_server(
        name,
        StaticResponse::Info(response),
        &["-s", "digests", "info"],
        input,
    )
}

fn run_python_and_rust_against_static_server(
    name: &str,
    response: StaticResponse,
    args: &[&str],
    input: &str,
) -> (Output, Output) {
    let root = temp_dir(name);
    let python_home = root.join("python");
    let rust_home = root.join("rust");
    std::fs::create_dir_all(&python_home).unwrap();
    std::fs::create_dir_all(&rust_home).unwrap();

    let mut server = StaticResponseServer::start(response, 2);
    let servers = format!("127.0.0.1:{}\n", server.port);
    std::fs::write(python_home.join("servers"), &servers).unwrap();
    std::fs::write(rust_home.join("servers"), servers).unwrap();

    let python = run_python_pyzor_args(&python_home, args, input);
    let rust = run_rust_pyzor_args(&rust_home, args, input);
    server.stop();

    let _ = std::fs::remove_dir_all(root);
    (python, rust)
}

#[derive(Clone, Copy)]
enum StaticResponse {
    Basic,
    ErrorEchoThread,
    ErrorThreadZero,
    Check {
        count: &'static str,
        wl_count: &'static str,
    },
    Info(StaticInfoResponse),
}

struct StaticResponseServer {
    port: u16,
    handle: Option<JoinHandle<()>>,
}

impl StaticResponseServer {
    fn start(response: StaticResponse, requests: usize) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; ruzor::MAX_PACKET_SIZE];
            for _ in 0..requests {
                let (len, peer) = socket.recv_from(&mut buf).expect("receive info request");
                let request = String::from_utf8_lossy(&buf[..len]);
                let thread = request
                    .lines()
                    .find_map(|line| line.strip_prefix("Thread: ").map(str::trim))
                    .expect("request thread id");
                let packet = response.packet(thread);
                socket
                    .send_to(packet.as_bytes(), peer)
                    .expect("send info response");
            }
        });
        Self {
            port,
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

impl Drop for StaticResponseServer {
    fn drop(&mut self) {
        self.stop();
    }
}

impl StaticResponse {
    fn packet(self, thread: &str) -> String {
        match self {
            Self::Basic => format!("Code: 200\nDiag: OK\nPV: 2.1\nThread: {thread}\n\n"),
            Self::ErrorEchoThread => format!(
                "Code: 400\nDiag: Bad request: Invalid Protocol Version\nPV: 2.1\nThread: {thread}\n\n"
            ),
            Self::ErrorThreadZero => "Code: 400\nDiag: Bad request: Invalid Protocol Version\nPV: 2.1\nThread: 0\n\n".to_string(),
            Self::Check { count, wl_count } => format!(
                "Code: 200\nDiag: OK\nPV: 2.1\nThread: {thread}\nCount: {count}\nWL-Count: {wl_count}\n\n"
            ),
            Self::Info(info) => format!(
                "Code: 200\nDiag: OK\nPV: 2.1\nThread: {thread}\nEntered: {}\nUpdated: {}\nWL-Entered: {}\nWL-Updated: {}\nCount: {}\nWL-Count: {}\n\n",
                info.entered,
                info.updated,
                info.wl_entered,
                info.wl_updated,
                info.count,
                info.wl_count
            ),
        }
    }
}

const PYTHON_PYZORD_CONFIG_LOG: &str = r#"
import sys
import pyzor.config

log_file = sys.argv[1]
passwd = sys.argv[2]
access = sys.argv[3]
logger = pyzor.config.setup_logging("pyzord", log_file, False)
logger.info("Starting pyzord server.")
accounts = pyzor.config.load_passwd_file(passwd)
pyzor.config.load_access_file(access, accounts)
"#;

const PYTHON_USAGE_SERVER: &str = r#"
import sys
import pyzor.config
import pyzor.server

port = int(sys.argv[1])
passwd = sys.argv[2]
access = sys.argv[3]
usage_log = sys.argv[4]
pyzor.config.setup_logging("pyzord-usage", usage_log, False)
server = pyzor.server.Server(("127.0.0.1", port), {}, passwd, access)
server.serve_forever()
"#;

const PYTHON_DEBUG_SERVER: &str = r#"
import sys
import pyzor.config
import pyzor.server

port = int(sys.argv[1])
passwd = sys.argv[2]
access = sys.argv[3]
log_file = sys.argv[4]
pyzor.config.setup_logging("pyzord", log_file, True)
server = pyzor.server.Server(("127.0.0.1", port), {}, passwd, access)
server.serve_forever()
"#;

const PYTHON_NICE_SERVER: &str = r#"
import os
import sys
import pyzor.server

port = int(sys.argv[1])
passwd = sys.argv[2]
access = sys.argv[3]
os.nice(1)
server = pyzor.server.Server(("127.0.0.1", port), {}, passwd, access)
server.serve_forever()
"#;

fn run_python_pyzord_config_log(log_file: &Path, passwd: &Path, access: &Path) -> Output {
    Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .env("TZ", "UTC")
        .arg("-c")
        .arg(PYTHON_PYZORD_CONFIG_LOG)
        .arg(log_file)
        .arg(passwd)
        .arg(access)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run Python pyzord config logger")
}

fn spawn_rust_config_log_server(
    homedir: &Path,
    port: u16,
    passwd: &str,
    access: &str,
    log_file: &str,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ruzord"))
        .env("TZ", "UTC")
        .arg("--homedir")
        .arg(homedir)
        .arg("--password-file")
        .arg(passwd)
        .arg("--access-file")
        .arg(access)
        .arg("--log-file")
        .arg(log_file)
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
        .expect("spawn Rust config-log pyzord")
}

fn spawn_python_usage_server(homedir: &Path, port: u16, usage_log: &Path) -> Child {
    let passwd = homedir.join("pyzord.passwd");
    let access = homedir.join("pyzord.access");
    std::fs::write(&passwd, "").unwrap();
    std::fs::write(&access, "ALL : anonymous : allow\n").unwrap();
    Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .env("TZ", "UTC")
        .arg("-c")
        .arg(PYTHON_USAGE_SERVER)
        .arg(port.to_string())
        .arg(passwd)
        .arg(access)
        .arg(usage_log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Python usage pyzord")
}

fn spawn_python_debug_server(homedir: &Path, port: u16, log_file: &Path) -> Child {
    let passwd = homedir.join("pyzord.passwd");
    let access = homedir.join("pyzord.access");
    std::fs::write(&passwd, "").unwrap();
    std::fs::write(&access, "ALL : anonymous : allow\n").unwrap();
    Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .env("TZ", "UTC")
        .arg("-c")
        .arg(PYTHON_DEBUG_SERVER)
        .arg(port.to_string())
        .arg(passwd)
        .arg(access)
        .arg(log_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Python debug pyzord")
}

fn spawn_python_nice_server(homedir: &Path, port: u16) -> Child {
    let passwd = homedir.join("pyzord.passwd");
    let access = homedir.join("pyzord.access");
    std::fs::write(&passwd, "").unwrap();
    std::fs::write(&access, "ALL : anonymous : allow\n").unwrap();
    Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .env("TZ", "UTC")
        .arg("-c")
        .arg(PYTHON_NICE_SERVER)
        .arg(port.to_string())
        .arg(passwd)
        .arg(access)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Python nice pyzord")
}

fn spawn_rust_nice_server(homedir: &Path, port: u16) -> Child {
    std::fs::write(homedir.join("pyzord.passwd"), "").unwrap();
    std::fs::write(homedir.join("pyzord.access"), "ALL : anonymous : allow\n").unwrap();
    Command::new(env!("CARGO_BIN_EXE_ruzord"))
        .env("TZ", "UTC")
        .arg("--homedir")
        .arg(homedir)
        .arg("--nice")
        .arg("1")
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
        .expect("spawn Rust nice pyzord")
}

fn spawn_rust_debug_server(homedir: &Path, port: u16, log_file: &Path) -> Child {
    std::fs::write(homedir.join("pyzord.passwd"), "").unwrap();
    std::fs::write(homedir.join("pyzord.access"), "ALL : anonymous : allow\n").unwrap();
    Command::new(env!("CARGO_BIN_EXE_ruzord"))
        .env("TZ", "UTC")
        .arg("--homedir")
        .arg(homedir)
        .arg("--password-file")
        .arg("pyzord.passwd")
        .arg("--access-file")
        .arg("pyzord.access")
        .arg("--dsn")
        .arg(homedir.join("pyzord.db"))
        .arg("--debug")
        .arg("--log-file")
        .arg(log_file)
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Rust debug pyzord")
}

fn spawn_rust_usage_server(homedir: &Path, port: u16, usage_log: &Path) -> Child {
    std::fs::write(homedir.join("pyzord.passwd"), "").unwrap();
    std::fs::write(homedir.join("pyzord.access"), "ALL : anonymous : allow\n").unwrap();
    Command::new(env!("CARGO_BIN_EXE_ruzord"))
        .env("TZ", "UTC")
        .arg("--homedir")
        .arg(homedir)
        .arg("--password-file")
        .arg("pyzord.passwd")
        .arg("--access-file")
        .arg("pyzord.access")
        .arg("--dsn")
        .arg(homedir.join("pyzord.db"))
        .arg("--usage-log-file")
        .arg(usage_log)
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn Rust usage pyzord")
}

fn send_raw_packet(address: &Address, packet: &str) -> std::io::Result<String> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    socket.send_to(packet.as_bytes(), (address.0.as_str(), address.1))?;
    let mut buf = [0u8; ruzor::MAX_PACKET_SIZE];
    let (len, _) = socket.recv_from(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..len]).to_string())
}

fn wait_for_raw_response(server: &mut Child, address: &Address, packet: &str) {
    for _ in 0..50 {
        if let Some(status) = server.try_wait().expect("poll pyzord") {
            panic!("pyzord exited before readiness: {status}");
        }
        match send_raw_packet(address, packet) {
            Ok(_) => return,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("raw pyzord request failed: {error}"),
        }
    }
    panic!("pyzord did not become ready on {}:{}", address.0, address.1);
}

fn wait_for_logged_ping(server: &mut Child, address: &Address) {
    let client = Client::new(HashMap::new(), Some(1), ruzor::digest::DIGEST_SPEC.to_vec());
    for _ in 0..50 {
        if let Some(status) = server.try_wait().expect("poll pyzord") {
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

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn process_priority(pid: u32) -> i32 {
    // SAFETY: getpriority reads the scheduler priority for a child pid owned by this test.
    unsafe { getpriority(PRIO_PROCESS, pid) }
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn stable_log_file(path: &Path) -> String {
    stable_log_text(&std::fs::read(path).unwrap())
}

fn stable_pyzord_debug_exchange_log_file(path: &Path) -> String {
    let text = stable_log_file(path);
    let mut output = text
        .lines()
        .filter(|line| {
            line.starts_with("DEBUG Received:")
                || line.starts_with("DEBUG Got a ")
                || line.starts_with("DEBUG Request ")
                || line.starts_with("DEBUG Sending:")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    output
}

fn stable_protocol_debug_log_file(path: &Path) -> String {
    stable_protocol_debug_log_text(&std::fs::read(path).unwrap())
}

fn stable_protocol_debug_log_text(bytes: &[u8]) -> String {
    let text = stable_log_text(bytes);
    let mut output = text
        .lines()
        .map(stable_protocol_debug_log_line)
        .collect::<Vec<_>>()
        .join("\n");
    if text.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn stable_protocol_debug_log_line(line: &str) -> String {
    let mut line = line.to_string();
    for (header, replacement) in [("Thread", "<thread>"), ("Time", "<time>"), ("Sig", "<sig>")] {
        line = replace_escaped_header_value(line, header, replacement);
    }
    replace_text_between(line, "(expected ", ")", "<thread>")
}

fn replace_text_between(mut line: String, prefix: &str, suffix: &str, replacement: &str) -> String {
    let mut search_start = 0;
    while let Some(relative_start) = line[search_start..].find(prefix) {
        let value_start = search_start + relative_start + prefix.len();
        let Some(relative_end) = line[value_start..].find(suffix) else {
            break;
        };
        let value_end = value_start + relative_end;
        line.replace_range(value_start..value_end, replacement);
        search_start = value_start + replacement.len();
    }
    line
}

fn replace_escaped_header_value(mut line: String, header: &str, replacement: &str) -> String {
    let prefix = format!("{header}: ");
    let mut search_start = 0;
    while let Some(relative_start) = line[search_start..].find(&prefix) {
        let value_start = search_start + relative_start + prefix.len();
        let Some(relative_end) = line[value_start..].find("\\n") else {
            break;
        };
        let value_end = value_start + relative_end;
        line.replace_range(value_start..value_end, replacement);
        search_start = value_start + replacement.len();
    }
    line
}

fn stable_log_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut output = text
        .lines()
        .map(stable_log_line)
        .collect::<Vec<_>>()
        .join("\n");
    if text.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn stable_log_line(line: &str) -> String {
    line.split_once(") ")
        .map(|(_, message)| message.to_string())
        .unwrap_or_else(|| line.to_string())
}

fn run_python_pyzord_args(homedir: &Path, args: &[&str]) -> Output {
    Command::new("/usr/bin/python3")
        .env("PYTHONPATH", "reference/pyzor")
        .arg("reference/pyzor/scripts/pyzord")
        .arg("--homedir")
        .arg(homedir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run Python pyzord")
}

fn run_rust_pyzord_args(homedir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ruzord"))
        .arg("--homedir")
        .arg(homedir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run Rust pyzord")
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "pyzor-python-cli-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
