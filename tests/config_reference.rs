use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ruzor::config::{
    expand_homefile, load_access_file, load_local_whitelist, load_passwd_file, load_servers,
    read_ini_section,
};

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pyzor-config-{name}-{nanos}"));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn passwd_loading_matches_reference_cases() {
    let dir = temp_dir("passwd");
    let passwd = dir.join("ruzord.passwd");

    assert!(load_passwd_file(dir.join("missing")).is_empty());

    std::fs::write(
        &passwd,
        "alice : alice_key\nbob : bob_key\ninvalid ; key\n# carol : carol_key\n",
    )
    .unwrap();
    assert_eq!(
        load_passwd_file(&passwd),
        HashMap::from([
            ("alice".to_string(), "alice_key".to_string()),
            ("bob".to_string(), "bob_key".to_string()),
        ])
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn access_loading_matches_reference_rule_ordering() {
    let dir = temp_dir("access");
    let access = dir.join("ruzord.access");
    let accounts = HashMap::from([
        ("alice".to_string(), "alice_key".to_string()),
        ("bob".to_string(), "bob_key".to_string()),
    ]);
    let all = HashSet::from([
        "check".to_string(),
        "report".to_string(),
        "ping".to_string(),
        "pong".to_string(),
        "info".to_string(),
        "whitelist".to_string(),
    ]);

    let default_acl = load_access_file(dir.join("missing"), &accounts);
    assert_eq!(
        default_acl["anonymous"],
        HashSet::from([
            "check".to_string(),
            "report".to_string(),
            "ping".to_string(),
            "pong".to_string(),
            "info".to_string(),
        ])
    );

    std::fs::write(
        &access,
        "all : all : allow\nping : bob : deny\ninvalid line\nall : alice : not-allowed\n",
    )
    .unwrap();
    let acl = load_access_file(&access, &accounts);
    assert_eq!(acl["alice"], all);
    let mut bob = all.clone();
    bob.remove("ping");
    assert_eq!(acl["bob"], bob);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn access_loading_matches_reference_empty_and_multi_field_cases() {
    let dir = temp_dir("access-extra");
    let access = dir.join("ruzord.access");
    let accounts = HashMap::from([
        ("alice".to_string(), "alice_key".to_string()),
        ("bob".to_string(), "bob_key".to_string()),
    ]);
    let all = HashSet::from([
        "check".to_string(),
        "report".to_string(),
        "ping".to_string(),
        "pong".to_string(),
        "info".to_string(),
        "whitelist".to_string(),
    ]);

    std::fs::write(&access, "").unwrap();
    assert!(load_access_file(&access, &accounts).is_empty());

    std::fs::write(&access, "all : alice bob: allow\n").unwrap();
    let acl = load_access_file(&access, &accounts);
    assert_eq!(acl["alice"], all);
    assert_eq!(acl["bob"], all);

    std::fs::write(&access, "ping pong : alice: allow\n").unwrap();
    let acl = load_access_file(&access, &accounts);
    assert_eq!(
        acl["alice"],
        HashSet::from(["ping".to_string(), "pong".to_string()])
    );
    assert!(!acl.contains_key("bob"));

    std::fs::write(&access, "all: alice: allow\n# all: bob : allow\n").unwrap();
    let acl = load_access_file(&access, &accounts);
    assert_eq!(acl["alice"], all);
    assert!(!acl.contains_key("bob"));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn servers_loading_matches_reference_defaults_and_comments() {
    let dir = temp_dir("servers");
    let servers = dir.join("servers");

    assert_eq!(
        load_servers(dir.join("missing")),
        vec![("public.pyzor.org".to_string(), 24441)]
    );

    std::fs::write(
        &servers,
        "#ignored.pyzor.org:24441\nrandom.pyzor.org:33544\n127.1.2.45:13587\n",
    )
    .unwrap();
    assert_eq!(
        load_servers(&servers),
        vec![
            ("random.pyzor.org".to_string(), 33544),
            ("127.1.2.45".to_string(), 13587),
        ]
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn local_whitelist_comment_stripping_matches_reference_regex() {
    let dir = temp_dir("local-whitelist");
    let whitelist = dir.join("whitelist");
    std::fs::write(
        &whitelist,
        "# leading comment\nabc # trailing comment\nabc\\# literal\n",
    )
    .unwrap();

    assert_eq!(
        load_local_whitelist(&whitelist),
        HashSet::from([
            "# leading comment".to_string(),
            "abc".to_string(),
            "abc\\# literal".to_string(),
        ])
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ini_option_names_are_loaded_case_insensitively_like_python_configparser() {
    let dir = temp_dir("ini-case");
    let config = dir.join("config");
    std::fs::write(
        &config,
        "[client]
ServersFile = mixed_servers
REPORTTHRESHOLD = 7
",
    )
    .unwrap();

    let values = read_ini_section(&config, "client");

    assert_eq!(
        values.get("serversfile"),
        Some(&"mixed_servers".to_string())
    );
    assert_eq!(values.get("reportthreshold"), Some(&"7".to_string()));
    assert!(!values.contains_key("ServersFile"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn expand_homefile_matches_reference_homedir_rules() {
    let home = PathBuf::from("/home/user/pyzor");

    assert_eq!(
        expand_homefile(&home, "my.file"),
        "/home/user/pyzor/my.file"
    );
    assert_eq!(expand_homefile(&home, ""), "");
    assert_eq!(
        expand_homefile(&home, "/home/user2/pyzor"),
        "/home/user2/pyzor"
    );
    let expected_home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
    assert_eq!(expand_homefile(&home, "~"), expected_home);
}
