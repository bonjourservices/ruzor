use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::ANONYMOUS_USER;
use crate::account::{Account, key_from_hexstr};
use crate::logging::Logger;
use crate::python_repr;

pub type Address = (String, u16);

const ALL_OPS: [&str; 6] = ["check", "report", "ping", "pong", "info", "whitelist"];
const DEFAULT_ANON_OPS: [&str; 5] = ["check", "report", "ping", "pong", "info"];

pub fn load_passwd_file(path: impl AsRef<Path>) -> HashMap<String, String> {
    load_passwd_file_with_logger(path, None)
}

pub fn load_passwd_file_with_logger(
    path: impl AsRef<Path>,
    logger: Option<&Logger>,
) -> HashMap<String, String> {
    let path = path.as_ref();
    let Ok(text) = fs::read_to_string(path) else {
        if let Some(logger) = logger {
            logger
                .info("Accounts file does not exist - only the anonymous user will be available.");
        }
        return HashMap::new();
    };
    let mut accounts = HashMap::new();
    let mut account_names = Vec::new();
    for line in py_lines(&text) {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split(':').collect();
        if parts.len() != 2 {
            if let Some(logger) = logger {
                logger.warning(format!(
                    "Invalid accounts line: {}",
                    python_repr::text(line)
                ));
            }
            continue;
        }
        let user = parts[0].trim().to_string();
        let key = parts[1].trim().to_string();
        if !accounts.contains_key(&user) {
            account_names.push(user.clone());
        }
        if let Some(logger) = logger {
            logger.debug(format!("Creating an account for {user} with key {key}."));
        }
        accounts.insert(user, key);
    }
    if let Some(logger) = logger {
        logger.info(format!("Accounts: {}", account_names.join(",")));
    }
    accounts
}

pub fn load_access_file(
    path: impl AsRef<Path>,
    accounts: &HashMap<String, String>,
) -> HashMap<String, HashSet<String>> {
    load_access_file_with_logger(path, accounts, None)
}

pub fn load_access_file_with_logger(
    path: impl AsRef<Path>,
    accounts: &HashMap<String, String>,
    logger: Option<&Logger>,
) -> HashMap<String, HashSet<String>> {
    let path = path.as_ref();
    let Ok(text) = fs::read_to_string(path) else {
        if let Some(logger) = logger {
            logger.info(
                "Using default ACL: the anonymous user may use the check, report, ping and info commands.",
            );
        }
        let mut acl = HashMap::new();
        acl.insert(
            ANONYMOUS_USER.to_string(),
            DEFAULT_ANON_OPS
                .iter()
                .map(|op| (*op).to_string())
                .collect(),
        );
        return acl;
    };

    let mut acl: HashMap<String, HashSet<String>> = HashMap::new();
    for line in py_lines(&text) {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line
            .split(':')
            .map(|part| part.trim().to_lowercase())
            .collect();
        if parts.len() != 3 {
            if let Some(logger) = logger {
                logger.warning(format!("Invalid ACL line: {}", python_repr::text(line)));
            }
            continue;
        }
        let allowed = match parts[2].as_str() {
            "allow" => true,
            "deny" => false,
            _ => {
                if let Some(logger) = logger {
                    logger.warning(format!("Invalid ACL line: {}", python_repr::text(line)));
                }
                continue;
            }
        };
        let operations: Vec<String> = if parts[0] == "all" {
            ALL_OPS.iter().map(|op| (*op).to_string()).collect()
        } else {
            parts[0].split_whitespace().map(str::to_string).collect()
        };
        let users: Vec<String> = if parts[1] == "all" {
            account_names(accounts)
        } else {
            parts[1].split_whitespace().map(str::to_string).collect()
        };
        for user in users {
            if let Some(logger) = logger {
                let action = if allowed { "Granting" } else { "Revoking" };
                logger.debug(format!("{action} {} to {user}.", operations.join(",")));
            }
            let entry = acl.entry(user).or_default();
            if allowed {
                entry.extend(operations.iter().cloned());
            } else {
                for op in &operations {
                    entry.remove(op);
                }
            }
        }
    }
    if let Some(logger) = logger {
        logger.info(format!("ACL: {}", python_acl_repr(&acl)));
    }
    acl
}
pub fn load_accounts(path: impl AsRef<Path>) -> HashMap<Address, Account> {
    load_accounts_with_logger(path, None)
}

pub fn load_accounts_with_logger(
    path: impl AsRef<Path>,
    logger: Option<&Logger>,
) -> HashMap<Address, Account> {
    let path = path.as_ref();
    let Ok(text) = fs::read_to_string(path) else {
        if let Some(logger) = logger {
            logger.warning(
                "No accounts are setup.  All commands will be executed by the anonymous user.",
            );
        }
        return HashMap::new();
    };
    let mut accounts = HashMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split(':').map(str::trim).collect();
        if parts.len() != 4 {
            if let Some(logger) = logger {
                logger.warning(format!(
                    "account file: invalid line {lineno}: wrong number of parts"
                ));
            }
            continue;
        }
        let Ok(port) = parts[1].parse::<u16>() else {
            if let Some(logger) = logger {
                logger.warning(format!(
                    "account file: invalid line {lineno}: invalid literal for int() with base 10: '{}'",
                    parts[1]
                ));
            }
            continue;
        };
        let (salt, key) = match key_from_hexstr(parts[3]) {
            Ok(keystuff) => keystuff,
            Err(error) => {
                if let Some(logger) = logger {
                    logger.warning(format!("account file: invalid line {lineno}: {error}"));
                }
                continue;
            }
        };
        if salt.is_empty() && key.is_empty() {
            if let Some(logger) = logger {
                logger.warning(format!(
                    "account file: invalid line {lineno}: keystuff can't be all None's"
                ));
            }
            continue;
        }
        accounts.insert(
            (parts[0].to_string(), port),
            Account::new(parts[2], Some(salt), key),
        );
    }
    accounts
}
pub fn load_servers(path: impl AsRef<Path>) -> Vec<Address> {
    let mut servers = Vec::new();
    if let Ok(text) = fs::read_to_string(path) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((host, port)) = line.rsplit_once(':') else {
                continue;
            };
            if host.is_empty()
                || !host
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ".-".contains(ch))
            {
                continue;
            }
            if let Ok(port) = port.parse::<u16>() {
                servers.push((host.to_string(), port));
            }
        }
    }
    if servers.is_empty() {
        servers.push(("public.pyzor.org".to_string(), 24441));
    }
    servers
}

pub fn load_local_whitelist(path: impl AsRef<Path>) -> HashSet<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return HashSet::new();
    };
    let mut whitelist = HashSet::new();
    for line in text.lines() {
        let line = strip_comment(line).trim();
        if !line.is_empty() {
            whitelist.insert(line.to_string());
        }
    }
    whitelist
}

pub fn write_local_whitelist(
    path: impl AsRef<Path>,
    values: &HashSet<String>,
) -> std::io::Result<()> {
    let mut values: Vec<_> = values.iter().cloned().collect();
    values.sort();
    fs::write(path, values.join("\n"))
}

pub fn expand_homefile(homedir: impl AsRef<Path>, value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let expanded = if value == "~" {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("~"))
    } else if let Some(rest) = value.strip_prefix("~/") {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("~"))
            .join(rest)
    } else {
        PathBuf::from(value)
    };
    if expanded.is_absolute() {
        expanded.to_string_lossy().to_string()
    } else {
        homedir
            .as_ref()
            .join(expanded)
            .to_string_lossy()
            .to_string()
    }
}

pub fn read_ini_section(path: impl AsRef<Path>, section: &str) -> HashMap<String, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    let mut current = String::new();
    let mut values = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].trim().to_lowercase();
            continue;
        }
        if current != section.to_lowercase() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    values
}

fn py_lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

fn account_names(accounts: &HashMap<String, String>) -> Vec<String> {
    let mut names: Vec<_> = accounts.keys().cloned().collect();
    names.sort();
    names
}

fn python_acl_repr(acl: &HashMap<String, HashSet<String>>) -> String {
    let mut users: Vec<_> = acl.keys().collect();
    users.sort();
    let entries = users
        .into_iter()
        .map(|user| {
            let mut ops: Vec<_> = acl[user].iter().collect();
            ops.sort();
            let ops = ops
                .into_iter()
                .map(|op| format!("'{}'", python_repr::single_quoted(op)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("'{}': {{{}}}", python_repr::single_quoted(user), ops)
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("defaultdict(<class 'set'>, {{{entries}}})")
}

fn strip_comment(line: &str) -> &str {
    for (index, ch) in line.char_indices() {
        if ch == '#' && index > 0 && !line[..index].ends_with('\\') {
            return &line[..index];
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{load_access_file, load_servers};

    #[test]
    fn default_servers() {
        assert_eq!(
            load_servers("/path/that/does/not/exist"),
            vec![("public.pyzor.org".to_string(), 24441)]
        );
    }

    #[test]
    fn default_acl() {
        let acl = load_access_file("/path/that/does/not/exist", &HashMap::new());
        assert!(acl["anonymous"].contains("check"));
        assert!(!acl["anonymous"].contains("whitelist"));
    }
}
