use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GDBM_DIR");
    println!("cargo:rerun-if-env-changed=GDBM_HOME");
    println!("cargo:rerun-if-env-changed=GDBM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=HOMEBREW_PREFIX");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    if env::var_os("CARGO_FEATURE_BACKEND_GDBM").is_none() {
        return;
    }

    for lib_dir in gdbm_library_dirs() {
        println!("cargo:rerun-if-changed={}", lib_dir.display());
        if has_gdbm_library(&lib_dir) {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
        }
    }
}

fn gdbm_library_dirs() -> Vec<PathBuf> {
    let mut dirs = BTreeSet::new();

    if let Some(lib_dir) = env_path("GDBM_LIB_DIR") {
        dirs.insert(lib_dir);
    }

    for env_var in ["GDBM_DIR", "GDBM_HOME"] {
        if let Some(root) = env_path(env_var) {
            dirs.insert(root.join("lib"));
        }
    }

    for lib_dir in pkg_config_library_dirs() {
        dirs.insert(lib_dir);
    }

    if target_is_macos() {
        if let Some(homebrew_prefix) = env_path("HOMEBREW_PREFIX") {
            dirs.insert(homebrew_prefix.join("opt").join("gdbm").join("lib"));
        }
        if let Some(homebrew_gdbm_prefix) = homebrew_gdbm_prefix() {
            dirs.insert(homebrew_gdbm_prefix.join("lib"));
        }

        dirs.insert(PathBuf::from("/opt/homebrew/opt/gdbm/lib"));
        dirs.insert(PathBuf::from("/usr/local/opt/gdbm/lib"));
        dirs.insert(PathBuf::from("/opt/local/lib"));
    }

    dirs.into_iter().collect()
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn pkg_config_library_dirs() -> Vec<PathBuf> {
    let Ok(output) = Command::new("pkg-config")
        .args(["--libs-only-L", "gdbm"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|flag| flag.strip_prefix("-L"))
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn target_is_macos() -> bool {
    env::var("CARGO_CFG_TARGET_OS")
        .map(|target_os| target_os == "macos")
        .unwrap_or(false)
}

fn homebrew_gdbm_prefix() -> Option<PathBuf> {
    let output = Command::new("brew")
        .args(["--prefix", "gdbm"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if prefix.is_empty() {
        None
    } else {
        Some(PathBuf::from(prefix))
    }
}

fn has_gdbm_library(dir: &Path) -> bool {
    let Ok(entries) = dir.read_dir() else {
        return false;
    };

    entries.filter_map(Result::ok).any(|entry| {
        entry
            .file_name()
            .to_str()
            .map(|name| {
                matches!(name, "libgdbm.a" | "libgdbm.dylib")
                    || name.starts_with("libgdbm.so")
                    || name.starts_with("libgdbm.")
            })
            .unwrap_or(false)
    })
}
