# pyzor

[![CI](https://github.com/bonjourservices/pyzor/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjourservices/pyzor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/pyzor.svg)](https://crates.io/crates/pyzor)
[![Docs.rs](https://docs.rs/pyzor/badge.svg)](https://docs.rs/pyzor)
[![GitHub release](https://img.shields.io/github/v/release/bonjourservices/pyzor)](https://github.com/bonjourservices/pyzor/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust implementation of the Pyzor 1.1.2 UDP client and server.

Pyzor is a collaborative, networked spam detection system that identifies messages by digest and lets clients check, report, or whitelist those digests against a Pyzor server. This crate provides the `pyzor` client and `pyzord` daemon as a Rust package with command-line behavior and storage formats compatible with the upstream Pyzor 1.1 documentation.

## Compatibility

This project targets 1:1 observable compatibility with Pyzor 1.1.2 for the client and server CLIs:

- Same UDP protocol shape: RFC-822-style datagrams, `PV: 2.1`, 8192-byte packet limit, thread ids, SHA-1 digests, and SHA-1 request signatures.
- Same client commands: `check`, `info`, `report`, `whitelist`, `ping`, `pong`, `digest`, `predigest`, `genkey`, `local_whitelist`, and `local_unwhitelist`.
- Same input styles: `msg`, `mbox`, and `digests`.
- Same server operations, anonymous access defaults, passwd/access-file semantics, logging behavior, forwarding behavior, and Unix signal handling for graceful shutdown and reload.
- Same backend record formats for GNU gdbm, Redis v1, Redis v0, and MySQL.

Upstream Pyzor documentation is available at <https://www.pyzor.org/en/latest/>. This crate intentionally covers the client/server package surface; it does not ship the Python-only `pyzor-migrate` helper.

## Install

### Prebuilt Binaries

Download release archives from <https://github.com/bonjourservices/pyzor/releases>. Release archives contain `pyzor`, `pyzord`, `README.md`, and `LICENSE` for the target platform. The default release binaries use the GNU gdbm backend and require GNU gdbm at runtime.

### Cargo

Install the full package with the default backends:

```sh
cargo install pyzor --locked
```

The default build includes the GNU gdbm backend, so system GNU gdbm headers/libraries must be available:

```sh
# Debian/Ubuntu
sudo apt-get install libgdbm-dev pkg-config

# macOS/Homebrew
brew install gdbm pkg-config
```

For a build without the gdbm backend:

```sh
cargo install pyzor --no-default-features --features backend-redis,backend-mysql --locked
```

## Quick Start

Create a small test message:

```sh
cat > /tmp/pyzor-msg.eml <<'EOF'
From: a@example.com
To: b@example.com
Subject: test

hello pyzor
EOF
```

Print the Pyzor digest without contacting a server:

```sh
pyzor digest < /tmp/pyzor-msg.eml
```

Start a local server in one terminal:

```sh
mkdir -p /tmp/pyzor-server /tmp/pyzor-client
printf '127.0.0.1:24441\n' > /tmp/pyzor-client/servers
pyzord --homedir /tmp/pyzor-server -a 127.0.0.1 -p 24441
```

Use the client from another terminal:

```sh
pyzor --homedir /tmp/pyzor-client ping
pyzor --homedir /tmp/pyzor-client report < /tmp/pyzor-msg.eml
pyzor --homedir /tmp/pyzor-client check < /tmp/pyzor-msg.eml
pyzor --homedir /tmp/pyzor-client info < /tmp/pyzor-msg.eml
```

Check by digest rather than by message content:

```sh
pyzor digest < /tmp/pyzor-msg.eml > /tmp/pyzor-digest.txt
pyzor --homedir /tmp/pyzor-client -s digests check < /tmp/pyzor-digest.txt
```

## Client Usage

The client reads from stdin for message-oriented commands:

```sh
pyzor [options] command
```

Common commands:

```sh
pyzor digest < message.eml
pyzor predigest < message.eml
pyzor check < message.eml
pyzor report < message.eml
pyzor whitelist < message.eml
pyzor info < message.eml
pyzor ping
pyzor pong < message.eml
pyzor local_whitelist < message.eml
pyzor local_unwhitelist < message.eml
pyzor genkey
```

Useful options:

```sh
--homedir DIR
--servers-file FILE
--accounts-file FILE
--local-whitelist FILE
--log-file FILE
-s, --style msg|mbox|digests
-t, --timeout SECONDS
-r, --report-threshold COUNT
-w, --whitelist-threshold COUNT
-d, --debug
-n, --nice NICE
```

If no server file is configured, Pyzor clients default to the public Pyzor server `public.pyzor.org:24441`, matching upstream Pyzor. Use a local `servers` file for private testing so `report` and `whitelist` do not affect a public server.

## Server Usage

Run a server with the default GNU gdbm backend:

```sh
pyzord --homedir /var/lib/pyzor -a 0.0.0.0 -p 24441
```

Use explicit paths for database, passwd, and ACL files:

```sh
pyzord --homedir /var/lib/pyzor \
  --dsn /var/lib/pyzor/pyzord.db \
  --password-file pyzord.passwd \
  --access-file pyzord.access \
  -a 0.0.0.0 -p 24441
```

Backend examples:

```sh
# Redis v1 hash backend
pyzord -e redis --dsn 127.0.0.1,6379,,0 -a 127.0.0.1 -p 24441

# Legacy Redis v0 string backend
pyzord -e redis_v0 --dsn 127.0.0.1,6379,,0 -a 127.0.0.1 -p 24441

# MySQL backend: host,user,password,database,table
pyzord -e mysql --dsn 127.0.0.1,pyzor,secret,pyzord,digests -a 127.0.0.1 -p 24441
```

The MySQL table must use the upstream Pyzor schema:

```sql
CREATE TABLE digests (
  digest char(40) NOT NULL,
  r_count int(11) DEFAULT NULL,
  wl_count int(11) DEFAULT NULL,
  r_entered datetime DEFAULT NULL,
  wl_entered datetime DEFAULT NULL,
  r_updated datetime DEFAULT NULL,
  wl_updated datetime DEFAULT NULL,
  PRIMARY KEY (digest)
);
```

Operational options:

```sh
pyzord --threads true --max-threads 10 --db-connections 10 -a 127.0.0.1 -p 24441
pyzord --processes true --max-processes 40 -a 127.0.0.1 -p 24441
pyzord --pre-fork 4 -e redis --dsn 127.0.0.1,6379,,0 -a 127.0.0.1 -p 24441
pyzord --detach /var/log/pyzord.out --homedir /var/lib/pyzor
```

On Unix, send `SIGTERM` for graceful shutdown and `SIGUSR1` to reload passwd/access files:

```sh
kill -TERM $(cat /var/lib/pyzor/pyzord.pid)
kill -USR1 $(cat /var/lib/pyzor/pyzord.pid)
```

## Configuration Files

By default, both commands use `~/.pyzor` when `HOME` is set, otherwise `/etc/pyzor`. Paths in config files are resolved relative to `--homedir` unless absolute.

Common files:

- `servers`: one `host:port` server per line for client operations.
- `accounts`: client credentials in upstream Pyzor format.
- `whitelist`: local client whitelist digests.
- `pyzord.passwd`: server account database.
- `pyzord.access`: server ACL file.
- `pyzord.db`: default GNU gdbm digest database.

If no access file exists, anonymous users may `check`, `report`, `ping`, `pong`, and `info`; `whitelist` is denied by default.

## Build From Source

Requirements:

- Rust stable, MSRV `1.95`.
- GNU gdbm development files for the default backend.
- Redis or MySQL only when using those live backends.

Build:

```sh
cargo build --release --locked
```

Run directly from the checkout:

```sh
cargo run --bin pyzor -- digest < message.eml
cargo run --bin pyzord -- --homedir .pyzor -a 127.0.0.1 -p 24441
```

## Test

The normal package test suite is self-contained:

```sh
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
cargo package --locked
```

Optional live backend tests:

```sh
cargo test --test redis_backend -- --ignored --test-threads=1
cargo test --test mysql_docker_backend -- --ignored --test-threads=1
PYZOR_MYSQL_DSN=host,user,password,db,table cargo test --test mysql_backend -- --ignored
cargo test --test gdbm_native_backend -- --test-threads=1
```

## Feature Flags

| Feature | Default | Description |
| --- | --- | --- |
| `backend-gdbm` | yes | GNU gdbm server backend, compatible with Python `dbm.gnu` databases. |
| `backend-gdbm-native` | no | Alias for `backend-gdbm` kept for compatibility with earlier builds. |
| `backend-redis` | yes | Redis v1/v0 server backends. |
| `backend-mysql` | yes | MySQL server backend through the Rust `mysql` crate. |

## Releases

GitHub releases are tag-driven. To cut a release:

```sh
git tag -a v0.1.0 -m 'pyzor v0.1.0'
git push origin v0.1.0
```

The release workflow builds with stable Rust, verifies the crate package, and uploads native binary archives for Linux x64, macOS arm64, and macOS Intel. CI runs on pushes and pull requests with `fmt`, `clippy`, `cargo test`, and `cargo package`.

## License

MIT. See [LICENSE](LICENSE).
