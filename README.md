# Ruzor

[![CI](https://github.com/bonjourservices/ruzor/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjourservices/ruzor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/ruzor.svg)](https://crates.io/crates/ruzor)
[![GitHub release](https://img.shields.io/github/v/release/bonjourservices/ruzor)](https://github.com/bonjourservices/ruzor/releases)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

Ruzor is the Rust port of the Pyzor 1.1.2 UDP client and server.

Pyzor is a collaborative, networked spam detection system that identifies messages by digest and lets clients check, report, or whitelist those digests against a Pyzor server. This crate provides the `ruzor` client and `ruzord` daemon as a Rust package with command-line behavior and storage formats compatible with the upstream Pyzor 1.1 documentation.

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

Download release archives from <https://github.com/bonjourservices/ruzor/releases>. Release archives contain `ruzor`, `ruzord`, `README.md`, and `LICENSE` for the target platform. The default release binaries use the GNU gdbm backend and require GNU gdbm at runtime.

### Cargo

Install the full package with the default backends:

```sh
cargo install ruzor --locked
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
cargo install ruzor --no-default-features --features backend-redis,backend-mysql --locked
```

## Quick Start

Create a small test message:

```sh
cat > /tmp/ruzor-msg.eml <<'EOF'
From: a@example.com
To: b@example.com
Subject: test

hello ruzor
EOF
```

Print the Pyzor digest without contacting a server:

```sh
ruzor digest < /tmp/ruzor-msg.eml
```

Start a local server in one terminal:

```sh
mkdir -p /tmp/ruzor-server /tmp/ruzor-client
printf '127.0.0.1:24441\n' > /tmp/ruzor-client/servers
ruzord --homedir /tmp/ruzor-server -a 127.0.0.1 -p 24441
```

Use the client from another terminal:

```sh
ruzor --homedir /tmp/ruzor-client ping
ruzor --homedir /tmp/ruzor-client report < /tmp/ruzor-msg.eml
ruzor --homedir /tmp/ruzor-client check < /tmp/ruzor-msg.eml
ruzor --homedir /tmp/ruzor-client info < /tmp/ruzor-msg.eml
```

Check by digest rather than by message content:

```sh
ruzor digest < /tmp/ruzor-msg.eml > /tmp/ruzor-digest.txt
ruzor --homedir /tmp/ruzor-client -s digests check < /tmp/ruzor-digest.txt
```

## Client Usage

The client reads from stdin for message-oriented commands:

```sh
ruzor [options] command
```

Common commands:

```sh
ruzor digest < message.eml
ruzor predigest < message.eml
ruzor check < message.eml
ruzor report < message.eml
ruzor whitelist < message.eml
ruzor info < message.eml
ruzor ping
ruzor pong < message.eml
ruzor local_whitelist < message.eml
ruzor local_unwhitelist < message.eml
ruzor genkey
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
ruzord --homedir /var/lib/ruzor -a 0.0.0.0 -p 24441
```

Use explicit paths for database, passwd, and ACL files:

```sh
ruzord --homedir /var/lib/ruzor \
  --dsn /var/lib/ruzor/ruzord.db \
  --password-file ruzord.passwd \
  --access-file ruzord.access \
  -a 0.0.0.0 -p 24441
```

Backend examples:

```sh
# Redis v1 hash backend
ruzord -e redis --dsn 127.0.0.1,6379,,0 -a 127.0.0.1 -p 24441

# Legacy Redis v0 string backend
ruzord -e redis_v0 --dsn 127.0.0.1,6379,,0 -a 127.0.0.1 -p 24441

# MySQL backend: host,user,password,database,table
ruzord -e mysql --dsn 127.0.0.1,ruzor,secret,ruzord,digests -a 127.0.0.1 -p 24441
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
ruzord --threads true --max-threads 10 --db-connections 10 -a 127.0.0.1 -p 24441
ruzord --processes true --max-processes 40 -a 127.0.0.1 -p 24441
ruzord --pre-fork 4 -e redis --dsn 127.0.0.1,6379,,0 -a 127.0.0.1 -p 24441
ruzord --detach /var/log/ruzord.out --homedir /var/lib/ruzor
```

On Unix, send `SIGTERM` for graceful shutdown and `SIGUSR1` to reload passwd/access files:

```sh
kill -TERM $(cat /var/lib/ruzor/ruzord.pid)
kill -USR1 $(cat /var/lib/ruzor/ruzord.pid)
```

## Configuration Files

By default, both commands use `~/.ruzor` when `HOME` is set, otherwise `/etc/ruzor`. Paths in config files are resolved relative to `--homedir` unless absolute.

Common files:

- `servers`: one `host:port` server per line for client operations.
- `accounts`: client credentials in upstream Pyzor format.
- `whitelist`: local client whitelist digests.
- `ruzord.passwd`: server account database.
- `ruzord.access`: server ACL file.
- `ruzord.db`: default GNU gdbm digest database.

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
cargo run --bin ruzor -- digest < message.eml
cargo run --bin ruzord -- --homedir .ruzor -a 127.0.0.1 -p 24441
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
git tag -a v0.1.0 -m 'ruzor v0.1.0'
git push origin v0.1.0
```

The release workflow builds with stable Rust, verifies the crate package, and uploads native binary archives for Linux x64, macOS arm64, and macOS Intel. CI runs on pushes and pull requests with `fmt`, `clippy`, `cargo test`, and `cargo package`.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
