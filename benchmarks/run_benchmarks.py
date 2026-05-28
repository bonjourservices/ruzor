#!/usr/bin/env python3
"""Local Ruzor/Pyzor benchmark harness.

The script expects:
- Rust release binaries at target/release/ruzor and target/release/ruzord.
- Upstream Pyzor installed with:
  python3 -m pip install --target /tmp/ruzor-bench-pyzor pyzor==1.1.2
- hyperfine available at /opt/homebrew/bin/hyperfine or in PATH.

It writes a JSON result file in a temporary directory and prints a README-ready
summary to stdout.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Optional

DIGEST = "7421216f915a87e02da034cc483f5c876e1a1338"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=Path.cwd(), type=Path)
    parser.add_argument("--python-root", default=Path("/tmp/ruzor-bench-pyzor"), type=Path)
    parser.add_argument("--python-bin", default=sys.executable)
    parser.add_argument(
        "--hyperfine",
        default=shutil.which("hyperfine") or "/opt/homebrew/bin/hyperfine",
    )
    parser.add_argument("--cli-runs", default=80, type=int)
    parser.add_argument("--server-requests", default=10_000, type=int)
    return parser.parse_args()


def human_bytes(size: float) -> str:
    value = float(size)
    for unit in ["B", "KiB", "MiB", "GiB"]:
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value:.0f} B"
        value /= 1024
    return f"{value:.1f} GiB"


def dir_size(path: Path, exclude_pycache: bool) -> int:
    total = 0
    for item in path.rglob("*"):
        if not item.is_file():
            continue
        if exclude_pycache and "__pycache__" in item.parts:
            continue
        total += item.stat().st_size
    return total


def write_python_wrapper(bin_dir: Path, python_bin: Path, python_root: Path, name: str) -> Path:
    wrapper = bin_dir / name
    wrapper.write_text(
        "\n".join(
            [
                f"#!{python_bin}",
                "import runpy",
                "import sys",
                f"sys.path.insert(0, {str(python_root)!r})",
                f"sys.argv[0] = {name!r}",
                f"runpy.run_path({str(python_root / 'bin' / name)!r}, run_name='__main__')",
                "",
            ]
        )
    )
    wrapper.chmod(0o755)
    return wrapper


def run_hyperfine(
    repo_root: Path,
    hyperfine: Path,
    out_dir: Path,
    name: str,
    commands: list[tuple[str, str]],
    runs: int,
    warmup: int,
) -> dict[str, dict[str, float]]:
    out_json = out_dir / f"{name}.json"
    args = [
        str(hyperfine),
        "--warmup",
        str(warmup),
        "--runs",
        str(runs),
        "--export-json",
        str(out_json),
    ]
    for display_name, command in commands:
        args.extend(["--command-name", display_name, command])
    subprocess.run(args, cwd=repo_root, check=True)
    data = json.loads(out_json.read_text())
    return {
        result["command"]: {
            "mean_s": result["mean"],
            "stddev_s": result["stddev"],
            "median_s": result.get("median", result["mean"]),
            "min_s": result["min"],
            "max_s": result["max"],
        }
        for result in data["results"]
    }


def command_text(command: list[str]) -> str:
    return subprocess.check_output(command, stderr=subprocess.STDOUT, text=True).strip()


def resolve_executable(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or path.exists():
        return path.resolve()
    resolved = shutil.which(value)
    if resolved:
        return Path(resolved).resolve()
    return path


def rss_kib(pid: int) -> int:
    output = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
    return int(output.strip())


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def packet(op: str, thread: int, digest: Optional[str] = None) -> bytes:
    headers = [f"Op: {op}", f"Thread: {thread}", "PV: 2.1", "User: anonymous"]
    if digest is not None:
        headers.insert(1, f"Op-Digest: {digest}")
        if op in {"report", "whitelist"}:
            headers.insert(2, "Op-Spec: 2.0")
    return ("\n".join(headers) + "\n\n").encode()


def send_once(port: int, payload: bytes) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(payload, ("127.0.0.1", port))
        data, _ = sock.recvfrom(8192)
        return data
    finally:
        sock.close()


def wait_ready(proc: subprocess.Popen[bytes], port: int) -> None:
    for attempt in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f"server exited early with {proc.returncode}")
        try:
            response = send_once(port, packet("ping", attempt))
            if b"Code: 200" in response:
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server did not become ready")


def latency_bench(port: int, op: str, count: int) -> dict[str, float]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    latencies = []
    try:
        for index in range(200):
            sock.sendto(packet(op, index, DIGEST if op != "ping" else None), ("127.0.0.1", port))
            sock.recvfrom(8192)

        start = time.perf_counter()
        for index in range(count):
            payload = packet(op, index + 1000, DIGEST if op != "ping" else None)
            before = time.perf_counter_ns()
            sock.sendto(payload, ("127.0.0.1", port))
            response, _ = sock.recvfrom(8192)
            after = time.perf_counter_ns()
            if b"Code: 200" not in response:
                raise RuntimeError(f"unexpected response: {response!r}")
            latencies.append((after - before) / 1000.0)
        elapsed = time.perf_counter() - start
    finally:
        sock.close()

    ordered = sorted(latencies)
    return {
        "requests": float(count),
        "elapsed_s": elapsed,
        "rps": count / elapsed,
        "mean_us": statistics.fmean(latencies),
        "p50_us": ordered[int(count * 0.50)],
        "p95_us": ordered[int(count * 0.95)],
        "p99_us": ordered[int(count * 0.99)],
    }


def start_server(
    repo_root: Path,
    bench_dir: Path,
    rust_pyzord: Path,
    python_pyzord: Path,
    kind: str,
    request_count: int,
) -> dict[str, object]:
    home = bench_dir / f"{kind}-server"
    home.mkdir()
    (home / "pyzord.passwd").write_text("")
    (home / "pyzord.access").write_text("ALL : anonymous : allow\n")
    port = free_udp_port()

    if kind == "rust":
        command = [
            str(rust_pyzord),
            "--homedir",
            str(home),
            "--dsn",
            str(home / "pyzord.db"),
            "--password-file",
            "pyzord.passwd",
            "--access-file",
            "pyzord.access",
            "-a",
            "127.0.0.1",
            "-p",
            str(port),
        ]
    else:
        command = [
            str(python_pyzord),
            "--homedir",
            str(home),
            "--dsn",
            str(home / "pyzord.db"),
            "--password-file",
            "pyzord.passwd",
            "--access-file",
            "pyzord.access",
            "-a",
            "127.0.0.1",
            "-p",
            str(port),
        ]

    proc = subprocess.Popen(
        command,
        cwd=repo_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_ready(proc, port)
        time.sleep(0.2)
        idle_rss = rss_kib(proc.pid)

        report_response = send_once(port, packet("report", 900, DIGEST))
        if b"Code: 200" not in report_response:
            raise RuntimeError(f"report failed: {report_response!r}")

        ping = latency_bench(port, "ping", request_count)
        check = latency_bench(port, "check", request_count)
        after_rss = rss_kib(proc.pid)
        return {
            "pid": proc.pid,
            "idle_rss_kib": idle_rss,
            "after_rss_kib": after_rss,
            "ping": ping,
            "check": check,
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def build_inputs(bench_dir: Path) -> tuple[Path, Path, Path]:
    small_msg = bench_dir / "small.eml"
    small_msg.write_text(
        "From: a@example.com\nTo: b@example.com\nSubject: benchmark\n\n"
        "hello ruzor benchmark\n"
    )

    large_msg = bench_dir / "large.eml"
    large_body = "hello benchmark pyzor ruzor spam digest token\n" * 1024
    large_msg.write_text(
        "From: a@example.com\nTo: b@example.com\nSubject: large benchmark\n\n" + large_body
    )

    mbox = bench_dir / "batch.mbox"
    messages = []
    for index in range(100):
        messages.append(
            "From sender@example.com Thu Jan  1 00:00:00 2026\n"
            "From: sender@example.com\n"
            "To: recv@example.com\n"
            f"Subject: batch {index}\n\n"
            f"hello batch message {index} "
            + ("x" * 200)
            + "\n"
        )
    mbox.write_text("\n".join(messages))
    return small_msg, large_msg, mbox


def main() -> None:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    rust_pyzor = repo_root / "target/release/ruzor"
    rust_pyzord = repo_root / "target/release/ruzord"
    python_root = args.python_root.resolve()
    python_bin = resolve_executable(args.python_bin)
    hyperfine = resolve_executable(args.hyperfine)

    if not rust_pyzor.exists() or not rust_pyzord.exists():
        raise SystemExit("release binaries missing; run cargo build --release --locked first")
    if not (python_root / "pyzor").exists():
        raise SystemExit(
            f"upstream Pyzor missing at {python_root}; run "
            "python3 -m pip install --target /tmp/ruzor-bench-pyzor pyzor==1.1.2"
        )
    if not hyperfine.exists():
        raise SystemExit("hyperfine not found")

    bench_dir = Path(tempfile.mkdtemp(prefix="ruzor-bench-"))
    wrappers = bench_dir / "bin"
    wrappers.mkdir()
    python_pyzor = write_python_wrapper(wrappers, python_bin, python_root, "pyzor")
    python_pyzord = write_python_wrapper(wrappers, python_bin, python_root, "pyzord")
    small_msg, large_msg, mbox = build_inputs(bench_dir)
    rust_home = bench_dir / "rust-home"
    python_home = bench_dir / "python-home"
    rust_home.mkdir()
    python_home.mkdir()

    archive_dir = bench_dir / "archive" / "ruzor-local"
    archive_dir.mkdir(parents=True)
    shutil.copy2(rust_pyzor, archive_dir / "ruzor")
    shutil.copy2(rust_pyzord, archive_dir / "ruzord")
    shutil.copy2(repo_root / "README.md", archive_dir / "README.md")
    shutil.copy2(repo_root / "LICENSE", archive_dir / "LICENSE")
    archive = bench_dir / "ruzor-local.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(archive_dir, arcname="ruzor-local")

    rust_version = command_text([str(rust_pyzor), "--version"])
    rustd_version = command_text([str(rust_pyzord), "--version"])
    py_version = command_text([str(python_pyzor), "--version"])
    pyd_version = command_text([str(python_pyzord), "--version"])

    try:
        cpu = subprocess.check_output(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
            text=True,
        ).strip()
    except Exception:
        cpu = platform.processor()

    rust_cmd = str(rust_pyzor)
    python_cmd = str(python_pyzor)
    cli_runs = args.cli_runs

    hyperfine_results = {
        "client_startup_version": run_hyperfine(
            repo_root,
            hyperfine,
            bench_dir,
            "startup",
            [
                ("rust ruzor --version", f"{rust_cmd} --version"),
                ("python pyzor --version", f"{python_cmd} --version"),
            ],
            runs=cli_runs,
            warmup=10,
        ),
        "digest_small_message": run_hyperfine(
            repo_root,
            hyperfine,
            bench_dir,
            "digest-small",
            [
                ("rust digest small", f"{rust_cmd} --homedir {rust_home} digest < {small_msg}"),
                (
                    "python digest small",
                    f"{python_cmd} --homedir {python_home} digest < {small_msg}",
                ),
            ],
            runs=cli_runs,
            warmup=10,
        ),
        "digest_large_message": run_hyperfine(
            repo_root,
            hyperfine,
            bench_dir,
            "digest-large",
            [
                ("rust digest 46KiB", f"{rust_cmd} --homedir {rust_home} digest < {large_msg}"),
                (
                    "python digest 46KiB",
                    f"{python_cmd} --homedir {python_home} digest < {large_msg}",
                ),
            ],
            runs=cli_runs,
            warmup=10,
        ),
        "digest_100_message_mbox": run_hyperfine(
            repo_root,
            hyperfine,
            bench_dir,
            "digest-mbox",
            [
                (
                    "rust digest 100-msg mbox",
                    f"{rust_cmd} --homedir {rust_home} -s mbox digest < {mbox}",
                ),
                (
                    "python digest 100-msg mbox",
                    f"{python_cmd} --homedir {python_home} -s mbox digest < {mbox}",
                ),
            ],
            runs=max(30, cli_runs // 2),
            warmup=8,
        ),
    }

    server_results = {
        "rust": start_server(
            repo_root,
            bench_dir,
            rust_pyzord,
            python_pyzord,
            "rust",
            args.server_requests,
        ),
        "python": start_server(
            repo_root,
            bench_dir,
            rust_pyzord,
            python_pyzord,
            "python",
            args.server_requests,
        ),
    }

    result = {
        "environment": {
            "date": time.strftime("%Y-%m-%d"),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu": cpu,
            "python": subprocess.check_output([str(python_bin), "--version"], text=True).strip(),
            "hyperfine": subprocess.check_output([str(hyperfine), "--version"], text=True).strip(),
            "rust_client": rust_version,
            "rust_server": rustd_version,
            "python_client": py_version,
            "python_server": pyd_version,
        },
        "sizes": {
            "rust_ruzor_bytes": rust_pyzor.stat().st_size,
            "rust_ruzord_bytes": rust_pyzord.stat().st_size,
            "rust_release_archive_bytes": archive.stat().st_size,
            "python_package_bytes_no_pycache": dir_size(python_root, exclude_pycache=True),
            "python_package_bytes_with_pycache": dir_size(python_root, exclude_pycache=False),
        },
        "hyperfine": hyperfine_results,
        "server": server_results,
    }

    output = bench_dir / "benchmark-results.json"
    output.write_text(json.dumps(result, indent=2))

    def speedup(rust_seconds: float, python_seconds: float) -> float:
        return python_seconds / rust_seconds

    print("\n=== BENCHMARK SUMMARY ===")
    print(f"results_json={output}")
    print(f"environment={result['environment']}")
    print("\nSizes:")
    for key, value in result["sizes"].items():
        print(f"  {key}: {human_bytes(value)}")

    print("\nHyperfine means:")
    for group, results in hyperfine_results.items():
        labels = list(results.keys())
        for label in labels:
            item = results[label]
            stddev_s = item["stddev_s"] or 0.0
            print(
                f"  {group} / {label}: "
                f"{item['mean_s'] * 1000:.3f} ms +/- {stddev_s * 1000:.3f} ms"
            )
        if len(labels) == 2:
            rust_label = next(label for label in labels if label.startswith("rust"))
            python_label = next(label for label in labels if label.startswith("python"))
            print(
                "  speedup: "
                f"{speedup(results[rust_label]['mean_s'], results[python_label]['mean_s']):.2f}x"
            )

    print("\nServer RSS and latency:")
    for kind, server in server_results.items():
        print(
            f"  {kind}: idle RSS {server['idle_rss_kib'] / 1024:.2f} MiB, "
            f"after {server['after_rss_kib'] / 1024:.2f} MiB"
        )
        for op in ["ping", "check"]:
            item = server[op]
            print(
                f"    {op}: {item['rps']:.0f} req/s, mean {item['mean_us']:.1f} us, "
                f"p50 {item['p50_us']:.1f} us, p95 {item['p95_us']:.1f} us, "
                f"p99 {item['p99_us']:.1f} us"
            )


if __name__ == "__main__":
    main()
