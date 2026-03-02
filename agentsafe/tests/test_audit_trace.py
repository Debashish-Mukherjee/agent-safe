from __future__ import annotations

from pathlib import Path

from agentsafe.audit.trace import build_trace_attestation, collect_traced_paths


def test_collect_traced_paths_reads_multiple_trace_files(tmp_path: Path):
    workspace = tmp_path
    trace_dir = workspace / ".agentsafe_trace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    (trace_dir / "req-1.123").write_text(
        'openat(AT_FDCWD, "/etc/ld-musl-x86_64.so.1", O_RDONLY|O_CLOEXEC) = 3\n',
        encoding="utf-8",
    )
    (trace_dir / "req-1.124").write_text(
        'openat(AT_FDCWD, "./README.md", O_RDONLY) = 3\n'
        'newfstatat(AT_FDCWD, "/workspace", 0x7ffe, 0) = 0\n',
        encoding="utf-8",
    )

    paths = collect_traced_paths(workspace, trace_prefix=".agentsafe_trace/req-1")
    assert "/etc/ld-musl-x86_64.so.1" in paths
    assert "./README.md" in paths
    assert "/workspace" in paths


def test_collect_traced_paths_returns_empty_without_trace_dir(tmp_path: Path):
    assert collect_traced_paths(tmp_path, trace_prefix=".agentsafe_trace/missing") == []


def test_trace_attestation_is_stable_and_detects_tamper(tmp_path: Path):
    workspace = tmp_path
    trace_dir = workspace / ".agentsafe_trace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    f1 = trace_dir / "req-2.1"
    f2 = trace_dir / "req-2.2"
    f1.write_text('openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3\n', encoding="utf-8")
    f2.write_text('openat(AT_FDCWD, "./x.txt", O_RDONLY) = 3\n', encoding="utf-8")

    a1 = build_trace_attestation(workspace, trace_prefix=".agentsafe_trace/req-2")
    a2 = build_trace_attestation(workspace, trace_prefix=".agentsafe_trace/req-2")
    assert a1["trace_digest"]
    assert a1["trace_digest"] == a2["trace_digest"]
    assert a1["trace_file_count"] == 2

    f2.write_text('openat(AT_FDCWD, "./y.txt", O_RDONLY) = 3\n', encoding="utf-8")
    a3 = build_trace_attestation(workspace, trace_prefix=".agentsafe_trace/req-2")
    assert a3["trace_digest"] != a1["trace_digest"]
