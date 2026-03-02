from __future__ import annotations

from pathlib import Path

from agentsafe.audit.trace import build_trace_attestation, verify_trace_attestations


def _event(workspace: Path, trace_prefix: str, trace_digest: str) -> dict:
    return {
        "request_id": "r1",
        "sandbox": {
            "trace_files": True,
            "trace_prefix": trace_prefix,
            "trace_digest": trace_digest,
            "workspace_mount": str(workspace),
        },
    }


def test_verify_trace_attestations_ok(tmp_path: Path):
    trace_dir = tmp_path / ".agentsafe_trace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    (trace_dir / "req-1.1").write_text('openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3\n', encoding="utf-8")
    att = build_trace_attestation(tmp_path, ".agentsafe_trace/req-1")
    report = verify_trace_attestations([_event(tmp_path, ".agentsafe_trace/req-1", str(att["trace_digest"]))])
    assert report["valid"] is True
    assert report["checked"] == 1
    assert report["ok"] == 1


def test_verify_trace_attestations_detects_mismatch(tmp_path: Path):
    trace_dir = tmp_path / ".agentsafe_trace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    (trace_dir / "req-2.1").write_text('openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3\n', encoding="utf-8")
    report = verify_trace_attestations([_event(tmp_path, ".agentsafe_trace/req-2", "wrong-digest")])
    assert report["valid"] is False
    assert report["failed"] == 1
    assert report["failures"][0]["status"] == "digest_mismatch"
