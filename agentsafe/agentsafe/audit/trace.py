from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any


_PATH_RE = re.compile(r'"([^"]+)"')


def _extract_paths(line: str) -> list[str]:
    out: list[str] = []
    for match in _PATH_RE.finditer(line):
        candidate = match.group(1)
        if candidate.startswith("/") or candidate.startswith("./") or candidate.startswith("../"):
            out.append(candidate)
    return out


def collect_traced_paths(workspace: Path, trace_prefix: str, limit: int = 200) -> list[str]:
    prefix = Path(trace_prefix)
    base = prefix.name
    trace_dir = workspace / prefix.parent
    if not trace_dir.exists():
        return []

    paths: list[str] = []
    seen: set[str] = set()
    for trace_file in sorted(trace_dir.glob(f"{base}*")):
        if not trace_file.is_file():
            continue
        for line in trace_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            for p in _extract_paths(line):
                if p in seen:
                    continue
                seen.add(p)
                paths.append(p)
                if len(paths) >= limit:
                    return paths
    return paths


def _trace_files(workspace: Path, trace_prefix: str) -> list[Path]:
    prefix = Path(trace_prefix)
    trace_dir = workspace / prefix.parent
    if not trace_dir.exists():
        return []
    base = prefix.name
    return sorted([p for p in trace_dir.glob(f"{base}*") if p.is_file()])


def build_trace_attestation(workspace: Path, trace_prefix: str) -> dict[str, object]:
    files = _trace_files(workspace, trace_prefix=trace_prefix)
    if not files:
        return {
            "trace_digest": "",
            "trace_file_count": 0,
            "trace_files": [],
            "trace_bytes": 0,
        }

    hasher = hashlib.sha256()
    total_bytes = 0
    rel_names: list[str] = []
    for trace_file in files:
        rel = trace_file.relative_to(workspace).as_posix()
        rel_names.append(rel)
        content = trace_file.read_bytes()
        total_bytes += len(content)
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(content)
        hasher.update(b"\0")

    return {
        "trace_digest": hasher.hexdigest(),
        "trace_file_count": len(rel_names),
        "trace_files": rel_names,
        "trace_bytes": total_bytes,
    }


def verify_trace_attestations(events: list[dict[str, Any]], workspace_override: str = "") -> dict[str, Any]:
    checked = 0
    ok = 0
    failures: list[dict[str, Any]] = []
    for idx, event in enumerate(events, start=1):
        sandbox = event.get("sandbox")
        if not isinstance(sandbox, dict):
            continue
        if not sandbox.get("trace_files"):
            continue

        checked += 1
        request_id = str(event.get("request_id", ""))
        trace_prefix = str(sandbox.get("trace_prefix", "") or "")
        expected_digest = str(sandbox.get("trace_digest", "") or "")
        workspace_mount = workspace_override or str(sandbox.get("workspace_mount", "") or "")
        if not workspace_mount or not trace_prefix:
            failures.append(
                {
                    "index": idx,
                    "request_id": request_id,
                    "status": "missing_metadata",
                }
            )
            continue

        attestation = build_trace_attestation(Path(workspace_mount), trace_prefix=trace_prefix)
        actual_digest = str(attestation.get("trace_digest", ""))
        if not expected_digest:
            failures.append(
                {
                    "index": idx,
                    "request_id": request_id,
                    "status": "missing_expected_digest",
                }
            )
            continue
        if actual_digest != expected_digest:
            failures.append(
                {
                    "index": idx,
                    "request_id": request_id,
                    "status": "digest_mismatch",
                    "expected": expected_digest,
                    "actual": actual_digest,
                }
            )
            continue
        ok += 1

    return {
        "valid": len(failures) == 0,
        "checked": checked,
        "ok": ok,
        "failed": len(failures),
        "failures": failures,
    }
