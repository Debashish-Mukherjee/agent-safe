from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests


def _read_events(ledger_path: str | Path) -> list[dict[str, Any]]:
    path = Path(ledger_path)
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        events.append(json.loads(line))
    return events


def export_ledger_to_otel(ledger_path: str | Path, endpoint: str, timeout: int = 5) -> int:
    events = _read_events(ledger_path)
    count = 0
    for event in events:
        payload = {"event": event}
        response = requests.post(endpoint, json=payload, timeout=timeout)
        response.raise_for_status()
        count += 1
    return count


def export_ledger_to_splunk(
    ledger_path: str | Path,
    endpoint: str,
    token: str,
    index: str = "",
    source: str = "agentsafe",
    sourcetype: str = "agentsafe:json",
    timeout: int = 5,
) -> int:
    events = _read_events(ledger_path)
    headers = {"Authorization": f"Splunk {token}"}
    count = 0
    for event in events:
        payload: dict[str, Any] = {
            "event": event,
            "source": source,
            "sourcetype": sourcetype,
        }
        if index:
            payload["index"] = index
        response = requests.post(endpoint, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()
        count += 1
    return count


def export_ledger_to_elastic(
    ledger_path: str | Path,
    endpoint: str,
    index: str = "agentsafe-audit",
    api_key: str = "",
    timeout: int = 5,
) -> int:
    events = _read_events(ledger_path)
    if not events:
        return 0

    bulk_lines: list[str] = []
    for event in events:
        bulk_lines.append(json.dumps({"index": {"_index": index}}, sort_keys=True))
        bulk_lines.append(json.dumps(event, sort_keys=True))
    body = "\n".join(bulk_lines) + "\n"
    headers = {"Content-Type": "application/x-ndjson"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    response = requests.post(endpoint.rstrip("/") + "/_bulk", data=body.encode("utf-8"), headers=headers, timeout=timeout)
    response.raise_for_status()
    return len(events)


def export_ledger_to_sentinel(
    ledger_path: str | Path,
    endpoint: str,
    shared_key: str,
    log_type: str = "AgentSafeAudit",
    timeout: int = 5,
) -> int:
    events = _read_events(ledger_path)
    if not events:
        return 0

    headers = {
        "Content-Type": "application/json",
        "Log-Type": log_type,
        # Placeholder shared key header for local/custom collectors.
        "x-agentsafe-shared-key": shared_key,
    }
    response = requests.post(endpoint, json=events, headers=headers, timeout=timeout)
    response.raise_for_status()
    return len(events)
