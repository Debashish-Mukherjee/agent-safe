from __future__ import annotations

import json
from pathlib import Path

from agentsafe.telemetry.exporter import (
    export_ledger_to_elastic,
    export_ledger_to_otel,
    export_ledger_to_sentinel,
    export_ledger_to_splunk,
)


def _write_ledger(tmp_path: Path) -> Path:
    path = tmp_path / "ledger.jsonl"
    entries = [
        {"request_id": "r1", "decision": "ALLOW", "tool": "run"},
        {"request_id": "r2", "decision": "BLOCK", "tool": "fetch"},
    ]
    path.write_text("\n".join(json.dumps(item) for item in entries), encoding="utf-8")
    return path


def test_export_otel_posts_each_event(tmp_path: Path, monkeypatch):
    ledger = _write_ledger(tmp_path)
    calls: list[dict] = []

    class Resp:
        def raise_for_status(self):
            return None

    def fake_post(url, json, timeout):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return Resp()

    monkeypatch.setattr("agentsafe.telemetry.exporter.requests.post", fake_post)
    count = export_ledger_to_otel(ledger_path=ledger, endpoint="http://collector/otel")
    assert count == 2
    assert calls[0]["json"]["event"]["request_id"] == "r1"


def test_export_splunk_sets_auth_header(tmp_path: Path, monkeypatch):
    ledger = _write_ledger(tmp_path)
    calls: list[dict] = []

    class Resp:
        def raise_for_status(self):
            return None

    def fake_post(url, json, headers, timeout):
        calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return Resp()

    monkeypatch.setattr("agentsafe.telemetry.exporter.requests.post", fake_post)
    count = export_ledger_to_splunk(
        ledger_path=ledger,
        endpoint="http://collector/splunk",
        token="token-123",
        index="agentsafe",
    )
    assert count == 2
    assert calls[0]["headers"]["Authorization"] == "Splunk token-123"
    assert calls[0]["json"]["index"] == "agentsafe"


def test_export_elastic_posts_ndjson_bulk(tmp_path: Path, monkeypatch):
    ledger = _write_ledger(tmp_path)
    captured = {}

    class Resp:
        def raise_for_status(self):
            return None

    def fake_post(url, data, headers, timeout):
        captured.update({"url": url, "data": data, "headers": headers, "timeout": timeout})
        return Resp()

    monkeypatch.setattr("agentsafe.telemetry.exporter.requests.post", fake_post)
    count = export_ledger_to_elastic(
        ledger_path=ledger,
        endpoint="http://elastic:9200",
        index="agentsafe-audit",
        api_key="key-123",
    )
    assert count == 2
    assert captured["url"] == "http://elastic:9200/_bulk"
    assert captured["headers"]["Authorization"] == "ApiKey key-123"
    assert b'"_index": "agentsafe-audit"' in captured["data"]


def test_export_sentinel_posts_batch(tmp_path: Path, monkeypatch):
    ledger = _write_ledger(tmp_path)
    captured = {}

    class Resp:
        def raise_for_status(self):
            return None

    def fake_post(url, json, headers, timeout):
        captured.update({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return Resp()

    monkeypatch.setattr("agentsafe.telemetry.exporter.requests.post", fake_post)
    count = export_ledger_to_sentinel(
        ledger_path=ledger,
        endpoint="http://sentinel/ingest",
        shared_key="shared",
        log_type="AgentSafeAudit",
    )
    assert count == 2
    assert captured["headers"]["x-agentsafe-shared-key"] == "shared"
    assert len(captured["json"]) == 2
