from __future__ import annotations

import json

from agentsafe.audit.ledger import AuditLedger


def test_ledger_chain_verifies_after_writes(tmp_path):
    ledger = AuditLedger(audit_dir=tmp_path / "audit")
    ledger.write_event({"request_id": "r1", "actor": "a", "tool": "run", "decision": "ALLOW", "reason": "ok"})
    ledger.write_event({"request_id": "r2", "actor": "a", "tool": "fetch", "decision": "BLOCK", "reason": "deny"})
    result = ledger.verify_chain()
    assert result.valid is True
    assert result.events == 2
    assert result.checked == 2
    assert result.last_hash


def test_ledger_chain_detects_payload_tamper(tmp_path):
    ledger = AuditLedger(audit_dir=tmp_path / "audit")
    ledger.write_event({"request_id": "r1", "actor": "a", "tool": "run", "decision": "ALLOW", "reason": "ok"})
    ledger.write_event({"request_id": "r2", "actor": "a", "tool": "fetch", "decision": "BLOCK", "reason": "deny"})

    lines = ledger.ledger_path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["reason"] = "tampered"
    lines[1] = json.dumps(second, sort_keys=True)
    ledger.ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = ledger.verify_chain()
    assert result.valid is False
    assert result.error == "hash_mismatch"
    assert result.error_index == 2


def test_ledger_chain_detects_prev_hash_mismatch(tmp_path):
    ledger = AuditLedger(audit_dir=tmp_path / "audit")
    ledger.write_event({"request_id": "r1", "actor": "a", "tool": "run", "decision": "ALLOW", "reason": "ok"})
    ledger.write_event({"request_id": "r2", "actor": "a", "tool": "fetch", "decision": "BLOCK", "reason": "deny"})

    lines = ledger.ledger_path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["chain_prev_hash"] = "wrong"
    second["chain_hash"] = ledger._event_hash(second)
    lines[1] = json.dumps(second, sort_keys=True)
    ledger.ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = ledger.verify_chain()
    assert result.valid is False
    assert result.error == "prev_hash_mismatch"
    assert result.error_index == 2


def test_ledger_chain_strict_fails_on_legacy_event_without_chain(tmp_path):
    ledger = AuditLedger(audit_dir=tmp_path / "audit")
    legacy = {
        "timestamp": "2026-03-02T00:00:00+00:00",
        "request_id": "r1",
        "actor": "a",
        "tool": "run",
        "decision": "ALLOW",
        "reason": "ok",
    }
    ledger.ledger_path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    result = ledger.verify_chain(strict=True)
    assert result.valid is False
    assert result.error == "missing_chain_hash"
    assert result.error_index == 1
