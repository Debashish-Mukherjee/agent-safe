from __future__ import annotations

import json

from agentsafe.audit.integrity import append_checkpoint, load_hmac_key, verify_checkpoints
from agentsafe.audit.ledger import AuditLedger


def test_checkpoint_sign_and_verify_current_hash(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSAFE_LEDGER_HMAC_KEY", "test-secret")
    ledger = AuditLedger(audit_dir=tmp_path / "audit")
    ledger.write_event({"request_id": "r1", "actor": "a", "tool": "run", "decision": "ALLOW", "reason": "ok"})
    chain = ledger.verify_chain()
    assert chain.valid is True

    key = load_hmac_key()
    row = append_checkpoint(audit_dir=tmp_path / "audit", ledger_hash=chain.last_hash, key=key, note="nightly")
    assert row["signature"]

    verify = verify_checkpoints(
        audit_dir=tmp_path / "audit",
        key=key,
        expected_ledger_hash=chain.last_hash,
    )
    assert verify.valid is True
    assert verify.checkpoints == 1


def test_checkpoint_verify_detects_tamper(tmp_path):
    ledger = AuditLedger(audit_dir=tmp_path / "audit")
    ledger.write_event({"request_id": "r1", "actor": "a", "tool": "run", "decision": "ALLOW", "reason": "ok"})
    key = b"test-secret"
    append_checkpoint(audit_dir=tmp_path / "audit", ledger_hash=ledger.verify_chain().last_hash, key=key)

    cp = tmp_path / "audit" / "checkpoints.jsonl"
    rows = cp.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(rows[0])
    tampered["ledger_hash"] = "deadbeef"
    rows[0] = json.dumps(tampered, sort_keys=True)
    cp.write_text("\n".join(rows) + "\n", encoding="utf-8")

    verify = verify_checkpoints(audit_dir=tmp_path / "audit", key=key)
    assert verify.valid is False
    assert verify.error == "signature_mismatch"

