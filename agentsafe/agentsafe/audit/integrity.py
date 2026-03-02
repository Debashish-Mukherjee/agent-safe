from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_CHECKPOINT_FILE = "checkpoints.jsonl"


@dataclass(slots=True)
class CheckpointVerification:
    valid: bool
    checkpoints: int
    checked: int
    last_signed_hash: str
    error: str = ""
    error_index: int = 0


def _canonical_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signature(payload: dict[str, object], key: bytes) -> str:
    return hmac.new(key, _canonical_bytes(payload), hashlib.sha256).hexdigest()


def load_hmac_key(key_file: str = "", env_var: str = "AGENTSAFE_LEDGER_HMAC_KEY") -> bytes:
    if key_file:
        value = Path(key_file).read_text(encoding="utf-8").strip()
        if value:
            return value.encode("utf-8")
        raise ValueError(f"empty key file: {key_file}")
    env_value = os.environ.get(env_var, "").strip()
    if env_value:
        return env_value.encode("utf-8")
    raise ValueError(f"missing HMAC key: provide --key-file or set {env_var}")


def append_checkpoint(
    *,
    audit_dir: str | Path,
    ledger_hash: str,
    key: bytes,
    note: str = "",
    checkpoint_file: str = DEFAULT_CHECKPOINT_FILE,
) -> dict[str, object]:
    if not ledger_hash:
        raise ValueError("ledger hash is empty")
    checkpoint_path = Path(audit_dir) / checkpoint_file
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ledger_hash": ledger_hash,
        "note": note,
        "algorithm": "hmac-sha256",
    }
    payload["signature"] = _signature(payload, key)
    with checkpoint_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")
    return payload


def verify_checkpoints(
    *,
    audit_dir: str | Path,
    key: bytes,
    expected_ledger_hash: str = "",
    checkpoint_file: str = DEFAULT_CHECKPOINT_FILE,
) -> CheckpointVerification:
    checkpoint_path = Path(audit_dir) / checkpoint_file
    if not checkpoint_path.exists():
        if expected_ledger_hash:
            return CheckpointVerification(
                valid=False,
                checkpoints=0,
                checked=0,
                last_signed_hash="",
                error="checkpoint_missing",
                error_index=0,
            )
        return CheckpointVerification(valid=True, checkpoints=0, checked=0, last_signed_hash="")

    lines = checkpoint_path.read_text(encoding="utf-8").splitlines()
    checked = 0
    last_signed_hash = ""
    for idx, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return CheckpointVerification(
                valid=False,
                checkpoints=len(lines),
                checked=checked,
                last_signed_hash=last_signed_hash,
                error="json_decode_error",
                error_index=idx,
            )
        if not isinstance(row, dict):
            return CheckpointVerification(
                valid=False,
                checkpoints=len(lines),
                checked=checked,
                last_signed_hash=last_signed_hash,
                error="checkpoint_not_object",
                error_index=idx,
            )

        signature = row.get("signature")
        if not isinstance(signature, str) or not signature:
            return CheckpointVerification(
                valid=False,
                checkpoints=len(lines),
                checked=checked,
                last_signed_hash=last_signed_hash,
                error="missing_signature",
                error_index=idx,
            )
        material = {k: v for k, v in row.items() if k != "signature"}
        if _signature(material, key) != signature:
            return CheckpointVerification(
                valid=False,
                checkpoints=len(lines),
                checked=checked,
                last_signed_hash=last_signed_hash,
                error="signature_mismatch",
                error_index=idx,
            )
        ledger_hash = row.get("ledger_hash", "")
        if isinstance(ledger_hash, str):
            last_signed_hash = ledger_hash
        checked += 1

    if expected_ledger_hash and expected_ledger_hash != last_signed_hash:
        return CheckpointVerification(
            valid=False,
            checkpoints=len(lines),
            checked=checked,
            last_signed_hash=last_signed_hash,
            error="ledger_hash_mismatch",
            error_index=len(lines),
        )

    return CheckpointVerification(
        valid=True,
        checkpoints=len(lines),
        checked=checked,
        last_signed_hash=last_signed_hash,
    )
