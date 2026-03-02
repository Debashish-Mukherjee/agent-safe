from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ChainVerification:
    valid: bool
    events: int
    checked: int
    last_hash: str
    error: str = ""
    error_index: int = 0


class AuditLedger:
    def __init__(self, audit_dir: str | Path = "audit"):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.audit_dir / "ledger.jsonl"

    def new_request_id(self) -> str:
        return str(uuid.uuid4())

    @staticmethod
    def _hash_payload(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @classmethod
    def _event_hash(cls, event: dict[str, Any]) -> str:
        data = {k: v for k, v in event.items() if k != "chain_hash"}
        return cls._hash_payload(data)

    def _last_known_hash(self) -> str:
        if not self.ledger_path.exists():
            return ""
        last_hash = ""
        for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            stored = event.get("chain_hash")
            if isinstance(stored, str) and stored:
                last_hash = stored
                continue
            last_hash = self._event_hash(event)
        return last_hash

    def write_event(self, event: dict[str, Any]) -> None:
        base_payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        payload = {
            **base_payload,
            "chain_prev_hash": self._last_known_hash(),
        }
        payload["chain_hash"] = self._event_hash(payload)
        with self.ledger_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")

    def verify_chain(self, strict: bool = False) -> ChainVerification:
        if not self.ledger_path.exists():
            return ChainVerification(valid=True, events=0, checked=0, last_hash="")

        lines = self.ledger_path.read_text(encoding="utf-8").splitlines()
        expected_prev = ""
        last_hash = ""
        checked = 0
        for idx, line in enumerate(lines, start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return ChainVerification(
                    valid=False,
                    events=len(lines),
                    checked=checked,
                    last_hash=last_hash,
                    error="json_decode_error",
                    error_index=idx,
                )
            if not isinstance(event, dict):
                return ChainVerification(
                    valid=False,
                    events=len(lines),
                    checked=checked,
                    last_hash=last_hash,
                    error="event_not_object",
                    error_index=idx,
                )

            prev = event.get("chain_prev_hash", "")
            if not isinstance(prev, str):
                prev = ""
            if prev != expected_prev:
                return ChainVerification(
                    valid=False,
                    events=len(lines),
                    checked=checked,
                    last_hash=last_hash,
                    error="prev_hash_mismatch",
                    error_index=idx,
                )

            computed_hash = self._event_hash(event)
            stored_hash = event.get("chain_hash")
            if stored_hash is None:
                if strict:
                    return ChainVerification(
                        valid=False,
                        events=len(lines),
                        checked=checked,
                        last_hash=last_hash,
                        error="missing_chain_hash",
                        error_index=idx,
                    )
                current_hash = computed_hash
            else:
                if not isinstance(stored_hash, str) or not stored_hash:
                    return ChainVerification(
                        valid=False,
                        events=len(lines),
                        checked=checked,
                        last_hash=last_hash,
                        error="invalid_chain_hash",
                        error_index=idx,
                    )
                if stored_hash != computed_hash:
                    return ChainVerification(
                        valid=False,
                        events=len(lines),
                        checked=checked,
                        last_hash=last_hash,
                        error="hash_mismatch",
                        error_index=idx,
                    )
                current_hash = stored_hash

            expected_prev = current_hash
            last_hash = current_hash
            checked += 1

        return ChainVerification(valid=True, events=len(lines), checked=checked, last_hash=last_hash)

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        if not self.ledger_path.exists():
            return []
        lines = self.ledger_path.read_text(encoding="utf-8").splitlines()
        out: list[dict[str, Any]] = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def all_events(self) -> list[dict[str, Any]]:
        if not self.ledger_path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                out.append(event)
        return out
