from __future__ import annotations

import fnmatch
import json
import uuid
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(slots=True)
class Grant:
    grant_id: str
    actor: str
    tool: str
    scope: str
    reason: str
    created_at: str
    expires_at: str


class GrantStore:
    def __init__(self, path: str | Path = "audit/grants.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, event: dict) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")

    def issue(self, actor: str, tool: str, scope: str, ttl_seconds: int, reason: str) -> Grant:
        now = datetime.now(timezone.utc)
        grant = Grant(
            grant_id=str(uuid.uuid4()),
            actor=actor,
            tool=tool,
            scope=scope,
            reason=reason,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
        )
        self._append({"action": "issue", **asdict(grant)})
        return grant

    def revoke(self, grant_id: str, reason: str = "manual revoke") -> None:
        self._append(
            {
                "action": "revoke",
                "grant_id": grant_id,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def _load_events(self) -> list[dict]:
        if not self.path.exists():
            return []
        events: list[dict] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def active_grants(self) -> list[Grant]:
        events = self._load_events()
        revoked = {event.get("grant_id") for event in events if event.get("action") == "revoke"}
        out: list[Grant] = []
        now = datetime.now(timezone.utc)
        for event in events:
            if event.get("action") != "issue":
                continue
            if event.get("grant_id") in revoked:
                continue
            expires = datetime.fromisoformat(event["expires_at"])
            if expires <= now:
                continue
            out.append(
                Grant(
                    grant_id=event["grant_id"],
                    actor=event["actor"],
                    tool=event["tool"],
                    scope=event["scope"],
                    reason=event.get("reason", ""),
                    created_at=event["created_at"],
                    expires_at=event["expires_at"],
                )
            )
        return out

    def is_allowed(self, actor: str, tool: str, scope: str) -> bool:
        for grant in self.active_grants():
            actor_ok = grant.actor in {actor, "*"}
            tool_ok = grant.tool in {tool, "*"}
            scope_ok = fnmatch.fnmatch(scope, grant.scope)
            if actor_ok and tool_ok and scope_ok:
                return True
        return False
