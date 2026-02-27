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


@dataclass(slots=True)
class ApprovalRequest:
    request_id: str
    actor: str
    tool: str
    scope: str
    reason: str
    created_at: str
    expires_at: str
    status: str = "pending"
    reviewer: str = ""
    reviewed_at: str = ""
    review_note: str = ""
    grant_id: str = ""


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


class ApprovalRequestStore:
    def __init__(self, path: str | Path = "audit/approval_requests.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, event: dict) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")

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

    def _materialize(self) -> dict[str, ApprovalRequest]:
        requests: dict[str, ApprovalRequest] = {}
        for event in self._load_events():
            action = event.get("action")
            if action == "request":
                req = ApprovalRequest(
                    request_id=event["request_id"],
                    actor=event["actor"],
                    tool=event["tool"],
                    scope=event["scope"],
                    reason=event.get("reason", ""),
                    created_at=event["created_at"],
                    expires_at=event["expires_at"],
                )
                requests[req.request_id] = req
                continue
            if action in {"approve", "reject"}:
                req_id = event.get("request_id")
                if not req_id or req_id not in requests:
                    continue
                req = requests[req_id]
                req.status = "approved" if action == "approve" else "rejected"
                req.reviewer = event.get("reviewer", "")
                req.reviewed_at = event.get("reviewed_at", "")
                req.review_note = event.get("reason", "")
                req.grant_id = event.get("grant_id", "")
        return requests

    def create(self, actor: str, tool: str, scope: str, reason: str, ttl_seconds: int = 900) -> ApprovalRequest:
        now = datetime.now(timezone.utc)
        req = ApprovalRequest(
            request_id=str(uuid.uuid4()),
            actor=actor,
            tool=tool,
            scope=scope,
            reason=reason,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
        )
        self._append({"action": "request", **asdict(req)})
        return req

    def list(self, status: str = "all") -> list[ApprovalRequest]:
        items = list(self._materialize().values())
        now = datetime.now(timezone.utc)
        out: list[ApprovalRequest] = []
        for req in items:
            if datetime.fromisoformat(req.expires_at) <= now and req.status == "pending":
                req.status = "expired"
            if status != "all" and req.status != status:
                continue
            out.append(req)
        out.sort(key=lambda x: x.created_at, reverse=True)
        return out

    def approve(
        self,
        request_id: str,
        reviewer: str,
        ttl_seconds: int,
        reason: str,
        grant_store: GrantStore,
    ) -> Grant:
        req = self._materialize().get(request_id)
        if req is None:
            raise ValueError(f"unknown request_id: {request_id}")
        if req.status != "pending":
            raise ValueError(f"request is not pending: {request_id} status={req.status}")
        if datetime.fromisoformat(req.expires_at) <= datetime.now(timezone.utc):
            raise ValueError(f"request expired: {request_id}")

        grant = grant_store.issue(
            actor=req.actor,
            tool=req.tool,
            scope=req.scope,
            ttl_seconds=ttl_seconds,
            reason=reason,
        )
        self._append(
            {
                "action": "approve",
                "request_id": request_id,
                "grant_id": grant.grant_id,
                "reviewer": reviewer,
                "reason": reason,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        return grant

    def reject(self, request_id: str, reviewer: str, reason: str) -> None:
        req = self._materialize().get(request_id)
        if req is None:
            raise ValueError(f"unknown request_id: {request_id}")
        if req.status != "pending":
            raise ValueError(f"request is not pending: {request_id} status={req.status}")
        self._append(
            {
                "action": "reject",
                "request_id": request_id,
                "reviewer": reviewer,
                "reason": reason,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
            }
        )


def render_scope_template(template: str, value: str, tool: str) -> str:
    if template == "run-binary":
        return f"{value} *"
    if template == "run-command":
        return value
    if template == "tool-prefix":
        return f"{tool} {value}*".rstrip()
    if template == "http-domain":
        domain = value.strip().lower()
        return f"http.fetch https://{domain}*"
    raise ValueError(f"unknown template: {template}")
