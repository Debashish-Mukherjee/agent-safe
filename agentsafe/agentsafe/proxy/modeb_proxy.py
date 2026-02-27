from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urljoin

import requests

from agentsafe.approvals.grants import GrantStore
from agentsafe.audit.ledger import AuditLedger
from agentsafe.integrations.model import ToolAction
from agentsafe.integrations.registry import AdapterFn, get_adapter
from agentsafe.policy.factory import load_backend


@dataclass(slots=True)
class ProxyConfig:
    upstream: str
    policy_path: str
    policy_backend: str
    workspace: str
    path_regexes: list[str]
    adapter: str = "openclaw_generic"
    actor_header: str = "X-Agent-Actor"


@dataclass(slots=True)
class ProxyEvaluation:
    allowed: bool
    reason: str
    rule_id: str
    action: ToolAction


def load_proxy_config() -> ProxyConfig:
    regex_csv = os.environ.get(
        "AGENTSAFE_PROXY_TOOL_PATH_REGEX",
        r"^/v1/tools/execute$,^/gateway/tools/execute$,^/api/tools/.+",
    )
    return ProxyConfig(
        upstream=os.environ.get("AGENTSAFE_UPSTREAM_URL", "http://openclaw:3333"),
        policy_path=os.environ.get("AGENTSAFE_POLICY", "policies/demo-openclaw.yaml"),
        policy_backend=os.environ.get("AGENTSAFE_POLICY_BACKEND", "yaml"),
        workspace=os.environ.get("AGENTSAFE_WORKSPACE", "."),
        path_regexes=[part.strip() for part in regex_csv.split(",") if part.strip()],
        adapter=os.environ.get("AGENTSAFE_PROXY_ADAPTER", "openclaw_generic"),
        actor_header=os.environ.get("AGENTSAFE_ACTOR_HEADER", "X-Agent-Actor"),
    )


def _route_matches(path: str, path_regexes: list[str]) -> bool:
    return any(re.search(pattern, path) for pattern in path_regexes)


def _command_from_action(action: ToolAction) -> list[str]:
    raw = action.args.get("command") or action.args.get("cmd") or []
    if isinstance(raw, list):
        return [str(part) for part in raw]
    return shlex.split(str(raw))


def grant_scope_for_action(action: ToolAction) -> str:
    lowered = action.tool.lower()
    if lowered in {"shell.run", "run", "command"}:
        return f"{action.tool} {shlex.join(_command_from_action(action))}".strip()
    if lowered in {"http.fetch", "fetch", "browser.fetch"}:
        return f"{action.tool} {str(action.args.get('url', ''))}".strip()
    return f"{action.tool} {json.dumps(action.args, sort_keys=True)}"


def is_privileged_action(action: ToolAction) -> bool:
    lowered = action.tool.lower()
    if lowered in {"shell.run", "run", "command"}:
        cmd = _command_from_action(action)
        first = cmd[0] if cmd else ""
        return first in {"curl", "wget", "apt", "apt-get"}
    return lowered in {"http.fetch", "browser.fetch", "fetch"}


def evaluate_action(action: ToolAction, backend, workspace_root: Path) -> ProxyEvaluation:
    lowered = action.tool.lower()

    if lowered in {"shell.run", "run", "command"}:
        cmd = _command_from_action(action)
        if not cmd:
            return ProxyEvaluation(False, "empty command", "proxy_empty_cmd", action)

        decision = backend.evaluate_run(cmd, workspace_root)
        if not decision.allowed:
            return ProxyEvaluation(False, decision.reason, decision.rule_id, action)

        for candidate in [arg for arg in cmd[1:] if "/" in arg or str(arg).startswith(".")]:
            path_decision = backend.evaluate_path(str(candidate), workspace_root)
            if not path_decision.allowed:
                return ProxyEvaluation(False, path_decision.reason, path_decision.rule_id, action)

        return ProxyEvaluation(True, decision.reason, decision.rule_id, action)

    if lowered in {"http.fetch", "fetch", "browser.fetch"}:
        url = str(action.args.get("url", ""))
        decision = backend.evaluate_fetch(url)
        return ProxyEvaluation(decision.allowed, decision.reason, decision.rule_id, action)

    return ProxyEvaluation(False, f"tool not allowlisted at proxy boundary: {action.tool}", "proxy_tool_block", action)


def build_audit_event(eval_result: ProxyEvaluation, config: ProxyConfig, request_id: str) -> dict:
    return {
        "request_id": request_id,
        "actor": eval_result.action.actor,
        "tool": "proxy",
        "args_summary": f"route={eval_result.action.route} tool={eval_result.action.tool}",
        "decision": "ALLOW" if eval_result.allowed else "BLOCK",
        "reason": eval_result.reason,
        "rule_id": eval_result.rule_id,
        "proxy": {
            "route": eval_result.action.route,
            "tool": eval_result.action.tool,
            "args": eval_result.action.args,
            "session_id": eval_result.action.session_id,
            "upstream": config.upstream,
            "policy_backend": config.policy_backend,
            "adapter": config.adapter,
        },
    }


def process_tool_request(
    *,
    path: str,
    payload: dict,
    fallback_actor: str,
    config: ProxyConfig,
    backend,
    grants: GrantStore,
    workspace_root: Path,
    adapter_fn: AdapterFn,
) -> ProxyEvaluation:
    action = adapter_fn(path, payload, fallback_actor)
    evaluation = evaluate_action(action=action, backend=backend, workspace_root=workspace_root)

    if evaluation.allowed and is_privileged_action(action):
        scope = grant_scope_for_action(action)
        if not grants.is_allowed(actor=action.actor, tool=action.tool, scope=scope):
            return ProxyEvaluation(False, "proxy approval grant required", "proxy_approval_required", action)

    return evaluation


class ModeBHandler(BaseHTTPRequestHandler):
    config: ProxyConfig
    backend = None
    ledger: AuditLedger
    grants: GrantStore
    adapter_fn: AdapterFn

    def log_message(self, format: str, *args):
        _ = (format, args)

    def _write_json(self, code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length) if content_length else b"{}"
        generated_request_id = self.ledger.new_request_id()
        actor = self.headers.get(self.config.actor_header, "openclaw-agent")

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            payload = {}

        if _route_matches(self.path, self.config.path_regexes):
            try:
                adapter_fn = self.__class__.adapter_fn
                evaluation = process_tool_request(
                    path=self.path,
                    payload=payload,
                    fallback_actor=actor,
                    config=self.config,
                    backend=self.backend,
                    grants=self.grants,
                    workspace_root=Path(self.config.workspace).resolve(),
                    adapter_fn=adapter_fn,
                )
            except ValueError as exc:
                self._write_json(400, {"error": "bad_request", "reason": str(exc), "request_id": generated_request_id})
                return

            request_id = evaluation.action.request_id or generated_request_id
            self.ledger.write_event(build_audit_event(evaluation, self.config, request_id=request_id))

            if not evaluation.allowed:
                self._write_json(403, {"error": "blocked", "reason": evaluation.reason, "rule_id": evaluation.rule_id, "request_id": request_id})
                return

        upstream_url = urljoin(self.config.upstream.rstrip("/") + "/", self.path.lstrip("/"))
        headers = {k: v for k, v in self.headers.items() if k.lower() not in {"host", "content-length"}}
        try:
            response = requests.post(upstream_url, data=raw_body, headers=headers, timeout=20)
        except requests.RequestException as exc:
            self._write_json(502, {"error": "upstream_unavailable", "reason": str(exc), "request_id": generated_request_id})
            return
        self.send_response(response.status_code)
        for key, value in response.headers.items():
            if key.lower() in {"content-length", "transfer-encoding", "connection"}:
                continue
            self.send_header(key, value)
        body = response.content
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_modeb_proxy(listen_host: str, listen_port: int) -> None:
    config = load_proxy_config()
    backend = load_backend(config.policy_backend, config.policy_path)
    ledger = AuditLedger()
    grants = GrantStore()
    adapter_fn = get_adapter(config.adapter)

    ModeBHandler.config = config
    ModeBHandler.backend = backend
    ModeBHandler.ledger = ledger
    ModeBHandler.grants = grants
    ModeBHandler.adapter_fn = adapter_fn

    server = ThreadingHTTPServer((listen_host, listen_port), ModeBHandler)
    print(f"agentsafe modeb proxy listening on {listen_host}:{listen_port}")
    print(f"upstream={config.upstream} policy={config.policy_path} backend={config.policy_backend} adapter={config.adapter}")
    server.serve_forever()
