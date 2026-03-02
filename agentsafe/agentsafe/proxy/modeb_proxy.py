from __future__ import annotations

import json
import os
import re
import shlex
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from urllib.parse import urljoin

import requests

from agentsafe.approvals.grants import GrantStore
from agentsafe.audit.ledger import AuditLedger
from agentsafe.integrations.model import ToolAction
from agentsafe.integrations.registry import AdapterFn, get_adapter
from agentsafe.policy.factory import load_backend
from agentsafe.policy.profiles import PolicyProfileError, resolve_policy_profile
from agentsafe.policy.evaluate import evaluate_fetch_request
from agentsafe.policy.output_controls import deterministic_jitter_ms
from agentsafe.policy.rbac import RbacPolicy, RbacPolicyError, is_tool_allowed, load_rbac_policy


@dataclass(slots=True)
class ProxyConfig:
    upstream: str
    policy_path: str
    policy_backend: str
    workspace: str
    path_regexes: list[str]
    tool_methods: list[str]
    adapter: str = "openclaw_auto"
    actor_header: str = "X-Agent-Actor"
    team_header: str = "X-Agent-Team"
    profile_header: str = "X-Agent-Profile"
    rbac_path: str = ""
    profiles_path: str = ""


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
    method_csv = os.environ.get("AGENTSAFE_PROXY_TOOL_METHODS", "POST,PUT,PATCH")
    return ProxyConfig(
        upstream=os.environ.get("AGENTSAFE_UPSTREAM_URL", "http://openclaw:3333"),
        policy_path=os.environ.get("AGENTSAFE_POLICY", "policies/demo-openclaw.yaml"),
        policy_backend=os.environ.get("AGENTSAFE_POLICY_BACKEND", "yaml"),
        workspace=os.environ.get("AGENTSAFE_WORKSPACE", "."),
        path_regexes=[part.strip() for part in regex_csv.split(",") if part.strip()],
        tool_methods=[part.strip().upper() for part in method_csv.split(",") if part.strip()],
        adapter=os.environ.get("AGENTSAFE_PROXY_ADAPTER", "openclaw_auto"),
        actor_header=os.environ.get("AGENTSAFE_ACTOR_HEADER", "X-Agent-Actor"),
        team_header=os.environ.get("AGENTSAFE_TEAM_HEADER", "X-Agent-Team"),
        profile_header=os.environ.get("AGENTSAFE_PROFILE_HEADER", "X-Agent-Profile"),
        rbac_path=os.environ.get("AGENTSAFE_RBAC_POLICY", ""),
        profiles_path=os.environ.get("AGENTSAFE_PROXY_PROFILES_PATH", ""),
    )


def _route_matches(path: str, path_regexes: list[str]) -> bool:
    return any(re.search(pattern, path) for pattern in path_regexes)


def _method_matches(method: str, allowed_methods: list[str]) -> bool:
    return method.upper() in {m.upper() for m in allowed_methods}


def should_inspect_tool_call(method: str, path: str, config: ProxyConfig) -> bool:
    return _method_matches(method, config.tool_methods) and _route_matches(path, config.path_regexes)


def forward_upstream(method: str, url: str, headers: dict[str, str], raw_body: bytes):
    return requests.request(method=method, url=url, data=raw_body, headers=headers, timeout=20, stream=True)


def relay_upstream_response(
    handler: BaseHTTPRequestHandler,
    response,
    *,
    max_bytes: int = 0,
    min_delay_ms: int = 0,
    jitter_ms: int = 0,
    jitter_seed: str = "",
) -> None:
    delay_ms = max(0, min_delay_ms) + deterministic_jitter_ms(jitter_seed, max(0, jitter_ms))
    if delay_ms:
        time.sleep(delay_ms / 1000.0)

    handler.send_response(response.status_code)
    for key, value in response.headers.items():
        if key.lower() in {"content-length", "transfer-encoding", "connection"}:
            continue
        handler.send_header(key, value)
    handler.end_headers()
    remaining = max_bytes if max_bytes > 0 else None
    try:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if chunk:
                if remaining is not None:
                    if remaining <= 0:
                        break
                    if len(chunk) > remaining:
                        chunk = chunk[:remaining]
                    remaining -= len(chunk)
                handler.wfile.write(chunk)
    finally:
        response.close()


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
        policy = getattr(backend, "policy", None)
        if policy is not None:
            method = str(action.args.get("method", "GET") or "GET")
            parsed = urlparse(url)
            path = parsed.path or "/"
            headers_raw = action.args.get("headers", {})
            headers = {str(k): str(v) for k, v in headers_raw.items()} if isinstance(headers_raw, dict) else {}
            body_raw = action.args.get("body", action.args.get("data", ""))
            if isinstance(body_raw, (dict, list)):
                body = json.dumps(body_raw, sort_keys=True)
            else:
                body = str(body_raw or "")
            req_decision = evaluate_fetch_request(
                policy,
                method=method,
                path=path,
                headers=headers,
                body=body,
            )
            if not req_decision.allowed:
                return ProxyEvaluation(False, req_decision.reason, req_decision.rule_id, action)

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
    actor_team: str,
    rbac_policy: RbacPolicy | None,
    workspace_root: Path,
    adapter_fn: AdapterFn,
) -> ProxyEvaluation:
    action = adapter_fn(path, payload, fallback_actor)
    if rbac_policy is not None and not is_tool_allowed(rbac_policy, actor=action.actor, team=actor_team, tool=action.tool):
        return ProxyEvaluation(False, f"rbac blocked tool: {action.tool}", "proxy_rbac_block", action)

    evaluation = evaluate_action(action=action, backend=backend, workspace_root=workspace_root)

    if evaluation.allowed and is_privileged_action(action):
        scope = grant_scope_for_action(action)
        if not grants.is_allowed(actor=action.actor, tool=action.tool, scope=scope, session_id=action.session_id):
            return ProxyEvaluation(False, "proxy approval grant required", "proxy_approval_required", action)

    return evaluation


class ModeBHandler(BaseHTTPRequestHandler):
    config: ProxyConfig
    backend = None
    ledger: AuditLedger
    grants: GrantStore
    rbac_policy: RbacPolicy | None
    backend_cache: dict[tuple[str, str], object]
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

    def _read_body(self) -> bytes:
        content_length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(content_length) if content_length else b""

    def _handle_request(self, method: str):
        raw_body = self._read_body()
        generated_request_id = self.ledger.new_request_id()
        actor = self.headers.get(self.config.actor_header, "openclaw-agent")
        team = self.headers.get(self.config.team_header, "")
        profile = self.headers.get(self.config.profile_header, "")

        backend = self.backend
        if should_inspect_tool_call(method=method, path=self.path, config=self.config):
            try:
                payload = json.loads(raw_body.decode("utf-8"))
            except json.JSONDecodeError:
                payload = {}
            try:
                if self.config.profiles_path:
                    selected = resolve_policy_profile(
                        profiles_path=self.config.profiles_path,
                        profile_name=profile,
                        actor=actor,
                        team=team,
                    )
                    cache_key = (selected.backend, selected.policy_path)
                    backend = self.backend_cache.get(cache_key)
                    if backend is None:
                        backend = load_backend(selected.backend, selected.policy_path)
                        self.backend_cache[cache_key] = backend

                adapter_fn = self.__class__.adapter_fn
                evaluation = process_tool_request(
                    path=self.path,
                    payload=payload,
                    fallback_actor=actor,
                    config=self.config,
                    backend=backend,
                    grants=self.grants,
                    actor_team=team,
                    rbac_policy=self.rbac_policy,
                    workspace_root=Path(self.config.workspace).resolve(),
                    adapter_fn=adapter_fn,
                )
            except (ValueError, PolicyProfileError) as exc:
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
            response = forward_upstream(method=method, url=upstream_url, headers=headers, raw_body=raw_body)
        except requests.RequestException as exc:
            self._write_json(502, {"error": "upstream_unavailable", "reason": str(exc), "request_id": generated_request_id})
            return
        out_policy = getattr(getattr(backend, "policy", None), "tools", None)
        output = getattr(out_policy, "output", None)
        relay_upstream_response(
            self,
            response,
            max_bytes=int(getattr(output, "proxy_max_response_bytes", 0) or 0),
            min_delay_ms=int(getattr(output, "proxy_min_delay_ms", 0) or 0),
            jitter_ms=int(getattr(output, "proxy_jitter_ms", 0) or 0),
            jitter_seed=generated_request_id,
        )

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_PATCH(self):
        self._handle_request("PATCH")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_GET(self):
        self._handle_request("GET")


def run_modeb_proxy(listen_host: str, listen_port: int) -> None:
    config = load_proxy_config()
    backend = load_backend(config.policy_backend, config.policy_path)
    ledger = AuditLedger()
    grants = GrantStore()
    rbac_policy: RbacPolicy | None = None
    if config.rbac_path:
        try:
            rbac_policy = load_rbac_policy(config.rbac_path)
        except RbacPolicyError as exc:
            raise ValueError(f"invalid RBAC policy: {exc}")
    adapter_fn = get_adapter(config.adapter)

    ModeBHandler.config = config
    ModeBHandler.backend = backend
    ModeBHandler.ledger = ledger
    ModeBHandler.grants = grants
    ModeBHandler.rbac_policy = rbac_policy
    ModeBHandler.backend_cache = {}
    ModeBHandler.adapter_fn = adapter_fn

    server = ThreadingHTTPServer((listen_host, listen_port), ModeBHandler)
    print(f"agentsafe modeb proxy listening on {listen_host}:{listen_port}")
    print(f"upstream={config.upstream} policy={config.policy_path} backend={config.policy_backend} adapter={config.adapter}")
    server.serve_forever()
