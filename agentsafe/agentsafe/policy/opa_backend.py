from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

import requests

from agentsafe.policy.backend import PolicyBackend
from agentsafe.policy.evaluate import Decision
from agentsafe.policy.load import load_policy
from agentsafe.policy.model import Policy


class OpaPolicyBackend(PolicyBackend):
    """
    OPA HTTP API backend.

    This backend expects an OPA policy decision endpoint returning:
    {
      "result": {"allow": bool, "reason": str, "rule_id": str}
    }
    at:
      <AGENTSAFE_OPA_URL>/v1/data/agentsafe/evaluate
    """

    def __init__(self, policy_path: str, opa_url: str | None = None):
        self.policy_path = str(policy_path)
        self.policy: Policy = load_policy(policy_path)
        self.opa_url = (opa_url or os.environ.get("AGENTSAFE_OPA_URL", "")).strip()
        self.decision_path = os.environ.get("AGENTSAFE_OPA_DECISION_PATH", "agentsafe/evaluate").strip("/") or "agentsafe/evaluate"

    def _not_configured(self) -> Decision:
        return Decision(
            False,
            "OPA backend configured but AGENTSAFE_OPA_URL is not set",
            "opa_not_configured",
        )

    def _query_opa(self, input_doc: dict) -> Decision:
        if not self.opa_url:
            return self._not_configured()

        endpoint = f"{self.opa_url.rstrip('/')}/v1/data/{self.decision_path}"
        try:
            response = requests.post(endpoint, json={"input": input_doc}, timeout=8)
            response.raise_for_status()
            body = response.json()
        except requests.RequestException as exc:
            return Decision(False, f"OPA query failed: {exc}", "opa_query_failed")
        except ValueError:
            return Decision(False, "OPA response was not valid JSON", "opa_bad_response")

        result = body.get("result")
        if isinstance(result, bool):
            return Decision(result, "OPA boolean decision", "opa_boolean")
        if not isinstance(result, dict):
            return Decision(False, "OPA result missing decision object", "opa_bad_result")

        allowed = bool(result.get("allow"))
        reason = str(result.get("reason") or ("OPA allow" if allowed else "OPA deny"))
        rule_id = str(result.get("rule_id") or "opa_decision")
        return Decision(allowed, reason, rule_id)

    @staticmethod
    def _normalize_path(path: str, workspace_root: Path) -> str:
        path = path.replace("$HOME", str(Path.home())).replace("~", str(Path.home()))
        p = Path(path)
        if not p.is_absolute():
            p = workspace_root / p
        return str(p.resolve())

    @staticmethod
    def _url_components(url: str) -> dict[str, str | int]:
        parsed = urlparse(url)
        return {
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "url": url,
        }

    def evaluate_run(self, cmd: list[str], workspace_root: Path) -> Decision:
        action = {
            "type": "run",
            "cmd": [str(part) for part in cmd],
            "workspace_root": str(workspace_root),
        }
        return self._query_opa({"action": action, "policy": asdict(self.policy)})

    def evaluate_path(self, candidate: str, workspace_root: Path) -> Decision:
        normalized = self._normalize_path(candidate, workspace_root)
        action = {
            "type": "path",
            "candidate": candidate,
            "normalized": normalized,
            "workspace_root": str(workspace_root),
        }
        return self._query_opa({"action": action, "policy": asdict(self.policy)})

    def evaluate_fetch(self, url: str) -> Decision:
        action = {"type": "fetch", **self._url_components(url)}
        return self._query_opa({"action": action, "policy": asdict(self.policy)})

    def env_allowlist(self) -> list[str]:
        return list(self.policy.tools.env_allowlist)

    def network_mode(self) -> str:
        return self.policy.tools.network.mode
