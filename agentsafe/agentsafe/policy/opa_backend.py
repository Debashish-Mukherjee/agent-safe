from __future__ import annotations

from pathlib import Path

from agentsafe.policy.backend import PolicyBackend
from agentsafe.policy.evaluate import Decision


class OpaPolicyBackend(PolicyBackend):
    """Feature-flag stub for future OPA integration."""

    def __init__(self, policy_path: str):
        self.policy_path = str(policy_path)

    def _not_ready(self) -> Decision:
        return Decision(False, "OPA backend not configured in this build", "opa_not_configured")

    def evaluate_run(self, cmd: list[str], workspace_root: Path) -> Decision:
        _ = (cmd, workspace_root)
        return self._not_ready()

    def evaluate_path(self, candidate: str, workspace_root: Path) -> Decision:
        _ = (candidate, workspace_root)
        return self._not_ready()

    def evaluate_fetch(self, url: str) -> Decision:
        _ = url
        return self._not_ready()

    def env_allowlist(self) -> list[str]:
        return []

    def network_mode(self) -> str:
        return "none"
