from __future__ import annotations

from pathlib import Path

from agentsafe.policy.backend import PolicyBackend
from agentsafe.policy.evaluate import Decision, evaluate_command, evaluate_path, evaluate_url
from agentsafe.policy.load import load_policy
from agentsafe.policy.model import Policy


class YamlPolicyBackend(PolicyBackend):
    def __init__(self, policy: Policy):
        self.policy = policy

    @classmethod
    def from_path(cls, path: str | Path) -> "YamlPolicyBackend":
        return cls(load_policy(path))

    def evaluate_run(self, cmd: list[str], workspace_root: Path) -> Decision:
        return evaluate_command(self.policy, cmd, workspace_root)

    def evaluate_path(self, candidate: str, workspace_root: Path) -> Decision:
        return evaluate_path(self.policy, candidate, workspace_root)

    def evaluate_fetch(self, url: str) -> Decision:
        return evaluate_url(self.policy, url)

    def env_allowlist(self) -> list[str]:
        return list(self.policy.tools.env_allowlist)

    def network_mode(self) -> str:
        return self.policy.tools.network.mode
