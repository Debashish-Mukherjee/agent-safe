from __future__ import annotations

from pathlib import Path

from agentsafe.policy.backend import PolicyBackend
from agentsafe.policy.opa_backend import OpaPolicyBackend
from agentsafe.policy.yaml_backend import YamlPolicyBackend


def load_backend(policy_backend: str, policy_path: str | Path) -> PolicyBackend:
    if policy_backend == "yaml":
        return YamlPolicyBackend.from_path(policy_path)
    if policy_backend == "opa":
        return OpaPolicyBackend(str(policy_path))
    raise ValueError(f"Unsupported policy backend: {policy_backend}")
