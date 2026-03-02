from __future__ import annotations

import os

from agentsafe.sandbox.docker_runner import DockerSandboxRunner
from agentsafe.sandbox.firecracker_runner import FirecrackerSandboxRunner


def build_sandbox_runner(
    *,
    profile: str = "",
    cpu_limit: str | None = None,
    mem_limit: str | None = None,
) -> DockerSandboxRunner:
    selected = (profile or os.environ.get("AGENTSAFE_SANDBOX_PROFILE", "docker")).strip().lower()
    if selected in {"docker", ""}:
        return DockerSandboxRunner(cpu_limit=cpu_limit, mem_limit=mem_limit)
    if selected == "gvisor":
        runtime = os.environ.get("AGENTSAFE_GVISOR_RUNTIME", "runsc").strip() or "runsc"
        return DockerSandboxRunner(cpu_limit=cpu_limit, mem_limit=mem_limit, runtime=runtime)
    if selected == "firecracker":
        return FirecrackerSandboxRunner()
    raise ValueError(f"unsupported sandbox profile: {selected}")
