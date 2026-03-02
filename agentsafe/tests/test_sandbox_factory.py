from __future__ import annotations

import pytest

from agentsafe.sandbox.firecracker_runner import FirecrackerSandboxRunner
from agentsafe.sandbox.factory import build_sandbox_runner


def test_build_sandbox_runner_profiles(monkeypatch):
    docker = build_sandbox_runner(profile="docker")
    assert docker.runtime == ""

    gvisor = build_sandbox_runner(profile="gvisor")
    assert gvisor.runtime == "runsc"

    monkeypatch.setenv("AGENTSAFE_FIRECRACKER_RUNTIME", "kata-fc")
    firecracker = build_sandbox_runner(profile="firecracker")
    assert isinstance(firecracker, FirecrackerSandboxRunner)


def test_build_sandbox_runner_invalid_profile():
    with pytest.raises(ValueError):
        build_sandbox_runner(profile="invalid")
