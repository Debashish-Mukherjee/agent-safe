from __future__ import annotations

from pathlib import Path

from agentsafe.sandbox.docker_runner import DockerSandboxRunner


def test_docker_cmd_includes_trace_wrapper(tmp_path: Path):
    runner = DockerSandboxRunner()
    cmd = runner._docker_cmd(
        command=["ls", "-la"],
        workspace=tmp_path,
        network_mode="none",
        env={},
        trace_files=True,
        trace_prefix=".agentsafe_trace/req-1",
    )
    rendered = cmd[-1]
    assert "strace -ff -e trace=%file" in rendered
    assert ".agentsafe_trace/req-1" in rendered
    assert "ls -la" in rendered
