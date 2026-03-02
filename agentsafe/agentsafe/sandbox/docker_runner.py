from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    container_id: str
    command: list[str]


class DockerSandboxRunner:
    def __init__(
        self,
        image: str = "agentsafe-sandbox:local",
        cpu_limit: str | None = None,
        mem_limit: str | None = None,
        runtime: str = "",
        extra_args: list[str] | None = None,
    ):
        self.image = image
        self.cpu_limit = cpu_limit
        self.mem_limit = mem_limit
        self.runtime = runtime.strip()
        self.extra_args = list(extra_args or [])

    def _docker_cmd(
        self,
        command: list[str],
        workspace: Path,
        network_mode: str,
        env: dict[str, str],
        trace_files: bool,
        trace_prefix: str,
    ) -> list[str]:
        cmd = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--add-host",
            "host.docker.internal:host-gateway",
            "-u",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{workspace.resolve()}:/workspace:rw",
            "-w",
            "/workspace",
            "--network",
            network_mode,
        ]
        if self.runtime:
            cmd.extend(["--runtime", self.runtime])
        if self.cpu_limit:
            cmd.extend(["--cpus", self.cpu_limit])
        if self.mem_limit:
            cmd.extend(["--memory", self.mem_limit])
        if self.extra_args:
            cmd.extend(self.extra_args)

        for key, value in env.items():
            cmd.extend(["-e", f"{key}={value}"])

        cmd.append(self.image)

        rendered = shlex.join(command)
        if trace_files:
            if not trace_prefix:
                raise ValueError("trace_prefix is required when trace_files is enabled")
            trace_prefix_q = shlex.quote(trace_prefix)
            trace_dir_q = shlex.quote(str(Path(trace_prefix).parent))
            wrapped = (
                f"if command -v strace >/dev/null 2>&1; then "
                f"mkdir -p {trace_dir_q}; "
                f"strace -ff -e trace=%file -o {trace_prefix_q} {rendered}; "
                f"else {rendered}; fi"
            )
            cmd.append(wrapped)
        else:
            cmd.append(rendered)
        return cmd

    def run(
        self,
        command: list[str],
        workspace: Path,
        network_mode: str = "none",
        env: dict[str, str] | None = None,
        timeout: int = 60,
        trace_files: bool = False,
        trace_prefix: str = "",
    ) -> SandboxResult:
        env = env or {}
        docker_cmd = self._docker_cmd(
            command=command,
            workspace=workspace,
            network_mode=network_mode,
            env=env,
            trace_files=trace_files,
            trace_prefix=trace_prefix,
        )
        proc = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=timeout, check=False)
        container_id = "ephemeral"
        return SandboxResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            container_id=container_id,
            command=command,
        )
