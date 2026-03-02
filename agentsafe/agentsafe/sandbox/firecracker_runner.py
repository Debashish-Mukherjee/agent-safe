from __future__ import annotations

import base64
import json
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from agentsafe.sandbox.docker_runner import SandboxResult


class FirecrackerSandboxRunner:
    def __init__(
        self,
        firecracker_bin: str = "",
        kernel_image: str = "",
        rootfs_image: str = "",
        vcpu_count: int = 1,
        mem_mib: int = 256,
    ):
        self.firecracker_bin = firecracker_bin or os.environ.get("AGENTSAFE_FIRECRACKER_BIN", "firecracker")
        self.kernel_image = kernel_image or os.environ.get("AGENTSAFE_FIRECRACKER_KERNEL", "")
        self.rootfs_image = rootfs_image or os.environ.get("AGENTSAFE_FIRECRACKER_ROOTFS", "")
        self.vcpu_count = int(os.environ.get("AGENTSAFE_FIRECRACKER_VCPU", str(vcpu_count)))
        self.mem_mib = int(os.environ.get("AGENTSAFE_FIRECRACKER_MEM_MIB", str(mem_mib)))

    @staticmethod
    def _boot_args(command: list[str]) -> str:
        cmd_b64 = base64.b64encode(shlex.join(command).encode("utf-8")).decode("ascii")
        return (
            "console=ttyS0 reboot=k panic=1 pci=off "
            f"agentsafe_cmd_b64={cmd_b64}"
        )

    @staticmethod
    def _api_call(sock_path: str, method: str, path: str, payload: dict | None = None) -> tuple[int, str]:
        body = ""
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"))
        content_len = len(body.encode("utf-8"))
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Accept: application/json\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {content_len}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        ).encode("utf-8")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(sock_path)
            client.sendall(request)
            chunks: list[bytes] = []
            while True:
                data = client.recv(65536)
                if not data:
                    break
                chunks.append(data)
        raw = b"".join(chunks).decode("utf-8", errors="replace")
        status_line = raw.splitlines()[0] if raw else ""
        parts = status_line.split()
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return status, raw

    def _validate(self) -> str:
        if shutil.which(self.firecracker_bin) is None:
            return f"firecracker binary not found: {self.firecracker_bin}"
        if not self.kernel_image:
            return "AGENTSAFE_FIRECRACKER_KERNEL is required for firecracker profile"
        if not self.rootfs_image:
            return "AGENTSAFE_FIRECRACKER_ROOTFS is required for firecracker profile"
        if not Path(self.kernel_image).exists():
            return f"firecracker kernel image not found: {self.kernel_image}"
        if not Path(self.rootfs_image).exists():
            return f"firecracker rootfs image not found: {self.rootfs_image}"
        if not Path("/dev/kvm").exists():
            return "/dev/kvm not available"
        return ""

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
        _ = (workspace, network_mode, env, trace_files, trace_prefix)
        invalid = self._validate()
        if invalid:
            return SandboxResult(
                returncode=2,
                stdout="",
                stderr=invalid,
                container_id="firecracker",
                command=command,
            )

        fc_tmp = Path(tempfile.mkdtemp(prefix="agentsafe-firecracker-", dir="/tmp"))
        api_sock = str(fc_tmp / "firecracker.sock")
        proc = subprocess.Popen(
            [self.firecracker_bin, "--api-sock", api_sock],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            started = False
            for _ in range(80):
                if Path(api_sock).exists():
                    started = True
                    break
                if proc.poll() is not None:
                    break
                time.sleep(0.05)
            if not started:
                out, err = proc.communicate(timeout=2)
                return SandboxResult(2, out, f"firecracker api socket not ready\n{err}", "firecracker", command)

            code, body = self._api_call(
                api_sock,
                "PUT",
                "/machine-config",
                {"vcpu_count": self.vcpu_count, "mem_size_mib": self.mem_mib, "ht_enabled": False},
            )
            if code not in {200, 204}:
                out, err = proc.communicate(timeout=2)
                return SandboxResult(2, out, f"machine-config failed ({code})\n{body}\n{err}", "firecracker", command)

            code, body = self._api_call(
                api_sock,
                "PUT",
                "/boot-source",
                {
                    "kernel_image_path": self.kernel_image,
                    "boot_args": self._boot_args(command),
                },
            )
            if code not in {200, 204}:
                out, err = proc.communicate(timeout=2)
                return SandboxResult(2, out, f"boot-source failed ({code})\n{body}\n{err}", "firecracker", command)

            code, body = self._api_call(
                api_sock,
                "PUT",
                "/drives/rootfs",
                {
                    "drive_id": "rootfs",
                    "path_on_host": self.rootfs_image,
                    "is_root_device": True,
                    "is_read_only": True,
                },
            )
            if code not in {200, 204}:
                out, err = proc.communicate(timeout=2)
                return SandboxResult(2, out, f"rootfs attach failed ({code})\n{body}\n{err}", "firecracker", command)

            code, body = self._api_call(api_sock, "PUT", "/actions", {"action_type": "InstanceStart"})
            if code not in {200, 204}:
                out, err = proc.communicate(timeout=2)
                return SandboxResult(2, out, f"instance start failed ({code})\n{body}\n{err}", "firecracker", command)

            # Start/boot path succeeded. Full guest command execution requires guest-side runner integration.
            time.sleep(min(max(timeout, 1), 3))
            self._api_call(api_sock, "PUT", "/actions", {"action_type": "SendCtrlAltDel"})
            proc.terminate()
            out, err = proc.communicate(timeout=4)
            note = (
                "firecracker microVM boot succeeded; guest command execution requires"
                " a configured guest runner consuming agentsafe_cmd_b64"
            )
            return SandboxResult(0, out, f"{note}\n{err}".strip(), "firecracker", command)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            return SandboxResult(2, out, f"firecracker timeout\n{err}", "firecracker", command)
        finally:
            shutil.rmtree(fc_tmp, ignore_errors=True)
