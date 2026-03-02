from __future__ import annotations

from agentsafe.sandbox.firecracker_runner import FirecrackerSandboxRunner


def test_firecracker_boot_args_embeds_command():
    args = FirecrackerSandboxRunner._boot_args(["echo", "hello world"])
    assert "agentsafe_cmd_b64=" in args
    assert "console=ttyS0" in args


def test_firecracker_runner_reports_missing_kernel_rootfs(tmp_path):
    import shutil

    runner = FirecrackerSandboxRunner(
        firecracker_bin="firecracker",
        kernel_image="",
        rootfs_image="",
    )
    original_which = shutil.which
    try:
        shutil.which = lambda name: "/usr/bin/firecracker" if name == "firecracker" else original_which(name)
        result = runner.run(command=["ls"], workspace=tmp_path)
    finally:
        shutil.which = original_which
    assert result.returncode == 2
    assert "AGENTSAFE_FIRECRACKER_KERNEL" in result.stderr or "AGENTSAFE_FIRECRACKER_ROOTFS" in result.stderr
