# Firecracker Integration Harness

This harness provides a real Firecracker microVM boot path for AgentSafe
(`--sandbox-profile firecracker`) instead of Docker runtime aliasing.

## Requirements
- `firecracker` installed and runnable by your user.
- `/dev/kvm` accessible.
- Guest kernel image and rootfs image paths.

## Minimal setup
```bash
export AGENTSAFE_FIRECRACKER_BIN=firecracker
export AGENTSAFE_FIRECRACKER_KERNEL=/path/to/vmlinux
export AGENTSAFE_FIRECRACKER_ROOTFS=/path/to/rootfs.ext4
```

Run:
```bash
agentsafe run \
  --policy policies/demo-openclaw.yaml \
  --sandbox-profile firecracker \
  --workspace . \
  -- ls
```

Notes:
- Current adapter validates and boots a real microVM.
- Guest-side command execution requires a guest init/runner that consumes
  `agentsafe_cmd_b64` from kernel boot args and executes inside the VM.
- Until that guest runner is wired, `run` reports successful microVM boot with
  an execution-note in stderr preview.
