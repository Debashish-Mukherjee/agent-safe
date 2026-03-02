#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AGENTSAFE_FIRECRACKER_KERNEL:-}" || -z "${AGENTSAFE_FIRECRACKER_ROOTFS:-}" ]]; then
  echo "AGENTSAFE_FIRECRACKER_KERNEL and AGENTSAFE_FIRECRACKER_ROOTFS must be set"
  exit 2
fi

echo "[firecracker-demo] using kernel=${AGENTSAFE_FIRECRACKER_KERNEL}"
echo "[firecracker-demo] using rootfs=${AGENTSAFE_FIRECRACKER_ROOTFS}"

agentsafe run \
  --policy policies/demo-openclaw.yaml \
  --sandbox-profile firecracker \
  --workspace . \
  -- ls
