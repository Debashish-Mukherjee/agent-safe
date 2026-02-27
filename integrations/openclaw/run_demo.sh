#!/usr/bin/env bash
set -euo pipefail

cd /repo
POLICY="policies/demo-openclaw.yaml"
ACTOR="openclaw-agent"
WORKSPACE="${HOST_WORKSPACE:-/home/debashish/trials/agent-safe}"
echo "[demo] Using workspace: $WORKSPACE"

echo "[demo] Scenario 1: filesystem exfil attempt (expected BLOCK)"
set +e
agentsafe run --policy "$POLICY" --actor "$ACTOR" --workspace "$WORKSPACE" -- cat /etc/passwd
S1_RC=$?
set -e
echo "[demo] scenario1 exit=$S1_RC"

echo "[demo] Scenario 2: network egress blocked domain (expected BLOCK)"
set +e
agentsafe fetch --policy "$POLICY" --actor "$ACTOR" --workspace "$WORKSPACE" https://example.com --output demos/example.html
S2_RC=$?
set -e
echo "[demo] scenario2 exit=$S2_RC"

echo "[demo] Scenario 3: safe operations (expected ALLOW)"
if [ ! -d "$WORKSPACE/.git" ]; then
  git -C "$WORKSPACE" init >/dev/null 2>&1
fi
agentsafe run --policy "$POLICY" --actor "$ACTOR" --workspace "$WORKSPACE" -- ls
agentsafe run --policy "$POLICY" --actor "$ACTOR" --workspace "$WORKSPACE" -- git status

echo "[demo] Scenario 4: approval required flow"
rm -f "$WORKSPACE/.agentsafe_approvals"
set +e
agentsafe run --policy "$POLICY" --actor "$ACTOR" --workspace "$WORKSPACE" -- curl https://openai.com
S4_BLOCK_RC=$?
set -e
echo "curl https://openai.com" >> "$WORKSPACE/.agentsafe_approvals"
set +e
agentsafe run --policy "$POLICY" --actor "$ACTOR" --workspace "$WORKSPACE" -- curl https://openai.com
S4_ALLOW_RC=$?
set -e
echo "[demo] scenario4 block_exit=$S4_BLOCK_RC allow_exit=$S4_ALLOW_RC"

echo "[demo] Audit tail"
agentsafe audit tail --lines 20

echo "[demo] Audit markdown report"
agentsafe audit report --format md --output audit/report.md
cat audit/report.md
