# AgentSafe: Zero-Trust Sandbox for Local AI Agents

AgentSafe is an open-source safety harness you put in front of local agent tool calls. It applies policy, executes commands in a restricted Docker sandbox, controls network egress, and records an audit trail that explains every allow/block decision.

## What problem does this solve?
Local coding or automation agents can execute shell commands and fetch data with broad host access. A single prompt injection or bad tool decision can read secrets (`~/.ssh`), modify sensitive files, or exfiltrate data over the network. AgentSafe constrains that blast radius.

## Why OpenClaw-style agents are scary
OpenClaw-style agents can chain tool calls fast and autonomously. Without guardrails they can:
- Read host credentials and config files.
- Execute risky package/system commands.
- Exfiltrate data to arbitrary domains.
- Hide intent unless you maintain robust logs.

AgentSafe enforces default-deny policy plus auditable decisions.

## MVP features
- Default-deny policy engine (YAML)
- Command allow-list with optional argument regex
- Workspace-only path controls + explicit deny roots (`/etc`, `/proc`, `/sys`, `$HOME`)
- Env var allow-list (no ambient secrets)
- Network modes:
  - `none` (default)
  - domain allow-list (`allow_proxy`) with HTTP CONNECT proxy
- Simple per-tool token-bucket rate limiting
- Append-only JSONL audit ledger + markdown audit report
- OpenClaw Docker/WSL demo integration (with deterministic mock flow)
- Mode B gateway proxy enforcement point for tool-execution APIs (configurable regex path matching)
- Session-scoped CLI grants with TTL (`agentsafe grant ...`)
- Local-first telemetry export command (`agentsafe telemetry export --mode otel --endpoint ...`)
- Signed policy bundle format with ed25519 verification support

## WSL2 prerequisites
- Windows with WSL2 Ubuntu
- Docker Desktop or Docker Engine integrated with WSL
- `docker compose` available in WSL shell
- Python 3.11+
- GNU Make

## Quickstart (5-10 minutes)
```bash
git clone <this-repo>
cd agent-safe
make setup
make demo-openclaw
make demo-modeb-gateway
```

Expected behavior:
- BLOCK read attempt on `/etc/passwd`
- BLOCK egress attempt to `https://example.com`
- ALLOW safe commands (`ls`, `git status`)
- Approval-required flow for `curl` (block, then allow after token)
- Audit events in `audit/ledger.jsonl`
- Shareable report at `audit/report.md`

## How policy works (short)
Policies live in `policies/*.yaml`.
- `default_decision: deny`
- `tools.commands`: allowed binaries and optional arg regex
- `tools.paths`: allow + deny path roots
- `tools.env_allowlist`: which env vars are passed to sandbox
- `tools.network`: `none` or `allow_proxy` + allowed domains/ports
- `tools.rate_limits`: token bucket by category (`run`, `fetch`)

CLI usage:
```bash
agentsafe run --policy policies/demo-openclaw.yaml --actor openclaw-agent --workspace . -- ls
agentsafe fetch --policy policies/demo-openclaw.yaml --actor openclaw-agent --workspace . https://github.com --output demos/github.html
agentsafe audit tail
agentsafe audit report --format md --output audit/report.md
agentsafe grant issue --actor openclaw-agent --tool run --scope "curl *" --ttl 600 --reason "demo approval"
agentsafe proxy --host 0.0.0.0 --port 8090
agentsafe policy bundle --policy policies/demo-openclaw.yaml --out policies/bundle.json
agentsafe policy verify --policy policies/demo-openclaw.yaml --bundle policies/bundle.json
```

## OPA backend (optional)
`yaml` remains the default backend. To use OPA/Rego decisions:
```bash
docker run --rm -p 8181:8181 \
  -v $(pwd)/policies/opa:/policies \
  openpolicyagent/opa:latest run --server --addr=0.0.0.0:8181 /policies/agentsafe.rego

export AGENTSAFE_OPA_URL=http://127.0.0.1:8181
agentsafe run --policy policies/demo-openclaw.yaml --policy-backend opa --workspace . -- ls
```

Notes:
- AgentSafe sends action + loaded YAML policy as OPA input to `agentsafe/evaluate`.
- Rego sample file: `policies/opa/agentsafe.rego`.

Live integration parity test (Dockerized OPA):
```bash
make test-opa-live
```

## Demo walkthrough
1. Filesystem exfil attempt:
- Command: `agentsafe run ... -- cat /etc/passwd`
- Result: `BLOCK path denied`

2. Network egress blocked:
- Command: `agentsafe fetch ... https://example.com`
- Result: `BLOCK domain not allowlisted`

3. Safe operations allowed:
- Commands: `agentsafe run ... -- ls`, `agentsafe run ... -- git status`
- Result: `ALLOW`

4. Approval-required command:
- Command: `agentsafe run ... -- curl https://openai.com`
- Result: `BLOCK requires approval`
- Add approval token to `.agentsafe_approvals`, rerun -> allowed by policy gate.

## OpenClaw integration
See [integrations/openclaw/README.md](integrations/openclaw/README.md).

## Light Gateway contract-first Mode B
See [integrations/light_gateway/README.md](integrations/light_gateway/README.md).
This provides a strict canonical tool-execution contract at `/v1/tools/execute`
for adapter and policy/grant/audit testing independent of OpenClaw internals.

Mode A (implemented):
- OpenClaw agent tools are wrapped with `agentsafe run` and `agentsafe fetch`.

Mode B (scaffold):
- Reverse proxy/policy enforcement at gateway API boundary (see `agentsafe/agentsafe/proxy/modeb_proxy.py`).
- Canonical boundary is configurable with `AGENTSAFE_PROXY_TOOL_PATH_REGEX`.

## Threat model and non-goals
See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## MVP limitations
- Command/file observation in `run` is best-effort from arguments, not full syscall tracing.
- `agentsafe fetch` runs inside the Docker sandbox using `curl`, but file-touch visibility is still output-path based (not syscall traced).
- Domain allow-list can still leak data to allowed domains.
- Docker sandbox is strong but not equivalent to microVM isolation.
