# OpenClaw Integration (Docker on WSL)

This folder provides a deterministic integration harness for OpenClaw-style agents.

## What runs
- `openclaw`: configurable image (`OPENCLAW_IMAGE`) and optional API key (`OPENAI_API_KEY`).
- `agentsafe-proxy`: local HTTP CONNECT allow-list proxy.
- `fake-bank-api`: local service to represent sensitive targets.
- `demo-runner`: executes scripted agent flow using `agentsafe` wrappers.

## Run
```bash
cd integrations/openclaw
docker compose up --build --abort-on-container-exit demo-runner
```
If your environment uses legacy compose v1, replace `docker compose` with `docker-compose`.

## Notes
- Default `openclaw` service command is a placeholder to keep compose deterministic if image behavior varies.
- To use an official OpenClaw image, set:
```bash
export OPENCLAW_IMAGE=<official-image>
export OPENAI_API_KEY=<optional>
```
- The MVP demo still proves sandbox enforcement even without LLM keys.

## Mode B proxy (API boundary)
Run AgentSafe reverse proxy in front of tool execution routes:
```bash
AGENTSAFE_UPSTREAM_URL=http://openclaw:3333 \
AGENTSAFE_POLICY=policies/demo-openclaw.yaml \
AGENTSAFE_POLICY_BACKEND=yaml \
AGENTSAFE_PROXY_TOOL_PATH_REGEX='^/v1/tools/execute$,^/gateway/tools/execute$,^/api/tools/.+' \
agentsafe proxy --host 0.0.0.0 --port 8090
```
Default adapter is `openclaw_auto` (strict v1 first, then generic fallback). Override with:
```bash
export AGENTSAFE_PROXY_ADAPTER=openclaw_strict_v1
```

Grant privileged tool call approval (TTL scoped):
```bash
agentsafe grant issue --actor openclaw-agent --tool run --scope 'curl *' --ttl 900 --reason 'demo'
```

## Demo outputs
Expected:
- Scenario 1: BLOCK for `/etc/passwd`
- Scenario 2: BLOCK for `https://example.com`
- Scenario 3: ALLOW for `ls` and `git status`
- Scenario 4: BLOCK then ALLOW after `.agentsafe_approvals` token

## Capture real gateway payloads for strict adapters
Use this to collect real OpenClaw tool-execution requests before adding
`adapter_strict_<version>.py` implementations:
```bash
python3 integrations/openclaw/capture_requests.py --port 9088
```
Point OpenClaw gateway/tool-callback traffic to this capture endpoint, then copy useful files from:
- `agentsafe/tests/fixtures/openclaw/captured/`
