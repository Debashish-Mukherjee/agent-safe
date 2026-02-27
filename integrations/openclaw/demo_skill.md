# OpenClaw Skill Convention for AgentSafe (Mode A)

Use these wrappers for all side effects:

- Shell/tool execution:
  - `agentsafe run --policy /repo/policies/demo-openclaw.yaml --actor openclaw-agent --workspace /repo -- <cmd ...>`
- Downloads/network fetch:
  - `agentsafe fetch --policy /repo/policies/demo-openclaw.yaml --actor openclaw-agent --workspace /repo <url> --output <relpath>`

Rules:
- Never execute shell commands directly.
- Never call `curl` or `wget` directly without `agentsafe run`.
- Prefer read-only operations unless user explicitly asks to modify workspace files.
- Treat BLOCK responses as policy boundaries; explain and request approval only when needed.
