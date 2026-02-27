# AgentSafe Threat Model (MVP+)

## Assets to protect
- Host files outside workspace (home directory, SSH keys, system files)
- Secrets in environment variables
- Network credentials and internal services
- Audit integrity of what agent attempted and what was allowed/blocked

## Attacker model
- Prompt injection in external content
- Agent misbehavior due to tool misuse
- Malicious plugin/tool instruction trying to escalate scope

## Mitigations in MVP
- Sandbox execution in Docker with restricted mount (workspace only)
- Default-deny command policy + argument/path checks
- Explicit deny path roots (`/etc`, `/proc`, `/sys`, `$HOME`, `~/.ssh`)
- Environment allow-list (do not pass arbitrary host env)
- Network `none` by default
- Optional domain allow-list proxy for HTTPS CONNECT
- Append-only JSONL audit ledger for policy decisions and execution metadata

## Additional mitigations in MVP+
- Mode B API-boundary proxy for OpenClaw tool execution routes
- Session-scoped CLI grants with TTL and least-privilege scope matching
- Policy bundle hash verification and optional ed25519 signature verification
- Local-only telemetry by default; explicit opt-in export only

## Not solved in MVP
- Data exfiltration to an allowed domain
- Covert channels via command output size/timing
- Kernel/container escape class vulnerabilities
- Full syscall-level file trace for `agentsafe run`
- Host process isolation outside Docker boundary
- Full trust/provenance chain for distributed policy delivery (planned)
- Human approval UI workflow (CLI-driven grants only in current phase)
