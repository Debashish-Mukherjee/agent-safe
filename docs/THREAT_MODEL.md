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
- Hash-chained JSONL audit ledger for policy decisions and execution metadata

## Additional mitigations in MVP+
- Mode B API-boundary proxy for OpenClaw tool execution routes
- Method-aware proxy interception with configurable route/method allowlist
- Strict-first OpenClaw adapter routing (`strict_v2` -> `strict_v1` -> generic fallback)
- Optional per-tool RBAC gate at proxy boundary (actor/team role mapping -> allowed tool patterns)
- Session-scoped CLI grants with TTL and least-privilege scope matching
  - For privileged Mode B proxy actions, grant checks enforce actor + tool + scope + `session_id` matching.
  - Backward-compatible default remains wildcard session scope (`*`) when no session is specified.
- File-backed approval request workflow (`grant request/approve/reject`) with reviewer metadata
- Policy bundle hash verification, provenance metadata, parent-chain linkage verification, and optional ed25519 signature verification
  - Added `policy attest` CLI for issuer/source-based policy attestations.
  - Added trust-policy verification (`policy verify-trust`) for issuer/source URI/age and parent-chain enforcement.
- Optional OPA/Rego backend support with local live parity test path
- Local-only telemetry by default; explicit opt-in export only
- Optional SIEM export connectors (Splunk, Elastic, Sentinel) for external monitoring pipelines
- Local audit dashboard generation from ledger events (`agentsafe audit dashboard`)
- Local approval dashboard server with approve/reject workflow (`agentsafe serve --dashboard`)
- Pluggable sandbox runtime profiles for Docker runtime adapters (`docker`, `gvisor`, `firecracker`)
  - Firecracker adapter now boots a real microVM path via `FirecrackerSandboxRunner` (guest execution contract required for full in-VM command lifecycle)
- Outbound `http.fetch` exfil controls at proxy boundary: method/path/header/body checks and deny-pattern filtering
- Output-channel controls: stdout/stderr caps and proxy response size/timing controls (delay + jitter knobs)
- Optional HMAC-signed ledger checkpoints for local integrity anchoring (`agentsafe audit checkpoint` / `verify-checkpoints`)

## Residual Risks and Future Hardening

### Partially mitigated risks
- Data exfiltration to an allowed domain remains possible.
- Covert-channel leakage via output size/timing remains possible.
  Current state: output caps and response pacing controls are implemented, but cannot eliminate all side channels.
- Syscall-level file trace for `agentsafe run` is best-effort, not tamper-resistant.
  Current state: optional `--trace-files` via `strace`, with trace digest bound into hash-chained audit events.
  Verification commands: `agentsafe audit verify-trace`, `agentsafe audit verify-all`.

### Out of scope for MVP/MVP+
- Kernel/container escape class vulnerabilities are reduced by sandboxing but not eliminated.
- Host process isolation outside the container/microVM boundary is not guaranteed.
- Strong tamper resistance for local audit/grant/request ledgers is not complete.
  Current state: local hash chaining and optional HMAC checkpoints, without immutable/WORM or external anchoring.

### Planned hardening
- Distributed trust roots and transparency-log-backed signatures (Cosign/Sigstore).
