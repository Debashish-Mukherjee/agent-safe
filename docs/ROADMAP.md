# Roadmap

Legend: `[x]` complete, `[ ]` pending (with `in progress` noted inline when partial).

## Phase 0-4A foundations
- [x] Repo bootstrap and dev UX
- [x] Policy engine + CLI + audit + Docker sandbox runner
- [x] OpenClaw integration demo (Mode A wrappers)
- [x] Mode B proxy service with configurable tool-route boundary regex matching
- [x] Policy backend abstraction (`yaml` default, optional OPA/Rego backend via HTTP API)
- [x] CLI-driven TTL grants for approval workflows
- [x] Local-only by default telemetry with explicit OTEL export command
- [x] Policy bundle manifest + hash verification and optional ed25519 signature verification

## Phase 4B/4C
- [x] Harden Mode B forwarding coverage for additional HTTP methods and streaming calls
  - Implemented in proxy: method-aware interception (`AGENTSAFE_PROXY_TOOL_METHODS`) and streaming-safe upstream relay.
- [x] Add structured tool schema adapters per OpenClaw version
  - `openclaw_auto` strict-first router (`strict_v2` -> `strict_v1` -> `strict_legacy` -> generic fallback).
  - Payload capture utility: `integrations/openclaw/capture_requests.py`.
  - Fixture normalizer: `integrations/openclaw/normalize_captures.py`.
- [x] Expand OPA/Rego parity coverage and add integration test with live OPA container
  - Local live test path added: `make test-opa-live`.
  - Local OPA service helpers added: `make opa-local-up`, `make opa-local-health`, `make opa-local-down`.
  - Expanded live parity assertions for env/network metadata and additional fetch block cases.
- [x] Add grant UX for fine-grained scope templates and approval workflows
  - Commands: `grant scope-template`, `grant request`, `grant requests`, `grant approve`, `grant reject`.
  - File-backed approval request ledger: `audit/approval_requests.jsonl`.
  - Session-scoped grant enforcement at proxy boundary (`session_id` aware matching).

## Enterprise trajectory
- [x] Per-tool RBAC and session-scoped grants (JIT approvals)
  - Session-scoped grant enforcement implemented (`session_id` match for privileged proxy actions).
  - Added file-backed per-tool RBAC policy support at proxy boundary (`AGENTSAFE_RBAC_POLICY`), including global and per-role deny patterns.
- [x] Signed policy bundles and trust chain (Cosign/Sigstore later)
  - Bundle provenance metadata + manifest hash added at bundle creation time.
  - Added explicit attestation command (`agentsafe policy attest`) with issuer/source metadata.
  - Added chain linkage verification (`agentsafe policy verify-chain --bundle ... --parent-bundle ...`).
  - Added trust-policy verification (`agentsafe policy verify-trust`) for issuer/source/age/parent-chain controls.
  - Added local hash-chained audit ledger verification (`agentsafe audit verify-chain`) as a tamper-evident foundation.
  - Added optional HMAC-signed checkpoint flow for ledger tip integrity (`agentsafe audit checkpoint`, `agentsafe audit verify-checkpoints`).
  - Added combined audit verification command (`agentsafe audit verify-all`) with trace attestation checks.
- [x] OpenTelemetry audit export
- [x] SIEM connectors (Splunk, Elastic, Sentinel)
- [x] Per-user and per-team policy profiles
  - Added profile resolver (`agentsafe policy profile-resolve`) and profile-aware `run`/`fetch` via `--profiles-path`, `--actor`, `--team`, `--profile`.
  - Added proxy-boundary profile selection (`AGENTSAFE_PROXY_PROFILES_PATH`) via actor/team/profile headers.
  - Added example profile config: `policies/profiles.example.yaml`.
- [x] Local audit UI/dashboard graph
- [x] Human approval UI workflow (local dashboard server + approve/reject API)
  - Added local server command: `agentsafe serve --dashboard`.
  - Dashboard actions are wired to existing grant request stores (`/api/approval-requests/.../approve|reject`).
- [x] Pluggable sandboxes: gVisor and Firecracker profiles (documented + adapters)
  - Added `FirecrackerSandboxRunner` (`agentsafe/agentsafe/sandbox/firecracker_runner.py`).
  - Wired factory profile selection so `--sandbox-profile firecracker` uses microVM adapter (not Docker runtime alias).
  - Added integration harness/docs: `integrations/firecracker/README.md`, `integrations/firecracker/run_demo_firecracker.sh`.
  - Added runner tests: `agentsafe/tests/test_firecracker_runner.py`.
- [x] Allowed-domain exfil controls
  - Added outbound request policy checks in Mode B proxy for `http.fetch` args: method/path/header/body size.
  - Added policy knobs: `http_methods`, `http_path_allow_regex`, `max_request_body_bytes`, `deny_header_patterns`, `deny_body_patterns`.
  - Added policy/proxy tests for method/path/header/body and deny-pattern blocking (headers + body).
