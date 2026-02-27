# Roadmap

## Completed (Phase 0-4A foundations)
- Repo bootstrap and dev UX
- Policy engine + CLI + audit + Docker sandbox runner
- OpenClaw integration demo (Mode A wrappers)
- Mode B proxy service with configurable tool-route boundary regex matching
- Policy backend abstraction (`yaml` default, `opa` feature-flag stub)
- CLI-driven TTL grants for session-scoped approvals
- Local-only by default telemetry with explicit OTEL export command
- Policy bundle manifest + hash verification and optional ed25519 signature verification

## Next: Phase 4B/4C
- Harden Mode B forwarding coverage for additional HTTP methods and streaming calls
- Add structured tool schema adapters per OpenClaw version
- Replace OPA stub with real OPA/Rego adapter
- Add grant UX for fine-grained scope templates and approval workflows

## Enterprise trajectory
- Per-tool RBAC and session-scoped grants (JIT approvals)
- Signed policy bundles and trust chain (Cosign/Sigstore later)
- OpenTelemetry audit export
- SIEM connectors (Splunk, Elastic, Sentinel)
- Per-user and per-team policy profiles
- Local audit UI/dashboard graph
- Pluggable sandboxes: gVisor and Firecracker profiles (documented + adapters)
