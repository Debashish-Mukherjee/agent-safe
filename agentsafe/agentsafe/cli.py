from __future__ import annotations

import builtins
import json
import os
import shlex
import sys
from dataclasses import asdict
from pathlib import Path

import typer
from rich.console import Console

from agentsafe.approvals.grants import ApprovalRequestStore
from agentsafe.approvals.grants import GrantStore
from agentsafe.approvals.grants import render_scope_template
from agentsafe.audit.ledger import AuditLedger
from agentsafe.audit.integrity import append_checkpoint, load_hmac_key, verify_checkpoints
from agentsafe.audit.render import render_html_dashboard
from agentsafe.audit.render import render_markdown_report
from agentsafe.audit.trace import build_trace_attestation, collect_traced_paths, verify_trace_attestations
from agentsafe.policy.evaluate import RateLimiter
from agentsafe.policy.factory import load_backend
from agentsafe.policy.load import PolicyError, load_policy
from agentsafe.policy.output_controls import cap_text_bytes
from agentsafe.policy.profiles import PolicyProfileError, resolve_policy_profile
from agentsafe.policy.signing.bundle import (
    SigningError,
    attest_policy,
    bundle_digest,
    verify_bundle_chain,
    verify_bundle_hash,
    verify_bundle_manifest,
    verify_bundle_signature,
    write_bundle,
)
from agentsafe.policy.signing.trust import verify_bundle_trust
from agentsafe.proxy.modeb_proxy import run_modeb_proxy
from agentsafe.sandbox.factory import build_sandbox_runner
from agentsafe.telemetry.exporter import (
    export_ledger_to_elastic,
    export_ledger_to_otel,
    export_ledger_to_sentinel,
    export_ledger_to_splunk,
)
from agentsafe.ui.server import run_dashboard_server

app = typer.Typer(help="AgentSafe CLI")
audit_app = typer.Typer(help="Audit commands")
grant_app = typer.Typer(help="Grant commands")
policy_app = typer.Typer(help="Policy bundle/signature commands")
telemetry_app = typer.Typer(help="Telemetry commands")
app.add_typer(audit_app, name="audit")
app.add_typer(grant_app, name="grant")
app.add_typer(policy_app, name="policy")
app.add_typer(telemetry_app, name="telemetry")
console = Console()


def _collect_env(env_allowlist: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in env_allowlist:
        val = os.environ.get(key)
        if val is not None:
            out[key] = val
    return out


def _parse_proxy_logs(proxy_log_path: Path) -> list[dict[str, object]]:
    if not proxy_log_path.exists():
        return []
    entries: list[dict[str, object]] = []
    for line in proxy_log_path.read_text(encoding="utf-8").splitlines()[-50:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _runner_env_and_network(backend) -> tuple[dict[str, str], str]:
    network_mode = "none"
    run_env = _collect_env(backend.env_allowlist())
    if backend.network_mode() == "allow_proxy":
        network_mode = "bridge"
        proxy_url = os.environ.get("AGENTSAFE_PROXY_URL", "http://host.docker.internal:8080")
        run_env["HTTP_PROXY"] = proxy_url
        run_env["HTTPS_PROXY"] = proxy_url
    return run_env, network_mode


def _requires_approval(command: list[str]) -> bool:
    return bool(command) and Path(command[0]).name in {"curl", "wget", "apt-get", "apt"}


def _approval_exists(workspace: Path, command: list[str], actor: str) -> bool:
    command_string = shlex.join(command)
    approval_file = workspace / ".agentsafe_approvals"
    if approval_file.exists() and command_string in approval_file.read_text(encoding="utf-8").splitlines():
        return True

    grants = GrantStore()
    if grants.is_allowed(actor=actor, tool="run", scope=command_string):
        return True
    if grants.is_allowed(actor=actor, tool="run", scope=f"{Path(command[0]).name} *"):
        return True
    return False


def _resolve_policy_and_backend(
    *,
    policy: str,
    policy_backend: str,
    actor: str,
    team: str,
    profile_name: str,
    profiles_path: str,
) -> tuple[str, str]:
    policy_value = policy.strip()
    backend_value = policy_backend.strip()
    if policy_value:
        return policy_value, (backend_value or "yaml")

    if not profiles_path.strip():
        raise PolicyProfileError("policy path required unless --profiles-path is provided")

    selection = resolve_policy_profile(
        profiles_path=profiles_path,
        profile_name=profile_name,
        actor=actor,
        team=team,
    )
    return selection.policy_path, (backend_value or selection.backend)


@app.command("run")
def run(
    policy: str = typer.Option("", "--policy", help="Path to policy YAML"),
    actor: str = typer.Option("unknown-agent", "--actor"),
    team: str = typer.Option("", "--team", help="Optional team for policy profile selection"),
    profile: str = typer.Option("", "--profile", help="Named policy profile from profile file"),
    profiles_path: str = typer.Option("", "--profiles-path", help="Policy profiles YAML file"),
    workspace: str = typer.Option(".", "--workspace"),
    sandbox_profile: str = typer.Option("", "--sandbox-profile", help="docker|gvisor|firecracker"),
    trace_files: bool = typer.Option(False, "--trace-files", help="Capture best-effort file syscall trace with strace"),
    cpu_limit: str = typer.Option("", "--cpu-limit"),
    mem_limit: str = typer.Option("", "--mem-limit"),
    policy_backend: str = typer.Option("", "--policy-backend", help="yaml or opa (overrides profile backend)"),
    cmd: list[str] = typer.Argument(..., help="Command to execute, use -- separator"),
) -> None:
    ledger = AuditLedger()
    request_id = ledger.new_request_id()
    workspace_path = Path(workspace).resolve()

    try:
        effective_policy, effective_backend = _resolve_policy_and_backend(
            policy=policy,
            policy_backend=policy_backend,
            actor=actor,
            team=team,
            profile_name=profile,
            profiles_path=profiles_path,
        )
        backend = load_backend(effective_backend, effective_policy)
        loaded = load_policy(effective_policy)
    except (PolicyError, PolicyProfileError, ValueError) as exc:
        console.print(f"[red]BLOCK[/red] invalid policy/backend: {exc}")
        raise typer.Exit(2)

    limiter = RateLimiter(loaded.tools.rate_limits)

    rate_decision = limiter.check("run")
    if not rate_decision.allowed:
        ledger.write_event(
            {
                "request_id": request_id,
                "actor": actor,
                "tool": "run",
                "args_summary": shlex.join(cmd),
                "decision": "BLOCK",
                "reason": rate_decision.reason,
                "rule_id": rate_decision.rule_id,
                "sandbox": {},
                "files_touched": [],
            }
        )
        console.print(f"[red]BLOCK[/red] {rate_decision.reason}")
        raise typer.Exit(2)

    decision = backend.evaluate_run(cmd, workspace_path)
    if not decision.allowed:
        ledger.write_event(
            {
                "request_id": request_id,
                "actor": actor,
                "tool": "run",
                "args_summary": shlex.join(cmd),
                "decision": "BLOCK",
                "reason": decision.reason,
                "rule_id": decision.rule_id,
                "sandbox": {},
                "files_touched": [],
            }
        )
        console.print(f"[red]BLOCK[/red] {decision.reason}")
        raise typer.Exit(2)

    file_args = [arg for arg in cmd[1:] if "/" in arg or arg.startswith(".")]
    for candidate in file_args:
        path_decision = backend.evaluate_path(candidate, workspace_path)
        if not path_decision.allowed:
            ledger.write_event(
                {
                    "request_id": request_id,
                    "actor": actor,
                    "tool": "run",
                    "args_summary": shlex.join(cmd),
                    "decision": "BLOCK",
                    "reason": path_decision.reason,
                    "rule_id": path_decision.rule_id,
                    "sandbox": {},
                    "files_touched": [candidate],
                }
            )
            console.print(f"[red]BLOCK[/red] {path_decision.reason}")
            raise typer.Exit(2)

    if _requires_approval(cmd) and not _approval_exists(workspace_path, cmd, actor=actor):
        reason = "command requires approval token in .agentsafe_approvals"
        ledger.write_event(
            {
                "request_id": request_id,
                "actor": actor,
                "tool": "run",
                "args_summary": shlex.join(cmd),
                "decision": "BLOCK",
                "reason": reason,
                "rule_id": "approval_required",
                "sandbox": {},
                "files_touched": [],
            }
        )
        console.print(f"[yellow]BLOCK[/yellow] {reason}")
        raise typer.Exit(3)

    run_env, network_mode = _runner_env_and_network(backend)
    proxy_log = Path("audit/proxy.log.jsonl")

    try:
        runner = build_sandbox_runner(
            profile=sandbox_profile,
            cpu_limit=cpu_limit or None,
            mem_limit=mem_limit or None,
        )
    except ValueError as exc:
        console.print(f"[red]BLOCK[/red] invalid sandbox profile: {exc}")
        raise typer.Exit(2)
    trace_prefix = f"audit/trace/{request_id}"
    result = runner.run(
        command=cmd,
        workspace=workspace_path,
        network_mode=network_mode,
        env=run_env,
        trace_files=trace_files,
        trace_prefix=trace_prefix,
    )

    decision_label = "ALLOW" if result.returncode == 0 else "BLOCK"
    reason = decision.reason if result.returncode == 0 else f"command exited non-zero ({result.returncode})"
    network_attempts = _parse_proxy_logs(proxy_log) if backend.network_mode() == "allow_proxy" else []
    traced_paths = collect_traced_paths(workspace_path, trace_prefix=trace_prefix) if trace_files else []
    trace_attestation = build_trace_attestation(workspace_path, trace_prefix=trace_prefix) if trace_files else {}
    files_touched = sorted({*file_args, *traced_paths})
    capped_stdout, stdout_truncated = cap_text_bytes(result.stdout, loaded.tools.output.max_stdout_bytes)
    capped_stderr, stderr_truncated = cap_text_bytes(result.stderr, loaded.tools.output.max_stderr_bytes)

    ledger.write_event(
        {
            "request_id": request_id,
            "actor": actor,
            "tool": "run",
            "args_summary": shlex.join(cmd),
            "decision": decision_label,
            "reason": reason,
            "rule_id": decision.rule_id,
            "sandbox": {
                "container_id": result.container_id,
                "workspace_mount": str(workspace_path),
                "network_mode": network_mode,
                "trace_files": trace_files,
                "trace_prefix": trace_prefix if trace_files else "",
                "trace_digest": trace_attestation.get("trace_digest", ""),
                "trace_file_count": trace_attestation.get("trace_file_count", 0),
                "trace_bytes": trace_attestation.get("trace_bytes", 0),
                "trace_artifacts": trace_attestation.get("trace_files", []),
            },
            "network_attempts": network_attempts,
            "files_touched": files_touched,
            "stdout_preview": capped_stdout[-800:],
            "stderr_preview": capped_stderr[-800:],
            "output_controls": {
                "max_stdout_bytes": loaded.tools.output.max_stdout_bytes,
                "max_stderr_bytes": loaded.tools.output.max_stderr_bytes,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
            },
        }
    )

    builtins.print(capped_stdout, end="")
    if capped_stderr:
        sys.stderr.write(capped_stderr)

    if result.returncode != 0:
        raise typer.Exit(result.returncode)


@app.command("fetch")
def fetch(
    policy: str = typer.Option("", "--policy", help="Path to policy YAML"),
    actor: str = typer.Option("unknown-agent", "--actor"),
    team: str = typer.Option("", "--team", help="Optional team for policy profile selection"),
    profile: str = typer.Option("", "--profile", help="Named policy profile from profile file"),
    profiles_path: str = typer.Option("", "--profiles-path", help="Policy profiles YAML file"),
    workspace: str = typer.Option(".", "--workspace"),
    sandbox_profile: str = typer.Option("", "--sandbox-profile", help="docker|gvisor|firecracker"),
    output: str = typer.Option("", "--output", help="Relative output file path in workspace"),
    policy_backend: str = typer.Option("", "--policy-backend", help="yaml or opa (overrides profile backend)"),
    url: str = typer.Argument(...),
) -> None:
    ledger = AuditLedger()
    request_id = ledger.new_request_id()
    workspace_path = Path(workspace).resolve()

    try:
        effective_policy, effective_backend = _resolve_policy_and_backend(
            policy=policy,
            policy_backend=policy_backend,
            actor=actor,
            team=team,
            profile_name=profile,
            profiles_path=profiles_path,
        )
        backend = load_backend(effective_backend, effective_policy)
        loaded = load_policy(effective_policy)
    except (PolicyError, PolicyProfileError, ValueError) as exc:
        console.print(f"[red]BLOCK[/red] invalid policy/backend: {exc}")
        raise typer.Exit(2)

    limiter = RateLimiter(loaded.tools.rate_limits)
    rate_decision = limiter.check("fetch")
    if not rate_decision.allowed:
        ledger.write_event(
            {
                "request_id": request_id,
                "actor": actor,
                "tool": "fetch",
                "args_summary": url,
                "decision": "BLOCK",
                "reason": rate_decision.reason,
                "rule_id": rate_decision.rule_id,
                "sandbox": {},
                "files_touched": [],
            }
        )
        console.print(f"[red]BLOCK[/red] {rate_decision.reason}")
        raise typer.Exit(2)

    decision = backend.evaluate_fetch(url)
    if not decision.allowed:
        ledger.write_event(
            {
                "request_id": request_id,
                "actor": actor,
                "tool": "fetch",
                "args_summary": url,
                "decision": "BLOCK",
                "reason": decision.reason,
                "rule_id": decision.rule_id,
                "sandbox": {},
                "network_attempts": [{"url": url}],
                "files_touched": [],
            }
        )
        console.print(f"[red]BLOCK[/red] {decision.reason}")
        raise typer.Exit(2)

    out_name = output or Path(url).name or "download.bin"
    out_path = (workspace_path / out_name).resolve()
    path_decision = backend.evaluate_path(str(out_path), workspace_path)
    if not path_decision.allowed:
        ledger.write_event(
            {
                "request_id": request_id,
                "actor": actor,
                "tool": "fetch",
                "args_summary": url,
                "decision": "BLOCK",
                "reason": path_decision.reason,
                "rule_id": path_decision.rule_id,
                "sandbox": {},
                "files_touched": [str(out_path)],
            }
        )
        console.print(f"[red]BLOCK[/red] {path_decision.reason}")
        raise typer.Exit(2)

    out_rel = out_path.relative_to(workspace_path).as_posix()
    run_env, network_mode = _runner_env_and_network(backend)
    proxy_log = Path("audit/proxy.log.jsonl")

    try:
        runner = build_sandbox_runner(profile=sandbox_profile)
    except ValueError as exc:
        console.print(f"[red]BLOCK[/red] invalid sandbox profile: {exc}")
        raise typer.Exit(2)
    result = runner.run(
        command=["curl", "-fsSL", url, "-o", out_rel],
        workspace=workspace_path,
        network_mode=network_mode,
        env=run_env,
    )
    if result.returncode != 0:
        reason = f"fetch command exited non-zero ({result.returncode})"
        ledger.write_event(
            {
                "request_id": request_id,
                "actor": actor,
                "tool": "fetch",
                "args_summary": url,
                "decision": "BLOCK",
                "reason": reason,
                "rule_id": "fetch_exec_error",
                "sandbox": {
                    "container_id": result.container_id,
                    "workspace_mount": str(workspace_path),
                    "network_mode": network_mode,
                },
                "network_attempts": _parse_proxy_logs(proxy_log) if backend.network_mode() == "allow_proxy" else [],
                "stderr_preview": result.stderr[-800:],
                "files_touched": [],
            }
        )
        console.print(f"[red]BLOCK[/red] {reason}")
        raise typer.Exit(2)

    ledger.write_event(
        {
            "request_id": request_id,
            "actor": actor,
            "tool": "fetch",
            "args_summary": url,
            "decision": "ALLOW",
            "reason": decision.reason,
            "rule_id": decision.rule_id,
            "sandbox": {
                "container_id": result.container_id,
                "workspace_mount": str(workspace_path),
                "network_mode": network_mode,
            },
            "network_attempts": _parse_proxy_logs(proxy_log) if backend.network_mode() == "allow_proxy" else [],
            "files_touched": [str(out_path)],
        }
    )
    console.print(f"[green]ALLOW[/green] saved to {out_path}")


@app.command("proxy")
def proxy(
    host: str = typer.Option("0.0.0.0", "--host"),
    port: int = typer.Option(8090, "--port"),
) -> None:
    run_modeb_proxy(listen_host=host, listen_port=port)


@audit_app.command("tail")
def audit_tail(lines: int = typer.Option(20, "--lines")) -> None:
    ledger = AuditLedger()
    for event in ledger.tail(lines):
        console.print_json(data=event)


@audit_app.command("report")
def audit_report(
    format: str = typer.Option("md", "--format"),
    output: str = typer.Option("audit/report.md", "--output"),
) -> None:
    if format != "md":
        raise typer.BadParameter("Only md format is supported in MVP")
    ledger = AuditLedger()
    report = render_markdown_report(ledger)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    console.print(f"wrote {output_path}")


@audit_app.command("dashboard")
def audit_dashboard(
    output: str = typer.Option("audit/dashboard.html", "--output"),
    limit: int = typer.Option(1000, "--limit"),
) -> None:
    ledger = AuditLedger()
    dashboard = render_html_dashboard(ledger, limit=limit)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(dashboard, encoding="utf-8")
    console.print(f"wrote {output_path}")


@audit_app.command("verify-chain")
def audit_verify_chain(
    strict: bool = typer.Option(False, "--strict", help="Fail on legacy events without chain_hash"),
) -> None:
    ledger = AuditLedger()
    result = ledger.verify_chain(strict=strict)
    console.print_json(data=asdict(result))
    if not result.valid:
        raise typer.Exit(2)


@audit_app.command("verify-trace")
def audit_verify_trace(
    workspace: str = typer.Option("", "--workspace", help="Override workspace root for trace artifact lookup"),
) -> None:
    ledger = AuditLedger()
    report = verify_trace_attestations(ledger.all_events(), workspace_override=workspace)
    console.print_json(data=report)
    if not report.get("valid", False):
        raise typer.Exit(2)


@audit_app.command("verify-all")
def audit_verify_all(
    strict_chain: bool = typer.Option(False, "--strict-chain", help="Fail if any event is missing chain_hash"),
    workspace: str = typer.Option("", "--workspace", help="Override workspace root for trace artifact lookup"),
) -> None:
    ledger = AuditLedger()
    chain_report = asdict(ledger.verify_chain(strict=strict_chain))
    trace_report = verify_trace_attestations(ledger.all_events(), workspace_override=workspace)
    out = {
        "valid": bool(chain_report.get("valid")) and bool(trace_report.get("valid")),
        "chain": chain_report,
        "trace": trace_report,
    }
    console.print_json(data=out)
    if not out["valid"]:
        raise typer.Exit(2)


@audit_app.command("checkpoint")
def audit_checkpoint(
    key_file: str = typer.Option("", "--key-file", help="Path to HMAC key file (fallback: AGENTSAFE_LEDGER_HMAC_KEY)"),
    note: str = typer.Option("", "--note", help="Optional checkpoint annotation"),
    audit_dir: str = typer.Option("audit", "--audit-dir"),
) -> None:
    ledger = AuditLedger(audit_dir=audit_dir)
    chain = ledger.verify_chain()
    if not chain.valid:
        console.print("[red]FAIL[/red] ledger chain invalid; refusing to checkpoint")
        console.print_json(data=asdict(chain))
        raise typer.Exit(2)
    if not chain.last_hash:
        raise typer.BadParameter("ledger has no events to checkpoint")
    try:
        key = load_hmac_key(key_file=key_file)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    checkpoint = append_checkpoint(audit_dir=audit_dir, ledger_hash=chain.last_hash, key=key, note=note)
    console.print_json(data=checkpoint)


@audit_app.command("verify-checkpoints")
def audit_verify_checkpoints(
    key_file: str = typer.Option("", "--key-file", help="Path to HMAC key file (fallback: AGENTSAFE_LEDGER_HMAC_KEY)"),
    audit_dir: str = typer.Option("audit", "--audit-dir"),
    require_current: bool = typer.Option(
        False,
        "--require-current",
        help="Require latest signed checkpoint hash to equal current ledger chain tip",
    ),
) -> None:
    ledger = AuditLedger(audit_dir=audit_dir)
    chain = ledger.verify_chain()
    if require_current and not chain.valid:
        console.print("[red]FAIL[/red] ledger chain invalid; cannot compare with current tip")
        console.print_json(data=asdict(chain))
        raise typer.Exit(2)
    expected_hash = chain.last_hash if require_current else ""
    try:
        key = load_hmac_key(key_file=key_file)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    result = verify_checkpoints(audit_dir=audit_dir, key=key, expected_ledger_hash=expected_hash)
    console.print_json(data=asdict(result))
    if not result.valid:
        raise typer.Exit(2)


@grant_app.command("issue")
def grant_issue(
    actor: str = typer.Option(..., "--actor"),
    tool: str = typer.Option(..., "--tool"),
    scope: str = typer.Option(..., "--scope", help="glob pattern, e.g. 'curl *'"),
    session_id: str = typer.Option("*", "--session-id", help="optional session scope (glob), defaults to '*'"),
    ttl: int = typer.Option(900, "--ttl", help="seconds"),
    reason: str = typer.Option("manual approval", "--reason"),
) -> None:
    grant = GrantStore().issue(actor=actor, tool=tool, scope=scope, session_id=session_id, ttl_seconds=ttl, reason=reason)
    console.print_json(data=asdict(grant))


@grant_app.command("scope-template")
def grant_scope_template(
    template: str = typer.Option(..., "--template", help="run-binary|run-command|tool-prefix|http-domain"),
    value: str = typer.Option(..., "--value"),
    tool: str = typer.Option("run", "--tool"),
) -> None:
    try:
        scope = render_scope_template(template=template, value=value, tool=tool)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    console.print(scope)


@grant_app.command("request")
def grant_request(
    actor: str = typer.Option(..., "--actor"),
    tool: str = typer.Option(..., "--tool"),
    scope: str = typer.Option(..., "--scope"),
    session_id: str = typer.Option("*", "--session-id", help="optional session scope (glob), defaults to '*'"),
    ttl: int = typer.Option(900, "--ttl", help="request expiry in seconds"),
    reason: str = typer.Option("agent requested privileged action", "--reason"),
) -> None:
    req = ApprovalRequestStore().create(
        actor=actor,
        tool=tool,
        scope=scope,
        session_id=session_id,
        reason=reason,
        ttl_seconds=ttl,
    )
    console.print_json(data=asdict(req))


@grant_app.command("requests")
def grant_requests(status: str = typer.Option("pending", "--status", help="pending|approved|rejected|expired|all")) -> None:
    rows = [asdict(item) for item in ApprovalRequestStore().list(status=status)]
    console.print_json(data={"requests": rows})


@grant_app.command("approve")
def grant_approve(
    request_id: str = typer.Argument(...),
    reviewer: str = typer.Option("human-operator", "--reviewer"),
    ttl: int = typer.Option(900, "--ttl", help="granted token ttl in seconds"),
    reason: str = typer.Option("approved by human operator", "--reason"),
) -> None:
    try:
        grant = ApprovalRequestStore().approve(
            request_id=request_id,
            reviewer=reviewer,
            ttl_seconds=ttl,
            reason=reason,
            grant_store=GrantStore(),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    console.print_json(data=asdict(grant))


@grant_app.command("reject")
def grant_reject(
    request_id: str = typer.Argument(...),
    reviewer: str = typer.Option("human-operator", "--reviewer"),
    reason: str = typer.Option("rejected by human operator", "--reason"),
) -> None:
    try:
        ApprovalRequestStore().reject(request_id=request_id, reviewer=reviewer, reason=reason)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    console.print(f"rejected {request_id}")


@grant_app.command("list")
def grant_list() -> None:
    grants = [asdict(g) for g in GrantStore().active_grants()]
    console.print_json(data={"active_grants": grants})


@grant_app.command("revoke")
def grant_revoke(grant_id: str = typer.Argument(...), reason: str = typer.Option("manual revoke", "--reason")) -> None:
    GrantStore().revoke(grant_id=grant_id, reason=reason)
    console.print(f"revoked {grant_id}")


@telemetry_app.command("export")
def telemetry_export(
    mode: str = typer.Option("otel", "--mode"),
    endpoint: str = typer.Option("", "--endpoint"),
    ledger: str = typer.Option("audit/ledger.jsonl", "--ledger"),
    splunk_token: str = typer.Option("", "--splunk-token"),
    splunk_index: str = typer.Option("", "--splunk-index"),
    splunk_source: str = typer.Option("agentsafe", "--splunk-source"),
    splunk_sourcetype: str = typer.Option("agentsafe:json", "--splunk-sourcetype"),
    elastic_api_key: str = typer.Option("", "--elastic-api-key"),
    elastic_index: str = typer.Option("agentsafe-audit", "--elastic-index"),
    sentinel_shared_key: str = typer.Option("", "--sentinel-shared-key"),
    sentinel_log_type: str = typer.Option("AgentSafeAudit", "--sentinel-log-type"),
) -> None:
    if not endpoint:
        raise typer.BadParameter("--endpoint is required")
    if mode == "otel":
        count = export_ledger_to_otel(ledger_path=ledger, endpoint=endpoint)
        console.print(f"exported {count} events to {endpoint} (otel)")
        return
    if mode == "splunk":
        if not splunk_token:
            raise typer.BadParameter("--splunk-token is required for splunk mode")
        count = export_ledger_to_splunk(
            ledger_path=ledger,
            endpoint=endpoint,
            token=splunk_token,
            index=splunk_index,
            source=splunk_source,
            sourcetype=splunk_sourcetype,
        )
        console.print(f"exported {count} events to {endpoint} (splunk)")
        return
    if mode == "elastic":
        count = export_ledger_to_elastic(
            ledger_path=ledger,
            endpoint=endpoint,
            api_key=elastic_api_key,
            index=elastic_index,
        )
        console.print(f"exported {count} events to {endpoint} (elastic)")
        return
    if mode == "sentinel":
        if not sentinel_shared_key:
            raise typer.BadParameter("--sentinel-shared-key is required for sentinel mode")
        count = export_ledger_to_sentinel(
            ledger_path=ledger,
            endpoint=endpoint,
            shared_key=sentinel_shared_key,
            log_type=sentinel_log_type,
        )
        console.print(f"exported {count} events to {endpoint} (sentinel)")
        return
    raise typer.BadParameter("Unsupported --mode, expected: otel|splunk|elastic|sentinel")


@app.command("serve")
def serve(
    dashboard: bool = typer.Option(False, "--dashboard", help="Start local approval dashboard server"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8787, "--port"),
) -> None:
    if dashboard:
        run_dashboard_server(host=host, port=port)
        return
    raise typer.BadParameter("no service selected; pass --dashboard")


@policy_app.command("bundle")
def policy_bundle(
    policy: str = typer.Option(..., "--policy"),
    out: str = typer.Option("policies/bundle.json", "--out"),
    signature_b64: str = typer.Option("", "--signature-b64"),
    issuer: str = typer.Option("", "--issuer"),
    source_uri: str = typer.Option("", "--source-uri"),
    parent_bundle: str = typer.Option("", "--parent-bundle", help="Optional previous bundle path"),
) -> None:
    parent_digest = bundle_digest(parent_bundle) if parent_bundle else ""
    out_path = write_bundle(
        policy_path=policy,
        out_path=out,
        signature_b64=signature_b64,
        issuer=issuer,
        source_uri=source_uri,
        parent_bundle_sha256=parent_digest,
    )
    console.print(f"wrote {out_path}")


@policy_app.command("attest")
def policy_attest(
    policy: str = typer.Option(..., "--policy"),
    out: str = typer.Option("policies/bundle.json", "--out"),
    signature_b64: str = typer.Option("", "--signature-b64"),
    issuer: str = typer.Option(..., "--issuer"),
    source_uri: str = typer.Option("", "--source-uri"),
    parent_bundle: str = typer.Option("", "--parent-bundle", help="Optional previous bundle path"),
) -> None:
    parent_digest = bundle_digest(parent_bundle) if parent_bundle else ""
    result = attest_policy(
        policy_path=policy,
        out_path=out,
        signature_b64=signature_b64,
        issuer=issuer,
        source_uri=source_uri,
        parent_bundle_sha256=parent_digest,
    )
    console.print_json(data=result)


@policy_app.command("verify")
def policy_verify(
    policy: str = typer.Option(..., "--policy"),
    bundle: str = typer.Option(..., "--bundle"),
    pubkey: str = typer.Option("", "--pubkey", help="PEM ed25519 public key"),
) -> None:
    if not verify_bundle_manifest(bundle_path=bundle):
        console.print("[red]FAIL[/red] bundle manifest hash mismatch")
        raise typer.Exit(2)

    if not verify_bundle_hash(policy_path=policy, bundle_path=bundle):
        console.print("[red]FAIL[/red] bundle hash mismatch")
        raise typer.Exit(2)

    if pubkey:
        try:
            ok = verify_bundle_signature(policy_path=policy, bundle_path=bundle, public_key_pem=pubkey)
        except SigningError as exc:
            console.print(f"[red]FAIL[/red] {exc}")
            raise typer.Exit(2)
        if not ok:
            console.print("[red]FAIL[/red] signature verification failed")
            raise typer.Exit(2)

    console.print("[green]OK[/green] policy bundle verified")


@policy_app.command("verify-chain")
def policy_verify_chain(
    bundle: str = typer.Option(..., "--bundle"),
    parent_bundle: str = typer.Option("", "--parent-bundle"),
) -> None:
    if not verify_bundle_chain(bundle_path=bundle, parent_bundle_path=parent_bundle):
        console.print("[red]FAIL[/red] bundle chain verification failed")
        raise typer.Exit(2)
    console.print("[green]OK[/green] bundle chain verified")


@policy_app.command("verify-trust")
def policy_verify_trust(
    policy: str = typer.Option(..., "--policy"),
    bundle: str = typer.Option(..., "--bundle"),
    trust_policy: str = typer.Option(..., "--trust-policy"),
    parent_bundle: list[str] = typer.Option([], "--parent-bundle"),
    pubkey: list[str] = typer.Option([], "--pubkey"),
) -> None:
    result = verify_bundle_trust(
        policy_path=policy,
        bundle_path=bundle,
        trust_policy_path=trust_policy,
        parent_bundles=parent_bundle,
        pubkeys=pubkey,
    )
    console.print_json(data=asdict(result))
    if not result.valid:
        raise typer.Exit(2)


@policy_app.command("profile-resolve")
def policy_profile_resolve(
    profiles_path: str = typer.Option(..., "--profiles-path"),
    actor: str = typer.Option("", "--actor"),
    team: str = typer.Option("", "--team"),
    profile: str = typer.Option("", "--profile"),
) -> None:
    try:
        selected = resolve_policy_profile(
            profiles_path=profiles_path,
            profile_name=profile,
            actor=actor,
            team=team,
        )
    except PolicyProfileError as exc:
        raise typer.BadParameter(str(exc))
    console.print_json(
        data={
            "profile": selected.profile,
            "policy": selected.policy_path,
            "backend": selected.backend,
            "source": selected.source,
        }
    )


def run_alias() -> None:
    argv = ["run", *sys.argv[1:]]
    app(argv, standalone_mode=False)


def fetch_alias() -> None:
    argv = ["fetch", *sys.argv[1:]]
    app(argv, standalone_mode=False)


if __name__ == "__main__":
    app()
