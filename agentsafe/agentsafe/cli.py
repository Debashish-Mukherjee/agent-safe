from __future__ import annotations

import builtins
import json
import os
import shlex
import sys
from dataclasses import asdict
from pathlib import Path

import requests
import typer
from rich.console import Console

from agentsafe.approvals.grants import GrantStore
from agentsafe.audit.ledger import AuditLedger
from agentsafe.audit.render import render_markdown_report
from agentsafe.policy.evaluate import RateLimiter
from agentsafe.policy.factory import load_backend
from agentsafe.policy.load import PolicyError, load_policy
from agentsafe.policy.signing.bundle import SigningError, verify_bundle_hash, verify_bundle_signature, write_bundle
from agentsafe.proxy.modeb_proxy import run_modeb_proxy
from agentsafe.sandbox.docker_runner import DockerSandboxRunner
from agentsafe.telemetry.exporter import export_ledger_to_otel

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


@app.command("run")
def run(
    policy: str = typer.Option(..., "--policy", help="Path to policy YAML"),
    actor: str = typer.Option("unknown-agent", "--actor"),
    workspace: str = typer.Option(".", "--workspace"),
    cpu_limit: str = typer.Option("", "--cpu-limit"),
    mem_limit: str = typer.Option("", "--mem-limit"),
    policy_backend: str = typer.Option("yaml", "--policy-backend", help="yaml or opa"),
    cmd: list[str] = typer.Argument(..., help="Command to execute, use -- separator"),
) -> None:
    ledger = AuditLedger()
    request_id = ledger.new_request_id()
    workspace_path = Path(workspace).resolve()

    try:
        backend = load_backend(policy_backend, policy)
        loaded = load_policy(policy)
    except (PolicyError, ValueError) as exc:
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

    network_mode = "none"
    run_env = _collect_env(backend.env_allowlist())
    proxy_log = Path("audit/proxy.log.jsonl")
    if backend.network_mode() == "allow_proxy":
        network_mode = "bridge"
        proxy_url = os.environ.get("AGENTSAFE_PROXY_URL", "http://host.docker.internal:8080")
        run_env["HTTP_PROXY"] = proxy_url
        run_env["HTTPS_PROXY"] = proxy_url

    runner = DockerSandboxRunner(cpu_limit=cpu_limit or None, mem_limit=mem_limit or None)
    result = runner.run(command=cmd, workspace=workspace_path, network_mode=network_mode, env=run_env)

    decision_label = "ALLOW" if result.returncode == 0 else "BLOCK"
    reason = decision.reason if result.returncode == 0 else f"command exited non-zero ({result.returncode})"
    network_attempts = _parse_proxy_logs(proxy_log) if backend.network_mode() == "allow_proxy" else []

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
            },
            "network_attempts": network_attempts,
            "files_touched": file_args,
            "stdout_preview": result.stdout[-800:],
            "stderr_preview": result.stderr[-800:],
        }
    )

    builtins.print(result.stdout, end="")
    if result.stderr:
        sys.stderr.write(result.stderr)

    if result.returncode != 0:
        raise typer.Exit(result.returncode)


@app.command("fetch")
def fetch(
    policy: str = typer.Option(..., "--policy", help="Path to policy YAML"),
    actor: str = typer.Option("unknown-agent", "--actor"),
    workspace: str = typer.Option(".", "--workspace"),
    output: str = typer.Option("", "--output", help="Relative output file path in workspace"),
    policy_backend: str = typer.Option("yaml", "--policy-backend", help="yaml or opa"),
    url: str = typer.Argument(...),
) -> None:
    ledger = AuditLedger()
    request_id = ledger.new_request_id()
    workspace_path = Path(workspace).resolve()

    try:
        backend = load_backend(policy_backend, policy)
        loaded = load_policy(policy)
    except (PolicyError, ValueError) as exc:
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

    out_path.parent.mkdir(parents=True, exist_ok=True)
    resp = requests.get(url, timeout=20)
    if resp.status_code >= 400:
        reason = f"HTTP error: {resp.status_code}"
        ledger.write_event(
            {
                "request_id": request_id,
                "actor": actor,
                "tool": "fetch",
                "args_summary": url,
                "decision": "BLOCK",
                "reason": reason,
                "rule_id": "fetch_http_error",
                "sandbox": {},
                "network_attempts": [{"url": url, "status_code": resp.status_code}],
                "files_touched": [],
            }
        )
        console.print(f"[red]BLOCK[/red] {reason}")
        raise typer.Exit(2)

    out_path.write_bytes(resp.content)
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
                "workspace_mount": str(workspace_path),
                "network_mode": backend.network_mode(),
            },
            "network_attempts": [{"url": url, "status_code": resp.status_code}],
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


@grant_app.command("issue")
def grant_issue(
    actor: str = typer.Option(..., "--actor"),
    tool: str = typer.Option(..., "--tool"),
    scope: str = typer.Option(..., "--scope", help="glob pattern, e.g. 'curl *'"),
    ttl: int = typer.Option(900, "--ttl", help="seconds"),
    reason: str = typer.Option("manual approval", "--reason"),
) -> None:
    grant = GrantStore().issue(actor=actor, tool=tool, scope=scope, ttl_seconds=ttl, reason=reason)
    console.print_json(data=asdict(grant))


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
) -> None:
    if mode != "otel":
        raise typer.BadParameter("Only otel export mode is supported")
    if not endpoint:
        raise typer.BadParameter("--endpoint is required")
    count = export_ledger_to_otel(ledger_path=ledger, endpoint=endpoint)
    console.print(f"exported {count} events to {endpoint}")


@policy_app.command("bundle")
def policy_bundle(
    policy: str = typer.Option(..., "--policy"),
    out: str = typer.Option("policies/bundle.json", "--out"),
    signature_b64: str = typer.Option("", "--signature-b64"),
) -> None:
    out_path = write_bundle(policy_path=policy, out_path=out, signature_b64=signature_b64)
    console.print(f"wrote {out_path}")


@policy_app.command("verify")
def policy_verify(
    policy: str = typer.Option(..., "--policy"),
    bundle: str = typer.Option(..., "--bundle"),
    pubkey: str = typer.Option("", "--pubkey", help="PEM ed25519 public key"),
) -> None:
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


def run_alias() -> None:
    argv = ["run", *sys.argv[1:]]
    app(argv, standalone_mode=False)


def fetch_alias() -> None:
    argv = ["fetch", *sys.argv[1:]]
    app(argv, standalone_mode=False)


if __name__ == "__main__":
    app()
