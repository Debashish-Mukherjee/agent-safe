# AgentSafe Demo Script

## What Is the Blast Radius of Your AI Agent?

## Objective

Demonstrate how AgentSafe reduces blast radius for an OpenClaw-style local
agent by enforcing:

- Filesystem isolation
- Network egress allow-listing
- Privileged command approval
- Human-readable audit logging

## Prerequisites

From WSL Ubuntu:

```bash
make setup
```

## Start the Demo

```bash
make demo-openclaw
```

This starts OpenClaw demo services, AgentSafe proxy, and a deterministic
demo runner flow.

## Scene 1: Host data exfiltration attempt

Agent attempts:

```text
cat /etc/passwd
```

Expected:

```text
BLOCK path denied: /etc/passwd
rule_id: path_deny
```

## Scene 2: Uncontrolled internet egress attempt

Agent attempts:

```text
fetch https://example.com
```

Expected:

```text
BLOCK domain not allowlisted: example.com
rule_id: net_domain_block
```

## Scene 3: Legitimate developer activity

Agent attempts:

```text
ls
git status
```

Expected:

```text
ALLOW command allowed: ls
ALLOW command allowed: git
```

## Scene 4: Approval-required command

Agent attempts:

```text
curl https://openai.com
```

First attempt expected:

```text
BLOCK command requires approval token in .agentsafe_approvals
rule_id: approval_required
```

Manual approval:

```bash
echo "curl https://openai.com" >> .agentsafe_approvals
```

Second attempt expected:

```text
ALLOW command allowed: curl
```

Note: response content may be a challenge page depending on upstream site, but
the policy decision should be ALLOW after approval.

## Scene 5: Forensic traceability

View audit stream:

```bash
agentsafe audit tail --lines 20
```

Generate markdown report:

```bash
agentsafe audit report --format md --output audit/report.md
```

Look for these decisions in `audit/ledger.jsonl`:

- `path_deny`
- `net_domain_block`
- `cmd_ls`
- `cmd_git_readonly`
- `approval_required`
- `cmd_curl`

## Conclusion

AgentSafe enforces workspace-only filesystem access, default-deny network
egress, tool-level policy, approval gating, and auditable decision logs.
