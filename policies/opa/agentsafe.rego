package agentsafe

default evaluate := {
  "allow": false,
  "reason": "no matching rule",
  "rule_id": "opa_default_deny",
}

evaluate := out if {
  input.action.type == "run"
  count(input.action.cmd) > 0
  binary := lower(last(split(input.action.cmd[0], "/")))
  some i
  rule := input.policy.tools.commands[i]
  lower(rule.binary) == binary
  out := {
    "allow": true,
    "reason": sprintf("command allowed: %v", [binary]),
    "rule_id": object.get(rule, "rule_id", "cmd_allow"),
  }
}

evaluate := out if {
  input.action.type == "fetch"
  input.policy.tools.network.mode != "none"
  host := lower(input.action.host)
  some i
  allowed_domain := lower(input.policy.tools.network.domains[i])
  host == allowed_domain or endswith(host, concat("", [".", allowed_domain]))
  some j
  input.action.port == input.policy.tools.network.ports[j]
  out := {
    "allow": true,
    "reason": sprintf("domain allowed: %v:%v", [host, input.action.port]),
    "rule_id": "net_domain_allow",
  }
}

evaluate := out if {
  input.action.type == "path"
  candidate := input.action.normalized
  some i
  denied := input.policy.tools.paths.deny[i]
  startswith(candidate, denied)
  out := {
    "allow": false,
    "reason": sprintf("path denied: %v", [candidate]),
    "rule_id": "path_deny",
  }
}

evaluate := out if {
  input.action.type == "path"
  candidate := input.action.normalized
  some i
  allowed := input.policy.tools.paths.allow[i]
  startswith(candidate, allowed)
  out := {
    "allow": true,
    "reason": sprintf("path allowed: %v", [candidate]),
    "rule_id": "path_allow",
  }
}
