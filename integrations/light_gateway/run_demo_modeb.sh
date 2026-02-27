#!/usr/bin/env bash
set -euo pipefail

cd /repo

PROXY_URL="http://agentsafe-modeb-proxy:8090/v1/tools/execute"
rm -f audit/ledger.jsonl audit/grants.jsonl

post_json() {
  local payload="$1"
  python3 - <<'PY' "$PROXY_URL" "$payload"
import json
import sys
import requests
url = sys.argv[1]
payload = json.loads(sys.argv[2])
resp = requests.post(url, json=payload, timeout=20)
print(f"status={resp.status_code}")
print(resp.text)
PY
}

echo "[modeb] Scenario 1: BLOCK shell exfil"
post_json '{"request_id":"lg-1","actor":"openclaw-agent","session_id":"sess-1","tool":"shell.run","args":{"command":"cat /etc/passwd"},"context":{"cwd":"/workspace"}}'

echo "[modeb] Scenario 2: BLOCK disallowed fetch"
post_json '{"request_id":"lg-2","actor":"openclaw-agent","session_id":"sess-1","tool":"http.fetch","args":{"url":"https://example.com"},"context":{"cwd":"/workspace"}}'

echo "[modeb] Scenario 3: ALLOW safe shell"
post_json '{"request_id":"lg-3","actor":"openclaw-agent","session_id":"sess-1","tool":"shell.run","args":{"command":"ls"},"context":{"cwd":"/workspace"}}'

echo "[modeb] Scenario 4a: BLOCK curl without grant"
post_json '{"request_id":"lg-4a","actor":"openclaw-agent","session_id":"sess-1","tool":"shell.run","args":{"command":"curl https://openai.com"},"context":{"cwd":"/workspace"}}'

echo "[modeb] issuing grant"
agentsafe grant issue --actor openclaw-agent --tool shell.run --scope 'shell.run curl https://openai.com' --ttl 600 --reason 'modeb demo'

echo "[modeb] Scenario 4b: ALLOW curl with grant"
post_json '{"request_id":"lg-4b","actor":"openclaw-agent","session_id":"sess-1","tool":"shell.run","args":{"command":"curl https://openai.com"},"context":{"cwd":"/workspace"}}'

echo "[modeb] Audit tail"
agentsafe audit tail --lines 20
