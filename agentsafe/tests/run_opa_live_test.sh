#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OPA_CONTAINER="agentsafe-opa-live"
OPA_IMAGE="${OPA_IMAGE:-openpolicyagent/opa:latest}"
OPA_PORT="${OPA_PORT:-8181}"

cleanup() {
  docker rm -f "$OPA_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[opa-live] starting OPA container on host port ${OPA_PORT}"
cleanup
docker run -d --name "$OPA_CONTAINER" \
  -p "${OPA_PORT}:8181" \
  -v "${REPO_ROOT}/policies/opa:/policies:ro" \
  "$OPA_IMAGE" run --server --addr=0.0.0.0:8181 /policies/agentsafe.rego >/dev/null

echo "[opa-live] waiting for OPA readiness"
for _ in $(seq 1 30); do
  if docker run --rm --add-host host.docker.internal:host-gateway curlimages/curl:8.11.1 -sSf "http://host.docker.internal:${OPA_PORT}/health?plugins" >/dev/null; then
    break
  fi
  sleep 1
done

echo "[opa-live] running live integration test"
docker run --rm --add-host host.docker.internal:host-gateway \
  -v "${REPO_ROOT}:/repo" -w /repo \
  -e AGENTSAFE_OPA_URL="http://host.docker.internal:${OPA_PORT}" \
  python:3.11-slim sh -lc \
  "pip install -q -e ./agentsafe pytest && pytest agentsafe/tests/test_opa_live_integration.py -q"

echo "[opa-live] success"
