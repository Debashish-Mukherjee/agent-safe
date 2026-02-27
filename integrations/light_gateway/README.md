# Light Gateway (Contract-First Mode B)

This integration provides a minimal OpenClaw-style tool boundary with strict
request/response schema for Mode B proxy enforcement.

## Canonical endpoint
- `POST /v1/tools/execute`
- `POST /v1/tools/plan` (stub)

## Request schema (`/v1/tools/execute`)
- `request_id` string (required)
- `actor` string (optional)
- `session_id` string (optional)
- `tool` string (required): e.g. `shell.run`, `http.fetch`
- `args` object (required)
- `context` object (optional)

## Response schema
- `request_id`
- `decision` (`allow`/`block` from gateway)
- `result` object
- `error` optional

## Example request
```json
{
  "request_id": "lg-1",
  "actor": "openclaw-agent",
  "session_id": "sess-1",
  "tool": "shell.run",
  "args": {"command": "ls"},
  "context": {"cwd": "/workspace"}
}
```

## Run demo
```bash
docker-compose -f integrations/light_gateway/docker-compose.yml up --build --abort-on-container-exit modeb-demo-runner
```
