# Local OPA Service

Run a local Open Policy Agent endpoint for `AGENTSAFE_OPA_URL`:

```bash
docker compose -f integrations/opa_local/docker-compose.yml up -d
export AGENTSAFE_OPA_URL=http://127.0.0.1:8181
```

Health check:

```bash
curl -fsS http://127.0.0.1:8181/health
```

Stop:

```bash
docker compose -f integrations/opa_local/docker-compose.yml down
```
