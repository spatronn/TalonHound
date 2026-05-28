# ClickHouse Credential Drift Note

If ClickHouse uses a persistent volume, changing `CLICKHOUSE_PASSWORD` in `.env` does **not** automatically rotate existing CH user passwords.

## Symptoms
- Some services can connect, others fail with `AUTHENTICATION_FAILED (516)`
- Retro worker stale while container is still Up

## Verify
```bash
docker compose exec -T clickhouse clickhouse-client -u demo --password "$CLICKHOUSE_PASSWORD" -q "SELECT 1"
```

Also verify backend/retro/correlation containers are using the same password env.

## Remediation
- Keep all services on same `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD`
- If password was changed after first init, either:
  - update CH user password explicitly, or
  - recreate volume intentionally (data-destructive)
