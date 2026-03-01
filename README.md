# Demo Runbook

## Quick Links

- Windows demo setup: `docs/windows-demo-config.md`
- Container operations & tuning: `docs/container-operations-and-tuning.md`

## Run

```bash
cd /opt/demo-runbook
docker compose up -d --build
```

## Check

```bash
docker compose ps
docker compose logs --tail=100 backend
docker compose logs --tail=100 signal-engine
```
