# Demo Runbook

## Quick Links

- System diagram: `docs/system-diagram.md`
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
