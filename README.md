# Demo Runbook

## Quick Links

- System diagram: `docs/system-diagram.md`
- Container operations & tuning: `docs/container-operations-and-tuning.md`

## Run

```bash
cd /opt/demo-runbook
docker compose up -d --build
```

The **proxy** service terminates TLS on **443** and redirects **80 → HTTPS**. UI: `https://localhost` (first run uses a self-signed cert from `proxy/certs/`; browser warning is expected). See `proxy/README.md` for Let’s Encrypt / prod certs.

## Check

```bash
docker compose ps
docker compose logs --tail=100 proxy
docker compose logs --tail=100 backend
docker compose logs --tail=100 signal-engine
```
