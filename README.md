# Demo Runbook

## Quick Links

- **Deployment & migrations:** `docs/deployment.md`
- System diagram: `docs/system-diagram.md`
- Container operations & tuning: `docs/container-operations-and-tuning.md`
- IOC exposure & impact scoring: `docs/risk-engine-analytics.md` (API fields: `risk_score`, `institution_risk_score`)

## Run

```bash
cd /opt/demo-runbook
docker compose up -d db redis clickhouse
docker compose run --rm backend npm run migrate   # explicit one-shot — see docs/deployment.md
docker compose up -d --build
```

For production-style ordering (migrate before backend/workers), see **`docs/deployment.md`**.

The **proxy** service terminates TLS on **443** and redirects **80 → HTTPS**. UI: `https://localhost` (first run uses a self-signed cert from `proxy/certs/`; browser warning is expected). See `proxy/README.md` for Let’s Encrypt / prod certs.

## Check

```bash
docker compose ps
docker compose logs --tail=100 proxy
docker compose logs --tail=100 backend
docker compose logs --tail=100 signal-engine
```

## IP Enrichment (IPinfo Lite)

- On-demand only: configure **Administration → Enrichment Providers → IPinfo Lite** (or set `IPINFO_LITE_TOKEN` in env).
- Used for IP IOCs and URL observables whose host is a public IP address.
- Results are cached per IP for 24 hours in `ioc_ip_enrichment`.

"# TalonHound" 
