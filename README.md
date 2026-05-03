# Demo Runbook

## Quick Links

- System diagram: `docs/system-diagram.md`
- Container operations & tuning: `docs/container-operations-and-tuning.md`
- Risk engine analytics: `docs/risk-engine-analytics.md`

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
docker compose logs --tail=100 enrichment-sync-job
```

## Daily ASN Enrichment

- Container: `demo-enrichment-sync-job`
- Purpose: Downloads ASN source zip, extracts JSON, and refreshes ASN lookup data via batch import + atomic swap.
- Schedule: every 24 hours (`ENRICHMENT_SYNC_INTERVAL_MS=86400000`)
- Source URL (default): `https://geoip.oxl.app/file/asn_full.json.zip`

