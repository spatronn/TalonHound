# TalonHound

Self-hosted threat intelligence and IOC management platform.

## Quick Links

- **Deployment & migrations:** [`docs/deployment.md`](docs/deployment.md)
- **Release & versioning:** [`docs/release.md`](docs/release.md)
- System diagram: [`docs/system-diagram.md`](docs/system-diagram.md)
- Container operations & tuning: [`docs/container-operations-and-tuning.md`](docs/container-operations-and-tuning.md)

## Run (development / source build)

```bash
cd /opt/TalonHound
docker compose up -d db redis
docker compose run --rm backend npm run migrate   # explicit one-shot — see docs/deployment.md
docker compose up -d --build
```

For production-style ordering (migrate before backend/workers), see [`docs/deployment.md`](docs/deployment.md).

**Clean install login** (first empty database only): `admin@talonhound.local` / `admin` — password change is required on first login. Not recreated after deletion or on later restarts.

The **proxy** service terminates TLS on **443** and redirects **80 → HTTPS**. UI: `https://localhost` (first run uses a self-signed cert from `proxy/certs/`; browser warning is expected). See [`proxy/README.md`](proxy/README.md) for Let’s Encrypt / prod certs.

## Check

```bash
docker compose ps
docker compose logs --tail=100 proxy
docker compose logs --tail=100 backend
curl -sk https://localhost/readyz
```

## Version

Canonical product version: [`VERSION`](VERSION)

Installed version is shown in **Administration → Settings** and via authenticated `GET /api/system/version`.

Official beta/stable releases are published through GitHub Releases and GHCR. See [`docs/release.md`](docs/release.md).

## IP Enrichment (IPinfo Lite)

- On-demand only: configure **Administration → Enrichment Providers → IPinfo Lite** (or set `IPINFO_LITE_TOKEN` in env).
- Used for IP IOCs and URL observables whose host is a public IP address.
- Results are cached per IP for 24 hours in `ioc_ip_enrichment`.
