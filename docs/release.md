# TalonHound Release and Versioning

TalonHound uses a single canonical product version stored in the repository root [`VERSION`](../VERSION) file.

## Release channels

| Channel | Example tag | Example VERSION | GitHub Release |
|--------|---------------|-----------------|----------------|
| Beta prerelease | `v0.1.0-beta.1` | `0.1.0-beta.1` | Prerelease |
| Release candidate | `v0.2.0-rc.1` | `0.2.0-rc.1` | Prerelease |
| Stable | `v1.0.0` | `1.0.0` | Normal release |

Git tags must use the form `v${VERSION}`. A release tag is rejected unless it exactly matches the canonical `VERSION` file.

Database migrations for the first public Beta are documented in [`docs/database-migrations.md`](database-migrations.md). Release manifests record `database.latestMigration` derived from repository migration files (baseline `001_core.sql` → `1` for v0.1.0-beta.1).

## Official artifacts

Each official release publishes:

- GitHub source snapshot for the tag
- GitHub Release notes and `release-manifest.json`
- GHCR container images:
  - `ghcr.io/spatronn/talonhound-backend`
  - `ghcr.io/spatronn/talonhound-frontend`
  - `ghcr.io/spatronn/talonhound-integration`
  - `ghcr.io/spatronn/talonhound-proxy`

Infrastructure dependencies remain upstream official images in `docker-compose.yml`:

- PostgreSQL
- Redis

Release manifests record immutable image digests (`sha256:...`). Tags are human-friendly identifiers; digests are the authoritative deployment identity.

## Development versus official release

### Development / existing production host workflow

Build from repository source with the default compose file:

```bash
docker compose up -d db redis
docker compose run --rm backend npm run migrate
docker compose up -d --build
```

Build metadata can be supplied with:

```bash
export TALONHOUND_VERSION="$(tr -d '\r\n' < VERSION)"
export TALONHOUND_COMMIT="$(git rev-parse HEAD)"
export TALONHOUND_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose build backend frontend
```

See also [`docs/deployment.md`](deployment.md) and [`scripts/release/deploy-application.sh`](../scripts/release/deploy-application.sh).

### Official release deployment

Use CI-built GHCR images with the release compose override:

```bash
export TALONHOUND_VERSION=0.1.0-beta.1
export TALONHOUND_BACKEND_IMAGE=ghcr.io/spatronn/talonhound-backend:${TALONHOUND_VERSION}
export TALONHOUND_FRONTEND_IMAGE=ghcr.io/spatronn/talonhound-frontend:${TALONHOUND_VERSION}
export TALONHOUND_INTEGRATION_IMAGE=ghcr.io/spatronn/talonhound-integration:${TALONHOUND_VERSION}
export TALONHOUND_PROXY_IMAGE=ghcr.io/spatronn/talonhound-proxy:${TALONHOUND_VERSION}

docker compose -f docker-compose.yml -f docker-compose.release.yml pull
docker compose -f docker-compose.yml -f docker-compose.release.yml up -d
```

Do not pass `--build` for official release deployments.

Future TalonHound updaters will consume `release-manifest.json` to select compatible versions and image digests. Automatic update polling is not implemented yet.

## Installed version visibility

- API: authenticated `GET /api/system/version`
- UI: **Administration → Settings → Installed Version**

## CI and release automation

- Normal pushes and pull requests run [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) only.
- Publishing to GHCR and GitHub Releases happens only from [`.github/workflows/release.yml`](../.github/workflows/release.yml) on trusted version tags (`v*`).
- Release images receive GitHub Artifact Attestations tied to their immutable digests.

## Configuration compatibility

Upgrades must preserve operator-managed `.env` and persistent Docker volumes. Release automation does not overwrite local configuration.

## Manual upgrade

A fully documented in-place upgrade path for switching between source-built and GHCR release images will be added with the updater phase. Until then, treat release deployments as new compose image selection using the manifest digests, preserving existing volumes and `.env`.
