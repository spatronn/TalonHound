# TalonHound Upgrade

Safe, backup-first upgrades for public beta. Update **checks** are informational; **upgrades** are an explicit host CLI operation.

## Architecture

```text
Runtime version (VERSION / getProductVersionInfo)
        ↓
Backend update checker (cached HTTPS GET)
        ↓
Trusted channel manifest (updates/<channel>.json)
        ↓
Administration → Settings → Updates
```

```text
CLI upgrade
   ↓
Preflight
   ↓
Mandatory backup
   ↓
Exact GitHub Release + GHCR images
   ↓
Migrations
   ↓
Service transition
   ↓
Health + version validation
```

Upgrades never use `main`, `latest`, or mutable floating tags as the production target.

## Checking the installed version

- UI: **System → Settings → Installed Version**
- API: authenticated `GET /api/system/version`
- Host: `cat VERSION` or the `TALONHOUND_VERSION` value in `.env` after a release-image upgrade

## Checking for updates

Administrators open **System → Settings → Updates**.

- Automatic checks default to about every 24 hours (`UPDATE_CHECK_INTERVAL_HOURS`)
- **Check for Updates** forces a refresh
- **View Release Notes** opens the release URL from the channel manifest
- Failure to reach the update server does **not** affect `/healthz`, `/readyz`, workers, or login

Configuration (`.env` / compose; System Administrator / host operator):

```bash
UPDATE_CHECK_ENABLED=true
UPDATE_CHECK_INTERVAL_HOURS=24
# Optional override (HTTPS only). Default:
# https://raw.githubusercontent.com/spatronn/TalonHound/main/updates/beta.json
UPDATE_MANIFEST_URL=
UPDATE_CHANNEL=   # optional pin; otherwise derived from the installed SemVer
```

## Upgrade commands

```bash
sudo ./installation.sh --upgrade
sudo ./installation.sh --upgrade-to 0.1.0-beta.3
sudo ./installation.sh --upgrade --dry-run
```

Host Node.js is optional. When `node` is not installed on the host, upgrade helpers run inside the backend container.

Equivalent entrypoint:

```bash
sudo ./scripts/upgrade.sh --upgrade
```

### Lifecycle

1. Preflight (installation layout, Docker, DB, backup volume, version identity)
2. Disk space check (default minimum 15 GB free; `TALONHOUND_UPGRADE_DISK_MIN_GB`)
3. Resolve exact target (channel manifest or `--upgrade-to`)
4. Download and validate `release-manifest.json` for that tag
5. Create a mandatory pre-upgrade backup (`pre-upgrade-<from>-to-<to>-<timestamp>`)
6. Pin GHCR image references in `.env` (secrets and TLS are never regenerated)
7. Stop application services (PostgreSQL/Redis stay up)
8. Pull images and run `npm run migrate`
9. Start services with `docker-compose.release.yml`
10. Bounded `/healthz` + `/readyz` checks and confirm reported version equals the target

### Dry run

`--dry-run` performs resolution, artifact reachability, disk, Docker, and database checks without mutating schema, containers, or data.

## Failure and recovery

- Backup failure aborts before any schema or container mutation.
- Migration failure aborts further steps. Do **not** start an older application binary against a newer schema unless compatibility is known.
- Post-migration start/health failures print the pre-upgrade backup id and point to [`docs/backup-restore.md`](backup-restore.md).

Restore example:

```bash
sudo ./scripts/restore-stack.sh --backup-id pre-upgrade-0.1.0-beta.1-to-0.1.0-beta.3-20260904T120000Z --confirm
```

## Offline / restricted networks

If GitHub or the configured manifest URL is unreachable, update status shows **Update check failed**. A development / unversioned build (`dev`) still discovers the latest published channel version but reports **Development build** instead of up-to-date/outdated. A missing channel manifest (HTTP 404) reports **No release published**. The product remains fully usable in all of these cases. Perform upgrades from a host that can reach GitHub/GHCR, or stage images in a private registry and point image env vars accordingly after validating digests.

### Private GitHub repositories

The default channel URL is:

```text
https://raw.githubusercontent.com/spatronn/TalonHound/main/updates/<channel>.json
```

That URL is only readable when the repository (or that path) is public. For private forks or mirrors, set an HTTPS `UPDATE_MANIFEST_URL` that your installation can reach (internal static host, object storage, or a future `https://update.talonhound.io/v1/releases/beta.json`). No architecture change is required—configuration only.

## Channels

| Channel | Example | Manifest |
|--------|---------|----------|
| beta | `0.1.0-beta.3` | `updates/beta.json` |
| stable | `1.0.0` | `updates/stable.json` (published with the first stable release) |

Channel switching UI is intentionally out of scope for public beta; the installed SemVer derives the channel.

## Chosen distribution model

Beta upgrades consume **exact GHCR images** recorded in the per-release `release-manifest.json` (immutable digests + version tags). Source-tree `git pull` of `main` is not an upgrade path. Fresh installs may still source-build via `installation.sh`; the first upgrade switches the installation to release images while preserving `.env` and volumes.
