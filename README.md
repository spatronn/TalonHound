# TalonHound

Self-hosted threat intelligence and IOC management platform.

TalonHound ingests, deduplicates, enriches, and republishes indicators of compromise (IOCs)
from community and custom feeds, and lets analysts search, triage, and export them — all on
infrastructure you control.

TalonHound is **not** a SIEM, EDR, or XDR replacement. It focuses on IOC lifecycle management
and threat-feed workflows for self-hosted deployments.

## Features

- IOC ingestion from community and custom threat feeds, with per-source provenance and canonical deduplication
- Analyst search, triage, suppression, and bulk operations over large IOC sets
- Enrichment providers (VirusTotal, AbuseIPDB, IPinfo Lite, RDAP) — all optional and configured after install
- Published feeds (JSON / CSV / STIX / TAXII 2.1) with per-key access and rate limiting
- Role-based access control, audit logging, and a protected System Administrator account
- Scheduled backups with restore, and a single canonical system timezone across the whole stack

## Beta status

Current version: [`VERSION`](VERSION) (`0.1.0-beta.1`).

This is a **Beta** release. Core install and day-to-day workflows are usable, but interfaces,
configuration, and APIs may still evolve. Review release notes before upgrading, and keep
backups (see [`docs/backup-restore.md`](docs/backup-restore.md)).

## Requirements

- Ubuntu 24.04 (tested; other Linux may work)
- Docker Engine + Docker Compose plugin (the installer sets these up if missing)
- 4 GB RAM minimum (8 GB recommended), 2 vCPU, ~20 GB free disk
- Root access on the host

### Architecture support

| Platform | Status |
| --- | --- |
| **Ubuntu 24.04 / `linux/arm64`** (aarch64) | **Tested** — clean-host install, runtime, Setup Wizard, reboot, and source build validated |
| **`linux/amd64`** (x86_64) | **Build- and test-validated in CI** (native amd64 build + tests; emulated arm64 build). No clean-host amd64 install has been performed yet |

Official container images are published as multi-architecture OCI indexes covering
`linux/amd64` and `linux/arm64`, so `docker` pulls the image matching the host automatically.

## Installation

```bash
git clone https://github.com/spatronn/TalonHound.git
cd TalonHound
sudo ./installation.sh
```

The installer generates all required secrets, applies database migrations, starts the stack,
and prints the URL plus a **one-time Setup Code**:

```text
TalonHound installed successfully.

Open the following URL to complete setup:

    https://<server-ip>

Setup Code:

    XXXX-XXXX-XXXX-XXXX
```

Open `https://<server-ip>` in a browser and complete the Setup Wizard. The browser will show a
certificate warning on first run because TalonHound uses a self-signed certificate initially
(see [`proxy/README.md`](proxy/README.md) for Let's Encrypt / production certificates).

Re-running `sudo ./installation.sh` is safe: it never overwrites secrets, the `.env` file, the
database, or the completed setup state.

## First run

There is **no default administrator password.** The Setup Wizard guides you through:

1. **Setup Code** — the one-time code printed by the installer (proves you control the host)
2. **System validation** — PostgreSQL, Redis, schema, and application readiness
3. **Create System Administrator** — you choose the username and password; it is valid immediately
4. **System timezone** — the single IANA timezone used across logs, schedules, exports, and the UI

After completing setup you are redirected to the login page. The setup code is permanently
invalidated and the setup endpoints refuse further initialization.

Lost the setup code before finishing setup? Run `sudo ./installation.sh --rotate-setup-code`.

## Updates

To update an existing installation, see [`docs/deployment.md`](docs/deployment.md). Official
beta and stable releases are published through GitHub Releases and GHCR — see
[`docs/release.md`](docs/release.md).

## Documentation

- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Security:** [`SECURITY.md`](SECURITY.md)
- **Deployment & migrations:** [`docs/deployment.md`](docs/deployment.md)
- **Database migrations:** [`docs/database-migrations.md`](docs/database-migrations.md)
- **System timezone:** [`docs/system-timezone.md`](docs/system-timezone.md)
- **Backup & restore:** [`docs/backup-restore.md`](docs/backup-restore.md)
- **Release & versioning:** [`docs/release.md`](docs/release.md)
- **System diagram:** [`docs/system-diagram.md`](docs/system-diagram.md)
- **Container operations & tuning:** [`docs/container-operations-and-tuning.md`](docs/container-operations-and-tuning.md)

The installed version is shown in **Administration → Settings** and via authenticated
`GET /api/system/version`.

## Development (build from source)

`installation.sh` is the supported path for operators. Developers who build and run from source
directly (manual Docker Compose, explicit migrations, source rebuilds) should follow
[`docs/deployment.md`](docs/deployment.md), which documents the manual bring-up and migration
commands.
