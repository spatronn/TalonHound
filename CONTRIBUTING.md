# Contributing to TalonHound

Thanks for your interest in TalonHound. The project is maintainer-driven during Beta; focused contributions are welcome.

## Before you start

- Search existing issues before opening a new one.
- For **security vulnerabilities**, follow [`SECURITY.md`](SECURITY.md) — do **not** open a public issue.
- Keep pull requests small and focused on one change.

## Development setup

Operators should use `sudo ./installation.sh`. Developers building from source should follow [`docs/deployment.md`](docs/deployment.md).

## Pull requests

1. Branch from the latest `main`.
2. Include tests for behavioral changes when practical.
3. Do not commit secrets, `.env` files, dumps, or local scratch (`scripts/_tmp_*`).
4. Run the relevant unit tests for the area you touched (backend / frontend / integration).
5. Keep documentation updates in the same PR when behavior changes.

## Database migrations

- `backend/migrations/001_core.sql` is the public baseline; later files are forward-only.
- **Never** edit, squash, or delete a migration that has already shipped in a public release.
- Add new schema changes as a new sequential migration file.
- See [`docs/database-migrations.md`](docs/database-migrations.md).

## Code style

Match the surrounding code. Prefer clear, minimal changes over broad refactors in the same PR.

## Review

Maintainers may request changes, defer features, or close out-of-scope PRs during Beta while interfaces and configuration are still evolving.
