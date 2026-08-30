#!/usr/bin/env bash
# Disposable Postgres 16 harness for File Artifact DB tests.
# Exit 2 = environment skip (NOT a pass). Exit 1 = failure. Exit 0 = pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ALLOW_FILE_ARTIFACT_DB_TESTS="${ALLOW_FILE_ARTIFACT_DB_TESTS:-1}"
export NODE_ENV="${NODE_ENV:-test}"
export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_PORT="${DB_PORT:-55432}"
export DB_USER="${DB_USER:-talonhound}"
export DB_PASSWORD="${DB_PASSWORD:-test}"
export DB_NAME="${DB_NAME:-talonhound_file_artifact_test}"

cd "$ROOT/backend"
exec node scripts/fileArtifactDbTests.js
