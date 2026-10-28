#!/usr/bin/env bash
# Isolated end-to-end test: backup (PostgreSQL + Threat Library files) → restore
# into a second, empty PostgreSQL and file store → verify every restored
# artifact reference resolves to a file with the recorded sha256.
#
# Everything runs in throwaway containers on a private network with tmpfs data
# directories; no compose project, named volume or host port is touched.
#
#   scripts/test-backup-restore-threat-library-e2e.sh
#
# Env: TALONHOUND_E2E_IMAGE (default talonhound-backend:local) — any image with
# node, pg_dump/pg_restore and /app/node_modules; the repository source is
# mounted over it, so the code under test is this checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TALONHOUND_E2E_IMAGE:-talonhound-backend:local}"
RUN_ID="th-tl-e2e-$$"
NET="$RUN_ID-net"
WORK="$(mktemp -d "/tmp/${RUN_ID}.XXXX")"
PG_PASSWORD="e2e-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

cleanup() {
  docker rm -f "$RUN_ID-src" "$RUN_ID-dst" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  # Files written by root inside containers
  docker run --rm -v "$WORK:/w" alpine:latest sh -c 'rm -rf /w/*' >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n[e2e] %s\n' "$*"; }

docker network create --internal "$NET" >/dev/null
for side in src dst; do
  docker run -d --rm --name "$RUN_ID-$side" --network "$NET" --network-alias "pg-$side" \
    --tmpfs /var/lib/postgresql/data:rw,size=1g \
    -e POSTGRES_USER=talonhound -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB=talonhound \
    postgres:16-alpine >/dev/null
done
for side in src dst; do
  for _ in $(seq 1 60); do
    docker exec "$RUN_ID-$side" pg_isready -U talonhound -d talonhound >/dev/null 2>&1 && break
    sleep 1
  done
done
mkdir -p "$WORK/src-tl" "$WORK/src-backups" "$WORK/dst-tl"

# node in the image against this checkout: the source is mounted read-only and
# copied next to the image's node_modules (ESM resolution ignores NODE_PATH).
node_in() {
  local side="$1"; shift
  docker run --rm -i --network "$NET" \
    -v "$ROOT:/src:ro" -v "$WORK:/work" -w /src/backend \
\
    -e DB_HOST="pg-$side" -e DB_PORT=5432 -e DB_USER=talonhound -e DB_PASSWORD="$PG_PASSWORD" -e DB_NAME=talonhound \
    -e THREAT_LIBRARY_STORAGE_DIR="/work/$side-tl" -e BACKUP_DIR=/work/src-backups \
    -e ALLOW_BACKUP_DB_TESTS=1 \
    "$IMAGE" sh -c 'cp -r /src/backend /tmp/app && rm -rf /tmp/app/node_modules && ln -s /app/node_modules /tmp/app/node_modules && cd /tmp/app && "$@"' sh "$@"
}

step "migrate source and target databases"
node_in src node migrate.js >/dev/null
node_in dst node migrate.js >/dev/null

step "integration tests (real PostgreSQL, pg_dump --snapshot)"
IT_OUT="$(node_in src node --test lib/backup/threatLibraryBackup.integration.test.js 2>&1 || true)"
printf '%s
' "$IT_OUT" | grep -E '^ℹ (tests|pass|fail|skipped)|✔|✖' || true
printf '%s
' "$IT_OUT" | grep -qE '^ℹ pass 3$' || { echo "[e2e] integration tests did not all pass" >&2; printf '%s
' "$IT_OUT" | tail -40 >&2; exit 1; }

step "seed reports with HTML and PDF sources, then back up"
node_in src node --input-type=module -e '
import pg from "pg";
import { createThreatReport, insertArtifact } from "./lib/threatLibrary/store.js";
import { storeArtifactBuffer } from "./lib/threatLibrary/artifactStore.js";
import { createBackupRow, getBackupById } from "./lib/backup/backupStore.js";
import { executeBackupJob } from "./lib/backup/runBackup.js";
import { generateBackupId } from "./lib/backup/ids.js";
const pool = new pg.Pool({ host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME });
for (let i = 0; i < 6; i += 1) {
  const r = await createThreatReport(pool, { title: `e2e report ${i}`, source_type: i % 3 === 0 ? "pdf" : "url", import_status: "ready", analysis_status: "ready" });
  const parts = i % 3 === 0 ? [[`%PDF-1.7 e2e ${i} ` + "x".repeat(5000 + i), ".pdf", "pdf_upload"]] : [[`<html>e2e ${i}</html>` + "y".repeat(20000 * i), ".html", "url_fetch"]];
  for (const [c, ext, type] of parts) {
    const s = await storeArtifactBuffer(r.id, Buffer.from(c), { ext });
    await insertArtifact(pool, r.id, { artifact_type: type, size_bytes: s.sizeBytes, sha256: s.sha256, storage_key: s.storageKey });
  }
  await insertArtifact(pool, r.id, { artifact_type: "canonical_document" });
}
const row = await createBackupRow(pool, { backupId: generateBackupId(), triggerType: "manual" });
await executeBackupJob(pool, row.id, { logger: {} });
const done = await getBackupById(pool, row.id);
console.log(JSON.stringify({ status: done.status, error: done.error_code, archive: done.archive_filename, files_size_bytes: Number(done.files_size_bytes), tl: done.manifest?.components?.threat_library }));
if (done.status !== "completed") process.exit(1);
await pool.end();
' | tee "$WORK/backup.json"
ARCHIVE="$(sed -n 's/.*"archive":"\([^"]*\)".*/\1/p' "$WORK/backup.json")"
[ -n "$ARCHIVE" ] || { echo "[e2e] backup failed" >&2; exit 1; }

step "verify archive (checksums, Threat Library component, pg_restore --list)"
node_in src node --input-type=module -e "
import { verifyBackupArchive } from './lib/backup/verify.js';
const r = await verifyBackupArchive('/work/src-backups/$ARCHIVE');
console.log(JSON.stringify({ ok: r.ok, error: r.error, threatLibrary: r.threatLibrary }));
if (!r.ok) process.exit(1);
"

step "extract archive and run the restore CLI checks used by restore-stack.sh"
mkdir -p "$WORK/extract"
node_in src node --input-type=module -e "
import { extractTarGz } from './lib/backup/archive.js';
await extractTarGz('/work/src-backups/$ARCHIVE', '/work/extract');
"
BUNDLE_NAME="$(ls "$WORK/extract")"
BUNDLE="/work/extract/$BUNDLE_NAME"
node_in dst node scripts/restore-threat-library-artifacts.js verify "$BUNDLE"

step "interrupted restore: stage then abort leaves the target store untouched"
mkdir -p "$WORK/dst-tl/reports/777" && echo keep > "$WORK/dst-tl/reports/777/existing.html"
node_in dst node scripts/restore-threat-library-artifacts.js stage "$BUNDLE" --id e2e-abort
node_in dst node scripts/restore-threat-library-artifacts.js abort --id e2e-abort
test -f "$WORK/dst-tl/reports/777/existing.html"
test ! -e "$WORK/dst-tl/.restore-e2e-abort"
echo "[e2e] abort ok"

step "restore: pg_restore into empty target, then stage + commit Threat Library files"
docker exec -i "$RUN_ID-dst" psql -U talonhound -d postgres -v ON_ERROR_STOP=1 >/dev/null <<SQL
DROP DATABASE talonhound WITH (FORCE);
CREATE DATABASE talonhound OWNER talonhound;
SQL
docker cp "$WORK/extract/$BUNDLE_NAME/database/postgres.dump" "$RUN_ID-dst:/tmp/restore.dump"
docker exec "$RUN_ID-dst" pg_restore -U talonhound -d talonhound --no-owner --no-acl --exit-on-error /tmp/restore.dump
node_in dst node scripts/restore-threat-library-artifacts.js stage "$BUNDLE" --id e2e-1
node_in dst node scripts/restore-threat-library-artifacts.js commit --id e2e-1

step "verify restored references resolve to real files with matching sha256"
node_in dst node --input-type=module -e '
import crypto from "node:crypto";
import fs from "node:fs";
import pg from "pg";
import { readArtifactBuffer } from "./lib/threatLibrary/artifactStore.js";
const pool = new pg.Pool({ host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME });
const { rows } = await pool.query("SELECT id, report_id, storage_key, sha256 FROM threat_report_artifacts WHERE storage_key IS NOT NULL");
const { rows: reps } = await pool.query("SELECT COUNT(*)::int AS n FROM threat_reports");
let ok = 0; const bad = [];
for (const r of rows) {
  try {
    const buf = await readArtifactBuffer(r.storage_key);
    const h = crypto.createHash("sha256").update(buf).digest("hex");
    if (h === r.sha256) ok += 1; else bad.push(`${r.storage_key}: sha mismatch`);
  } catch (e) { bad.push(`${r.storage_key}: ${e.code}`); }
}
const prev = fs.existsSync("/work/dst-tl/.reports-pre-restore-e2e-1/777/existing.html");
console.log(JSON.stringify({ reports: reps[0].n, referenced: rows.length, resolved: ok, missing_or_corrupt: bad, previous_tree_kept: prev }));
await pool.end();
if (bad.length || rows.length === 0 || !prev) process.exit(1);
'

step "shell detection (restore-stack.sh helpers): format 3 vs legacy bundles"
# Runs as root in a container: the extracted bundle is root-owned with 0750/0640
# modes (restore-stack.sh extracts as the invoking user, so it can read its own).
docker run --rm -i -v "$ROOT:/src:ro" -v "$WORK:/work" alpine:latest sh -s "$BUNDLE" <<'SH'
set -eu
. /src/scripts/lib/backup-common.sh
expect_mode() {
  TL_MODE=""
  detect_threat_library_component "$1" || { echo "[e2e] detection failed for $1" >&2; exit 1; }
  [ "$TL_MODE" = "$2" ] || { echo "[e2e] expected TL_MODE=$2 for $1, got $TL_MODE" >&2; exit 1; }
  echo "[e2e] $3 → TL_MODE=$TL_MODE"
}
expect_mode "$1" full "format 3 bundle"
mkdir -p /work/legacy /work/broken
printf '{"format_version": 2, "application": "TalonHound", "components": {"postgres": {}}}' > /work/legacy/manifest.json
expect_mode /work/legacy legacy "format 2 bundle"
printf '{"format_version": 3, "application": "TalonHound", "components": {"postgres": {}}}' > /work/broken/manifest.json
if detect_threat_library_component /work/broken 2>/dev/null; then echo "[e2e] format 3 without component accepted" >&2; exit 1; fi
echo "[e2e] format 3 without component refused"
SH

echo
echo "[e2e] PASS"
