#!/usr/bin/env node
/**
 * Threat Library artifact storage consistency report (read-only).
 *
 * Usage (inside backend or threat-library-worker container):
 *   node scripts/threat-library-artifact-audit.js
 *
 * Compares files under THREAT_LIBRARY_STORAGE_DIR/reports with
 * threat_report_artifacts.storage_key. Never modifies the filesystem or the
 * database; exits 1 when unreferenced files or missing artifacts are found.
 */
import pg from 'pg';
import { auditArtifactConsistency } from '../lib/threatLibrary/artifactStore.js';

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  max: 1
});

try {
  const { rows } = await pool.query(
    `SELECT storage_key FROM threat_report_artifacts WHERE storage_key IS NOT NULL`
  );
  const report = await auditArtifactConsistency(rows.map((r) => r.storage_key));
  console.log(JSON.stringify(report, null, 1));
  process.exitCode = report.unreferenced.length || report.missing.length ? 1 : 0;
} finally {
  await pool.end();
}
