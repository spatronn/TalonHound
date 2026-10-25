/**
 * Report lifecycle lock protocol (tl-report-lifecycle-lock-v1).
 *
 * Invariant: a committed finalized report (analysis_status ready / skipped)
 * never gains an unresolved linked IOC Source or a pending actionable
 * Indicator, except through an explicit, authorized lifecycle transition that
 * moves it out of the finalized phase first (Refresh extraction / Retry /
 * Rerun AI claim the report; Reopen for review records a durable audit row).
 *
 * Every transaction that can introduce such an obligation locks the parent
 * report row FIRST, then its child rows:
 *
 *   finalize   SELECT … FROM threat_reports … FOR UPDATE
 *   mutations  SELECT … FROM threat_reports … FOR KEY SHARE
 *
 * FOR UPDATE conflicts with FOR KEY SHARE, so finalization and an in-flight
 * mutation of the same report always serialize, in either order. KEY SHARE
 * does not conflict with ordinary report-row updates (progress, status) or
 * with other mutations, so the protocol never blocks unrelated work. The
 * mutation re-reads the report under its lock (a locking read returns the
 * latest committed row in READ COMMITTED), so a finalize that committed while
 * it waited is seen, and the mutation refuses (`report_finalized`) instead of
 * landing an obligation on a finalized report. A future child insert is
 * covered because the mutation takes the parent lock itself; foreign-key
 * locks and `NOT EXISTS` checks alone are not relied upon.
 *
 * Lock order is always report → candidate rows → source rows (deterministic).
 */

import { resolveReportPhase, REPORT_PHASES } from './reportPhase.js';
import { reviewActionableIndicatorSql } from './indicatorMembership.js';

export const REPORT_LIFECYCLE_LOCK_VERSION = 'tl-report-lifecycle-lock-v1';
export const REPORT_FINALIZED_CODE = 'report_finalized';

/** PostgreSQL deadlock / serialization failures a short transaction may retry. */
export const RETRYABLE_TX_CODES = Object.freeze(['40P01', '40001']);

export class ReportFinalizedError extends Error {
  constructor(message = 'The report is finalized. Reopen it for review before adding sources or indicators.') {
    super(message);
    this.code = REPORT_FINALIZED_CODE;
    this.status = 409;
  }
}

export function isFinalizedReport(row) {
  return resolveReportPhase(row) === REPORT_PHASES.FINALIZED;
}

/**
 * Lock the report row for a mutation that may add an obligation.
 * @param {{ query: Function }} client a client inside a transaction
 * @param {number} reportId
 */
export async function lockReportForMutation(client, reportId) {
  const { rows } = await client.query(
    `SELECT id, public_id, analysis_status, import_status, finalized_at
       FROM threat_reports WHERE id = $1 FOR KEY SHARE`,
    [reportId]
  );
  return rows[0] || null;
}

/**
 * Lock the report row for finalize / reopen (exclusive against mutations).
 * @param {{ query: Function }} client
 * @param {number} reportId
 */
export async function lockReportForFinalize(client, reportId) {
  const { rows } = await client.query(`SELECT * FROM threat_reports WHERE id = $1 FOR UPDATE`, [reportId]);
  return rows[0] || null;
}

/** Ids of pending actionable Indicators of a report (the finalize review obligation). */
export async function pendingObligationIds(client, reportId) {
  const { rows } = await client.query(
    `SELECT c.id FROM threat_report_candidates c
      WHERE c.report_id = $1
        AND COALESCE(c.review_status, 'pending') = 'pending'
        AND ${reviewActionableIndicatorSql('c')}`,
    [reportId]
  );
  return new Set(rows.map((r) => Number(r.id)));
}

/**
 * Run `fn(client)` in a transaction: its own when `db` is a pool, the
 * caller's when `db` is already a checked-out client.
 * @template T
 * @param {object} db
 * @param {(client: object) => Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function inReportTransaction(db, fn) {
  // Same contract as store.acquireDbSession (kept local: store.js imports this module).
  const owned = typeof db?.release !== 'function' && typeof db?.connect === 'function';
  const client = owned ? await db.connect() : db;
  try {
    if (owned) await client.query('BEGIN');
    const out = await fn(client);
    if (owned) await client.query('COMMIT');
    return out;
  } catch (err) {
    if (owned) {
      try {
        await client.query('ROLLBACK');
      } catch {
        /* ignore */
      }
    }
    throw err;
  } finally {
    if (owned) client.release();
  }
}
