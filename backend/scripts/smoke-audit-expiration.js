/**
 * E2E smoke: expiration worker emits a single ioc.expired audit per IOC (forward-fix).
 * Run inside backend container: node scripts/smoke-audit-expiration.js
 */
import '../lib/ensure-db-password.js';
import pg from 'pg';
import { createAuditLogService } from '../lib/auditLogService.js';
import { runExpirationWorkerBatch } from '../lib/iocExpiration.js';
import { AUDIT_ACTION, AUDIT_ACTION_LABELS } from '../lib/auditConstants.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const audit = createAuditLogService(pool);
const marker = `audit-exp-smoke-${Date.now()}`;

function fail(message, detail = null) {
  console.error('FAIL:', message);
  if (detail != null) console.error(JSON.stringify(detail, null, 2));
  process.exit(1);
}

async function loadFeeds(client, count) {
  const { rows } = await client.query(
    `SELECT integration_id AS feed_id, name, key
     FROM integration_feeds
     WHERE active IS DISTINCT FROM FALSE
     ORDER BY name
     LIMIT $1`,
    [count]
  );
  if (rows.length < count) {
    fail(`need at least ${count} integration feeds`, { found: rows.length });
  }
  return rows;
}

async function createFixture(client, { domain, feeds }) {
  const past = new Date(Date.now() - 3600_000).toISOString();
  const { rows: iocRows } = await client.query(
    `INSERT INTO ioc_items (observable, observable_type, source_name, confidence, status, note)
     VALUES ($1, 'domain', $2, 'medium', 'active', $3)
     RETURNING id, observable, observable_type`,
    [domain, 'audit-expiration-smoke', `${marker}-fixture`]
  );
  const ioc = iocRows[0];
  const membershipIds = [];

  for (const feed of feeds) {
    const { rows } = await client.query(
      `INSERT INTO ioc_feed_memberships (
         ioc_item_id, ioc_observable_type, feed_id, status, expires_at,
         expiration_reason, first_seen_in_feed, last_seen_in_feed
       )
       VALUES ($1, 'domain', $2::uuid, 'active', $3::timestamptz, 'policy_ttl', NOW(), NOW())
       RETURNING id`,
      [ioc.id, feed.feed_id, past]
    );
    membershipIds.push(rows[0].id);
  }

  return { ioc, membershipIds, feeds };
}

async function fetchIocAudits(client, iocId, since) {
  const { rows } = await client.query(
    `SELECT id, action, source, entity_type, entity_id, entity_display, metadata, created_at
     FROM audit_logs
     WHERE entity_type = 'ioc'
       AND entity_id = $1
       AND created_at >= $2
     ORDER BY created_at ASC`,
    [String(iocId), since]
  );
  return rows;
}

async function fetchMembershipAudits(client, membershipIds, since) {
  if (!membershipIds.length) return [];
  const { rows } = await client.query(
    `SELECT id, action, source, entity_type, entity_id, metadata, created_at
     FROM audit_logs
     WHERE action = 'ioc_feed_membership.expired'
       AND entity_id = ANY($1::text[])
       AND created_at >= $2
     ORDER BY created_at ASC`,
    [membershipIds.map(String), since]
  );
  return rows;
}

async function cleanupFixture(client, iocId, membershipIds) {
  await client.query(
    `DELETE FROM audit_logs
     WHERE (entity_type = 'ioc' AND entity_id = $1)
        OR (entity_type = 'ioc_feed_membership' AND entity_id = ANY($2::text[]))`,
    [String(iocId), membershipIds.map(String)]
  );
  await client.query(
    'DELETE FROM ioc_feed_memberships WHERE ioc_item_id = $1 AND ioc_observable_type = $2',
    [iocId, 'domain']
  );
  await client.query(
    'DELETE FROM ioc_items WHERE id = $1 AND observable_type = $2',
    [iocId, 'domain']
  );
}

function assertSingleIocExpiredAudit(audits, { ioc, feeds, expectFeedCount }) {
  const iocExpired = audits.filter((row) => row.action === AUDIT_ACTION.IOC_EXPIRED);
  const membershipExpired = audits.filter((row) => row.action === 'ioc_feed_membership.expired');

  if (membershipExpired.length > 0) {
    fail('unexpected ioc_feed_membership.expired audit rows', membershipExpired);
  }
  if (iocExpired.length !== 1) {
    fail(`expected exactly 1 ioc.expired audit, got ${iocExpired.length}`, audits);
  }

  const row = iocExpired[0];
  const title = AUDIT_ACTION_LABELS[AUDIT_ACTION.IOC_EXPIRED];
  if (title !== 'IOC Expired') {
    fail(`unexpected audit title mapping for ioc.expired: ${title}`);
  }
  if (row.source !== 'expiration-worker') {
    fail(`expected source expiration-worker, got ${row.source}`, row);
  }
  if (row.entity_display !== `domain · ${ioc.observable}`) {
    fail(`unexpected entity_display: ${row.entity_display}`, row);
  }

  const metadata = row.metadata || {};
  if (metadata.ioc_value !== ioc.observable) {
    fail('metadata.ioc_value mismatch', metadata);
  }
  if (metadata.ioc_observable_type !== 'domain') {
    fail('metadata.ioc_observable_type mismatch', metadata);
  }
  if (Number(metadata.ioc_id) !== Number(ioc.id)) {
    fail('metadata.ioc_id mismatch', metadata);
  }
  if (metadata.source !== 'expiration-worker') {
    fail('metadata.source should be expiration-worker', metadata);
  }

  const affected = Array.isArray(metadata.affected_feeds) ? metadata.affected_feeds : [];
  if (expectFeedCount === 1) {
    if (!metadata.feed_name) fail('metadata.feed_name missing for single-feed case', metadata);
    const feedName = feeds[0]?.name;
    if (metadata.feed_name !== feedName) {
      fail(`metadata.feed_name expected ${feedName}, got ${metadata.feed_name}`, metadata);
    }
  } else if (expectFeedCount === 2) {
    if (affected.length !== 2) {
      fail(`expected affected_feeds.length=2, got ${affected.length}`, metadata);
    }
    const names = affected.map((f) => f.feed_name).filter(Boolean).sort();
    const expected = feeds.map((f) => f.name).sort();
    if (JSON.stringify(names) !== JSON.stringify(expected)) {
      fail('affected_feeds feed_name mismatch', { names, expected, metadata });
    }
    if (!metadata.feed_name || !String(metadata.feed_name).includes(',')) {
      fail('metadata.feed_name should list multiple feeds', metadata);
    }
  }

  return row;
}

async function runScenario(client, feedCount) {
  const domain = `${marker}-${feedCount}f.invalid`;
  const since = new Date();
  const feeds = await loadFeeds(client, feedCount);
  const fixture = await createFixture(client, { domain, feeds });

  try {
    const batch = await runExpirationWorkerBatch(client, { audit, batchSize: 500 });
    const iocAudits = await fetchIocAudits(client, fixture.ioc.id, since);
    const membershipAudits = await fetchMembershipAudits(client, fixture.membershipIds, since);

    if (membershipAudits.length > 0) {
      fail(`scenario ${feedCount}-feed: membership.expired audits created`, membershipAudits);
    }

    assertSingleIocExpiredAudit(iocAudits, {
      ioc: fixture.ioc,
      feeds: fixture.feeds,
      expectFeedCount: feedCount
    });

    console.log(JSON.stringify({
      scenario: `${feedCount}_feed`,
      domain,
      ioc_id: fixture.ioc.id,
      batch,
      audit_count: iocAudits.length,
      feed_names: feeds.map((f) => f.name)
    }, null, 2));

    return { ok: true, feedCount };
  } finally {
    await cleanupFixture(client, fixture.ioc.id, fixture.membershipIds);
  }
}

async function main() {
  const client = await pool.connect();
  try {
    await runScenario(client, 1);
    await runScenario(client, 2);
    console.log('AUDIT_EXPIRATION_SMOKE_PASSED');
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
