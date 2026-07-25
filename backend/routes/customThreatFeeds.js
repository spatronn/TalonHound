import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';
import { validateHexColor } from '../lib/sourceColor.js';
import {
  validateCustomFeedAuth,
  normalizeCustomFeedAuth,
  buildCustomFeedAuthSummary
} from '../lib/customThreatFeedAuth.js';
import { findActiveRunningJobForSource } from '../lib/integrationQueueRecovery.js';
import { syncSingleFeedSchedule } from '../lib/integrationFeedScheduleSync.js';
import { formatExpirationSummary } from '../lib/iocExpiration.js';
import {
  CUSTOM_FEED_JOB_NAME,
  CUSTOM_FEED_KEY_PREFIX,
  FEED_FORMATS,
  FIXED_IOC_TYPES,
  IOC_TYPE_MODES,
  extractUrlHost,
  generateCustomFeedKey,
  sanitizeUrlForDisplay,
  validateFeedUrl,
  normalizeCustomFeedName,
  findCustomFeedNameConflict,
  DUPLICATE_CUSTOM_FEED_NAME_ERROR,
  isCustomFeedNameUniqueViolation
} from '../lib/customThreatFeedUtils.js';
import { fetchFeedUrl } from '../lib/customThreatFeedFetch.js';
import { parseFeedContent, buildParseSample } from '../lib/customThreatFeedParser.js';
import { isAllowedScheduleCron, isRunOnceSchedule } from '../lib/integrationSchedule.js';

const DEFAULT_SCHEDULE_CRON = '0 * * * *';
const DEFAULT_CONFIDENCE = 'medium';

const FEED_AUDIT_FIELDS = ['name', 'format', 'ioc_type_mode', 'fixed_ioc_type', 'description', 'color'];

const FEED_ROW_SELECT = `
  SELECT c.*,
         f.key AS integration_key,
         f.name AS feed_name,
         f.color AS feed_color,
         f.schedule_cron AS schedule,
         f.default_confidence,
         f.active AS integration_active,
         f.archived_at,
         f.credentials,
         p.enabled AS exp_enabled,
         p.expiration_mode,
         p.ttl_days AS exp_ttl_days,
         p.grace_days AS exp_grace_days,
         lr.status AS last_run_status,
         lr.finished_at AS last_run_finished_at,
         lr.error_message AS last_run_error,
         ls.finished_at AS last_success_at
  FROM custom_threat_feeds c
  JOIN integration_feeds f ON f.integration_id = c.feed_id
  LEFT JOIN threat_feed_expiration_policies p
    ON p.feed_id = f.integration_id AND p.observable_type = 'all'
  LEFT JOIN LATERAL (
    SELECT status, finished_at, error_message
    FROM custom_threat_feed_runs r
    WHERE r.feed_id = c.id
    ORDER BY started_at DESC
    LIMIT 1
  ) lr ON TRUE
  LEFT JOIN LATERAL (
    SELECT finished_at
    FROM custom_threat_feed_runs r
    WHERE r.feed_id = c.id AND r.status IN ('success', 'partial_success')
    ORDER BY finished_at DESC NULLS LAST
    LIMIT 1
  ) ls ON TRUE
`;

function actorFromReq(req) {
  const publicId = req.user?.publicId;
  const actorId = publicId && /^[0-9a-f-]{36}$/i.test(String(publicId)) ? String(publicId) : null;
  return {
    actor: req.user?.username || req.user?.email || 'unknown',
    actor_id: actorId
  };
}

function validateFeedPayload(body, partial = false) {
  const errors = [];
  const name = body?.name !== undefined ? normalizeCustomFeedName(body.name) : '';
  if (!partial && !name) errors.push('name is required');
  if (partial && body?.name !== undefined && !name) errors.push('name is required');
  if (body?.url !== undefined || !partial) {
    const urlCheck = validateFeedUrl(body?.url);
    if (!urlCheck.ok) errors.push(urlCheck.error);
  }
  if (body?.format !== undefined && !FEED_FORMATS.includes(body.format)) {
    errors.push(`format must be one of: ${FEED_FORMATS.join(', ')}`);
  }
  if (body?.ioc_type_mode !== undefined && !IOC_TYPE_MODES.includes(body.ioc_type_mode)) {
    errors.push(`ioc_type_mode must be one of: ${IOC_TYPE_MODES.join(', ')}`);
  }
  if (body?.fixed_ioc_type !== undefined && body.fixed_ioc_type != null && body.fixed_ioc_type !== '') {
    if (!FIXED_IOC_TYPES.includes(body.fixed_ioc_type)) {
      errors.push(`fixed_ioc_type must be one of: ${FIXED_IOC_TYPES.join(', ')}`);
    }
  }
  if (body?.ioc_type_mode === 'fixed' && !partial && !FIXED_IOC_TYPES.includes(body?.fixed_ioc_type)) {
    errors.push('fixed_ioc_type is required when ioc_type_mode is fixed');
  }
  if (body?.schedule_cron !== undefined) {
    const scheduleCron = String(body.schedule_cron || '').trim();
    if (!isAllowedScheduleCron(scheduleCron)) {
      errors.push('schedule_cron is invalid');
    }
  }
  if (body?.auth !== undefined) {
    const authCheck = validateCustomFeedAuth(body.auth);
    if (!authCheck.ok) errors.push(`auth: ${authCheck.error}`);
  }
  if (body?.color !== undefined) {
    const colorCheck = validateHexColor(body.color);
    if (!colorCheck.ok) errors.push(colorCheck.error);
  }
  return errors;
}

function buildExpirationPolicy(row) {
  if (row.expiration_mode == null && row.exp_enabled == null) return null;
  return {
    enabled: Boolean(row.exp_enabled),
    expiration_mode: row.expiration_mode || 'never',
    ttl_days: row.exp_ttl_days ?? null,
    grace_days: row.exp_grace_days ?? null
  };
}

async function fetchFeedRow(pool, id) {
  const { rows } = await pool.query(
    `${FEED_ROW_SELECT}
     WHERE c.id = $1::uuid
     LIMIT 1`,
    [id]
  );
  return rows[0] || null;
}

function serializeFeedRow(row) {
  if (!row) return null;
  const expirationPolicy = buildExpirationPolicy(row);
  return {
    id: row.id,
    feed_id: row.feed_id,
    integration_key: row.integration_key,
    key: row.integration_key,
    name: row.feed_name,
    color: row.feed_color || null,
    url_host: row.url_host,
    url_display: sanitizeUrlForDisplay(row.url),
    format: row.format,
    ioc_type_mode: row.ioc_type_mode,
    fixed_ioc_type: row.fixed_ioc_type,
    schedule: row.schedule || DEFAULT_SCHEDULE_CRON,
    default_confidence: row.default_confidence || DEFAULT_CONFIDENCE,
    active: row.integration_active !== false,
    expiration_policy: expirationPolicy,
    expiration_summary: expirationPolicy ? formatExpirationSummary(expirationPolicy) : 'Never',
    timeout_ms: row.timeout_ms,
    description: row.description,
    deactivated_at: row.deactivated_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_success_at: row.last_success_at || null,
    last_run_status: row.last_run_status || null,
    last_run_finished_at: row.last_run_finished_at || null,
    last_error: row.last_run_error || null,
    archived_at: row.archived_at || null,
    feed_kind: 'custom',
    feed_update_mode: 'snapshot',
    auth: buildCustomFeedAuthSummary(row.credentials || {})
  };
}

function auditFeedMeta(row) {
  return {
    feed_id: row?.id,
    feed_name: row?.feed_name || row?.name,
    url_host: row?.url_host || extractUrlHost(row?.url)
  };
}

async function queueCustomFeedSync(pool, importQueue, feedRow, triggeredBy, manualPriority) {
  const integrationKey = feedRow.integration_key;
  const blocking = await findActiveRunningJobForSource(pool, integrationKey);
  if (blocking) {
    return {
      ok: false,
      status: 409,
      body: {
        message: `A sync is already in progress for this feed (job ${blocking.job_id}).`,
        blocking_job_id: blocking.job_id
      }
    };
  }

  const job = await importQueue.add(
    CUSTOM_FEED_JOB_NAME,
    { triggeredBy, integration_key: integrationKey, custom_feed_id: feedRow.id },
    { priority: manualPriority }
  );

  await pool.query(
    `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, updated_at)
     VALUES ($1, $2, $3, 'queued', $4, NOW(), NOW())
     ON CONFLICT (job_id)
     DO UPDATE SET status='queued', triggered_by=$4, updated_at=NOW(), started_at=NULL, finished_at=NULL, error_message=NULL, failure_type=NULL`,
    [String(job.id), integrationKey, CUSTOM_FEED_JOB_NAME, triggeredBy]
  );

  return { ok: true, job_id: String(job.id) };
}

async function computeDeleteCheck(pool, feedRow) {
  const feedId = feedRow.feed_id;
  const ctfId = feedRow.id;
  const integrationKey = feedRow.integration_key;
  const enabled = feedRow.active !== false;

  const [runsRes, activeMemberRes, historicalMemberRes, jobsRes, publishedRes] = await Promise.all([
    pool.query(
      `SELECT COUNT(*)::int AS cnt FROM custom_threat_feed_runs
       WHERE feed_id = $1::uuid AND status IN ('success', 'partial_success')`,
      [ctfId]
    ),
    pool.query(
      `SELECT COUNT(*)::int AS cnt FROM ioc_feed_memberships
       WHERE feed_id = $1::uuid AND status = 'active' AND purged_at IS NULL`,
      [feedId]
    ),
    pool.query(
      `SELECT COUNT(*)::int AS cnt FROM ioc_feed_memberships
       WHERE feed_id = $1::uuid AND (status != 'active' OR purged_at IS NOT NULL)`,
      [feedId]
    ),
    pool.query(
      `SELECT COUNT(*)::int AS cnt FROM integration_queue_jobs
       WHERE integration_key = $1 AND status IN ('queued', 'running')`,
      [integrationKey]
    ),
    pool.query(
      `SELECT COUNT(*)::int AS cnt FROM published_feeds
       WHERE include_feed_keys IS NOT NULL
         AND include_feed_keys @> to_jsonb(ARRAY[$1::text])`,
      [integrationKey]
    )
  ]);

  const successfulRunCount = Number(runsRes.rows[0]?.cnt || 0);
  const activeMemberCount = Number(activeMemberRes.rows[0]?.cnt || 0);
  const historicalMemberCount = Number(historicalMemberRes.rows[0]?.cnt || 0);
  const queuedOrRunningCount = Number(jobsRes.rows[0]?.cnt || 0);
  const publishedDepCount = Number(publishedRes.rows[0]?.cnt || 0);

  let canDelete = false;
  let deleteMode = null;
  let reason = null;
  let requiresPurge = false;
  let requiresDisable = false;

  if (queuedOrRunningCount > 0) {
    reason = 'job_running_or_queued';
  } else if (activeMemberCount > 0) {
    // Active IOCs always block delete regardless of published deps.
    reason = 'requires_purge';
    requiresPurge = true;
    requiresDisable = true;
  } else if (publishedDepCount > 0) {
    // No active IOCs but still linked to published feeds.
    // Allow a cleanup delete that atomically unlinks then removes the feed.
    canDelete = true;
    deleteMode = 'cleanup_delete';
  } else if (successfulRunCount === 0 && historicalMemberCount === 0) {
    canDelete = true;
    deleteMode = 'direct_delete';
  } else if (feedRow.integration_active === false) {
    canDelete = true;
    deleteMode = 'soft_delete';
  } else {
    reason = 'requires_disable';
    requiresDisable = true;
  }

  return {
    feed_id: feedRow.id,
    name: feedRow.feed_name,
    can_delete: canDelete,
    delete_mode: deleteMode,
    reason,
    successful_run_count: successfulRunCount,
    active_membership_count: activeMemberCount,
    historical_membership_count: historicalMemberCount,
    queued_or_running_job_count: queuedOrRunningCount,
    published_feed_dependency_count: publishedDepCount,
    requires_purge: requiresPurge,
    requires_disable: requiresDisable
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 * @param {{ importQueue: import('bullmq').Queue, manualJobPriority: number }} deps
 */
export function registerCustomThreatFeedRoutes(app, pool, audit, deps) {
  const { importQueue, manualJobPriority = 1 } = deps;

  app.get('/api/custom-threat-feeds', async (_req, res) => {
    try {
      const { rows } = await pool.query(
        `${FEED_ROW_SELECT}
         WHERE c.deactivated_at IS NULL
         ORDER BY c.created_at DESC`
      );
      return res.json({ feeds: rows.map(serializeFeedRow) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list Custom Threat Feeds', detail: err.message });
    }
  });

  app.post('/api/custom-threat-feeds', requireRole(ROLES.ADMIN), async (req, res) => {
    const body = req.body || {};
    const errors = validateFeedPayload(body, false);
    if (errors.length) return res.status(400).json({ message: errors.join('; ') });

    const feedName = normalizeCustomFeedName(body.name);
    const nameConflict = await findCustomFeedNameConflict(pool, feedName);
    if (nameConflict) {
      console.warn('[custom-threat-feeds] duplicate name rejected on create', { name: feedName });
      return res.status(409).json({ error: DUPLICATE_CUSTOM_FEED_NAME_ERROR });
    }

    const urlCheck = validateFeedUrl(body.url);
    const feedKey = generateCustomFeedKey();
    const scheduleCron = isAllowedScheduleCron(body.schedule_cron)
      ? String(body.schedule_cron).trim()
      : DEFAULT_SCHEDULE_CRON;
    const { actor, actor_id: actorId } = actorFromReq(req);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const authValidated = validateCustomFeedAuth(body.auth ?? null);
      const newCredentials = normalizeCustomFeedAuth(authValidated.value, {});

      const colorCheck = validateHexColor(body.color);
      const integrationInsert = await client.query(
        `INSERT INTO integration_feeds (
           key, name, source_url, schedule_cron, trust_level, active,
           feed_kind, feed_update_mode, default_confidence, credentials, color, integration_id
         ) VALUES ($1, $2, $3, $4, 'not_categorized', TRUE, 'custom', 'snapshot', $5, $6::jsonb, $7, gen_random_uuid())
         RETURNING integration_id, key, name`,
        [
          feedKey,
          feedName,
          sanitizeUrlForDisplay(body.url),
          scheduleCron,
          DEFAULT_CONFIDENCE,
          JSON.stringify(newCredentials),
          colorCheck.value
        ]
      );
      const integration = integrationInsert.rows[0];

      const customInsert = await client.query(
        `INSERT INTO custom_threat_feeds (
           feed_id, url, url_host, format, ioc_type_mode, fixed_ioc_type,
           timeout_ms, description, created_by, created_by_username
         ) VALUES (
           $1::uuid, $2, $3, $4, $5, $6,
           $7, $8, $9::uuid, $10
         )
         RETURNING id`,
        [
          integration.integration_id,
          urlCheck.url,
          urlCheck.url_host,
          body.format || 'auto',
          body.ioc_type_mode || 'auto',
          body.ioc_type_mode === 'fixed' ? body.fixed_ioc_type : null,
          30000,
          body.description ? String(body.description).trim() : null,
          actorId,
          actor
        ]
      );

      await client.query('COMMIT');
      await syncSingleFeedSchedule(pool, importQueue, feedKey, { logPrefix: '[custom-feeds]' });
      if (isRunOnceSchedule(scheduleCron)) {
        console.log('[custom-feeds] custom feed schedule set to run_once', { feed_key: feedKey });
      }

      const row = await fetchFeedRow(pool, customInsert.rows[0].id);
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.CUSTOM_FEED_CREATED,
        entityType: AUDIT_ENTITY.CUSTOM_THREAT_FEED,
        entityId: row.id,
        entityDisplay: row.feed_name,
        metadata: {
          ...auditFeedMeta(row),
          ...pickSafeFields(body, FEED_AUDIT_FIELDS),
          actor
        }
      }).catch(() => {});

      return res.status(201).json({ feed: serializeFeedRow(row) });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      if (isCustomFeedNameUniqueViolation(err)) {
        console.warn('[custom-threat-feeds] duplicate name rejected on create (db)', { name: feedName });
        return res.status(409).json({ error: DUPLICATE_CUSTOM_FEED_NAME_ERROR });
      }
      console.error('[custom-threat-feeds] create failed', err?.message || err);
      return res.status(500).json({ message: 'Failed to create Custom Threat Feed', detail: err.message });
    } finally {
      client.release();
    }
  });

  app.get('/api/custom-threat-feeds/:id', async (req, res) => {
    try {
      const row = await fetchFeedRow(pool, req.params.id);
      if (!row) return res.status(404).json({ message: 'Custom Threat Feed not found' });
      return res.json({ feed: serializeFeedRow(row) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load Custom Threat Feed', detail: err.message });
    }
  });

  app.put('/api/custom-threat-feeds/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const body = req.body || {};
    const errors = validateFeedPayload(body, true);
    if (errors.length) return res.status(400).json({ message: errors.join('; ') });

    const existing = await fetchFeedRow(pool, req.params.id);
    if (!existing || existing.deactivated_at) {
      return res.status(404).json({ message: 'Custom Threat Feed not found' });
    }

    const urlCheck = body.url !== undefined ? validateFeedUrl(body.url) : { ok: true, url: existing.url, url_host: existing.url_host };
    if (!urlCheck.ok) return res.status(400).json({ message: urlCheck.error });

    if (body.name !== undefined) {
      const feedName = normalizeCustomFeedName(body.name);
      const nameConflict = await findCustomFeedNameConflict(pool, feedName, existing.id);
      if (nameConflict) {
        console.warn('[custom-threat-feeds] duplicate name rejected on update', {
          name: feedName,
          feed_id: existing.id
        });
        return res.status(409).json({ error: DUPLICATE_CUSTOM_FEED_NAME_ERROR });
      }
    }

    const { actor, actor_id: actorId } = actorFromReq(req);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      if (body.name !== undefined) {
        await client.query(
          `UPDATE integration_feeds SET name = $2, updated_at = NOW() WHERE integration_id = $1::uuid`,
          [existing.feed_id, normalizeCustomFeedName(body.name)]
        );
      }

      if (body.url !== undefined) {
        await client.query(
          `UPDATE integration_feeds SET source_url = $2, updated_at = NOW() WHERE integration_id = $1::uuid`,
          [existing.feed_id, sanitizeUrlForDisplay(body.url)]
        );
      }

      if (body.auth !== undefined) {
        const authValidated = validateCustomFeedAuth(body.auth);
        if (authValidated.ok) {
          const updatedCredentials = normalizeCustomFeedAuth(authValidated.value, existing.credentials || {});
          await client.query(
            `UPDATE integration_feeds SET credentials = $2::jsonb, updated_at = NOW() WHERE integration_id = $1::uuid`,
            [existing.feed_id, JSON.stringify(updatedCredentials)]
          );
        }
      }

      if (body.color !== undefined) {
        const colorCheck = validateHexColor(body.color);
        await client.query(
          `UPDATE integration_feeds SET color = $2, updated_at = NOW() WHERE integration_id = $1::uuid`,
          [existing.feed_id, colorCheck.value]
        );
      }

      const scheduleChanged = body.schedule_cron !== undefined;
      const scheduleCron = scheduleChanged ? String(body.schedule_cron || '').trim() : null;
      if (scheduleChanged) {
        await client.query(
          `UPDATE integration_feeds SET schedule_cron = $2, updated_at = NOW() WHERE integration_id = $1::uuid`,
          [existing.feed_id, scheduleCron]
        );
      }

      await client.query(
        `UPDATE custom_threat_feeds
         SET url = COALESCE($2, url),
             url_host = COALESCE($3, url_host),
             format = COALESCE($4, format),
             ioc_type_mode = COALESCE($5, ioc_type_mode),
             fixed_ioc_type = CASE WHEN $5 = 'fixed' THEN $6 WHEN $5 = 'auto' THEN NULL ELSE fixed_ioc_type END,
             description = COALESCE($7, description),
             updated_by = $8::uuid,
             updated_by_username = $9,
             updated_at = NOW()
         WHERE id = $1::uuid`,
        [
          existing.id,
          body.url !== undefined ? urlCheck.url : null,
          body.url !== undefined ? urlCheck.url_host : null,
          body.format ?? null,
          body.ioc_type_mode ?? null,
          body.fixed_ioc_type ?? null,
          body.description !== undefined ? (body.description ? String(body.description).trim() : null) : null,
          actorId,
          actor
        ]
      );

      await client.query('COMMIT');

      if (scheduleChanged) {
        await syncSingleFeedSchedule(pool, importQueue, existing.integration_key, { logPrefix: '[custom-feeds]' });
        if (isRunOnceSchedule(scheduleCron)) {
          console.log('[custom-feeds] custom feed schedule set to run_once', { feed_key: existing.integration_key });
        }
      }

      const row = await fetchFeedRow(pool, existing.id);
      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.CUSTOM_FEED_UPDATED,
        entityType: AUDIT_ENTITY.CUSTOM_THREAT_FEED,
        entityId: row.id,
        entityDisplay: row.feed_name,
        metadata: {
          ...auditFeedMeta(row),
          ...pickSafeFields(body, FEED_AUDIT_FIELDS),
          actor
        }
      }).catch(() => {});

      return res.json({ feed: serializeFeedRow(row) });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      if (isCustomFeedNameUniqueViolation(err)) {
        console.warn('[custom-threat-feeds] duplicate name rejected on update (db)', { feed_id: existing.id });
        return res.status(409).json({ error: DUPLICATE_CUSTOM_FEED_NAME_ERROR });
      }
      return res.status(500).json({ message: 'Failed to update Custom Threat Feed', detail: err.message });
    } finally {
      client.release();
    }
  });

  app.post('/api/custom-threat-feeds/:id/deactivate', requireRole(ROLES.ADMIN), async (req, res) => {
    const existing = await fetchFeedRow(pool, req.params.id);
    if (!existing || existing.deactivated_at) {
      return res.status(404).json({ message: 'Custom Threat Feed not found' });
    }
    const { actor } = actorFromReq(req);

    await pool.query(
      `UPDATE custom_threat_feeds
       SET deactivated_at = NOW(), updated_at = NOW()
       WHERE id = $1::uuid`,
      [existing.id]
    );
    await pool.query(
      `UPDATE integration_feeds
       SET active = FALSE,
           archived_at = COALESCE(archived_at, NOW()),
           updated_at = NOW()
       WHERE integration_id = $1::uuid`,
      [existing.feed_id]
    );
    await syncSingleFeedSchedule(pool, importQueue, existing.integration_key, { logPrefix: '[custom-feeds]' });

    await audit.auditSuccess({
      req,
      action: AUDIT_ACTION.CUSTOM_FEED_DEACTIVATED,
      entityType: AUDIT_ENTITY.CUSTOM_THREAT_FEED,
      entityId: existing.id,
      entityDisplay: existing.feed_name,
      metadata: { ...auditFeedMeta(existing), actor }
    }).catch(() => {});

    return res.json({ ok: true, message: 'Custom Threat Feed deactivated' });
  });

  app.post('/api/custom-threat-feeds/:id/unlink-from-published', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const feedRow = await fetchFeedRow(pool, req.params.id);
      if (!feedRow || feedRow.deactivated_at) {
        return res.status(404).json({ message: 'Custom Threat Feed not found' });
      }

      const { actor } = actorFromReq(req);

      const { rows: unlinkedRows } = await pool.query(
        `UPDATE published_feeds
         SET include_feed_keys = (
           SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
           FROM jsonb_array_elements_text(include_feed_keys) AS elem
           WHERE elem != $1
         ), updated_at = NOW()
         WHERE include_feed_keys IS NOT NULL
           AND include_feed_keys @> to_jsonb(ARRAY[$1::text])
         RETURNING id, name`,
        [feedRow.integration_key]
      );

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.CUSTOM_FEED_UNLINKED_FROM_PUBLISHED,
        entityType: AUDIT_ENTITY.CUSTOM_THREAT_FEED,
        entityId: feedRow.id,
        entityDisplay: feedRow.feed_name,
        metadata: {
          ...auditFeedMeta(feedRow),
          unlinked_published_feed_ids: unlinkedRows.map((r) => Number(r.id)),
          unlinked_published_feed_count: unlinkedRows.length,
          actor
        }
      }).catch(() => {});

      return res.json({
        ok: true,
        unlinked_count: unlinkedRows.length,
        unlinked_published_feeds: unlinkedRows.map((r) => ({ id: Number(r.id), name: r.name }))
      });
    } catch (err) {
      console.error('[custom-threat-feeds] unlink-from-published failed', err?.message || err);
      return res.status(500).json({ message: 'Failed to unlink from published feeds', detail: err.message });
    }
  });

  app.post('/api/custom-threat-feeds/:id/test-fetch', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    const row = await fetchFeedRow(pool, req.params.id);
    if (!row || row.deactivated_at) {
      return res.status(404).json({ message: 'Custom Threat Feed not found' });
    }

    try {
      const fetchResult = await fetchFeedUrl(row.url, {
        timeoutMs: row.timeout_ms,
        credentials: row.credentials || null
      });
      const parsed = parseFeedContent(fetchResult.bodyText, {
        format: row.format,
        contentType: fetchResult.contentType,
        url: row.url,
        iocTypeMode: row.ioc_type_mode,
        fixedIocType: row.fixed_ioc_type
      });
      const sample = buildParseSample(parsed.valid, parsed.invalidRows);
      return res.json({
        http_status: fetchResult.httpStatus,
        detected_format: parsed.detectedFormat,
        detected_rows: parsed.totalRows,
        fetched_bytes: fetchResult.fetchedBytes,
        ...sample
      });
    } catch (err) {
      return res.status(400).json({
        message: 'Test fetch failed',
        detail: err.message
      });
    }
  });

  app.post('/api/custom-threat-feeds/:id/sync', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
    const row = await fetchFeedRow(pool, req.params.id);
    if (!row || row.deactivated_at) {
      return res.status(404).json({ message: 'Custom Threat Feed not found' });
    }
    if (row.integration_active === false) {
      return res.status(409).json({ message: 'Custom Threat Feed is disabled' });
    }

    const { actor } = actorFromReq(req);
    const triggeredBy = `manual-ui:${actor}`;

    try {
      const queued = await queueCustomFeedSync(pool, importQueue, row, triggeredBy, manualJobPriority);
      if (!queued.ok) return res.status(queued.status).json(queued.body);

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.CUSTOM_FEED_SYNC_QUEUED,
        entityType: AUDIT_ENTITY.CUSTOM_THREAT_FEED,
        entityId: row.id,
        entityDisplay: row.feed_name,
        metadata: {
          ...auditFeedMeta(row),
          actor,
          job_id: queued.job_id
        }
      }).catch(() => {});

      return res.status(202).json({
        ok: true,
        queued: true,
        message: 'Custom threat feed run queued',
        job_id: queued.job_id
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to queue sync', detail: err.message });
    }
  });

  app.get('/api/custom-threat-feeds/:id/runs', async (req, res) => {
    const row = await fetchFeedRow(pool, req.params.id);
    if (!row) return res.status(404).json({ message: 'Custom Threat Feed not found' });

    const limit = Math.min(Math.max(Number(req.query?.limit || 20), 1), 100);
    try {
      const { rows } = await pool.query(
        `SELECT id, feed_id, status, started_at, finished_at, duration_ms,
                fetched_bytes, http_status, total_rows, valid_rows, invalid_rows,
                inserted, updated, refreshed, expired_missing, duplicate_rows,
                error_message, invalid_samples, triggered_by
         FROM custom_threat_feed_runs
         WHERE feed_id = $1::uuid
         ORDER BY started_at DESC
         LIMIT $2`,
        [row.id, limit]
      );
      return res.json({ runs: rows, feed: serializeFeedRow(row) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load run history', detail: err.message });
    }
  });

  app.get('/api/custom-threat-feeds/:id/delete-check', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const feedRow = await fetchFeedRow(pool, req.params.id);
      if (!feedRow || feedRow.deactivated_at) {
        return res.status(404).json({ message: 'Custom Threat Feed not found' });
      }
      const check = await computeDeleteCheck(pool, feedRow);
      return res.json(check);
    } catch (err) {
      console.error('[custom-threat-feeds] delete-check failed', err?.message || err);
      return res.status(500).json({ message: 'Failed to check delete eligibility', detail: err.message });
    }
  });

  app.delete('/api/custom-threat-feeds/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const feedRow = await fetchFeedRow(pool, req.params.id);
      if (!feedRow || feedRow.deactivated_at) {
        return res.status(404).json({ message: 'Custom Threat Feed not found' });
      }

      const check = await computeDeleteCheck(pool, feedRow);
      if (!check.can_delete) {
        return res.status(409).json({ message: 'Cannot delete this Custom Threat Feed', ...check });
      }

      const { actor } = actorFromReq(req);

      if (check.delete_mode === 'cleanup_delete') {
        // Determine inner deletion mode based on run history (same logic as direct/soft paths).
        const innerMode = (check.successful_run_count === 0 && check.historical_membership_count === 0)
          ? 'direct_delete'
          : 'soft_delete';

        const client = await pool.connect();
        let unlinkedRows = [];
        try {
          await client.query('BEGIN');

          // Atomically remove this feed's integration key from all published_feeds.include_feed_keys.
          const unlinkRes = await client.query(
            `UPDATE published_feeds
             SET include_feed_keys = (
               SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
               FROM jsonb_array_elements_text(include_feed_keys) AS elem
               WHERE elem != $1
             ), updated_at = NOW()
             WHERE include_feed_keys IS NOT NULL
               AND include_feed_keys @> to_jsonb(ARRAY[$1::text])
             RETURNING id, name`,
            [feedRow.integration_key]
          );
          unlinkedRows = unlinkRes.rows;

          if (innerMode === 'direct_delete') {
            await client.query(
              `UPDATE integration_feeds SET active = FALSE WHERE integration_id = $1::uuid`,
              [feedRow.feed_id]
            );
          } else {
            await client.query(
              `UPDATE custom_threat_feeds SET deactivated_at = NOW(), updated_at = NOW() WHERE id = $1::uuid`,
              [feedRow.id]
            );
            await client.query(
              `UPDATE integration_feeds
               SET active = FALSE,
                   archived_at = COALESCE(archived_at, NOW()),
                   updated_at = NOW()
               WHERE integration_id = $1::uuid`,
              [feedRow.feed_id]
            );
          }

          await client.query('COMMIT');
        } catch (err) {
          await client.query('ROLLBACK').catch(() => {});
          throw err;
        } finally {
          client.release();
        }

        // Outside the transaction: remove the scheduled job, then hard-delete if applicable.
        await syncSingleFeedSchedule(pool, importQueue, feedRow.integration_key, { logPrefix: '[custom-feeds-delete]' });
        if (innerMode === 'direct_delete') {
          await pool.query(`DELETE FROM integration_feeds WHERE integration_id = $1::uuid`, [feedRow.feed_id]);
        }

        const unlinkedIds = unlinkedRows.map((r) => Number(r.id));
        await audit.auditSuccess({
          req,
          action: AUDIT_ACTION.CUSTOM_FEED_CLEANUP_DELETED,
          entityType: AUDIT_ENTITY.CUSTOM_THREAT_FEED,
          entityId: feedRow.id,
          entityDisplay: feedRow.feed_name,
          metadata: {
            ...auditFeedMeta(feedRow),
            delete_mode: check.delete_mode,
            inner_delete_mode: innerMode,
            linked_published_feed_count: check.published_feed_dependency_count,
            unlinked_published_feed_ids: unlinkedIds,
            active_membership_count: check.active_membership_count,
            historical_membership_count: check.historical_membership_count,
            actor
          }
        }).catch(() => {});

        return res.json({
          ok: true,
          message: 'Custom Threat Feed deleted and unlinked from Published Feeds',
          delete_mode: check.delete_mode,
          unlinked_published_feed_count: unlinkedRows.length
        });
      }

      if (check.delete_mode === 'direct_delete') {
        await pool.query(`UPDATE integration_feeds SET active = FALSE WHERE integration_id = $1::uuid`, [feedRow.feed_id]);
        await syncSingleFeedSchedule(pool, importQueue, feedRow.integration_key, { logPrefix: '[custom-feeds-delete]' });
        await pool.query(`DELETE FROM integration_feeds WHERE integration_id = $1::uuid`, [feedRow.feed_id]);
      } else {
        await pool.query(
          `UPDATE custom_threat_feeds SET deactivated_at = NOW(), updated_at = NOW() WHERE id = $1::uuid`,
          [feedRow.id]
        );
        await pool.query(
          `UPDATE integration_feeds
           SET active = FALSE,
               archived_at = COALESCE(archived_at, NOW()),
               updated_at = NOW()
           WHERE integration_id = $1::uuid`,
          [feedRow.feed_id]
        );
      }

      await audit.auditSuccess({
        req,
        action: AUDIT_ACTION.CUSTOM_FEED_DELETED,
        entityType: AUDIT_ENTITY.CUSTOM_THREAT_FEED,
        entityId: feedRow.id,
        entityDisplay: feedRow.feed_name,
        metadata: {
          ...auditFeedMeta(feedRow),
          delete_mode: check.delete_mode,
          successful_run_count: check.successful_run_count,
          active_membership_count: check.active_membership_count,
          historical_membership_count: check.historical_membership_count,
          actor
        }
      }).catch(() => {});

      return res.json({ ok: true, message: 'Custom Threat Feed deleted', delete_mode: check.delete_mode });
    } catch (err) {
      console.error('[custom-threat-feeds] delete failed', err?.message || err);
      return res.status(500).json({ message: 'Failed to delete Custom Threat Feed', detail: err.message });
    }
  });
}

export { CUSTOM_FEED_KEY_PREFIX };
