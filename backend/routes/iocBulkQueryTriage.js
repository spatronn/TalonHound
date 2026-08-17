import { requireTriageRole, isAdminRole, normalizeAppRole } from '../lib/rbac.js';
import { actorEmail, actorUserId, canAccessOwnedArtifact } from '../lib/artifactOwnership.js';
import {
  parseQueryWideRequest,
  compileQueryWideTarget,
  resolveQueryWideTarget,
  countMatchingIocs,
  executeQueryWideBulk,
  decideExecutionMode,
  auditQueryWideOperation,
  payloadFromBody
} from '../lib/iocBulkQueryTriage.js';
import { getBulkQueryConfig } from '../lib/iocBulkQueryJob/config.js';
import {
  createBulkQueryJob,
  getBulkQueryJobById,
  listBulkQueryJobs,
  countBulkQueryJobs,
  countActiveForUser,
  setJobId
} from '../lib/iocBulkQueryJob/store.js';
import {
  serializeBulkQueryJob,
  parseListStatusFilter
} from '../lib/iocBulkQueryJob/status.js';

function sendErr(res, outcome) {
  return res.status(outcome.status || 400).json({
    message: outcome.message,
    code: outcome.code || undefined
  });
}

/**
 * Query-wide bulk triage. Distinct from explicit-ID /api/iocs/bulk/*.
 */
export function registerIocBulkQueryTriageRoutes(app, pool, {
  bulkQueryQueue = null,
  audit = null,
  deps = {}
} = {}) {
  const countFn = deps.countMatchingIocs || countMatchingIocs;
  const executeFn = deps.executeQueryWideBulk || executeQueryWideBulk;
  const compileFn = deps.compileQueryWideTarget || compileQueryWideTarget;
  const resolveFn = deps.resolveQueryWideTarget || resolveQueryWideTarget;
  const triage = requireTriageRole();

  async function preview(req, res) {
    const parsed = parseQueryWideRequest({
      query: req.body?.query,
      selection_mode: 'all_matching',
      deep_search_id: req.body?.deep_search_id
    }, 'tag');
    if (!parsed.ok) return sendErr(res, parsed);
    let compiled;
    try {
      compiled = parsed.deepSearchId
        ? await resolveFn(pool, parsed, { req })
        : compileFn(parsed.query);
    } catch {
      return res.status(500).json({ message: 'Failed to compile search query' });
    }
    if (!compiled.ok) return sendErr(res, compiled);
    try {
      const counted = compiled.deepSearchId != null && compiled.matchCount != null
        ? { ok: true, matchCount: compiled.matchCount }
        : await countFn(pool, compiled);
      if (!counted.ok) return sendErr(res, counted);
      return res.json({
        ok: true,
        query: compiled.originalQuery,
        normalized_query: compiled.normalizedQuery,
        match_count: counted.matchCount,
        ...(compiled.deepSearchId ? { deep_search_id: compiled.deepSearchId } : {})
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to count matching IOCs', detail: err.message });
    }
  }

  async function runAction(req, res, action) {
    const parsed = parseQueryWideRequest(req.body, action);
    if (!parsed.ok) return sendErr(res, parsed);
    let compiled;
    try {
      compiled = parsed.deepSearchId
        ? await resolveFn(pool, parsed, { req })
        : compileFn(parsed.query);
    } catch {
      return res.status(500).json({ message: 'Failed to compile search query' });
    }
    if (!compiled.ok) return sendErr(res, compiled);

    const payload = payloadFromBody(action, req.body);
    if (compiled.deepSearchId) payload.deep_search_id = compiled.deepSearchId;
    const cfg = getBulkQueryConfig();

    let counted;
    try {
      counted = compiled.deepSearchId != null && compiled.matchCount != null
        ? { ok: true, matchCount: compiled.matchCount }
        : await countFn(pool, compiled);
    } catch (err) {
      return res.status(500).json({ message: 'Failed to count matching IOCs', detail: err.message });
    }
    if (!counted.ok) return sendErr(res, counted);
    // Client-supplied match_count is ignored; counted.matchCount is authoritative.
    if (compiled.deepSearchId) payload.expected_match_count = counted.matchCount;

    const mode = decideExecutionMode(counted.matchCount, cfg, {
      skipHardLimit: Boolean(compiled.deepSearchId)
    });
    if (!mode.ok) return sendErr(res, mode);

    if (mode.mode === 'sync') {
      try {
        const outcome = await executeFn(pool, {
          compiled,
          action,
          payload,
          user: req.user,
          req,
          audit,
          includeResults: true
        });
        if (!outcome.ok) return sendErr(res, outcome);
        await auditQueryWideOperation(audit, {
          req,
          action,
          compiled,
          matchCount: outcome.matchCount,
          succeeded: outcome.succeeded,
          skipped: outcome.skipped,
          failed: outcome.failed,
          mode: 'sync',
          reason: payload.reason || null
        });
        return res.status(200).json({
          ok: outcome.failed === 0,
          mode: 'sync',
          selection_mode: 'all_matching',
          query: compiled.normalizedQuery,
          match_count: outcome.matchCount,
          requested: outcome.requested,
          succeeded: outcome.succeeded,
          skipped: outcome.skipped,
          failed: outcome.failed,
          results: outcome.results
        });
      } catch (err) {
        const status = err.status || 500;
        if (status < 500) return res.status(status).json({ message: err.message, code: err.code });
        return res.status(500).json({ message: 'Query-wide bulk action failed', detail: err.message });
      }
    }

    if (!bulkQueryQueue) {
      return res.status(503).json({
        message: 'Query-wide bulk queue is unavailable',
        code: 'QUEUE_UNAVAILABLE'
      });
    }

    const email = actorEmail(req);
    const userId = actorUserId(req);
    if (!email || !userId) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    try {
      const active = await countActiveForUser(pool, userId);
      if (active >= cfg.maxConcurrentPerUser) {
        return res.status(429).json({
          message: `Too many query-wide bulk jobs already running (max ${cfg.maxConcurrentPerUser})`,
          code: 'CONCURRENCY_LIMIT'
        });
      }
      const row = await createBulkQueryJob(pool, {
        action,
        originalQuery: compiled.originalQuery,
        normalizedQuery: compiled.normalizedQuery,
        normalizedAst: compiled.ast,
        payload,
        requestedById: userId,
        requestedByEmail: email,
        requestedByPublicId: req.user?.publicId || null,
        requestedByRole: normalizeAppRole(req.user?.role)
      });
      const job = await bulkQueryQueue.add(
        'ioc-bulk-query',
        { jobId: row.id },
        { jobId: row.id, removeOnComplete: 100, removeOnFail: 100 }
      );
      if (job?.id) await setJobId(pool, row.id, String(job.id));
      await auditQueryWideOperation(audit, {
        req,
        action,
        compiled,
        matchCount: counted.matchCount,
        succeeded: 0,
        skipped: 0,
        failed: 0,
        mode: 'async',
        reason: payload.reason || null,
        jobId: row.id,
        outcome: 'enqueued'
      });
      return res.status(202).json({
        ok: true,
        mode: 'async',
        selection_mode: 'all_matching',
        query: compiled.normalizedQuery,
        match_count: counted.matchCount,
        job_id: row.id,
        task: serializeBulkQueryJob(row)
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to enqueue query-wide bulk job', detail: err.message });
    }
  }

  app.post('/api/iocs/bulk/query/preview', triage, (req, res) => {
    preview(req, res).catch(() => {
      res.status(500).json({ message: 'Failed to preview query-wide bulk' });
    });
  });

  app.post('/api/iocs/bulk/query/tags', triage, (req, res) => {
    runAction(req, res, 'tag').catch(() => {
      res.status(500).json({ message: 'Query-wide bulk tag failed' });
    });
  });

  app.post('/api/iocs/bulk/query/classifications', triage, (req, res) => {
    runAction(req, res, 'classification').catch(() => {
      res.status(500).json({ message: 'Query-wide bulk classification failed' });
    });
  });

  app.post('/api/iocs/bulk/query/suppress', triage, (req, res) => {
    runAction(req, res, 'suppress').catch(() => {
      res.status(500).json({ message: 'Query-wide bulk suppress failed' });
    });
  });

  app.post('/api/iocs/bulk/query/expire', triage, (req, res) => {
    runAction(req, res, 'expire').catch(() => {
      res.status(500).json({ message: 'Query-wide bulk expire failed' });
    });
  });

  app.get('/api/iocs/bulk/query-jobs', async (req, res) => {
    const userId = actorUserId(req);
    const wantAll = req.query.scope === 'all' && isAdminRole(normalizeAppRole(req.user?.role));
    const statuses = parseListStatusFilter(req.query.status);
    if (statuses === undefined) {
      return res.status(400).json({
        message: 'Invalid status filter. Allowed: all, processing, ready, failed, expired, or a concrete status.'
      });
    }
    const pageRaw = Number(req.query.page);
    const page = Math.max(Number.isFinite(pageRaw) ? Math.trunc(pageRaw) : 1, 1);
    const sizeRaw = Number(req.query.page_size ?? req.query.pageSize);
    const pageSize = Math.min(Math.max(Number.isFinite(sizeRaw) ? Math.trunc(sizeRaw) : 25, 1), 100);
    try {
      const [rows, total] = await Promise.all([
        listBulkQueryJobs(pool, {
          userId,
          includeAll: wantAll,
          limit: pageSize,
          offset: (page - 1) * pageSize,
          statuses
        }),
        countBulkQueryJobs(pool, { userId, includeAll: wantAll, statuses })
      ]);
      return res.json({
        items: rows.map((r) => serializeBulkQueryJob(r)),
        total,
        page,
        page_size: pageSize
      });
    } catch {
      return res.status(500).json({ message: 'Failed to list query-wide bulk jobs' });
    }
  });

  app.get('/api/iocs/bulk/query-jobs/:id', async (req, res) => {
    try {
      const row = await getBulkQueryJobById(pool, req.params.id);
      if (!row) return res.status(404).json({ message: 'Bulk job not found' });
      if (!canAccessOwnedArtifact(req, row)) return res.status(403).json({ message: 'Forbidden' });
      return res.json(serializeBulkQueryJob(row));
    } catch {
      return res.status(500).json({ message: 'Failed to read bulk job' });
    }
  });
}
