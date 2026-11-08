/**
 * MCP Published Feed tools — thin adapter over publishedFeedManagementService.
 * Never returns access keys, tokens, or secrets.
 */

import { mcpActorAuditFields } from './mcpIocService.js';
import {
  listFeeds,
  getFeed,
  createFeed,
  updateFeed,
  previewFeedMembership,
  listFeedMembership,
  regenerateFeed,
  feedAuditSnapshot
} from './publishedFeedManagementService.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';
import { pickSafeFields } from './auditRedaction.js';

function ok(body) {
  return { body };
}

function fail(code, message, extra = {}) {
  return { error: { code, message, ...extra } };
}

function stripSecrets(feed) {
  if (!feed || typeof feed !== 'object') return feed;
  const {
    // Defensive: never leak key material even if a future field appears.
    access_keys,
    token,
    token_hash,
    api_key,
    secrets,
    ...safe
  } = feed;
  void access_keys;
  void token;
  void token_hash;
  void api_key;
  void secrets;
  return safe;
}

export async function mcpListPublishedFeeds(pool) {
  const { feeds } = await listFeeds(pool);
  return ok({ feeds: feeds.map(stripSecrets) });
}

export async function mcpGetPublishedFeed(pool, args = {}) {
  const id = args.id ?? args.feed_id;
  if (id == null) return fail('INVALID_ARGUMENT', 'id is required');
  const result = await getFeed(pool, id, { includeCuratedIds: true });
  if (result.error) {
    return fail(
      result.error.status === 404 ? 'NOT_FOUND' : 'INVALID_ARGUMENT',
      result.error.message
    );
  }
  return ok({ feed: stripSecrets(result.feed) });
}

export async function mcpPreviewPublishedFeed(pool, args = {}) {
  const result = await previewFeedMembership(pool, args);
  if (result.error) {
    return fail(
      result.error.status === 404 ? 'NOT_FOUND' : 'INVALID_ARGUMENT',
      result.error.message
    );
  }
  return ok(result.preview);
}

export async function mcpGetPublishedFeedMembership(pool, args = {}) {
  const id = args.id ?? args.feed_id;
  if (id == null) return fail('INVALID_ARGUMENT', 'id is required');
  const result = await listFeedMembership(pool, id, {
    limit: args.limit,
    offset: args.offset
  });
  if (result.error) {
    return fail(
      result.error.status === 404 ? 'NOT_FOUND' : 'INVALID_ARGUMENT',
      result.error.message
    );
  }
  return ok({
    feed: stripSecrets(result.feed),
    membership: result.membership
  });
}

export async function mcpCreatePublishedFeed(pool, args = {}, ctx = {}) {
  const dryRun = Boolean(args.dry_run);
  const result = await createFeed(pool, args, {
    dryRun,
    createdBy: ctx.user?.publicId || ctx.user?.public_id || null
  });
  if (result.error) {
    return fail('INVALID_ARGUMENT', result.error.message, result.error.dsl ? { dsl: result.error.dsl } : {});
  }
  if (result.dry_run) {
    return ok({ dry_run: true, ...result.would_create ? { would_create: result.would_create } : result });
  }
  if (ctx.audit?.auditSuccess && ctx.req) {
    const actor = mcpActorAuditFields(ctx.mcpAuth || ctx.req.mcpAuth, ctx.user || ctx.req.user);
    await ctx.audit.auditSuccess({
      req: ctx.req,
      action: AUDIT_ACTION.FEED_CREATED,
      entityType: AUDIT_ENTITY.FEED,
      entityId: String(result.feed.id),
      entityDisplay: result.feed.name,
      severity: AUDIT_SEVERITY.INFO,
      actorUsername: actor.actorUsername,
      actorEmail: actor.actorEmail,
      actorRole: actor.actorRole,
      actorPublicId: actor.actorPublicId,
      source: 'mcp',
      after: feedAuditSnapshot(result.row),
      metadata: { ...actor.metadataExtras, via: 'mcp', tool: 'create_published_feed' }
    }).catch(() => {});
  }
  return ok({ dry_run: false, feed: stripSecrets(result.feed) });
}

export async function mcpUpdatePublishedFeed(pool, args = {}, ctx = {}) {
  const id = args.id ?? args.feed_id;
  if (id == null) return fail('INVALID_ARGUMENT', 'id is required');
  const dryRun = Boolean(args.dry_run);
  const { id: _id, feed_id: _fid, dry_run: _dr, ...body } = args;
  void _id;
  void _fid;
  void _dr;
  const result = await updateFeed(pool, id, body, {
    dryRun,
    createdBy: ctx.user?.publicId || ctx.user?.public_id || null
  });
  if (result.error) {
    return fail(
      result.error.status === 404 ? 'NOT_FOUND' : 'INVALID_ARGUMENT',
      result.error.message,
      result.error.dsl ? { dsl: result.error.dsl } : {}
    );
  }
  if (result.dry_run) {
    return ok({ dry_run: true, ...result });
  }
  if (ctx.audit?.auditSuccess && ctx.req) {
    const actor = mcpActorAuditFields(ctx.mcpAuth || ctx.req.mcpAuth, ctx.user || ctx.req.user);
    await ctx.audit.auditSuccess({
      req: ctx.req,
      action: AUDIT_ACTION.FEED_UPDATED,
      entityType: AUDIT_ENTITY.FEED,
      entityId: String(result.feed.id),
      entityDisplay: result.feed.name,
      severity: AUDIT_SEVERITY.INFO,
      actorUsername: actor.actorUsername,
      actorEmail: actor.actorEmail,
      actorRole: actor.actorRole,
      actorPublicId: actor.actorPublicId,
      source: 'mcp',
      before: result.before,
      after: feedAuditSnapshot(result.row),
      metadata: {
        ...actor.metadataExtras,
        via: 'mcp',
        tool: 'update_published_feed',
        changed_fields: Object.keys(body)
      }
    }).catch(() => {});
  }
  return ok({ dry_run: false, feed: stripSecrets(result.feed) });
}

export async function mcpRegeneratePublishedFeed(pool, args = {}, ctx = {}) {
  const id = args.id ?? args.feed_id;
  if (id == null) return fail('INVALID_ARGUMENT', 'id is required');
  const result = await regenerateFeed(pool, id, { force: true });
  if (result.error) {
    return fail(
      result.error.code === 'generation_in_progress' ? 'CONFLICT' : 'ERROR',
      result.error.message,
      { regeneration: result.error.regeneration }
    );
  }
  if (ctx.audit?.auditSuccess && ctx.req) {
    const actor = mcpActorAuditFields(ctx.mcpAuth || ctx.req.mcpAuth, ctx.user || ctx.req.user);
    await ctx.audit.auditSuccess({
      req: ctx.req,
      action: AUDIT_ACTION.FEED_RUN_TRIGGERED,
      entityType: AUDIT_ENTITY.FEED,
      entityId: String(result.feed.id),
      entityDisplay: result.feed.name,
      severity: AUDIT_SEVERITY.INFO,
      actorUsername: actor.actorUsername,
      actorEmail: actor.actorEmail,
      actorRole: actor.actorRole,
      actorPublicId: actor.actorPublicId,
      source: 'mcp',
      metadata: {
        ...actor.metadataExtras,
        via: 'mcp',
        tool: 'regenerate_published_feed',
        regeneration: pickSafeFields(result.regeneration, [
          'status', 'item_count', 'generated_at', 'last_status', 'reason'
        ])
      }
    }).catch(() => {});
  }
  return ok({
    feed: stripSecrets(result.feed),
    regeneration: result.regeneration
  });
}
