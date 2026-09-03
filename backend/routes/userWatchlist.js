/**
 * Per-user IOC Watchlist (Favorites) HTTP API.
 *
 *   PUT    /api/ioc/:publicId/watchlist   → add the IOC to the caller's watchlist
 *   DELETE /api/ioc/:publicId/watchlist   → remove it
 *   GET    /api/ioc/:publicId/watchlist   → caller's membership for one IOC (uncached)
 *   GET    /api/watchlist                 → caller's watchlist, paginated
 *
 * Isolation invariant: user_id ALWAYS comes from the authenticated session
 * (actorUserId), never from the request body/query/params. A client cannot name
 * whose watchlist is read or written. Machine principals (no numeric user id) are
 * rejected — a watchlist belongs to a human account.
 *
 * The per-IOC GET is intentionally separate from GET /api/ioc/details, which is a
 * process-wide cache shared across users: baking per-user membership into that
 * payload would leak one user's watchlist state to another on a cache hit.
 */

import { actorUserId } from '../lib/artifactOwnership.js';
import {
  parseWatchlistPublicId,
  resolveIocRefByPublicId,
  addToWatchlist,
  removeFromWatchlist,
  isWatchlisted,
  countWatchlist,
  listWatchlistRefs,
  loadIocRowsForRefs,
  iocRowToPageItem,
  parseWatchlistListParams,
  buildWatchlistPagination
} from '../lib/userIocWatchlist.js';

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ mapPageItems?: (pool: any, items: any[], viewerUserId: number) => Promise<any[]> }} [deps]
 */
export function registerUserWatchlistRoutes(app, pool, deps = {}) {
  const mapPageItems = typeof deps.mapPageItems === 'function' ? deps.mapPageItems : null;

  function requireInteractiveUser(req, res) {
    const userId = actorUserId(req);
    if (!userId) {
      res.status(403).json({ message: 'A user account is required to use the watchlist.' });
      return null;
    }
    return userId;
  }

  async function resolveOrReject(res, publicIdRaw) {
    const publicId = parseWatchlistPublicId(publicIdRaw);
    if (!publicId) {
      res.status(400).json({ message: 'Invalid IOC id' });
      return null;
    }
    const ref = await resolveIocRefByPublicId(pool, publicId);
    if (!ref) {
      res.status(404).json({ message: 'IOC not found' });
      return null;
    }
    return ref;
  }

  app.put('/api/ioc/:publicId/watchlist', async (req, res) => {
    const userId = requireInteractiveUser(req, res);
    if (!userId) return undefined;
    try {
      const ref = await resolveOrReject(res, req.params?.publicId);
      if (!ref) return undefined;
      await addToWatchlist(pool, userId, ref);
      return res.json({ watchlisted: true });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update watchlist', detail: err.message });
    }
  });

  app.delete('/api/ioc/:publicId/watchlist', async (req, res) => {
    const userId = requireInteractiveUser(req, res);
    if (!userId) return undefined;
    try {
      const ref = await resolveOrReject(res, req.params?.publicId);
      if (!ref) return undefined;
      await removeFromWatchlist(pool, userId, ref);
      return res.json({ watchlisted: false });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update watchlist', detail: err.message });
    }
  });

  app.get('/api/ioc/:publicId/watchlist', async (req, res) => {
    const userId = requireInteractiveUser(req, res);
    if (!userId) return undefined;
    try {
      const ref = await resolveOrReject(res, req.params?.publicId);
      if (!ref) return undefined;
      const watchlisted = await isWatchlisted(pool, userId, ref);
      return res.json({ watchlisted });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to read watchlist state', detail: err.message });
    }
  });

  app.get('/api/watchlist', async (req, res) => {
    const userId = requireInteractiveUser(req, res);
    if (!userId) return undefined;
    try {
      const { page, pageSize, limit, offset } = parseWatchlistListParams(req.query || {});
      const total = await countWatchlist(pool, userId);
      const pagination = buildWatchlistPagination({ page, pageSize, total });

      if (total === 0 || page > pagination.page_count) {
        return res.json({ items: [], pagination });
      }

      const refs = await listWatchlistRefs(pool, userId, { limit, offset });
      const rows = await loadIocRowsForRefs(pool, refs);

      // Preserve watchlist order (newest star first). loadIocRowsForRefs may return
      // rows in any order and can omit an IOC that was hard-deleted between the two
      // queries — the FK cascade normally prevents that, so this is just defensive.
      const rank = new Map(refs.map((r, i) => [r.ioc_id, i]));
      const ordered = rows
        .filter((r) => rank.has(Number(r.id)))
        .sort((a, b) => rank.get(Number(a.id)) - rank.get(Number(b.id)));

      let items = ordered.map(iocRowToPageItem);
      if (mapPageItems) {
        items = await mapPageItems(pool, items, userId);
        // Enrichment must not reorder the watchlist; re-sort by star recency.
        items.sort((a, b) => (rank.get(Number(a.id)) ?? 0) - (rank.get(Number(b.id)) ?? 0));
      } else {
        for (const it of items) it.watchlisted = true;
      }

      return res.json({ items, pagination });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load watchlist', detail: err.message });
    }
  });
}
