const UUID_RE = /^[0-9a-f-]{36}$/i;

export function parseThreatActorIdInput(raw) {
  if (raw == null) return [];
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) return parsed;
      } catch {
        /* fall through */
      }
    }
    return trimmed.split(',').map((x) => x.trim()).filter(Boolean);
  }
  return [];
}

/** Normalize multi-select actor UUID input; empty array = none selected. */
export function normalizeIocThreatActorIds(raw) {
  const items = parseThreatActorIdInput(raw);
  const seen = new Set();
  const ids = [];
  for (const item of items) {
    const id = String(item?.id ?? item?.threat_actor_id ?? item ?? '').trim();
    if (!UUID_RE.test(id)) continue;
    const key = id.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      ids.push(id);
    }
  }
  return ids;
}

export function legacyThreatActorColumnValue(ids) {
  if (!ids?.length) return null;
  return ids[0];
}

export function buildThreatActorEntry(row) {
  if (!row) return null;
  const id = row.id || row.threat_actor_id;
  if (!id) return null;
  return {
    id,
    name: row.name || null,
    slug: row.slug || null,
    aliases: row.aliases || [],
    active: row.active != null ? Boolean(row.active) : true
  };
}

export function buildMultiThreatActorResponseFields(actors = []) {
  const list = (actors || []).map(buildThreatActorEntry).filter(Boolean);
  const primary = list[0] || null;
  return {
    threat_actors: list,
    threat_actor_ids: list.map((a) => a.id),
    threat_actor_id: primary?.id || null,
    threat_actor_name: primary?.name || null
  };
}

export function emptyThreatActorResponseFields() {
  return buildMultiThreatActorResponseFields([]);
}

function iocPairKey(iocId, observableType) {
  return `${Number(iocId)}|${String(observableType || '')}`;
}

export async function validateIocThreatActorIds(pool, raw, { requireActive = true } = {}) {
  const ids = normalizeIocThreatActorIds(raw);
  if (!ids.length) return { ok: true, value: [] };

  const { rows } = await pool.query(
    `SELECT id, name, slug, aliases, active
     FROM threat_actors
     WHERE id = ANY($1::uuid[])`,
    [ids]
  );
  const byId = new Map(rows.map((r) => [String(r.id).toLowerCase(), r]));
  const ordered = [];
  for (const id of ids) {
    const row = byId.get(id.toLowerCase());
    if (!row) return { ok: false, error: `Threat actor not found: ${id}` };
    if (requireActive && row.active === false) {
      return { ok: false, error: `Threat actor is inactive: ${row.name || id}` };
    }
    ordered.push(row);
  }
  return { ok: true, value: ids, rows: ordered };
}

export async function loadIocThreatActorDetails(pool, pairs) {
  const map = new Map();
  if (!pairs?.length) return map;

  const validPairs = pairs
    .map((p) => ({
      id: Number(p?.id ?? p?.ioc_id),
      observable_type: String(p?.observable_type ?? p?.ioc_observable_type ?? '').trim()
    }))
    .filter((p) => Number.isFinite(p.id) && p.id > 0 && p.observable_type);
  if (!validPairs.length) return map;

  const values = validPairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
  const params = validPairs.flatMap((p) => [p.id, p.observable_type]);
  let rows;
  try {
    ({ rows } = await pool.query(
      `SELECT ita.ioc_id, ita.ioc_observable_type, ita.threat_actor_id,
              ta.name, ta.slug, ta.aliases, ta.active
       FROM ioc_threat_actors ita
       JOIN threat_actors ta ON ta.id = ita.threat_actor_id
       WHERE (ita.ioc_id, ita.ioc_observable_type) IN (VALUES ${values})
       ORDER BY ta.name ASC`,
      params
    ));
  } catch (err) {
    if (String(err?.message || '').includes('ioc_threat_actors')) return map;
    throw err;
  }

  for (const row of rows) {
    const key = iocPairKey(row.ioc_id, row.ioc_observable_type);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(buildThreatActorEntry(row));
  }

  const detailMap = new Map();
  for (const [key, actors] of map.entries()) {
    detailMap.set(key, buildMultiThreatActorResponseFields(actors));
  }
  return detailMap;
}

export async function fetchIocThreatActors(pool, iocId, observableType) {
  const map = await loadIocThreatActorDetails(pool, [{ id: iocId, observable_type: observableType }]);
  return map.get(iocPairKey(iocId, observableType)) || emptyThreatActorResponseFields();
}

/**
 * Replace junction rows and mirror primary into ioc_items.threat_actor_id.
 * Accepts a pool or an already-open client (pass `{ manageTransaction: false }` when caller owns BEGIN/COMMIT).
 */
export async function replaceIocThreatActors(poolOrClient, {
  iocId,
  observableType,
  threatActorIds,
  sourceType = 'analyst',
  sourceName = null,
  actor = null,
  manageTransaction = true
}) {
  const ids = normalizeIocThreatActorIds(threatActorIds);
  const client = manageTransaction ? await poolOrClient.connect() : poolOrClient;
  try {
    if (manageTransaction) await client.query('BEGIN');
    await client.query(
      `DELETE FROM ioc_threat_actors WHERE ioc_id = $1 AND ioc_observable_type = $2`,
      [iocId, observableType]
    );
    for (const id of ids) {
      await client.query(
        `INSERT INTO ioc_threat_actors
           (ioc_id, ioc_observable_type, threat_actor_id, source_type, source_name, created_by, updated_by)
         VALUES ($1, $2, $3::uuid, $4, $5, $6, $6)
         ON CONFLICT (ioc_id, ioc_observable_type, threat_actor_id) DO UPDATE
           SET updated_at = NOW(), updated_by = EXCLUDED.updated_by, source_type = EXCLUDED.source_type`,
        [iocId, observableType, id, sourceType, sourceName, actor]
      );
    }
    const legacyId = legacyThreatActorColumnValue(ids);
    await client.query(
      `UPDATE ioc_items SET threat_actor_id = $3::uuid WHERE id = $1 AND observable_type = $2`,
      [iocId, observableType, legacyId]
    );
    if (manageTransaction) await client.query('COMMIT');
    return ids;
  } catch (err) {
    if (manageTransaction) {
      try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    }
    throw err;
  } finally {
    if (manageTransaction) client.release();
  }
}

export function diffThreatActorIds(oldIds, newIds) {
  const oldSet = new Set((oldIds || []).map((x) => String(x).toLowerCase()));
  const newSet = new Set((newIds || []).map((x) => String(x).toLowerCase()));
  const oldList = [...oldSet];
  const newList = [...newSet];
  return {
    old_threat_actor_ids: oldList,
    new_threat_actor_ids: newList,
    added: newList.filter((x) => !oldSet.has(x)),
    removed: oldList.filter((x) => !newSet.has(x))
  };
}

export function parseThreatActorBody(body) {
  if (Array.isArray(body?.threat_actor_ids)) return body.threat_actor_ids;
  if (Array.isArray(body?.threat_actors)) {
    return body.threat_actors.map((x) => x?.id ?? x?.threat_actor_id ?? x);
  }
  if (body?.threat_actor_id !== undefined) {
    const v = body.threat_actor_id;
    if (v === null || v === '' || v === false) return [];
    return [v];
  }
  return undefined;
}
