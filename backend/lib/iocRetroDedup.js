function clean(value) {
  return String(value || '').trim().toLowerCase();
}

function timeKey(value) {
  if (!value) return '';
  const ms = new Date(value).getTime();
  return Number.isNaN(ms) ? String(value || '') : new Date(ms).toISOString();
}

export function normalizeRetroSourceType(row = {}) {
  const explicit = clean(row.source_type);
  const tokens = [row.source_type, row.parser_source, row.source, row.protocol]
    .map((v) => clean(v))
    .join(' ');
  if (explicit && explicit !== 'generic') return explicit;
  if (/(proxy|url|http|webproxy|swg|squid)/.test(tokens)) return 'proxy';
  if (/(^|\s)dns(\s|$)|bind_dns|resolver|query/.test(tokens)) return 'dns';
  if (/(waf|f5|asm|modsecurity|nginx-waf)/.test(tokens)) return 'waf';
  if (/(endpoint|edr|xdr|sysmon|process|file)/.test(tokens)) return 'endpoint';
  if (/(firewall|traffic|forti|palo|pan-os|checkpoint|netflow)/.test(tokens)) return 'firewall';
  return explicit || 'generic';
}

export function isRealtimeEquivalentForRetro(retro = {}, realtime = {}) {
  if (clean(realtime.detection_type) !== 'realtime') return false;
  if (clean(retro.ioc_type) !== clean(realtime.ioc_type)) return false;
  if (clean(retro.matched_ioc) !== clean(realtime.matched_ioc)) return false;
  if (timeKey(retro._bucketStart || retro.bucket_start) !== timeKey(realtime.bucket_start)) return false;
  if (clean(retro.source) !== clean(realtime.source)) return false;
  if (clean(retro.host || retro.host_name) !== clean(realtime.host_name || realtime.host)) return false;

  const retroSourceType = normalizeRetroSourceType(retro);
  const realtimeSourceType = normalizeRetroSourceType(realtime);
  if (retroSourceType !== realtimeSourceType) return false;

  const retroLogId = clean(retro.syslog_log_id);
  const realtimeLogId = clean(realtime.syslog_log_id);
  if (retroLogId && realtimeLogId) return retroLogId === realtimeLogId;

  const retroRawHash = clean(retro.raw_log_hash);
  const realtimeRawHash = clean(realtime.raw_log_hash);
  if (retroRawHash && realtimeRawHash) return retroRawHash === realtimeRawHash;

  return true;
}

export async function filterRetroRowsWithRealtimeDuplicates(client, rows = []) {
  if (!rows.length) return { kept: [], skipped: [] };

  const values = [];
  const params = [];
  rows.forEach((r, idx) => {
    const base = idx * 6;
    values.push(`($${base + 1}::int,$${base + 2}::text,$${base + 3}::text,$${base + 4}::text,$${base + 5}::text,$${base + 6}::timestamptz)`);
    params.push(
      idx,
      clean(r.matched_ioc),
      clean(r.ioc_type),
      String(r.source || ''),
      String(r.host || r.host_name || ''),
      r._bucketStart || r.bucket_start
    );
  });

  const q = await client.query(
    `WITH candidates(idx, matched_ioc, ioc_type, source, host_name, bucket_start) AS (
       VALUES ${values.join(',')}
     )
     SELECT
       c.idx,
       e.id,
       e.matched_ioc,
       e.ioc_type,
       e.source,
       e.host_name,
       e.bucket_start,
       e.detection_type,
       e.parser_source,
       e.source_type,
       e.raw_log_hash,
       e.syslog_log_id
     FROM candidates c
     JOIN ioc_match_events e
       ON lower(e.matched_ioc) = c.matched_ioc
      AND lower(e.ioc_type) = c.ioc_type
      AND COALESCE(e.source, '') = c.source
      AND COALESCE(e.host_name, '') = c.host_name
      AND e.bucket_start = c.bucket_start
     WHERE lower(COALESCE(e.detection_type, '')) = 'realtime'`,
    params
  );

  const duplicates = new Map();
  for (const existing of q.rows || []) {
    const idx = Number(existing.idx);
    const retro = rows[idx];
    if (!retro) continue;
    if (isRealtimeEquivalentForRetro(retro, existing)) {
      const current = duplicates.get(idx) || [];
      current.push(existing.id);
      duplicates.set(idx, current);
    }
  }

  const kept = [];
  const skipped = [];
  rows.forEach((row, idx) => {
    const duplicateEventIds = duplicates.get(idx);
    if (duplicateEventIds?.length) skipped.push({ row, duplicateEventIds });
    else kept.push(row);
  });

  return { kept, skipped };
}
