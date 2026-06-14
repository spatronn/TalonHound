/** Squid / explicit HTTP proxy evidence in a raw syslog line. */
export function rawLooksLikeSquidOrHttpProxy(raw) {
  return /\bsquid[_\s-]?proxy\b|\bTCP_(?:TUNNEL|MISS|HIT|DENIED|REFRESH|MEM_HIT|CLIENT_REFRESH)\/[0-9-]{3}|\bCONNECT\s+[^\s]+:[0-9]+|\bHIER_DIRECT\//i.test(String(raw || ''));
}

export function rawLooksLikeBindDns(raw) {
  return /\bbind_dns:\b/i.test(String(raw || ''))
    || /\bqueries:\s*info:\s*client\b/i.test(String(raw || ''))
    || /\bquery:\s*\S+\s+IN\s+[A-Z]+\b/i.test(String(raw || ''));
}

export function inferEventFamilyFromRow(row = {}) {
  const explicit = String(row.event_family || '').toLowerCase();
  if (explicit && explicit !== 'generic') return explicit;

  const sourceType = String(row.source_type || '').toLowerCase();
  const parser = String(row.parser_source || '').toLowerCase();
  const raw = String(row.raw_log_snapshot || row.raw_sample || '');

  if (rawLooksLikeSquidOrHttpProxy(raw)) return 'proxy';
  if (rawLooksLikeBindDns(raw)) return 'dns';
  if (sourceType === 'proxy' || /(proxy|squid|web|url|http)/.test(parser)) return 'proxy';
  if (sourceType === 'dns' || /(^|\s)dns(\s|$)|resolver|bind_dns/.test(parser)) return 'dns';
  if (sourceType === 'firewall' || /(firewall|forti|palo|pan-os|checkpoint|traffic|netflow)/.test(parser)) return 'firewall';
  if (/(endpoint|edr|xdr|sysmon|process|file|hash)/.test(sourceType)) return 'endpoint';
  return sourceType || 'generic';
}

export function isSubstantiveDnsEvent(row = {}) {
  const family = inferEventFamilyFromRow(row);
  if (family !== 'dns') return false;

  const raw = String(row.raw_log_snapshot || row.raw_sample || '').trim();
  if (rawLooksLikeBindDns(raw) || /\bquery:/i.test(raw)) return true;

  const mc = row.match_context && typeof row.match_context === 'object' ? row.match_context : {};
  if (mc.query || mc.response_ip) return true;

  // Correlation stubs: source_type=dns with no raw payload are not display evidence.
  if (!raw) {
    const parser = String(row.parser_source || '').toLowerCase();
    if (parser === 'syslog_observables' || parser === 'unknown') return false;
  }

  return Boolean(raw);
}

export function extractProxyHttpStatus(row = {}) {
  const status = String(row?.normalized_event_json?.status || row?.match_context?.status || row?.match_context?.http_status || '').trim();
  if (/^\d{3}$/.test(status)) return Number(status);

  const raw = String(row.raw_log_snapshot || row.raw_sample || '');
  const m = raw.match(/\bTCP_(?:TUNNEL|MISS|HIT|DENIED|REFRESH|MEM_HIT|CLIENT_REFRESH)\/(\d{3})\b/i);
  return m ? Number(m[1]) : null;
}

export function isProxyFailedEvent(row = {}) {
  const family = inferEventFamilyFromRow(row);
  if (family !== 'proxy' && !rawLooksLikeSquidOrHttpProxy(row.raw_log_snapshot || row.raw_sample || '')) return false;

  const action = String(row?.match_context?.action || row?.normalized_event_json?.action || '').toLowerCase();
  if (['deny', 'denied', 'drop', 'dropped', 'block', 'blocked', 'reject', 'rejected'].includes(action)) return true;

  const status = extractProxyHttpStatus(row);
  if (Number.isFinite(status) && status >= 400) return true;

  const raw = String(row.raw_log_snapshot || row.raw_sample || '').toLowerCase();
  return /\btcp_(?:tunnel|miss|hit|denied)\/(?:50[0-9]|4\d{2})\b/.test(raw);
}

export function isProxyAccessObservedEvent(row = {}) {
  const family = inferEventFamilyFromRow(row);
  if (family !== 'proxy' && !rawLooksLikeSquidOrHttpProxy(row.raw_log_snapshot || row.raw_sample || '')) return false;

  const action = String(row?.match_context?.action || row?.normalized_event_json?.action || '').toLowerCase();
  if (['accept', 'accepted', 'allow', 'allowed', 'permit'].includes(action)) return true;

  const method = String(row?.normalized_event_json?.method || row?.match_context?.method || '').toUpperCase();
  const status = extractProxyHttpStatus(row);
  const raw = String(row.raw_log_snapshot || row.raw_sample || '').toLowerCase();

  if (method === 'CONNECT' && status >= 200 && status < 400) return true;
  if (status >= 200 && status < 400) return true;
  if (/tcp_(?:miss|tunnel)\/(?:200|301|302)\b/.test(raw)) return true;
  if (/(GET|POST|HEAD|PUT|DELETE)/.test(method) && /(?:^|\D)(200|301|302)(?:\D|$)/.test(raw)) return true;

  return false;
}
