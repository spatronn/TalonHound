/**
 * Shared detection-event source family normalization (aligned with classifyEventContext).
 */

export function rawLooksLikeSquidOrHttpProxy(raw) {
  return /\bsquid[_\s-]?proxy\b|\bTCP_(?:TUNNEL|MISS|HIT|DENIED|REFRESH|MEM_HIT|CLIENT_REFRESH)\/[0-9-]{3}|\bCONNECT\s+[^\s]+:[0-9]+|\bHIER_DIRECT\//i.test(String(raw || ''));
}

export function normEventSourceType(row = {}) {
  const st = String(row?.source_type || '').toLowerCase();
  if (st === 'squid_proxy') return 'proxy';
  if (st && !['generic', 'unknown', ''].includes(st)) return st;

  const parser = String(row?.parser_source || '').toLowerCase();
  const raw = String(row?.raw_log_snapshot || row?.raw_sample || row?.raw_message_sample || '');
  const rawLower = raw.toLowerCase();

  if (rawLooksLikeSquidOrHttpProxy(raw) || /(proxy|squid|web|http)/.test(parser)) return 'proxy';

  const bindDnsSig = /\bbind_dns:\b/i.test(raw)
    || /\bqueries:\s*info:\s*client\b/i.test(raw)
    || /\bquery:\s*\S+\s+IN\s+[A-Z]+\b/i.test(raw);
  if (bindDnsSig || /(dns|bind|resolver|microsoft_dns)/.test(parser)) return 'dns';

  if (/(firewall|forti|palo|pan-os|checkpoint|traffic|netflow)/.test(parser)) return 'firewall';
  if (/\b(srcip|dstip)=/.test(rawLower) || /\baction=(allow|deny|drop)\b/.test(rawLower)) return 'firewall';

  return st || 'generic';
}
