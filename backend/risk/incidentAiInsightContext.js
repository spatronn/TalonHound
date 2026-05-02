function ipToLong(ip) {
  const p = String(ip || '').split('.').map((x) => Number(x));
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3]) >>> 0;
}

function cidrContains(ip, cidr) {
  const [base, maskStr] = String(cidr || '').split('/');
  const mask = Number(maskStr);
  if (!base || !Number.isInteger(mask) || mask < 0 || mask > 32) return false;
  const ipN = ipToLong(ip);
  const baseN = ipToLong(base);
  if (ipN == null || baseN == null) return false;
  const m = mask === 0 ? 0 : ((0xffffffff << (32 - mask)) >>> 0);
  return (ipN & m) === (baseN & m);
}

function buildIgnoreCidrs() {
  const raw = String(process.env.AI_INSIGHT_HOST_IGNORE_CIDRS || '127.0.0.0/8,169.254.0.0/16,224.0.0.0/4,172.18.0.0/16');
  return raw.split(',').map((x) => x.trim()).filter(Boolean);
}

function isIgnoredHost(ip, cidrs) {
  return cidrs.some((c) => cidrContains(ip, c));
}

export async function enrichIncidentContextWithRelatedIocs(context, { pool } = {}) {
  if (!context || typeof context !== 'object') return { ...context, related_iocs: [] };
  if (!pool || typeof pool.query !== 'function') throw new Error('pool.query is required');
  if (!context?.id || String(context?.ioc_type || '').toLowerCase() !== 'domain') {
    return { ...context, related_iocs: [] };
  }

  const enableDnsResponseIpRelation = String(process.env.AI_INSIGHT_ENABLE_DNS_RESPONSE_IP_RELATION || 'false').trim().toLowerCase() === 'true';
  if (!enableDnsResponseIpRelation) {
    return { ...context, related_iocs: [] };
  }

  const lookbackHours = Math.max(Number(process.env.AI_INSIGHT_RELATED_IOC_LOOKBACK_HOURS || 24), 1);
  const lookforwardHours = Math.max(Number(process.env.AI_INSIGHT_RELATED_IOC_LOOKFORWARD_HOURS || 24), 1);
  const ignoreCidrs = buildIgnoreCidrs();

  const dnsQ = await pool.query(
    `SELECT
       COALESCE(NULLIF(m.match_context->>'response_ip',''), NULLIF(m.destination_ip,'')) AS response_ip,
       MIN(m.event_time) AS first_seen,
       MAX(m.event_time) AS last_seen,
       ARRAY_REMOVE(ARRAY_AGG(DISTINCT NULLIF(COALESCE(m.match_context->>'client_ip', m.host_name),'')), NULL) AS client_ips
     FROM ioc_match_events m
     WHERE m.activity_id = $1::uuid
       AND LOWER(COALESCE(m.ioc_type,'')) = 'domain'
     GROUP BY 1
     HAVING COALESCE(NULLIF(m.match_context->>'response_ip',''), NULLIF(m.destination_ip,'')) ~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'`,
    [context.id]
  );

  const relatedIocs = [];
  for (const row of dnsQ.rows || []) {
    const responseIp = row.response_ip;
    const inIoc = await pool.query(`SELECT 1 FROM ioc_activity WHERE ioc_type='ip' AND ioc_value=$1 LIMIT 1`, [responseIp]);

    const traffic = await pool.query(
      `SELECT
         SUM(CASE WHEN LOWER(COALESCE(match_context->>'action','')) IN ('accept','accepted','allow','allowed','permit') THEN 1 ELSE 0 END)::bigint AS accepted_count,
         SUM(CASE WHEN LOWER(COALESCE(match_context->>'action','')) IN ('deny','denied','drop','blocked','block') THEN 1 ELSE 0 END)::bigint AS blocked_count,
         MIN(event_time) AS first_seen,
         MAX(event_time) AS last_seen,
         ARRAY_REMOVE(ARRAY_AGG(DISTINCT NULLIF(COALESCE(match_context->>'srcip', host_name),'')), NULL) AS internal_hosts,
         ARRAY_REMOVE(ARRAY_AGG(DISTINCT (match_context->>'service')), NULL) AS services,
         ARRAY_REMOVE(ARRAY_AGG(DISTINCT (match_context->>'dstport')), NULL) AS ports,
         SUM(COALESCE(NULLIF(match_context->>'sentbyte','')::bigint,0))::bigint AS sent_bytes,
         SUM(COALESCE(NULLIF(match_context->>'rcvdbyte','')::bigint,0))::bigint AS received_bytes
       FROM ioc_match_events
       WHERE event_time BETWEEN ($2::timestamptz - ($4 || ' hours')::interval) AND ($3::timestamptz + ($5 || ' hours')::interval)
         AND (
           COALESCE(match_context->>'dstip', destination_ip) = $1
           OR COALESCE(match_context->>'srcip', host_name) = $1
         )`,
      [responseIp, context.first_seen, context.last_seen, lookbackHours, lookforwardHours]
    );

    const t = traffic.rows?.[0] || {};
    const rawDnsClientIps = row.client_ips || [];
    const rawTrafficHosts = t.internal_hosts || [];
    const ignoredHosts = [];
    const filteredDnsClientHosts = rawDnsClientIps.filter((ip) => {
      const ignored = isIgnoredHost(ip, ignoreCidrs);
      if (ignored) ignoredHosts.push(ip);
      return !ignored;
    });
    const filteredTrafficInternalHosts = rawTrafficHosts.filter((ip) => {
      const ignored = isIgnoredHost(ip, ignoreCidrs);
      if (ignored && !ignoredHosts.includes(ip)) ignoredHosts.push(ip);
      return !ignored;
    });

    const acceptedCount = Number(t.accepted_count || 0);
    const sameHost = filteredDnsClientHosts.some((ip) => filteredTrafficInternalHosts.includes(ip));

    let chainType = 'linked_ioc_without_accepted_traffic';
    let attributionStatus = null;
    let riskSignal = 'low_to_medium';
    if (acceptedCount > 0 && sameHost) {
      chainType = 'same_host_dns_to_connection';
      riskSignal = 'high';
    } else if (acceptedCount > 0 && filteredTrafficInternalHosts.length > 0) {
      chainType = 'environment_level_related_activity';
      riskSignal = 'medium';
    } else if (acceptedCount > 0) {
      chainType = 'accepted_traffic_to_related_ioc';
      riskSignal = 'medium';
      attributionStatus = 'accepted_traffic_without_valid_host_attribution';
    } else if (filteredDnsClientHosts.length === 0) {
      attributionStatus = 'no_valid_dns_client_after_filter';
    }

    relatedIocs.push({
      relationship: 'dns_response_ip',
      source_ioc: context.ioc_value,
      source_ioc_type: 'domain',
      related_ioc: responseIp,
      related_ioc_type: 'ip',
      related_ioc_in_ioc_list: inIoc.rowCount > 0,
      chain_type: chainType,
      attribution_status: attributionStatus,
      raw_dns_client_ips: rawDnsClientIps,
      filtered_dns_client_hosts: filteredDnsClientHosts,
      raw_traffic_hosts: rawTrafficHosts,
      filtered_traffic_internal_hosts: filteredTrafficInternalHosts,
      ignored_hosts: ignoredHosts,
      ignore_cidrs_used: ignoreCidrs,
      dns: {
        query: context.ioc_value,
        response_ip: responseIp,
        client_ips: filteredDnsClientHosts,
        first_seen: row.first_seen,
        last_seen: row.last_seen
      },
      traffic: {
        accepted_count: acceptedCount,
        blocked_count: Number(t.blocked_count || 0),
        unique_internal_hosts: filteredTrafficInternalHosts.length,
        internal_hosts: filteredTrafficInternalHosts,
        ports: (t.ports || []).map((x) => Number(x)).filter(Boolean),
        services: t.services || [],
        first_seen: t.first_seen || null,
        last_seen: t.last_seen || null,
        sent_bytes: Number(t.sent_bytes || 0),
        received_bytes: Number(t.received_bytes || 0)
      },
      risk_signal: riskSignal
    });
  }

  return {
    ...context,
    related_iocs: relatedIocs
  };
}

export function summarizeRelatedIocSignals(relatedIocs) {
  const list = Array.isArray(relatedIocs) ? relatedIocs : [];
  const hasAccepted = list.some((r) => Number(r?.traffic?.accepted_count || 0) > 0);
  const hasIocListMatch = list.some((r) => r?.related_ioc_in_ioc_list === true);
  return {
    related_iocs_count: list.length,
    related_iocs_has_accepted_traffic: hasAccepted,
    related_iocs_has_ioc_list_match: hasIocListMatch
  };
}
