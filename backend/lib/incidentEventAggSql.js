/**
 * Shared ioc_match_events aggregate columns for incident risk scoring.
 * Used by list, detail stats, and institution overview queries.
 */
export const IOC_MATCH_EVENT_STATS_SELECT = `
  COUNT(*)::bigint AS event_count,
  COUNT(DISTINCT NULLIF(
    COALESCE(
      NULLIF(m.match_context->>'observed_host', ''),
      NULLIF(m.host_name, ''),
      CASE
        WHEN (LOWER(COALESCE(m.source_type, '')) = 'dns' OR LOWER(COALESCE(m.parser_source, '')) ~ '(dns|bind_dns|resolver)')
          THEN NULLIF(m.match_context->>'client_ip', '')
        WHEN (LOWER(COALESCE(m.source_type, '')) = 'proxy' OR LOWER(COALESCE(m.parser_source, '')) ~ '(proxy|squid|web)')
          THEN NULLIF(m.match_context->>'client_ip', '')
        WHEN (LOWER(COALESCE(m.source_type, '')) = 'firewall' OR LOWER(COALESCE(m.parser_source, '')) ~ '(firewall|forti|palo|pan-os|checkpoint|traffic)')
          THEN NULLIF(m.match_context->>'srcip', '')
        ELSE NULL
      END,
      CASE
        WHEN (LOWER(COALESCE(m.source_type, '')) = 'dns' OR LOWER(COALESCE(m.parser_source, '')) ~ '(dns|bind_dns|resolver)')
          THEN NULLIF((regexp_match(COALESCE(m.raw_log_snapshot, ''), '\\bclient\\s+[^\\s]*\\s*([0-9]{1,3}(?:\\.[0-9]{1,3}){3})#[0-9]+'))[1], '')
        WHEN (LOWER(COALESCE(m.source_type, '')) = 'proxy' OR LOWER(COALESCE(m.parser_source, '')) ~ '(proxy|squid|web)')
          THEN COALESCE(
            NULLIF((regexp_match(COALESCE(m.raw_log_snapshot, ''), '\\s([0-9]{1,3}(?:\\.[0-9]{1,3}){3})\\s+TCP_[A-Z_]+\\/[0-9]{3}'))[1], ''),
            NULLIF((regexp_match(COALESCE(m.raw_log_snapshot, ''), '\\b(?:TCP_[A-Z_]+|NONE)\\/(?:[0-9]{3}|-)\\s+([0-9]{1,3}(?:\\.[0-9]{1,3}){3})\\s'))[1], '')
          )
        WHEN (LOWER(COALESCE(m.source_type, '')) = 'firewall' OR LOWER(COALESCE(m.parser_source, '')) ~ '(firewall|forti|palo|pan-os|checkpoint|traffic)')
          THEN NULLIF((regexp_match(COALESCE(m.raw_log_snapshot, ''), '\\bsrcip=([0-9]{1,3}(?:\\.[0-9]{1,3}){3})\\b'))[1], '')
        ELSE NULL
      END
    ),
    ''
  ))::int AS asset_count,
  SUM(CASE WHEN LOWER(COALESCE(m.match_context->>'action', '')) IN ('accept','accepted','allow','allowed','permit') THEN 1 ELSE 0 END)::bigint AS accepted_connections,
  SUM(CASE WHEN LOWER(COALESCE(m.match_context->>'action', '')) IN ('deny','denied','drop','blocked','block') THEN 1 ELSE 0 END)::bigint AS blocked_connections,
  SUM(CASE
        WHEN LOWER(COALESCE(m.match_context->>'direction', '')) = 'inbound'
          OR LOWER(COALESCE(m.match_context->>'flow', '')) = 'inbound'
        THEN 1 ELSE 0
      END)::bigint AS inbound_events,
  SUM(CASE
        WHEN LOWER(COALESCE(m.match_context->>'direction', '')) = 'outbound'
          OR LOWER(COALESCE(m.match_context->>'flow', '')) = 'outbound'
        THEN 1 ELSE 0
      END)::bigint AS outbound_events,
  SUM(CASE
        WHEN LOWER(COALESCE(m.match_context->>'list', '')) = 'blacklist'
          OR LOWER(COALESCE(m.match_context->>'threat_list', '')) = 'blacklist'
          OR LOWER(COALESCE(m.source_name, '')) LIKE '%blacklist%'
        THEN 1 ELSE 0
      END)::bigint AS blacklist_hits,
  BOOL_OR(
    LOWER(COALESCE(m.source_type, '')) ~ '(endpoint|edr|xdr|sysmon|process|file|hash)'
    OR LOWER(COALESCE(m.parser_source, '')) ~ '(endpoint|edr|xdr|sysmon|process|file|hash)'
  ) AS has_endpoint_evidence,
  BOOL_OR(
    LOWER(COALESCE(m.source_type, '')) ~ '(proxy|squid|web|url)'
    OR LOWER(COALESCE(m.parser_source, '')) ~ '(proxy|squid|web|url)'
  ) AS has_proxy_evidence,
  BOOL_OR(
    LOWER(COALESCE(m.source_type, '')) ~ '(dns|bind_dns|resolver|dns_kv)'
    OR LOWER(COALESCE(m.parser_source, '')) ~ '(dns|bind_dns|resolver|dns_kv)'
  ) AS has_dns_evidence,
  BOOL_OR(
    LOWER(COALESCE(m.source_type, '')) ~ '(firewall|forti|palo|pan-os|checkpoint|traffic|netflow)'
    OR LOWER(COALESCE(m.parser_source, '')) ~ '(firewall|forti|palo|pan-os|checkpoint|traffic|netflow)'
  ) AS has_firewall_evidence,
  (
    SELECT LOWER(NULLIF(st.source_type, ''))
    FROM (
      SELECT LOWER(COALESCE(NULLIF(m2.source_type, ''), 'generic')) AS source_type, COUNT(*)::bigint AS c
      FROM ioc_match_events m2
      WHERE m2.activity_id = a.id
      GROUP BY 1
      ORDER BY c DESC, source_type ASC
      LIMIT 1
    ) st
  ) AS dominant_source_type,
  (
    SELECT LOWER(NULLIF(st.parser_source, ''))
    FROM (
      SELECT LOWER(COALESCE(NULLIF(m2.parser_source, ''), 'unknown')) AS parser_source, COUNT(*)::bigint AS c
      FROM ioc_match_events m2
      WHERE m2.activity_id = a.id
      GROUP BY 1
      ORDER BY c DESC, parser_source ASC
      LIMIT 1
    ) st
  ) AS dominant_parser_source,
  CASE
    WHEN BOOL_OR(LOWER(COALESCE(m.detection_type, '')) = 'realtime') THEN 'realtime'
    WHEN BOOL_OR(LOWER(COALESCE(m.detection_type, '')) IN ('retro', 'retroactive')) THEN 'retro'
    ELSE NULL
  END AS detection_type,
  CASE
    WHEN BOOL_OR(LOWER(COALESCE(m.confidence, '')) = 'high') THEN 'high'
    WHEN BOOL_OR(LOWER(COALESCE(m.confidence, '')) = 'medium') THEN 'medium'
    WHEN BOOL_OR(LOWER(COALESCE(m.confidence, '')) = 'low') THEN 'low'
    ELSE NULL
  END AS confidence
`;
