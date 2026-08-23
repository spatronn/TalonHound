-- Canonical enrichment-provider health store.
--
-- Health is deliberately separated from enrichment usage. Prior to this table,
-- provider health was derived from the freshness of the last *enrichment* (via
-- threat_intel_provider_configs.last_success_at, itself written by real IOC
-- enrichment traffic). That made an idle-but-working provider drift to Unknown
-- once the last analyst enrichment aged past the freshness window.
--
-- This table records only explicit health-check evidence: manual "Test
-- Connection" actions and scheduled 24h health probes. Enrichment activity is
-- tracked independently in enrichment_usage_daily and never writes here.
--
-- One row per active-probe provider (virustotal, ipinfo_lite, abuseipdb, rdap).
-- Spamhaus DROP keeps deriving operational health from its dataset sync and is
-- not probed, so it does not require a row here.

CREATE TABLE IF NOT EXISTS enrichment_provider_health (
  provider TEXT PRIMARY KEY,
  -- Canonical status: healthy | degraded | unhealthy | unknown
  status TEXT NOT NULL DEFAULT 'unknown',
  -- Last probe attempt of any outcome.
  last_check_at TIMESTAMPTZ,
  -- Last successful probe.
  last_success_at TIMESTAMPTZ,
  -- Last failed probe.
  last_failure_at TIMESTAMPTZ,
  -- Origin of the most recent probe: manual | scheduled.
  check_source TEXT,
  -- Sanitized error class of the most recent failure:
  -- auth | rate_limit | network | timeout | http | not_configured | unknown
  error_category TEXT,
  -- Sanitized, human-readable evidence for the current status. Never contains
  -- secrets, tokens, or raw provider response bodies.
  evidence TEXT,
  -- Consecutive failed probes; reset to zero on any success. Drives the
  -- transient-failure -> degraded -> unhealthy escalation.
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT enrichment_provider_health_status_chk
    CHECK (status IN ('healthy', 'degraded', 'unhealthy', 'unknown'))
);
