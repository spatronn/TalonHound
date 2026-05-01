import { buildIncidentStatsSnapshot, buildIncidentVersion } from './llmRiskCommon.js';

const ALLOWED_ADJUSTMENTS = new Set([-10, -5, 0, 5, 10]);

function toBool(v, defaultValue = false) {
  if (v == null) return defaultValue;
  const s = String(v).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(s)) return true;
  if (['0', 'false', 'no', 'off'].includes(s)) return false;
  return defaultValue;
}

function clamp(value, min = 0, max = 100) {
  return Math.min(Math.max(Number(value) || 0, min), max);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(Number(ms) || 0, 0)));
}

function isTimeoutError(err) {
  const name = String(err?.name || '');
  const code = String(err?.code || '').toUpperCase();
  const msg = String(err?.message || '').toLowerCase();
  if (name === 'AbortError') return true;
  if (code === 'ETIMEDOUT') return true;
  if (msg.includes('socket hang up')) return true;
  return false;
}

function normalizeAdjustment(raw) {
  const n = Number(String(raw ?? '').replace(/^\+/, ''));
  if (!Number.isFinite(n)) return 0;
  return ALLOWED_ADJUSTMENTS.has(n) ? n : 0;
}

function normalizeConfidence(raw) {
  const c = Number(raw);
  if (!Number.isFinite(c)) return 0;
  return clamp(c, 0, 1);
}

function extractJson(text) {
  if (!text || typeof text !== 'string') return null;

  try {
    return JSON.parse(text);
  } catch {
    // continue
  }

  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;

  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
}

function normalizeAdvisorOutput(raw, fallbackReason = 'fallback') {
  const parsed = raw && typeof raw === 'object' ? raw : {};
  const confidence = normalizeConfidence(parsed.confidence);
  let reason = String(parsed.reason || fallbackReason || 'fallback').slice(0, 240);

  if (/blacklist/i.test(reason)) {
    return {
      adjustment: 0,
      confidence: 0,
      reason: 'invalid_reason_blacklist_reference'
    };
  }

  if (confidence < 0.6) {
    return {
      adjustment: 0,
      confidence,
      reason: reason || 'low_confidence'
    };
  }

  return {
    adjustment: normalizeAdjustment(parsed.adjustment),
    confidence,
    reason
  };
}

function buildGenericPrompt() {
  return `You are a cybersecurity risk assistant. Return a small adjustment score only.
Rules:
- Return ONLY JSON
- adjustment must be one of: -10, -5, 0, +5, +10
- Never claim facts not present in Incident Data
- Do not mention blacklist
- Reason should focus on: ioc_type, total_hits/hits, event_count, observed_hosts/unique_hosts, duration, persistence
Output:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildDomainPrompt() {
  return `DOMAIN IOC ANALYSIS RULES:
- Domain IOC incidents must be evaluated using DNS behavior, not accepted/blocked traffic.
- DNS queries to suspicious or matched IOC domains are meaningful security signals.
- Use total_hits/hits as the main volume signal.
- Use event_count only as the number of sampled/correlated detection events, not as total activity volume.
- Multiple observed hosts increase concern.
- Persistence over time increases concern.
- Repeated DNS queries over a long duration may indicate beaconing, malware communication, or misconfigured repeated access.
- Do not mention blacklist status.
- Do not decrease risk when DNS volume is high or persistent.
Increase risk if:
- total_hits is high
- observed_hosts >= 2
- duration is long
- repeated DNS queries are observed
Return neutral if:
- total_hits is low
- single host
- short duration
- no persistence
Decrease risk only if:
- there is clear evidence of benign/test activity
- very low volume and no persistence
Return ONLY JSON:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildIpPrompt() {
  return `IP IOC ANALYSIS RULES:
- accepted/blocked logic applies only for IP/network IOC.
- Use accepted_connections, blocked_connections, inbound_events, outbound_events, unique_hosts/observed_hosts, and persistence.
- Do not mention blacklist status.
Increase risk:
- accepted traffic is meaningful
- multiple hosts affected
- persistent activity over time
Decrease risk:
- mostly blocked traffic
- clear scanning/noise pattern with low persistence
Return ONLY JSON:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildUrlPrompt() {
  return `URL IOC ANALYSIS RULES:
- Focus on url_requests/request_count, successful access, unique users/hosts, persistence, and suspicious path patterns.
- Do not mention blacklist status.
Increase risk:
- successful and repeated URL access
- multiple hosts/users
- persistent activity or suspicious path behavior
Decrease risk:
- very low request volume and no persistence
Return ONLY JSON:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildHashPrompt() {
  return `HASH IOC ANALYSIS RULES:
- Focus on affected_hosts, file_observations, execution evidence, and persistence/spread behavior.
- Do not mention blacklist status.
Increase risk:
- multiple affected hosts
- execution evidence
- persistence or spread over time
Decrease risk:
- single host, very low observations, no spread evidence
Return ONLY JSON:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildPromptByType(iocType) {
  if (iocType === 'domain') return buildDomainPrompt();
  if (iocType === 'ip') return buildIpPrompt();
  if (iocType === 'url') return buildUrlPrompt();
  if (iocType === 'hash') return buildHashPrompt();
  return buildGenericPrompt();
}

function normalizeIocType(raw) {
  const t = String(raw || '').toLowerCase();
  if (t === 'ip') return 'ip';
  if (t === 'domain') return 'domain';
  if (t === 'url') return 'url';
  if (['md5', 'sha1', 'sha256', 'hash', 'file_hash'].includes(t)) return 'hash';
  return 'unknown';
}

function parseTags(raw) {
  if (Array.isArray(raw)) return raw.map((x) => String(x)).filter(Boolean);
  if (typeof raw === 'string' && raw.trim()) {
    return raw.split(',').map((x) => x.trim()).filter(Boolean);
  }
  return [];
}

function normalizeVerdict(raw) {
  const v = String(raw || '').toLowerCase();
  if (v === 'fp') return 'fp';
  if (v === 'tp') return 'tp';
  if (v === 'suspicious') return 'suspicious';
  return 'unknown';
}

function buildIncidentPayload(incident = {}) {
  const snapshot = buildIncidentStatsSnapshot(incident);
  const iocType = normalizeIocType(incident?.ioc_type || incident?.observable_type);
  const totalHits = Math.max(Number(incident?.hits ?? incident?.total_hits ?? snapshot.total_events || 0), 0);
  const eventCount = Math.max(Number(incident?.event_count ?? snapshot.total_events || 0), 0);
  const observedHosts = Math.max(Number(incident?.observed_hosts ?? incident?.asset_count ?? snapshot.unique_hosts || 0), 0);
  const firstSeenMs = incident?.first_seen ? new Date(incident.first_seen).getTime() : NaN;
  const lastSeenMs = incident?.last_seen ? new Date(incident.last_seen).getTime() : NaN;
  const durationMinutes = Number.isFinite(firstSeenMs) && Number.isFinite(lastSeenMs) && lastSeenMs >= firstSeenMs
    ? Math.round((lastSeenMs - firstSeenMs) / 60000)
    : 0;

  const base = {
    ioc: String(incident?.ioc_value || incident?.observable_value || ''),
    ioc_type: iocType,
    activity_type: iocType === 'domain' ? 'dns' : iocType,
    first_seen: incident?.first_seen || null,
    last_seen: incident?.last_seen || null,
    duration_minutes: durationMinutes,
    history: {
      previous_incident_count: Math.max(Number(incident?.previous_incident_count || 0), 0),
      previous_verdict: normalizeVerdict(incident?.previous_verdict)
    }
  };

  if (iocType === 'domain') {
    return {
      ...base,
      stats: {
        total_hits: totalHits,
        hits: totalHits,
        dns_queries: totalHits,
        event_count: eventCount,
        observed_hosts: observedHosts,
        unique_hosts: observedHosts,
        duration_minutes: durationMinutes
      }
    };
  }

  if (iocType === 'ip') {
    return {
      ...base,
      stats: {
        total_hits: totalHits,
        event_count: eventCount,
        observed_hosts: observedHosts,
        unique_hosts: observedHosts,
        accepted_connections: snapshot.accepted_connections,
        blocked_connections: snapshot.blocked_connections,
        inbound_events: Math.max(Number(incident?.inbound_events || 0), 0),
        outbound_events: Math.max(Number(incident?.outbound_events || 0), 0),
        duration_minutes: durationMinutes
      }
    };
  }

  if (iocType === 'url') {
    return {
      ...base,
      stats: {
        total_hits: totalHits,
        event_count: eventCount,
        url_requests: totalHits,
        successful_access: Math.max(Number(incident?.accepted_connections || snapshot.accepted_connections || 0), 0),
        observed_hosts: observedHosts,
        unique_hosts: observedHosts,
        duration_minutes: durationMinutes
      }
    };
  }

  if (iocType === 'hash') {
    return {
      ...base,
      stats: {
        total_hits: totalHits,
        event_count: eventCount,
        file_observations: totalHits,
        affected_hosts: observedHosts,
        execution_evidence: Math.max(Number(incident?.accepted_connections || snapshot.accepted_connections || 0), 0),
        persistence_signals: Math.max(Number(incident?.previous_incident_count || 0), 0),
        duration_minutes: durationMinutes
      }
    };
  }

  return {
    ...base,
    stats: {
      total_hits: totalHits,
      event_count: eventCount,
      observed_hosts: observedHosts,
      unique_hosts: observedHosts,
      accepted_connections: snapshot.accepted_connections,
      blocked_connections: snapshot.blocked_connections,
      duration_minutes: durationMinutes
    }
  };
}

export function createLlmRiskAdvisor({ redis, queue } = {}) {
  const enabled = toBool(process.env.LLM_RISK_ADVISOR_ENABLED, false);
  const url = String(process.env.LLM_RISK_ADVISOR_URL || 'http://192.168.1.8:11434/api/generate').trim();
  const model = String(process.env.LLM_RISK_ADVISOR_MODEL || 'qwen2.7:7b').trim();
  const timeoutMs = Math.max(Number(process.env.LLM_RISK_ADVISOR_TIMEOUT_MS || 8000), 1000);
  const manualTimeoutMs = Math.max(Number(process.env.LLM_RISK_ADVISOR_MANUAL_TIMEOUT_MS || 25000), timeoutMs);
  const cacheTtlSeconds = Math.max(Number(process.env.LLM_RISK_ADVISOR_CACHE_TTL_SECONDS || 3600), 30);
  const aiWeight = Math.max(Number(process.env.LLM_RISK_ADVISOR_AI_WEIGHT || 2), 0);

  function computeFinalRisk(baseRisk, adjustment, confidence) {
    const base = clamp(Number(baseRisk || 0), 0, 100);
    const adj = Number(adjustment || 0);
    const conf = clamp(Number(confidence || 0), 0, 1);
    const weighted = adj * conf * aiWeight;
    return clamp(base + weighted, 0, 100);
  }

  function fallback(baseRisk, reason = 'fallback') {
    const base = clamp(Number(baseRisk || 0), 0, 100);
    return {
      risk_before_llm: Number(base.toFixed(2)),
      llm_risk_adjustment: 0,
      llm_risk_confidence: 0,
      llm_risk_reason: reason,
      final_risk_score: Number(base.toFixed(2))
    };
  }

  function getCacheKey(incidentId, version) {
    const id = String(incidentId || '').trim();
    const v = String(version || '').trim();
    if (!id || !v) return null;
    return `risk:llm:incident:${id}:${v}`;
  }

  async function getCached({ incidentId, version, baseRisk }) {
    const key = getCacheKey(incidentId, version);
    if (!key || !redis || typeof redis.get !== 'function') return null;

    try {
      const raw = await redis.get(key);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      const normalized = normalizeAdvisorOutput(parsed, 'cache');
      const base = clamp(Number(baseRisk || 0), 0, 100);
      const finalRisk = computeFinalRisk(base, normalized.adjustment, normalized.confidence);

      return {
        risk_before_llm: Number(base.toFixed(2)),
        llm_risk_adjustment: normalized.adjustment,
        llm_risk_confidence: Number(normalized.confidence.toFixed(3)),
        llm_risk_reason: normalized.reason,
        llm_last_updated_at: parsed?.llm_last_updated_at || null,
        llm_version: parsed?.llm_version || version || null,
        final_risk_score: Number(finalRisk.toFixed(2))
      };
    } catch {
      return null;
    }
  }

  async function setCached({ incidentId, version, value }) {
    const key = getCacheKey(incidentId, version);
    if (!key || !redis || typeof redis.set !== 'function') return;
    try {
      await redis.set(key, JSON.stringify(value), 'EX', cacheTtlSeconds);
    } catch {
      // no-op
    }
  }

  async function enqueueEvaluation({ incidentId, version, reason = 'manual' }) {
    if (!enabled) return false;
    if (!queue || typeof queue.add !== 'function') return false;

    const id = String(incidentId || '').trim();
    const v = String(version || '').trim();
    if (!id || !v) return false;

    try {
      await queue.add(
        'llm-risk-evaluate',
        { incidentId: id, version: v, reason },
        {
          jobId: `llm-risk:${id}:${v}`,
          removeOnComplete: true,
          removeOnFail: 200,
          attempts: 1
        }
      );
      return true;
    } catch {
      return false;
    }
  }

  async function evaluateAndCache({ incident, baseRisk, version, force = false, timeoutMsOverride } = {}) {
    const base = clamp(Number(baseRisk || 0), 0, 100);
    if (!enabled && !force) return fallback(base, 'disabled');

    const verdict = String(incident?.verdict || '').trim().toLowerCase();
    if (verdict === 'fp') {
      const out = fallback(base, 'fp_verdict_guard');
      out.llm_risk_adjustment = 0;
      return out;
    }

    const initialTimeout = Math.max(Number(timeoutMsOverride || timeoutMs), 1000);
    const retryBackoffMs = 5000;
    const secondTimeout = initialTimeout + 5000;

    async function singleAttempt(requestTimeoutMs) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
      try {
        const incidentPayload = buildIncidentPayload(incident);
        const payload = {
          model,
          stream: false,
          format: 'json',
          prompt: `${buildPromptByType(incidentPayload?.ioc_type)}\n\nIncident Data:\n${JSON.stringify(incidentPayload, null, 2)}`
        };

        const response = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal
        });

        if (!response.ok) {
          return { ok: false, kind: 'http', reason: `llm_http_${response.status}` };
        }

        const body = await response.json();
        const modelJson = extractJson(body?.response);
        if (!modelJson) {
          return { ok: false, kind: 'parse', reason: 'invalid_json' };
        }

        return { ok: true, normalized: normalizeAdvisorOutput(modelJson, 'ok') };
      } catch (err) {
        if (isTimeoutError(err)) return { ok: false, kind: 'timeout', reason: 'timeout' };
        return { ok: false, kind: 'network', reason: 'endpoint_unreachable' };
      } finally {
        clearTimeout(timer);
      }
    }

    const first = await singleAttempt(initialTimeout);
    let result = first;

    if (!first.ok && first.kind === 'timeout') {
      await sleep(retryBackoffMs);
      result = await singleAttempt(secondTimeout);
    }

    if (!result.ok) {
      return fallback(base, result.reason || 'fallback');
    }

    const normalized = result.normalized;
    await setCached({
      incidentId: incident?.id || incident?.incident_id,
      version,
      value: {
        ...normalized,
        llm_last_updated_at: new Date().toISOString(),
        llm_version: version || null
      }
    });

    const finalRisk = computeFinalRisk(base, normalized.adjustment, normalized.confidence);
    return {
      risk_before_llm: Number(base.toFixed(2)),
      llm_risk_adjustment: normalized.adjustment,
      llm_risk_confidence: Number(normalized.confidence.toFixed(3)),
      llm_risk_reason: normalized.reason,
      llm_last_updated_at: new Date().toISOString(),
      llm_version: version || null,
      final_risk_score: Number(finalRisk.toFixed(2))
    };
  }

  function computeVersion(input) {
    return buildIncidentVersion(input);
  }

  return {
    enabled,
    timeoutMs,
    manualTimeoutMs,
    fallback,
    computeVersion,
    getCached,
    enqueueEvaluation,
    evaluateAndCache
  };
}
