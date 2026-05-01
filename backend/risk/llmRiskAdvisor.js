import crypto from 'crypto';
import { buildIncidentStatsSnapshot, buildIncidentVersion } from './llmRiskCommon.js';

const ALLOWED_ADJUSTMENTS = new Set([-20, -10, -5, 0, 5, 10, 15, 20]);

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

function normalizeAdvisorOutput(raw, fallbackReason = 'fallback', incidentData = null) {
  const parsed = raw && typeof raw === 'object' ? raw : {};
  const data = incidentData && typeof incidentData === 'object' ? incidentData : {};
  let confidence = normalizeConfidence(parsed.confidence);
  let reason = String(parsed.reason || fallbackReason || 'fallback').slice(0, 240);
  const rawModelAdjustment = normalizeAdjustment(parsed.adjustment ?? parsed.risk_adjustment);
  let adjustment = rawModelAdjustment;

  if (/blacklist/i.test(reason)) {
    return { adjustment: 0, confidence: 0, reason: 'invalid_reason_blacklist_reference', raw_model_adjustment: rawModelAdjustment };
  }

  const appendOnce = (base, msg) => (String(base).includes(msg) ? String(base) : `${base} ${msg}`.trim());
  const drivers = Array.isArray(parsed.main_risk_drivers) ? parsed.main_risk_drivers.map((x) => String(x)) : [];
  const reducing = Array.isArray(parsed.risk_reducing_factors) ? parsed.risk_reducing_factors.map((x) => String(x)) : [];
  const evidenceText = `${reason} ${drivers.join(' ')}`.toLowerCase();

  const stats = data?.stats || {};
  const iocType = String(data?.ioc_type || '').toLowerCase();
  const activityType = String(data?.activity_type || '').toLowerCase();
  const toNum = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

  const highVolumeMinHits = Math.max(Number(process.env.AI_INSIGHT_HIGH_VOLUME_MIN_HITS || 1000), 1);
  const multipleHostsMin = Math.max(Number(process.env.AI_INSIGHT_MULTIPLE_HOSTS_MIN || 2), 1);
  const longDurationHoursMin = Math.max(Number(process.env.AI_INSIGHT_LONG_DURATION_MIN_HOURS || 24), 1);
  const dnsLongDurationMinMinutes = Math.max(Number(process.env.AI_INSIGHT_DNS_LONG_DURATION_MIN_MINUTES || 720), 1);

  const totalHits = toNum(stats.total_hits ?? stats.hits ?? stats.dns_queries ?? stats.event_count ?? data.total_hits ?? data.hits ?? data.dns_queries ?? data.event_count);
  const hostCount = toNum(stats.observed_hosts ?? stats.unique_hosts ?? stats.affected_hosts ?? data.observed_hosts ?? data.unique_hosts ?? data.affected_hosts);
  const durationMinutesFromField = toNum(stats.duration_minutes ?? data.duration_minutes);
  const durationHoursFromField = toNum(stats.duration_hours ?? data.duration_hours);
  const firstSeenMs = data?.first_seen ? new Date(data.first_seen).getTime() : (data?.first_seen_at ? new Date(data.first_seen_at).getTime() : NaN);
  const lastSeenMs = data?.last_seen ? new Date(data.last_seen).getTime() : (data?.last_seen_at ? new Date(data.last_seen_at).getTime() : NaN);
  const durationMinutes = durationMinutesFromField > 0
    ? durationMinutesFromField
    : (durationHoursFromField > 0 ? durationHoursFromField * 60 : (Number.isFinite(firstSeenMs) && Number.isFinite(lastSeenMs) && lastSeenMs >= firstSeenMs ? (lastSeenMs - firstSeenMs) / 60000 : 0));

  const hasHighVolumeMetric = totalHits >= highVolumeMinHits;
  const hasMultipleHostsMetric = hostCount >= multipleHostsMin;
  const isDnsLike = activityType === 'dns' || iocType === 'domain';
  const hasLongDurationMetric = isDnsLike
    ? durationMinutes >= dnsLongDurationMinMinutes
    : (durationHoursFromField > 0 ? durationHoursFromField >= longDurationHoursMin : (durationMinutes / 60) >= longDurationHoursMin);

  const relatedIocs = Array.isArray(data?.related_iocs) ? data.related_iocs : [];
  const relatedAccepted = relatedIocs.some((r) => Number(r?.traffic?.accepted_count || 0) > 0);
  const relatedInList = relatedIocs.some((r) => r?.related_ioc_in_ioc_list === true);
  const hasSameHostChain = relatedIocs.some((r) => r?.chain_type === 'same_host_dns_to_connection');
  const hasEnvChain = relatedIocs.some((r) => r?.chain_type === 'environment_level_related_activity');

  const hasAcceptedOrSuccessfulMetric = toNum(stats.accepted_connections ?? stats.successful_access ?? data.accepted_count ?? data.successful_count) > 0 || relatedAccepted;
  const hasStrongMaliciousContextMetric = /(\btp\b|high-confidence|high confidence|\bc2\b|malware|ransomware|phishing|botnet|scanner|exploit)/i.test(evidenceText)
    || String(data?.history?.previous_verdict || '').toLowerCase() === 'tp'
    || relatedInList;
  const hasBenignEvidenceMetric = /(false positive|\bfp\b|allowlisted|trusted benign|known internal test|smoke test|benign destination|internal security test)/i.test(evidenceText)
    || reducing.some((x) => /(allowlisted|trusted|benign|internal test|false positive|fp)/i.test(String(x)))
    || String(data?.history?.previous_verdict || '').toLowerCase() === 'fp';

  // text fallback only when metrics are unavailable
  const hasHighVolume = totalHits > 0 ? hasHighVolumeMetric : /(high total_hits|high volume|many queries|high dns|high hits)/i.test(evidenceText);
  const hasMultipleHosts = hostCount > 0 ? hasMultipleHostsMetric : /(multiple hosts|many hosts|multiple observed hosts|observed_hosts\s*>=\s*2|unique_hosts\s*>=\s*2)/i.test(evidenceText);
  const hasLongDuration = durationMinutes > 0 ? hasLongDurationMetric : /(long duration|persistence|persistent|over several hours|over time|repeated over long duration)/i.test(evidenceText);
  const hasRepeatedOnly = /(repeated dns|repeated)/i.test(evidenceText);
  const hasAcceptedOrSuccessful = hasAcceptedOrSuccessfulMetric || /(accepted|successful)/i.test(evidenceText);
  const hasStrongMaliciousContext = hasStrongMaliciousContextMetric;
  const explicitBenign = hasBenignEvidenceMetric;

  let floor = 0;
  if (!explicitBenign) {
    if (hasEnvChain && relatedAccepted) floor = Math.max(floor, 5);
    if (hasSameHostChain && relatedAccepted) floor = Math.max(floor, 10);
    if (hasHighVolume && hasMultipleHosts && hasLongDuration) floor = Math.max(floor, 5);
    if (floor >= 5 && (hasAcceptedOrSuccessful || hasStrongMaliciousContext)) floor = Math.max(floor, 10);
  }

  let normalizationReason = null;
  if (!explicitBenign && adjustment < floor) {
    adjustment = floor;
    confidence = Math.min(confidence || 0.6, 0.6);
    normalizationReason = 'deterministic_guardrail_floor';
    reason = appendOnce(reason, 'Final adjustment was normalized by deterministic guardrails based on incident metrics.').slice(0, 240);
  } else if (!explicitBenign && rawModelAdjustment < 0 && floor === 0 && (hasHighVolume || hasRepeatedOnly || hasMultipleHosts || hasLongDuration)) {
    adjustment = 0;
    confidence = Math.min(confidence || 0.6, 0.6);
    normalizationReason = 'negative_neutralized';
    reason = appendOnce(reason, 'Negative adjustment was neutralized because the stated drivers are risk-increasing, not risk-reducing.').slice(0, 240);
  }

  return {
    adjustment,
    confidence,
    reason,
    raw_model_adjustment: rawModelAdjustment,
    normalization_reason: normalizationReason,
    hasHighVolume,
    hasMultipleHosts,
    hasLongDuration,
    hasAcceptedOrSuccessfulTraffic: hasAcceptedOrSuccessful,
    hasStrongMaliciousContext,
    hasBenignEvidence: explicitBenign,
    thresholds_used: {
      AI_INSIGHT_HIGH_VOLUME_MIN_HITS: highVolumeMinHits,
      AI_INSIGHT_MULTIPLE_HOSTS_MIN: multipleHostsMin,
      AI_INSIGHT_LONG_DURATION_MIN_HOURS: longDurationHoursMin,
      AI_INSIGHT_DNS_LONG_DURATION_MIN_MINUTES: dnsLongDurationMinMinutes
    },
    detected_positive_factors: [
      hasHighVolume ? 'high_volume' : null,
      hasMultipleHosts ? 'multiple_hosts' : null,
      hasLongDuration ? 'long_duration_or_persistence' : null,
      hasAcceptedOrSuccessful ? 'accepted_or_successful' : null,
      hasStrongMaliciousContext ? 'strong_malicious_context' : null,
      hasSameHostChain ? 'same_host_dns_to_connection' : null,
      hasEnvChain ? 'environment_level_related_activity' : null
    ].filter(Boolean),
    detected_negative_factors: explicitBenign ? ['explicit_benign_or_fp'] : []
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

function buildConsistencyRules() {
  return `Global consistency rules:
- Do not reduce risk unless you can name a concrete risk-reducing factor.
- High activity, multiple hosts, long duration, persistence, or accepted traffic are never risk-reducing factors by themselves.
- If risk_reducing_factors is empty, risk_adjustment must be >= 0.
- Negative risk_adjustment is allowed only for explicit benign evidence (FP verdict, known internal test, allowlisted/trusted benign IOC, blocked-only with no successful activity and limited scope, or low-confidence IOC source with no meaningful internal activity).
- If evidence is mixed/insufficient, use risk_adjustment=0.
- confidence can be high only when output is internally consistent; use 0.40-0.70 for limited/contradictory evidence.
- If a domain resolves to an IP that is also an IOC, treat it as linked infrastructure.
- Accepted traffic to related IOC IP is stronger than DNS-only activity.
- same_host_dns_to_connection implies stronger evidence than environment_level_related_activity.
- Do not overclaim; use "possible communication" unless evidence is strong.
- Use risk_adjustment range -20..20.
Return ONLY JSON:
{
  "ai_risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "risk_adjustment": -20|-10|-5|0|5|10|15|20,
  "confidence": 0-1,
  "main_risk_drivers": [],
  "risk_reducing_factors": [],
  "reason": "",
  "recommended_action": ""
}`;
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
  const totalHits = Math.max(Number((incident?.hits ?? incident?.total_hits ?? snapshot.total_events) ?? 0), 0);
  const eventCount = Math.max(Number((incident?.event_count ?? snapshot.total_events) ?? 0), 0);
  const observedHosts = Math.max(Number((incident?.observed_hosts ?? incident?.asset_count ?? snapshot.unique_hosts) ?? 0), 0);
  const firstSeenMs = incident?.first_seen ? new Date(incident.first_seen).getTime() : NaN;
  const lastSeenMs = incident?.last_seen ? new Date(incident.last_seen).getTime() : NaN;
  const durationMinutes = Number.isFinite(firstSeenMs) && Number.isFinite(lastSeenMs) && lastSeenMs >= firstSeenMs
    ? Math.round((lastSeenMs - firstSeenMs) / 60000)
    : 0;

  const base = {
    ioc: String(incident?.ioc_value || incident?.observable_value || ''),
    ioc_type: iocType,
    activity_type: iocType === 'domain' ? 'dns' : iocType,
    related_iocs: Array.isArray(incident?.related_iocs) ? incident.related_iocs : [],
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
  const model = String(process.env.LLM_RISK_ADVISOR_MODEL || 'qwen2.5:14b').trim();
  const timeoutMs = Math.max(Number(process.env.LLM_RISK_ADVISOR_TIMEOUT_MS || 15000), 1000);
  const manualTimeoutMs = Math.max(Number(process.env.LLM_RISK_ADVISOR_MANUAL_TIMEOUT_MS || 30000), timeoutMs);
  const llmTemperature = Number(process.env.LLM_RISK_TEMPERATURE ?? 0.2);
  const llmNumCtx = Math.max(Number(process.env.LLM_RISK_NUM_CTX ?? 2048), 256);
  const llmNumPredict = Math.max(Number(process.env.LLM_RISK_NUM_PREDICT ?? 180), 1);
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
          options: {
            temperature: Number.isFinite(llmTemperature) ? llmTemperature : 0.2,
            num_ctx: llmNumCtx,
            num_predict: llmNumPredict
          },
          prompt: `${buildPromptByType(incidentPayload?.ioc_type)}\n\n${buildConsistencyRules()}\n\nIncident Data:\n${JSON.stringify(incidentPayload, null, 2)}`
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

        return { ok: true, normalized: normalizeAdvisorOutput(modelJson, 'ok', incidentPayload) };
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
      raw_model_adjustment: normalized.raw_model_adjustment,
      normalization_reason: normalized.normalization_reason,
      detected_positive_factors: normalized.detected_positive_factors || [],
      detected_negative_factors: normalized.detected_negative_factors || [],
      llm_last_updated_at: new Date().toISOString(),
      llm_version: version || null,
      final_risk_score: Number(finalRisk.toFixed(2))
    };
  }

  function computeVersion(input) {
    const base = buildIncidentVersion(input);
    const related = Array.isArray(input?.related_iocs) ? input.related_iocs : [];
    if (!related.length) return base;

    const relatedRaw = related
      .map((r) => [
        r?.related_ioc || '',
        r?.chain_type || '',
        Number(r?.traffic?.accepted_count || 0),
        r?.related_ioc_in_ioc_list ? 1 : 0
      ].join('|'))
      .sort()
      .join(';');

    const extra = crypto.createHash('sha1').update(relatedRaw).digest('hex').slice(0, 8);
    return `${base}${extra}`.slice(0, 24);
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
