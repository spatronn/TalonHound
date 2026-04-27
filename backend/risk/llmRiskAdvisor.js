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
  const reason = String(parsed.reason || fallbackReason || 'fallback').slice(0, 240);

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

function buildPrompt() {
  return `You are a cybersecurity risk assistant. Your task is NOT to calculate full risk. ONLY return a small adjustment score.

Rules:
- Return ONLY JSON
- adjustment must be one of: -10, -5, 0, +5, +10
- Be conservative
- High volume alone is NOT enough
- Blocked traffic or scanner-like behavior -> decrease risk
- Accepted connections + blacklist + persistence -> increase risk
- If IOC is high-severity (e.g., cobaltstrike, c2, ransomware, botnet, apt), do NOT downscore based on low volume alone
- A single confirmed high-severity hit can be significant
- For high-severity IOC, prefer 0 or positive adjustment unless evidence strongly indicates false positive
- Never claim facts not present in Incident Data
- If evidence is insufficient, return adjustment=0 with a cautious reason
- Reason must reference only provided Incident Data fields
- Reason must cite at least two Incident Data fields by name (e.g., accepted_connections, blocked_connections, blacklist_hits, unique_hosts, total_events)
- Avoid vague explanations such as "low activity" alone
- If adjustment is 0, explain why evidence is insufficient to increase or decrease risk
- Keep reason concise (max 18 words), analyst-friendly, and action-oriented

Output:
{ "adjustment": <number>, "confidence": 0-1, "reason": "short explanation" }`;
}

function normalizeIocType(raw) {
  const t = String(raw || '').toLowerCase();
  if (t === 'ip') return 'ip';
  if (t === 'domain') return 'domain';
  if (t === 'url') return 'url';
  if (['md5', 'sha1', 'sha256', 'hash'].includes(t)) return 'hash';
  return 'hash';
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
  const confidenceRaw = String(incident?.confidence || '').toLowerCase();
  const confidence = ['low', 'medium', 'high'].includes(confidenceRaw) ? confidenceRaw : 'medium';

  return {
    ioc: String(incident?.ioc_value || incident?.observable_value || ''),
    ioc_type: normalizeIocType(incident?.ioc_type || incident?.observable_type),
    stats: {
      total_events: snapshot.total_events,
      accepted_connections: snapshot.accepted_connections,
      blocked_connections: snapshot.blocked_connections,
      inbound_events: Math.max(Number(incident?.inbound_events || 0), 0),
      outbound_events: Math.max(Number(incident?.outbound_events || 0), 0),
      unique_hosts: snapshot.unique_hosts
    },
    threat_intel: {
      blacklist_hits: snapshot.blacklist_hits,
      confidence,
      tags: parseTags(incident?.tags)
    },
    history: {
      previous_incident_count: Math.max(Number(incident?.previous_incident_count || 0), 0),
      previous_verdict: normalizeVerdict(incident?.previous_verdict)
    }
  };
}

export function createLlmRiskAdvisor({ redis, queue } = {}) {
  const enabled = toBool(process.env.LLM_RISK_ADVISOR_ENABLED, false);
  const url = String(process.env.LLM_RISK_ADVISOR_URL || 'http://192.168.1.26:11434/api/generate').trim();
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
        const payload = {
          model,
          stream: false,
          format: 'json',
          prompt: `${buildPrompt()}\n\nIncident Data:\n${JSON.stringify(buildIncidentPayload(incident), null, 2)}`
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
