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

function normalizeAdjustment(raw) {
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    return ALLOWED_ADJUSTMENTS.has(raw) ? raw : 0;
  }

  const s = String(raw ?? '').trim();
  if (!s) return 0;
  const parsed = Number(s.replace(/^\+/, ''));
  if (!Number.isFinite(parsed)) return 0;
  return ALLOWED_ADJUSTMENTS.has(parsed) ? parsed : 0;
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

Output:
{ "adjustment": <number>, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildIncidentPayload(incident = {}, baseRisk = 0) {
  return {
    incident_id: incident.incident_id ?? null,
    id: incident.id ?? null,
    status: incident.status ?? null,
    verdict: incident.verdict ?? null,
    ioc_type: incident.ioc_type ?? null,
    ioc_value: incident.ioc_value ?? null,
    source_name: incident.source_name ?? null,
    total_hits: Number(incident.total_hits || 0),
    event_count: Number(incident.event_count || 0),
    asset_count: Number(incident.asset_count || 0),
    confidence: incident.confidence ?? null,
    first_seen: incident.first_seen ?? null,
    last_seen: incident.last_seen ?? null,
    note: incident.note ?? null,
    base_risk: Number(baseRisk || 0)
  };
}

export function createLlmRiskAdvisor({ redis } = {}) {
  const enabled = toBool(process.env.LLM_RISK_ADVISOR_ENABLED, false);
  const url = String(process.env.LLM_RISK_ADVISOR_URL || 'http://192.168.1.26:11434/api/generate').trim();
  const model = String(process.env.LLM_RISK_ADVISOR_MODEL || 'qwen2.7:7b').trim();
  const timeoutMs = Math.max(Number(process.env.LLM_RISK_ADVISOR_TIMEOUT_MS || 8000), 1000);
  const cacheTtlSeconds = Math.max(Number(process.env.LLM_RISK_ADVISOR_CACHE_TTL_SECONDS || 3600), 30);

  async function getFromCache(cacheKey) {
    if (!redis || typeof redis.get !== 'function') return null;
    try {
      const raw = await redis.get(cacheKey);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return normalizeAdvisorOutput(parsed, 'cache');
    } catch {
      return null;
    }
  }

  async function setCache(cacheKey, value) {
    if (!redis || typeof redis.set !== 'function') return;
    try {
      await redis.set(cacheKey, JSON.stringify(value), 'EX', cacheTtlSeconds);
    } catch {
      // no-op
    }
  }

  async function ask({ incident, baseRisk }) {
    const base = clamp(Number(baseRisk || 0), 0, 100);

    const fallback = {
      risk_before_llm: Number(base.toFixed(2)),
      llm_risk_adjustment: 0,
      llm_risk_confidence: 0,
      llm_risk_reason: enabled ? 'fallback' : 'disabled',
      final_risk_score: Number(base.toFixed(2))
    };

    if (!enabled) return fallback;

    const verdict = String(incident?.verdict || '').trim().toLowerCase();
    if (verdict === 'fp') {
      return {
        ...fallback,
        llm_risk_reason: 'fp_verdict_guard'
      };
    }

    const cacheId = String(incident?.id || incident?.incident_id || '').trim();
    const cacheKey = cacheId ? `risk:llm:incident:${cacheId}` : null;

    if (cacheKey) {
      const cached = await getFromCache(cacheKey);
      if (cached) {
        const finalRisk = clamp(base + cached.adjustment, 0, 100);
        return {
          risk_before_llm: Number(base.toFixed(2)),
          llm_risk_adjustment: cached.adjustment,
          llm_risk_confidence: Number(cached.confidence.toFixed(3)),
          llm_risk_reason: cached.reason,
          final_risk_score: Number(finalRisk.toFixed(2))
        };
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const payload = {
        model,
        stream: false,
        prompt: `${buildPrompt()}\n\nIncident context:\n${JSON.stringify(buildIncidentPayload(incident, base), null, 2)}`
      };

      const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      if (!response.ok) {
        return {
          ...fallback,
          llm_risk_reason: `llm_http_${response.status}`
        };
      }

      const body = await response.json();
      const modelJson = extractJson(body?.response);
      if (!modelJson) {
        return {
          ...fallback,
          llm_risk_reason: 'invalid_json'
        };
      }

      const normalized = normalizeAdvisorOutput(modelJson, 'ok');
      const finalRisk = clamp(base + normalized.adjustment, 0, 100);
      const out = {
        risk_before_llm: Number(base.toFixed(2)),
        llm_risk_adjustment: normalized.adjustment,
        llm_risk_confidence: Number(normalized.confidence.toFixed(3)),
        llm_risk_reason: normalized.reason,
        final_risk_score: Number(finalRisk.toFixed(2))
      };

      if (cacheKey) await setCache(cacheKey, normalized);
      return out;
    } catch (err) {
      const isAbort = err?.name === 'AbortError';
      return {
        ...fallback,
        llm_risk_reason: isAbort ? 'timeout' : 'endpoint_unreachable'
      };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    ask
  };
}
