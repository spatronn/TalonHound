import { buildIncidentVersion } from './llmRiskCommon.js';
import { buildLlmAdvisorPayload } from './llmAdvisor.js';
import { normalizeIocType } from './activityBuilder.js';

const ALLOWED_ADJUSTMENTS = new Set([-10, -5, 0, 5, 10]);
const logger = console;

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

function countSentences(text) {
  const cleaned = String(text || '').trim();
  if (!cleaned) return 0;
  return cleaned
    .split(/[.!?]+/g)
    .map((part) => part.trim())
    .filter(Boolean)
    .length;
}

function validateDecisionAwareReason(reason, adjustment) {
  const text = String(reason || '').trim();
  const lower = text.toLowerCase();
  if (!text) return { valid: false, code: 'invalid_reason_empty' };

  // Keep reasons short and analyst-friendly.
  if (countSentences(text) > 2) return { valid: false, code: 'invalid_reason_too_long' };

  if (
    /blacklist/.test(lower) ||
    /no blacklist hits/.test(lower) ||
    /domain not in blacklist/.test(lower)
  ) {
    return { valid: false, code: 'invalid_reason_blacklist_reference' };
  }

  // Enforce observation + conclusion structure with causal language.
  const hasCausalLink = /(suggests|indicates|therefore|which|because|thus|so)\b/i.test(text);
  if (!hasCausalLink) return { valid: false, code: 'invalid_reason_observation_only' };

  if (adjustment > 0 && !/increase(?:s|d)? risk|higher risk|elevates? risk/i.test(text)) {
    return { valid: false, code: 'invalid_reason_adjustment_mismatch_positive' };
  }
  if (adjustment < 0 && !/reduce(?:s|d)? risk|lower risk|decreases? risk/i.test(text)) {
    return { valid: false, code: 'invalid_reason_adjustment_mismatch_negative' };
  }
  if (adjustment === 0 && !/inconclusive|neutral/i.test(text)) {
    return { valid: false, code: 'invalid_reason_adjustment_mismatch_neutral' };
  }

  return { valid: true, code: 'ok' };
}

function buildReasonFallback(iocType) {
  if (iocType === 'domain') {
    return 'Observed DNS activity across multiple hosts suggests repeated communication behavior, but available signals are inconclusive.';
  }
  if (iocType === 'ip') {
    return 'Network activity observed, but signals are insufficient to determine a strong risk adjustment.';
  }
  return 'Observed activity does not provide sufficient evidence for a strong risk adjustment.';
}

function isInternalReason(reason) {
  const text = String(reason || '').trim().toLowerCase();
  if (!text) return true;
  return [
    /^invalid_reason_/,
    /^validation_failed$/,
    /^parse_error$/,
    /^invalid_json$/,
    /^low_confidence$/,
    /^fallback$/,
    /^disabled$/,
    /^fp_verdict_guard$/,
    /^timeout$/,
    /^endpoint_unreachable$/,
    /^cache$/,
    /^ok$/,
    /^llm_http_/
  ].some((pattern) => pattern.test(text));
}

function toUserReason(reason, iocType) {
  const text = String(reason || '').trim();
  if (isInternalReason(text)) return buildReasonFallback(iocType);
  return text.slice(0, 240);
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
  const adjustment = normalizeAdjustment(parsed.adjustment);
  let reason = String(parsed.reason || fallbackReason || 'fallback').slice(0, 240);
  const reasonValidation = validateDecisionAwareReason(reason, adjustment);

  return {
    adjustment: confidence < 0.6 ? 0 : adjustment,
    confidence,
    reason,
    reasonValidation,
    reasonValid: reasonValidation.valid
  };
}

function buildGenericPrompt() {
  return `You are a cybersecurity risk assistant. Return only a small risk adjustment.
Rules:
- Return ONLY JSON.
- adjustment must be one of: -10, -5, 0, +5, +10
- Never claim facts not present in Incident Data.
- Do not mention blacklist status.
- Use the unified activity model fields:
  - activity.type
  - activity.volume
  - activity.unique_hosts
  - activity.persistence
  - activity.has_execution
  - activity.is_blocked
  - activity.signals
- Core risk logic:
  - has_execution => risk increases strongly
  - is_blocked => risk reduces
  - high volume alone is not enough; combine with spread/persistence/execution
  - higher unique_hosts => risk increases
  - higher persistence => risk increases
- DNS special rule:
  - DNS only (no execution) is weak
  - DNS + connection/execution is strong
  - DNS + blocked tends to lower risk
- Reason must be 1-2 sentences and include observation + conclusion.
- If adjustment > 0, reason must explicitly say risk increases.
- If adjustment < 0, reason must explicitly say risk reduces.
- If adjustment == 0, reason must explicitly say risk is inconclusive or neutral.
Output:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildPromptByType() {
  return buildGenericPrompt();
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

  function fallback(baseRisk, reason = 'fallback', iocType = 'unknown') {
    const base = clamp(Number(baseRisk || 0), 0, 100);
    return {
      risk_before_llm: Number(base.toFixed(2)),
      llm_risk_adjustment: 0,
      llm_risk_confidence: 0,
      llm_risk_reason: toUserReason(reason, normalizeIocType(iocType)),
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
      const iocType = normalizeIocType(parsed?.ioc_type);
      const base = clamp(Number(baseRisk || 0), 0, 100);
      const finalRisk = computeFinalRisk(base, normalized.adjustment, normalized.confidence);

      return {
        risk_before_llm: Number(base.toFixed(2)),
        llm_risk_adjustment: normalized.adjustment,
        llm_risk_confidence: Number(normalized.confidence.toFixed(3)),
        llm_risk_reason: toUserReason(normalized.reason, iocType),
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
    const iocType = normalizeIocType(incident?.ioc_type || incident?.observable_type);
    if (!enabled && !force) return fallback(base, 'disabled', iocType);

    const verdict = String(incident?.verdict || '').trim().toLowerCase();
    if (verdict === 'fp') {
      const out = fallback(base, 'fp_verdict_guard', iocType);
      out.llm_risk_adjustment = 0;
      return out;
    }

    const initialTimeout = Math.max(Number(timeoutMsOverride || timeoutMs), 1000);
    const retryBackoffMs = 5000;
    const secondTimeout = initialTimeout + 5000;

    async function singleAttempt(requestTimeoutMs) {
      const incidentPayload = buildLlmAdvisorPayload(incident);
      let lastNormalized = null;
      for (let i = 0; i < 2; i += 1) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
        try {
        const payload = {
          model,
          stream: false,
          format: 'json',
          prompt: `${buildPromptByType()}\n\nIncident Data:\n${JSON.stringify(incidentPayload, null, 2)}`
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

        const normalized = normalizeAdvisorOutput(modelJson, 'ok');
        if (!normalized.reasonValid) {
          logger.warn({
            incident_id: incident?.id || incident?.incident_id || null,
            reason_validation_failed: true,
            llm_response: modelJson
          });
          lastNormalized = normalized;
          continue;
        }
        return { ok: true, normalized };
        } catch (err) {
          if (isTimeoutError(err)) return { ok: false, kind: 'timeout', reason: 'timeout' };
          return { ok: false, kind: 'network', reason: 'endpoint_unreachable' };
        } finally {
          clearTimeout(timer);
        }
      }
      const fallbackReason = buildReasonFallback(incidentPayload?.ioc_type);
      return {
        ok: true,
        normalized: {
          adjustment: lastNormalized?.adjustment ?? 0,
          confidence: lastNormalized?.confidence ?? 0,
          reason: fallbackReason,
          reasonValidation: { valid: true, code: 'fallback_applied' },
          reasonValid: true
        }
      };
    }

    const first = await singleAttempt(initialTimeout);
    let result = first;

    if (!first.ok && first.kind === 'timeout') {
      await sleep(retryBackoffMs);
      result = await singleAttempt(secondTimeout);
    }

    if (!result.ok) {
      return fallback(base, result.reason || 'fallback', iocType);
    }

    const normalized = result.normalized;
    const reasonForUi = toUserReason(normalized.reason, iocType);
    await setCached({
      incidentId: incident?.id || incident?.incident_id,
      version,
      value: {
        adjustment: normalized.adjustment,
        confidence: normalized.confidence,
        reason: reasonForUi,
        ioc_type: iocType,
        llm_last_updated_at: new Date().toISOString(),
        llm_version: version || null
      }
    });

    const finalRisk = computeFinalRisk(base, normalized.adjustment, normalized.confidence);
    return {
      risk_before_llm: Number(base.toFixed(2)),
      llm_risk_adjustment: normalized.adjustment,
      llm_risk_confidence: Number(normalized.confidence.toFixed(3)),
      llm_risk_reason: reasonForUi,
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
