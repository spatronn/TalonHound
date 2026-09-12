/**
 * Deterministic JSON extraction from provider text (no random brace grabbing).
 */

/**
 * Strip common local-model reasoning wrappers without treating them as payload.
 * @param {string} text
 */
export function stripReasoningWrappers(text) {
  let s = String(text || '');
  s = s.replace(/<think>[\s\S]*?<\/think>/gi, '');
  s = s.replace(/<reasoning>[\s\S]*?<\/reasoning>/gi, '');
  return s.trim();
}

/**
 * @param {string} text
 * @returns {{ ok: true, value: object, method: string } | { ok: false, code: string, error: string }}
 */
export function extractJsonObject(text) {
  const stripped = stripReasoningWrappers(text);
  if (!stripped) {
    return { ok: false, code: 'ai_output_parse_error', error: 'Empty AI response' };
  }

  // Direct parse
  try {
    const v = JSON.parse(stripped);
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return { ok: true, value: v, method: 'direct' };
    }
    return { ok: false, code: 'ai_output_parse_error', error: 'Top-level JSON must be an object' };
  } catch {
    /* continue */
  }

  // Fenced ```json ... ```
  const fence = stripped.match(/```(?:json|JSON)?\s*\r?\n?([\s\S]*?)\r?\n?```/);
  if (fence) {
    const inner = fence[1].trim();
    try {
      const v = JSON.parse(inner);
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        return { ok: true, value: v, method: 'fence' };
      }
    } catch {
      return { ok: false, code: 'ai_output_parse_error', error: 'Fenced JSON block is malformed' };
    }
  }

  // Known prose wrapper: "Here is the JSON:" then one object, optional trailing whitespace only
  const prose = stripped.match(
    /^(?:here(?:'s| is)?(?: the)?(?: requested| corrected)? json(?: object)?:\s*)(\{[\s\S]*\})\s*$/i
  );
  if (prose) {
    try {
      const v = JSON.parse(prose[1]);
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        return { ok: true, value: v, method: 'prose_wrapper' };
      }
    } catch {
      return { ok: false, code: 'ai_output_parse_error', error: 'Prose-wrapped JSON is malformed' };
    }
  }

  // Single top-level object: first { to last } with only whitespace outside
  const start = stripped.indexOf('{');
  const end = stripped.lastIndexOf('}');
  if (start >= 0 && end > start) {
    const before = stripped.slice(0, start).trim();
    const after = stripped.slice(end + 1).trim();
    const beforeOk = !before || /^(here(?:'s| is)?(?: the)?(?: requested| corrected)? json(?: object)?:)$/i.test(before);
    if (beforeOk && !after) {
      try {
        const v = JSON.parse(stripped.slice(start, end + 1));
        if (v && typeof v === 'object' && !Array.isArray(v)) {
          return { ok: true, value: v, method: 'bounded_object' };
        }
      } catch {
        return { ok: false, code: 'ai_output_parse_error', error: 'JSON object is truncated or malformed' };
      }
    }
    if (before || after) {
      return {
        ok: false,
        code: 'ai_output_parse_error',
        error: 'Ambiguous AI response: JSON mixed with unexpected prose'
      };
    }
  }

  return { ok: false, code: 'ai_output_parse_error', error: 'Could not extract a single JSON object from AI response' };
}

/**
 * Cap model-output sample for failed-chunk diagnostics (never prompts/secrets).
 * @param {string} text
 * @param {number} [maxChars]
 */
export function capRawOutputSample(text, maxChars = 8000) {
  const s = String(text || '');
  if (s.length <= maxChars) return s;
  return `${s.slice(0, maxChars)}\n…[truncated ${s.length - maxChars} chars]`;
}
