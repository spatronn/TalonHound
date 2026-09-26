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
    const span = stripped.slice(start, end + 1);
    const beforeOk = !before || /^(here(?:'s| is)?(?: the)?(?: requested| corrected)? json(?: object)?:)$/i.test(before);
    let spanValue = null;
    let spanOk = false;
    try {
      const v = JSON.parse(span);
      spanOk = !!(v && typeof v === 'object' && !Array.isArray(v));
      if (spanOk) spanValue = v;
    } catch {
      spanOk = false;
    }
    if (beforeOk && !after && spanOk) {
      return { ok: true, value: spanValue, method: 'bounded_object' };
    }
    if (beforeOk && !after && !spanOk) {
      return {
        ok: false,
        code: 'ai_output_parse_error',
        error: looksLikeMultipleTopLevelObjects(span)
          ? 'Ambiguous AI response: multiple JSON objects'
          : 'JSON object is truncated or malformed'
      };
    }
    if (before || after) {
      return {
        ok: false,
        code: 'ai_output_parse_error',
        error: classifyAmbiguousRemainder(span, before, after)
      };
    }
  }

  return { ok: false, code: 'ai_output_parse_error', error: 'Could not extract a single JSON object from AI response' };
}

function looksLikeMultipleTopLevelObjects(span) {
  let depth = 0;
  let inString = false;
  let escape = false;
  let objects = 0;
  for (const ch of span) {
    if (inString) {
      if (escape) escape = false;
      else if (ch === '\\') escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === '{') {
      if (depth === 0) objects += 1;
      depth += 1;
    } else if (ch === '}') {
      depth = Math.max(0, depth - 1);
    }
  }
  return objects > 1;
}

function looksLikeJsonContinuation(text) {
  return /^\s*[,\[\]\{":]/.test(text) || /^\s*[A-Za-z0-9_]+\s*:/.test(text);
}

/**
 * Fail-closed classification only — never returns a parseable value.
 * @param {string} span
 * @param {string} before
 * @param {string} after
 */
function classifyAmbiguousRemainder(span, before, after) {
  if (looksLikeMultipleTopLevelObjects(span)) {
    return 'Ambiguous AI response: multiple JSON objects';
  }
  if (/^\s*\{/.test(after)) {
    return 'Ambiguous AI response: multiple JSON payloads';
  }
  if (looksLikeJsonContinuation(after)) {
    return 'Ambiguous AI response: JSON object is truncated';
  }
  if (before || after) {
    return 'Ambiguous AI response: JSON mixed with unexpected prose';
  }
  return 'JSON object is truncated or malformed';
}

/**
 * Cap model-output sample for failed-chunk diagnostics (never prompts/secrets).
 * @param {string} text
 * @param {number} [maxChars]
 */
export function capRawOutputSample(text, maxChars = 8000) {
  const s = String(text || '');
  if (s.length <= maxChars) return s;
  const head = Math.floor(maxChars * 0.6);
  const tail = maxChars - head;
  const omitted = s.length - head - tail;
  return `${s.slice(0, head)}\n…[truncated ${omitted} chars]…\n${s.slice(-tail)}`;
}
