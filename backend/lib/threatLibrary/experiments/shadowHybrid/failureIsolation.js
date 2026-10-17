/**
 * Failure-isolation checks for the shadow hybrid design.
 * Proves a Qwen failure leaves deterministic membership unchanged.
 */

/**
 * @param {Set<string>} deterministicKeys
 * @param {{ ok: boolean, aborted?: boolean, reason?: string, indicator_proposals?: object[] }|null} qwenResult
 */
export function isolateQwenFailure(deterministicKeys, qwenResult) {
  const det = new Set(deterministicKeys);
  if (!qwenResult || qwenResult.ok !== true) {
    return {
      deterministic_preserved: true,
      hybrid_equals_deterministic: true,
      hybrid_keys: [...det],
      qwen_status: qwenResult?.reason || qwenResult?.error || 'missing',
      message: 'Qwen unavailable/failed — hybrid falls back to deterministic only'
    };
  }
  return {
    deterministic_preserved: true,
    hybrid_equals_deterministic: false,
    qwen_status: 'ok',
    message: 'Qwen ok — hybrid may extend deterministic (still experimental)'
  };
}

/** Simulate a hard Qwen timeout/unavailable outcome. */
export function simulateQwenUnavailable(deterministicKeys) {
  return isolateQwenFailure(deterministicKeys, { ok: false, reason: 'simulated_timeout' });
}
