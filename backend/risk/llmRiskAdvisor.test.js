import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createLlmRiskAdvisor,
  normalizeAdvisorOutput,
  buildAdvisorParseFallback,
  PERSISTABLE_PARSE_FALLBACK_REASONS
} from './llmRiskAdvisor.js';

function buildEnrichedDomainIncident() {
  return {
    ioc: 'malicious-domain.com',
    ioc_type: 'domain',
    activity_type: 'dns',
    stats: {
      total_hits: 2500,
      observed_hosts: 6,
      duration_minutes: 60 * 36
    },
    related_iocs: [
      {
        relationship: 'dns_response_ip',
        source_ioc: 'malicious-domain.com',
        related_ioc: '5.6.7.8',
        related_ioc_in_ioc_list: true,
        chain_type: 'environment_level_related_activity',
        traffic: { accepted_count: 4, services: ['tcp'], ports: [8080] }
      }
    ]
  };
}

test('normalizer sets +10 floor for strong related IOC evidence', () => {
  const enrichedContext = buildEnrichedDomainIncident();
  const out = normalizeAdvisorOutput({ risk_adjustment: 5, confidence: 0.9, reason: 'high dns volume' }, 'ok', enrichedContext);

  assert.equal(out.hasAcceptedOrSuccessfulTraffic, true);
  assert.equal(out.hasStrongMaliciousContext, true);
  assert.equal(out.adjustment, 10);
  assert.match(out.reason, /malicious-domain\.com/i);
  assert.match(out.reason, /5\.6\.7\.8/);
  assert.match(out.reason, /ioc list/i);
  assert.match(out.reason, /accepted traffic/i);
  assert.match(out.reason, /tcp\/8080/i);
  assert.match(out.reason, /environment-level/i);
  assert.doesNotMatch(out.reason, /confirmed compromise/i);
});

test('worker/manual equivalent enriched context yields same signals and adjustment', () => {
  const workerContext = buildEnrichedDomainIncident();
  const manualContext = JSON.parse(JSON.stringify(workerContext));

  const workerOut = normalizeAdvisorOutput({ risk_adjustment: 0, confidence: 0.6, reason: 'dns activity' }, 'ok', workerContext);
  const manualOut = normalizeAdvisorOutput({ risk_adjustment: 0, confidence: 0.6, reason: 'dns activity' }, 'ok', manualContext);

  assert.equal(workerOut.hasAcceptedOrSuccessfulTraffic, manualOut.hasAcceptedOrSuccessfulTraffic);
  assert.equal(workerOut.hasStrongMaliciousContext, manualOut.hasStrongMaliciousContext);
  assert.equal(workerOut.adjustment, manualOut.adjustment);
});

test('domain invalid_reason path uses tiered fallback, not URL hardcoded string', () => {
  const out = normalizeAdvisorOutput(
    { risk_adjustment: 5, confidence: 0.2, reason: 'this increases the risk of breach' },
    'ok',
    { ioc_type: 'domain', activity_type: 'dns', stats: { observed_hosts: 1, duration_minutes: 2 } }
  );
  assert.equal(out.normalization_reason, 'invalid_reason_persistence_contradiction');
  assert.equal(out.adjustment, 0);
  assert.ok(out.confidence >= 0.45 && out.confidence <= 0.65);
  assert.ok(!out.reason.includes('Repeated proxy URL access attempts'));
  assert.ok(out.reason.includes('normalized detection events'));
  assert.ok(out.reason.includes('DNS activity related to the IOC domain'));
});

test('domain model DNS-heavy reason is rewritten when proxy signals exist in payload evidence', () => {
  const payload = {
    ioc: 'kapindakimutlulukhemenal.com',
    ioc_type: 'domain',
    activity_type: 'dns',
    incident: { detection_event_count: 2, evidence_log_count: 5 },
    evidence_log_count: 5,
    stats: { observed_hosts: 1, duration_minutes: 3, event_count: 2 },
    event_summary: { source_types: { dns: 1, proxy: 1 } },
    playbook_coverage: { proxy_evidence: true },
    evidence_summary: { samples: ['TCP_TUNNEL/200 CONNECT kapindakimutlulukhemenal.com'] },
    sample_events: []
  };
  const out = normalizeAdvisorOutput(
    { risk_adjustment: 0, confidence: 0.6, reason: 'Moderate DNS query volume with no persistence or a single observed host, and short duration.' },
    'ok',
    payload
  );
  assert.match(out.reason, /proxy|CONNECT|network-level/i);
  assert.ok(!/^moderate dns query volume/i.test(out.reason.trim()));
  assert.equal(out.adjustment, 5);
  assert.equal(out.normalization_reason, 'domain_dns_proxy_tunnel_adjustment');
});

test('URL playbook incomplete still uses URL-specific fallback', () => {
  const out = normalizeAdvisorOutput(
    { risk_adjustment: 10, confidence: 0.8, reason: 'nothing useful here' },
    'ok',
    { ioc_type: 'url', stats: { observed_hosts: 1, duration_minutes: 5 } }
  );
  assert.equal(out.normalization_reason, 'invalid_reason_persistence_contradiction');
  assert.ok(out.reason.includes('proxy URL') || out.reason.includes('observed network activity'));
});

function withEnv(overrides, fn) {
  const prev = {};
  for (const [key, value] of Object.entries(overrides)) {
    prev[key] = process.env[key];
    process.env[key] = String(value);
  }
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      for (const key of Object.keys(overrides)) {
        if (prev[key] === undefined) delete process.env[key];
        else process.env[key] = prev[key];
      }
    });
}

function baseEnvironmentSummary() {
  return {
    range_days: 30,
    totals: { total_incidents: 4, open_incidents: 2, closed_incidents: 2, detection_events: 20, observed_hosts: 3 },
    threat_class_distribution: [{ key: 'phishing', count: 3 }],
    top_tags: [{ key: 'phishing', count: 3 }],
    top_ioc_sources: [{ key: 'feed', count: 4 }],
    recommended_controls_frequency: [{ key: 'email_gateway', count: 2 }],
    missing_context_frequency: [{ key: 'rdap_missing', count: 1 }],
    allowed_blocked_unknown_ratio: { allowed: 8, blocked: 10, unknown: 2 },
    top_risk_drivers: [{ key: 'repeated activity', count: 2 }],
    top_risk_reducers: [],
    highest_risk_incidents: [{ id: 'a', incident_id: 1, risk_score: 80, reason_summary: 'sample' }]
  };
}

test('environment insight oversized prompt is rejected before LLM call', async () => {
  const oldFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    throw new Error('should not call fetch');
  };
  try {
    await withEnv({ ENVIRONMENT_INSIGHT_MAX_PROMPT_CHARS: 1000 }, async () => {
      const advisor = createLlmRiskAdvisor();
      const summary = {
        ...baseEnvironmentSummary(),
        top_tags: Array.from({ length: 100 }, (_, i) => ({ key: `tag-${i}`, count: i }))
      };
      const out = await advisor.generateEnvironmentInsight(summary);
      assert.equal(out.ok, false);
      assert.equal(out.reason, 'prompt_too_large');
      assert.equal(called, false);
      assert.ok(out.metrics.final_prompt_chars > out.metrics.max_prompt_chars);
    });
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('environment insight timeout remains graceful when retry also times out', async () => {
  const oldFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    const err = new Error('aborted');
    err.name = 'AbortError';
    throw err;
  };
  try {
    const advisor = createLlmRiskAdvisor();
    const out = await advisor.generateEnvironmentInsight(baseEnvironmentSummary());
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'timeout');
    assert.equal(calls, 2);
    assert.equal(out.previous_failure.reason, 'timeout');
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('environment insight compact retry can succeed after first timeout', async () => {
  const oldFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    if (calls === 1) {
      const err = new Error('aborted');
      err.name = 'AbortError';
      throw err;
    }
    return {
      ok: true,
      async json() {
        return {
          response: JSON.stringify({
            executive_summary: 'Concise posture summary.',
            posture_level: 'moderate',
            primary_exposure: 'phishing',
            key_findings: ['Phishing dominates observed risk.'],
            risk_score_explanation: {
              why_score_is_high_or_low: 'Moderate due to limited data.',
              main_risk_drivers: ['phishing'],
              main_risk_reducers: ['blocked activity']
            },
            top_recommendations: [
              { control_area: 'email_gateway', recommendation: 'Review email gateway detections.', reason: 'Phishing is dominant.', priority: 'medium' }
            ],
            visibility_gaps: ['rdap_missing'],
            trend_notes: 'No trend comparison available.'
          })
        };
      }
    };
  };
  try {
    const advisor = createLlmRiskAdvisor();
    const out = await advisor.generateEnvironmentInsight(baseEnvironmentSummary());
    assert.equal(out.ok, true);
    assert.equal(out.generation_mode, 'compact_retry');
    assert.equal(out.previous_failure.reason, 'timeout');
    assert.equal(calls, 2);
    assert.equal(out.output.posture_level, 'moderate');
    assert.equal(out.input_summary.highest_risk_incidents.length, 0);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('manual sync timeout defaults below manual background timeout', () => {
  const advisor = createLlmRiskAdvisor();
  assert.ok(advisor.manualSyncTimeoutMs <= advisor.manualTimeoutMs);
  assert.ok(advisor.manualSyncTimeoutMs >= 5000);
});

test('buildAdvisorParseFallback exposes user-facing invalid_json reason', () => {
  const out = buildAdvisorParseFallback('invalid_json', { ioc_type: 'domain' });
  assert.equal(out.adjustment, 0);
  assert.equal(out.confidence, 0.45);
  assert.equal(out.normalization_reason, 'invalid_json');
  assert.match(out.reason, /could not be parsed reliably/i);
  assert.ok(out.structured_output?.summary);
  assert.ok(PERSISTABLE_PARSE_FALLBACK_REASONS.has('invalid_json'));
});

test('evaluateAndCache persists invalid_json fallback', async () => {
  const oldFetch = globalThis.fetch;
  let persisted = false;
  const mockDb = {
    query: async (sql) => {
      if (String(sql).includes('INSERT INTO incident_ai_insights')) persisted = true;
      return { rows: [] };
    }
  };
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => ({ response: 'not-json{{{', done_reason: 'length' })
  });
  try {
    const advisor = createLlmRiskAdvisor({ db: mockDb, redis: null, queue: null });
    const out = await advisor.evaluateAndCache({
      incident: {
        id: 'a5d54a5e-61a4-472e-843b-5b2a64c144f7',
        incident_id: 900,
        ioc_type: 'domain',
        event_count: 2,
        verdict: 'Unreviewed'
      },
      baseRisk: 30,
      version: 'test-invalid-json',
      force: true,
      timeoutMsOverride: 5000,
      maxAttempts: 1
    });
    assert.equal(persisted, true);
    assert.equal(out.llm_risk_adjustment, 0);
    assert.equal(out.normalization_reason, 'invalid_json');
    assert.match(out.llm_risk_reason, /could not be parsed reliably/i);
    assert.ok(out.llm_last_updated_at);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('evaluateAndCache persists valid JSON response', async () => {
  const oldFetch = globalThis.fetch;
  let persisted = false;
  const mockDb = {
    query: async (sql) => {
      if (String(sql).includes('INSERT INTO incident_ai_insights')) persisted = true;
      return { rows: [] };
    }
  };
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => ({
      response: JSON.stringify({
        risk_adjustment: 5,
        confidence: 0.6,
        reason: 'Observed DNS and proxy activity related to the IOC domain from one host.'
      }),
      done_reason: 'stop'
    })
  });
  try {
    const advisor = createLlmRiskAdvisor({ db: mockDb, redis: null, queue: null });
    const out = await advisor.evaluateAndCache({
      incident: {
        id: 'a5d54a5e-61a4-472e-843b-5b2a64c144f7',
        incident_id: 899,
        ioc_type: 'domain',
        event_count: 2,
        verdict: 'Unreviewed'
      },
      baseRisk: 30,
      version: 'test-valid-json',
      force: true,
      timeoutMsOverride: 5000,
      maxAttempts: 1
    });
    assert.equal(persisted, true);
    assert.equal(out.llm_risk_adjustment, 5);
    assert.ok(out.llm_last_updated_at);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test('evaluateAndCache timeout does not persist fallback insight', async () => {
  const oldFetch = globalThis.fetch;
  let persisted = false;
  const mockDb = {
    query: async (sql) => {
      if (String(sql).includes('INSERT INTO incident_ai_insights')) persisted = true;
      return { rows: [] };
    }
  };
  globalThis.fetch = async (_url, opts = {}) => new Promise((_resolve, reject) => {
    opts?.signal?.addEventListener('abort', () => {
      reject(Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }));
    });
  });
  try {
    const advisor = createLlmRiskAdvisor({ db: mockDb, redis: null, queue: null });
    const out = await advisor.evaluateAndCache({
      incident: {
        id: 'a5d54a5e-61a4-472e-843b-5b2a64c144f7',
        incident_id: 900,
        ioc_type: 'domain',
        event_count: 2,
        verdict: 'Unreviewed'
      },
      baseRisk: 30,
      version: 'test-timeout',
      force: true,
      timeoutMsOverride: 40,
      maxAttempts: 1
    });
    assert.equal(persisted, false);
    assert.equal(out.llm_risk_reason, 'timeout');
    assert.equal(out.llm_risk_adjustment, 0);
  } finally {
    globalThis.fetch = oldFetch;
  }
});
