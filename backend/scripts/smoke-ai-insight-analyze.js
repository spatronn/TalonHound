const BASE = process.env.SMOKE_BASE_URL || 'http://127.0.0.1:3000';
const INCIDENTS = String(process.env.SMOKE_INCIDENT_IDS || '899,900')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);

async function login(api) {
  const jar = new Map();
  const storeCookie = (res) => {
    for (const line of res.headers.getSetCookie?.() || []) {
      const part = String(line).split(';')[0];
      const eq = part.indexOf('=');
      if (eq > 0) jar.set(part.slice(0, eq), part.slice(eq + 1));
    }
  };
  const headers = () => ({
    Cookie: [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; '),
    ...(jar.has('demo_csrf') ? { 'X-CSRF-Token': jar.get('demo_csrf') } : {})
  });
  const loginRes = await fetch(`${api}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'demo@demo.local', password: 'Password1!' })
  });
  storeCookie(loginRes);
  if (!loginRes.ok) throw new Error(`login failed HTTP ${loginRes.status}`);
  return { headers, storeCookie };
}

async function timedAnalyze(api, headerFn, incidentId) {
  const t0 = Date.now();
  const res = await fetch(`${api}/incidents/${incidentId}/ai-analyze`, {
    method: 'POST',
    headers: { ...headerFn(), 'Content-Type': 'application/json' }
  });
  const body = await res.json().catch(() => ({}));
  return {
    incidentId,
    status: res.status,
    ms: Date.now() - t0,
    processing: body?.status === 'processing',
    hasAdjustment: body?.item?.llm_risk_adjustment !== null && body?.item?.llm_risk_adjustment !== undefined,
    reason: body?.item?.llm_risk_reason || body?.message || null
  };
}

async function main() {
  const api = `${BASE.replace(/\/+$/, '')}/api`;
  const { headers } = await login(api);
  const results = [];
  for (const incidentId of INCIDENTS) {
    results.push(await timedAnalyze(api, headers, incidentId));
  }
  console.log(JSON.stringify({ base: BASE, results }, null, 2));
  for (const r of results) {
    if (r.status === 504) {
      console.error(`FAIL incident ${r.incidentId}: HTTP 504`);
      process.exit(1);
    }
    if (r.ms > 55000) {
      console.error(`FAIL incident ${r.incidentId}: too slow ${r.ms}ms`);
      process.exit(1);
    }
    if (r.status !== 200 && r.status !== 202) {
      console.error(`FAIL incident ${r.incidentId}: HTTP ${r.status}`);
      process.exit(1);
    }
  }
  console.log('AI_INSIGHT_ANALYZE_SMOKE_PASSED');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
