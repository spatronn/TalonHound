const BASE = 'http://127.0.0.1:3000';

async function main() {
  const jar = new Map();
  const storeCookie = (res) => {
    for (const line of res.headers.getSetCookie?.() || []) {
      const part = String(line).split(';')[0];
      const eq = part.indexOf('=');
      if (eq > 0) jar.set(part.slice(0, eq), part.slice(eq + 1));
    }
  };
  const headers = () => ({ Cookie: [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ') });
  const loginRes = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'demo@demo.local', password: 'Password1!' })
  });
  storeCookie(loginRes);
  const res = await fetch(`${BASE}/api/incidents/900`, { headers: headers() });
  const body = await res.json();
  const ex = body?.item?.risk_explanation || {};
  console.log('status', res.status);
  console.log('evidence', ex.evidence_tier, ex.evidence_tier_label);
  console.log('outcome', ex.action_outcome, ex.action_outcome_label);
  console.log('event_summary', JSON.stringify(body?.item?.event_summary || {}));
  if (ex.evidence_tier_label !== 'Proxy Evidence' || ex.action_outcome_label !== 'Proxy Failed') process.exit(1);
  console.log('INCIDENT_900_SMOKE_PASSED');
}

main().catch((e) => { console.error(e); process.exit(1); });
