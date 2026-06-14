const BASE = 'http://127.0.0.1:3000';
const EMAIL = process.env.DEMO_EMAIL || 'demo@demo.local';
const PASSWORD = process.env.DEMO_PASSWORD || 'Password1!';

async function main() {
  const jar = new Map();
  const storeCookie = (res) => {
    const raw = res.headers.getSetCookie?.() || [];
    for (const line of raw) {
      const part = String(line).split(';')[0];
      const eq = part.indexOf('=');
      if (eq > 0) jar.set(part.slice(0, eq), part.slice(eq + 1));
    }
  };
  const cookieHeader = () => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');

  const loginRes = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD })
  });
  storeCookie(loginRes);
  const loginBody = await loginRes.json();
  if (!loginRes.ok || !loginBody?.user) {
    console.error('LOGIN_FAIL', loginRes.status, loginBody);
    process.exit(1);
  }
  const headers = () => ({ Cookie: cookieHeader() });

  const listRes = await fetch(`${BASE}/api/incidents?page=1&page_size=500`, { headers: headers() });
  const listBody = await listRes.json();
  let found883 = (listBody?.items || []).some((i) => Number(i.incident_id) === 883);
  console.log('DEFAULT_PAGE1_HAS_883', found883, 'total', listBody?.pagination?.total, 'page_size', listBody?.pagination?.page_size);
  if (!found883) {
    const searchRes = await fetch(`${BASE}/api/incidents?q=883&page=1&page_size=20`, { headers: headers() });
    const searchBody = await searchRes.json();
    found883 = (searchBody?.items || []).some((i) => Number(i.incident_id) === 883);
    console.log('SEARCH_LIST_HAS_883', found883, 'total_default', listBody?.pagination?.total);
  }
  if (!found883) process.exit(1);

  const detailRes = await fetch(`${BASE}/api/incidents/883`, { headers: headers() });
  console.log('DETAIL_STATUS', detailRes.status);
  if (detailRes.status !== 200) process.exit(1);

  const closedRes = await fetch(`${BASE}/api/incidents?status=closed&page=1&page_size=5`, { headers: headers() });
  const closedBody = await closedRes.json();
  console.log('CLOSED_FILTER_OK', (closedBody?.items || []).every((i) => i.status === 'closed'));

  const fpRes = await fetch(`${BASE}/api/incidents?verdict=FP&page=1&page_size=200`, { headers: headers() });
  const fpBody = await fpRes.json();
  console.log('FP_FILTER_HAS_883', (fpBody?.items || []).some((i) => Number(i.incident_id) === 883));

  const fromToRes = await fetch(`${BASE}/api/incidents?from=2026-05-01&to=2026-05-04&page=1&page_size=200`, { headers: headers() });
  const fromToBody = await fromToRes.json();
  console.log('FROMTO_INCLUDES_883', (fromToBody?.items || []).some((i) => Number(i.incident_id) === 883));

  console.log('API_SMOKE_PASSED');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
