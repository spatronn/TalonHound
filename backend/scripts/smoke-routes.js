/**
 * Smoke-check that critical API route modules are mounted (not Express 404 HTML).
 * Usage: npm run smoke:routes
 * Env: SMOKE_BASE_URL (default http://127.0.0.1:3000), SMOKE_EMAIL, SMOKE_PASSWORD
 */

const BASE = String(process.env.SMOKE_BASE_URL || 'http://127.0.0.1:3000').replace(/\/$/, '');
const SMOKE_EMAIL = process.env.SMOKE_EMAIL || 'admin@talonhound.local';
const SMOKE_PASSWORD = process.env.SMOKE_PASSWORD || 'admin';

/** @type {{ name: string, path: string, method?: string, assert?: (res: Response, body: unknown) => void }[]} */
const CHECKS = [
  {
    name: 'audit_logs',
    path: '/api/audit-logs?limit=1'
  },
  {
    name: 'rdap_enrichment',
    path: '/api/enrichment/rdap?value=https://authstrt-terezor.wixstudio.com/io-start&ioc_type=url',
    assert: (_res, body) => {
      const data = /** @type {{ rdap_domain?: string, normalized_host?: string }} */ (body);
      if (String(data?.rdap_domain || '').toLowerCase() !== 'wixstudio.com') {
        throw new Error(`expected rdap_domain=wixstudio.com, got ${data?.rdap_domain}`);
      }
      const host = String(data?.normalized_host || '').toLowerCase();
      if (!host.includes('authstrt-terezor.wixstudio.com')) {
        throw new Error(`expected normalized_host to include authstrt-terezor.wixstudio.com, got ${data?.normalized_host}`);
      }
    }
  },
  {
    name: 'ip_enrichment',
    path: '/api/enrichment/ip/8.8.8.8'
  },
  {
    name: 'abuseipdb_enrichment',
    path: '/api/enrichment/abuseipdb/ip/8.8.8.8'
  },
  {
    name: 'analyst_intelligence',
    path: '/api/ioc/999999999/analyst-intelligence',
    assert: (res, body) => {
      if (res.status !== 404) return;
      const data = /** @type {{ message?: string }} */ (body);
      if (data?.message !== 'IOC not found') {
        throw new Error(`expected application 404 IOC not found, got ${JSON.stringify(body)}`);
      }
    }
  },
  {
    name: 'ioc_expiration_feed_policy',
    path: '/api/threat-feeds/__smoke_missing_feed__/expiration-policy',
    assert: (res, body) => {
      if (res.status !== 404) return;
      const data = /** @type {{ error?: string, success?: boolean }} */ (body);
      if (data?.error !== 'Feed not found') {
        throw new Error(`expected application 404 Feed not found, got ${JSON.stringify(body)}`);
      }
    }
  },
  {
    name: 'ioc_expiration_memberships',
    path: '/api/ioc/00000000-0000-0000-0000-000000000000/feed-memberships',
    assert: (res, body) => {
      if (res.status !== 404) return;
      const data = /** @type {{ message?: string }} */ (body);
      if (data?.message !== 'IOC not found') {
        throw new Error(`expected application 404 IOC not found, got ${JSON.stringify(body)}`);
      }
    }
  },
  {
    name: 'admin_enrichment_providers_rdap',
    path: '/api/admin/enrichment-providers',
    assert: (_res, body) => {
      const data = /** @type {{ providers?: Array<{ provider?: string }> }} */ (body);
      const providers = (data?.providers || []).map((p) => p.provider);
      for (const key of ['virustotal', 'ipinfo_lite', 'abuseipdb', 'rdap']) {
        if (!providers.includes(key)) {
          throw new Error(`admin enrichment providers missing ${key}; got ${providers.join(', ')}`);
        }
      }
    }
  }
];

function isExpressHtml404(res, text) {
  const ct = String(res.headers.get('content-type') || '').toLowerCase();
  if (res.status === 404 && ct.includes('text/html')) return true;
  if (res.status === 404 && /cannot get/i.test(text)) return true;
  return false;
}

async function login() {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: SMOKE_EMAIL, password: SMOKE_PASSWORD })
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`login failed (${res.status}): ${text.slice(0, 200)}`);
  }
  const setCookie = res.headers.getSetCookie?.() || [];
  if (!setCookie.length) {
    throw new Error('login succeeded but no Set-Cookie header returned');
  }
  return setCookie.map((c) => c.split(';')[0]).join('; ');
}

async function runCheck(cookie, check) {
  const method = check.method || 'GET';
  const res = await fetch(`${BASE}${check.path}`, {
    method,
    headers: { Cookie: cookie, Accept: 'application/json' }
  });
  const text = await res.text();
  if (isExpressHtml404(res, text)) {
    throw new Error(`Express 404 — route not mounted (${check.path})`);
  }

  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }

  if (check.assert) {
    await check.assert(res, body);
  }

  console.log(`[smoke:routes] OK ${check.name} ${method} ${check.path} → ${res.status}`);
}

async function main() {
  console.log(`[smoke:routes] base=${BASE}`);
  const cookie = await login();
  for (const check of CHECKS) {
    await runCheck(cookie, check);
  }
  console.log('[smoke:routes] all checks passed');
}

main().catch((err) => {
  console.error('[smoke:routes] FAILED:', err?.message || err);
  process.exit(1);
});
