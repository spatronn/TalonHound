import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeSourceNameInput,
  validateSourceName,
  parseManualExpirationInput
} from './iocSourceValidation.js';
import { createManualIoc, inferObservableType, resolveStorageObservableType, resolveManualExpirationFromSource, manualIocDuplicateLockKey } from './manualIocCreate.js';

const THREAT_HUNTING_SOURCE = {
  id: 7,
  name: 'Threat-Hunting',
  default_confidence: 'high',
  default_threat_classification: 'unknown',
  default_expire_policy: 'expire_after_days',
  default_expire_days: 30,
  active: true,
  archived_at: null
};

function makeInsertRow(overrides = {}) {
  const now = new Date('2026-06-28T12:00:00.000Z');
  return {
    id: 9001,
    public_id: '11111111-1111-4111-8111-111111111111',
    observable: 'deneme.ekhtelalattabrizi.xyz',
    observable_type: 'domain',
    source_name: 'Threat-Hunting',
    source_url: 'manuel hunting',
    confidence: 'high',
    category: null,
    threat_classification: 'unknown',
    threat_actor_id: null,
    note: null,
    ioc_source_id: 7,
    status: 'active',
    expires_at: '2026-07-28T12:00:00.000Z',
    expired_at: null,
    expiration_reason: 'manual_custom_expire',
    manual_status_override: true,
    manual_status: 'active',
    manual_override_reason: 'manual_custom_expire',
    manual_expires_at: '2026-07-28T12:00:00.000Z',
    created_at: now
  };
}

function createManualIocPoolMock({
  sourceRow = THREAT_HUNTING_SOURCE,
  insertRow = makeInsertRow(),
  enabledTags = [],
  onAdvisoryLock = null,
  insertDelayMs = 0
} = {}) {
  const queries = [];
  const query = async (sql, params = []) => {
    queries.push({ sql: String(sql), params: [...params] });
    const normalized = String(sql).replace(/\s+/g, ' ').trim();

    if (normalized.startsWith('BEGIN') || normalized.startsWith('COMMIT') || normalized.startsWith('ROLLBACK')) {
      return { rows: [] };
    }
    if (normalized.includes('pg_advisory_xact_lock')) {
      if (typeof onAdvisoryLock === 'function') await onAdvisoryLock(params[0]);
      return { rows: [] };
    }
    if (normalized.includes('FROM ioc_sources WHERE id = $1')) {
      return { rows: sourceRow ? [sourceRow] : [] };
    }
    if (normalized.includes('SELECT slug, name, active, system_default, sort_order FROM threat_classifications')) {
      return {
        rows: [
          { slug: 'unknown', name: 'Unknown', active: true, system_default: true, sort_order: 0 },
          { slug: 'phishing', name: 'Phishing', active: true, system_default: true, sort_order: 10 },
          { slug: 'credential_theft', name: 'Credential Theft', active: true, system_default: true, sort_order: 20 }
        ]
      };
    }
    if (normalized.includes('FROM tags') && normalized.includes('id = ANY')) {
      const wanted = Array.isArray(params[0]) ? params[0].map(Number) : [];
      return {
        rows: enabledTags.filter((t) => wanted.includes(Number(t.id)))
      };
    }
    if (normalized.includes('INSERT INTO ioc_tags')) {
      return { rows: [{ tag_id: params[2] }], rowCount: 1 };
    }
    if (normalized.includes('INSERT INTO ioc_items')) {
      assert.match(normalized, /threat_actor_id IS NOT DISTINCT FROM \$8::uuid/);
      assert.doesNotMatch(normalized, /\$8::text/);
      // Durable provenance: created_origin ($16) + created_by_user_id ($17).
      assert.match(normalized, /created_origin, created_by_user_id/);
      assert.match(normalized, /\$16, \$17::uuid/);
      if (insertDelayMs > 0) {
        await new Promise((r) => setTimeout(r, insertDelayMs));
      }
      return { rows: [insertRow] };
    }
    if (normalized.includes('FROM ioc_items WHERE id = $1 AND observable_type = $2')) {
      return { rows: [insertRow] };
    }
    if (normalized.includes('DELETE FROM ioc_threat_classifications')) {
      return { rows: [] };
    }
    if (normalized.includes('INSERT INTO ioc_threat_classifications')) {
      return { rows: [] };
    }
    if (normalized.includes('UPDATE ioc_items SET threat_classification = $3')) {
      return { rows: [] };
    }
    if (normalized.includes('INSERT INTO ioc_observables')) {
      return { rows: [] };
    }
    if (normalized.includes('FROM ioc_items') && normalized.includes('manual_status_override')) {
      return { rows: [{ ...insertRow, status: 'active' }] };
    }
    if (normalized.includes('FROM ioc_suppressions')) {
      return { rows: [] };
    }
    if (normalized.includes('FROM ioc_feed_memberships')) {
      return { rows: [] };
    }
    if (normalized.includes('UPDATE ioc_items') && normalized.includes('SET status = $3')) {
      return { rows: [] };
    }
    throw new Error(`Unexpected query: ${normalized.slice(0, 160)}`);
  };

  return {
    queries,
    query,
    connect: async () => ({
      query,
      release: () => {}
    })
  };
}

test('createManualIoc succeeds for domain with free-text source reference and no classifications', async () => {
  const pool = createManualIocPoolMock();
  const result = await createManualIoc(pool, {
    ip: 'deneme.ekhtelalattabrizi.xyz',
    source_id: 7,
    source_url: 'manuel hunting',
    confidence: 'high',
    threat_classifications: [],
    threat_classification: 'unknown'
  });

  assert.equal(result.status, 201);
  assert.equal(result.body.observable, 'deneme.ekhtelalattabrizi.xyz');
  assert.equal(result.body.source_url, 'manuel hunting');
  assert.equal(result.body.threat_classification, 'unknown');
  assert.deepEqual(result.body.threat_classifications.map((x) => x.value), ['unknown']);
});

test('createManualIoc reports manual_status_override=false (manual source is not a lifecycle override)', async () => {
  const pool = createManualIocPoolMock();
  const result = await createManualIoc(pool, {
    ip: 'deneme.ekhtelalattabrizi.xyz',
    source_id: 7,
    source_url: 'manuel hunting',
    confidence: 'high'
  });

  assert.equal(result.status, 201);
  // The row still carries the internal manual_status_override flag for its own expiry
  // bookkeeping, but the analyst-facing response must not present it as an override.
  assert.equal(result.body.manual_status_override, false);
});

test('createManualIoc accepts missing threat_classifications field', async () => {
  const pool = createManualIocPoolMock();
  const result = await createManualIoc(pool, {
    ip: 'deneme.ekhtelalattabrizi.xyz',
    source_id: 7,
    source_url: 'manuel hunting',
    confidence: 'high'
  });

  assert.equal(result.status, 201);
  assert.equal(result.body.threat_classification, 'unknown');
});

test('createManualIoc stores multiple threat classifications', async () => {
  const pool = createManualIocPoolMock({
    insertRow: makeInsertRow({ threat_classification: 'phishing' })
  });
  const result = await createManualIoc(pool, {
    ip: 'deneme.ekhtelalattabrizi.xyz',
    source_id: 7,
    source_url: 'manuel hunting',
    confidence: 'high',
    threat_classifications: ['phishing', 'credential_theft']
  });

  assert.equal(result.status, 201);
  assert.equal(result.body.threat_classification, 'phishing');
  assert.deepEqual(
    result.body.threat_classifications.map((x) => x.value),
    ['phishing', 'credential_theft']
  );
});

test('createManualIoc stamps manual origin and records the creating user', async () => {
  const pool = createManualIocPoolMock();
  const creatorPublicId = '22222222-2222-4222-8222-222222222222';
  const result = await createManualIoc(
    pool,
    { ip: 'deneme.ekhtelalattabrizi.xyz', source_id: 7, confidence: 'high' },
    { user: { publicId: creatorPublicId } }
  );

  assert.equal(result.status, 201);
  const insert = pool.queries.find((q) => q.sql.includes('INSERT INTO ioc_items'));
  assert.ok(insert, 'expected an ioc_items insert');
  // $15 = manual_override_by_user_id; $16 = created_origin; $17 = created_by_user_id
  assert.equal(insert.params[14], creatorPublicId);
  assert.equal(insert.params[15], 'manual_add');
  assert.equal(insert.params[16], creatorPublicId);
});

test('createManualIoc stamps api origin without a creating user', async () => {
  const pool = createManualIocPoolMock();
  const result = await createManualIoc(
    pool,
    { ip: 'deneme.ekhtelalattabrizi.xyz', source_id: 7, confidence: 'high' },
    { createdOrigin: 'api' }
  );

  assert.equal(result.status, 201);
  const insert = pool.queries.find((q) => q.sql.includes('INSERT INTO ioc_items'));
  assert.equal(insert.params[15], 'api');
  assert.equal(insert.params[16], null);
});

test('createManualIoc rejects invalid source', async () => {
  const pool = createManualIocPoolMock({ sourceRow: null });
  const result = await createManualIoc(pool, {
    ip: 'deneme.ekhtelalattabrizi.xyz',
    source_id: 99999,
    confidence: 'high'
  });
  assert.equal(result.status, 400);
  assert.match(result.body.message, /Invalid IOC source/);
});

test('createManualIoc rejects missing IOC value', async () => {
  const pool = createManualIocPoolMock();
  const result = await createManualIoc(pool, { source_id: 7, confidence: 'high' });
  assert.equal(result.status, 400);
  assert.match(result.body.message, /required/i);
});

test('createManualIoc assigns tag_ids atomically', async () => {
  const pool = createManualIocPoolMock({
    enabledTags: [
      { id: 11, name: 'watchlist', type: 'context', category: 'custom' },
      { id: 12, name: 'vip', type: 'context', category: 'targeting' }
    ]
  });
  const result = await createManualIoc(pool, {
    ip: 'deneme.ekhtelalattabrizi.xyz',
    source_id: 7,
    confidence: 'high',
    tag_ids: [11, 12]
  });

  assert.equal(result.status, 201);
  assert.deepEqual(
    result.body.tags.map((t) => ({ id: t.id, name: t.name })),
    [
      { id: 11, name: 'watchlist' },
      { id: 12, name: 'vip' }
    ]
  );
  assert.ok(pool.queries.some((q) => q.sql.includes('INSERT INTO ioc_tags')));
});

test('createManualIoc rejects invalid tag_ids', async () => {
  const pool = createManualIocPoolMock({
    enabledTags: [{ id: 11, name: 'watchlist', type: 'context', category: 'custom' }]
  });
  const result = await createManualIoc(pool, {
    ip: 'deneme.ekhtelalattabrizi.xyz',
    source_id: 7,
    confidence: 'high',
    tag_ids: [11, 999]
  });
  assert.equal(result.status, 400);
  assert.match(result.body.message, /tags are invalid/i);
});

test('normalizeSourceNameInput replaces spaces and strips invalid chars', () => {
  assert.equal(normalizeSourceNameInput('Internal Hunting'), 'Internal_Hunting');
  assert.equal(normalizeSourceNameInput('  SOC@Manual! '), 'SOCManual');
});

test('validateSourceName enforces pattern', () => {
  assert.equal(validateSourceName('ab').ok, false);
  assert.equal(validateSourceName('Internal_Hunting').ok, true);
});

test('parseManualExpirationInput never expire', () => {
  const r = parseManualExpirationInput({ expiration_policy: 'never' });
  assert.equal(r.ok, true);
  assert.equal(r.policy, 'never');
  assert.equal(r.manual_expires_at, null);
  assert.equal(r.manual_override_reason, 'manual_never_expire');
});

test('parseManualExpirationInput expire after days', () => {
  const now = new Date('2026-05-30T12:00:00.000Z');
  const r = parseManualExpirationInput(
    { expiration_policy: 'expire_after_days', expire_days: 30 },
    { now }
  );
  assert.equal(r.ok, true);
  assert.equal(r.expire_days, 30);
  assert.equal(r.manual_override_reason, 'manual_custom_expire');
  const exp = new Date(r.manual_expires_at);
  assert.equal(exp.toISOString(), '2026-06-29T12:00:00.000Z');
});

test('parseManualExpirationInput rejects past custom date', () => {
  const now = new Date('2026-05-30T12:00:00.000Z');
  const r = parseManualExpirationInput(
    { expiration_policy: 'custom_date', expires_at: '2026-05-29T12:00:00.000Z' },
    { now }
  );
  assert.equal(r.ok, false);
});

test('resolveManualExpirationFromSource uses source default expire after days', () => {
  const now = new Date('2026-05-30T12:00:00.000Z');
  const r = resolveManualExpirationFromSource(
    { default_expire_policy: 'expire_after_days', default_expire_days: 30 },
    { now }
  );
  assert.equal(r.ok, true);
  assert.equal(r.policy, 'expire_after_days');
  assert.equal(r.expire_days, 30);
  assert.equal(new Date(r.manual_expires_at).toISOString(), '2026-06-29T12:00:00.000Z');
});

test('resolveManualExpirationFromSource uses source default never expire', () => {
  const r = resolveManualExpirationFromSource({ default_expire_policy: 'never' });
  assert.equal(r.ok, true);
  assert.equal(r.policy, 'never');
  assert.equal(r.manual_expires_at, null);
});

test('resolveManualExpirationFromSource ignores null policy and falls back to never', () => {
  const r = resolveManualExpirationFromSource({ default_expire_policy: null, default_expire_days: null });
  assert.equal(r.ok, true);
  assert.equal(r.policy, 'never');
  assert.equal(r.manual_expires_at, null);
});

test('inferObservableType detects ip domain url hash', () => {
  assert.equal(inferObservableType('1.2.3.4'), 'ip');
  assert.equal(inferObservableType('evil.com'), 'domain');
  assert.equal(inferObservableType('https://evil.com/x'), 'url');
  assert.equal(inferObservableType('a'.repeat(64)), 'hash');
});

test('resolveStorageObservableType maps abstract hash to md5/sha1/sha256', () => {
  assert.equal(resolveStorageObservableType('a'.repeat(32)).type, 'md5');
  assert.equal(resolveStorageObservableType('b'.repeat(40)).type, 'sha1');
  assert.equal(resolveStorageObservableType('c'.repeat(64)).type, 'sha256');
  assert.equal(resolveStorageObservableType('evil.com').type, 'domain');
  assert.equal(resolveStorageObservableType('d'.repeat(128)).ok, false);
});

test('manualIocDuplicateLockKey is stable for nullable fields', () => {
  const a = manualIocDuplicateLockKey({
    observable: 'evil.com',
    observableType: 'domain',
    sourceName: 'Threat-Hunting',
    confidence: 'high',
    category: null,
    sourceUrl: null,
    threatClassification: 'unknown',
    threatActorId: null
  });
  const b = manualIocDuplicateLockKey({
    observable: 'evil.com',
    observableType: 'domain',
    sourceName: 'Threat-Hunting',
    confidence: 'high',
    category: undefined,
    sourceUrl: '',
    threatClassification: 'unknown',
    threatActorId: ''
  });
  assert.equal(a, b);
  assert.match(a, /^manual_ioc\u001f/);
});

test('createManualIoc takes advisory xact lock before INSERT', async () => {
  const events = [];
  const pool = createManualIocPoolMock({
    onAdvisoryLock: async (key) => {
      events.push(`lock:${String(key).slice(0, 20)}`);
    }
  });
  const origConnect = pool.connect;
  pool.connect = async () => {
    const client = await origConnect();
    const origQuery = client.query;
    client.query = async (sql, params) => {
      const n = String(sql).replace(/\s+/g, ' ').trim();
      if (n.startsWith('BEGIN')) events.push('BEGIN');
      if (n.includes('pg_advisory_xact_lock')) events.push('LOCK');
      if (n.includes('INSERT INTO ioc_items')) events.push('INSERT');
      if (n.startsWith('COMMIT')) events.push('COMMIT');
      return origQuery(sql, params);
    };
    return client;
  };

  const result = await createManualIoc(pool, {
    ip: 'deneme.ekhtelalattabrizi.xyz',
    source_id: 7,
    confidence: 'high'
  });
  assert.equal(result.status, 201);
  const core = events.filter((e) => ['BEGIN', 'LOCK', 'INSERT', 'COMMIT'].includes(e));
  // Create path must lock before insert; later lifecycle recompute may open another txn.
  assert.deepEqual(core.slice(0, 4), ['BEGIN', 'LOCK', 'INSERT', 'COMMIT']);
  assert.ok(core.indexOf('LOCK') < core.indexOf('INSERT'));
});

test('concurrent createManualIoc serializes on advisory lock', async () => {
  let lockHeld = false;
  const lockWaiters = [];
  const order = [];

  async function takeLock() {
    if (!lockHeld) {
      lockHeld = true;
      return;
    }
    await new Promise((resolve) => lockWaiters.push(resolve));
    lockHeld = true;
  }

  function releaseLock() {
    lockHeld = false;
    const next = lockWaiters.shift();
    if (next) next();
  }

  function makeSerialPool(label) {
    const pool = createManualIocPoolMock({
      insertDelayMs: 30,
      onAdvisoryLock: async () => {
        order.push(`${label}:lock-wait`);
        await takeLock();
        order.push(`${label}:lock-held`);
      }
    });
    const origConnect = pool.connect;
    pool.connect = async () => {
      const client = await origConnect();
      const origQuery = client.query;
      client.query = async (sql, params) => {
        const n = String(sql).replace(/\s+/g, ' ').trim();
        const result = await origQuery(sql, params);
        if (n.startsWith('COMMIT') || n.startsWith('ROLLBACK')) {
          order.push(`${label}:release`);
          releaseLock();
        }
        return result;
      };
      return client;
    };
    return pool;
  }

  const body = {
    ip: 'race.example.com',
    source_id: 7,
    confidence: 'high',
    threat_classifications: []
  };

  const [a, b] = await Promise.all([
    createManualIoc(makeSerialPool('A'), body),
    createManualIoc(makeSerialPool('B'), body)
  ]);

  assert.equal(a.status, 201);
  assert.equal(b.status, 201);
  // Second lock-held must not occur before the first release.
  const firstHeld = order.indexOf('A:lock-held');
  const secondHeld = order.indexOf('B:lock-held');
  const firstRelease = order.indexOf('A:release');
  const altFirstHeld = order.indexOf('B:lock-held') < order.indexOf('A:lock-held')
    ? order.indexOf('B:lock-held')
    : firstHeld;
  const altFirstRelease = order.indexOf('B:lock-held') < order.indexOf('A:lock-held')
    ? order.indexOf('B:release')
    : firstRelease;
  const altSecondHeld = order.indexOf('B:lock-held') < order.indexOf('A:lock-held')
    ? order.indexOf('A:lock-held')
    : secondHeld;
  assert.ok(altFirstHeld >= 0 && altFirstRelease >= 0 && altSecondHeld >= 0);
  assert.ok(altSecondHeld > altFirstRelease, `expected serialization, order=${JSON.stringify(order)}`);
});
