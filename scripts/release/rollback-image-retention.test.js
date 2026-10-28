import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  formatPlanLines,
  parseDockerTime,
  planRollbackRetention
} from './rollback-image-retention.js';

const SERVICES = ['backend', 'frontend', 'proxy', 'integration-worker', 'integration-scheduler'];

function generation(label, day, { services = SERVICES, idOf = (svc) => `${svc}-${label}` } = {}) {
  return services.map((svc) => ({
    Repository: `talonhound-${svc}`,
    Tag: `rollback-${label}`,
    ID: `sha256:${idOf(svc)}`,
    CreatedAt: `2026-10-${String(day).padStart(2, '0')} 10:00:00 +0000 UTC`
  }));
}

const current = SERVICES.map((svc) => ({
  Repository: `talonhound-${svc}`,
  Tag: svc === 'backend' ? 'local' : 'latest',
  ID: `sha256:${svc}-current`,
  CreatedAt: '2026-10-28 10:00:00 +0000 UTC'
}));

const removedRefs = (plan) => plan.remove.map((r) => r.ref).sort();

test('parseDockerTime handles docker CreatedAt and ISO strings', () => {
  assert.equal(parseDockerTime('2026-10-27 18:57:02 +0000 UTC'), Date.parse('2026-10-27T18:57:02Z'));
  assert.equal(parseDockerTime('2026-10-27 21:57:02 +0300 +03'), Date.parse('2026-10-27T18:57:02Z'));
  assert.equal(parseDockerTime('2026-10-27T18:57:02Z'), Date.parse('2026-10-27T18:57:02Z'));
  assert.equal(parseDockerTime(''), 0);
});

test('keeps the two newest complete generations and removes older ones', () => {
  const images = [...current, ...generation('aaa1111', 20), ...generation('bbb2222', 24), ...generation('ccc3333', 26)];
  const plan = planRollbackRetention({ images, inUseImageIds: current.map((i) => i.ID) });
  assert.deepEqual(plan.kept_generations.map((g) => g.label), ['ccc3333', 'bbb2222']);
  assert.deepEqual(removedRefs(plan), SERVICES.map((s) => `talonhound-${s}:rollback-aaa1111`).sort());
  assert.ok(plan.remove.every((r) => r.untag_only === false));
});

test('newer partial generations are kept without counting toward the complete quota', () => {
  const images = [
    ...generation('old0001', 10),
    ...generation('mid0002', 15),
    ...generation('new0003', 20),
    ...generation('fe-only', 25, { services: ['frontend'] })
  ];
  const plan = planRollbackRetention({ images, inUseImageIds: [] });
  assert.deepEqual(plan.kept_generations.map((g) => g.label), ['fe-only', 'new0003', 'mid0002']);
  assert.ok(removedRefs(plan).every((r) => r.endsWith(':rollback-old0001')));
});

test('never plans images used by containers, current tags, or unrelated repositories', () => {
  const images = [
    ...current,
    ...generation('aaa1111', 20, { idOf: (svc) => (svc === 'proxy' ? 'proxy-current' : `${svc}-aaa`) }),
    ...generation('bbb2222', 24),
    ...generation('ccc3333', 26),
    { Repository: 'postgres', Tag: 'rollback-x', ID: 'sha256:pg', CreatedAt: '2026-01-01 00:00:00 +0000 UTC' },
    { Repository: 'talonhound-backend', Tag: 'pre-pr35-abc', ID: 'sha256:pre', CreatedAt: '2026-01-01 00:00:00 +0000 UTC' },
    { Repository: 'mytalonhound-backend', Tag: 'rollback-zzz', ID: 'sha256:z', CreatedAt: '2026-01-01 00:00:00 +0000 UTC' }
  ];
  const plan = planRollbackRetention({ images, inUseImageIds: ['proxy-current'] });
  const refs = removedRefs(plan);
  assert.ok(!refs.includes('talonhound-proxy:rollback-aaa1111'));
  assert.deepEqual(plan.skipped, [
    { ref: 'talonhound-proxy:rollback-aaa1111', generation: 'aaa1111', reason: 'in_use' }
  ]);
  assert.ok(refs.every((r) => /^talonhound-[a-z-]+:rollback-aaa1111$/.test(r)));
  assert.ok(!refs.some((r) => r.startsWith('postgres') || r.includes('pre-pr35') || r.startsWith('my')));
});

test('a tag sharing its image id with a kept tag is reported as untag-only', () => {
  const images = [
    ...generation('aaa1111', 20, { idOf: (svc) => `${svc}-shared` }),
    ...generation('bbb2222', 24, { idOf: (svc) => `${svc}-shared` }),
    ...generation('ccc3333', 26)
  ];
  const plan = planRollbackRetention({ images, inUseImageIds: [] });
  assert.equal(plan.remove.length, SERVICES.length);
  assert.ok(plan.remove.every((r) => r.untag_only === true));
});

test('fewer complete generations than keep removes nothing', () => {
  const plan = planRollbackRetention({ images: generation('only001', 20), inUseImageIds: [] });
  assert.equal(plan.remove.length, 0);
});

test('keep below two is rejected', () => {
  assert.throws(() => planRollbackRetention({ images: [] }, { keep: 1 }), /keep must be an integer >= 2/);
  assert.throws(() => planRollbackRetention({ images: [] }, { keep: 'x' }), /keep/);
  const plan = planRollbackRetention(
    { images: [...generation('a', 1), ...generation('b', 2), ...generation('c', 3), ...generation('d', 4)] },
    { keep: 3 }
  );
  assert.deepEqual(plan.kept_generations.map((g) => g.label), ['d', 'c', 'b']);
});

test('CLI emits line records for the shell wrapper', () => {
  const script = fileURLToPath(new URL('./rollback-image-retention.js', import.meta.url));
  const input = JSON.stringify({
    images: [...generation('a', 1), ...generation('b', 2), ...generation('c', 3)],
    inUseImageIds: []
  });
  const r = spawnSync(process.execPath, [script, '--format', 'lines'], { input, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout.trim().split('\n');
  assert.deepEqual(lines.filter((l) => l.startsWith('KEEP')), ['KEEP c', 'KEEP b']);
  assert.equal(lines.filter((l) => l.startsWith('REMOVE ')).length, SERVICES.length);
  assert.equal(formatPlanLines({ kept_generations: [], remove: [], skipped: [] }), '');

  const bad = spawnSync(process.execPath, [script, '--keep', '1'], { input, encoding: 'utf8' });
  assert.equal(bad.status, 2);
});
