/**
 * AI progress writes must never land after the analysis settled (a late
 * "analyzing" write used to overwrite a terminal failed status).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createProgressGate } from './pipeline.js';

const tick = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test('close() waits for the in-flight progress write, then drops later ones', async () => {
  const log = [];
  const gate = createProgressGate(async (p) => {
    log.push(`start ${p.n}`);
    await tick(20);
    log.push(`end ${p.n}`);
  });
  gate.push({ n: 1 }); // fire-and-forget, like the stream activity callback
  await tick(1);
  await gate.close();
  log.push('terminal status');
  gate.push({ n: 2 });
  await tick(30);
  assert.deepEqual(log, ['start 1', 'end 1', 'terminal status']);
});

test('queued-but-not-started writes are skipped once closed; writes are serialized in order', async () => {
  const log = [];
  const gate = createProgressGate(async (p) => {
    log.push(`start ${p.n}`);
    await tick(10);
    log.push(`end ${p.n}`);
  });
  gate.push({ n: 1 });
  gate.push({ n: 2 });
  gate.push({ n: 3 });
  await tick(1);
  await gate.close();
  assert.deepEqual(log, ['start 1', 'end 1']);
});

test('a failing write still rejects its awaiting caller and does not block close()', async () => {
  const gate = createProgressGate(async () => {
    throw new Error('db down');
  });
  await assert.rejects(gate.push({ n: 1 }), /db down/);
  await gate.close();
  assert.equal(await gate.push({ n: 2 }), undefined);
});
