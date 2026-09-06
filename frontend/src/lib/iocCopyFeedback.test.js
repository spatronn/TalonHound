import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  IOC_COPY_FEEDBACK_MS,
  IOC_COPY_SUCCESS_COLOR,
  beginCopiedFeedback,
  clearCopiedFeedbackTimer,
  copyTextToClipboard,
  getIocCopyControlLabels,
  scheduleCopiedFeedbackReset
} from './iocCopyFeedback.js';

describe('beginCopiedFeedback', () => {
  it('marks copied and increments epoch so re-clicks restart the effect timer', () => {
    assert.deepEqual(beginCopiedFeedback(0), { copied: true, feedbackEpoch: 1 });
    assert.deepEqual(beginCopiedFeedback(3), { copied: true, feedbackEpoch: 4 });
  });
});

describe('getIocCopyControlLabels', () => {
  it('initial / normal state uses Copy IOC labels', () => {
    assert.deepEqual(getIocCopyControlLabels(false), {
      ariaLabel: 'Copy IOC',
      title: 'Copy IOC'
    });
  });

  it('success state uses Copied labels', () => {
    assert.deepEqual(getIocCopyControlLabels(true), {
      ariaLabel: 'Copied',
      title: 'Copied'
    });
  });
});

describe('copyTextToClipboard', () => {
  it('succeeds when writeText resolves', async () => {
    const seen = [];
    const result = await copyTextToClipboard('1.2.3.4', {
      writeText: async (text) => { seen.push(text); }
    });
    assert.deepEqual(result, { ok: true });
    assert.deepEqual(seen, ['1.2.3.4']);
  });

  it('does not report success when clipboard is missing', async () => {
    assert.deepEqual(await copyTextToClipboard('1.2.3.4', null), {
      ok: false,
      reason: 'unsupported'
    });
    assert.deepEqual(await copyTextToClipboard('1.2.3.4', {}), {
      ok: false,
      reason: 'unsupported'
    });
  });

  it('does not report success when writeText rejects', async () => {
    const result = await copyTextToClipboard('evil.com', {
      writeText: async () => { throw new Error('denied'); }
    });
    assert.deepEqual(result, { ok: false, reason: 'failed' });
  });

  it('rejects empty / placeholder values without calling clipboard', async () => {
    let called = 0;
    const clipboard = { writeText: async () => { called += 1; } };
    assert.equal((await copyTextToClipboard('', clipboard)).ok, false);
    assert.equal((await copyTextToClipboard('  ', clipboard)).ok, false);
    assert.equal((await copyTextToClipboard('-', clipboard)).ok, false);
    assert.equal(called, 0);
  });
});

function createFakeTimers() {
  let nextId = 1;
  const pending = new Map();
  return {
    pending,
    timers: {
      setTimeout: (fn, ms) => {
        const id = nextId++;
        pending.set(id, { fn, ms });
        return id;
      },
      clearTimeout: (id) => {
        pending.delete(id);
      }
    },
    run(id) {
      const entry = pending.get(id);
      if (!entry) return false;
      pending.delete(id);
      entry.fn();
      return true;
    }
  };
}

describe('scheduleCopiedFeedbackReset', () => {
  it('sets copied true then false after the feedback window', () => {
    const states = [];
    const timerRef = { current: null };
    const fake = createFakeTimers();

    scheduleCopiedFeedbackReset(timerRef, (v) => states.push(v), IOC_COPY_FEEDBACK_MS, fake.timers);
    assert.deepEqual(states, [true]);
    assert.equal(fake.pending.size, 1);
    const [id, entry] = [...fake.pending.entries()][0];
    assert.equal(entry.ms, 2000);
    assert.equal(typeof IOC_COPY_SUCCESS_COLOR, 'string');

    assert.equal(fake.run(id), true);
    assert.deepEqual(states, [true, false]);
    assert.equal(timerRef.current, null);
  });

  it('repeated clicks clear the prior timer so old timeout cannot end new feedback early', () => {
    const states = [];
    const timerRef = { current: null };
    const fake = createFakeTimers();

    scheduleCopiedFeedbackReset(timerRef, (v) => states.push(v), 2000, fake.timers);
    const firstId = timerRef.current;
    scheduleCopiedFeedbackReset(timerRef, (v) => states.push(v), 2000, fake.timers);
    const secondId = timerRef.current;

    assert.equal(fake.pending.size, 1);
    assert.notEqual(firstId, secondId);
    assert.deepEqual(states, [true, true]);

    // Cleared first timeout must be a no-op; only the latest timer fires.
    assert.equal(fake.run(firstId), false);
    assert.deepEqual(states, [true, true]);

    assert.equal(fake.run(secondId), true);
    assert.deepEqual(states, [true, true, false]);
  });

  it('clearCopiedFeedbackTimer removes pending timeout without flipping state', () => {
    const states = [];
    const timerRef = { current: null };
    const fake = createFakeTimers();

    scheduleCopiedFeedbackReset(timerRef, (v) => states.push(v), 2000, fake.timers);
    clearCopiedFeedbackTimer(timerRef, fake.timers);
    assert.equal(fake.pending.size, 0);
    assert.equal(timerRef.current, null);
    assert.deepEqual(states, [true]);
  });
});
