import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeOverflowMenuPosition } from './backupMenuPosition.js';

const trigger = {
  top: 400,
  bottom: 432,
  left: 900,
  right: 932,
  width: 32,
  height: 32
};

describe('computeOverflowMenuPosition', () => {
  it('opens below and right-aligns to the trigger by default', () => {
    const pos = computeOverflowMenuPosition({
      trigger,
      menuWidth: 168,
      menuHeight: 132,
      viewportWidth: 1366,
      viewportHeight: 768
    });
    assert.equal(pos.placement, 'bottom');
    assert.equal(pos.top, 436);
    assert.equal(pos.left, 932 - 168);
  });

  it('flips above when there is not enough space below', () => {
    const lowTrigger = { ...trigger, top: 700, bottom: 732 };
    const pos = computeOverflowMenuPosition({
      trigger: lowTrigger,
      menuWidth: 168,
      menuHeight: 132,
      viewportWidth: 1366,
      viewportHeight: 768
    });
    assert.equal(pos.placement, 'top');
    assert.ok(pos.top < lowTrigger.top);
    assert.ok(pos.top + 132 <= lowTrigger.top);
  });

  it('keeps the menu inside the right viewport edge', () => {
    const nearRight = { ...trigger, left: 1300, right: 1332 };
    const pos = computeOverflowMenuPosition({
      trigger: nearRight,
      menuWidth: 168,
      menuHeight: 132,
      viewportWidth: 1366,
      viewportHeight: 768,
      pad: 8
    });
    assert.ok(pos.left + 168 <= 1366 - 8);
    assert.ok(pos.left >= 8);
  });

  it('keeps the menu inside the left viewport edge', () => {
    const nearLeft = { top: 100, bottom: 132, left: 4, right: 36, width: 32, height: 32 };
    const pos = computeOverflowMenuPosition({
      trigger: nearLeft,
      menuWidth: 168,
      menuHeight: 132,
      viewportWidth: 1280,
      viewportHeight: 720,
      pad: 8
    });
    assert.equal(pos.left, 8);
  });
});
