import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BTN_BASE,
  BTN_VARIANTS,
  buttonClassName,
  confirmButtonVariant
} from './uiButtons.js';

test('buttonClassName defaults to secondary', () => {
  assert.equal(buttonClassName(), `${BTN_BASE} ${BTN_VARIANTS.secondary}`);
});

test('buttonClassName includes primary / danger / dangerSolid / ghost / icon', () => {
  assert.equal(buttonClassName({ variant: 'primary' }), `${BTN_BASE} ${BTN_VARIANTS.primary}`);
  assert.equal(buttonClassName({ variant: 'danger' }), `${BTN_BASE} ${BTN_VARIANTS.danger}`);
  assert.equal(buttonClassName({ variant: 'dangerSolid' }), `${BTN_BASE} ${BTN_VARIANTS.dangerSolid}`);
  assert.equal(buttonClassName({ variant: 'ghost' }), `${BTN_BASE} ${BTN_VARIANTS.ghost}`);
  assert.equal(buttonClassName({ variant: 'icon' }), `${BTN_BASE} ${BTN_VARIANTS.icon}`);
});

test('warning and success remain valid aliases (neutral family in CSS)', () => {
  assert.equal(buttonClassName({ variant: 'warning' }), `${BTN_BASE} ${BTN_VARIANTS.warning}`);
  assert.equal(buttonClassName({ variant: 'success' }), `${BTN_BASE} ${BTN_VARIANTS.success}`);
});

test('buttonClassName supports size and extra className', () => {
  assert.equal(
    buttonClassName({ variant: 'primary', size: 'sm', className: 'foo' }),
    `${BTN_BASE} ${BTN_VARIANTS.primary} th-btn--sm foo`
  );
});

test('unknown variant still emits base class only for variant slot skipped', () => {
  assert.equal(buttonClassName({ variant: 'not-a-real-variant' }), BTN_BASE);
});

test('confirmButtonVariant maps tones to sparse accents', () => {
  assert.equal(confirmButtonVariant('danger'), 'dangerSolid');
  assert.equal(confirmButtonVariant('warning'), 'secondary');
  assert.equal(confirmButtonVariant('primary'), 'primary');
  assert.equal(confirmButtonVariant(undefined), 'primary');
});
