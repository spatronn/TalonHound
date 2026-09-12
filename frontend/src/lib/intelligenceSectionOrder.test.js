import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ANALYST_INTELLIGENCE_SECTION,
  THREAT_CONTEXT_SECTION,
  buildIntelligenceSectionOrder
} from './intelligenceSectionOrder.js';

// Flags each representative IOC type produces in IntelligenceTabPanel:
//   - Derived Infrastructure renders only for URL IOCs with an extractable host.
//   - File Information renders only for hash IOCs (md5/sha1/sha256/...).
const IOC_TYPE_FLAGS = {
  domain: { showDerivedInfrastructure: false, showFileInformation: false },
  ip: { showDerivedInfrastructure: false, showFileInformation: false },
  url: { showDerivedInfrastructure: true, showFileInformation: false },
  md5: { showDerivedInfrastructure: false, showFileInformation: true },
  sha1: { showDerivedInfrastructure: false, showFileInformation: true },
  sha256: { showDerivedInfrastructure: false, showFileInformation: true }
};

function lastOf(order) {
  return order[order.length - 1];
}

test('Analyst Intelligence is the final section for every supported IOC type', () => {
  for (const [type, flags] of Object.entries(IOC_TYPE_FLAGS)) {
    const order = buildIntelligenceSectionOrder(flags);
    assert.equal(
      lastOf(order),
      ANALYST_INTELLIGENCE_SECTION,
      `expected analyst to be last for ${type}, got ${JSON.stringify(order)}`
    );
  }
});

test('Threat Context appears immediately above Analyst Intelligence', () => {
  for (const [type, flags] of Object.entries(IOC_TYPE_FLAGS)) {
    const order = buildIntelligenceSectionOrder(flags);
    const threatIdx = order.indexOf(THREAT_CONTEXT_SECTION);
    const analystIdx = order.indexOf(ANALYST_INTELLIGENCE_SECTION);
    assert.ok(threatIdx >= 0, `threat context missing for ${type}`);
    assert.equal(threatIdx, analystIdx - 1, `threat context must sit above analyst for ${type}`);
  }
});

test('Analyst Intelligence appears exactly once for every IOC type', () => {
  for (const [type, flags] of Object.entries(IOC_TYPE_FLAGS)) {
    const order = buildIntelligenceSectionOrder(flags);
    const count = order.filter((k) => k === ANALYST_INTELLIGENCE_SECTION).length;
    assert.equal(count, 1, `expected exactly one analyst section for ${type}`);
  }
});

test('every IOC type opens with Summary then Automated Intelligence', () => {
  for (const [type, flags] of Object.entries(IOC_TYPE_FLAGS)) {
    const order = buildIntelligenceSectionOrder(flags);
    assert.deepEqual(order.slice(0, 2), ['summary', 'automated'], `bad opening for ${type}`);
  }
});

test('domain / IP: summary -> automated -> threatContext -> analyst', () => {
  for (const type of ['domain', 'ip']) {
    const order = buildIntelligenceSectionOrder(IOC_TYPE_FLAGS[type]);
    assert.deepEqual(order, ['summary', 'automated', 'threatContext', 'analyst']);
  }
});

test('URL: Derived Infrastructure renders above Threat Context / Analyst', () => {
  const order = buildIntelligenceSectionOrder(IOC_TYPE_FLAGS.url);
  assert.deepEqual(order, ['summary', 'automated', 'derivedInfrastructure', 'threatContext', 'analyst']);
  assert.ok(order.indexOf('derivedInfrastructure') < order.indexOf(THREAT_CONTEXT_SECTION));
});

test('hash: Automated Intelligence -> File Information -> Threat Context -> Analyst', () => {
  for (const type of ['md5', 'sha1', 'sha256']) {
    const order = buildIntelligenceSectionOrder(IOC_TYPE_FLAGS[type]);
    assert.deepEqual(order, ['summary', 'automated', 'fileInformation', 'threatContext', 'analyst']);
    assert.ok(
      order.indexOf('automated') < order.indexOf('fileInformation'),
      `automated must precede file information for ${type}`
    );
    assert.ok(
      order.indexOf('fileInformation') < order.indexOf(ANALYST_INTELLIGENCE_SECTION),
      `file information must precede analyst for ${type}`
    );
  }
});

test('Analyst stays last even when all type-specific sections are present', () => {
  const order = buildIntelligenceSectionOrder({
    showDerivedInfrastructure: true,
    showFileInformation: true
  });
  assert.equal(lastOf(order), ANALYST_INTELLIGENCE_SECTION);
  const analystIdx = order.indexOf(ANALYST_INTELLIGENCE_SECTION);
  for (const key of ['summary', 'automated', 'derivedInfrastructure', 'fileInformation', 'threatContext']) {
    assert.ok(order.indexOf(key) < analystIdx, `${key} must be above analyst`);
  }
});

test('no-arg call is safe and still ends with analyst', () => {
  const order = buildIntelligenceSectionOrder();
  assert.deepEqual(order, ['summary', 'automated', 'threatContext', 'analyst']);
});
