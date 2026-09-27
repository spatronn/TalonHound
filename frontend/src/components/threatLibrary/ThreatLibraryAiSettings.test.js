/**
 * Source contract for Threat Library AI Settings concurrency control.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MAX_CONCURRENT_REPORT_ANALYSES_DEFAULT,
  MAX_CONCURRENT_REPORT_ANALYSES_MAX,
  MAX_CONCURRENT_REPORT_ANALYSES_MIN,
  parseConcurrentReportAnalyses
} from './aiSettingsConcurrency.js';

const src = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'ThreatLibraryAiSettings.jsx'), 'utf8');

test('frontend concurrency range matches backend (integer 1–4, default 2)', () => {
  assert.equal(MAX_CONCURRENT_REPORT_ANALYSES_MIN, 1);
  assert.equal(MAX_CONCURRENT_REPORT_ANALYSES_MAX, 4);
  assert.equal(MAX_CONCURRENT_REPORT_ANALYSES_DEFAULT, 2);
  assert.equal(parseConcurrentReportAnalyses(1), 1);
  assert.equal(parseConcurrentReportAnalyses('4'), 4);
  assert.equal(parseConcurrentReportAnalyses(2.5), null);
  assert.equal(parseConcurrentReportAnalyses(0), null);
  assert.equal(parseConcurrentReportAnalyses(5), null);
});

test('AI Settings exposes Concurrent report analyses with helper text and matching validation', () => {
  assert.match(src, /htmlFor="tl-ai-concurrency">Concurrent report analyses</);
  assert.match(src, /id="tl-ai-concurrency"/);
  assert.match(src, /min=\{MAX_CONCURRENT_REPORT_ANALYSES_MIN\}/);
  assert.match(src, /max=\{MAX_CONCURRENT_REPORT_ANALYSES_MAX\}/);
  assert.match(src, /max_concurrent_report_analyses/);
  assert.match(src, /Maximum number of Threat Library reports that can be analyzed by AI at the same time/);
  assert.match(src, /Additional imports remain queued until a slot becomes available/);
  assert.match(src, /Increasing this value starts queued reports immediately; decreasing it does not stop analyses that are already running/);
  assert.match(src, /parseConcurrentReportAnalyses\(form\.max_concurrent_report_analyses\)/);
});
