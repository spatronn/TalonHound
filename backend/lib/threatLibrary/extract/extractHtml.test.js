/**
 * Layered HTML extraction + Weixin adapter + page classification tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractCanonicalDocumentFromHtml, extractGenericArticleDocument } from './extractHtml.js';
import { classifyFetchedHtmlPage } from './classifySourcePage.js';
import { assessDocumentQuality, meaningfulCharCount } from './quality.js';
import { extractWeixinDocument } from './adapters/weixin.js';
import { htmlToCanonicalDocument, validateThreatLibraryUrl } from '../urlIngest.js';

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const load = (name) => readFileSync(join(fixtureDir, name), 'utf8');

test('Weixin article HTML extracts Chinese title and body blocks', () => {
  const html = load('weixin-article.html');
  const extracted = extractCanonicalDocumentFromHtml(html, {
    url: 'https://mp.weixin.qq.com/s/exampleArticleIdNotReal',
    finalUrl: 'https://mp.weixin.qq.com/s/exampleArticleIdNotReal',
    httpStatus: 200
  });
  assert.equal(extracted.ok, true);
  assert.match(extracted.document.title, /APT组织/);
  assert.ok(extracted.path.includes('weixin_ok'));
  assert.equal(extracted.document.meta.adapter, 'weixin');
  assert.ok(extracted.document.blocks.length >= 5);
  const text = extracted.document.blocks.map((b) => b.text).join('\n');
  assert.match(text, /evil-phish\.example/);
  assert.match(text, /203\.0\.113\.88/);
  assert.match(text, /钓鱼邮件/);
  assert.ok(meaningfulCharCount(extracted.document) > 80);
  // Language hint zh*
  assert.ok(String(extracted.document.language || '').startsWith('zh'));
});

test('primary generic empty + Weixin adapter succeeds', () => {
  const html = load('weixin-article.html');
  const generic = extractGenericArticleDocument(html, { url: 'https://mp.weixin.qq.com/s/x' });
  // No <article>/<main>; body still has content via p tags — may or may not be empty.
  // Force adapter path: Weixin extractor alone must succeed.
  const wx = extractWeixinDocument(html, { url: 'https://mp.weixin.qq.com/s/x' });
  assert.equal(wx.ok, true);
  assert.ok(wx.document.blocks.length > generic.blocks.filter((b) => /js_content/.test(b.text)).length);
});

test('Weixin verification/interstitial is not empty_document', () => {
  const html = load('weixin-verification.html');
  const finalUrl =
    'https://mp.weixin.qq.com/mp/wappoc_appmsgcaptcha?poc_token=abc&target_url=https%3A%2F%2Fmp.weixin.qq.com%2Fs%2Fx';
  const extracted = extractCanonicalDocumentFromHtml(html, {
    url: 'https://mp.weixin.qq.com/s/x',
    finalUrl,
    httpStatus: 200
  });
  assert.equal(extracted.ok, false);
  assert.equal(extracted.code, 'source_verification_required');
  assert.match(extracted.message, /verification|interstitial/i);
});

test('classifyFetchedHtmlPage detects Weixin captcha URL', () => {
  const c = classifyFetchedHtmlPage({
    finalUrl: 'https://mp.weixin.qq.com/mp/wappoc_appmsgcaptcha?poc_token=1',
    bodyText: '<div id="js_verify">去验证</div><p>环境异常</p>',
    httpStatus: 200
  });
  assert.equal(c.code, 'source_verification_required');
});

test('generic structured fallback when no article/main', () => {
  const html = load('generic-no-article.html');
  const extracted = extractCanonicalDocumentFromHtml(html, {
    url: 'https://vendor.example/report',
    finalUrl: 'https://vendor.example/report',
    httpStatus: 200
  });
  assert.equal(extracted.ok, true);
  assert.match(extracted.document.title, /Odd Vendor|Ransomware/i);
  assert.ok(extracted.document.blocks.some((b) => /redirector\.example/.test(b.text)));
});

test('truly empty page fails empty', () => {
  const extracted = extractCanonicalDocumentFromHtml('<html><body><p> </p></body></html>', {
    url: 'https://example.com/empty',
    httpStatus: 200
  });
  assert.equal(extracted.ok, false);
  assert.ok(
    ['document_empty_after_extraction', 'article_not_found', 'document_below_quality_threshold'].includes(
      extracted.code
    )
  );
});

test('navigation-only page fails quality threshold', () => {
  const html = load('nav-only.html');
  const extracted = extractCanonicalDocumentFromHtml(html, {
    url: 'https://example.com/nav',
    httpStatus: 200
  });
  assert.equal(extracted.ok, false);
  assert.ok(
    extracted.code === 'document_below_quality_threshold'
    || extracted.code === 'document_empty_after_extraction'
    || extracted.code === 'empty_document'
  );
});

test('Chinese no-space text passes quality gate', () => {
  const q = assessDocumentQuality({
    title: '测试',
    language: 'zh',
    blocks: [{
      id: 'b001',
      type: 'paragraph',
      text: '这是一段没有空格的中文威胁情报正文内容用于验证字符阈值以及CJK文本在质量门禁中的正确处理方式。'
    }]
  });
  assert.equal(q.ok, true);
  assert.ok(q.chars >= 40);
});

test('encoding: Unicode preserved through Weixin path', () => {
  const html = load('weixin-article.html');
  const doc = htmlToCanonicalDocument(html, {
    url: 'https://mp.weixin.qq.com/s/x',
    finalUrl: 'https://mp.weixin.qq.com/s/x'
  });
  assert.match(doc.blocks.map((b) => b.text).join(''), /木马分析|钓鱼/);
});

test('SSRF policy still rejects private hosts', () => {
  assert.equal(validateThreatLibraryUrl('http://127.0.0.1/x').ok, false);
  assert.equal(validateThreatLibraryUrl('http://10.1.2.3/x').ok, false);
  assert.equal(validateThreatLibraryUrl('https://mp.weixin.qq.com/s/x').ok, true);
});
