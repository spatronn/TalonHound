/**
 * Classify fetched HTML before / during article extraction.
 * Distinguishes verification/blocked shells from empty articles.
 */

/**
 * @param {{ finalUrl?: string|null, bodyText?: string, httpStatus?: number|null }} input
 * @returns {{
 *   kind: 'article_candidate'|'verification_required'|'access_denied'|'blocked'|'js_shell'|'empty_or_minimal',
 *   code: string|null,
 *   message: string|null,
 *   signals: string[]
 * }}
 */
export function classifyFetchedHtmlPage(input = {}) {
  const finalUrl = String(input.finalUrl || '');
  const body = String(input.bodyText || '');
  const status = Number(input.httpStatus) || 0;
  const signals = [];

  if (status === 401 || status === 403) {
    return {
      kind: 'access_denied',
      code: 'source_access_denied',
      message: `Source returned HTTP ${status}; article content is not accessible.`,
      signals: [`http_${status}`]
    };
  }

  const lowerUrl = finalUrl.toLowerCase();
  if (
    lowerUrl.includes('wappoc_appmsgcaptcha')
    || lowerUrl.includes('secitptpage')
    || /[?&]poc_token=/.test(lowerUrl)
  ) {
    signals.push('weixin_captcha_url');
  }

  if (/id=["']js_verify["']/i.test(body)) signals.push('js_verify');
  if (/secitptpage\/verify/i.test(body)) signals.push('secitptpage_verify');
  if (/wappoc_appmsgcaptcha/i.test(body)) signals.push('wappoc_appmsgcaptcha');
  if (/环境异常/.test(body)) signals.push('env_abnormal_zh');
  if (/去验证/.test(body)) signals.push('go_verify_zh');
  if (/完成验证后即可继续访问/.test(body)) signals.push('verify_to_continue_zh');
  if (/weui-msg/i.test(body) && /验证/.test(body)) signals.push('weui_verify_msg');
  if (/captcha|recaptcha|hcaptcha|cf-challenge|attention required|access denied|request blocked/i.test(body)) {
    signals.push('generic_challenge');
  }

  const verificationHits = signals.filter((s) =>
    [
      'weixin_captcha_url',
      'js_verify',
      'secitptpage_verify',
      'wappoc_appmsgcaptcha',
      'env_abnormal_zh',
      'go_verify_zh',
      'verify_to_continue_zh',
      'weui_verify_msg',
      'generic_challenge'
    ].includes(s)
  );

  if (verificationHits.length >= 1 && (
    signals.includes('weixin_captcha_url')
    || signals.includes('js_verify')
    || verificationHits.length >= 2
  )) {
    return {
      kind: 'verification_required',
      code: 'source_verification_required',
      message:
        'Source returned a verification/interstitial page instead of the article. '
        + 'Automatic fetch cannot complete verification. Import a PDF/THIB export, or paste content if available.',
      signals
    };
  }

  // JS-only shells: almost no text-bearing tags, many scripts, no article containers
  const scriptCount = (body.match(/<script\b/gi) || []).length;
  const pCount = (body.match(/<p\b/gi) || []).length;
  const hasContentRoot = /id=["']js_content["']|<article\b|<main\b|rich_media_content/i.test(body);
  const textApprox = body
    .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, '')
    .length;

  if (!hasContentRoot && scriptCount >= 8 && pCount <= 2 && textApprox < 80) {
    signals.push('js_shell_like');
    return {
      kind: 'js_shell',
      code: 'article_not_found',
      message:
        'Fetched page looks like a JavaScript shell without extractable article HTML. '
        + 'Browser rendering is not enabled; try PDF upload or another import path.',
      signals
    };
  }

  if (textApprox < 20 && body.length < 500) {
    return {
      kind: 'empty_or_minimal',
      code: 'document_empty_after_extraction',
      message: 'Fetched page had no extractable article content.',
      signals: [...signals, 'minimal_body']
    };
  }

  return { kind: 'article_candidate', code: null, message: null, signals };
}

/**
 * Host helpers for adapter selection (hostname only — no network).
 * @param {string|null|undefined} url
 */
export function hostnameOf(url) {
  try {
    return new URL(String(url || '')).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function isWeixinHost(hostname) {
  const h = String(hostname || '').toLowerCase();
  return h === 'mp.weixin.qq.com' || h.endsWith('.weixin.qq.com');
}
