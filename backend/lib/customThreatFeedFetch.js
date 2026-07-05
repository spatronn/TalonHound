import { validateFeedUrl } from './customThreatFeedUtils.js';
import { buildCustomFeedAuthHeaders } from './customThreatFeedAuth.js';

export const DEFAULT_MAX_FETCH_BYTES = Math.max(
  Number(process.env.CUSTOM_FEED_MAX_FETCH_BYTES || 52_428_800),
  1024
);

export async function fetchFeedUrl(url, options = {}) {
  const check = validateFeedUrl(url);
  if (!check.ok) {
    const err = new Error(check.error);
    err.code = 'invalid_url';
    throw err;
  }

  const timeoutMs = Math.max(Number(options.timeoutMs || 30000), 1000);
  const maxBytes = Math.max(Number(options.maxBytes || DEFAULT_MAX_FETCH_BYTES), 1024);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const authHeaders = buildCustomFeedAuthHeaders(options.credentials || null);

  try {
    const res = await fetch(check.url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        ...authHeaders,
        Accept: 'text/plain,text/csv,*/*',
        'User-Agent': 'demo-runbook-custom-threat-feed/1.0'
      }
    });

    const redirectUrl = res.url || check.url;
    const redirectCheck = validateFeedUrl(redirectUrl);
    if (!redirectCheck.ok) {
      const err = new Error('Redirect target URL is not allowed');
      err.code = 'redirect_blocked';
      throw err;
    }

    const contentType = res.headers.get('content-type') || '';
    const reader = res.body?.getReader?.();
    let bodyText = '';
    let fetchedBytes = 0;

    if (reader) {
      const decoder = new TextDecoder('utf-8', { fatal: false });
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        fetchedBytes += value.byteLength;
        if (fetchedBytes > maxBytes) {
          const err = new Error(`Response exceeds maximum size (${maxBytes} bytes)`);
          err.code = 'response_too_large';
          throw err;
        }
        bodyText += decoder.decode(value, { stream: true });
      }
      bodyText += decoder.decode();
    } else {
      const buf = Buffer.from(await res.arrayBuffer());
      fetchedBytes = buf.byteLength;
      if (fetchedBytes > maxBytes) {
        const err = new Error(`Response exceeds maximum size (${maxBytes} bytes)`);
        err.code = 'response_too_large';
        throw err;
      }
      bodyText = buf.toString('utf-8');
    }

    return {
      ok: res.ok,
      httpStatus: res.status,
      contentType,
      bodyText,
      fetchedBytes,
      finalUrl: redirectCheck.url
    };
  } catch (err) {
    if (err?.name === 'AbortError') {
      const timeoutErr = new Error(`Fetch timed out after ${timeoutMs}ms`);
      timeoutErr.code = 'timeout';
      throw timeoutErr;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
