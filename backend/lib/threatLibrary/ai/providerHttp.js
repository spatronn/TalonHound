/**
 * Provider HTTP transport for Threat Library AI calls.
 *
 * Node's global fetch (undici) applies its own 300s headersTimeout and
 * bodyTimeout, independent of the Threat Library timeout policy: a header wait
 * longer than 300s fails as "fetch failed" no matter what the settings say.
 * This transport uses node:http(s) directly, so the only timeouts are the ones
 * client.js enforces, and every cancellation destroys the socket — the
 * provider sees the connection close and drops the request (Ollama cancels
 * work for a closed client connection).
 *
 * A transport is `(url, init) => { response, closed }`:
 *  - response: Promise of a fetch-like `{ ok, status, body: ReadableStream, text() }`
 *  - closed:   Promise that settles once the underlying socket is released
 *  - sent():   true once the request was written to the connection (the
 *              provider may be executing it); false for connect failures
 * `init` = { method, headers, body, signal, connectTimeoutMs }.
 */

import http from 'node:http';
import https from 'node:https';
import { Readable } from 'node:stream';
import { AI_FAILURE_CODES, aiFailure } from './timeouts.js';

/**
 * @param {string} url
 * @param {{ method?: string, headers?: object, body?: string, signal?: AbortSignal, connectTimeoutMs?: number }} init
 */
export function nodeHttpTransport(url, init = {}) {
  const target = new URL(url);
  const mod = target.protocol === 'https:' ? https : http;
  const payload = init.body == null ? '' : String(init.body);
  let req;
  let written = false;
  let settleClosed;
  const closed = new Promise((resolve) => {
    settleClosed = resolve;
  });

  const response = new Promise((resolve, reject) => {
    if (init.signal?.aborted) {
      settleClosed('not_started');
      reject(init.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED));
      return;
    }
    req = mod.request({
      method: init.method || 'POST',
      protocol: target.protocol,
      hostname: target.hostname.replace(/^\[|\]$/g, ''),
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      headers: {
        ...(init.headers || {}),
        'content-length': Buffer.byteLength(payload)
      },
      // One connection per call: nothing is pooled, so destroying the socket
      // on cancellation can never affect another request.
      agent: false
    });

    let connectTimer = null;
    const clearConnectTimer = () => {
      if (connectTimer) clearTimeout(connectTimer);
      connectTimer = null;
    };
    req.once('socket', (socket) => {
      const connectEvent = mod === https ? 'secureConnect' : 'connect';
      if (socket.connecting) {
        const ms = Number(init.connectTimeoutMs) || 0;
        if (ms > 0) {
          connectTimer = setTimeout(() => req.destroy(aiFailure(AI_FAILURE_CODES.CONNECTION_TIMEOUT)), ms);
        }
        socket.once(connectEvent, clearConnectTimer);
      }
    });
    req.once('finish', () => {
      written = true;
    });
    req.once('close', () => {
      clearConnectTimer();
      settleClosed('closed');
    });

    const onAbort = () => req.destroy(init.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED));
    init.signal?.addEventListener('abort', onAbort, { once: true });
    req.once('close', () => init.signal?.removeEventListener('abort', onAbort));

    req.once('error', (err) => {
      clearConnectTimer();
      reject(err);
    });
    req.once('response', (res) => {
      clearConnectTimer();
      const status = Number(res.statusCode) || 0;
      resolve({
        ok: status >= 200 && status < 300,
        status,
        headers: res.headers,
        body: Readable.toWeb(res),
        async text() {
          const parts = [];
          for await (const part of res) parts.push(Buffer.from(part));
          return Buffer.concat(parts).toString('utf8');
        }
      });
    });
    req.end(payload);
  });

  return { response, closed, sent: () => written };
}

/**
 * Adapt a fetch-style function (tests, alternative clients) to the transport
 * contract. `closed` settles when the response promise does; a fetch stub has
 * no socket to observe.
 * @param {(url: string, init: object) => Promise<object>} fetchFn
 */
export function fetchTransport(fetchFn) {
  return (url, init = {}) => {
    const response = Promise.resolve().then(() =>
      fetchFn(url, {
        method: init.method || 'POST',
        headers: init.headers,
        body: init.body,
        signal: init.signal
      })
    );
    const closed = response.then(
      () => 'closed',
      () => 'closed'
    );
    // A fetch stub cannot tell; assume the request reached the provider.
    return { response, closed, sent: () => true };
  };
}
