/**
 * Mock Ollama /api/chat server for Threat Library AI tests (real HTTP).
 *
 * Models the behaviour measured on the production Ollama host:
 *  - `capacity` requests execute at once (production: 1); the rest wait in
 *    an internal FIFO queue;
 *  - HTTP headers are withheld until the request is executing AND its prompt
 *    evaluation is done (headers arrive with the first token);
 *  - the reply streams as NDJSON chunks, the final line carries Ollama's
 *    duration metrics (ns): total_duration includes the internal queue wait;
 *  - a client disconnect cancels the request, queued or executing, and frees
 *    its slot (what Ollama does for a closed connection).
 *
 * Per-request behaviour comes from `plan(request)`, which may return
 * { promptEvalMs, genMs, content, chunks, fault } where fault is one of
 * 'hang_headers' | 'stall_after_first' | 'disconnect_mid_stream' | 'http_503',
 * and `ignoreCancel: true` to model a provider that keeps executing after the
 * client disconnects (lost FIN / provider bug): the request holds its
 * execution slot until it finishes on its own.
 */

import http from 'node:http';

const DEFAULT_CONTENT = JSON.stringify({ summary: 'ok', entities: [], candidate_updates: [], relationships: [] });

const sleep = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms)));

/**
 * @param {{ capacity?: number, plan?: (req: object) => object }} [options]
 */
export async function startMockOllama(options = {}) {
  const capacity = Math.max(1, options.capacity || 1);
  const plan = options.plan || (() => ({}));
  const queue = [];
  let executing = 0;
  let maxExecuting = 0;
  let maxQueued = 0;
  let seq = 0;
  const requests = [];

  const pump = () => {
    while (executing < capacity && queue.length) {
      const job = queue.shift();
      if (job.cancelled) continue;
      executing += 1;
      maxExecuting = Math.max(maxExecuting, executing);
      job.run().finally(() => {
        executing -= 1;
        pump();
      });
    }
  };

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        body = {};
      }
      const record = {
        id: (seq += 1),
        user: body?.messages?.find?.((m) => m.role === 'user')?.content || '',
        receivedAt: Date.now(),
        startedAt: null,
        headersAt: null,
        endedAt: null,
        clientClosedEarly: false,
        clientClosedAt: null,
        outcome: 'queued'
      };
      requests.push(record);
      const p = { promptEvalMs: 20, genMs: 50, chunks: 4, content: DEFAULT_CONTENT, ...(plan(record, body) || {}) };
      let finished = false;
      const write = (chunk) => {
        if (!res.destroyed && !res.writableEnded) res.write(chunk);
      };
      const job = {
        cancelled: false,
        async run() {
          if (job.cancelled) return;
          record.startedAt = Date.now();
          record.outcome = 'executing';
          if (p.fault === 'hang_headers') {
            // Never respond; the slot is held until the client disconnects.
            await new Promise((resolve) => res.once('close', resolve));
            return;
          }
          await sleep(p.promptEvalMs);
          if (job.cancelled) return;
          if (p.fault === 'http_503') {
            res.writeHead(503, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'server busy, please try again' }));
            finished = true;
            record.endedAt = Date.now();
            record.outcome = 'http_503';
            return;
          }
          if (!res.destroyed) res.writeHead(200, { 'content-type': 'application/x-ndjson' });
          record.headersAt = Date.now();
          const content = String(p.content);
          const n = Math.max(1, p.chunks);
          const size = Math.ceil(content.length / n);
          const evalStart = Date.now();
          for (let i = 0; i < n; i += 1) {
            if (job.cancelled) return;
            write(`${JSON.stringify({ message: { content: content.slice(i * size, (i + 1) * size) }, done: false })}\n`);
            if (i === 0 && p.fault === 'stall_after_first') {
              await new Promise((resolve) => res.once('close', resolve));
              return;
            }
            if (i === 0 && p.fault === 'disconnect_mid_stream') {
              await sleep(5);
              res.socket?.destroy();
              record.outcome = 'server_disconnected';
              return;
            }
            await sleep(p.genMs / n);
          }
          if (job.cancelled) return;
          const now = Date.now();
          if (res.destroyed) {
            finished = true;
            record.endedAt = now;
            record.outcome = 'completed_after_client_left';
            return;
          }
          res.end(
            `${JSON.stringify({
              message: { content: '' },
              done: true,
              done_reason: 'stop',
              prompt_eval_count: 1000,
              eval_count: 100,
              total_duration: (now - record.receivedAt) * 1e6,
              load_duration: 0,
              prompt_eval_duration: p.promptEvalMs * 1e6,
              eval_duration: (now - evalStart) * 1e6
            })}\n`
          );
          finished = true;
          record.endedAt = now;
          record.outcome = 'completed';
        }
      };
      res.once('close', () => {
        if (!finished && p.ignoreCancel) {
          record.clientClosedEarly = true;
          record.clientClosedAt = Date.now();
          return; // keeps executing (or stays queued) regardless
        }
        if (!finished) {
          job.cancelled = true;
          record.clientClosedEarly = true;
          record.clientClosedAt = Date.now();
          if (record.outcome === 'queued') record.outcome = 'cancelled_in_queue';
          else if (record.outcome === 'executing') record.outcome = 'cancelled_executing';
        }
      });
      queue.push(job);
      pump();
      maxQueued = Math.max(maxQueued, queue.filter((j) => !j.cancelled).length);
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    requests,
    stats: () => ({ maxExecuting, maxQueued, executing, queued: queue.filter((j) => !j.cancelled).length }),
    async close() {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    }
  };
}
