#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import dgram from 'node:dgram';

const ENABLED = String(process.env.LOG_FORWARDER_ENABLED || 'true').toLowerCase() !== 'false';
const TARGET_HOST = process.env.SYSLOG_FORWARD_TARGET_HOST || 'syslog-receiver';
const TARGET_PORT = Number(process.env.SYSLOG_FORWARD_TARGET_PORT || 514);
const HOSTNAME = process.env.LOG_FORWARDER_HOSTNAME || 'lab-forwarder';
const START_FROM_BEGINNING = String(process.env.LOG_FORWARDER_START_FROM_BEGINNING || 'false').toLowerCase() === 'true';
const POLL_MS = Math.max(Number(process.env.LOG_FORWARDER_POLL_MS || 1000), 250);

const SOURCES = [
  {
    key: 'bind',
    tag: process.env.LOG_FORWARDER_BIND_TAG || 'bind_dns',
    path: process.env.BIND_LOG_PATH || '/logs/bind-query.log',
  },
  {
    key: 'squid',
    tag: process.env.LOG_FORWARDER_SQUID_TAG || 'squid_proxy',
    path: process.env.SQUID_LOG_PATH || '/logs/squid-access.log',
  }
];

const socket = dgram.createSocket('udp4');
const state = new Map();
const metrics = {
  forwarded_lines_total: 0,
  bind_forwarded_lines: 0,
  squid_forwarded_lines: 0,
  read_errors: 0,
  last_forward_time: null
};

function fmtTs(d = new Date()) {
  const m = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()];
  return `${m} ${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
}

function toSyslog(tag, line) {
  return `<134>${fmtTs()} ${HOSTNAME} ${tag}: ${line}`;
}

function sendLine(src, line) {
  const msg = Buffer.from(toSyslog(src.tag, line));
  socket.send(msg, TARGET_PORT, TARGET_HOST);
  metrics.forwarded_lines_total += 1;
  metrics[`${src.key}_forwarded_lines`] += 1;
  metrics.last_forward_time = new Date().toISOString();
}

function ensureState(src) {
  if (state.has(src.path)) return state.get(src.path);
  state.set(src.path, { offset: 0, ino: null, warnedMissing: false });
  return state.get(src.path);
}

function pollSource(src) {
  const st = ensureState(src);
  let stat;
  try {
    stat = fs.statSync(src.path);
  } catch {
    if (!st.warnedMissing) {
      console.warn(`[lab-log-forwarder] source_missing key=${src.key} path=${src.path}`);
      st.warnedMissing = true;
    }
    return;
  }

  st.warnedMissing = false;

  const rotated = st.ino !== null && st.ino !== stat.ino;
  const truncated = stat.size < st.offset;

  if (st.ino === null || rotated || truncated) {
    st.ino = stat.ino;
    st.offset = START_FROM_BEGINNING ? 0 : stat.size;
    console.log(`[lab-log-forwarder] source_open key=${src.key} path=${src.path} start_offset=${st.offset} rotated=${rotated} truncated=${truncated}`);
  }

  if (stat.size <= st.offset) return;

  const stream = fs.createReadStream(src.path, { encoding: 'utf8', start: st.offset, end: stat.size - 1 });
  let buf = '';
  stream.on('data', (chunk) => { buf += chunk; });
  stream.on('error', (err) => {
    metrics.read_errors += 1;
    console.error(`[lab-log-forwarder] read_error key=${src.key} path=${src.path} err=${err?.message || err}`);
  });
  stream.on('end', () => {
    const lines = buf.split(/\r?\n/).filter(Boolean);
    for (const line of lines) sendLine(src, line);
    st.offset = stat.size;
  });
}

if (!ENABLED) {
  console.log('[lab-log-forwarder] disabled by LOG_FORWARDER_ENABLED=false');
  process.exit(0);
}

console.log(`[lab-log-forwarder] start target=${TARGET_HOST}:${TARGET_PORT} start_from_beginning=${START_FROM_BEGINNING} poll_ms=${POLL_MS}`);
for (const s of SOURCES) console.log(`[lab-log-forwarder] watch key=${s.key} path=${s.path} tag=${s.tag}`);

setInterval(() => {
  for (const src of SOURCES) {
    try { pollSource(src); } catch (err) {
      metrics.read_errors += 1;
      console.error(`[lab-log-forwarder] poll_error key=${src.key} err=${err?.message || err}`);
    }
  }
}, POLL_MS);

setInterval(() => {
  console.log(`[lab-log-forwarder] metrics forwarded_lines_total=${metrics.forwarded_lines_total} bind_forwarded_lines=${metrics.bind_forwarded_lines} squid_forwarded_lines=${metrics.squid_forwarded_lines} read_errors=${metrics.read_errors} last_forward_time=${metrics.last_forward_time || '-'} target=${TARGET_HOST}:${TARGET_PORT}`);
}, 30000);
