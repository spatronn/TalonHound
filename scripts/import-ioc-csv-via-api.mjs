import { readFile } from 'node:fs/promises';

const csvPath = process.argv[2];
const apiBase = process.argv[3] || 'http://localhost/api';

if (!csvPath) {
  console.error('Usage: node scripts/import-ioc-csv-via-api.mjs <csvPath> [apiBase]');
  process.exit(1);
}

function parseCsvLine(line) {
  const out = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inQ) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i += 1;
      } else if (ch === '"') {
        inQ = false;
      } else {
        cur += ch;
      }
    } else if (ch === ',') {
      out.push(cur);
      cur = '';
    } else if (ch === '"') {
      inQ = true;
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

async function main() {
  const content = await readFile(csvPath, 'utf8');
  const lines = content.trim().split(/\r?\n/);
  const headers = parseCsvLine(lines[0]);
  const idx = Object.fromEntries(headers.map((h, i) => [h, i]));

  let ok = 0;
  let fail = 0;

  for (let i = 1; i < lines.length; i += 1) {
    const cols = parseCsvLine(lines[i]);
    const body = {
      ip: cols[idx.ip],
      source_name: cols[idx.source_name],
      source_url: cols[idx.source_url],
      confidence: cols[idx.confidence],
      category: cols[idx.category],
      note: cols[idx.note]
    };

    try {
      const res = await fetch(`${apiBase}/ioc/ip`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (!res.ok) {
        fail += 1;
      } else {
        ok += 1;
      }
    } catch {
      fail += 1;
    }

    if (i % 1000 === 0) {
      console.log(`processed=${i} ok=${ok} fail=${fail}`);
    }
  }

  console.log(JSON.stringify({ ok, fail, total: ok + fail }, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
