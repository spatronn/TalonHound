import { mkdir, writeFile } from 'node:fs/promises';

const BASE_URL = 'http://rules.emergingthreats.net/blockrules/';

function nowStamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}_${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`;
}

function parseLinks(html) {
  const links = [...html.matchAll(/href="\.\/([^"]+)"/g)].map((m) => m[1]);
  return links.filter((name) => /\.(rules|txt)$/i.test(name));
}

function isIPv4(value) {
  const m = value.match(/^(\d{1,3})(?:\.(\d{1,3})){3}$/);
  if (!m) return false;
  return value.split('.').every((x) => Number(x) >= 0 && Number(x) <= 255);
}

function isCIDR(value) {
  const [ip, mask] = value.split('/');
  if (!ip || mask == null) return false;
  return isIPv4(ip) && Number.isInteger(Number(mask)) && Number(mask) >= 0 && Number(mask) <= 32;
}

function extractIPs(text) {
  const found = new Set();
  const ipv4Like = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g) || [];
  for (const token of ipv4Like) {
    if (isIPv4(token) || isCIDR(token)) found.add(token);
  }
  return [...found];
}

function inferCategory(fileName) {
  const f = fileName.toLowerCase();
  if (f.includes('threatview') || f.includes('_c2')) return 'c2';
  if (f.includes('botcc')) return 'botnet-c2';
  if (f.includes('tor')) return 'tor';
  if (f.includes('compromised')) return 'compromised-host';
  if (f.includes('drop')) return 'known-malicious';
  if (f.includes('dshield')) return 'scanner';
  if (f.includes('ciarmy')) return 'bruteforce';
  return 'malicious-ip';
}

function inferConfidence(fileName) {
  const f = fileName.toLowerCase();
  if (f.includes('threatview') || f.includes('high-confidence')) return 'high';
  if (f.includes('drop') || f.includes('compromised') || f.includes('botcc') || f.includes('ciarmy')) return 'high';
  return 'medium';
}

function csvEscape(value) {
  const s = String(value ?? '');
  if (s.includes('"') || s.includes(',') || s.includes('\n')) return `"${s.replaceAll('"', '""')}"`;
  return s;
}

async function main() {
  const indexRes = await fetch(BASE_URL);
  if (!indexRes.ok) throw new Error(`Failed to fetch index: ${indexRes.status}`);
  const indexHtml = await indexRes.text();

  const files = parseLinks(indexHtml);
  const rows = [];
  const dedup = new Set();

  for (const file of files) {
    const url = new URL(file, BASE_URL).toString();
    const res = await fetch(url);
    if (!res.ok) continue;

    const body = await res.text();
    const ips = extractIPs(body);
    const sourceName = `EmergingThreats:${file}`;
    const confidence = inferConfidence(file);
    const category = inferCategory(file);

    for (const ip of ips) {
      const key = `${ip}|${sourceName}`;
      if (dedup.has(key)) continue;
      dedup.add(key);
      rows.push({
        ip,
        source_name: sourceName,
        source_url: url,
        confidence,
        category,
        note: `Auto-imported from ET blockrules (${file})`
      });
    }
  }

  await mkdir('reports', { recursive: true });
  const stamp = nowStamp();
  const jsonPath = `reports/et_blockrules_import_${stamp}.json`;
  const csvPath = `reports/et_blockrules_import_${stamp}.csv`;

  await writeFile(jsonPath, JSON.stringify({ total: rows.length, generated_at: new Date().toISOString(), rows }, null, 2));

  const header = 'ip,source_name,source_url,confidence,category,note\n';
  const csv = rows.map((r) => [r.ip, r.source_name, r.source_url, r.confidence, r.category, r.note].map(csvEscape).join(',')).join('\n');
  await writeFile(csvPath, header + csv + '\n');

  console.log(JSON.stringify({
    ok: true,
    files_scanned: files.length,
    rows_prepared: rows.length,
    json: jsonPath,
    csv: csvPath
  }, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
