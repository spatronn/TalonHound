#!/usr/bin/env node
/**
 * Build / extend a PRIVATE benchmark source store for the committed
 * real-report labels (lib/threatLibrary/benchmark/real-reports).
 *
 *   node scripts/threat-library-benchmark-sources.js <store-dir> <retained source file>...
 *
 * HTML is copied as <sha256>.html (the runner re-hashes it). A PDF is stored as
 * <sha256-of-the-PDF>.canonical.json: the production ingester's canonical
 * document (pdfToCanonicalDocument), because the runner is synchronous; the
 * PDF bytes are hashed so the label still names the original file.
 *
 * The store holds publisher content and must stay outside the repository
 * (CI reads it from a secret mount via TL_BENCHMARK_SOURCE_DIR). Nothing is
 * fetched from the network.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pdfToCanonicalDocument, THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } from '../lib/threatLibrary/pdfIngest.js';

const [storeDir, ...files] = process.argv.slice(2);
if (!storeDir || !files.length) {
  console.log('usage: node scripts/threat-library-benchmark-sources.js <store-dir> <retained source file>...');
  process.exit(storeDir ? 1 : 0);
}
const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1')), '..', '..');
if (path.resolve(storeDir).startsWith(repoRoot + path.sep)) {
  console.error('refusing to write a source store inside the repository');
  process.exit(1);
}
fs.mkdirSync(storeDir, { recursive: true });
for (const file of files) {
  const raw = fs.readFileSync(file);
  const sha256 = crypto.createHash('sha256').update(raw).digest('hex');
  if (/\.pdf$/i.test(file) || raw.subarray(0, 5).toString('latin1') === '%PDF-') {
    const r = await pdfToCanonicalDocument(raw, { fileName: path.basename(file) });
    const document = r.document || r;
    fs.writeFileSync(
      path.join(storeDir, `${sha256}.canonical.json`),
      JSON.stringify({ source_sha256: sha256, extractor: THREAT_LIBRARY_PDF_EXTRACTOR_VERSION, document })
    );
    console.log(`${sha256}  pdf_canonical  ${path.basename(file)}`);
  } else {
    fs.writeFileSync(path.join(storeDir, `${sha256}.html`), raw);
    console.log(`${sha256}  html           ${path.basename(file)}`);
  }
}
