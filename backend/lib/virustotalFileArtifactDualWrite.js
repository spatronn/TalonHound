/**
 * VirusTotal enrichment → file-artifact dual-write (attach the VT exact hash set
 * to the IOC's file artifact). Best-effort: never fails the enrichment response,
 * never silent; failures are logged once per call without hashes or the VT raw
 * response.
 */
import { createServiceLogger } from './appLogger.js';
import { runBestEffortFileArtifactDualWrite } from './fileArtifactDualWriteDiagnostics.js';

const vtLog = createServiceLogger('backend');
const loadFileArtifacts = () => import('./fileArtifacts/index.js');

/**
 * @param {import('pg').Pool} pool
 * @param {{ iocId: number, iocType: string, observable: string, raw: any }} input
 * @param {{ loadFileArtifacts?: () => Promise<any>, logger?: { warn: Function } }} [deps]
 * @returns {Promise<{ ok: boolean, result?: any }>} never rejects
 */
export async function dualWriteVirusTotalFileArtifact(pool, { iocId, iocType, observable, raw }, deps = {}) {
  const attr = raw?.data?.attributes || {};
  return runBestEffortFileArtifactDualWrite({
    run: async () => {
      const {
        dualWriteFileArtifactForObservable,
        extractExactHashesFromVtRaw,
        isFileArtifactsDualWriteEnabled
      } = await (deps.loadFileArtifacts || loadFileArtifacts)();
      if (!isFileArtifactsDualWriteEnabled() || extractExactHashesFromVtRaw(raw).length < 1) {
        return { skipped: true };
      }
      const noteParts = [];
      if (attr.md5) noteParts.push(`md5=${String(attr.md5).toLowerCase()}`);
      if (attr.sha1) noteParts.push(`sha1=${String(attr.sha1).toLowerCase()}`);
      if (attr.sha256) noteParts.push(`sha256=${String(attr.sha256).toLowerCase()}`);
      return dualWriteFileArtifactForObservable(pool, {
        observable,
        observableType: iocType === 'hash'
          ? (attr.sha256 ? 'sha256' : (attr.sha1 ? 'sha1' : 'md5'))
          : iocType,
        sourceName: 'VirusTotal',
        note: noteParts.join(' | '),
        attachNoteSiblings: true,
        providerMapping: true,
        observationType: 'enrichment_derived',
        relationMethod: 'enrichment_result'
      });
    },
    logger: deps.logger || vtLog,
    fields: {
      component: 'virustotal_enrichment',
      source: 'virustotal',
      ioc_id: String(iocId),
      observable_type: iocType
    },
    redactValues: [observable, attr.md5, attr.sha1, attr.sha256]
  });
}
