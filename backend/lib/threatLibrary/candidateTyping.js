/**
 * Evidence-aware typing for dotted tokens (domain vs file vs code).
 * No vendor/domain allowlists — decisions are syntactic + local context.
 */

/** Common file extensions that often appear in threat reports as artifacts (not TLDs). */
const FILE_EXT_HINT = new Set([
  'exe', 'dll', 'sys', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jse', 'wsf',
  'lnk', 'url', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'pdf',
  'zip', 'rar', '7z', 'gz', 'tar', 'iso', 'img',
  'php', 'asp', 'aspx', 'jsp', 'cgi',
  'txt', 'log', 'dat', 'bin', 'cfg', 'ini', 'xml', 'json', 'csv',
  'enc', 'locked', 'crypt', 'payload', 'tmp', 'temp',
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'svg',
  'apk', 'ipa', 'dmg', 'pkg', 'msi', 'jar', 'class'
]);

/** Very common public suffixes / multi-part TLDs — still not a whitelist of "safe" hosts. */
const MULTI_PART_TLD = new Set([
  'co.uk', 'com.au', 'com.br', 'co.jp', 'co.kr', 'com.cn', 'com.tw', 'com.hk',
  'org.uk', 'net.au', 'gov.uk', 'ac.uk', 'edu.cn'
]);

/**
 * @param {string} token
 */
export function splitDottedToken(token) {
  return String(token || '')
    .toLowerCase()
    .replace(/^\.+|\.+$/g, '')
    .split('.')
    .filter(Boolean);
}

/**
 * @param {string} token
 * @param {{ surroundingText?: string, urlPathBasenames?: Set<string>, knownUrlHosts?: Set<string> }} [ctx]
 * @returns {{ kind: 'domain'|'file_artifact'|'code_identifier'|'skip', reason: string }}
 */
export function resolveDottedTokenType(token, ctx = {}) {
  const raw = String(token || '').trim();
  const lower = raw.toLowerCase();
  const parts = splitDottedToken(lower);
  if (parts.length < 2) return { kind: 'skip', reason: 'not_dotted' };

  const surrounding = String(ctx.surroundingText || '');
  const basenames = ctx.urlPathBasenames || new Set();
  const hosts = ctx.knownUrlHosts || new Set();

  if (basenames.has(lower)) {
    return { kind: 'file_artifact', reason: 'url_path_basename' };
  }

  // Exact host from a parsed URL → domain
  if (hosts.has(lower)) {
    return { kind: 'domain', reason: 'url_host' };
  }

  const last = parts[parts.length - 1];
  const multiTld = parts.length >= 3 ? `${parts[parts.length - 2]}.${last}` : '';

  // Code / method identifiers: Program.Main, loader.Program.Main, Namespace.Class.Method
  const looksLikeCode =
    /\b(program|loader|namespace|class|method|function|main|init|start)\b/i.test(parts.join('.')) ||
    (/^[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)+$/.test(raw) &&
      parts.every((p) => /[A-Za-z]/.test(p) && !FILE_EXT_HINT.has(p) && p.length <= 40) &&
      !MULTI_PART_TLD.has(multiTld) &&
      last.length <= 12 &&
      !/^(com|net|org|io|co|info|biz|edu|gov|mil|cn|ru|de|uk|fr|jp|kr|tr|xyz|top|site|online)$/i.test(last));

  // Stronger code signal: CamelCase segments or trailing Main/Init
  const camelParts = raw.split('.').filter(Boolean);
  const hasCamel = camelParts.some((p) => /^[A-Z][a-z]+[A-Z]/.test(p) || p === 'Main' || p === 'Program');
  const codeContext = /\b(\.NET|C#|Java|class\s|namespace\s|method\s|函数|类\s|反编译)/i.test(surrounding);

  if ((hasCamel && parts.length >= 2 && FILE_EXT_HINT.has(last) === false && last.length <= 8 && !isLikelyPublicSuffix(last, multiTld)) ||
      (looksLikeCode && (codeContext || hasCamel || /\.(main|init|start|run|load)$/i.test(lower)))) {
    // Avoid treating real domains like Evil.Main.com — require no known TLD-ish last OR code context
    if (!isLikelyPublicSuffix(last, multiTld) || codeContext || hasCamel) {
      if (!isLikelyPublicSuffix(last, multiTld) || hasCamel || codeContext) {
        return { kind: 'code_identifier', reason: hasCamel ? 'camel_method' : 'code_context' };
      }
    }
  }

  // Filename / artifact: extension hint + (context OR multi-dot payload-like OR basename)
  if (FILE_EXT_HINT.has(last)) {
    const fileLabel = /(file\s*name|filename|file\s*:|资源|文件名|样本|payload|download|保存|lnk|resource)/i.test(surrounding);
    const multiDotArtifact = parts.length >= 3; // OrionSetup.payload.enc
    const shortBasename = parts.length === 2 && parts[0].length <= 32;
    if (fileLabel || multiDotArtifact || basenames.has(lower) || shortBasename) {
      // Exception: real hostnames like foo.php.com are rare; if last is php/txt/enc/lnk treat as file when not a known multi-part host form
      if (!MULTI_PART_TLD.has(multiTld)) {
        return { kind: 'file_artifact', reason: fileLabel ? 'file_label' : multiDotArtifact ? 'multi_dot_ext' : 'file_extension' };
      }
    }
  }

  // Reject tokens with no alphabetic TLD-like last label that is a file ext without domain evidence
  if (FILE_EXT_HINT.has(last) && !hosts.has(lower) && !/\b(domain|host|server|dns|c2|url|http)\b/i.test(surrounding)) {
    return { kind: 'file_artifact', reason: 'extension_without_host_context' };
  }

  // Default: treat as domain candidate when it looks hostname-like
  if (isLikelyPublicSuffix(last, multiTld) || last.length >= 2) {
    // Still reject pure code-like two-label forms with non-TLD last (e.g. program.main)
    if (parts.length === 2 && !isLikelyPublicSuffix(last, multiTld) && /^(main|init|start|load|run|test|config)$/i.test(last)) {
      return { kind: 'code_identifier', reason: 'method_suffix' };
    }
    return { kind: 'domain', reason: 'hostname_shape' };
  }

  return { kind: 'skip', reason: 'unresolved' };
}

/**
 * @param {string} last
 * @param {string} multiTld
 */
function isLikelyPublicSuffix(last, multiTld) {
  if (MULTI_PART_TLD.has(multiTld)) return true;
  // Common gTLD / ccTLD shapes — not a safety allowlist, only syntax for "looks like DNS"
  return /^(com|net|org|io|co|info|biz|edu|gov|mil|app|dev|cloud|xyz|top|site|online|tech|store|shop|club|pro|tv|me|cc|cn|ru|de|uk|fr|jp|kr|tr|us|br|in|au|ca|nl|eu|ai|gg|to|pw|su|tk|ml|ga|cf|gq)$/i.test(
    last
  );
}

/**
 * Extract hostname from URL string.
 * @param {string} url
 */
export function hostnameFromUrl(url) {
  try {
    const u = new URL(String(url));
    return (u.hostname || '').toLowerCase().replace(/\.$/, '');
  } catch {
    const m = String(url).match(/^https?:\/\/([^\/?#:]+)/i);
    return m ? m[1].toLowerCase() : '';
  }
}

/**
 * Path basename from URL.
 * @param {string} url
 */
export function pathBasenameFromUrl(url) {
  try {
    const u = new URL(String(url));
    const parts = u.pathname.split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1].toLowerCase() : '';
  } catch {
    const path = String(url).split(/[?#]/)[0];
    const parts = path.split('/').filter(Boolean);
    const last = parts[parts.length - 1] || '';
    return last.includes('.') ? last.toLowerCase() : '';
  }
}
