/**
 * Central observable-type resolver for Threat Library candidates.
 *
 * A string that merely looks domain-like or URL-like is not a network IOC.
 * Every syntactic guess ("has dots", "has a slash") passes through this module
 * before it can become a reviewable candidate:
 *
 *   raw occurrence → syntactic guess → context-aware type resolver
 *                  → canonical value validator → evidence / promotion gate
 *
 * The resolver separates NETWORK OBSERVABLES (hostname, absolute URL) from
 * TECHNICAL ARTIFACTS (mutex / single-instance names, class / namespace /
 * method identifiers, configuration keys, registry paths, relative paths and
 * routes, command syntax, filenames). Decisions come from three inputs only:
 *
 *   1. canonical syntax      — hostname-compatible labels, absolute URL shape
 *   2. source semantics      — the type label / heading / clause the value sits in
 *   3. provenance            — table row, indicator list row, code block, zone
 *
 * There is deliberately no allowlist of known-good domains, no vendor logic
 * and no per-report rule. Public-suffix knowledge is a *signal* about syntax
 * ("looks like DNS"), never the sole rule: internal hostnames with unusual
 * suffixes still promote when the source asserts network semantics.
 *
 * Label / clause hints are multilingual optimisations (EN / TR / DE / ES / RU /
 * ZH); structure (typed table rows, indicator lists) works for any language.
 */

import { refangObservable } from './defang.js';
import { isValidIpAddress } from '../publicIp.js';

/** Bump when typing / promotion semantics change (feeds the candidate contract). */
export const OBSERVABLE_TYPE_RESOLVER_VERSION = 'tl-type-resolver-v1';

export const RESOLVED_TYPES = Object.freeze({
  DOMAIN: 'domain',
  URL: 'url',
  TECHNICAL_ARTIFACT: 'technical_artifact',
  CODE_IDENTIFIER: 'code_identifier',
  FILE_ARTIFACT: 'file_artifact',
  RELATIVE_PATH: 'relative_path',
  FILE_PATH: 'file_path'
});

/** Resolved types that are never network IOCs (kept as report context only). */
export const NON_NETWORK_RESOLVED_TYPES = Object.freeze(
  new Set([
    RESOLVED_TYPES.TECHNICAL_ARTIFACT,
    RESOLVED_TYPES.CODE_IDENTIFIER,
    RESOLVED_TYPES.FILE_ARTIFACT,
    RESOLVED_TYPES.RELATIVE_PATH,
    RESOLVED_TYPES.FILE_PATH
  ])
);

/** Candidate types that can be reviewed / matched / created as IOC records. */
export const NETWORK_IOC_TYPES = Object.freeze(new Set(['ip', 'ipv6', 'cidr', 'domain', 'url', 'md5', 'sha1', 'sha256']));

/**
 * @param {string} type
 */
export function isNonNetworkResolvedType(type) {
  return NON_NETWORK_RESOLVED_TYPES.has(String(type || ''));
}

// ---------------------------------------------------------------------------
// Label semantics (type cells, headings, inline labels)
// ---------------------------------------------------------------------------

/**
 * Artifact label families. A label that names one of these tells us the value
 * is a host/code artifact, whatever it looks like syntactically.
 */
const ARTIFACT_LABEL_FAMILIES = Object.freeze([
  {
    kind: 'mutex',
    re: /(?<![a-z0-9])(?:mutex(?:es)?|mutant|muteks|semaphore|single[\s-]?instance|singleinstance|instance\s*(?:name|marker|identifier|id)|互斥(?:体|量|锁)?|信号量|мьютекс|мутекс|семафор)(?![a-z0-9])/i
  },
  {
    kind: 'code',
    re: /(?<![a-z0-9])(?:class(?:es)?|classname|namespace|method|function|assembly|module|package|symbol|export|import|type\s*name|entry\s*point|entrypoint|sınıf|isim\s*alanı|metot|fonksiyon|modül|paket|klasse|methode|funktion|modul|paket|clase|método|metodo|función|funcion|módulo|modulo|paquete|класс|метод|функци[яи]|модул[ья]|пакет|类名?|命名空间|方法|函数|模块|包名)(?![a-z0-9])/i
  },
  {
    kind: 'config',
    re: /(?<![a-z0-9])(?:config(?:uration)?(?:\s*(?:key|block|value|entry|field))?|setting(?:s)?|property|properties|parameter(?:s)?|option(?:s)?|flag(?:s)?|key\s*name|field(?:s)?|attribute(?:s)?|yapılandırma|ayar(?:lar|ı)?|parametre|özellik|konfiguration|einstellung(?:en)?|configuración|configuracion|ajuste(?:s)?|parámetro|parametro|propiedad|конфигурац[а-я]*|настройк[а-я]*|параметр[а-я]*|свойств[а-я]*|配置(?:项|键|文件)?|参数|属性|设置)(?![a-z0-9])/i
  },
  {
    kind: 'registry',
    re: /(?<![a-z0-9])(?:registry(?:\s*(?:key|value|path))?|reg\s*key|hkcu|hklm|hkey_[a-z_]+|kayıt\s*defteri|registrierung(?:sschlüssel)?|注册表(?:项|键)?|реестр[а-я]*|registro)(?![a-z0-9])/i
  },
  {
    kind: 'file',
    re: /(?<![a-z0-9])(?:file\s*name(?:s)?|filename(?:s)?|file(?:s)?|dropped\s*file(?:s)?|resource(?:s)?|pe\s*resource|pdb(?:\s*path)?|artifact(?:s)?|artefact(?:s)?|dosya(?:\s*adı|\s*adi)?|kaynak|datei(?:name)?|ressource|archivo|fichero|recurso|файл[а-я]*|ресурс[а-я]*|文件(?:名)?|资源)(?![a-z0-9])/i
  },
  {
    kind: 'path',
    re: /(?<![a-z0-9])(?:path(?:s)?|route(?:s)?|uri\s*path|url\s*path|request\s*path|directory|directories|folder(?:s)?|yol(?:u)?|dizin|pfad|verzeichnis|ruta|directorio|путь|пути|каталог|路径|目录)(?![a-z0-9])/i
  },
  {
    kind: 'command',
    re: /(?<![a-z0-9])(?:command(?:s)?|cmd|command\s*line|commandline|script(?:s)?|powershell|shell|one-?liner|komut(?:u|lar)?|befehl(?:e)?|comando(?:s)?|команд[аы]|命令(?:行)?|脚本)(?![a-z0-9])/i
  },
  {
    kind: 'process',
    re: /(?<![a-z0-9])(?:process(?:es)?(?:\s*name)?|service(?:\s*name)?|scheduled\s*task|task(?:\s*name)?|named\s*pipe|pipe(?:\s*name)?|event(?:\s*name)?|window\s*title|user[\s-]?agent|süreç|servis|görev|prozess|dienst|aufgabe|proceso|servicio|tarea|процесс[а-я]*|служб[а-я]*|задач[а-я]*|канал|进程|服务|任务|管道)(?![a-z0-9])/i
  },
  {
    kind: 'metadata',
    re: /(?<![a-z0-9])(?:version(?:s)?|product(?:\s*name)?|company(?:\s*name)?|metadata|pe\s*metadata|compile(?:r|d)?(?:\s*time)?|signature|certificate|thumbprint|serial|port(?:s)?|protocol|mime|magic|string(?:s)?|marker|identifier|id|sürüm|ürün|şirket|imza|sertifika|protokol|ver(?:sion)?|firma|zertifikat|versión|version|empresa|firma|certificado|верси[яи]|подпис[ьи]|сертификат|版本|公司|签名|证书|端口|协议|字符串)(?![a-z0-9])/i
  }
]);

/**
 * Network label nouns — a type cell / heading / inline label that names a
 * network observable is positive evidence, regardless of value shape.
 */
const NETWORK_LABEL_RE =
  /(?:^|\b)(?:domain(?:s)?|domain\s*name(?:s)?|hostname(?:s)?|host\s*name(?:s)?|fqdn(?:s)?|host(?:s)?|server(?:s)?|c2|c&c|c\s*&\s*c|command\s*(?:and|&)\s*control|dns|url(?:s)?|uri|ip(?:v4|v6)?(?:\s*address(?:es)?)?|address(?:es)?|endpoint(?:s)?|beacon(?:s)?|callback|panel|infrastructure|alan\s*ad[ıi]|sunucu|ana\s*bilgisayar|adres|domäne|dominio|servidor|anfitrión|dirección|домен(?:ы)?|хост|сервер|адрес|域名|主机(?:名)?|服务器|回连(?:地址)?|地址|网址|链接)(?:\b|$)/i;

/**
 * Network relation stated right at the token ("connects to X", "resolves to
 * X", "domain X", "C2 server X", "hosted on X"). Multilingual optimisation.
 */
const NETWORK_RELATION_BEFORE_RE =
  /(?:connect(?:s|ed|ing)?\s+(?:back\s+)?to|communicat(?:es|ed|ing)\s+with|beacon(?:s|ed|ing)?\s+to|resolv(?:es|ed|ing)?\s+to|resolving\s+to|reach(?:es|ed|ing)?\s+out\s+to|call(?:s|ed|ing)?\s+(?:back\s+)?(?:to|home\s+to)|check(?:s|ed|ing)?\s+in\s+(?:to|with)|download(?:s|ed|ing)?\s+from|served\s+from|fetch(?:es|ed|ing)?\s+from|retriev(?:es|ed|ing)\s+from|hosted\s+(?:on|at)|hosting\s+(?:on|at)|sent\s+to|exfiltrat(?:es|ed|ing)\s+to|post(?:s|ed|ing)?\s+to|queries|query|lookup\s+(?:of|for)|nslookup|ping(?:s|ed)?|the\s+(?:c2|c&c|command[\s-]and[\s-]control|malicious|attacker[\s-]controlled|phishing|payload|staging|distribution|callback|beacon|dns|hosting)\s+(?:domain|host|hostname|server|url|panel|site|address|endpoint|infrastructure)|(?:domain|hostname|host\s*name|fqdn|server|c2|c&c|dns\s*name|url|endpoint)(?:\s*name)?|bağlan(?:ır|an|dı|ıyor)|iletişim\s+kurar|çözümlen(?:ir|en)|indir(?:ir|ilen|di)|alan\s*ad[ıi]|sunucu(?:su|ya)?|verbindet\s+sich\s+mit|kommuniziert\s+mit|se\s+conecta\s+a|resuelve\s+a|descarga(?:do)?\s+de(?:sde)?|dominio|servidor|подключа[её]тся\s+к|соединя[её]тся\s+с|обращается\s+к|загружа[её]т(?:ся)?\s+с|домен|сервер|连接(?:到|至)?|回连|通信|解析(?:到|为)?|下载|域名|服务器|主机)\s*[:：,\-–—]?\s*["'“‘`(\[]?\s*$/i;

/** Network vocabulary anywhere in the clause (weaker than a direct relation). */
const NETWORK_CLAUSE_RE =
  /(?:\bconnect|\bcommunicat|\bbeacon|\bresolv|\bc2\b|\bc&c\b|command\s*(?:and|&)\s*control|\bcallback\b|\bdomain\b|\bhostname\b|\bfqdn\b|\bdns\b|\burl\b|\bhttps?\b|\bdownload|\bserved\s+from|\bhosted\b|\bnslookup\b|\bserver\b|\bc2\s*server|bağlan|alan\s*ad[ıi]|sunucu|çözümle|indir|domäne|dominio|servidor|resuelve|descarga|подключ|соедин|домен|сервер|разреш|скач|域名|连接|回连|解析|服务器|下载|主机)/i;

/**
 * Artifact vocabulary directly before the token ("named mutex X", "mutex: X",
 * "class X", "config key X", "the setting X").
 */
const ARTIFACT_LABEL_BEFORE_RE =
  /(?:mutex(?:es)?|mutant|muteks|semaphore|single[\s-]?instance(?:\s+(?:identifier|marker|name|check|lock))?|instance\s+(?:name|marker|identifier)|class(?:name)?|namespace|method|function|assembly|module|package|symbol|type\s*name|entry\s*point|config(?:uration)?(?:\s*(?:key|value|entry|block|option|property|setting))?|setting|property|parameter|option|flag|key|field|attribute|registry\s*(?:key|value|path)?|reg\s*key|file\s*name|filename|resource|pdb(?:\s*path)?|scheduled\s*task|task\s*name|service\s*name|named\s*pipe|pipe\s*name|event\s*name|window\s*title|user[\s-]?agent|mutex\s+name|string|marker|identifier|muteks\s+ad[ıi]|sınıf|metot|fonksiyon|modül|yapılandırma|ayar|parametre|anahtar|kayıt\s*defteri|dosya\s*ad[ıi]|klasse|methode|funktion|konfiguration|einstellung|registrierung|clase|método|metodo|función|funcion|configuración|configuracion|ajuste|parámetro|parametro|registro|класс|метод|функци[яи]|конфигурац[а-я]*|настройк[а-я]*|параметр|мьютекс|мутекс|реестр[а-я]*|互斥(?:体|量|锁)?|信号量|类名?|命名空间|方法|函数|模块|配置(?:项|键)?|参数|属性|注册表(?:项|键)?|文件名)(?:\s+(?:name[ds]?|named|called|value|of|is|was|as|olarak|adl[ıi]|ad[ıi]|ist|es|как|为|是|名为|名称为|名称))?\s*[:：=,\-–—]?\s*["'“‘`(\[]?\s*$/i;

/** Artifact vocabulary anywhere in the clause (used when no network relation is stated). */
const ARTIFACT_CLAUSE_RE =
  /(?:\bmutex|\bmutant\b|muteks|\bsemaphore|single[\s-]?instance|singleinstance|\bnamespace|\bclass\b|\bmethod\b|\bfunction\b|\bassembly\b|\bmodule\b|\bpackage\b|\bsymbol\b|config(?:uration)?\s*(?:key|value|entry|block|option|property|setting|file)|\bsetting|\bproperty|\bparameter|\bregistry|\bhkcu\b|\bhklm\b|\bhkey_|\bpdb\b|scheduled\s*task|named\s*pipe|\bpipe\s*name|\bevent\s*name|\bwindow\s*title|user[\s-]?agent|sınıf|metot|fonksiyon|modül|yapılandırma|ayar|parametre|kayıt\s*defteri|klasse|methode|funktion|konfiguration|einstellung|registrierung|clase|método|metodo|función|funcion|configuración|configuracion|ajuste|parámetro|parametro|класс|метод|функци|конфигурац|настройк|параметр|мьютекс|мутекс|реестр|互斥|信号量|类名|命名空间|方法|函数|模块|配置|参数|属性|注册表)/i;

/** Code-context vocabulary (decompilation, language names) around a token. */
const CODE_CONTEXT_RE = /(?:\.NET\b|\bC#|\bC\+\+|\bJava\b|\bGo(?:lang)?['’]s\b|\bRust\b|\bPython\b|\bclass\s|\bnamespace\s|\bmethod\s|\bfunction\s|\bstruct\b|\bpackage\s|decompil|disassembl|反编译|代码片段|函数|类\s|derleme|sınıf|Klasse|Methode|класс|метод)/i;

/**
 * @param {string} label
 * @returns {{ kind: string }|null}
 */
export function parseArtifactTypeLabel(label) {
  const norm = normalizeLabel(label);
  if (!norm || norm.length > 64) return null;
  for (const fam of ARTIFACT_LABEL_FAMILIES) {
    if (fam.re.test(norm)) return { kind: fam.kind };
  }
  return null;
}

/**
 * @param {string} label
 */
export function isNetworkTypeLabel(label) {
  const norm = normalizeLabel(label);
  if (!norm || norm.length > 64) return false;
  return NETWORK_LABEL_RE.test(norm);
}

function normalizeLabel(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[ -⁯　]/g, ' ')
    .replace(/[():：,.;/|"'`*#]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Semantics of a source label (type cell, heading, column header) for a
 * dotted / slashed value: network, artifact, or neutral.
 * A label that names both ("C2 port", "URL path") is network-leaning for
 * hostnames but never turns a relative path into a URL (syntax gate below).
 * @param {string|null|undefined} label
 * @returns {{ semantics: 'network'|'artifact'|'neutral', kind?: string }}
 */
export function classifyTypeLabel(label) {
  const norm = normalizeLabel(label);
  if (!norm) return { semantics: 'neutral' };
  // Only short labels are type labels; a sentence or a long section title is not.
  if (norm.length > 48 || norm.split(' ').length > 3) return { semantics: 'neutral' };
  const network = NETWORK_LABEL_RE.test(norm);
  const artifact = parseArtifactTypeLabel(norm);
  if (network && (!artifact || artifact.kind === 'path' || artifact.kind === 'metadata')) return { semantics: 'network' };
  if (artifact) return { semantics: 'artifact', kind: artifact.kind };
  return { semantics: 'neutral' };
}

// ---------------------------------------------------------------------------
// Canonical syntax
// ---------------------------------------------------------------------------

const HOST_LABEL_RE = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/i;
const TLD_LABEL_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i;

/**
 * Hostname-compatible syntax (labels, alphabetic or IDN TLD, length limits).
 * Says nothing about whether the value IS a hostname — only that it could be.
 * @param {string} value
 */
export function isHostnameSyntax(value) {
  const v = String(value || '').trim().replace(/\.$/, '');
  if (!v || v.length > 253 || /\s/.test(v)) return false;
  const labels = v.split('.');
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1];
  if (!TLD_LABEL_RE.test(tld)) return false;
  for (let i = 0; i < labels.length - 1; i += 1) {
    if (!HOST_LABEL_RE.test(labels[i])) return false;
  }
  return true;
}

/**
 * Compact "looks like DNS" suffix knowledge: the ISO 3166 ccTLD set plus the
 * most common gTLDs. This is a SYNTAX signal (strong vs weak suffix), never a
 * safety allowlist — unknown suffixes still resolve as domains when the
 * source asserts network semantics or the value is otherwise plain.
 */
const CC_TLDS = new Set(
  'ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw'.split(
    ' '
  )
);
const COMMON_GTLDS = new Set(
  'com net org info biz edu gov mil int arpa app dev cloud xyz top site online tech store shop club pro tv cc ai gg pw tk ml ga cf gq icu buzz live life world today news blog work zone space link click host website web page one run fun vip win bid loan men party trade stream download review date faith racing science accountant cricket gdn mom lol pics email digital agency group company solutions services network systems media center name mobi asia tel travel xxx wang cyou rest sbs bond quest hair skin makeup beauty cfd best monster fit yachts autos boats motorcycles homes cam ru su рф moscow москва'.split(
    ' '
  )
);
const MULTI_PART_SUFFIX = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'com.br', 'com.cn', 'net.cn', 'org.cn', 'edu.cn', 'gov.cn',
  'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'or.kr', 'com.tw', 'com.hk', 'com.tr', 'gen.tr', 'org.tr', 'net.tr', 'com.mx', 'com.ar', 'com.co',
  'co.in', 'co.za', 'com.sg', 'com.my', 'co.id', 'com.vn', 'com.ua', 'com.ru', 'com.pl', 'com.es', 'com.pt', 'com.ph', 'com.pk', 'com.eg',
  'com.sa', 'com.ng', 'com.ke'
]);

/**
 * Last labels that read as code / configuration words rather than TLDs when
 * they sit in TLD position (agent.server.timeout, Loader.Program.Main).
 */
const CODE_WORD_LAST_LABEL_RE =
  /^(?:main|init|start|run|load|exec|execute|test|tests|spec|config|configuration|settings?|setting|options?|params?|properties|prop|timeout|interval|delay|enabled|disabled|debug|verbose|level|mode|path|dir|file|name|value|key|type|index|instance|singleinstance|client|server|program|module|package|namespace|class|handler|manager|helper|utils?|utilities|core|common|internal|impl|api|app|application|data|model|view|controller|component|provider|factory|builder|loader|runtime|engine|plugin|task|job|worker|event|listener|callback|logger|logging|log|dll|exe|sys|bin|dat|tmp|temp|json|xml|yaml|yml|ini|cfg|conf|txt|log|fs|io|dispose|close|open|read|write|send|recv|receive|connect|encrypt|decrypt|encode|decode|checksum|hash|update|create|delete|remove|add|get|set|is|has|to|from|with|host|hostname|port|addr|address|url|uri|ip|domain|user|username|pass|password|token|secret|uid|pid|count|size|len|length|max|min|default|base|root|home|target|source|dest|output|input|build|release|status|state|result|error|errors|warn|warning|trace|string|str|int|bool|boolean|number|num|text|html|css|sql|py|rb|go|rs|java|cs|cpp|hpp|h|c)$/i;

const FILE_EXT_HINT = new Set([
  'exe', 'dll', 'sys', 'scr', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'hta', 'js', 'jse', 'wsf', 'py', 'sh', 'elf', 'so', 'dylib',
  'lnk', 'url', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'pdf',
  'zip', 'rar', '7z', 'gz', 'tar', 'iso', 'img',
  'php', 'asp', 'aspx', 'jsp', 'cgi',
  'txt', 'log', 'dat', 'bin', 'cfg', 'ini', 'xml', 'json', 'csv',
  'enc', 'locked', 'crypt', 'payload', 'tmp', 'temp',
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'svg',
  'apk', 'ipa', 'dmg', 'pkg', 'msi', 'jar', 'class'
]);

export { FILE_EXT_HINT };

/**
 * Suffix strength of a dotted value.
 * @param {string[]} labels lowercase labels
 * @returns {'strong'|'plausible'|'weak'}
 */
export function suffixStrength(labels) {
  const last = labels[labels.length - 1] || '';
  const multi = labels.length >= 3 ? `${labels[labels.length - 2]}.${last}` : '';
  if (MULTI_PART_SUFFIX.has(multi)) return 'strong';
  if (CC_TLDS.has(last) || COMMON_GTLDS.has(last)) return 'strong';
  if (CODE_WORD_LAST_LABEL_RE.test(last)) return 'weak';
  if (FILE_EXT_HINT.has(last)) return 'weak';
  if (last.length > 12 || last.length < 2) return 'weak';
  if (/^\d+$/.test(last)) return 'weak';
  return 'plausible';
}

/**
 * Symbolic identifier shape in the ORIGINAL spelling: camelCase / PascalCase
 * segments mixed with lowercase ones, underscores, or an all-caps short
 * segment beside lowercase ones (embed.FS, bytes.Index, Loader.Program.Main).
 * Hostnames are case-insensitive; publishers write them lowercase or in one
 * case, so mixed-case segmentation is a code signal, not a DNS one.
 * @param {string} raw
 */
export function hasCodeIdentifierShape(raw, opts = {}) {
  const segments = String(raw || '').split('.').filter(Boolean);
  if (segments.length < 2) return false;
  if (segments.some((s) => s.includes('_'))) return true;
  if (segments.some((s) => /[a-z][A-Z]/.test(s) || /^[A-Z][a-z0-9]+[A-Z]/.test(s))) return true; // camelCase / PascalCase segment
  if (segments.every((s) => /^[A-Z0-9]+$/.test(s))) return false; // EVIL.COM
  const firstUpper = /^[A-Z]/.test(segments[0]);
  const later = segments.slice(1);
  const laterUpper = later.filter((s) => /^[A-Z]/.test(s)).length;
  const laterLower = later.filter((s) => /^[a-z]/.test(s)).length;
  if (laterUpper > 0 && laterLower > 0) return true; // a.B.c
  if (laterUpper > 0 && !firstUpper) return true; // embed.FS, bytes.Index
  if (laterUpper > 0 && firstUpper) {
    // Title case throughout (Loader.Program.Main vs Evil.Example.Com): the suffix decides.
    return opts.suffixStrength !== 'strong';
  }
  return false; // Exploit.in — brand-style capital on the first label only
}

/**
 * @param {string} text
 * @param {string} value
 */
export function clauseAround(text, value) {
  const hay = String(text || '');
  const needle = String(value || '');
  if (!hay || !needle) return { before: '', after: '', clause: hay };
  const low = hay.toLowerCase();
  const variants = [...new Set([needle, needle.replace(/\./g, '[.]'), needle.replace(/\[\.\]/g, '.')])].map((v) => v.toLowerCase());
  let idx = -1;
  let len = 0;
  for (const v of variants) {
    const i = low.indexOf(v);
    if (i >= 0) {
      idx = i;
      len = v.length;
      break;
    }
  }
  if (idx < 0) return { before: '', after: '', clause: hay.slice(0, 400) };
  const clauseStart = Math.max(
    0,
    Math.max(hay.lastIndexOf('. ', idx), hay.lastIndexOf('; ', idx), hay.lastIndexOf('。', idx), hay.lastIndexOf('\n', idx), hay.lastIndexOf(' ¶ ', idx), idx - 220)
  );
  let clauseEnd = hay.length;
  for (const stop of ['. ', '; ', '。', '\n', ' ¶ ']) {
    const j = hay.indexOf(stop, idx + len);
    if (j >= 0 && j < clauseEnd) clauseEnd = j;
  }
  clauseEnd = Math.min(clauseEnd, idx + len + 220);
  return {
    before: hay.slice(Math.max(0, idx - 90), idx),
    after: hay.slice(idx + len, Math.min(hay.length, idx + len + 90)),
    clause: hay.slice(clauseStart, clauseEnd)
  };
}

// ---------------------------------------------------------------------------
// URL / path canonical validation
// ---------------------------------------------------------------------------

const ABSOLUTE_URL_RE = /^(https?|ftps?|wss?):\/\/[^\s/?#]+(?:[/?#][^\s]*)?$/i;
const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const RELATIVE_PATH_RE = /^(?:\.{1,2}\/|\/(?!\/))[^\s]*/;
const WINDOWS_PATH_RE = /^(?:[a-zA-Z]:[\\/]|\\\\[^\s\\]+\\|%[A-Za-z_][A-Za-z0-9_]*%|~[\\/]|\$env:|\$home\b)/i;
const UNIX_ABS_PATH_RE = /^\/(?:etc|usr|var|tmp|home|opt|bin|sbin|dev|proc|root|lib|lib64|srv|mnt|media|boot|sys|run|data|private|Library|Applications|Users)(?:\/|$)/i;

/**
 * Port stated as prose right after a path / URL ("on port 8081", "port: 8081",
 * "8081 portu", "端口 8081", "порт 8081"). Contextual evidence only.
 */
const PORT_PROSE_RE =
  /(?:\b(?:on|over|via|at|using|through)\s+(?:tcp\s+|udp\s+)?port\s+(\d{1,5})\b|\bport\s*[:=]?\s*(\d{1,5})\b|\b(\d{1,5})\s*(?:\.\s*)?(?:portu|port'u|numaral[ıi]\s+port|nolu\s+port)\b|端口\s*(\d{1,5})|(\d{1,5})\s*端口|порт[а-я]*\s*(\d{1,5}))/i;

/**
 * @param {string} text
 * @returns {number|null}
 */
export function portFromProse(text) {
  const m = String(text || '').match(PORT_PROSE_RE);
  if (!m) return null;
  const n = Number(m.slice(1).find((g) => g != null));
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/**
 * Shape of a slashed / path-like value.
 * @param {string} refanged
 * @returns {'absolute_url'|'relative_path'|'file_path'|'scheme_less_url'|'other'}
 */
export function classifyPathLikeShape(refanged) {
  const v = String(refanged || '').trim();
  if (!v) return 'other';
  const head = v.split(/\s+/)[0];
  if (SCHEME_RE.test(head)) return 'absolute_url';
  if (WINDOWS_PATH_RE.test(head)) return 'file_path';
  if (UNIX_ABS_PATH_RE.test(head)) return 'file_path';
  if (RELATIVE_PATH_RE.test(head)) return 'relative_path';
  if (head.includes('/')) {
    const host = head.split('/')[0];
    if (isHostnameSyntax(host) || isValidIpAddress(host.split(':')[0])) return 'scheme_less_url';
    return 'other';
  }
  return 'other';
}

/**
 * Validate a candidate URL value. Only an absolute URL (scheme + valid host)
 * is a network URL; relative paths, routes and filesystem paths are kept as
 * non-network artifacts with the path and any prose-stated port preserved as
 * contextual evidence. Values with embedded prose are rejected so callers
 * split tokens and stop at the boundary.
 * @param {string} raw
 * @returns {{
 *   ok: boolean,
 *   resolved_type: string,
 *   reason: string,
 *   url?: string,
 *   host?: string,
 *   host_kind?: 'ip'|'domain',
 *   port?: number|null,
 *   normalized_path?: string,
 *   trailing_text?: string|null
 * }}
 */
export function validateUrlCandidate(raw) {
  const refanged = refangObservable(raw);
  if (!refanged) return { ok: false, resolved_type: 'invalid', reason: 'empty' };
  const shape = classifyPathLikeShape(refanged);
  const [head, ...restParts] = refanged.split(/\s+/);
  const trailing = restParts.join(' ').trim() || null;

  if (shape === 'relative_path' || shape === 'file_path') {
    const normalizedPath = stripTrailingPunct(head);
    return {
      ok: false,
      resolved_type: shape === 'file_path' ? RESOLVED_TYPES.FILE_PATH : RESOLVED_TYPES.RELATIVE_PATH,
      reason: shape === 'file_path' ? 'filesystem_path_without_host' : 'relative_path_without_scheme_or_host',
      normalized_path: normalizedPath,
      port: portFromProse(trailing || '') ?? null,
      trailing_text: trailing
    };
  }

  if (shape === 'absolute_url') {
    if (trailing) {
      // Prose after the URL token: caller must split; never absorb it into the value.
      return { ok: false, resolved_type: 'invalid', reason: 'url_followed_by_prose', normalized_path: stripTrailingPunct(head), trailing_text: trailing, port: portFromProse(trailing) };
    }
    const url = stripTrailingPunct(head);
    if (!ABSOLUTE_URL_RE.test(url)) return { ok: false, resolved_type: 'invalid', reason: 'unsupported_scheme_or_shape' };
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return { ok: false, resolved_type: 'invalid', reason: 'unparseable_url' };
    }
    const host = String(parsed.hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (!host) return { ok: false, resolved_type: 'invalid', reason: 'url_without_host' };
    const hostIsIp = isValidIpAddress(host);
    if (!hostIsIp && !isHostnameSyntax(host) && host !== 'localhost') {
      return { ok: false, resolved_type: 'invalid', reason: 'url_host_not_hostname_compatible' };
    }
    return {
      ok: true,
      resolved_type: RESOLVED_TYPES.URL,
      reason: 'absolute_url',
      url,
      host,
      host_kind: hostIsIp ? 'ip' : 'domain',
      port: parsed.port ? Number(parsed.port) : null
    };
  }

  if (shape === 'scheme_less_url') {
    if (trailing) return { ok: false, resolved_type: 'invalid', reason: 'url_followed_by_prose', trailing_text: trailing };
    const hostPart = head.split('/')[0];
    const host = hostPart.split(':')[0].toLowerCase();
    const hostIsIp = isValidIpAddress(host);
    if (!hostIsIp) {
      const labels = host.split('.');
      // Scheme-less host/path is only a URL when the host part is unambiguously DNS-shaped.
      if (suffixStrength(labels) !== 'strong') {
        return { ok: false, resolved_type: 'invalid', reason: 'scheme_less_url_host_not_dns_shaped' };
      }
    }
    return {
      ok: true,
      resolved_type: RESOLVED_TYPES.URL,
      reason: 'scheme_less_url_with_dns_host',
      url: stripTrailingPunct(head),
      host,
      host_kind: hostIsIp ? 'ip' : 'domain',
      port: null
    };
  }
  return { ok: false, resolved_type: 'invalid', reason: 'not_url_shaped' };
}

function stripTrailingPunct(s) {
  return String(s || '').replace(/[),.;:!?\]。，；]+$/g, '');
}

// ---------------------------------------------------------------------------
// Dotted token resolution (domain vs artifact)
// ---------------------------------------------------------------------------

/**
 * @typedef {object} DottedResolution
 * @property {'domain'|'technical_artifact'|'skip'} kind
 * @property {string|null} artifact_kind  mutex | code | config | registry | file | path | command | process | metadata | identifier
 * @property {string} reason
 * @property {boolean} labelled  a source-typed label (row / heading / inline) proved the reading — clause vocabulary alone does not
 * @property {object} signals
 */

/**
 * Resolve a hostname-shaped token using canonical syntax + source semantics +
 * provenance. `raw` must be the ORIGINAL spelling (case preserved).
 *
 * @param {string} raw
 * @param {{
 *   surroundingText?: string,
 *   typeLabel?: string|null,          // table type cell / column header / heading label for this value
 *   declaredType?: string|null,       // parsed declared observable type (domain/url/ip/...) when the source typed it
 *   zone?: string|null,
 *   blockType?: string|null,
 *   form?: string|null,               // standalone | url | ip_port | list_row | table_row
 *   strongZone?: boolean,
 *   urlPathBasenames?: Set<string>,
 *   knownUrlHosts?: Set<string>
 * }} [ctx]
 * @returns {DottedResolution}
 */
export function resolveDottedToken(raw, ctx = {}) {
  const original = String(raw || '').trim().replace(/\.$/, '');
  const lower = original.toLowerCase();
  const labels = lower.split('.').filter(Boolean);
  const signals = {};
  const out = (kind, reason, labelled = false) => ({
    kind,
    reason,
    labelled,
    artifact_kind: kind === 'technical_artifact' ? artifactKindFor(reason) : null,
    signals
  });

  if (labels.length < 2) return out('skip', 'not_dotted');
  if (!isHostnameSyntax(lower)) return out('skip', 'not_hostname_syntax');

  const basenames = ctx.urlPathBasenames || new Set();
  const hosts = ctx.knownUrlHosts || new Set();
  const label = classifyTypeLabel(ctx.typeLabel);
  const declared = String(ctx.declaredType || '').toLowerCase();
  const declaredNetwork = declared === 'domain' || declared === 'url' || label.semantics === 'network';
  const declaredArtifact = label.semantics === 'artifact';
  const surrounding = String(ctx.surroundingText || '');
  const { before, after, clause } = clauseAround(surrounding, original);
  const strength = suffixStrength(labels);
  const last = labels[labels.length - 1];
  const codeShape = hasCodeIdentifierShape(original, { suffixStrength: strength });
  const inlineArtifact = ARTIFACT_LABEL_BEFORE_RE.test(before);
  const inlineNetwork = NETWORK_RELATION_BEFORE_RE.test(before) || /^www\./.test(lower);
  const clauseArtifact = ARTIFACT_CLAUSE_RE.test(clause);
  const clauseNetwork = NETWORK_CLAUSE_RE.test(clause);
  const codeContext = CODE_CONTEXT_RE.test(clause) || ctx.blockType === 'code' || ctx.zone === 'code';
  const explicitRow = ctx.strongZone === true && (ctx.form === 'table_row' || ctx.form === 'list_row');
  // Key position: `token = value` / `"token": value` (never `token://`).
  const assignmentKey = /^["'`]?\s*(?:=(?!=)|:(?!\/\/)\s*(?:["'`\d[{]|true|false|null))/.test(after) && !declaredNetwork;
  Object.assign(signals, {
    suffix_strength: strength,
    code_shape: codeShape,
    label_semantics: label.semantics,
    label_kind: label.kind || null,
    inline_artifact_label: inlineArtifact,
    inline_network_relation: inlineNetwork,
    clause_artifact_words: clauseArtifact,
    clause_network_words: clauseNetwork,
    code_context: codeContext,
    explicit_indicator_row: explicitRow,
    assignment_key: assignmentKey
  });

  // 1. Source-typed labels are authoritative for the reading (not for validity).
  if (declaredArtifact) return out('technical_artifact', `${label.kind}_label`, true);
  if (declaredNetwork) return out('domain', 'declared_network_type', true);

  // 2. Parser knowledge: exact URL host / URL path basename.
  if (basenames.has(lower)) return out('technical_artifact', 'url_path_basename');
  if (hosts.has(lower)) return out('domain', 'url_host');

  // 3. Filename shapes (extension in TLD position).
  if (FILE_EXT_HINT.has(last)) {
    const fileLabel = /(file\s*name|filename|file\s*:|dosya|资源|文件名|样本|payload|download|保存|lnk|resource|dropped|saved\s+as)/i.test(clause);
    if (fileLabel) return out('technical_artifact', 'file_label');
    if (labels.length >= 3) return out('technical_artifact', 'multi_dot_ext');
    if (labels.length === 2 && labels[0].length <= 32) return out('technical_artifact', 'file_extension');
    if (!inlineNetwork && !clauseNetwork) return out('technical_artifact', 'extension_without_host_context');
  }

  // 4. Inline label right at the token decides before generic clause words.
  if (inlineArtifact) return out('technical_artifact', artifactReasonFrom(before, 'inline_artifact_label'), true);
  if (inlineNetwork) return out('domain', 'network_relation', true);

  // 5. Assignment / key position (`agent.server.host = …`, `"a.b.c": …`) is a
  //    configuration key whatever the suffix looks like.
  if (assignmentKey) return out('technical_artifact', 'config_context');

  // 6. Clause vocabulary: an artifact reading with no network relation stated.
  //    A DNS-shaped suffix is not overturned by loose clause words ("the module
  //    downloads from evil.com") — only by a label at the token.
  if (clauseArtifact && !clauseNetwork && strength !== 'strong') {
    return out('technical_artifact', artifactReasonFrom(clause, 'artifact_context'));
  }

  // 6. Symbolic identifier shape (case segmentation, underscores) is a code signal
  //    unless the source states a network relation for this exact token.
  if (codeShape) {
    if (strength === 'strong' && clauseNetwork && !clauseArtifact) return out('domain', 'network_context_mixed_case');
    return out('technical_artifact', codeContext ? 'code_context' : 'code_identifier_shape');
  }
  if (clauseNetwork && !clauseArtifact) {
    if (strength === 'weak' && CODE_WORD_LAST_LABEL_RE.test(last) && codeContext) return out('technical_artifact', 'code_context');
    return out('domain', 'network_context');
  }
  if (clauseArtifact && clauseNetwork) {
    // Both vocabularies: only a DNS-shaped suffix or an explicit indicator row can carry it.
    if (strength === 'strong' || explicitRow) return out('domain', 'network_context');
    return out('technical_artifact', artifactReasonFrom(clause, 'artifact_context'));
  }

  // 7. Provenance: an indicator row inside a publisher-curated indicator list
  //    is an explicit assertion even for an unusual suffix.
  if (explicitRow) return out('domain', 'explicit_indicator_row');

  // 8. Syntax alone.
  if (labels.length === 2 && CODE_WORD_LAST_LABEL_RE.test(last) && strength !== 'strong') {
    return out('technical_artifact', 'method_suffix');
  }
  // A dotted token in code / configuration context needs stronger evidence than
  // syntax alone, but an unusual (non-public) suffix is not by itself disqualifying:
  // only a code-word / file-extension / implausible suffix is.
  if (strength === 'weak') return out('technical_artifact', codeContext ? 'code_block_weak_suffix' : 'no_network_semantics');
  return out('domain', 'hostname_shape');
}

function artifactReasonFrom(text, fallback) {
  const fam = parseArtifactTypeLabel(text);
  if (fam?.kind === 'mutex') return 'single_instance_identifier_context';
  if (fam) return `${fam.kind}_context`;
  return fallback;
}

// ---------------------------------------------------------------------------
// Canonical IOC validity (final gate — AI cannot bypass)
// ---------------------------------------------------------------------------

const HASH_RE = { md5: /^[a-f0-9]{32}$/, sha1: /^[a-f0-9]{40}$/, sha256: /^[a-f0-9]{64}$/ };

/**
 * Does (type, value) have a valid canonical IOC shape? Used as the last gate
 * before any promotion / review eligibility / IOC creation.
 * @param {string} type
 * @param {string} value
 * @returns {{ ok: boolean, reason: string }}
 */
export function validateCanonicalIocValue(type, value) {
  const t = String(type || '').toLowerCase();
  const v = String(value || '').trim();
  if (!v) return { ok: false, reason: 'empty' };
  if (/\s/.test(v)) return { ok: false, reason: 'contains_whitespace' };
  switch (t) {
    case 'ip':
    case 'ipv6':
      return isValidIpAddress(v) ? { ok: true, reason: 'valid_ip' } : { ok: false, reason: 'invalid_ip' };
    case 'cidr': {
      const [addr, prefix] = v.split('/');
      const p = Number(prefix);
      if (!isValidIpAddress(addr) || !Number.isInteger(p)) return { ok: false, reason: 'invalid_cidr' };
      const max = addr.includes(':') ? 128 : 32;
      return p >= 0 && p <= max ? { ok: true, reason: 'valid_cidr' } : { ok: false, reason: 'invalid_cidr' };
    }
    case 'domain':
      return isHostnameSyntax(v) ? { ok: true, reason: 'hostname_syntax' } : { ok: false, reason: 'not_hostname_compatible' };
    case 'url': {
      const r = validateUrlCandidate(v);
      return r.ok ? { ok: true, reason: r.reason } : { ok: false, reason: r.reason };
    }
    case 'md5':
    case 'sha1':
    case 'sha256':
      return HASH_RE[t].test(v.toLowerCase()) ? { ok: true, reason: 'valid_hash' } : { ok: false, reason: 'invalid_hash' };
    default:
      return { ok: false, reason: 'unsupported_ioc_type' };
  }
}

/**
 * Explainable resolution record persisted with each candidate (admin diagnostics).
 * @param {{ raw: string, syntaxGuess: string, resolvedType: string, reason: string, promotion: 'eligible'|'excluded', signals?: object, normalizedPath?: string|null, port?: number|null, canonical?: { ok: boolean, reason: string }|null }} input
 */
export function buildTypeResolutionRecord(input) {
  return {
    resolver_version: OBSERVABLE_TYPE_RESOLVER_VERSION,
    raw: String(input.raw || '').slice(0, 300),
    syntax_guess: input.syntaxGuess || null,
    resolved_type: input.resolvedType || null,
    reason: input.reason || null,
    promotion: input.promotion || null,
    normalized_path: input.normalizedPath || undefined,
    port: input.port ?? undefined,
    canonical_valid: input.canonical ? input.canonical.ok : undefined,
    canonical_reason: input.canonical ? input.canonical.reason : undefined,
    signals: input.signals && Object.keys(input.signals).length ? input.signals : undefined
  };
}

/**
 * Coarse artifact family derived from the resolution reason (diagnostics / UI).
 * @param {string} reason
 */
export function artifactKindFor(reason) {
  const r = String(reason || '');
  if (/single_instance|mutex/.test(r)) return 'mutex';
  if (/^code_|method_suffix|code_block/.test(r)) return 'code';
  if (/url_path_basename|file_/.test(r) || r === 'multi_dot_ext' || r === 'extension_without_host_context') return 'file';
  const m = r.match(/^(config|registry|path|command|process|metadata|file|code)_(?:label|context)$/);
  if (m) return m[1];
  return 'identifier';
}
