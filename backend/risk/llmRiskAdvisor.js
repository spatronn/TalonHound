import crypto from 'crypto';
import { buildIncidentStatsSnapshot, buildIncidentVersion } from './llmRiskCommon.js';

const ALLOWED_ADJUSTMENTS = new Set([-20, -10, -5, 0, 5, 10, 15, 20]);

function toBool(v, defaultValue = false) {
  if (v == null) return defaultValue;
  const s = String(v).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(s)) return true;
  if (['0', 'false', 'no', 'off'].includes(s)) return false;
  return defaultValue;
}

function clamp(value, min = 0, max = 100) {
  return Math.min(Math.max(Number(value) || 0, min), max);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(Number(ms) || 0, 0)));
}

function isTimeoutError(err) {
  const name = String(err?.name || '');
  const code = String(err?.code || '').toUpperCase();
  const msg = String(err?.message || '').toLowerCase();
  if (name === 'AbortError') return true;
  if (code === 'ETIMEDOUT') return true;
  if (msg.includes('socket hang up')) return true;
  return false;
}

function normalizeAdjustment(raw) {
  const n = Number(String(raw ?? '').replace(/^\+/, ''));
  if (!Number.isFinite(n)) return 0;
  return ALLOWED_ADJUSTMENTS.has(n) ? n : 0;
}

function normalizeConfidence(raw) {
  const c = Number(raw);
  if (!Number.isFinite(c)) return 0;
  return clamp(c, 0, 1);
}

function extractJson(text) {
  if (!text || typeof text !== 'string') return null;

  try {
    return JSON.parse(text);
  } catch {
    // continue
  }

  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;

  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
}

function cleanReason(text, max = 900) {
  return String(text || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

/** Strip or soften claims in reason text when they are not supported by incident metrics or evidence. */
function applyFactualReasonGuards(reasonText, { hostCount = 0, durationMinutes = 0, hasNetworkLevelAccess = false } = {}) {
  let r = cleanReason(reasonText);
  const multiHostSupported = Number(hostCount) >= 2;
  const longDurationSupported = Number(durationMinutes) >= 60;
  if (!multiHostSupported) {
    r = r.replace(/\bacross multiple hosts\b/gi, 'from the observed host');
    r = r.replace(/\bmultiple hosts\b/gi, 'a single observed host');
    r = r.replace(/\bmultiple observed hosts\b/gi, 'a single observed host');
  }
  if (!longDurationSupported) {
    r = r.replace(/\bover an extended period\b/gi, 'within a short time window');
    r = r.replace(/\bextended period\b/gi, 'a short time window');
    r = r.replace(/\blong period\b/gi, 'a short time window');
    r = r.replace(/\bpersistent over time\b/gi, 'within a short time window');
    r = r.replace(/\bpersistent web activity\b/gi, 'observed network activity');
  }
  if (hasNetworkLevelAccess) {
    r = r.replace(/\bthe current evidence set does not confirm successful access\b/gi, 'network-level access was observed, but execution or compromise is not confirmed');
    r = r.replace(/\bsuccessful access not confirmed\b/gi, 'network-level access was observed, but execution or compromise is not confirmed');
    r = r.replace(/\bdoes not confirm successful access\b/gi, 'does not confirm endpoint execution or compromise beyond network-level access');
    r = r.replace(/\bdoes not confirm successful access, user interaction\b/gi, 'confirms network-level activity but not user interaction');
  }
  return cleanReason(r);
}

function safeJsonSnippet(obj, max = 12000) {
  try {
    const s = JSON.stringify(obj ?? '');
    return s.length > max ? `${s.slice(0, max)}…` : s;
  } catch {
    return '';
  }
}

/** Concatenate structured incident payload fields for proxy/DNS substring signals (not scored as extra events). */
function buildEvidenceHaystack(data = {}) {
  return [
    safeJsonSnippet(data.evidence_summary),
    safeJsonSnippet(data.sample_events),
    safeJsonSnippet(data.event_summary),
    safeJsonSnippet(data.playbook_coverage),
    safeJsonSnippet(data.incident),
    typeof data.evidence_logs_note === 'string' ? data.evidence_logs_note : ''
  ].join('\n').toLowerCase();
}

const PROXY_EVIDENCE_PHRASE_RE = /(squid_proxy|tcp_tunnel\s*\/\s*200|tcp_tunnel\/200|tcp_miss\s*\/\s*200|connect\s*\/\s*200|connect\/200|\bconnect\b|\bproxy\b|http\s+200|\bhttp\s*200\b|get\s+http|http\s+get)/i;
const TUNNEL_OR_CONNECT_200_RE = /(tcp_tunnel\s*\/\s*200|tcp_tunnel\/200|connect\s*\/\s*200|connect\/200)/i;

function inferDomainNetworkSignals(data = {}, hayFull = '') {
  const hay = String(hayFull || '').toLowerCase();
  const st = data?.event_summary?.source_types && typeof data.event_summary.source_types === 'object'
    ? data.event_summary.source_types
    : {};
  const dnsFromSummary = Math.max(
    Number(st.dns ?? st.DNS ?? st.dns_queries ?? 0) || 0,
    0
  );
  const proxyFromSummary = Math.max(Number(st.proxy ?? st.squid_proxy ?? 0) || 0, 0);
  const playbookProxy = Number(data?.playbook_coverage?.proxy_evidence ? 1 : 0) === 1;

  const hasDnsSignal = dnsFromSummary > 0
    || String(data?.activity_type || '').toLowerCase() === 'dns'
    || /\bdns\b|dns_query|dns_resolver|dns query/i.test(hay);
  const hasProxySignal = playbookProxy || proxyFromSummary > 0 || PROXY_EVIDENCE_PHRASE_RE.test(hay);
  const hasTunnelOrConnect200 = TUNNEL_OR_CONNECT_200_RE.test(hay)
    || /\btcp_tunnel\b.*\b200\b|\bconnect\b.*\b200\b/i.test(hay);

  let tier = 'generic_network';
  if (hasDnsSignal && hasProxySignal && hasTunnelOrConnect200) tier = 'dns_and_proxy_tunnel';
  else if (hasDnsSignal && hasProxySignal) tier = 'dns_and_proxy';
  else if (hasDnsSignal && !hasProxySignal) tier = 'dns_only';
  else if (!hasDnsSignal && hasProxySignal) tier = 'proxy_only';

  return {
    hasDnsSignal,
    hasProxySignal,
    hasTunnelOrConnect200,
    tier
  };
}

function buildTieredDomainInsightReason(data = {}, domainSignals, { hostCount = 0, durationMinutes = 0 } = {}) {
  const toN = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
  const inc = data?.incident || {};
  const detectionEvents = Math.max(0, toN(inc.detection_event_count ?? inc.event_count ?? data?.stats?.event_count ?? data?.event_count));
  const evidenceLogsRaw = data?.evidence_log_count ?? inc.evidence_log_count ?? data?.related_log_count ?? inc?.related_log_count;
  const evidenceLogsNum = Number(evidenceLogsRaw);
  const evidenceLogsReliable = Number.isFinite(evidenceLogsNum) && evidenceLogsNum > 0;
  const ioc = cleanReason(String(data?.ioc || data?.ioc_value || data?.observable_value || 'the IOC domain')).slice(0, 200);
  const hostPhrase = hostCount >= 2 ? 'multiple observed hosts' : 'a single observed host';
  const timePhrase = durationMinutes >= 60 ? 'over an extended period' : 'within a short time window';
  const countsLead = evidenceLogsReliable
    ? `Incident has ${detectionEvents} normalized detection events supported by ${Math.round(evidenceLogsNum)} raw evidence logs.`
    : `Incident has ${detectionEvents} normalized detection events.`;

  const tailShort = 'This supports network-level access based on correlated evidence, but the available correlated data alone does not prove compromise or payload execution.';

  if (domainSignals.tier === 'dns_and_proxy_tunnel') {
    return cleanReason(`${countsLead} DNS query and proxy CONNECT/200 activity to ${ioc} were observed from ${hostPhrase} ${timePhrase}. This indicates network-level access based on correlated DNS and proxy evidence, but the available correlated data alone does not prove compromise or payload execution.`);
  }
  if (domainSignals.tier === 'dns_and_proxy') {
    return cleanReason(`${countsLead} DNS and proxy activity involving ${ioc} were observed from ${hostPhrase} ${timePhrase}. ${tailShort}`);
  }
  if (domainSignals.tier === 'dns_only') {
    return cleanReason(`${countsLead} DNS activity related to ${ioc} was observed from ${hostPhrase} ${timePhrase}. The available correlated data alone does not prove compromise or payload execution.`);
  }
  if (domainSignals.tier === 'proxy_only') {
    return cleanReason(`${countsLead} Proxy network-level activity involving ${ioc} was observed from ${hostPhrase} ${timePhrase}. The available correlated data alone does not prove compromise or payload execution.`);
  }
  return cleanReason(`${countsLead} Network activity involving ${ioc} was observed from ${hostPhrase} ${timePhrase}. The available correlated data alone does not prove compromise or payload execution.`);
}

function domainReasonOmitsProxyEvidence(reasonText = '') {
  const r = String(reasonText || '');
  return !/(proxy|tcp_tunnel|connect\s*\/?\s*200|connect\/200|network-level|squid)/i.test(r);
}

function domainReasonLooksDnsHeavy(reasonText = '') {
  const r = String(reasonText || '');
  if (/moderate dns|dns query volume/i.test(r)) return true;
  if (/dns/i.test(r) && domainReasonOmitsProxyEvidence(r)) return true;
  return false;
}

function normalizeUrlTelemetryWording(reasonText = '') {
  let r = cleanReason(reasonText);
  r = r.replace(/Missing DNS resolution/gi, 'DNS resolution was not correlated in the current evidence set');
  r = r.replace(/Missing endpoint process/gi, 'Endpoint process telemetry is not available in the current evidence set');
  r = r.replace(/Missing content analysis/gi, 'Content-analysis evidence is not present in the available telemetry');
  r = r.replace(/no endpoint process evidence/gi, 'endpoint process context is not available in the current evidence set');
  r = r.replace(/no content analysis evidence/gi, 'content-analysis evidence is not present in the available telemetry');
  r = r.replace(/no user interaction/gi, 'available events do not confirm user interaction');
  r = r.replace(/no file was downloaded/gi, 'available events do not show downloaded content');
  return cleanReason(r);
}

function buildDomainEvidenceReasonOverride(data = {}, currentReason = '') {
  const reason = String(currentReason || '');
  const sourceTypes = data?.event_summary?.source_types || {};
  const sampleEvents = Array.isArray(data?.sample_events) ? data.sample_events : [];
  const evidenceSummary = data?.evidence_summary && typeof data.evidence_summary === 'object' ? data.evidence_summary : {};
  const evidenceSourceTypes = Array.isArray(evidenceSummary?.source_types) ? evidenceSummary.source_types.map((x) => String(x).toLowerCase()) : [];

  const hasProxyByType = Number(sourceTypes?.proxy || 0) > 0 || evidenceSourceTypes.includes('proxy');
  const sampleText = sampleEvents.map((s) => JSON.stringify(s)).join(' ').toLowerCase();
  const hasProxyBySample = /(tcp_tunnel\/200|connect\/200|\bconnect\b|tcp_miss\/200|get\s+http|squid_proxy|\bproxy\b)/i.test(sampleText);
  const hasProxyEvidence = hasProxyByType || hasProxyBySample || Number(data?.playbook_coverage?.proxy_evidence ? 1 : 0) === 1;
  const hasDnsEvidence = Number(sourceTypes?.dns || 0) > 0 || Number(data?.playbook_coverage?.dns_evidence ? 1 : 0) === 1;

  const observedHosts = Number(data?.incident?.observed_hosts ?? data?.stats?.observed_hosts ?? 0) || 0;
  const durationMinutes = Number(data?.incident?.duration_minutes ?? data?.duration_minutes ?? data?.stats?.duration_minutes ?? 0) || 0;

  const isDnsOnlyPhrase = /(high volume of dns queries|moderate dns query volume|moderate dns activity|high dns query volume|dns query volume|dns-only|dns queries|single host and short duration indicate low risk|no persistence or repeated queries)/i.test(reason)
    && !/(proxy|connect|tunnel|get|network-level access)/i.test(reason);

  if (String(data?.ioc_type || '').toLowerCase() !== 'domain') return null;
  if (!hasProxyEvidence) return null;
  if (!isDnsOnlyPhrase) return null;

  const hostPhrase = observedHosts > 1 ? 'multiple hosts' : 'a single host';
  const windowPhrase = durationMinutes >= 60 ? 'over an extended time window' : 'within a short time window';
  if (hasDnsEvidence) {
    return `DNS query and proxy CONNECT/200 activity to the IOC domain were observed from ${hostPhrase} ${windowPhrase}. This indicates network-level access based on correlated DNS and proxy evidence, but the available correlated data alone does not prove compromise or payload execution.`;
  }
  return `Proxy network activity to the IOC domain was observed from ${hostPhrase} ${windowPhrase}. This indicates network-level access based on correlated evidence, but the available correlated data alone does not prove compromise or payload execution.`;
}

function formatServicePort(traffic = {}) {
  const service = Array.isArray(traffic?.services) ? String(traffic.services.find(Boolean) || '').trim() : '';
  const port = Array.isArray(traffic?.ports) ? Number(traffic.ports.find((p) => Number.isFinite(Number(p)) && Number(p) > 0) || 0) : 0;
  if (service && port) return `${service}/${port}`;
  if (port) return `port ${port}`;
  if (service) return service;
  return 'not specified';
}

function buildRelatedIocEvidenceReason({ data, relatedIocs, hasHighVolume, hasMultipleHosts, hasLongDuration }) {
  const candidate = relatedIocs.find((r) =>
    r?.relationship === 'dns_response_ip'
    && r?.related_ioc_in_ioc_list === true
    && Number(r?.traffic?.accepted_count || 0) > 0
  );
  if (!candidate) return null;

  const domain = String(data?.ioc || data?.ioc_value || data?.observable_value || candidate?.source_ioc || 'the domain IOC');
  const relatedIp = String(candidate?.related_ioc || candidate?.dns?.response_ip || '');
  if (!relatedIp) return null;

  const acceptedCount = Number(candidate?.traffic?.accepted_count || 0);
  const servicePort = formatServicePort(candidate?.traffic || {});
  const chainType = String(candidate?.chain_type || '');
  const hasDurableDnsSignals = hasHighVolume && hasMultipleHosts && hasLongDuration;
  const dnsLead = hasDurableDnsSignals
    ? `High volume DNS activity was observed for ${domain} across multiple hosts over a persistent period.`
    : `DNS activity was observed for ${domain}.`;

  let chainSentence = '';
  if (chainType === 'same_host_dns_to_connection') {
    chainSentence = `The domain resolved to ${relatedIp}, which is also present in the IOC list, and the same internal host later established accepted traffic to ${relatedIp}${servicePort !== 'not specified' ? ` on ${servicePort}` : ''}. This suggests a possible DNS-to-connection chain to malicious infrastructure.`;
  } else if (chainType === 'environment_level_related_activity') {
    chainSentence = `The domain resolved to ${relatedIp}, which is also present in the IOC list, and accepted traffic to ${relatedIp}${servicePort !== 'not specified' ? ` on ${servicePort}` : ''} was observed from another internal host. This suggests environment-level related malicious infrastructure activity rather than DNS-only noise.`;
  } else {
    chainSentence = `The domain resolved to ${relatedIp}, which is also present in the IOC list, and accepted traffic to that related IOC IP${servicePort !== 'not specified' ? ` on ${servicePort}` : ''} was observed (${acceptedCount} events). Host attribution was inconclusive, so this should be treated as related infrastructure evidence, not a confirmed same-host chain.`;
  }

  return {
    reasonText: cleanReason(`${dnsLead} ${chainSentence}`),
    evidence: {
      domain,
      resolved_ip: relatedIp,
      resolved_ip_in_ioc_list: true,
      accepted_traffic: acceptedCount > 0,
      service_port: servicePort,
      chain_type: chainType || 'related_infrastructure_activity'
    }
  };
}

export function normalizeAdvisorOutput(raw, fallbackReason = 'fallback', incidentData = null) {
  const parsed = raw && typeof raw === 'object' ? raw : {};
  const data = incidentData && typeof incidentData === 'object' ? incidentData : {};
  let confidence = normalizeConfidence(parsed.confidence);
  let reason = cleanReason(parsed.reason || fallbackReason || 'fallback');
  const rawModelAdjustment = normalizeAdjustment(parsed.adjustment ?? parsed.risk_adjustment);
  let adjustment = rawModelAdjustment;

  if (/blacklist/i.test(reason)) {
    return { adjustment: 0, confidence: 0, reason: 'invalid_reason_blacklist_reference', raw_model_adjustment: rawModelAdjustment };
  }

  const appendOnce = (base, msg) => (String(base).includes(msg) ? String(base) : `${base} ${msg}`.trim());
  const drivers = Array.isArray(parsed.main_risk_drivers) ? parsed.main_risk_drivers.map((x) => String(x)) : [];
  const reducing = Array.isArray(parsed.risk_reducing_factors) ? parsed.risk_reducing_factors.map((x) => String(x)) : [];
  const evidenceText = `${reason} ${drivers.join(' ')}`.toLowerCase();

  const stats = data?.stats || {};
  const iocType = String(data?.ioc_type || '').toLowerCase();
  const activityType = String(data?.activity_type || '').toLowerCase();
  const toNum = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

  const highVolumeMinHits = Math.max(Number(process.env.AI_INSIGHT_HIGH_VOLUME_MIN_HITS || 1000), 1);
  const multipleHostsMin = Math.max(Number(process.env.AI_INSIGHT_MULTIPLE_HOSTS_MIN || 2), 1);
  const longDurationHoursMin = Math.max(Number(process.env.AI_INSIGHT_LONG_DURATION_MIN_HOURS || 24), 1);
  const dnsLongDurationMinMinutes = Math.max(Number(process.env.AI_INSIGHT_DNS_LONG_DURATION_MIN_MINUTES || 720), 1);

  const totalHits = toNum(stats.total_hits ?? stats.hits ?? stats.dns_queries ?? stats.event_count ?? data.total_hits ?? data.hits ?? data.dns_queries ?? data.event_count);
  const hostCount = toNum(stats.observed_hosts ?? stats.unique_hosts ?? stats.affected_hosts ?? data.observed_hosts ?? data.unique_hosts ?? data.affected_hosts);
  const durationMinutesFromField = toNum(stats.duration_minutes ?? data.duration_minutes);
  const durationHoursFromField = toNum(stats.duration_hours ?? data.duration_hours);
  const firstSeenMs = data?.first_seen ? new Date(data.first_seen).getTime() : (data?.first_seen_at ? new Date(data.first_seen_at).getTime() : NaN);
  const lastSeenMs = data?.last_seen ? new Date(data.last_seen).getTime() : (data?.last_seen_at ? new Date(data.last_seen_at).getTime() : NaN);
  const durationMinutes = durationMinutesFromField > 0
    ? durationMinutesFromField
    : (durationHoursFromField > 0 ? durationHoursFromField * 60 : (Number.isFinite(firstSeenMs) && Number.isFinite(lastSeenMs) && lastSeenMs >= firstSeenMs ? (lastSeenMs - firstSeenMs) / 60000 : 0));

  const evidenceHaystack = buildEvidenceHaystack(data);
  const hayFull = `${evidenceHaystack}\n${evidenceText}`;
  const domainSignals = iocType === 'domain'
    ? inferDomainNetworkSignals(data, hayFull)
    : { tier: 'generic_network', hasDnsSignal: false, hasProxySignal: false, hasTunnelOrConnect200: false };

  const hasHighVolumeMetric = totalHits >= highVolumeMinHits;
  const hasMultipleHostsMetric = hostCount >= multipleHostsMin;
  const isDnsLike = activityType === 'dns' || iocType === 'domain';
  const hasLongDurationMetric = isDnsLike
    ? durationMinutes >= dnsLongDurationMinMinutes
    : (durationHoursFromField > 0 ? durationHoursFromField >= longDurationHoursMin : (durationMinutes / 60) >= longDurationHoursMin);

  const relatedIocs = Array.isArray(data?.related_iocs) ? data.related_iocs : [];
  const dnsResponseIpRelations = relatedIocs.filter((r) => String(r?.relationship || '').toLowerCase() === 'dns_response_ip');
  const nonDnsRelatedIocs = relatedIocs.filter((r) => String(r?.relationship || '').toLowerCase() !== 'dns_response_ip');
  const relatedAccepted = nonDnsRelatedIocs.some((r) => Number(r?.traffic?.accepted_count || 0) > 0);
  const relatedInList = nonDnsRelatedIocs.some((r) => r?.related_ioc_in_ioc_list === true);
  const hasSameHostChain = nonDnsRelatedIocs.some((r) => r?.chain_type === 'same_host_dns_to_connection');
  const hasEnvChain = nonDnsRelatedIocs.some((r) => r?.chain_type === 'environment_level_related_activity');
  const hasAcceptedTrafficNoAttribution = nonDnsRelatedIocs.some((r) => r?.chain_type === 'accepted_traffic_to_related_ioc');

  const proxySourceCount = Number(data?.event_summary?.source_types?.proxy ?? data?.event_summary?.source_types?.squid_proxy ?? 0);
  const hasProxyCoverage = Number(data?.playbook_coverage?.proxy_evidence ? 1 : 0) === 1 || proxySourceCount > 0
    || PROXY_EVIDENCE_PHRASE_RE.test(evidenceHaystack);
  const hasNetworkAccessInText = /(tcp_tunnel|connect\s*\/\s*200|connect\/200|\bhttp\s*200\b|http\s+200)/i.test(hayFull);
  const hasDnsResponseIpAccepted = dnsResponseIpRelations.some((r) => Number(r?.traffic?.accepted_count || 0) > 0);
  const hasAcceptedOrSuccessfulMetric = toNum(stats.accepted_connections ?? stats.successful_access ?? data.accepted_count ?? data.successful_count) > 0 || relatedAccepted
    || hasProxyCoverage || hasNetworkAccessInText || hasDnsResponseIpAccepted;
  const hasAcceptedOrSuccessful = hasAcceptedOrSuccessfulMetric || /(accepted|successful)/i.test(evidenceText);

  const relatedDnsIpInIocList = dnsResponseIpRelations.some((r) => r?.related_ioc_in_ioc_list === true);
  const hasStrongMaliciousContextMetric = /(\btp\b|high-confidence|high confidence|\bc2\b|malware|ransomware|phishing|botnet|scanner|exploit)/i.test(evidenceText)
    || String(data?.history?.previous_verdict || '').toLowerCase() === 'tp'
    || relatedInList || relatedDnsIpInIocList;
  const hasBenignEvidenceMetric = /(false positive|\bfp\b|allowlisted|trusted benign|known internal test|smoke test|benign destination|internal security test)/i.test(evidenceText)
    || reducing.some((x) => /(allowlisted|trusted|benign|internal test|false positive|fp)/i.test(String(x)))
    || String(data?.history?.previous_verdict || '').toLowerCase() === 'fp';

  // text fallback only when metrics are unavailable
  const hasHighVolume = totalHits > 0 ? hasHighVolumeMetric : /(high total_hits|high volume|many queries|high dns|high hits)/i.test(evidenceText);
  const hasMultipleHosts = hostCount > 0 ? hasMultipleHostsMetric : /(multiple hosts|many hosts|multiple observed hosts|observed_hosts\s*>=\s*2|unique_hosts\s*>=\s*2)/i.test(evidenceText);
  const hasLongDuration = durationMinutes > 0 ? hasLongDurationMetric : /(long duration|persistence|persistent|over several hours|over time|repeated over long duration)/i.test(evidenceText);

  const hasPersistencePositivePhrase = /(prolonged period|extended period|over a long duration|repeated|persistent|over time)/i.test(reason);
  const hasPersistenceNegativePhrase = /(no persistence|lacks persistence|without persistence|lack of persistence)/i.test(reason);
  const hasCoupledBadPhrase = /(successful access\s+or\s+persistence|no confirmed successful access\s+or\s+persistence|lacks confirmed successful access\s+or\s+persistence|no successful access\s+or\s+persistence|lacks successful access\s+or\s+persistence)/i.test(reason);
  const urlPersistenceMismatch = iocType === 'url' && (
    (durationMinutes > 60 && hasPersistenceNegativePhrase)
    || (hasPersistencePositivePhrase && hasPersistenceNegativePhrase)
    || hasCoupledBadPhrase
  );
  const hasInternalGuardrailWords = /(deterministic guardrails|final adjustment|normalized by guardrails|adjustment was normalized|based on incident metrics)/i.test(reason);
  const hasForbiddenWords = /(blacklist|\bsafe\b|\bbenign\b|not a threat|no threat)/i.test(reason);
  const hasRiskOverstatement = /increases the risk/i.test(reason) && !hasAcceptedOrSuccessful;
  const hasCompromiseOverclaim = /(confirmed compromise|successful compromise|malicious activity is confirmed|confirmed threat)/i.test(reason) && !hasAcceptedOrSuccessful;
  const hasPlaybookObserved = /(proxy requests|url access attempts|web access attempts|\bproxy\b|\bconnect\b|tcp_tunnel|connect\s*\/\s*200|connect\/200|http\s+200|\bhttp\s*200\b|web access)/i.test(reason);
  const hasPlaybookMissing = /(endpoint process context|content analysis|confirmed successful access|user interaction|dns resolution)/i.test(reason);
  const urlPlaybookIncomplete = iocType === 'url' && (!hasPlaybookObserved || !hasPlaybookMissing);

  const triggersInvalidPersistencePath = urlPersistenceMismatch || hasInternalGuardrailWords || hasForbiddenWords || hasRiskOverstatement || hasCompromiseOverclaim || urlPlaybookIncomplete;
  if (triggersInvalidPersistencePath) {
    const urlHardcodedReason = 'Repeated proxy URL access attempts were observed across multiple hosts over an extended period, indicating persistent web activity. The current evidence set does not confirm successful access, user interaction, endpoint process context, or downloaded content, so the activity should be investigated.';
    const nonUrlFallbackReason = 'The evidence indicates network activity involving the IOC, but available telemetry does not confirm endpoint execution, compromise, downloaded content, or malicious payload execution.';
    const baseFallbackReason = iocType === 'url'
      ? urlHardcodedReason
      : (iocType === 'domain'
        ? buildTieredDomainInsightReason(data, domainSignals, { hostCount, durationMinutes })
        : nonUrlFallbackReason);
    const hasNetworkLevelAccess = Boolean(hasAcceptedOrSuccessful);
    const reasonOut = applyFactualReasonGuards(baseFallbackReason, {
      hostCount,
      durationMinutes,
      hasNetworkLevelAccess
    });
    const limitedConfidence = clamp(Math.max(confidence || 0, 0.45), 0.45, 0.65);
    return {
      adjustment: 0,
      confidence: limitedConfidence,
      reason: reasonOut,
      raw_model_adjustment: rawModelAdjustment,
      normalization_reason: 'invalid_reason_persistence_contradiction'
    };
  }
  const hasRepeatedOnly = /(repeated dns|repeated)/i.test(evidenceText);
  const hasStrongMaliciousContext = hasStrongMaliciousContextMetric;
  const explicitBenign = hasBenignEvidenceMetric;
  const relatedReason = buildRelatedIocEvidenceReason({
    data,
    relatedIocs,
    hasHighVolume,
    hasMultipleHosts,
    hasLongDuration
  });

  if (relatedReason?.reasonText) {
    reason = relatedReason.reasonText;
  }

  let floor = 0;
  if (!explicitBenign) {
    if (hasAcceptedTrafficNoAttribution && relatedAccepted && relatedInList) floor = Math.max(floor, 5);
    if (hasEnvChain && relatedAccepted) floor = Math.max(floor, (hasHighVolume && hasMultipleHosts && hasLongDuration) ? 10 : 5);
    if (hasSameHostChain && relatedAccepted) floor = Math.max(floor, 10);
    if (hasHighVolume && hasMultipleHosts && hasLongDuration) floor = Math.max(floor, 5);
    if (floor >= 5 && (hasAcceptedOrSuccessful || hasStrongMaliciousContext)) floor = Math.max(floor, 10);
  }

  let normalizationReason = null;
  if (!explicitBenign && adjustment < floor) {
    adjustment = floor;
    confidence = Math.min(confidence || 0.6, 0.6);
    normalizationReason = 'deterministic_guardrail_floor';
  } else if (!explicitBenign && rawModelAdjustment < 0 && floor === 0 && (hasHighVolume || hasRepeatedOnly || hasMultipleHosts || hasLongDuration)) {
    adjustment = 0;
    confidence = Math.min(confidence || 0.6, 0.6);
    normalizationReason = 'negative_neutralized';
    reason = cleanReason(appendOnce(reason, 'Negative adjustment was neutralized because the stated drivers are risk-increasing, not risk-reducing.'));
  }

  if (iocType === 'domain' && !relatedReason?.reasonText && domainSignals.hasProxySignal
    && (domainReasonOmitsProxyEvidence(reason) || domainReasonLooksDnsHeavy(reason))) {
    reason = buildTieredDomainInsightReason(data, domainSignals, { hostCount, durationMinutes });
  }

  if (/(limited evidence|inconclusive|uncertain|insufficient evidence|limits confidence)/i.test(reason)) {
    adjustment = 0;
    if (iocType === 'url') {
      confidence = clamp(Math.max(confidence || 0.5, 0.45), 0.45, 0.65);
    }
  }

  if (iocType === 'domain' && !explicitBenign && adjustment <= 0
    && domainSignals.hasDnsSignal && domainSignals.hasProxySignal && domainSignals.hasTunnelOrConnect200) {
    adjustment = 5;
    normalizationReason = 'domain_dns_proxy_tunnel_adjustment';
  }

  if (iocType === 'url') reason = normalizeUrlTelemetryWording(reason);
  const domainOverride = buildDomainEvidenceReasonOverride(data, reason);
  if (domainOverride) reason = cleanReason(domainOverride);

  reason = applyFactualReasonGuards(reason, {
    hostCount,
    durationMinutes,
    hasNetworkLevelAccess: Boolean(hasAcceptedOrSuccessful)
  });

  return {
    adjustment,
    confidence,
    reason,
    raw_model_adjustment: rawModelAdjustment,
    normalization_reason: normalizationReason,
    hasHighVolume,
    hasMultipleHosts,
    hasLongDuration,
    hasAcceptedOrSuccessfulTraffic: hasAcceptedOrSuccessful,
    hasStrongMaliciousContext,
    llm_related_evidence: relatedReason?.evidence || null,
    hasBenignEvidence: explicitBenign,
    thresholds_used: {
      AI_INSIGHT_HIGH_VOLUME_MIN_HITS: highVolumeMinHits,
      AI_INSIGHT_MULTIPLE_HOSTS_MIN: multipleHostsMin,
      AI_INSIGHT_LONG_DURATION_MIN_HOURS: longDurationHoursMin,
      AI_INSIGHT_DNS_LONG_DURATION_MIN_MINUTES: dnsLongDurationMinMinutes
    },
    detected_positive_factors: [
      hasHighVolume ? 'high_volume' : null,
      hasMultipleHosts ? 'multiple_hosts' : null,
      hasLongDuration ? 'long_duration_or_persistence' : null,
      hasAcceptedOrSuccessful ? 'accepted_or_successful' : null,
      hasStrongMaliciousContext ? 'strong_malicious_context' : null,
      hasSameHostChain ? 'same_host_dns_to_connection' : null,
      hasEnvChain ? 'environment_level_related_activity' : null
    ].filter(Boolean),
    detected_negative_factors: [
      explicitBenign ? 'explicit_benign_or_fp' : null,
      dnsResponseIpRelations.length > 0 ? 'dns_response_ip_forensic_only' : null
    ].filter(Boolean)
  };
}

function buildGenericPrompt() {
  return `You are a cybersecurity risk assistant. Return a small adjustment score only.
Rules:
- Return ONLY JSON
- adjustment must be one of: -10, -5, 0, +5, +10
- Never claim facts not present in Incident Data
- Do not mention blacklist
- Reason should focus on: ioc_type, total_hits/hits, event_count, observed_hosts/unique_hosts, duration, persistence
Output:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildDomainPrompt() {
  return `DOMAIN IOC ANALYSIS RULES:
- Domain IOC incidents must be evaluated using DNS behavior, not accepted/blocked traffic.
- DNS queries to suspicious or matched IOC domains are meaningful security signals.
- Use total_hits/hits as the main volume signal.
- Use event_count only as the number of sampled/correlated detection events, not as total activity volume.
- Multiple observed hosts increase concern.
- Persistence over time increases concern.
- Repeated DNS queries over a long duration may indicate beaconing, malware communication, or misconfigured repeated access.
- Do not mention blacklist status.
- Do not decrease risk when DNS volume is high or persistent.
Increase risk if:
- total_hits is high
- observed_hosts >= 2
- duration is long
- repeated DNS queries are observed
Return neutral if:
- total_hits is low
- single host
- short duration
- no persistence
Decrease risk only if:
- there is clear evidence of benign/test activity
- very low volume and no persistence
Return ONLY JSON:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildIpPrompt() {
  return `IP IOC ANALYSIS RULES:
- accepted/blocked logic applies only for IP/network IOC.
- Use accepted_connections, blocked_connections, inbound_events, outbound_events, unique_hosts/observed_hosts, and persistence.
- Do not mention blacklist status.
Increase risk:
- accepted traffic is meaningful
- multiple hosts affected
- persistent activity over time
Decrease risk:
- mostly blocked traffic
- clear scanning/noise pattern with low persistence
Return ONLY JSON:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildUrlPrompt() {
  return `URL IOC ANALYSIS RULES:
- URL IOC incidents must be evaluated using proxy/web access behavior.
- Use event_summary as the main source of behavior and sample_events only as examples.
- Analysts usually look for DNS resolution evidence, proxy/web access evidence, blocked vs successful outcome, HTTP method/status, POST/form signals, content analysis/sandbox evidence, endpoint process evidence, TI classification, and user interaction evidence.
- Explain which evidence is present in Incident Data and which is not available.
- Use exactly 1-2 sentences in reason.
- Sentence 1: observation (repeated proxy/URL/web access attempts, host count, duration, method/status/outcome if available).
- Sentence 2: missing evidence + action (limits confidence + should be monitored/investigated).
- Do not confuse hits with event_count: hits = total observed activity volume, event_count = persisted detection events.
- Repeated URL requests across multiple hosts over extended duration indicate persistent access attempts.
- POST requests may indicate submission behavior but do not prove user submission unless confirmed.
- HTTP 2xx/3xx can suggest successful/redirected access; 401/403/407/4xx limits confidence in successful access.
- Do not claim execution without endpoint/process evidence.
- Do not claim phishing impact without user interaction or TI support.
- Do not claim malware execution without file/process evidence.
- If only proxy evidence exists, explicitly say confidence is limited by what is available in the current telemetry/evidence set.
- Only interpret correlated evidence provided in Incident Data.
- Do not list missing telemetry/product types (endpoint, process, download, sandbox, EDR, content-analysis, payload) unless explicitly present in Incident Data.
- If compromise or execution is not proven by correlated evidence, state that directly without enumerating unavailable telemetry sources.
- Do not use "successful access or persistence" coupling.
- Do not say "no persistence" when duration is high or activity is repeated/prolonged.
- Do not mention blacklist status or internal guardrail/adjustment details.
Return ONLY JSON:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildHashPrompt() {
  return `HASH IOC ANALYSIS RULES:
- Focus on affected_hosts, file_observations, execution evidence, and persistence/spread behavior.
- Do not mention blacklist status.
Increase risk:
- multiple affected hosts
- execution evidence
- persistence or spread over time
Decrease risk:
- single host, very low observations, no spread evidence
Return ONLY JSON:
{ "adjustment": -10 | -5 | 0 | 5 | 10, "confidence": 0-1, "reason": "short explanation" }`;
}

function buildPromptByType(iocType) {
  if (iocType === 'domain') return buildDomainPrompt();
  if (iocType === 'ip') return buildIpPrompt();
  if (iocType === 'url') return buildUrlPrompt();
  if (iocType === 'hash') return buildHashPrompt();
  return buildGenericPrompt();
}

function buildConsistencyRules() {
  return `Global consistency rules:
- Detection Events are normalized detection records and may be used as primary scoring signals.
- Evidence Logs are raw supporting logs captured around the incident window. Do NOT count Evidence Logs as additional Detection Events.
- Use Evidence Logs only for context (DNS query, proxy CONNECT, firewall allow/block, repeated pattern timing, observed hosts).
- Do not increase risk solely because evidence_log_count > detection_event_count.
- Higher evidence_log_count can matter only when it shows meaningful repeated activity over time or across hosts.
- Prefer source/outcome semantics over raw log volume.
- DNS-only signal is weaker; DNS + successful proxy/firewall access from same observed host is stronger than DNS-only.
- Successful network access does not by itself prove compromise or payload execution.
- Do not reduce risk unless you can name a concrete risk-reducing factor.
- High activity, multiple hosts, long duration, persistence, or accepted traffic are never risk-reducing factors by themselves.
- If risk_reducing_factors is empty, risk_adjustment must be >= 0.
- Negative risk_adjustment is allowed only for explicit benign evidence (FP verdict, known internal test, allowlisted/trusted benign IOC, blocked-only with no successful activity and limited scope, or low-confidence IOC source with no meaningful internal activity).
- If evidence is mixed/insufficient, use risk_adjustment=0.
- confidence can be high only when output is internally consistent; use 0.40-0.70 for limited/contradictory evidence.
- Domain DNS resolved IPs may appear in context, but are forensic-only and must not be used as risk-boosting evidence.
- Do not treat domain -> dns_response_ip -> IP chains as accepted/successful evidence for domain risk changes.
- Do not overclaim; use "possible communication" unless evidence is strong.
- Use risk_adjustment range -20..20.
Return ONLY JSON:
{
  "ai_risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "risk_adjustment": -20|-10|-5|0|5|10|15|20,
  "confidence": 0-1,
  "main_risk_drivers": [],
  "risk_reducing_factors": [],
  "reason": "",
  "recommended_action": ""
}`;
}

function normalizeIocType(raw) {
  const t = String(raw || '').toLowerCase();
  if (t === 'ip') return 'ip';
  if (t === 'domain') return 'domain';
  if (t === 'url') return 'url';
  if (['md5', 'sha1', 'sha256', 'hash', 'file_hash'].includes(t)) return 'hash';
  return 'unknown';
}

function parseTags(raw) {
  if (Array.isArray(raw)) return raw.map((x) => String(x)).filter(Boolean);
  if (typeof raw === 'string' && raw.trim()) {
    return raw.split(',').map((x) => x.trim()).filter(Boolean);
  }
  return [];
}

function normalizeVerdict(raw) {
  const v = String(raw || '').toLowerCase();
  if (v === 'fp') return 'fp';
  if (v === 'tp') return 'tp';
  if (v === 'suspicious') return 'suspicious';
  return 'unknown';
}

function buildIncidentPayload(incident = {}) {
  const snapshot = buildIncidentStatsSnapshot(incident);
  const iocType = normalizeIocType(incident?.ioc_type || incident?.observable_type);
  const totalHits = Math.max(Number((incident?.hits ?? incident?.total_hits ?? snapshot.total_events) ?? 0), 0);
  const eventCount = Math.max(Number((incident?.event_count ?? snapshot.total_events) ?? 0), 0);
  const observedHosts = Math.max(Number((incident?.observed_hosts ?? incident?.asset_count ?? snapshot.unique_hosts) ?? 0), 0);
  const firstSeenMs = incident?.first_seen ? new Date(incident.first_seen).getTime() : NaN;
  const lastSeenMs = incident?.last_seen ? new Date(incident.last_seen).getTime() : NaN;
  const durationMinutes = Number.isFinite(firstSeenMs) && Number.isFinite(lastSeenMs) && lastSeenMs >= firstSeenMs
    ? Math.round((lastSeenMs - firstSeenMs) / 60000)
    : 0;

  const evidenceLogCount = Math.max(Number((incident?.evidence_log_count ?? incident?.related_log_count ?? 0) || 0), 0);
  const evidenceSummary = incident?.evidence_summary && typeof incident.evidence_summary === 'object'
    ? incident.evidence_summary
    : {
      note: 'raw evidence samples, not additional detection events',
      source_types: Array.isArray(incident?.evidence_source_types) ? incident.evidence_source_types : [],
      observed_host_count: observedHosts
    };

  const base = {
    incident: {
      id: incident?.incident_id || incident?.id || null,
      ioc: String(incident?.ioc_value || incident?.observable_value || ''),
      ioc_type: iocType,
      risk_before_llm: Number(incident?.risk_score || 0),
      hits: totalHits,
      event_count: eventCount,
      detection_event_count: eventCount,
      evidence_log_count: evidenceLogCount,
      observed_hosts: observedHosts,
      first_seen: incident?.first_seen || null,
      last_seen: incident?.last_seen || null,
      duration_minutes: durationMinutes,
      verdict: String(incident?.verdict || 'unknown').toLowerCase()
    },
    ioc: String(incident?.ioc_value || incident?.observable_value || ''),
    ioc_type: iocType,
    activity_type: iocType === 'domain' ? 'dns' : iocType,
    related_iocs: Array.isArray(incident?.related_iocs) ? incident.related_iocs : [],
    first_seen: incident?.first_seen || null,
    last_seen: incident?.last_seen || null,
    duration_minutes: durationMinutes,
    event_summary: incident?.event_summary || null,
    playbook_coverage: incident?.playbook_coverage || null,
    sample_events: Array.isArray(incident?.sample_events) ? incident.sample_events.slice(0, 10) : [],
    evidence_logs_note: 'Evidence Logs are raw supporting logs, not additional detection events.',
    evidence_log_count: evidenceLogCount,
    evidence_summary: evidenceSummary,
    field_notes: {
      hits: 'total observed IOC matches or activity volume',
      event_count: 'number of persisted detection events',
      detection_event_count: 'normalized detection records used for primary scoring',
      evidence_log_count: 'raw supporting evidence log count; do not treat as additional events',
      evidence_summary: 'context-only summary of raw evidence patterns (dns/proxy/firewall etc.)',
      sample_events: 'examples only, not total counts'
    },
    history: {
      previous_incident_count: Math.max(Number(incident?.previous_incident_count || 0), 0),
      previous_verdict: normalizeVerdict(incident?.previous_verdict)
    }
  };

  if (iocType === 'domain') {
    return {
      ...base,
      stats: {
        total_hits: totalHits,
        hits: totalHits,
        dns_queries: totalHits,
        event_count: eventCount,
        observed_hosts: observedHosts,
        unique_hosts: observedHosts,
        duration_minutes: durationMinutes
      }
    };
  }

  if (iocType === 'ip') {
    return {
      ...base,
      stats: {
        total_hits: totalHits,
        event_count: eventCount,
        observed_hosts: observedHosts,
        unique_hosts: observedHosts,
        accepted_connections: snapshot.accepted_connections,
        blocked_connections: snapshot.blocked_connections,
        inbound_events: Math.max(Number(incident?.inbound_events || 0), 0),
        outbound_events: Math.max(Number(incident?.outbound_events || 0), 0),
        duration_minutes: durationMinutes
      }
    };
  }

  if (iocType === 'url') {
    return {
      ...base,
      stats: {
        total_hits: totalHits,
        event_count: eventCount,
        url_requests: totalHits,
        successful_access: Math.max(Number(incident?.accepted_connections || snapshot.accepted_connections || 0), 0),
        observed_hosts: observedHosts,
        unique_hosts: observedHosts,
        duration_minutes: durationMinutes
      }
    };
  }

  if (iocType === 'hash') {
    return {
      ...base,
      stats: {
        total_hits: totalHits,
        event_count: eventCount,
        file_observations: totalHits,
        affected_hosts: observedHosts,
        execution_evidence: Math.max(Number(incident?.accepted_connections || snapshot.accepted_connections || 0), 0),
        persistence_signals: Math.max(Number(incident?.previous_incident_count || 0), 0),
        duration_minutes: durationMinutes
      }
    };
  }

  return {
    ...base,
    stats: {
      total_hits: totalHits,
      event_count: eventCount,
      observed_hosts: observedHosts,
      unique_hosts: observedHosts,
      accepted_connections: snapshot.accepted_connections,
      blocked_connections: snapshot.blocked_connections,
      duration_minutes: durationMinutes
    }
  };
}

export function createLlmRiskAdvisor({ redis, queue, db } = {}) {
  const enabled = toBool(process.env.LLM_RISK_ADVISOR_ENABLED, false);
  const url = String(process.env.LLM_RISK_ADVISOR_URL || 'http://192.168.1.8:11434/api/generate').trim();
  const model = String(process.env.LLM_RISK_ADVISOR_MODEL || 'qwen2.5:14b').trim();
  const timeoutMs = Math.max(Number(process.env.LLM_RISK_ADVISOR_TIMEOUT_MS || 15000), 1000);
  const manualTimeoutMs = Math.max(Number(process.env.LLM_RISK_ADVISOR_MANUAL_TIMEOUT_MS || 30000), timeoutMs);
  const llmTemperature = Number(process.env.LLM_RISK_TEMPERATURE ?? 0.2);
  const llmNumCtx = Math.max(Number(process.env.LLM_RISK_NUM_CTX ?? 2048), 256);
  const llmNumPredict = Math.max(Number(process.env.LLM_RISK_NUM_PREDICT ?? 180), 1);
  const cacheTtlSeconds = Math.max(Number(process.env.LLM_RISK_ADVISOR_CACHE_TTL_SECONDS || 3600), 30);
  const aiWeight = Math.max(Number(process.env.LLM_RISK_ADVISOR_AI_WEIGHT || 2), 0);

  function computeFinalRisk(baseRisk, adjustment, confidence) {
    const base = clamp(Number(baseRisk || 0), 0, 100);
    const adj = Number(adjustment || 0);
    const conf = clamp(Number(confidence || 0), 0, 1);
    const weighted = adj * conf * aiWeight;
    return clamp(base + weighted, 0, 100);
  }

  function fallback(baseRisk, reason = 'fallback') {
    const base = clamp(Number(baseRisk || 0), 0, 100);
    return {
      risk_before_llm: Number(base.toFixed(2)),
      llm_risk_adjustment: 0,
      llm_risk_confidence: 0,
      llm_risk_reason: reason,
      final_risk_score: Number(base.toFixed(2))
    };
  }

  function getCacheKey(incidentId, version) {
    const id = String(incidentId || '').trim();
    const v = String(version || '').trim();
    if (!id || !v) return null;
    return `risk:llm:incident:${id}:${v}`;
  }

  async function loadPersistedInsight({ incidentId, version }) {
    if (!db || typeof db.query !== 'function') return null;
    const id = String(incidentId || '').trim();
    if (!id) return null;
    try {
      const q = await db.query(
        `SELECT *
         FROM incident_ai_insights
         WHERE incident_id = $1::bigint
           AND ($2::text IS NULL OR insight_version = $2::text)
         ORDER BY llm_last_updated_at DESC, updated_at DESC
         LIMIT 1`,
        [Number(id), version ? String(version) : null]
      );
      return q.rows?.[0] || null;
    } catch (err) {
      console.warn('[llm-cache] persisted insight lookup failed', {
        incident_id: id,
        version: version ? String(version) : null,
        error: err?.message || String(err)
      });
      return null;
    }
  }

  async function getCached({ incidentId, version, baseRisk }) {
    const key = getCacheKey(incidentId, version);
    let raw = null;
    if (key && redis && typeof redis.get === 'function') {
      try { raw = await redis.get(key); } catch {}
    }

    try {
      const parsed = raw ? JSON.parse(raw) : null;
      const persisted = !parsed ? await loadPersistedInsight({ incidentId, version }) : null;
      const source = parsed || (persisted ? {
        llm_risk_adjustment: persisted.llm_risk_adjustment,
        llm_risk_confidence: persisted.llm_risk_confidence,
        llm_risk_reason: persisted.llm_risk_reason,
        llm_related_evidence: persisted.llm_related_evidence,
        raw_model_adjustment: persisted.raw_model_adjustment,
        normalization_reason: persisted.normalization_reason,
        llm_last_updated_at: persisted.llm_last_updated_at,
        llm_version: persisted.insight_version
      } : null);
      if (!source) return null;
      const normalized = normalizeAdvisorOutput(source, 'cache', source?.incident_payload || null);
      let cachedConfidence = Number(normalized?.confidence);
      if (!Number.isFinite(cachedConfidence)) cachedConfidence = Number(source?.llm_risk_confidence ?? source?.confidence ?? 0);
      const cachedIocType = String(source?.ioc_type || source?.incident_payload?.ioc_type || '').toLowerCase();
      const cachedReason = String(normalized?.reason || source?.reason || '');
      if (cachedIocType === 'url' && /(limited evidence|inconclusive|uncertain|insufficient evidence|limits confidence)/i.test(cachedReason)) {
        cachedConfidence = clamp(Math.max(cachedConfidence || 0.5, 0.45), 0.45, 0.65);
      }
      normalized.confidence = cachedConfidence;
      console.info(`[llm-confidence-trace] incident_id=${incidentId} ioc_type=${cachedIocType || 'cache'} model_raw_confidence=${Number(source?.confidence ?? source?.llm_risk_confidence ?? 0)} normalized_confidence=${Number(normalized?.confidence ?? 0)} reason_valid=${String(normalized?.reason || '').startsWith('invalid_reason_') ? 'false' : 'true'} reason_validation_code=${normalized?.normalization_reason || 'cache'} used_fallback_reason=${String(normalized?.reason || '').includes('fallback') ? 'true' : 'false'} is_low_confidence=${Number(normalized?.confidence || 0) < 0.4} effective_adjustment=${Number(normalized?.adjustment || 0)} final_confidence_returned=${Number(normalized?.confidence || 0)} cache_hit=${raw ? 'true' : 'false'} cache_write_value=na`);
      const base = clamp(Number(baseRisk || 0), 0, 100);
      const finalRisk = computeFinalRisk(base, normalized.adjustment, normalized.confidence);

      return {
        risk_before_llm: Number(base.toFixed(2)),
        llm_risk_adjustment: normalized.adjustment,
        llm_risk_confidence: Number(normalized.confidence.toFixed(3)),
        llm_risk_reason: normalized.reason,
        llm_related_evidence: source?.llm_related_evidence || normalized.llm_related_evidence || null,
        raw_model_adjustment: normalized.raw_model_adjustment,
        normalization_reason: normalized.normalization_reason,
        hasAcceptedOrSuccessfulTraffic: normalized.hasAcceptedOrSuccessfulTraffic,
        hasStrongMaliciousContext: normalized.hasStrongMaliciousContext,
        detected_positive_factors: normalized.detected_positive_factors || [],
        detected_negative_factors: normalized.detected_negative_factors || [],
        llm_last_updated_at: source?.llm_last_updated_at || null,
        llm_version: source?.llm_version || version || null,
        final_risk_score: Number(finalRisk.toFixed(2))
      };
    } catch {
      return null;
    }
  }

  async function setCached({ incidentId, version, value }) {
    const key = getCacheKey(incidentId, version);
    if (!key || !redis || typeof redis.set !== 'function') return;
    try {
      await redis.set(key, JSON.stringify(value), 'EX', cacheTtlSeconds);
    } catch {
      // no-op
    }
  }

  async function persistInsight({ incident, version, normalized }) {
    if (!db || typeof db.query !== 'function') return;
    const activityId = String(incident?.id || incident?.incident_id || '').trim();
    if (!activityId || !version) return;
    try {
      await db.query(
        `INSERT INTO incident_ai_insights (
           activity_id, incident_id, insight_version,
           llm_risk_adjustment, llm_risk_confidence, llm_risk_reason,
           llm_related_evidence, raw_model_adjustment, normalization_reason,
           llm_last_updated_at, updated_at
         ) VALUES (
           $1::uuid, $2::bigint, $3::text,
           $4::int, $5::double precision, $6::text,
           $7::jsonb, $8::int, $9::text,
           NOW(), NOW()
         )
         ON CONFLICT (activity_id, insight_version)
         DO UPDATE SET
           llm_risk_adjustment = CASE
             WHEN EXCLUDED.llm_risk_adjustment = 0
               AND incident_ai_insights.llm_risk_adjustment IS NOT NULL
               AND incident_ai_insights.llm_risk_adjustment <> 0
             THEN incident_ai_insights.llm_risk_adjustment
             ELSE EXCLUDED.llm_risk_adjustment
           END,
           llm_risk_confidence = EXCLUDED.llm_risk_confidence,
           llm_risk_reason = EXCLUDED.llm_risk_reason,
           llm_related_evidence = EXCLUDED.llm_related_evidence,
           raw_model_adjustment = EXCLUDED.raw_model_adjustment,
           normalization_reason = EXCLUDED.normalization_reason,
           llm_last_updated_at = NOW(),
           updated_at = NOW()`,
        [
          activityId,
          Number.isFinite(Number(incident?.incident_id)) ? Number(incident.incident_id) : null,
          String(version),
          normalized?.adjustment ?? null,
          Number.isFinite(Number(normalized?.confidence)) ? Number(normalized.confidence) : null,
          normalized?.reason ?? null,
          normalized?.llm_related_evidence ? JSON.stringify(normalized.llm_related_evidence) : null,
          Number.isFinite(Number(normalized?.raw_model_adjustment)) ? Number(normalized.raw_model_adjustment) : null,
          normalized?.normalization_reason ?? null
        ]
      );
    } catch {
      // no-op: cache path still works
    }
  }

  async function enqueueEvaluation({ incidentId, version, reason = 'manual' }) {
    if (!enabled) return false;
    if (!queue || typeof queue.add !== 'function') return false;

    const id = String(incidentId || '').trim();
    const v = String(version || '').trim();
    if (!id || !v) return false;

    try {
      await queue.add(
        'llm-risk-evaluate',
        { incidentId: id, version: v, reason },
        {
          jobId: `llm-risk:${id}:${v}`,
          removeOnComplete: true,
          removeOnFail: 200,
          attempts: 1
        }
      );
      return true;
    } catch {
      return false;
    }
  }

  async function evaluateAndCache({ incident, baseRisk, version, force = false, timeoutMsOverride } = {}) {
    const base = clamp(Number(baseRisk || 0), 0, 100);
    if (!enabled && !force) return fallback(base, 'disabled');

    const verdict = String(incident?.verdict || '').trim().toLowerCase();
    if (verdict === 'fp') {
      const out = fallback(base, 'fp_verdict_guard');
      out.llm_risk_adjustment = 0;
      return out;
    }

    const initialTimeout = Math.max(Number(timeoutMsOverride || timeoutMs), 1000);
    const retryBackoffMs = 5000;
    const secondTimeout = initialTimeout + 5000;

    async function singleAttempt(requestTimeoutMs) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
      try {
        const incidentPayload = buildIncidentPayload(incident);
        const payload = {
          model,
          stream: false,
          format: 'json',
          options: {
            temperature: Number.isFinite(llmTemperature) ? llmTemperature : 0.2,
            num_ctx: llmNumCtx,
            num_predict: llmNumPredict
          },
          prompt: `${buildPromptByType(incidentPayload?.ioc_type)}\n\n${buildConsistencyRules()}\n\nIncident Data:\n${JSON.stringify(incidentPayload, null, 2)}`
        };

        const response = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal
        });

        if (!response.ok) {
          return { ok: false, kind: 'http', reason: `llm_http_${response.status}` };
        }

        const body = await response.json();
        const modelJson = extractJson(body?.response);
        if (!modelJson) {
          return { ok: false, kind: 'parse', reason: 'invalid_json' };
        }

        const normalized = normalizeAdvisorOutput(modelJson, 'ok', incidentPayload);
        console.info(`[llm-confidence-trace] incident_id=${incident?.incident_id || incident?.id || ''} ioc_type=${incidentPayload?.ioc_type || ''} model_raw_confidence=${Number(modelJson?.confidence || 0)} normalized_confidence=${Number(normalized?.confidence || 0)} reason_valid=${String(normalized?.reason || '').startsWith('invalid_reason_') ? 'false' : 'true'} reason_validation_code=${normalized?.normalization_reason || 'ok'} used_fallback_reason=${String(normalized?.reason || '').includes('fallback') ? 'true' : 'false'} is_low_confidence=${Number(normalized?.confidence || 0) < 0.4} effective_adjustment=${Number(normalized?.adjustment || 0)} final_confidence_returned=${Number(normalized?.confidence || 0)} cache_hit=false cache_write_value=pending`);
        return { ok: true, normalized };
      } catch (err) {
        if (isTimeoutError(err)) return { ok: false, kind: 'timeout', reason: 'timeout' };
        return { ok: false, kind: 'network', reason: 'endpoint_unreachable' };
      } finally {
        clearTimeout(timer);
      }
    }

    const first = await singleAttempt(initialTimeout);
    let result = first;

    if (!first.ok && first.kind === 'timeout') {
      await sleep(retryBackoffMs);
      result = await singleAttempt(secondTimeout);
    }

    if (!result.ok) {
      return fallback(base, result.reason || 'fallback');
    }

    const normalized = result.normalized;
    await setCached({
      incidentId: incident?.id || incident?.incident_id,
      version,
      value: {
        ...normalized,
        ioc_type: incident?.ioc_type || null,
        incident_payload: buildIncidentPayload(incident),
        llm_last_updated_at: new Date().toISOString(),
        llm_version: version || null
      }
    });
    await persistInsight({ incident, version, normalized });

    const finalRisk = computeFinalRisk(base, normalized.adjustment, normalized.confidence);
    return {
      risk_before_llm: Number(base.toFixed(2)),
      llm_risk_adjustment: normalized.adjustment,
      llm_risk_confidence: Number(normalized.confidence.toFixed(3)),
      llm_risk_reason: normalized.reason,
      llm_related_evidence: normalized.llm_related_evidence || null,
      raw_model_adjustment: normalized.raw_model_adjustment,
      normalization_reason: normalized.normalization_reason,
      hasAcceptedOrSuccessfulTraffic: normalized.hasAcceptedOrSuccessfulTraffic,
      hasStrongMaliciousContext: normalized.hasStrongMaliciousContext,
      detected_positive_factors: normalized.detected_positive_factors || [],
      detected_negative_factors: normalized.detected_negative_factors || [],
      llm_last_updated_at: new Date().toISOString(),
      llm_version: version || null,
      final_risk_score: Number(finalRisk.toFixed(2))
    };
  }

  function computeVersion(input) {
    const base = buildIncidentVersion(input);
    const related = Array.isArray(input?.related_iocs) ? input.related_iocs : [];
    if (!related.length) return base;

    const relatedRaw = related
      .map((r) => [
        r?.related_ioc || '',
        r?.chain_type || '',
        Number(r?.traffic?.accepted_count || 0),
        r?.related_ioc_in_ioc_list ? 1 : 0
      ].join('|'))
      .sort()
      .join(';');

    const extra = crypto.createHash('sha1').update(relatedRaw).digest('hex').slice(0, 8);
    return `${base}${extra}`.slice(0, 24);
  }

  return {
    enabled,
    timeoutMs,
    manualTimeoutMs,
    fallback,
    computeVersion,
    getCached,
    enqueueEvaluation,
    evaluateAndCache
  };
}
