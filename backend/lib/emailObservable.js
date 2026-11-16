/**
 * Email address observables: one canonical identity for an `email` IOC.
 *
 * Canonical form = `local@domain`, lower-cased, refanged ("alex@x[.]ink",
 * "alex[@]x.ink", "alex [at] x.ink"), without a `mailto:` prefix or angle
 * brackets, the domain in its ASCII (punycode) form. The local part is
 * lower-cased too: providers treat it case-insensitively in practice and the
 * IOC layer already lower-cases every observable it indexes
 * (ioc_observables.observable_value), so `A@x.com` and `a@x.com` are one IOC.
 *
 * Deliberately strict: a dot-atom local part (no quoted strings, no comments),
 * a hostname with at least two labels and an alphabetic TLD. That keeps
 * package specifiers (`axios@1.14.1`, `@scope/pkg@2.0.0`), git remotes
 * (`git@github.com:org/repo`), IP-literal domains and user@host shorthands out.
 */

import { domainToASCII } from 'node:url';

export const EMAIL_OBSERVABLE_VERSION = 'email-observable-v1';

const MAX_EMAIL_LENGTH = 254;
const MAX_LOCAL_LENGTH = 64;
const MAX_DOMAIN_LENGTH = 253;
const LOCAL_PART_RE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/i;
const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i;
/**
 * Special-use / private names (RFC 2606, RFC 6761, mDNS, home networks): an
 * address there is a placeholder or an internal identifier (a browser
 * add-on id "x@extension.local", a certificate template "admin@acme.example"),
 * never an observable anyone can receive mail at.
 */
const RESERVED_DOMAIN_RE = /(?:^|\.)(?:example|invalid|localhost|test|local|localdomain|lan|internal|intranet|corp|home\.arpa)$|(?:^|\.)example\.(?:com|net|org)$/i;
/** A redacted local part ("e*******7", "j***"): the publisher hid the address. */
const REDACTED_LOCAL_RE = /\*/;

/**
 * Undo the defang spellings publishers use for addresses.
 * @param {string} raw
 */
export function refangEmail(raw) {
  return String(raw || '')
    .replace(/[​-‍⁠﻿]/g, '')
    .trim()
    .replace(/^mailto:/i, '')
    .replace(/^<(.*)>$/, '$1')
    .replace(/\s*(?:\[\s*@\s*\]|\(\s*@\s*\)|\{\s*@\s*\}|\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\})\s*/gi, '@')
    .replace(/\s*(?:\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\))\s*/gi, '.')
    .trim();
}

/**
 * @param {string} raw
 * @returns {{ ok: true, type: 'email', value: string, local: string, domain: string }
 *   | { ok: false, error: string }}
 */
export function parseEmailObservable(raw) {
  const v = refangEmail(raw);
  if (!v) return { ok: false, error: 'Email address is empty' };
  if (v.length > MAX_EMAIL_LENGTH) return { ok: false, error: 'Email address is too long' };
  const at = v.indexOf('@');
  if (at <= 0 || at !== v.lastIndexOf('@')) return { ok: false, error: 'Not an email address' };
  const local = v.slice(0, at);
  const rawDomain = v.slice(at + 1).replace(/\.$/, '');
  if (local.length > MAX_LOCAL_LENGTH || !LOCAL_PART_RE.test(local)) {
    return { ok: false, error: 'Invalid email local part' };
  }
  if (REDACTED_LOCAL_RE.test(local)) return { ok: false, error: 'Redacted email address' };
  if (!rawDomain || /[\s/:\\[\]]/.test(rawDomain)) return { ok: false, error: 'Invalid email domain' };
  const domain = domainToASCII(rawDomain.toLowerCase());
  if (!domain || domain.length > MAX_DOMAIN_LENGTH) return { ok: false, error: 'Invalid email domain' };
  const labels = domain.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL_RE.test(l)) || !TLD_RE.test(labels[labels.length - 1])) {
    return { ok: false, error: 'Invalid email domain' };
  }
  if (RESERVED_DOMAIN_RE.test(domain)) return { ok: false, error: 'Reserved email domain' };
  const value =`${local.toLowerCase()}@${domain}`;
  return { ok: true, type: 'email', value, local: local.toLowerCase(), domain };
}

/** @param {string} raw */
export function isEmailObservable(raw) {
  return parseEmailObservable(raw).ok === true;
}

/**
 * Canonical email identity or '' when the value is not an address.
 * @param {string} raw
 */
export function normalizeEmailObservable(raw) {
  const parsed = parseEmailObservable(raw);
  return parsed.ok ? parsed.value : '';
}
