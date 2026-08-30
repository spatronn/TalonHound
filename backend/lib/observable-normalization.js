export function normalizeUrlForMatch(value, opts = {}) {
  const dropHash = opts.dropHash !== false;
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const u = new URL(raw);
    const protocol = String(u.protocol || '').toLowerCase();
    const hostname = String(u.hostname || '').toLowerCase();
    let port = String(u.port || '');
    if ((protocol === 'http:' && port === '80') || (protocol === 'https:' && port === '443')) port = '';

    let pathname = u.pathname || '';
    if (!pathname) pathname = '/';

    const search = u.search || '';
    const hash = dropHash ? '' : (u.hash || '');
    const auth = u.username ? `${u.username}${u.password ? `:${u.password}` : ''}@` : '';
    const hostPort = port ? `${hostname}:${port}` : hostname;
    return `${protocol}//${auth}${hostPort}${pathname}${search}${hash}`;
  } catch {
    return raw;
  }
}

export function normalizeObservable(type, value) {
  const t = String(type || '').toLowerCase();
  const v = String(value || '').trim();
  if (!v) return '';
  if (t === 'url') return normalizeUrlForMatch(v);
  if (t === 'domain') return v.toLowerCase();
  return v;
}
