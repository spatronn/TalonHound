import React, { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import axios from 'axios';
import { ComposableMap, Geographies, Geography, ZoomableGroup } from 'react-simple-maps';

const CSRF_COOKIE_NAME = 'demo_csrf';

function readCookie(name) {
  const parts = `; ${document.cookie}`.split(`; ${name}=`);
  if (parts.length === 2) return decodeURIComponent(parts.pop().split(';').shift() || '');
  return '';
}

const api = axios.create({ baseURL: '/api', withCredentials: true });

api.interceptors.request.use((config) => {
  const method = String(config.method || 'get').toLowerCase();
  if (['post', 'put', 'patch', 'delete'].includes(method)) {
    const csrf = readCookie(CSRF_COOKIE_NAME);
    if (csrf) {
      config.headers = config.headers || {};
      config.headers['X-CSRF-Token'] = csrf;
    }
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const url = String(err.config?.url || '');
    const st = err.response?.status;
    if ((st === 401 || st === 403) && !url.includes('/auth/login')) {
      if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
        window.location.assign('/login');
      }
    }
    return Promise.reject(err);
  }
);

const SessionContext = React.createContext({
  authState: 'loading',
  userEmail: '',
  userId: null,
  role: 'admin',
  canWrite: true,
  refreshSession: async () => {}
});

function SessionProvider({ children }) {
  const [authState, setAuthState] = useState('loading');
  const [userEmail, setUserEmail] = useState('');
  const [userId, setUserId] = useState(null);
  const [role, setRole] = useState('admin');

  const refreshSession = useCallback(async () => {
    try {
      const { data } = await api.get('/auth/me');
      const u = data?.user || {};
      const em = String(u.email || '');
      if (em) {
        setUserEmail(em);
        setUserId(u.id != null ? String(u.id) : null);
        setRole(String(u.role || 'admin'));
        setAuthState('authed');
      } else {
        setAuthState('anon');
      }
    } catch {
      setAuthState('anon');
      setUserEmail('');
      setUserId(null);
      setRole('admin');
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  const canWrite = role !== 'readonly';
  const value = useMemo(
    () => ({ authState, userEmail, userId, role, canWrite, refreshSession }),
    [authState, userEmail, userId, role, canWrite, refreshSession]
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

function useSession() {
  return useContext(SessionContext);
}

const COMMON_TIMEZONES = [
  'UTC',
  'Europe/Istanbul',
  'Europe/Berlin',
  'Europe/London',
  'America/New_York',
  'Asia/Dubai'
];

const FILE_HASH_TYPES = new Set(['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);

function formatUserDateTime(value) {
  if (!value && value !== 0) return '-';
  const timeZone = localStorage.getItem('demo_timezone') || 'UTC';

  let dt;
  if (value instanceof Date) {
    dt = value;
  } else if (typeof value === 'number') {
    const ms = value > 1e12 ? value : value * 1000;
    dt = new Date(ms);
  } else {
    const raw = String(value).trim();
    if (!raw) return '-';

    if (/^\d+$/.test(raw)) {
      const num = Number(raw);
      const ms = num > 1e12 ? num : num * 1000;
      dt = new Date(ms);
    } else {
      const hasTz = /([zZ]|[+\-]\d{2}:?\d{2})$/.test(raw);
      const normalized = raw.includes(' ') ? raw.replace(' ', 'T') : raw;
      dt = new Date(hasTz ? normalized : `${normalized}Z`);
    }
  }

  if (Number.isNaN(dt.getTime())) return '-';

  return dt.toLocaleString('en-GB', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

function sanitizeSourceNote(note) {
  const raw = String(note || '').trim();
  if (!raw) return '-';

  const duplicateFileInfoKeys = new Set([
    'file_name',
    'file_type',
    'mime',
    'md5',
    'sha1',
    'sha256',
    'imphash',
    'tlsh',
    'ssdeep'
  ]);

  const filtered = raw
    .split('|')
    .map((p) => p.trim())
    .filter(Boolean)
    .filter((part) => {
      const idx = part.indexOf('=');
      if (idx <= 0) return true;
      const key = part.slice(0, idx).trim().toLowerCase();
      return !duplicateFileInfoKeys.has(key);
    });

  return filtered.length ? filtered.join(' | ') : '-';
}

function normalizeEventContext(event) {
  const sourceType = String(event?.source_type || '').toLowerCase();
  const parserSource = String(event?.parser_source || '').toLowerCase();
  const match = event?.match_context || {};
  const lab = String(event?.context_label || '');
  const v2famEarly = String(event?.v2_context?.event_family || '').toLowerCase();
  if (lab === 'DNS' && v2famEarly === 'proxy') return 'Proxy';

  if (event?.context_label) return String(event.context_label);
  if (event?.inferred_context) return String(event.inferred_context);

  const labelFromFamily = (fam) => {
    const f = String(fam || '').toLowerCase();
    if (f === 'proxy') return 'Proxy';
    if (f === 'dns') return 'DNS';
    if (f === 'firewall') return 'Firewall';
    if (f === 'waf') return 'WAF';
    if (f === 'endpoint') return 'Endpoint';
    return '';
  };
  const topFam = labelFromFamily(event?.event_family);
  if (topFam) return topFam;
  const v2Fam = labelFromFamily(event?.v2_context?.event_family);
  if (v2Fam) return v2Fam;

  const v2Control = String(event?.control_point || event?.v2_context?.control_point || '').toLowerCase();
  if (v2Control === 'proxy') return 'Proxy';
  if (v2Control === 'dns_resolver' || v2Control === 'dns') return 'DNS';
  if (v2Control === 'firewall') return 'Firewall';

  const norm = event?.normalized_event_json || {};

  const proxySource = /(proxy|web|url)/i.test(sourceType) || /(proxy|squid|web|url|http)/i.test(parserSource);
  const proxyFields = [norm?.url, norm?.http_host, norm?.request_url, norm?.method, norm?.status_code, match?.url, match?.http_host, match?.request_url]
    .some((v) => String(v || '').trim() !== '');
  if (proxySource || proxyFields) return 'Proxy';

  const dnsParser = /(dns|microsoft_dns|bind_dns|dns_debug|microsoft_dns_debug|dns_kv)/i.test(parserSource);
  const dnsSource = sourceType === 'dns';
  const dnsFields = [match?.ioc_query, match?.query_type, match?.response_ip, norm?.query, norm?.dns_query, norm?.domain_query]
    .some((v) => String(v || '').trim() !== '');
  if (dnsParser || dnsSource || dnsFields) return 'DNS';

  const firewallSource = /(firewall|traffic)/i.test(sourceType) || /(fortigate|firewall|traffic|paloalto|pan-os|checkpoint|netflow)/i.test(parserSource);
  const trafficFields = [match?.srcip, match?.dstip, match?.dstport, match?.proto, match?.action, norm?.src_ip, norm?.dst_ip, norm?.destination_port]
    .some((v) => String(v || '').trim() !== '');
  if (firewallSource || trafficFields) return 'Firewall';

  if (sourceType === 'waf' || /(waf|f5|asm|modsecurity|nginx-waf)/i.test(parserSource)) return 'WAF';
  if (sourceType === 'endpoint' || /(endpoint|edr|xdr|sysmon)/i.test(parserSource)) return 'Endpoint';

  const tokens = [
    event?.type,
    event?.log_type,
    event?.parser_type,
    event?.source_type,
    event?.context,
    event?.v2_context?.event_family,
    event?.v2_context?.control_point,
    event?.v2_context?.scenario_type,
    event?.matched_syslog_event
  ]
    .map((v) => String(v || '').toLowerCase())
    .filter(Boolean)
    .join(' ');

  if (/(proxy|url|http|webproxy|secure web gateway|swg)/i.test(tokens)) return 'Proxy';
  if (/(^|\s)dns(\s|$)|resolver|query_type|resolved_ip/i.test(tokens)) return 'DNS';
  if (/(waf|f5|asm|application firewall|modsecurity|nginx-waf)/i.test(tokens)) return 'WAF';
  if (/(endpoint|edr|xdr|process|file[_\s-]?event|sysmon)/i.test(tokens)) return 'Endpoint';
  if (/(firewall|traffic|fortigate|forti|paloalto|pan-os|checkpoint|netflow|forward)/i.test(tokens)) return 'Firewall';

  if ((sourceType === 'generic' || sourceType === '') && (parserSource === 'unknown' || parserSource === '')) return 'Generic';
  return 'Generic';
}

function LoginPage() {
  const navigate = useNavigate();
  const { refreshSession } = useSession();

  async function onSubmit(e) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const email = form.get('email');
    const password = form.get('password');

    try {
      await api.post('/auth/login', { email, password });
      localStorage.removeItem('demo_timezone');
      await refreshSession();
      navigate('/analytics');
    } catch (err) {
      const msg = err?.response?.data?.message || 'Invalid email or password';
      alert(msg);
    }
  }

  return (
    <div style={{ maxWidth: 360, margin: '80px auto', fontFamily: 'sans-serif' }}>
      <h2>Demo Login</h2>
      <form onSubmit={onSubmit}>
        <input name="email" type="text" placeholder="username or email" autoComplete="username" required style={{ width: '100%', marginBottom: 8, padding: 8 }} />
        <input name="password" type="password" placeholder="password" autoComplete="current-password" required style={{ width: '100%', marginBottom: 8, padding: 8 }} />
        <button type="submit" style={{ width: '100%', padding: 10 }}>Sign In</button>
      </form>
      <p style={{ fontSize: 12, color: '#555' }}>Demo user: demo@demo.local / Password1!</p>
    </div>
  );
}

function AppShell({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { userEmail, role, canWrite, refreshSession } = useSession();
  const [timezone, setTimezone] = useState(localStorage.getItem('demo_timezone') || 'UTC');
  const [needsTimezoneSelection, setNeedsTimezoneSelection] = useState(false);

  useEffect(() => {
    let mounted = true;
    async function loadPreference() {
      try {
        const { data } = await api.get('/users/me/preferences');
        if (!mounted) return;

        if (data?.timezone) {
          localStorage.setItem('demo_timezone', data.timezone);
          setTimezone(data.timezone);
          setNeedsTimezoneSelection(false);
        } else {
          setNeedsTimezoneSelection(true);
        }
      } catch {
        if (!localStorage.getItem('demo_timezone')) {
          setNeedsTimezoneSelection(true);
        }
      }
    }

    loadPreference();
    return () => {
      mounted = false;
    };
  }, []);

  async function saveTimezone(value) {
    try {
      const { data } = await api.put('/users/me/preferences', { timezone: value });
      const tz = data?.timezone || value;
      localStorage.setItem('demo_timezone', tz);
      setTimezone(tz);
      setNeedsTimezoneSelection(false);
    } catch {
      alert('Failed to save timezone');
    }
  }

  async function logout() {
    try {
      await api.post('/auth/logout');
    } catch {
      /* still leave app */
    }
    await refreshSession();
    navigate('/login');
  }

  const isActive = (path) => location.pathname === path;
  const isOpsActive = location.pathname.startsWith('/ioc');
  const isIntegrationsActive = location.pathname.startsWith('/threat-intelligence');

  const menuStyle = (active) => ({
    display: 'block',
    padding: '10px 12px',
    borderRadius: 6,
    textDecoration: 'none',
    color: active ? '#e2e8f0' : '#cbd5e1',
    background: active ? '#334155' : 'transparent',
    fontWeight: active ? 600 : 500
  });

  const subMenuStyle = (active) => ({
    display: 'block',
    padding: '8px 10px',
    marginLeft: 8,
    borderRadius: 6,
    textDecoration: 'none',
    color: active ? '#e2e8f0' : '#94a3b8',
    background: active ? '#1e293b' : 'transparent',
    fontSize: 14
  });

  return (
    <div style={{ width: '100%', margin: '16px 0', fontFamily: 'sans-serif', display: 'flex', gap: 16, alignItems: 'flex-start', padding: '0 16px', boxSizing: 'border-box' }}>
      <aside style={{ flex: '0 0 240px', border: '1px solid #e5e5e5', borderRadius: 10, padding: 12, height: 'fit-content', position: 'sticky', top: 16, background: '#fff' }}>
        <div style={{ marginBottom: 14, fontSize: 14 }}>User: <b>{userEmail || 'demo user'}</b> <span style={{ color: '#94a3b8' }}>({role})</span></div>

        <nav>
          <Link to="/system" style={menuStyle(isActive('/system'))}>0. System</Link>
          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(location.pathname.startsWith('/analytics'))}>2. Analytics</div>
            <Link to="/analytics" style={subMenuStyle(isActive('/analytics'))}>Overview</Link>
            <Link to="/analytics/statistics" style={subMenuStyle(isActive('/analytics/statistics'))}>Statistics</Link>
            <Link to="/analytics/detection-events" style={subMenuStyle(isActive('/analytics/detection-events'))}>Detection Events</Link>
            <Link to="/risk-overview" style={subMenuStyle(isActive('/risk-overview'))}>Risk Overview</Link>
          </div>
          <Link to="/incidents" style={menuStyle(location.pathname.startsWith('/incidents'))}>3. Incidents</Link>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(isOpsActive)}>4. Operations</div>
            <Link to="/ioc" style={subMenuStyle(isActive('/ioc'))}>IOC List</Link>
            <Link to="/ioc/hot" style={subMenuStyle(isActive('/ioc/hot'))}>Hot IOC List</Link>
            {canWrite ? (
              <Link to="/ioc/new" style={subMenuStyle(isActive('/ioc/new'))}>Add IOC</Link>
            ) : (
              <span style={{ ...subMenuStyle(false), opacity: 0.45, cursor: 'not-allowed' }} title="Read-only role">Add IOC</span>
            )}
          </div>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(isIntegrationsActive)}>5. Threat Intelligence</div>
            <Link to="/threat-intelligence/feeds" style={subMenuStyle(isActive('/threat-intelligence/feeds') || isActive('/threat-intelligence'))}>Feeds</Link>
            <Link to="/threat-intelligence/enrichment" style={subMenuStyle(isActive('/threat-intelligence/enrichment'))}>Enrichment</Link>
            <Link to="/threat-intelligence/queue" style={subMenuStyle(isActive('/threat-intelligence/queue'))}>Job Queue Status</Link>
            <Link to="/threat-intelligence/runs" style={subMenuStyle(isActive('/threat-intelligence/runs'))}>Recent Runs</Link>
            <Link to="/threat-intelligence/published-feeds" style={subMenuStyle(isActive('/threat-intelligence/published-feeds'))}>Published Feeds</Link>
          </div>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(location.pathname.startsWith('/administration'))}>6. Administration</div>
            <Link to="/administration" style={subMenuStyle(isActive('/administration') && !isActive('/administration/api-keys'))}>Settings</Link>
            <Link to="/administration/api-keys" style={subMenuStyle(isActive('/administration/api-keys'))}>API Keys</Link>
            <Link to="/administration/enrichment-providers" style={subMenuStyle(isActive('/administration/enrichment-providers'))}>Enrichment Providers</Link>
          </div>
        </nav>

        <div style={{ marginTop: 16, fontSize: 12, color: '#475569' }}>Timezone: <b>{timezone}</b></div>
        <button onClick={logout} style={{ marginTop: 10, width: '100%', padding: 9 }}>Logout</button>
      </aside>

      <main style={{ flex: 1, minWidth: 0 }}>
        {children}
      </main>

      {needsTimezoneSelection && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}>
          <div style={{ width: 440, maxWidth: '96vw', background: 'linear-gradient(180deg, #111827 0%, #0f172a 100%)', borderRadius: 14, padding: 20, border: '1px solid #334155', boxShadow: '0 24px 60px rgba(2,6,23,0.55)' }}>
            <h3 style={{ margin: '0 0 8px', color: '#f8fafc', fontSize: 22, fontWeight: 700 }}>Select Timezone</h3>
            <p style={{ fontSize: 14, color: '#94a3b8', margin: '0 0 14px' }}>This is required once. You can change it later from Administration.</p>
            <select
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              style={{
                width: '100%',
                height: 42,
                borderRadius: 10,
                border: '1px solid #334155',
                background: '#0b1220',
                color: '#e2e8f0',
                padding: '0 12px',
                marginBottom: 12,
                outline: 'none'
              }}
            >
              {COMMON_TIMEZONES.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
            </select>
            <button
              type="button"
              onClick={() => saveTimezone(timezone)}
              style={{
                width: '100%',
                height: 42,
                borderRadius: 10,
                border: '1px solid #2563eb',
                background: 'linear-gradient(180deg, #3b82f6 0%, #2563eb 100%)',
                color: '#eff6ff',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Save Timezone
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function DashboardPage() {
  const [mapData, setMapData] = useState({ total: 0, unique_ips: 0, countries: [], snapshot_time: null, note: '' });
  const [hoverInfo, setHoverInfo] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [center, setCenter] = useState([0, 12]);

  useEffect(() => {
    api.get('/ioc/map/countries', { params: { day: 'all' } })
      .then(({ data }) => setMapData({
        total: data?.total || 0,
        unique_ips: data?.unique_ips || 0,
        countries: data?.countries || [],
        snapshot_time: data?.snapshot_time || null,
        note: data?.note || ''
      }))
      .catch(() => setMapData({ total: 0, unique_ips: 0, countries: [], snapshot_time: null, note: '' }));
  }, []);

  const normalizeCode = (value) => String(value || '').trim().toUpperCase();
  const normalizeName = (value) => String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');

  const countryCounts = mapData.countries.reduce((acc, row) => {
    acc[normalizeCode(row.country_code)] = row.total;
    return acc;
  }, {});

  const displayNames = typeof Intl !== 'undefined' && Intl.DisplayNames
    ? new Intl.DisplayNames(['en'], { type: 'region' })
    : null;

  const countryNameCounts = {};
  for (const [code, count] of Object.entries(countryCounts)) {
    try {
      const n = displayNames?.of(code);
      if (n) countryNameCounts[normalizeName(n)] = count;
    } catch {}
  }
  countryNameCounts.unitedstates = countryCounts.US || 0;
  countryNameCounts.unitedstatesofamerica = countryCounts.US || 0;
  countryNameCounts.russia = countryCounts.RU || 0;
  countryNameCounts.russianfederation = countryCounts.RU || 0;
  countryNameCounts.iran = countryCounts.IR || 0;
  countryNameCounts.iranislamicrepublicof = countryCounts.IR || 0;
  countryNameCounts.southkorea = countryCounts.KR || 0;
  countryNameCounts.republicofkorea = countryCounts.KR || 0;
  countryNameCounts.korearepublicof = countryCounts.KR || 0;

  const maxCount = Math.max(...Object.values(countryCounts), 0);

  const countryColor = (count) => {
    if (!count || maxCount === 0) return '#0f172a';
    const ratio = count / maxCount;
    if (ratio <= 0.2) return '#fde047';
    if (ratio <= 0.4) return '#facc15';
    if (ratio <= 0.6) return '#fb923c';
    if (ratio <= 0.8) return '#f97316';
    return '#ef4444';
  };

  const resolveCountryCount = (geo) => {
    const p = geo.properties || {};
    const geoName = p.name || p.ADMIN || 'Unknown';
    const key = normalizeName(geoName);

    if (
      key === 'us'
      || key === 'usa'
      || key === 'unitedstates'
      || key === 'unitedstatesofamerica'
      || key.includes('unitedstates')
    ) return countryCounts.US || 0;

    if (key.includes('russia') || key.includes('russianfederation')) return countryCounts.RU || 0;
    if (key.includes('iran')) return countryCounts.IR || 0;
    if (key.includes('korea')) return countryCounts.KR || 0;

    return countryNameCounts[key] || 0;
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16 }}>
        <h2 style={{ marginTop: 0 }}>Threat World Map</h2>
        <div style={{ marginBottom: 12, fontSize: 15 }}>
          Total records in snapshot: <b style={{ fontSize: 22 }}>{mapData.total}</b>
          <span style={{ marginLeft: 10, color: '#94a3b8' }}>| Unique IPs: <b>{mapData.unique_ips}</b></span>
        </div>
        <div style={{ marginBottom: 10, fontSize: 13, color: '#94a3b8' }}>
          {mapData.snapshot_time ? `As of ${new Date(mapData.snapshot_time).toLocaleString()}, this view reflects the last 24 hours of processed IOC data.` : 'Snapshot is being prepared from processed IOC data.'}
        </div>
        <div style={{ marginBottom: 12, fontSize: 13, color: '#94a3b8' }}>
          {mapData.note || 'This dashboard is refreshed once per day around midnight in server local time while new IOC data continues to be processed in the background.'}
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
          <button onClick={() => setZoom((z) => Math.max(1, Number((z - 0.2).toFixed(2))))}>- Zoom out</button>
          <button onClick={() => setZoom((z) => Math.min(4, Number((z + 0.2).toFixed(2))))}>+ Zoom in</button>
          <button onClick={() => { setZoom(1); setCenter([0, 12]); }}>Reset</button>
        </div>

        <div style={{ border: '1px solid #334155', borderRadius: 10, background: '#0b1220', padding: 8, position: 'relative' }}>
          <ComposableMap projectionConfig={{ scale: 155 }} width={1080} height={420} style={{ width: '100%', height: 'auto', display: 'block' }}>
            <ZoomableGroup
              zoom={zoom}
              center={center}
              onMoveEnd={({ zoom: nextZoom, coordinates }) => {
                setZoom(nextZoom);
                setCenter(coordinates);
              }}
            >
              <Geographies geography="/world-lite.geojson">
                {({ geographies }) => geographies.map((geo) => {
                  const count = resolveCountryCount(geo);
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={countryColor(count)}
                      stroke="#475569"
                      strokeWidth={0.35}
                      onMouseEnter={() => setHoverInfo({
                        name: geo.properties?.name || geo.properties?.ADMIN || 'Unknown',
                        countryCount: count,
                        globalTotal: mapData.total
                      })}
                      onMouseLeave={() => setHoverInfo(null)}
                      style={{
                        default: { outline: 'none' },
                        hover: { outline: 'none', opacity: 0.85 },
                        pressed: { outline: 'none' }
                      }}
                    />
                  );
                })}
              </Geographies>
            </ZoomableGroup>
          </ComposableMap>

          {hoverInfo && (
            <div style={{ position: 'absolute', right: 10, top: 10, background: '#0f172a', color: '#fff', padding: '8px 10px', borderRadius: 8, fontSize: 13 }}>
              <div><b>{hoverInfo.name}</b></div>
              <div>Total in 24h snapshot: <b>{hoverInfo.globalTotal}</b></div>
              <div>Country count: <b>{hoverInfo.countryCount}</b></div>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 10, fontSize: 13, color: '#475569' }}>
          <span>Low</span>
          <div style={{ height: 10, width: 180, background: 'linear-gradient(90deg, #fde047 0%, #fb923c 50%, #ef4444 100%)', borderRadius: 999 }} />
          <span>High</span>
        </div>
      </section>
    </AppShell>
  );
}


function AnalyticsPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [iocLoading, setIocLoading] = useState(false);
  const [sources, setSources] = useState([]);
  const [rawEvents, setRawEvents] = useState([]);
  const [iocMatches, setIocMatches] = useState([]);

  async function loadIocMatches() {
    setIocLoading(true);
    try {
      const { data } = await api.get('/analytics/ioc-matches', { params: { limit: 10 } });
      setIocMatches(data?.items || []);
    } catch {
      setIocMatches([]);
    } finally {
      setIocLoading(false);
    }
  }

  async function loadSources() {
    setLoading(true);
    try {
      const [{ data: sourceData }, { data: rawData }] = await Promise.all([
        api.get('/analytics/data-sources'),
        api.get('/analytics/raw-events', { params: { limit: 10 } })
      ]);
      setSources(sourceData?.sources || []);
      setRawEvents(rawData?.items || []);
    } catch {
      setSources([]);
      setRawEvents([]);
    } finally {
      setLoading(false);
    }

    loadIocMatches().catch(() => {});
  }

  useEffect(() => {
    loadSources().catch(() => {});
  }, []);

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
          <div>
            <h2 style={{ marginTop: 0, marginBottom: 6 }}>Analytics</h2>
            <p style={{ color: '#94a3b8', margin: 0 }}>Current telemetry coverage overview.</p>
          </div>
          <button onClick={() => loadSources().catch(() => {})}>Refresh</button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginTop: 12 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 12, padding: 14, background: '#0f172a' }}>
            <div style={{ fontSize: 13, color: '#94a3b8' }}>Connected Data Sources</div>
            <div style={{ fontSize: 34, fontWeight: 800, marginTop: 6 }}>{loading ? '-' : sources.length}</div>
            <div style={{ fontSize: 13, color: '#cbd5e1', marginTop: 4 }}>
              {loading ? 'Loading...' : (sources.length ? `${sources[0].name} (${sources[0].platform}) ${sources[0].status}` : 'No active source')}
            </div>
          </div>
        </div>

        <div style={{ marginTop: 16, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                <th>Source</th>
                <th>Platform</th>
                <th>Status</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={4} style={{ color: '#94a3b8' }}>Loading data sources...</td></tr>
              ) : sources.length ? sources.map((source) => (
                <tr key={source.key} style={{ borderTop: '1px solid #334155' }}>
                  <td>{source.name}</td>
                  <td>{source.platform}</td>
                  <td style={{ color: source.status === 'active' ? '#22c55e' : '#f59e0b', fontWeight: 700 }}>{source.status}</td>
                  <td>{formatUserDateTime(source.last_seen_at)}</td>
                </tr>
              )) : (
                <tr><td colSpan={4} style={{ color: '#94a3b8' }}>No data sources connected yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 16, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>
            Last 10 Raw Events
          </div>
          <table width="100%" cellPadding="10" style={{ borderCollapse: "collapse", tableLayout: "fixed" }}>
            <thead>
              <tr style={{ textAlign: "left", background: "#111827" }}>
                <th style={{ width: 190 }}>Received At</th>
                <th style={{ width: 180 }}>Source</th>
                <th>Raw Event</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={3} style={{ color: "#94a3b8" }}>Loading raw events...</td></tr>
              ) : rawEvents.length ? rawEvents.map((evt) => (
                <tr key={evt.id} style={{ borderTop: "1px solid #334155" }}>
                  <td style={{ whiteSpace: "nowrap" }}>{formatUserDateTime(evt.received_at || evt.event_time || evt.created_at)}</td>
                  <td>{evt.source_key || evt.source || evt.source_ip || "-"}</td>
                  <td style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{evt.raw_event || evt.raw?.raw_event || "-"}</td>
                </tr>
              )) : (
                <tr><td colSpan={3} style={{ color: "#94a3b8" }}>No raw events yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 16, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>
            Last 10 Detection Events
          </div>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                <th style={{ width: 80 }}>ID</th>
                <th style={{ width: 170 }}>Detected At</th>
                <th style={{ width: 220 }}>Matched IOC</th>
                <th style={{ width: 140 }}>Detection</th>
                <th style={{ width: 140 }}>Verdict</th>
                <th style={{ width: 140 }}>Assignee</th>
                <th style={{ width: 180 }}>Source</th>
                <th style={{ width: 120 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {iocLoading ? (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>Loading IOC matches...</td></tr>
              ) : iocMatches.length ? iocMatches.map((evt) => {
                const verdict = String(evt.verdict || '').toLowerCase();
                const vm = verdict === 'fp'
                  ? { label: 'FP', color: '#ef4444' }
                  : verdict === 'tp'
                    ? { label: 'TP', color: '#22c55e' }
                    : verdict === 'suspicious'
                      ? { label: 'Suspicious', color: '#f59e0b' }
                      : verdict === 'in_progress'
                        ? { label: 'In Progress', color: '#f59e0b' }
                        : { label: 'Unreviewed', color: '#94a3b8' };
                return (
                  <tr key={`ioc-${evt.id}-${evt.event_time}`} style={{ borderTop: '1px solid #334155' }}>
                    <td>{evt.id}</td>
                    <td>{formatUserDateTime(evt.detected_at || evt.last_seen_at || evt.event_time || evt.created_at)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{evt.matched_ioc || '-'}</td>
                    <td>
                      <span style={{
                        display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${evt.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e'}`,
                        color: evt.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e', background: '#020617'
                      }}>
                        {evt.detection_mode === 'retroactive' ? 'Retroactive Match' : 'Real-Time Match'}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${vm.color}`, color: vm.color, background: '#020617'
                      }}>{vm.label}</span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{evt.assigned_to || 'Unassigned'}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {evt.source_count > 1
                        ? `${(evt.source_names && evt.source_names[0]) || evt.source_name || '-'} +${evt.source_count - 1}`
                        : ((evt.source_names && evt.source_names[0]) || evt.source_name || '-')}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button onClick={() => navigate(`/analytics/detection-events/${evt.id}`)} title="View detail" aria-label="View detail" style={{ minWidth: 32, padding: '4px 8px' }}>🔍</button>
                        <button onClick={() => navigate(`/analytics/detection-events/${evt.id}`)} title="Review verdict" aria-label="Review verdict" style={{ minWidth: 32, padding: '4px 8px' }}>✏️</button>
                      </div>
                    </td>
                  </tr>
                );
              }) : (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>No detection events yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}

function AnalyticsStatisticsPage() {
  const [loading, setLoading] = useState(true);
  const [hours, setHours] = useState(24);
  const [topSources, setTopSources] = useState([]);
  const [topClients, setTopClients] = useState([]);
  const [riskyClients, setRiskyClients] = useState([]);
  const [timeline, setTimeline] = useState([]);

  async function loadStats(targetHours = hours) {
    setLoading(true);
    try {
      const { data } = await api.get('/analytics/statistics', { params: { hours: targetHours } });
      setTopSources(data?.top_sources || []);
      setTopClients(data?.top_clients || []);
      setRiskyClients(data?.risky_clients || []);
      setTimeline(data?.timeline || []);
    } catch {
      setTopSources([]);
      setTopClients([]);
      setRiskyClients([]);
      setTimeline([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadStats(24).catch(() => {});
  }, []);

  const maxSource = Math.max(...topSources.map((x) => Number(x.event_count ?? x.events ?? 0)), 1);
  const maxClient = Math.max(...topClients.map((x) => Number(x.event_count ?? x.events ?? 0)), 1);
  const maxRiskyClient = Math.max(...riskyClients.map((x) => Number(x.risky_event_count || 0)), 1);

  const timelineByBucket = timeline.reduce((acc, row) => {
    const key = formatUserDateTime(row.bucket || row.hour);
    acc[key] = (acc[key] || 0) + Number(row.event_count ?? row.events ?? 0);
    return acc;
  }, {});

  const timelineRows = Object.entries(timelineByBucket).slice(-12);
  const maxTimeline = Math.max(...timelineRows.map(([, v]) => Number(v || 0)), 1);

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <div>
            <h2 style={{ margin: 0 }}>Analytics Statistics</h2>
            <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 4 }}>Top active source and client activity overview.</div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
              <option value={6}>Last 6h</option>
              <option value={24}>Last 24h</option>
              <option value={48}>Last 48h</option>
              <option value={72}>Last 72h</option>
            </select>
            <button onClick={() => loadStats(hours).catch(() => {})}>Refresh</button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12 }}>
            <h3 style={{ marginTop: 0 }}>Top Active Sources</h3>
            {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
              <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                    <th>Source</th>
                    <th>Events</th>
                    <th>Activity</th>
                  </tr>
                </thead>
                <tbody>
                  {topSources.length ? topSources.map((row) => {
                    const count = Number(row.event_count ?? row.events ?? 0);
                    const w = Math.max(6, Math.round((count / maxSource) * 100));
                    return (
                      <tr key={row.source_key || row.source} style={{ borderTop: '1px solid #334155' }}>
                        <td>{row.source_key || row.source}</td>
                        <td>{count}</td>
                        <td>
                          <div style={{ background: '#0f172a', borderRadius: 999, height: 10 }}>
                            <div style={{ width: `${w}%`, height: 10, borderRadius: 999, background: '#38bdf8' }} />
                          </div>
                        </td>
                      </tr>
                    );
                  }) : <tr><td colSpan={3} style={{ color: '#94a3b8' }}>No source activity</td></tr>}
                </tbody>
              </table>
            )}
          </div>

          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12 }}>
            <h3 style={{ marginTop: 0 }}>Top Active Clients</h3>
            {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
              <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                    <th>Client</th>
                    <th>Events</th>
                    <th>Activity</th>
                  </tr>
                </thead>
                <tbody>
                  {topClients.length ? topClients.map((row) => {
                    const count = Number(row.event_count ?? row.events ?? 0);
                    const w = Math.max(6, Math.round((count / maxClient) * 100));
                    return (
                      <tr key={row.host_name || row.host} style={{ borderTop: '1px solid #334155' }}>
                        <td>{row.host_name || row.host}</td>
                        <td>{count}</td>
                        <td>
                          <div style={{ background: '#0f172a', borderRadius: 999, height: 10 }}>
                            <div style={{ width: `${w}%`, height: 10, borderRadius: 999, background: '#22c55e' }} />
                          </div>
                        </td>
                      </tr>
                    );
                  }) : <tr><td colSpan={3} style={{ color: '#94a3b8' }}>No client activity</td></tr>}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div style={{ marginTop: 12, border: '1px solid #334155', borderRadius: 10, padding: 12 }}>
          <h3 style={{ marginTop: 0 }}>Risky Clients (IOC Match Activity)</h3>
          {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
            <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                  <th>Client</th>
                  <th>Risky Events</th>
                  <th>Last Seen</th>
                  <th>Risk Activity</th>
                </tr>
              </thead>
              <tbody>
                {riskyClients.length ? riskyClients.map((row) => {
                  const count = Number(row.risky_event_count || 0);
                  const w = Math.max(6, Math.round((count / maxRiskyClient) * 100));
                  return (
                    <tr key={row.host_name} style={{ borderTop: '1px solid #334155' }}>
                      <td>{row.host_name}</td>
                      <td>{count}</td>
                      <td>{formatUserDateTime(row.last_risky_seen_at)}</td>
                      <td>
                        <div style={{ background: '#0f172a', borderRadius: 999, height: 10 }}>
                          <div style={{ width: `${w}%`, height: 10, borderRadius: 999, background: '#ef4444' }} />
                        </div>
                      </td>
                    </tr>
                  );
                }) : <tr><td colSpan={4} style={{ color: '#94a3b8' }}>No risky client activity</td></tr>}
              </tbody>
            </table>
          )}
        </div>

        <div style={{ marginTop: 12, border: '1px solid #334155', borderRadius: 10, padding: 12 }}>
          <h3 style={{ marginTop: 0 }}>Activity Timeline (hourly)</h3>
          {loading ? <div style={{ color: '#94a3b8' }}>Loading...</div> : (
            <div style={{ display: 'grid', gap: 8 }}>
              {timelineRows.length ? timelineRows.map(([label, value]) => {
                const w = Math.max(4, Math.round((Number(value || 0) / maxTimeline) * 100));
                return (
                  <div key={label} style={{ display: 'grid', gridTemplateColumns: '180px 70px 1fr', gap: 10, alignItems: 'center' }}>
                    <div style={{ color: '#94a3b8', fontSize: 12 }}>{label}</div>
                    <div style={{ fontWeight: 700 }}>{value}</div>
                    <div style={{ background: '#0f172a', borderRadius: 999, height: 10 }}>
                      <div style={{ width: `${w}%`, height: 10, borderRadius: 999, background: '#f59e0b' }} />
                    </div>
                  </div>
                );
              }) : <div style={{ color: '#94a3b8' }}>No timeline data</div>}
            </div>
          )}
        </div>
      </section>
    </AppShell>
  );
}

function IOCMatchEventsPage() {
  const ALL_VERDICTS = ['unreviewed', 'in_progress', 'fp', 'tp'];
  const ALL_DETECTIONS = ['realtime', 'retroactive'];
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [rows, setRows] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [reviewVerdict, setReviewVerdict] = useState('');
  const [reviewNote, setReviewNote] = useState('');
  const [savingReview, setSavingReview] = useState(false);
  const [userLookup, setUserLookup] = useState({});
  const [detectionFilter, setDetectionFilter] = useState(ALL_DETECTIONS);
  const [verdictFilter, setVerdictFilter] = useState(ALL_VERDICTS);
  const [assigneeFilter, setAssigneeFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [activeDateQuick, setActiveDateQuick] = useState('24h');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [dateError, setDateError] = useState('');
  const filtersRef = useRef(null);
  const navigate = useNavigate();
  const { userEmail } = useSession();

  const toDateTimeLocal = (d) => {
    const dt = new Date(d);
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const day = String(dt.getDate()).padStart(2, '0');
    const hh = String(dt.getHours()).padStart(2, '0');
    const mm = String(dt.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${day}T${hh}:${mm}`;
  };

  const toIsoOrNull = (v) => {
    const raw = String(v || '').trim();
    if (!raw) return null;
    const d = new Date(raw);
    if (Number.isNaN(d.getTime())) return null;
    return d.toISOString();
  };

  const buildDefault24hRange = () => {
    const now = new Date();
    const from = new Date(now.getTime() - (24 * 60 * 60 * 1000));
    return { from: toDateTimeLocal(from), to: toDateTimeLocal(now) };
  };

  const formatRangeShort = (v) => {
    const d = new Date(String(v || '').trim());
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false });
  };

  const verdictMeta = (verdict) => {
    const v = String(verdict || '').toLowerCase();
    if (v === 'fp') return { label: 'FP', color: '#ef4444' };
    if (v === 'tp') return { label: 'TP', color: '#22c55e' };
    if (v === 'suspicious') return { label: 'Suspicious', color: '#f59e0b' };
    if (v === 'in_progress') return { label: 'In Progress', color: '#f59e0b' };
    return { label: 'Unreviewed', color: '#94a3b8' };
  };

  const loadEvents = useCallback(async (q = '', assignedTo = null, fromVal = '', toVal = '', verdictVals = [], detectionVals = []) => {
    const fromIso = toIsoOrNull(fromVal);
    const toIso = toIsoOrNull(toVal);
    if (fromIso && toIso && fromIso > toIso) {
      setDateError('Invalid date range: From must be earlier than or equal to To.');
      setRows([]);
      return;
    }
    setDateError('');
    setLoading(true);
    try {
      const params = { limit: 120, q: q || undefined };
      if (assignedTo) params.assigned_to = assignedTo; // UI hint, backend may ignore
      if (fromIso) params.from = fromIso;
      if (toIso) params.to = toIso;
      if (Array.isArray(verdictVals) && verdictVals.length && verdictVals.length < ALL_VERDICTS.length) params.verdict = verdictVals.join(',');
      if (Array.isArray(detectionVals) && detectionVals.length && detectionVals.length < ALL_DETECTIONS.length) params.detection = detectionVals.join(',');
      const { data } = await api.get('/ioc/match-events', { params });
      setRows(data?.items || []);
    } catch {
      setRows([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadUsers = useCallback(async () => {
    try {
      const { data } = await api.get('/users');
      const next = {};
      for (const u of (data?.users || [])) {
        const username = String(u?.username || '').trim();
        if (!username) continue;
        next[username.toLowerCase()] = username;
      }
      setUserLookup(next);
    } catch {
      setUserLookup({});
    }
  }, []);

  const resolveAssignee = useCallback((assignedTo) => {
    const raw = String(assignedTo || '').trim();
    if (!raw) return 'Unassigned';
    return userLookup[raw.toLowerCase()] || raw;
  }, [userLookup]);

  const resetFilters = useCallback(() => {
    setDetectionFilter(ALL_DETECTIONS);
    setVerdictFilter(ALL_VERDICTS);
    setAssigneeFilter('all');
    setSourceFilter('all');
    const def = buildDefault24hRange();
    setDateFrom(def.from);
    setDateTo(def.to);
    setActiveDateQuick('24h');
    setQuery('');
    loadEvents('', null, def.from, def.to).catch(() => {});
  }, [loadEvents]);

  const openReview = useCallback((evt) => {
    setSelectedEvent(evt || null);
    setReviewVerdict(String(evt?.verdict || '').toLowerCase());
    setReviewNote(String(evt?.note || ''));
  }, []);

  const closeReview = useCallback(() => {
    setSelectedEvent(null);
    setReviewVerdict('');
    setReviewNote('');
    setSavingReview(false);
  }, []);

  const toggleMulti = useCallback((arr, val) => (arr.includes(val) ? arr.filter((x) => x !== val) : [...arr, val]), []);

  const submitReview = useCallback(async () => {
    if (!selectedEvent?.id) return;
    setSavingReview(true);
    try {
      const payload = {
        verdict: reviewVerdict || null,
        note: reviewNote.trim() || null
      };
      const { data } = await api.patch(`/ioc/match-events/${selectedEvent.id}/verdict`, payload);
      const updated = data?.item || null;
      if (updated) {
        setRows((prev) => prev.map((r) => (r.id === updated.id ? { ...r, ...updated } : r)));
      }
      closeReview();
    } catch {
      // keep modal open on failure
    } finally {
      setSavingReview(false);
    }
  }, [selectedEvent, reviewVerdict, reviewNote, closeReview]);

  useEffect(() => {
    const def = buildDefault24hRange();
    setDateFrom(def.from);
    setDateTo(def.to);
    setActiveDateQuick('24h');
    loadEvents('', null, def.from, def.to).catch(() => {});
    loadUsers().catch(() => {});
  }, [loadEvents, loadUsers]);

  useEffect(() => {
    const onDown = (e) => {
      if (!filtersRef.current) return;
      if (!filtersRef.current.contains(e.target)) setFiltersOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, []);

  const sourceOptions = useMemo(() => {
    const set = new Set();
    for (const r of rows) {
      const s = String((r.source_names && r.source_names[0]) || r.source_name || '').trim();
      if (s) set.add(s);
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [rows]);

  const assigneeOptions = useMemo(() => {
    const users = Object.values(userLookup);
    return Array.from(new Set(users)).sort((a, b) => a.localeCompare(b));
  }, [userLookup]);

  const searchTerm = String(query || '').trim().toLowerCase();
  const filteredRows = useMemo(() => {
    return (rows || []).filter((evt) => {
      const detection = String(evt.detection_mode || '').toLowerCase();
      const verdict = String(evt.verdict || '').toLowerCase();
      const assigneeRaw = String(evt.assigned_to || '').trim();
      const assignee = resolveAssignee(assigneeRaw);
      const source = String((evt.source_names && evt.source_names[0]) || evt.source_name || '').trim();

      if (Array.isArray(detectionFilter) && detectionFilter.length && detectionFilter.length < ALL_DETECTIONS.length && !detectionFilter.includes(detection)) return false;
      if (Array.isArray(verdictFilter) && verdictFilter.length && verdictFilter.length < ALL_VERDICTS.length) {
        const verdictNorm = verdict || 'unreviewed';
        if (!verdictFilter.includes(verdictNorm)) return false;
      }

      if (assigneeFilter === 'unassigned') {
        if (assigneeRaw) return false;
      } else if (assigneeFilter !== 'all') {
        if (assignee.toLowerCase() !== assigneeFilter.toLowerCase()) return false;
      }

      if (sourceFilter !== 'all' && source.toLowerCase() !== sourceFilter.toLowerCase()) return false;

      if (searchTerm) {
        const hay = [
          `#${evt.id}`,
          String(evt.id || ''),
          evt.matched_ioc,
          source,
          assignee,
          evt.destination_ip,
          evt.host_name
        ].map((x) => String(x || '').toLowerCase()).join(' | ');
        if (!hay.includes(searchTerm)) return false;
      }

      return true;
    });
  }, [rows, detectionFilter, verdictFilter, assigneeFilter, sourceFilter, resolveAssignee, userEmail, searchTerm]);

  useEffect(() => {
    setPage(1);
  }, [query, detectionFilter, verdictFilter, assigneeFilter, sourceFilter, activeDateQuick, dateFrom, dateTo, pageSize]);

  const totalRows = filteredRows.length;
  const totalPages = Math.max(1, Math.ceil(totalRows / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedRows = filteredRows.slice((safePage - 1) * pageSize, safePage * pageSize);

  const activeFilters = [];
  if (dateFrom || dateTo) {
    activeFilters.push({
      key: 'date',
      label: `${formatRangeShort(dateFrom) || '-'} → ${formatRangeShort(dateTo) || '-'}`,
      onClear: () => {
        setDateFrom('');
        setDateTo('');
        setActiveDateQuick('');
        loadEvents(query, null, '', '', verdictFilter, detectionFilter).catch(() => {});
      }
    });
  }
  if (detectionFilter.length && detectionFilter.length < ALL_DETECTIONS.length) activeFilters.push({ key: 'detection', label: `Detection: ${detectionFilter.map((d) => d === 'realtime' ? 'Real-time' : 'Retroactive').join(', ')}`, onClear: () => setDetectionFilter(ALL_DETECTIONS) });
  if (verdictFilter.length && verdictFilter.length < ALL_VERDICTS.length) activeFilters.push({ key: 'verdict', label: `Verdict: ${verdictFilter.map((v) => v === 'unreviewed' ? 'Unreviewed' : v === 'in_progress' ? 'In Progress' : v.toUpperCase()).join(', ')}`, onClear: () => setVerdictFilter(ALL_VERDICTS) });
  if (assigneeFilter !== 'all') activeFilters.push({ key: 'assignee', label: `Assignee: ${assigneeFilter === 'unassigned' ? 'Unassigned' : assigneeFilter}`, onClear: () => setAssigneeFilter('all') });
  if (sourceFilter !== 'all') activeFilters.push({ key: 'source', label: `Source: ${sourceFilter}`, onClear: () => setSourceFilter('all') });

  const highlight = (text) => {
    const raw = String(text || '');
    if (!searchTerm || searchTerm.length < 2) return raw || '-';
    const idx = raw.toLowerCase().indexOf(searchTerm);
    if (idx === -1) return raw || '-';
    return (
      <>
        {raw.slice(0, idx)}
        <mark style={{ background: '#fef08a', color: '#111827', padding: '0 2px', borderRadius: 3 }}>{raw.slice(idx, idx + searchTerm.length)}</mark>
        {raw.slice(idx + searchTerm.length)}
      </>
    );
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <div style={{ display: 'grid', gap: 10, marginBottom: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
            <div>
              <h2 style={{ margin: 0 }}>Detection Events</h2>
              <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 4 }}>Search and inspect detection events.</div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') loadEvents(query, null, dateFrom, dateTo, verdictFilter, detectionFilter).catch(() => {}); }}
              placeholder="Search by ID, IP, domain, hash, or source... (e.g., 47.104.248.7 or #21371)"
              style={{ minWidth: 560, flex: 1 }}
            />
            <button onClick={() => loadEvents(query, null, dateFrom, dateTo, verdictFilter, detectionFilter).catch(() => {})}>Search</button>
          </div>

          <div style={{ border: '1px solid #334155', borderRadius: 10, background: '#0b1220', padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ color: '#93c5fd', fontSize: 12, fontWeight: 700 }}>Active Filters</span>
            {activeFilters.length ? activeFilters.map((f) => (
              <span key={f.key + f.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, border: '1px solid #475569', borderRadius: 999, padding: '3px 8px', fontSize: 12, color: '#cbd5e1' }}>
                {f.label}
                <button onClick={f.onClear} style={{ border: 'none', background: 'transparent', color: '#94a3b8', cursor: 'pointer', padding: 0 }}>✕</button>
              </span>
            )) : <span style={{ color: '#64748b', fontSize: 12 }}>None</span>}
            <button onClick={resetFilters} style={{ marginLeft: 'auto', fontSize: 12 }}>Clear all</button>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <input type="datetime-local" value={dateFrom} onChange={(e) => { setDateFrom(e.target.value); setActiveDateQuick(''); }} />
            <input type="datetime-local" value={dateTo} onChange={(e) => { setDateTo(e.target.value); setActiveDateQuick(''); }} />
            {[['1h', 'Last 1 hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days']].map(([k, lbl]) => (
              <button
                key={k}
                onClick={() => {
                  setActiveDateQuick(k);
                  const now = new Date();
                  const from = new Date(now.getTime() - (k === '1h' ? 60*60*1000 : k === '24h' ? 24*60*60*1000 : 7*24*60*60*1000));
                  const f = toDateTimeLocal(from);
                  const t = toDateTimeLocal(now);
                  setDateFrom(f);
                  setDateTo(t);
                  loadEvents(query, null, f, t, verdictFilter, detectionFilter).catch(() => {});
                }}
                style={{
                  borderRadius: 999,
                  padding: '6px 12px',
                  border: activeDateQuick === k ? '1px solid #93c5fd' : '1px solid #334155',
                  color: activeDateQuick === k ? '#dbeafe' : '#cbd5e1',
                  background: activeDateQuick === k ? '#1e3a8a' : '#020617',
                  boxShadow: activeDateQuick === k ? '0 0 0 1px rgba(147,197,253,0.35) inset' : 'none',
                  fontWeight: activeDateQuick === k ? 700 : 500
                }}
              >
                {lbl}
              </button>
            ))}
          </div>

          {dateError ? (
            <div style={{ color: '#fca5a5', fontSize: 12 }}>{dateError}</div>
          ) : null}

          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr', gap: 8, alignItems: 'start' }}>
            <div ref={filtersRef} style={{ position: 'relative' }}>
              <button
                onClick={() => setFiltersOpen((v) => !v)}
                style={{ minWidth: 220 }}
              >
                {`Filters (${verdictFilter.length} Verdict, ${detectionFilter.length} Detection)`}
              </button>
              {filtersOpen ? (
                <div style={{ position: 'absolute', top: 'calc(100% + 6px)', left: 0, zIndex: 20, width: 360, border: '1px solid #334155', borderRadius: 10, background: '#0b1220', padding: 10, boxShadow: '0 10px 30px rgba(2,6,23,0.45)' }}>
                  <div style={{ fontWeight: 700, marginBottom: 8 }}>Verdict</div>
                  <div style={{ display: 'grid', gap: 6, marginBottom: 8 }}>
                    {[
                      ['unreviewed', 'Unreviewed'],
                      ['in_progress', 'In Progress'],
                      ['fp', 'False Positive'],
                      ['tp', 'True Positive']
                    ].map(([v, lbl]) => (
                      <label key={v} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: verdictFilter.includes(v) ? '#dbeafe' : '#cbd5e1' }}>
                        <input type="checkbox" checked={verdictFilter.includes(v)} onChange={() => setVerdictFilter((prev) => toggleMulti(prev, v))} />
                        <span>{lbl}</span>
                      </label>
                    ))}
                  </div>
                  <div style={{ marginBottom: 10, display: 'flex', gap: 8 }}>
                    <button onClick={() => setVerdictFilter(ALL_VERDICTS)}>Select All</button>
                    <button onClick={() => setVerdictFilter([])}>Clear</button>
                  </div>

                  <div style={{ fontWeight: 700, marginBottom: 8 }}>Detection</div>
                  <div style={{ display: 'grid', gap: 6, marginBottom: 8 }}>
                    {[
                      ['realtime', 'Real-time'],
                      ['retroactive', 'Retroactive']
                    ].map(([v, lbl]) => (
                      <label key={v} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: detectionFilter.includes(v) ? '#dbeafe' : '#cbd5e1' }}>
                        <input type="checkbox" checked={detectionFilter.includes(v)} onChange={() => setDetectionFilter((prev) => toggleMulti(prev, v))} />
                        <span>{lbl}</span>
                      </label>
                    ))}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => setDetectionFilter(ALL_DETECTIONS)}>Select All</button>
                    <button onClick={() => setDetectionFilter([])}>Clear</button>
                  </div>
                </div>
              ) : null}
            </div>

            <select value={assigneeFilter} onChange={(e) => setAssigneeFilter(e.target.value)}>
              <option value="all">Assignee: All</option>
              <option value="unassigned">Assignee: Unassigned</option>
              {assigneeOptions.map((u) => <option key={u} value={u}>{u}</option>)}
            </select>
            <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
              <option value="all">Source: All</option>
              {sourceOptions.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>

        <div style={{ border: '1px solid #334155', borderRadius: 10, overflowX: 'auto', overflowY: 'hidden' }}>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 1260 }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                <th style={{ width: 80 }}>ID</th>
                <th style={{ width: 170 }}>Detected At</th>
                <th style={{ width: 240 }}>Matched IOC</th>
                <th style={{ width: 140 }}>Detection</th>
                <th style={{ width: 140 }}>Verdict</th>
                <th style={{ width: 140 }}>Assignee</th>
                <th style={{ width: 170 }}>Source</th>
                <th style={{ width: 140 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>Loading detection events...</td></tr>
              ) : pagedRows.length ? pagedRows.map((evt) => {
                const vm = verdictMeta(evt.verdict);
                return (
                  <tr key={evt.id} style={{ borderTop: '1px solid #334155' }}>
                    <td>{evt.id}</td>
                    <td>{formatUserDateTime(evt.detected_at || evt.last_seen_at || evt.event_time || evt.created_at)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{highlight(evt.matched_ioc)}</td>
                    <td>
                      <span style={{
                        display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${evt.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e'}`,
                        color: evt.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e', background: '#020617'
                      }}>
                        {evt.detection_mode === 'retroactive' ? 'Retroactive Match' : 'Real-Time Match'}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                        border: `1px solid ${vm.color}`, color: vm.color, background: '#020617'
                      }}>
                        {vm.label}
                      </span>
                    </td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {highlight(resolveAssignee(evt.assigned_to))}
                    </td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {highlight(evt.source_count > 1
                        ? `${(evt.source_names && evt.source_names[0]) || evt.source_name || '-'} +${evt.source_count - 1}`
                        : ((evt.source_names && evt.source_names[0]) || evt.source_name || '-'))}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button onClick={() => navigate(`/analytics/detection-events/${evt.id}`)} title="View detail" aria-label="View detail" style={{ minWidth: 32, padding: '4px 8px' }}>🔍</button>
                        <button onClick={() => openReview(evt)} title="Review verdict" aria-label="Review verdict" style={{ minWidth: 32, padding: '4px 8px' }}>✏️</button>
                      </div>
                    </td>
                  </tr>
                );
              }) : (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>No detection events found.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10, gap: 10, flexWrap: 'wrap' }}>
          <div style={{ color: '#94a3b8', fontSize: 13 }}>
            Showing {totalRows === 0 ? 0 : ((safePage - 1) * pageSize + 1)}-{Math.min(safePage * pageSize, totalRows)} of {totalRows}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <select value={String(pageSize)} onChange={(e) => setPageSize(Number(e.target.value) || 20)}>
              <option value="10">10 / page</option>
              <option value="20">20 / page</option>
              <option value="50">50 / page</option>
            </select>
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={safePage <= 1}>Prev</button>
            <span style={{ color: '#cbd5e1', fontSize: 13 }}>Page {safePage} / {totalPages}</span>
            <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={safePage >= totalPages}>Next</button>
          </div>
        </div>
      </section>

      {selectedEvent ? (
        <div onClick={closeReview} style={{ position: 'fixed', inset: 0, background: 'rgba(2, 6, 23, 0.7)', display: 'grid', placeItems: 'center', zIndex: 50, padding: 16 }}>
          <div onClick={(e) => e.stopPropagation()} style={{ width: 'min(680px, 96vw)', background: '#0f172a', border: '1px solid #334155', borderRadius: 12, padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h3 style={{ margin: 0 }}>Review Detection Event #{selectedEvent.id}</h3>
              <button onClick={closeReview}>Close</button>
            </div>

            <div style={{ color: '#94a3b8', fontSize: 13, marginBottom: 10 }}>
              {selectedEvent.matched_ioc || '-'} • {formatUserDateTime(selectedEvent.detected_at || selectedEvent.last_seen_at || selectedEvent.event_time || selectedEvent.created_at)}
            </div>

            <div style={{ marginBottom: 10 }}>
              <label style={{ display: 'block', fontSize: 13, marginBottom: 6, color: '#94a3b8' }}>Verdict</label>
              <select value={reviewVerdict} onChange={(e) => setReviewVerdict(e.target.value)} style={{ minWidth: 220 }}>
                <option value="">Unreviewed</option>
                <option value="in_progress">In Progress</option>
                <option value="fp">FP (False Positive)</option>
                <option value="tp">TP (True Positive)</option>
                <option value="suspicious">Suspicious</option>
              </select>
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={{ display: 'block', fontSize: 13, marginBottom: 6, color: '#94a3b8' }}>Analyst Note</label>
              <textarea value={reviewNote} onChange={(e) => setReviewNote(e.target.value)} rows={5} placeholder="Optional analyst note" style={{ width: '100%' }} />
            </div>

            <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 12 }}>
              Reviewer: {userEmail || 'unknown'}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button onClick={closeReview} disabled={savingReview}>Cancel</button>
              <button onClick={() => submitReview().catch(() => {})} disabled={savingReview}>{savingReview ? 'Saving...' : 'Save Verdict'}</button>
            </div>
          </div>
        </div>
      ) : null}
    </AppShell>
  );
}

function IOCMatchEventDetailsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { userEmail } = useSession();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [item, setItem] = useState(null);
  const [verdict, setVerdict] = useState('');
  const [note, setNote] = useState('');

  const verdictMeta = (v, assignedTo) => {
    const x = String(v || '').toLowerCase();
    if (x === 'fp') return { label: 'FP', color: '#ef4444' };
    if (x === 'tp') return { label: 'TP', color: '#22c55e' };
    if (x === 'suspicious') return { label: 'Suspicious', color: '#f59e0b' };
    if (x === 'in_progress') return { label: `In Progress${assignedTo ? ` (${assignedTo})` : ''}`, color: '#f59e0b' };
    return { label: 'Unreviewed', color: '#94a3b8' };
  };

  const loadDetail = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const { data } = await api.get(`/ioc/match-events/${id}`);
      const it = data?.item || null;
      setItem(it);
      setVerdict(String(it?.verdict || '').toLowerCase());
      setNote(String(it?.note || ''));
    } catch {
      setItem(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  const saveVerdict = useCallback(async (nextVerdict = verdict, nextNote = note, extra = {}) => {
    if (!id) return;
    setSaving(true);
    try {
      const { data } = await api.patch(`/ioc/match-events/${id}/verdict`, {
        verdict: nextVerdict || null,
        note: String(nextNote || '').trim() || null,
        ...extra
      });
      const it = data?.item || null;
      if (it) {
        setItem((prev) => ({ ...(prev || {}), ...it }));
        setVerdict(String(it.verdict || '').toLowerCase());
        setNote(String(it.note || ''));
      }
    } finally {
      setSaving(false);
    }
  }, [id, verdict, note]);

  const takeOwnership = useCallback(async () => {
    await saveVerdict('in_progress', note, { assigned_to: userEmail || null });
  }, [saveVerdict, note, userEmail]);

  useEffect(() => {
    loadDetail().catch(() => {});
  }, [loadDetail]);

  const vm = verdictMeta(item?.verdict, item?.assigned_to);

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h2 style={{ margin: 0 }}>Detection Event Details #{id}</h2>
          <button onClick={() => navigate('/analytics/detection-events')}>Back</button>
        </div>

        {loading ? (
          <div style={{ color: '#94a3b8' }}>Loading detail...</div>
        ) : !item ? (
          <div style={{ color: '#94a3b8' }}>Event detail not found.</div>
        ) : (
          <div style={{ display: 'grid', gap: 12 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Detected At</div>
                <div style={{ fontWeight: 700 }}>{formatUserDateTime(item.detected_at || item.last_seen_at || item.event_time || item.created_at)}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Matched IOC</div>
                <div>{item.matched_ioc || '-'}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Verdict</div>
                <span style={{
                  display: 'inline-block', borderRadius: 999, padding: '4px 10px', fontSize: 12, fontWeight: 700,
                  border: `1px solid ${vm.color}`, color: vm.color, background: '#020617'
                }}>{vm.label}</span>
              </div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
              <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Event Context (v2)</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 8, fontSize: 13 }}>
                <div><b>Event Family:</b> {item?.v2_context?.event_family || '—'}</div>
                <div><b>Control Point:</b> {item?.v2_context?.control_point || '—'}</div>
                <div><b>Matched Field:</b> {item?.v2_context?.matched_field || '—'}</div>
                <div><b>Scenario:</b> {item?.v2_context?.scenario_type || '—'}</div>
                <div><b>Direction:</b> {item?.v2_context?.direction || '—'}</div>
                <div><b>Outcome:</b> {item?.v2_context?.outcome || '—'}</div>
                <div><b>Classification Confidence:</b> {Number.isFinite(Number(item?.v2_context?.classification_confidence)) ? Number(item.v2_context.classification_confidence).toFixed(2) : '—'}</div>
                <div><b>Outcome Confidence:</b> {Number.isFinite(Number(item?.v2_context?.outcome_confidence)) ? Number(item.v2_context.outcome_confidence).toFixed(2) : '—'}</div>
                <div style={{ gridColumn: '1 / -1' }}><b>Context Explanation:</b> {item?.v2_context?.context_explanation || '—'}</div>
              </div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
              <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>Matched Syslog event</div>
              <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.45, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, monospace', fontSize: 13, background: '#020617', border: '1px solid #334155', borderRadius: 8, padding: 10, maxHeight: 280, overflowY: 'auto' }}>
                {item.matched_syslog_event || '-'}
              </div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a', display: 'grid', gap: 10 }}>
              <h3 style={{ margin: 0 }}>Analyst Actions</h3>
              <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 12, alignItems: 'center' }}>
                <label style={{ color: '#94a3b8', fontSize: 13 }}>Verdict</label>
                <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
                  <option value="">Unreviewed</option>
                  <option value="in_progress">In Progress</option>
                  <option value="tp">TP</option>
                  <option value="fp">FP</option>
                  <option value="suspicious">Suspicious</option>
                </select>
              </div>

              <div style={{ display: 'grid', gap: 8 }}>
                <label style={{ color: '#94a3b8', fontSize: 13 }}>Analyst Note</label>
                <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={5} placeholder="Optional analyst note" style={{ width: '100%' }} />
              </div>

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button onClick={() => takeOwnership().catch(() => {})} disabled={saving}>Take Ownership</button>
                <button onClick={() => saveVerdict('tp', note).catch(() => {})} disabled={saving}>Mark as TP</button>
                <button onClick={() => saveVerdict('fp', note).catch(() => {})} disabled={saving}>Mark as FP</button>
                <button onClick={() => saveVerdict('suspicious', note).catch(() => {})} disabled={saving}>Mark as Suspicious</button>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ color: '#94a3b8', fontSize: 12 }}>
                  Assigned: {item.assigned_to || '-'} {item.assigned_at ? `• ${formatUserDateTime(item.assigned_at)}` : ''}
                </div>
                <button onClick={() => saveVerdict().catch(() => {})} disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
              </div>
            </div>
          </div>
        )}
      </section>
    </AppShell>
  );
}

function IncidentEventsTable({ activityId, refreshKey = 0 }) {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [offset, setOffset] = useState(0);
  const pageSize = 50;

  const load = useCallback(async (nextOffset = 0, append = false) => {
    if (!activityId) return;
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get(`/incidents/${activityId}/events`, { params: { limit: pageSize, offset: nextOffset } });
      const incoming = data?.events || data?.items || [];
      setRows((prev) => (append ? [...prev, ...incoming] : incoming));
      setTotal(Number.isFinite(Number(data?.total)) ? Number(data.total) : null);
      setOffset(nextOffset + incoming.length);
    } catch {
      if (!append) setRows([]);
      setError('Failed to load events');
      if (!append) setTotal(null);
    } finally {
      setLoading(false);
    }
  }, [activityId]);

  useEffect(() => { load(0, false).catch(() => {}); }, [load, refreshKey]);

  const hasMore = total == null ? false : rows.length < total;

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>
        {total == null ? 'Events' : `Events (${total})`}
      </div>
      <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 1260 }}>
        <thead>
          <tr style={{ textAlign: 'left', background: '#111827' }}>
            <th style={{ width: 80 }}>ID</th>
            <th style={{ width: 170 }}>Detected At</th>
            <th style={{ width: 220 }}>Matched IOC</th>
            <th style={{ width: 200 }}>Context</th>
            <th style={{ width: 140 }}>Detection</th>
            <th style={{ width: 140 }}>Verdict</th>
            <th style={{ width: 140 }}>Assignee</th>
            <th style={{ width: 180 }}>Source</th>
            <th style={{ width: 140 }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {loading && rows.length === 0 ? <tr><td colSpan={9} style={{ color: '#94a3b8' }}>Loading events...</td></tr> : error ? <tr><td colSpan={9} style={{ color: '#fca5a5' }}>{error}</td></tr> : rows.length ? rows.map((r) => {
            const verdict = String(r.verdict || '').toLowerCase();
            const vm = verdict === 'fp'
              ? { label: 'FP', color: '#ef4444' }
              : verdict === 'tp'
                ? { label: 'TP', color: '#22c55e' }
                : verdict === 'suspicious'
                  ? { label: 'Suspicious', color: '#f59e0b' }
                  : verdict === 'in_progress'
                    ? { label: 'In Progress', color: '#f59e0b' }
                    : { label: 'Unreviewed', color: '#94a3b8' };

            return (
              <tr key={r.id} style={{ borderTop: '1px solid #334155' }}>
                <td>{r.id}</td>
                <td>{formatUserDateTime(r.detected_at || r.event_time || r.created_at)}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.matched_ioc || '-'}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  <span
                    style={{
                      display: 'inline-block',
                      borderRadius: 999,
                      padding: '3px 10px',
                      fontSize: 12,
                      fontWeight: 700,
                      border: '1px solid #475569',
                      color: '#cbd5e1',
                      background: '#020617'
                    }}
                  >
                    {normalizeEventContext(r)}
                  </span>
                </td>
                <td>
                  <span style={{
                    display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                    border: `1px solid ${r.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e'}`,
                    color: r.detection_mode === 'retroactive' ? '#f59e0b' : '#22c55e', background: '#020617'
                  }}>
                    {r.detection_mode === 'retroactive' ? 'Retroactive Match' : 'Real-Time Match'}
                  </span>
                </td>
                <td>
                  <span style={{
                    display: 'inline-block', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700,
                    border: `1px solid ${vm.color}`, color: vm.color, background: '#020617'
                  }}>{vm.label}</span>
                </td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.assigned_to || 'Unassigned'}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {r.source_count > 1
                    ? `${(r.source_names && r.source_names[0]) || r.source_name || '-'} +${r.source_count - 1}`
                    : ((r.source_names && r.source_names[0]) || r.source_name || '-')}
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => navigate(`/analytics/detection-events/${r.id}`)} title="View detail" aria-label="View detail" style={{ minWidth: 32, padding: '4px 8px' }}>🔍</button>
                    <button onClick={() => navigate(`/analytics/detection-events/${r.id}`)} title="Review verdict" aria-label="Review verdict" style={{ minWidth: 32, padding: '4px 8px' }}>✏️</button>
                  </div>
                </td>
              </tr>
            );
          }) : <tr><td colSpan={9} style={{ color: '#94a3b8' }}>No events linked to this incident.</td></tr>}
        </tbody>
      </table>
      <div style={{ padding: 10, borderTop: '1px solid #334155', background: '#0f172a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ color: '#94a3b8', fontSize: 12 }}>
          Showing {rows.length}{total == null ? '' : ` / ${total}`}
        </span>
        {hasMore ? <button onClick={() => load(offset, true).catch(() => {})} disabled={loading}>{loading ? 'Loading...' : 'Load more'}</button> : null}
      </div>
    </div>
  );
}

function RiskOverviewPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [trendData, setTrendData] = useState(null);
  const [range, setRange] = useState('24h');

  const load = useCallback(async (selectedRange = range) => {
    setLoading(true);
    try {
      const [ovRes, trRes] = await Promise.allSettled([
        api.get('/risk/overview'),
        api.get('/risk/trend', { params: { range: selectedRange } })
      ]);

      if (ovRes.status === 'fulfilled') {
        setData(ovRes.value?.data || null);
      } else {
        setData(null);
      }

      if (trRes.status === 'fulfilled') {
        setTrendData(trRes.value?.data || null);
      } else {
        setTrendData({ range: selectedRange, current: Number(ovRes.status === 'fulfilled' ? ovRes.value?.data?.institution_risk_score || 0 : 0), previous: 0, delta: 0, trend: 'stable', stats: { min: 0, max: 0, avg: 0 }, history: [] });
      }
    } catch {
      setData(null);
      setTrendData(null);
    } finally {
      setLoading(false);
    }
  }, [range]);

  useEffect(() => { load(range).catch(() => {}); }, [load, range]);

  const score = Math.max(0, Math.min(100, Number(data?.institution_risk_score || 0)));
  const level = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'GUARDED' : 'LOW';
  const levelColor = level === 'CRITICAL' ? '#ef4444' : level === 'HIGH' ? '#f97316' : level === 'MEDIUM' ? '#f59e0b' : level === 'GUARDED' ? '#eab308' : '#22c55e';
  const _deprecatedV2MetricsHidden = true;
  const top = Array.isArray(data?.top_contributing_incidents) ? data.top_contributing_incidents : [];
  const bd = data?.breakdown || {};
  const llmAggregate = data?.llm_adjustment_aggregate || bd?.llm_adjustment_aggregate || null;
  const dataTruncated = Boolean(data?.data_truncated);

  function formatAiDelta(value) {
    if (value === null || value === undefined) return '—';
    const n = Number(value);
    if (!Number.isFinite(n)) return '—';
    if (n > 0) return `+${n}`;
    if (n < 0) return `${n}`;
    return '0';
  }

  function aiDeltaStyle(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return { color: '#94a3b8', borderColor: '#475569', background: '#0f172a' };
    if (n > 0) return { color: '#fca5a5', borderColor: '#7f1d1d', background: 'rgba(127,29,29,0.25)' };
    if (n < 0) return { color: '#86efac', borderColor: '#14532d', background: 'rgba(20,83,45,0.25)' };
    return { color: '#cbd5e1', borderColor: '#475569', background: '#0f172a' };
  }
  const trend = String(trendData?.trend || 'stable');
  const delta = Number(trendData?.delta || 0);
  const trendArrow = trend === 'increasing' ? '↗' : trend === 'decreasing' ? '↘' : '→';
  const trendColor = trend === 'increasing' ? '#ef4444' : trend === 'decreasing' ? '#22c55e' : '#94a3b8';
  const history = Array.isArray(trendData?.history) ? trendData.history : [];
  const chartPoints = history.map((s, i) => {
    const x = history.length <= 1 ? 0 : (i / (history.length - 1)) * 100;
    const y = 100 - Math.max(0, Math.min(100, Number(s?.risk_score || 0)));
    return `${x},${y}`;
  }).join(' ');
  const stats = trendData?.stats || { min: 0, max: 0, avg: 0 };


  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
          <h2 style={{ margin: 0 }}>Risk Overview</h2>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {['24h', '7d', '30d'].map((r) => (
              <button
                key={r}
                onClick={() => setRange(r)}
                style={{ borderColor: range === r ? '#93c5fd' : '#475569' }}
              >
                {r.toUpperCase()}
              </button>
            ))}
            <button onClick={() => load(range).catch(() => {})}>Refresh</button>
          </div>
        </div>

        {loading ? <div style={{ color: '#94a3b8' }}>Loading risk overview...</div> : !data ? <div style={{ color: '#94a3b8' }}>Risk overview data is unavailable.</div> : (
          <>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a', marginBottom: 14 }}>
              <div style={{ fontSize: 13, color: '#94a3b8' }}>Institution Risk Estimate</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 6 }}>
                <div style={{ fontSize: 42, fontWeight: 800, lineHeight: 1 }}>{score.toFixed(2)}</div>
                <span style={{ border: `1px solid ${levelColor}`, color: levelColor, borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700 }}>{level}</span>
              </div>
              <div style={{ marginTop: 6, fontSize: 12, color: '#94a3b8' }}>Conservative estimate based on observed threat activity, exposure, and available event context.</div>
              <div style={{ marginTop: 10, height: 12, borderRadius: 999, background: '#1f2937', overflow: 'hidden' }}>
                <div style={{ width: `${score}%`, height: '100%', background: `linear-gradient(90deg, #22c55e 0%, #f59e0b 55%, #ef4444 100%)` }} />
              </div>
              <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8, color: trendColor, fontWeight: 700 }}>
                <span>{trendArrow}</span>
                <span style={{ textTransform: 'capitalize' }}>{trend}</span>
                <span style={{ color: '#94a3b8', fontWeight: 500 }}>Δ {delta >= 0 ? '+' : ''}{delta.toFixed(2)}</span>
              </div>
              {llmAggregate?.enabled ? (
                <div style={{ marginTop: 8, fontSize: 12, color: '#93c5fd', display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <span>AI adjusted risk enabled</span>
                  <span>AI Δ {Number(llmAggregate.total_adjustment || 0) >= 0 ? '+' : ''}{Number(llmAggregate.total_adjustment || 0).toFixed(2)}</span>
                </div>
              ) : null}
              <div style={{ marginTop: 10, border: '1px solid #334155', borderRadius: 8, padding: 8, background: '#0b1220' }}>
                {history.length >= 2 ? (
                  <svg viewBox="0 0 100 100" width="100%" height="110" preserveAspectRatio="none" aria-label="Institution risk trend">
                    <polyline fill="none" stroke="#60a5fa" strokeWidth="2" points={chartPoints} />
                    {history.map((p, i) => {
                      const x = history.length <= 1 ? 0 : (i / (history.length - 1)) * 100;
                      const y = 100 - Math.max(0, Math.min(100, Number(p?.risk_score || 0)));
                      return <circle key={`${p.ts}-${i}`} cx={x} cy={y} r="1.2" fill="#93c5fd"><title>{`${new Date(p.ts).toLocaleString()} • ${Number(p.risk_score || 0).toFixed(2)}`}</title></circle>;
                    })}
                  </svg>
                ) : (
                  <div style={{ color: '#64748b', fontSize: 12 }}>Not enough snapshots yet for trend chart.</div>
                )}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8, marginBottom: 12 }}>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Current</div><div style={{ fontSize: 18, fontWeight: 700 }}>{Number(trendData?.current || score).toFixed(2)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Peak</div><div style={{ fontSize: 18, fontWeight: 700 }}>{Number(stats.max || 0).toFixed(2)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Min</div><div style={{ fontSize: 18, fontWeight: 700 }}>{Number(stats.min || 0).toFixed(2)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Avg</div><div style={{ fontSize: 18, fontWeight: 700 }}>{Number(stats.avg || 0).toFixed(2)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, background: '#0f172a' }}><div style={{ fontSize: 11, color: '#94a3b8' }}>Delta</div><div style={{ fontSize: 18, fontWeight: 700, color: trendColor }}>{delta >= 0 ? '+' : ''}{delta.toFixed(2)}</div></div>
            </div>

            {dataTruncated ? (
              <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, border: '1px solid #f59e0b', color: '#fcd34d', background: 'rgba(245, 158, 11, 0.12)' }}>
                Risk score is calculated on a partial dataset
              </div>
            ) : null}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10, marginBottom: 14 }}>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>Open Incidents</div>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{Number(data?.active_incident_count || 0)}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Considered Incidents</div>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{Number(data?.total_active_incidents || 0)}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Raw Contribution</div>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{Number(bd?.total_raw_contribution || 0).toFixed(6)}</div>
              </div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>Score Model</div>
                <div style={{ fontSize: 24, fontWeight: 700 }}>evidence-aware</div>
              </div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
              <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Incident Evidence Breakdown</div>
              <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed' }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#111827' }}>
                    <th style={{ width: 100 }}>Incident ID</th>
                    <th>IOC</th>
                    <th style={{ width: 110 }}>Risk Score</th>
                    <th style={{ width: 110 }}>Contribution</th>
                    <th style={{ width: 90 }}>Verdict</th>
                    <th style={{ width: 110 }}>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {top.length ? top.map((it) => {
                    return (
                      <tr key={`${it.id}-${it.rank}`} style={{ borderTop: '1px solid #334155' }}>
                        <td>{it.incident_id || it.id ? <Link to={`/incidents/${it.incident_id || it.id}`}>#{it.incident_id || '-'}</Link> : '-'}</td>
                        <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{it.ioc_value || '-'}</td>
                        <td>{Number.isFinite(Number(it?.risk_score)) ? Number(it.risk_score).toFixed(2) : '—'}</td>
                        <td>{Number.isFinite(Number(it?.contribution)) ? Number(it.contribution).toFixed(3) : '—'}</td>
                        <td>{it.verdict || '—'}</td>
                        <td>{it.confidence || '—'}</td>
                      </tr>
                    );
                  }) : <tr><td colSpan={10} style={{ color: '#94a3b8' }}>No active incidents.</td></tr>}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>
    </AppShell>
  );
}

function IncidentDetailsPage() {
  const { id } = useParams();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [item, setItem] = useState(null);
  const [tab, setTab] = useState('summary');
  const [verdict, setVerdict] = useState('Unreviewed');
  const [note, setNote] = useState('');
  const [eventsRefreshKey, setEventsRefreshKey] = useState(0);
  const [showPropagateModal, setShowPropagateModal] = useState(false);
  const [propagationNote, setPropagationNote] = useState('');
  const [aiAnalyzing, setAiAnalyzing] = useState(false);
  const [aiStillAnalyzing, setAiStillAnalyzing] = useState(false);
  const [aiAnalyzeStartedAt, setAiAnalyzeStartedAt] = useState(null);
  const [aiError, setAiError] = useState('');
  const [evidenceSummary, setEvidenceSummary] = useState({ count: null, unavailable: false });

  useEffect(() => {
    const reason = item?.llm_risk_reason;
    if (typeof reason !== 'string' || !reason) return;
    console.log(reason.length, reason);
  }, [item?.llm_risk_reason]);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const { data } = await api.get(`/incidents/${id}`);
      const it = data?.item || null;
      setItem(it);
      setVerdict(String(it?.verdict || 'Unreviewed'));
      setNote(String(it?.note || ''));
    } catch {
      setItem(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    async function loadEvidenceSummary() {
      try {
        const { data } = await api.get(`/incidents/${id}/related-logs`, { params: { page: 1, pageSize: 1 } });
        if (cancelled) return;
        setEvidenceSummary({
          count: Number.isFinite(Number(data?.total)) ? Number(data.total) : null,
          unavailable: Boolean(data?.error === 'unavailable')
        });
      } catch {
        if (cancelled) return;
        setEvidenceSummary({ count: null, unavailable: true });
      }
    }
    loadEvidenceSummary().catch(() => {});
    return () => { cancelled = true; };
  }, [id, eventsRefreshKey]);

  useEffect(() => {
    if (!aiStillAnalyzing || !id) return undefined;

    let stopped = false;
    const timer = setInterval(async () => {
      if (stopped) return;
      try {
        const { data } = await api.get(`/incidents/${id}`);
        const it = data?.item || null;
        if (!it) return;
        setItem((prev) => ({ ...(prev || {}), ...it }));

        const hasAdjustment = it.llm_risk_adjustment !== null && it.llm_risk_adjustment !== undefined;
        const updatedAtMs = it.llm_last_updated_at ? Date.parse(it.llm_last_updated_at) : NaN;
        const startedAtMs = aiAnalyzeStartedAt ? Date.parse(aiAnalyzeStartedAt) : NaN;
        const isFresh = Number.isFinite(updatedAtMs) && Number.isFinite(startedAtMs) ? updatedAtMs >= startedAtMs : true;
        if (hasAdjustment && isFresh) {
          stopped = true;
          setAiStillAnalyzing(false);
          await load();
        }
      } catch {
        // keep polling silently
      }
    }, 2500);

    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [aiStillAnalyzing, aiAnalyzeStartedAt, id, load]);

  async function savePatch(patch = {}) {
    if (!id) return;
    setSaving(true);
    try {
      const { data } = await api.patch(`/incidents/${id}`, { verdict, note, ...patch });
      setItem((prev) => ({ ...(prev || {}), ...(data?.item || {}) }));
      if (data?.item?.note != null) setNote(String(data.item.note || ''));
      setEventsRefreshKey((k) => k + 1);
    } finally {
      setSaving(false);
    }
  }

  async function runAiAnalyze() {
    if (!id || aiAnalyzing) return;
    setAiAnalyzing(true);
    setAiStillAnalyzing(false);
    setAiAnalyzeStartedAt(new Date().toISOString());
    setAiError('');
    try {
      const { data, status } = await api.post(`/incidents/${id}/ai-analyze`);
      if (status === 202 || data?.status === 'processing') {
        setAiStillAnalyzing(true);
        return;
      }

      const nextItem = data?.item || null;
      if (nextItem) {
        setItem((prev) => ({ ...(prev || {}), ...nextItem }));
      }
      setAiStillAnalyzing(false);
      await load();
    } catch {
      setAiStillAnalyzing(false);
      setAiError('AI analysis failed');
      setTimeout(() => setAiError(''), 3000);
    } finally {
      setAiAnalyzing(false);
    }
  }

  const isFinalVerdict = verdict === 'TP' || verdict === 'FP' || verdict === 'Suspicious';

  async function onClickSave() {
    if (isFinalVerdict) {
      setPropagationNote(String(note || ''));
      setShowPropagateModal(true);
      return;
    }
    await savePatch({});
  }

  async function applyWithPropagation(shouldPropagate) {
    await savePatch({
      propagate_to_events: shouldPropagate,
      propagation_note: shouldPropagate ? propagationNote : undefined
    });
    setShowPropagateModal(false);
  }

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        {loading ? <div style={{ color: '#94a3b8' }}>Loading incident...</div> : !item ? <div style={{ color: '#94a3b8' }}>Incident not found.</div> : (
          <div style={{ display: 'grid', gap: 12 }}>
            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
              <h2 style={{ margin: 0, fontSize: 28, fontWeight: 800 }}>Incident #{item.incident_id || id}</h2>
              <div style={{ color: '#e2e8f0', marginTop: 6, fontSize: 16, fontWeight: 600 }}>{item.ioc_value}</div>
              <div style={{ color: '#94a3b8', marginTop: 6 }}>
                Type: {item.ioc_type}
                {' • '}Detection Events: {item.detection_event_count ?? item.event_count ?? 0}
                {' • '}Evidence Logs: {evidenceSummary.unavailable ? '-' : (Number.isFinite(Number(evidenceSummary.count)) ? Number(evidenceSummary.count) : (item.related_log_count ?? 0))}
                {' • '}Observed Hosts: {item.asset_count || 0}
              </div>
              <div style={{ color: '#94a3b8', marginTop: 4 }}>First Seen: {formatUserDateTime(item.first_seen)} • Last Seen: {formatUserDateTime(item.last_seen)}</div>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a', display: 'grid', gap: 10 }}>
              <h3 style={{ margin: 0 }}>Analyst Actions</h3>
              <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr', gap: 8, alignItems: 'center' }}>
                <label>Verdict</label>
                <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
                  <option>TP</option><option>FP</option><option>Suspicious</option><option>Unreviewed</option><option>In Progress</option>
                </select>
                <label>Note</label>
                <textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => onClickSave().catch(() => {})} disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
                <button onClick={() => savePatch({ take_ownership: true, verdict: 'In Progress' }).catch(() => {})} disabled={saving}>Take Ownership</button>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => setTab('summary')} style={{ borderColor: tab === 'summary' ? '#93c5fd' : '#475569' }}>Summary</button>
              <button onClick={() => setTab('events')} style={{ borderColor: tab === 'events' ? '#93c5fd' : '#475569' }}>Detection Events ({item.detection_event_count ?? item.event_count ?? 0})</button>
              <button onClick={() => setTab('relatedLogs')} style={{ borderColor: tab === 'relatedLogs' ? '#93c5fd' : '#475569' }}>Evidence Logs ({evidenceSummary.unavailable ? '-' : (Number.isFinite(Number(evidenceSummary.count)) ? Number(evidenceSummary.count) : (item.related_log_count ?? 0))})</button>
            </div>

            {tab === 'summary' ? (
              <div style={{ display: 'grid', gap: 10 }}>
                <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
                  <div>Risk Score: <b>{Number(item.risk_score || 0).toFixed(2)}</b></div>
                  <div>Status: <b>{item.status}</b></div>
                  <div>Verdict: <b>{item.verdict}</b></div>
                </div>

                <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a', display: 'grid', gap: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <h4 style={{ margin: 0, fontSize: 14, color: '#cbd5e1' }}>AI Insight</h4>
                    <button
                      onClick={() => runAiAnalyze().catch(() => {})}
                      disabled={aiAnalyzing || aiStillAnalyzing}
                      style={{ fontSize: 12, padding: '4px 8px', borderColor: '#475569', background: '#111827' }}
                    >
                      {aiAnalyzing ? 'Analyzing...' : aiStillAnalyzing ? 'Still analyzing...' : ((item.llm_risk_adjustment === null || item.llm_risk_adjustment === undefined) ? 'Analyze with AI' : 'Update AI Insight')}
                    </button>
                  </div>

                  {aiStillAnalyzing ? (
                    <div style={{ fontSize: 12, color: '#93c5fd' }}>Still analyzing...</div>
                  ) : null}

                  {aiError ? (
                    <div style={{ fontSize: 12, color: '#fca5a5' }}>{aiError}</div>
                  ) : null}

                  {(item.llm_risk_adjustment === null || item.llm_risk_adjustment === undefined) ? (
                    <div style={{ color: '#94a3b8', fontSize: 13 }}>No AI analysis yet</div>
                  ) : (
                    <>
                      {(() => {
                        const adj = Number(item.llm_risk_adjustment || 0);
                        const adjColor = adj > 0 ? '#fca5a5' : adj < 0 ? '#86efac' : '#94a3b8';
                        const adjText = adj > 0 ? `+${adj}` : `${adj}`;
                        const conf = Number(item.llm_risk_confidence);
                        const confText = Number.isFinite(conf) ? `${Math.round(Math.min(Math.max(conf, 0), 1) * 100)}%` : '—';

                        return (
                          <>
                            <div style={{ fontSize: 13 }}>Adjustment: <b style={{ color: adjColor }}>{adjText}</b></div>
                            <div style={{ fontSize: 13 }}>Confidence: <b>{confText}</b></div>
                            <div style={{ fontSize: 13, display: 'grid', gridTemplateColumns: '60px 1fr', gap: 8, alignItems: 'start' }}>
                              <span>Reason:</span>
                              <span style={{ color: '#cbd5e1', whiteSpace: 'normal', overflow: 'visible', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.4 }}>
                                {item.llm_risk_reason || '—'}
                              </span>
                            </div>
                            {item.llm_related_evidence ? (
                              <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
                                <div style={{ color: '#cbd5e1', marginBottom: 4 }}>Related Evidence:</div>
                                <div>- Domain: {item.llm_related_evidence.domain || '—'}</div>
                                <div>- Resolved IP: {item.llm_related_evidence.resolved_ip || '—'}</div>
                                <div>- Resolved IP in IOC list: {item.llm_related_evidence.resolved_ip_in_ioc_list ? 'yes' : 'no'}</div>
                                <div>- Accepted traffic: {item.llm_related_evidence.accepted_traffic ? 'yes' : 'no'}</div>
                                <div>- Service/port: {item.llm_related_evidence.service_port || 'not specified'}</div>
                                <div>- Chain type: {String(item.llm_related_evidence.chain_type || 'related_infrastructure_activity').replaceAll('_', ' ')}</div>
                              </div>
                            ) : null}
                          </>
                        );
                      })()}
                    </>
                  )}
                </div>
              </div>
            ) : tab === 'events' ? (
              <IncidentEventsTable activityId={item.id} refreshKey={eventsRefreshKey} />
            ) : (
              <IncidentRelatedLogsTable incidentId={item.incident_id || id} />
            )}
          </div>
        )}

        {showPropagateModal && (
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.75)', display: 'grid', placeItems: 'center', zIndex: 60 }}>
            <div style={{ width: 'min(640px, 92vw)', border: '1px solid #334155', borderRadius: 12, background: '#0f172a', padding: 16, display: 'grid', gap: 10 }}>
              <h3 style={{ margin: 0 }}>Apply verdict to related events?</h3>
              <div style={{ color: '#94a3b8' }}>Do you also want to apply this verdict to related events?</div>
              <label style={{ color: '#cbd5e1', fontSize: 13 }}>Note for related events (optional)</label>
              <textarea rows={3} value={propagationNote} onChange={(e) => setPropagationNote(e.target.value)} />
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button onClick={() => setShowPropagateModal(false)} disabled={saving}>Cancel</button>
                <button onClick={() => applyWithPropagation(false).catch(() => {})} disabled={saving}>No</button>
                <button onClick={() => applyWithPropagation(true).catch(() => {})} disabled={saving}>Yes</button>
              </div>
            </div>
          </div>
        )}
      </section>
    </AppShell>
  );
}

function IncidentRelatedLogsTable({ incidentId }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [loading, setLoading] = useState(false);
  const [unavailable, setUnavailable] = useState(false);

  const load = useCallback(async () => {
    if (!incidentId) return;
    setLoading(true);
    setUnavailable(false);
    try {
      const { data } = await api.get(`/incidents/${incidentId}/related-logs`, { params: { page, pageSize } });
      setItems(data?.items || []);
      setTotal(Number(data?.total || 0));
      if (data?.error === 'unavailable') setUnavailable(true);
    } catch {
      setItems([]);
      setTotal(0);
      setUnavailable(true);
    } finally {
      setLoading(false);
    }
  }, [incidentId, page, pageSize]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  const start = total ? ((page - 1) * pageSize) + 1 : 0;
  const end = total ? Math.min(page * pageSize, total) : 0;

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a', display: 'grid', gap: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h4 style={{ margin: 0 }}>Evidence Logs</h4>
          <div style={{ color: '#94a3b8', fontSize: 12 }}>Raw logs captured for this incident. These are not additional detection events. Use CSV export for full review.</div>
        </div>
        <a href={`/api/incidents/${incidentId}/related-logs/export.csv`} target="_blank" rel="noreferrer"><button>Download CSV</button></a>
      </div>

      {loading ? <div style={{ color: '#94a3b8' }}>Loading evidence logs...</div> : unavailable ? (
        <div style={{ color: '#94a3b8' }}>Evidence logs are currently unavailable.</div>
      ) : !items.length ? (
        <div style={{ color: '#94a3b8' }}>No raw evidence logs found for this incident.</div>
      ) : (
        <>
          {items.some((r) => r?.fallback === true || r?.evidence_origin === 'pg_detection_event_snapshot') ? (
            <div style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid #f59e0b', background: 'rgba(245,158,11,0.12)', color: '#fcd34d', fontSize: 12 }}>
              Some evidence rows are fallback snapshots derived from normalized event data (raw log was not persisted at detection time).
            </div>
          ) : null}
          <div style={{ color: '#94a3b8', fontSize: 12 }}>Showing {start}-{end} of {total} evidence logs</div>
          <div style={{ overflowX: 'auto', border: '1px solid #334155', borderRadius: 8 }}>
            <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', minWidth: 1000 }}>
              <thead><tr style={{ background: '#1f2937', textAlign: 'left' }}>
                <th>Time</th><th>Observed Host</th><th>Matched IOC</th><th>Source Type</th><th>Evidence</th>
              </tr></thead>
              <tbody>
                {items.map((r, i) => {
                  const isFallback = r?.fallback === true || r?.evidence_origin === 'pg_detection_event_snapshot';
                  return (
                    <tr key={`${r.evidence_hash || i}`} style={{ borderTop: '1px solid #334155' }}>
                      <td>{formatUserDateTime(r.log_ts)}</td>
                      <td>{r.observed_host || '-'}</td>
                      <td>{r.matched_ioc || '-'}</td>
                      <td>{r.source_type || '-'}</td>
                      <td style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                        {isFallback ? <div style={{ marginBottom: 4, fontSize: 11, color: '#fcd34d' }}>Derived snapshot (not raw log)</div> : null}
                        {r.raw_message_sample || '-'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>Prev</button>
            <span>Page {page}</span>
            <button onClick={() => setPage((p) => (p * pageSize < total ? p + 1 : p))} disabled={page * pageSize >= total}>Next</button>
            <select value={String(pageSize)} onChange={(e) => { setPage(1); setPageSize(Math.min(Math.max(Number(e.target.value), 1), 200)); }}>
              <option value="50">50 / page</option><option value="100">100 / page</option><option value="200">200 / page</option>
            </select>
          </div>
        </>
      )}
    </div>
  );
}

function IncidentPage() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [verdict, setVerdict] = useState([]);
  const [assigneeFilter, setAssigneeFilter] = useState('all');
  const [from, setFrom] = useState(() => {
    const now = new Date();
    const d = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${day}T${hh}:${mm}`;
  });
  const [to, setTo] = useState(() => {
    const d = new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${day}T${hh}:${mm}`;
  });
  const [quickRange, setQuickRange] = useState('24h');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [pagination, setPagination] = useState({ page: 1, page_size: 20, total: 0, total_pages: 1 });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, page_size: pageSize, q: query || undefined, status: status || undefined, from: from || undefined, to: to || undefined };
      if (verdict.length) params.verdict = verdict.join(',');
      if (assigneeFilter && assigneeFilter !== 'all') params.assignee = assigneeFilter;
      const { data } = await api.get('/incidents', { params });
      setItems(data?.items || []);
      setPagination(data?.pagination || { page: 1, page_size: pageSize, total: 0, total_pages: 1 });
    } catch {
      setItems([]);
      setPagination({ page: 1, page_size: pageSize, total: 0, total_pages: 1 });
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, query, status, verdict, assigneeFilter, from, to]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  const toggleVerdict = (v) => setVerdict((prev) => prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v]);

  const toDateTimeLocal = (d) => {
    const dt = new Date(d);
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const day = String(dt.getDate()).padStart(2, '0');
    const hh = String(dt.getHours()).padStart(2, '0');
    const mm = String(dt.getMinutes()).padStart(2, '0');
    return `${y}-${m}-${day}T${hh}:${mm}`;
  };

  const applyQuickRange = (key) => {
    const now = new Date();
    const fromDate = new Date(now.getTime() - (key === '1h' ? 60 * 60 * 1000 : key === '24h' ? 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000));
    setFrom(toDateTimeLocal(fromDate));
    setTo(toDateTimeLocal(now));
    setQuickRange(key);
    setPage(1);
  };

  const resetFilters = () => {
    setQuery('');
    setStatus('');
    setVerdict([]);
    setAssigneeFilter('all');
    applyQuickRange('24h');
  };

  const assigneeOptions = useMemo(() => {
    const set = new Set();
    for (const it of items || []) {
      const a = String(it?.assigned_to || '').trim();
      if (a) set.add(a);
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [items]);

  const activeFilters = [];
  if (from || to) activeFilters.push({ key: 'date', label: `${from || '-'} → ${to || '-'}`, onClear: () => { setFrom(''); setTo(''); setQuickRange(''); } });
  if (status) activeFilters.push({ key: 'status', label: `Status: ${status}`, onClear: () => setStatus('') });
  if (verdict.length) activeFilters.push({ key: 'verdict', label: `Verdict: ${verdict.join(', ')}`, onClear: () => setVerdict([]) });
  if (assigneeFilter !== 'all') activeFilters.push({ key: 'assignee', label: `Assignee: ${assigneeFilter}`, onClear: () => setAssigneeFilter('all') });

  const [tableWidths, setTableWidths] = useState({
    incidentId: 110,
    createdAt: 170,
    ioc: 240,
    type: 90,
    observedHosts: 130,
    firstSeen: 170,
    lastSeen: 170,
    status: 100,
    verdict: 120,
    assignee: 160,
    action: 100
  });
  const [resizeState, setResizeState] = useState(null);

  useEffect(() => {
    if (!resizeState) return;
    const onMove = (e) => {
      const delta = e.clientX - resizeState.startX;
      const next = Math.max(80, resizeState.startWidth + delta);
      setTableWidths((prev) => ({ ...prev, [resizeState.col]: next }));
    };
    const onUp = () => setResizeState(null);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [resizeState]);

  const startResize = (e, col) => {
    e.preventDefault();
    e.stopPropagation();
    setResizeState({ col, startX: e.clientX, startWidth: tableWidths[col] || 120 });
  };

  const headerCell = (label, col, extraProps = {}) => (
    <th style={{ position: 'relative', ...(col ? { width: tableWidths[col] } : {}), ...extraProps }}>
      {label}
      {col && (
        <span
          onMouseDown={(e) => startResize(e, col)}
          style={{ position: 'absolute', right: 0, top: 0, width: 8, height: '100%', cursor: 'col-resize', userSelect: 'none' }}
          title="Resize"
        />
      )}
    </th>
  );

  return (
    <AppShell>
      <section style={{ border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 }}>
        <h2 style={{ marginTop: 0 }}>Incidents</h2>

        <div style={{ display: 'grid', gap: 8, marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <input placeholder="Search IOC or #IncidentID..." value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { setPage(1); load().catch(() => {}); } }} style={{ minWidth: 320 }} />
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">Status: All</option>
              <option value="open">Open</option>
              <option value="closed">Closed</option>
            </select>
            <select value={assigneeFilter} onChange={(e) => setAssigneeFilter(e.target.value)}>
              <option value="all">Assignee: All</option>
              <option value="unassigned">Assignee: Unassigned</option>
              {assigneeOptions.map((u) => <option key={u} value={u}>{u}</option>)}
            </select>
            <input type="datetime-local" value={from} onChange={(e) => { setFrom(e.target.value); setQuickRange(''); }} />
            <input type="datetime-local" value={to} onChange={(e) => { setTo(e.target.value); setQuickRange(''); }} />
            <button
              onClick={() => applyQuickRange('1h')}
              style={{ borderColor: quickRange === '1h' ? '#93c5fd' : '#475569' }}
            >
              Last 1 hour
            </button>
            <button
              onClick={() => applyQuickRange('24h')}
              style={{ borderColor: quickRange === '24h' ? '#93c5fd' : '#475569' }}
            >
              Last 24 hours
            </button>
            <button
              onClick={() => applyQuickRange('7d')}
              style={{ borderColor: quickRange === '7d' ? '#93c5fd' : '#475569' }}
            >
              Last 7 days
            </button>
            <button onClick={() => { setPage(1); load().catch(() => {}); }}>Filter</button>
            <button onClick={resetFilters}>Clear</button>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, background: '#0b1220', padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ color: '#93c5fd', fontSize: 12, fontWeight: 700 }}>Active Filters</span>
            {activeFilters.length ? activeFilters.map((f) => (
              <span key={f.key + f.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, border: '1px solid #475569', borderRadius: 999, padding: '3px 8px', fontSize: 12, color: '#cbd5e1' }}>
                {f.label}
                <button onClick={f.onClear} style={{ border: 'none', background: 'transparent', color: '#94a3b8', cursor: 'pointer', padding: 0 }}>✕</button>
              </span>
            )) : <span style={{ color: '#64748b', fontSize: 12 }}>None</span>}
            <button onClick={resetFilters} style={{ marginLeft: 'auto', fontSize: 12 }}>Clear all</button>
          </div>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {['TP', 'FP', 'Suspicious', 'Unreviewed', 'In Progress'].map((v) => (
              <label key={v} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <input type="checkbox" checked={verdict.includes(v)} onChange={() => toggleVerdict(v)} /> {v}
              </label>
            ))}
          </div>
        </div>

        <div style={{ border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 1500 }}>
            <colgroup>
              <col style={{ width: tableWidths.incidentId }} />
              <col style={{ width: tableWidths.createdAt }} />
              <col style={{ width: tableWidths.ioc }} />
              <col style={{ width: tableWidths.type }} />
              <col style={{ width: tableWidths.observedHosts }} />
              <col style={{ width: tableWidths.firstSeen }} />
              <col style={{ width: tableWidths.lastSeen }} />
              <col style={{ width: tableWidths.status }} />
              <col style={{ width: tableWidths.verdict }} />
              <col style={{ width: tableWidths.assignee }} />
              <col style={{ width: tableWidths.action }} />
            </colgroup>
            <thead>
              <tr style={{ textAlign: 'left', background: '#1f2937' }}>
                {headerCell('Incident ID', 'incidentId')}
                {headerCell('Created At', 'createdAt')}
                {headerCell('IOC', 'ioc')}
                {headerCell('Type', 'type')}
                {headerCell(<span title="Number of unique hosts where this IOC was observed in logs">Observed Hosts</span>, 'observedHosts')}
                {headerCell('First Seen', 'firstSeen')}
                {headerCell('Last Seen', 'lastSeen')}
                {headerCell('Status', 'status')}
                {headerCell('Verdict', 'verdict')}
                {headerCell('Assignee', 'assignee')}
                {headerCell('Action', 'action')}
              </tr>
            </thead>
            <tbody>
              {loading ? <tr><td colSpan={11} style={{ color: '#94a3b8' }}>Loading incidents...</td></tr> : items.length ? items.map((it) => (
                <tr key={it.id} style={{ borderTop: '1px solid #334155', cursor: 'pointer' }} onClick={() => navigate(`/incidents/${it.incident_id || it.id}`)}>
                  <td><b>#{it.incident_id || '-'}</b></td>
                  <td>{formatUserDateTime(it.created_at)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{it.ioc_value}</td>
                  <td>{it.ioc_type}</td>
                  <td>{it.asset_count || 0}</td>
                  <td>{formatUserDateTime(it.first_seen)}</td>
                  <td>{formatUserDateTime(it.last_seen)}</td>
                  <td>{it.status}</td>
                  <td>{it.verdict}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{it.assigned_to || 'Unassigned'}</td>
                  <td><button onClick={(e) => { e.stopPropagation(); navigate(`/incidents/${it.incident_id || it.id}`); }}>View</button></td>
                </tr>
              )) : <tr><td colSpan={11} style={{ color: '#94a3b8' }}>No incidents.</td></tr>}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ color: '#94a3b8', fontSize: 13 }}>Total: {pagination.total}</div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <select value={String(pageSize)} onChange={(e) => { setPage(1); setPageSize(Number(e.target.value)); }}>
              <option value="10">10 / page</option>
              <option value="20">20 / page</option>
              <option value="50">50 / page</option>
            </select>
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={pagination.page <= 1}>Prev</button>
            <span>Page {pagination.page} / {pagination.total_pages}</span>
            <button onClick={() => setPage((p) => Math.min(p + 1, pagination.total_pages))} disabled={pagination.page >= pagination.total_pages}>Next</button>
          </div>
        </div>
      </section>
    </AppShell>
  );
}

function SystemStatusPage() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadStatus = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get('/system/status');
      setStatus(data);
    } catch {
      setError('Failed to load system status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStatus().catch(() => {});
  }, [loadStatus]);

  const database = status?.database || {};
  const redisStatus = status?.redis || {};
  const clickhouseStatus = status?.clickhouse || {};
  const queues = status?.queues || {};
  const queueRows = Object.entries(queues).filter(([key]) => key !== 'error');
  const integrations = status?.integrations || {};
  const telemetry = status?.telemetry || {};

  const statusDot = (ok) => ({
    display: 'inline-flex',
    alignItems: 'center',
    gap: 8,
    fontSize: 13,
    fontWeight: 700,
    color: ok ? '#22c55e' : '#f87171'
  });

  const renderTimestamp = (value) => (value ? formatUserDateTime(value) : '-');

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
          <div>
            <h2 style={{ margin: 0 }}>System Status</h2>
            <div style={{ color: '#94a3b8', fontSize: 13 }}>
              Last refresh: <b>{status?.generated_at ? formatUserDateTime(status.generated_at) : '-'}</b>
            </div>
          </div>
          <button onClick={() => loadStatus().catch(() => {})} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>

        {error && (
          <div style={{ marginTop: 12, padding: 10, borderRadius: 8, border: '1px solid #f87171', background: '#451a1a', color: '#fecaca' }}>
            {error}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12, marginTop: 16 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 700 }}>Database</div>
              <span style={statusDot(database.ok)}>● {database.ok ? 'OK' : 'Down'}</span>
            </div>
            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Name:</b> {database.current_database || '-'}</div>
              <div><b>Version:</b> {database.version ? database.version.split('on')[0].trim() : '-'}</div>
              <div><b>Size:</b> {database.size_mb !== undefined ? `${database.size_mb} MB` : '-'}</div>
              <div><b>Connections:</b> {database.connections ? `${database.connections.total} (active ${database.connections.active}, idle ${database.connections.idle})` : '-'}</div>
              {database.error && <div style={{ color: '#f87171' }}>{database.error}</div>}
            </div>
          </div>

          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 700 }}>Redis</div>
              <span style={statusDot(redisStatus.ok)}>● {redisStatus.ok ? 'OK' : 'Down'}</span>
            </div>
            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Version:</b> {redisStatus.version || '-'}</div>
              <div><b>Mode:</b> {redisStatus.mode || '-'}</div>
              <div><b>Uptime:</b> {redisStatus.uptime_seconds ? `${Math.round(redisStatus.uptime_seconds / 3600)}h` : '-'}</div>
              <div><b>Clients:</b> {redisStatus.connected_clients ?? '-'}</div>
              <div><b>Memory:</b> {redisStatus.memory_used_mb ? `${redisStatus.memory_used_mb} MB` : '-'}</div>
              {redisStatus.error && <div style={{ color: '#f87171' }}>{redisStatus.error}</div>}
            </div>
          </div>

          {/* ClickHouse card moved below as full-width section */}
        </div>

        <div style={{ marginTop: 20, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>ClickHouse</span>
            <span style={statusDot(clickhouseStatus.ok)}>● {clickhouseStatus.ok ? 'OK' : 'Down'}</span>
          </div>
          <div style={{ padding: 12, background: '#0f172a' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 6, fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Table:</b> {clickhouseStatus.table || 'syslog_logs'}</div>
              <div><b>Version:</b> {clickhouseStatus.version || '-'}</div>
              <div><b>Rows:</b> {clickhouseStatus.rows ?? '-'}</div>
              <div><b>Size:</b> {clickhouseStatus.size_mb !== undefined ? `${clickhouseStatus.size_mb} MB` : '-'}</div>
              <div><b>Retro Pending IOC:</b> {clickhouseStatus.retro_pending_ioc ?? '-'}</div>
              <div><b>Last retro scanned IOC:</b> {clickhouseStatus.retro_last_scanned_ioc ?? '-'}</div>
              <div><b>Last Retro Duration:</b> {clickhouseStatus.retro_last_duration_ms !== undefined ? `${clickhouseStatus.retro_last_duration_ms} ms` : '-'}</div>
              <div><b>Last Retro Run:</b> {clickhouseStatus.retro_last_run_at_iso ? formatUserDateTime(clickhouseStatus.retro_last_run_at_iso) : (clickhouseStatus.retro_last_run_at || '-')}</div>
              <div><b>Retro Cursor TS:</b> {clickhouseStatus.retro_cursor_ts_iso ? formatUserDateTime(clickhouseStatus.retro_cursor_ts_iso) : (clickhouseStatus.retro_cursor_ts || '-')}</div>
            </div>
            {clickhouseStatus.note && <div style={{ color: '#94a3b8', marginTop: 8 }}>{clickhouseStatus.note}</div>}
            {clickhouseStatus.error && <div style={{ color: '#f87171', marginTop: 8 }}>{clickhouseStatus.error}</div>}
          </div>
        </div>

        <div style={{ marginTop: 20, border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Queues</div>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 480 }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#111827' }}>
                <th>Queue</th>
                <th>Waiting</th>
                <th>Active</th>
                <th>Completed</th>
                <th>Failed</th>
                <th>Delayed</th>
              </tr>
            </thead>
            <tbody>
              {queueRows.length ? queueRows.map(([name, counts]) => (
                <tr key={name} style={{ borderTop: '1px solid #334155' }}>
                  <td style={{ textTransform: 'capitalize' }}>{name.replace(/_/g, ' ')}</td>
                  <td>{counts?.waiting ?? '-'}</td>
                  <td>{counts?.active ?? '-'}</td>
                  <td>{counts?.completed ?? '-'}</td>
                  <td>{counts?.failed ?? '-'}</td>
                  <td>{counts?.delayed ?? '-'}</td>
                </tr>
              )) : (
                <tr><td colSpan={6} style={{ color: '#94a3b8' }}>{queues.error || 'No queue data available'}</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginTop: 20 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>Integration Pipeline</div>
            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Active feeds:</b> {integrations.active_feeds ?? '-'} / {integrations.total_feeds ?? '-'}</div>
              <div><b>Last queue job:</b> {integrations.last_queue_job ? `${integrations.last_queue_job.status} @ ${renderTimestamp(integrations.last_queue_job.queued_at)}` : '-'}</div>
              <div><b>Last run:</b> {integrations.last_run ? `${integrations.last_run.status} (${integrations.last_run.job_type}) @ ${renderTimestamp(integrations.last_run.started_at)}` : '-'}</div>
              {integrations.error && <div style={{ color: '#f87171' }}>{integrations.error}</div>}
            </div>
          </div>


          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: 14, background: '#0f172a' }}>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>Telemetry</div>
            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><b>Signal events (24h):</b> {telemetry.signal_events_24h ?? '-'}</div>
              <div><b>Total IOCs:</b> {telemetry.ioc_total ?? '-'}</div>
              <div><b>IOCs added today:</b> {telemetry.ioc_today ?? '-'}</div>
              {telemetry.error && <div style={{ color: '#f87171' }}>{telemetry.error}</div>}
            </div>
          </div>
        </div>
      </section>
    </AppShell>
  );
}

function IntegrationsPage({ title = 'Feeds', onlyKeys = null, hideKeys = null, showRunAll = true } = {}) {
  const { canWrite } = useSession();
  const [loading, setLoading] = useState(true);
  const [integrations, setIntegrations] = useState([]);
  const [runningNowAll, setRunningNowAll] = useState(false);
  const [runningKeys, setRunningKeys] = useState({});
  const [tableWidths, setTableWidths] = useState({ name: 180, integrationId: 190, source: 280, addedAt: 170, schedule: 140, status: 120, lastRun: 170, nextRun: 180, action: 130 });
  const [resizeState, setResizeState] = useState(null);

  async function load() {
    setLoading(true);
    try {
      const { data } = await api.get('/integrations');
      setIntegrations(data?.integrations || []);
    } catch {
      setIntegrations([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load().catch(() => {}); }, []);

  async function runNowAll() {
    if (!canWrite) return;
    const ok = window.confirm('All integrations will be queued now. Do you want to continue?');
    if (!ok || runningNowAll) return;
    setRunningNowAll(true);
    try {
      await api.post('/integrations/run-now');
      await load();
      alert('All integrations queued');
    } catch {
      alert('Failed to queue integrations');
    } finally {
      setRunningNowAll(false);
    }
  }

  async function runNowOne(key, name) {
    if (!canWrite) return;
    const ok = window.confirm(`Queue run for ${name || key} now?`);
    if (!ok || runningKeys[key]) return;
    setRunningKeys((prev) => ({ ...prev, [key]: true }));
    try {
      await api.post(`/integrations/${encodeURIComponent(key)}/run-now`);
      await load();
      alert(`${key} queued`);
    } catch {
      alert(`Failed to queue ${key}`);
    } finally {
      setRunningKeys((prev) => ({ ...prev, [key]: false }));
    }
  }

  async function updateTrustLevel(key, trustLevel) {
    if (!canWrite) return;
    try {
      await api.put(`/integrations/${encodeURIComponent(key)}/trust-level`, { trust_level: trustLevel });
      setIntegrations((prev) => prev.map((i) => (i.key === key ? { ...i, trust_level: trustLevel } : i)));
    } catch {
      alert('Failed to update trust level');
    }
  }

  async function updateSchedule(key, scheduleCron) {
    if (!canWrite) return;
    try {
      await api.put(`/integrations/${encodeURIComponent(key)}/schedule`, { schedule_cron: scheduleCron });
      setIntegrations((prev) => prev.map((i) => (i.key === key ? { ...i, schedule: scheduleCron } : i)));
    } catch {
      alert('Failed to update schedule');
    }
  }

  const statusColor = (status) => {
    if (status === 'success') return '#166534';
    if (status === 'failed' || status === 'fail') return '#991b1b';
    if (status === 'running') return '#92400e';
    return '#334155';
  };

  const statusLabel = (status) => {
    if (status === 'success') return 'success';
    if (status === 'failed' || status === 'fail') return 'fail';
    if (status === 'running') return 'running';
    return 'never';
  };

  const SCHEDULE_OPTIONS = [
    { cron: '*/5 * * * *', label: 'Every 5 minutes' },
    { cron: '*/15 * * * *', label: 'Every 15 minutes' },
    { cron: '*/30 * * * *', label: 'Every 30 minutes' },
    { cron: '0 * * * *', label: 'Every hour' },
    { cron: '0 0 * * *', label: 'Every 24 hours' }
  ];

  const humanSchedule = (cron) => {
    const c = String(cron || '').trim();
    const found = SCHEDULE_OPTIONS.find((o) => o.cron === c);
    if (found) return found.label;
    return c || '-';
  };

  useEffect(() => {
    if (!resizeState) return undefined;
    function onMove(e) {
      const delta = e.clientX - resizeState.startX;
      const next = Math.max(80, resizeState.startWidth + delta);
      setTableWidths((prev) => ({ ...prev, [resizeState.col]: next }));
    }
    function onUp() { setResizeState(null); }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [resizeState]);

  function startResize(col, e) {
    e.preventDefault();
    e.stopPropagation();
    setResizeState({ col, startX: e.clientX, startWidth: tableWidths[col] || 120 });
  }

  const visibleIntegrations = integrations.filter((i) => {
    if (Array.isArray(onlyKeys) && onlyKeys.length) return onlyKeys.includes(i.key);
    if (Array.isArray(hideKeys) && hideKeys.length) return !hideKeys.includes(i.key);
    return true;
  });

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
          <h2 style={{ marginTop: 0, marginBottom: 10 }}>{title}</h2>
          <div style={{ display: 'flex', gap: 8 }}>
            {showRunAll ? <button onClick={runNowAll} disabled={runningNowAll || !canWrite}>{runningNowAll ? 'Queueing...' : 'Run now (all)'}</button> : null}
            <button onClick={() => load().catch(() => {})}>Refresh</button>
          </div>
        </div>

        {loading ? <div>Loading...</div> : (
          <div style={{ overflowX: 'auto' }}>
            <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
              <colgroup>
                <col style={{ width: tableWidths.name }} />
                <col style={{ width: tableWidths.integrationId }} />
                <col style={{ width: tableWidths.source }} />
                <col style={{ width: tableWidths.addedAt }} />
                <col style={{ width: tableWidths.schedule }} />
                <col style={{ width: tableWidths.status }} />
                <col style={{ width: tableWidths.lastRun }} />
                <col style={{ width: tableWidths.nextRun }} />
                <col style={{ width: tableWidths.action }} />
              </colgroup>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
                  <th style={{ position: 'relative' }}>Name<div onMouseDown={(e) => startResize('name', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th style={{ position: 'relative' }}>Integration ID<div onMouseDown={(e) => startResize('integrationId', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th style={{ position: 'relative' }}>Source<div onMouseDown={(e) => startResize('source', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th style={{ position: 'relative' }}>Added At<div onMouseDown={(e) => startResize('addedAt', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th style={{ position: 'relative' }}>Schedule<div onMouseDown={(e) => startResize('schedule', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th style={{ position: 'relative' }}>Last status<div onMouseDown={(e) => startResize('status', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th style={{ position: 'relative' }}>Last run start<div onMouseDown={(e) => startResize('lastRun', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th style={{ position: 'relative' }}>Next run<div onMouseDown={(e) => startResize('nextRun', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th style={{ position: 'relative' }}>Action<div onMouseDown={(e) => startResize('action', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                </tr>
              </thead>
              <tbody>
                {visibleIntegrations.map((i) => (
                  <tr key={i.key} style={{ borderBottom: '1px solid #f1f5f9' }}>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{i.name}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{i.integration_id || '-'}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{i.source_url}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(i.created_at)}</td>
                    <td>
                      <select
                        value={i.schedule || '0 * * * *'}
                        onChange={(e) => updateSchedule(i.key, e.target.value)}
                        disabled={!canWrite}
                        style={{ width: '100%', minWidth: 0, padding: '6px 8px', borderRadius: 8, border: '1px solid #cbd5e1', boxSizing: 'border-box', opacity: canWrite ? 1 : 0.55 }}
                      >
                        {SCHEDULE_OPTIONS.map((opt) => (
                          <option key={opt.cron} value={opt.cron}>{opt.label}</option>
                        ))}
                      </select>
                    </td>
                    <td style={{ color: statusColor(i.last_status), fontWeight: 700, textTransform: 'capitalize', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{statusLabel(i.last_status)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(i.last_started_at)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(i.next_run_at)}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}><button type="button" onClick={() => runNowOne(i.key, i.name)} disabled={Boolean(runningKeys[i.key]) || !canWrite}>{runningKeys[i.key] ? 'Queueing...' : 'Run now'}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </AppShell>
  );
}


function IntegrationsEnrichmentPage() {
  return <IntegrationsPage title="Enrichment" onlyKeys={["asn_enrichment"]} showRunAll={false} />;
}

function IntegrationsQueueStatusPage() {
  const [loading, setLoading] = useState(true);
  const [queue, setQueue] = useState({ counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [], pagination: { page: 1, page_size: 25, total: 0, total_pages: 1 } });
  const [tableWidths, setTableWidths] = useState({ id: 130, integration: 180, name: 140, state: 100, queued: 170, reason: 320 });
  const [resizeState, setResizeState] = useState(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [search, setSearch] = useState('');
  const [windowValue, setWindowValue] = useState('24h');

  async function load(targetPage = page, targetPageSize = pageSize, targetSearch = search, targetWindow = windowValue) {
    setLoading(true);
    try {
      const { data } = await api.get('/integrations', {
        params: {
          queue_page: targetPage,
          queue_page_size: targetPageSize,
          queue_search: targetSearch || undefined,
          queue_window: targetWindow
        }
      });
      setQueue(data?.queue || { counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [], pagination: { page: 1, page_size: 25, total: 0, total_pages: 1 } });
    } catch {
      setQueue({ counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [], pagination: { page: 1, page_size: targetPageSize, total: 0, total_pages: 1 } });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(page, pageSize, search, windowValue).catch(() => {}); }, [page, pageSize, search, windowValue]);

  useEffect(() => {
    if (!resizeState) return undefined;
    function onMove(e) {
      const delta = e.clientX - resizeState.startX;
      const next = Math.max(80, resizeState.startWidth + delta);
      setTableWidths((prev) => ({ ...prev, [resizeState.col]: next }));
    }
    function onUp() { setResizeState(null); }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [resizeState]);

  function startResize(col, e) {
    e.preventDefault();
    e.stopPropagation();
    setResizeState({ col, startX: e.clientX, startWidth: tableWidths[col] || 120 });
  }

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
          <h2 style={{ marginTop: 0 }}>Job Queue Status</h2>
          <button onClick={() => load(page, pageSize, search, windowValue).catch(() => {})}>Refresh</button>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
          <input
            value={search}
            onChange={(e) => { setPage(1); setSearch(e.target.value); }}
            placeholder="Search all columns..."
            style={{ minWidth: 260, padding: '8px 10px', borderRadius: 8, border: '1px solid #cbd5e1' }}
          />
          <select value={windowValue} onChange={(e) => { setPage(1); setWindowValue(e.target.value); }} style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid #cbd5e1' }}>
            <option value="24h">24 hours</option>
            <option value="1d">1 day</option>
            <option value="7d">7 days</option>
          </select>
          <select value={pageSize} onChange={(e) => { setPage(1); setPageSize(Number(e.target.value)); }} style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid #cbd5e1' }}>
            <option value={25}>25 rows</option>
            <option value={50}>50 rows</option>
          </select>
        </div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 10, fontSize: 14 }}>
          <span>Waiting: <b>{queue.counts?.waiting || 0}</b></span>
          <span>Active: <b>{queue.counts?.active || 0}</b></span>
          <span>Delayed: <b>{queue.counts?.delayed || 0}</b></span>
          <span>Failed: <b>{queue.counts?.failed || 0}</b></span>
          <span>Completed: <b>{queue.counts?.completed || 0}</b></span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
            <colgroup>
              <col style={{ width: tableWidths.id }} />
              <col style={{ width: tableWidths.integration }} />
              <col style={{ width: tableWidths.name }} />
              <col style={{ width: tableWidths.state }} />
              <col style={{ width: tableWidths.queued }} />
              <col style={{ width: tableWidths.reason }} />
            </colgroup>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
                <th style={{ position: 'relative' }}>Job ID<div onMouseDown={(e) => startResize('id', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Integration<div onMouseDown={(e) => startResize('integration', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Name<div onMouseDown={(e) => startResize('name', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>State<div onMouseDown={(e) => startResize('state', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Queued At<div onMouseDown={(e) => startResize('queued', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Reason<div onMouseDown={(e) => startResize('reason', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              </tr>
            </thead>
            <tbody>
              {loading ? <tr><td colSpan={6}>Loading...</td></tr> : (queue.jobs?.length ? queue.jobs.map((j) => (
                <tr key={String(j.id)} style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{j.id}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{j.integration_name || j.integration_key || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{j.name}</td>
                  <td style={{ color: (j.state === 'success' ? '#166534' : (j.state === 'failed' || j.state === 'fail' ? '#991b1b' : '#334155')), fontWeight: 700, textTransform: 'capitalize' }}>{j.state === 'fail' ? 'failed' : (j.state || '-')}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(j.timestamp)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{j.failed_reason || (j.state === 'success' ? 'Completed successfully' : '-')}</td>
                </tr>
              )) : <tr><td colSpan={6} style={{ color: '#64748b' }}>No queued jobs</td></tr>)}
            </tbody>
          </table>
        </div>
        <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
          <div style={{ color: '#64748b', fontSize: 13 }}>
            Page {queue.pagination?.page || page} / {queue.pagination?.total_pages || 1} · Total {queue.pagination?.total || 0}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button disabled={(queue.pagination?.page || page) <= 1 || loading} onClick={() => setPage((p) => Math.max(1, p - 1))}>Prev</button>
            <button disabled={(queue.pagination?.page || page) >= (queue.pagination?.total_pages || 1) || loading} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      </section>
    </AppShell>
  );
}

function IntegrationsRecentRunsPage() {
  const [loading, setLoading] = useState(true);
  const [recentRuns, setRecentRuns] = useState([]);
  const [tableWidths, setTableWidths] = useState({ id: 130, integration: 180, name: 140, state: 100, queued: 170, reason: 320 });
  const [resizeState, setResizeState] = useState(null);

  async function load() {
    setLoading(true);
    try {
      const { data } = await api.get('/integrations');
      setRecentRuns(data?.recent_runs || []);
    } catch {
      setRecentRuns([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load().catch(() => {}); }, []);

  useEffect(() => {
    if (!resizeState) return undefined;
    function onMove(e) {
      const delta = e.clientX - resizeState.startX;
      const next = Math.max(80, resizeState.startWidth + delta);
      setTableWidths((prev) => ({ ...prev, [resizeState.col]: next }));
    }
    function onUp() { setResizeState(null); }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [resizeState]);

  function startResize(col, e) {
    e.preventDefault();
    e.stopPropagation();
    setResizeState({ col, startX: e.clientX, startWidth: tableWidths[col] || 120 });
  }

  const statusColor = (status) => {
    if (status === 'success') return '#166534';
    if (status === 'failed' || status === 'fail') return '#991b1b';
    if (status === 'running') return '#92400e';
    if (status === 'queued') return '#1d4ed8';
    return '#334155';
  };

  const statusLabel = (status) => {
    if (status === 'success') return 'success';
    if (status === 'failed' || status === 'fail') return 'fail';
    if (status === 'running') return 'running';
    if (status === 'queued') return 'queued';
    return 'never';
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
          <h2 style={{ marginTop: 0 }}>Recent Runs</h2>
          <button onClick={() => load().catch(() => {})}>Refresh</button>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
            <colgroup>
              <col style={{ width: tableWidths.id }} />
              <col style={{ width: tableWidths.integration }} />
              <col style={{ width: tableWidths.name }} />
              <col style={{ width: tableWidths.state }} />
              <col style={{ width: tableWidths.queued }} />
              <col style={{ width: tableWidths.reason }} />
            </colgroup>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
                <th style={{ position: 'relative' }}>Job ID<div onMouseDown={(e) => startResize('id', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Integration<div onMouseDown={(e) => startResize('integration', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Name<div onMouseDown={(e) => startResize('name', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>State<div onMouseDown={(e) => startResize('state', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Queued At<div onMouseDown={(e) => startResize('queued', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Reason<div onMouseDown={(e) => startResize('reason', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              </tr>
            </thead>
            <tbody>
              {loading ? <tr><td colSpan={6}>Loading...</td></tr> : (recentRuns.length ? recentRuns.map((r) => (
                <tr key={String(r.job_id || r.id)} style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.job_id || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.integration_name || r.integration_key || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.name || r.job_type || '-'}</td>
                  <td style={{ color: statusColor(r.state || r.status), fontWeight: 700, textTransform: 'capitalize' }}>{statusLabel(r.state || r.status)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(r.timestamp || r.started_at)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.failed_reason || ((r.state || r.status) === 'success' ? 'Completed successfully' : '-')}</td>
                </tr>
              )) : <tr><td colSpan={6} style={{ color: '#64748b' }}>No runs yet</td></tr>)}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}

const FEED_WINDOW_OPTIONS = [
  { value: '1d', label: 'Last 1 day' },
  { value: '3d', label: 'Last 3 days' },
  { value: '7d', label: 'Last 1 week' },
  { value: 'all', label: 'All' }
];

const FEED_VERDICT_FILTER_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'malicious', label: 'Malicious' },
  { value: 'suspicious', label: 'Suspicious' }
];

function verdictFilterFromFeed(feed) {
  const arr = Array.isArray(feed?.verdict_filter) ? feed.verdict_filter : [];
  if (!arr.length) return ['all'];
  const lower = arr.map((v) => String(v).trim().toLowerCase()).filter(Boolean);
  if (lower.includes('all')) return ['all'];
  const known = lower.filter((v) => v === 'malicious' || v === 'suspicious');
  return known.length ? known : ['all'];
}

function verdictFilterToPayload(selected) {
  const v = Array.isArray(selected) ? selected : [];
  if (!v.length || v.includes('all')) return null;
  return v.filter((x) => x !== 'all');
}

function normalizeVerdictFilterSelection(selected, previous = []) {
  if (!selected.length) return ['all'];
  if (selected.includes('all') && selected.length > 1) {
    if (!previous.includes('all')) return ['all'];
    return selected.filter((x) => x !== 'all');
  }
  if (selected.includes('all')) return ['all'];
  return selected;
}

function FeedVerdictMultiSelect({ ui, value, onChange }) {
  const selected = Array.isArray(value) && value.length ? value : ['all'];
  return (
    <select
      multiple
      size={FEED_VERDICT_FILTER_OPTIONS.length}
      value={selected}
      onChange={(e) => {
        const next = Array.from(e.target.selectedOptions, (o) => o.value);
        onChange(normalizeVerdictFilterSelection(next, selected));
      }}
      style={{ ...ui.select, minHeight: 88 }}
    >
      {FEED_VERDICT_FILTER_OPTIONS.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

const PUBLISHED_FEEDS_UI = {
  section: { border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 },
  pageTitle: { margin: 0, fontSize: 22, fontWeight: 700, color: '#f1f5f9' },
  formPanel: {
    marginBottom: 20,
    padding: 16,
    border: '1px solid #334155',
    borderRadius: 10,
    background: '#0f172a'
  },
  formTitle: { marginTop: 0, marginBottom: 14, fontSize: 16, fontWeight: 600, color: '#e2e8f0' },
  label: { display: 'block', fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6 },
  input: {
    width: '100%',
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#020617',
    color: '#e2e8f0',
    fontSize: 14,
    boxSizing: 'border-box'
  },
  select: {
    width: '100%',
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#020617',
    color: '#e2e8f0',
    fontSize: 14,
    boxSizing: 'border-box',
    cursor: 'pointer'
  },
  textarea: {
    width: '100%',
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#020617',
    color: '#e2e8f0',
    fontSize: 14,
    boxSizing: 'border-box',
    minHeight: 72,
    resize: 'vertical'
  },
  helper: { display: 'block', fontSize: 11, color: '#64748b', marginTop: 4, lineHeight: 1.45 },
  checkRow: { display: 'flex', flexWrap: 'wrap', gap: 16, marginTop: 10 },
  checkLabel: { display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#cbd5e1', cursor: 'pointer' },
  btn: {
    padding: '8px 14px',
    borderRadius: 8,
    border: '1px solid #475569',
    background: '#1f2937',
    color: '#e2e8f0',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer'
  },
  btnPrimary: {
    padding: '8px 18px',
    borderRadius: 8,
    border: 'none',
    background: '#2563eb',
    color: '#fff',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer'
  },
  thead: { textAlign: 'left', borderBottom: '1px solid #334155', background: '#0f172a' },
  th: {
    padding: '10px 8px',
    color: '#94a3b8',
    fontSize: 11,
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.05em'
  },
  tr: { borderBottom: '1px solid #1e293b' },
  td: { padding: '10px 8px', color: '#e2e8f0', verticalAlign: 'middle' },
  expandCell: { background: '#0f172a', padding: 12, borderTop: '1px solid #334155' },
  linkBtn: { background: 'none', border: 'none', padding: 0, cursor: 'pointer', fontWeight: 600, color: '#93c5fd' },
  muted: { color: '#64748b' },
  modal: {
    width: 560,
    maxWidth: '96vw',
    background: 'linear-gradient(180deg, #111827 0%, #0f172a 100%)',
    borderRadius: 12,
    padding: 20,
    border: '1px solid #334155',
    color: '#e2e8f0',
    boxShadow: '0 24px 60px rgba(2,6,23,0.55)'
  },
  pageSub: { margin: '0 0 16px', fontSize: 14, color: '#94a3b8', lineHeight: 1.55, maxWidth: 720 },
  formModal: {
    width: 'min(720px, 96vw)',
    maxHeight: '90vh',
    overflowY: 'auto',
    background: 'linear-gradient(180deg, #111827 0%, #0f172a 100%)',
    borderRadius: 12,
    padding: 24,
    border: '1px solid #334155',
    color: '#e2e8f0',
    boxShadow: '0 24px 60px rgba(2,6,23,0.55)'
  },
  sectionHeading: {
    fontSize: 12,
    fontWeight: 700,
    color: '#94a3b8',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    margin: '0 0 12px',
    paddingBottom: 8,
    borderBottom: '1px solid #1e293b'
  },
  banner: {
    marginBottom: 16,
    padding: '12px 14px',
    borderRadius: 8,
    border: '1px solid #1d4ed8',
    background: 'rgba(37, 99, 235, 0.12)',
    color: '#bfdbfe',
    fontSize: 13,
    lineHeight: 1.5
  },
  badge: (on) => ({
    display: 'inline-block',
    marginLeft: 8,
    padding: '2px 8px',
    borderRadius: 999,
    fontSize: 10,
    fontWeight: 700,
    textTransform: 'uppercase',
    background: on ? 'rgba(34, 197, 94, 0.15)' : 'rgba(148, 163, 184, 0.15)',
    color: on ? '#86efac' : '#94a3b8',
    border: `1px solid ${on ? '#166534' : '#475569'}`
  }),
  modalSub: { fontSize: 13, color: '#94a3b8', margin: '0 0 12px', lineHeight: 1.5 },
  code: {
    display: 'block',
    wordBreak: 'break-all',
    padding: 10,
    background: '#020617',
    border: '1px solid #334155',
    borderRadius: 6,
    fontSize: 12,
    color: '#cbd5e1'
  }
};

function feedPullUrl(token) {
  const tok = token || '********';
  return `${window.location.origin}/public/feeds/${encodeURIComponent(tok)}/feed.txt`;
}

function PullUrlExamplesList({ ui, token, iocType, onCopy }) {
  const examples = feedUrlExamples(token, iocType);
  return (
    <ul style={{ margin: 0, paddingLeft: 0, listStyle: 'none', fontSize: 12 }}>
      {examples.map((ex) => (
        <li key={ex.label} style={{ marginBottom: 10, padding: 10, background: '#020617', borderRadius: 8, border: '1px solid #334155' }}>
          <div style={{ color: '#94a3b8', marginBottom: 4, fontSize: 11, fontWeight: 600 }}>{ex.label}</div>
          <code style={{ ...ui.code, marginBottom: token ? 6 : 0 }}>{ex.url}</code>
          {token && onCopy ? (
            <button type="button" style={{ ...ui.btn, fontSize: 11, padding: '4px 10px', marginTop: 6 }} onClick={() => onCopy(ex.url)}>Copy URL</button>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function feedUrlExamples(token, iocType = 'ip') {
  const base = feedPullUrl(token);
  const t = encodeURIComponent(iocType);
  return [
    { label: 'Default URL', url: base },
    { label: 'With limit', url: `${base}?limit=40000` },
    { label: 'With window', url: `${base}?window=7d` },
    { label: 'With ioc_type + window + limit', url: `${base}?ioc_type=${t}&window=7d&limit=40000` }
  ];
}

function FeedFormField({ ui, label, helper, children, fullWidth = false }) {
  return (
    <div style={fullWidth ? { gridColumn: '1 / -1' } : undefined}>
      <span style={ui.label}>{label}</span>
      {children}
      {helper ? <span style={ui.helper}>{helper}</span> : null}
    </div>
  );
}

function FeedFormSection({ title, children }) {
  const ui = PUBLISHED_FEEDS_UI;
  return (
    <div style={{ marginBottom: 22 }}>
      <h4 style={ui.sectionHeading}>{title}</h4>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
        {children}
      </div>
    </div>
  );
}

function PublishedFeedsPage() {
  const { canWrite } = useSession();
  const [loading, setLoading] = useState(true);
  const [feeds, setFeeds] = useState([]);
  const [showFormModal, setShowFormModal] = useState(false);
  const [editing, setEditing] = useState(null);
  const [regenerating, setRegenerating] = useState({});
  const [nextStep, setNextStep] = useState(null);
  const [form, setForm] = useState({
    name: '',
    description: '',
    enabled: true,
    ioc_type: 'ip',
    exclude_false_positive: true,
    exclude_expired: true,
    include_sources: '',
    include_tags: '',
    exclude_tags: '',
    verdict_filter: ['all'],
    time_window: 'all',
    max_items: '',
    refresh_interval_minutes: 15
  });

  async function loadFeeds() {
    setLoading(true);
    try {
      const { data } = await api.get('/published-feeds');
      setFeeds(data?.feeds || []);
    } catch {
      setFeeds([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadFeeds().catch(() => {}); }, []);

  function closeFormModal() {
    setShowFormModal(false);
    setEditing(null);
  }

  function openCreateForm() {
    setEditing(null);
    setForm({
      name: '',
      description: '',
      enabled: true,
      ioc_type: 'ip',
      exclude_false_positive: true,
      exclude_expired: true,
      include_sources: '',
      include_tags: '',
      exclude_tags: '',
      verdict_filter: ['all'],
      time_window: 'all',
      max_items: '',
      refresh_interval_minutes: 15
    });
    setShowFormModal(true);
  }

  function openEditForm(feed) {
    setEditing(feed);
    setForm({
      name: feed.name || '',
      description: feed.description || '',
      enabled: Boolean(feed.enabled),
      ioc_type: feed.ioc_type || 'ip',
      exclude_false_positive: feed.exclude_false_positive !== false,
      exclude_expired: feed.exclude_expired !== false,
      include_sources: (feed.include_sources || []).join(', '),
      include_tags: (feed.include_tags || []).join(', '),
      exclude_tags: (feed.exclude_tags || []).join(', '),
      verdict_filter: verdictFilterFromFeed(feed),
      time_window: feed.time_window || 'all',
      max_items: feed.max_items ?? '',
      refresh_interval_minutes: feed.refresh_interval_minutes || 15
    });
    setShowFormModal(true);
  }

  function splitCsv(s) {
    return String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
  }

  function buildPayload() {
    return {
      name: form.name.trim(),
      description: form.description.trim() || null,
      enabled: Boolean(form.enabled),
      ioc_type: form.ioc_type,
      format: 'txt',
      exclude_false_positive: Boolean(form.exclude_false_positive),
      exclude_expired: Boolean(form.exclude_expired),
      include_sources: splitCsv(form.include_sources),
      include_tags: splitCsv(form.include_tags),
      exclude_tags: splitCsv(form.exclude_tags),
      verdict_filter: verdictFilterToPayload(form.verdict_filter),
      time_window: form.time_window,
      max_items: form.max_items === '' ? null : Number(form.max_items),
      refresh_interval_minutes: Number(form.refresh_interval_minutes) || 15
    };
  }

  async function saveFeed(e) {
    e.preventDefault();
    if (!canWrite) return;
    const payload = buildPayload();
    try {
      if (editing?.id) {
        await api.patch(`/published-feeds/${editing.id}`, payload);
        closeFormModal();
        setNextStep(null);
        await loadFeeds();
      } else {
        const { data } = await api.post('/published-feeds', payload);
        const created = data?.feed;
        closeFormModal();
        await loadFeeds();
        if (created?.id) {
          setNextStep({
            message: 'Feed created. Create a Feed Access Key from Administration > API Keys to generate a pull URL.',
            feedId: created.id
          });
        }
      }
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to save feed');
    }
  }

  async function deleteFeed(id) {
    if (!canWrite || !window.confirm('Delete this published feed?')) return;
    try {
      await api.delete(`/published-feeds/${id}`);
      setNextStep(null);
      await loadFeeds();
    } catch {
      alert('Failed to delete feed');
    }
  }

  async function regenerateFeed(id) {
    if (!canWrite || regenerating[id]) return;
    setRegenerating((p) => ({ ...p, [id]: true }));
    try {
      await api.post(`/published-feeds/${id}/regenerate`);
      await loadFeeds();
    } catch {
      alert('Regenerate failed');
    } finally {
      setRegenerating((p) => ({ ...p, [id]: false }));
    }
  }

  const windowLabel = (w) => FEED_WINDOW_OPTIONS.find((o) => o.value === w)?.label || w;
  const ui = PUBLISHED_FEEDS_UI;

  return (
    <AppShell>
      <section className="published-feeds-page" style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, marginBottom: 8, flexWrap: 'wrap' }}>
          <div>
            <h2 style={ui.pageTitle}>Published Feeds</h2>
            <p style={ui.pageSub}>
              Publish filtered IOC snapshots as pull-based threat feeds for internal tools such as firewalls, proxies, DNS security, EDR, SIEM, or SOAR platforms.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button type="button" style={ui.btn} onClick={() => loadFeeds().catch(() => {})}>Refresh</button>
            {canWrite ? <button type="button" style={ui.btnPrimary} onClick={openCreateForm}>Create Feed</button> : null}
          </div>
        </div>

        {nextStep ? (
          <div style={ui.banner}>
            {nextStep.message}
            {nextStep.feedId && canWrite ? (
              <Link
                to={`/administration/api-keys?feed_id=${nextStep.feedId}`}
                style={{ ...ui.btnPrimary, marginLeft: 12, padding: '6px 12px', fontSize: 12, display: 'inline-block', textDecoration: 'none' }}
                onClick={() => setNextStep(null)}
              >
                Create API Key
              </Link>
            ) : null}
          </div>
        ) : null}

        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table published-feeds-table" width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 13, background: 'transparent' }}>
            <thead>
              <tr style={ui.thead}>
                <th style={ui.th}>Name</th>
                <th style={ui.th}>IOC Type</th>
                <th style={ui.th}>Window</th>
                <th style={ui.th}>Max Items</th>
                <th style={ui.th}>Last Generated</th>
                <th style={ui.th}>Status</th>
                <th style={ui.th}>Items</th>
                <th style={ui.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr style={ui.tr}><td colSpan={8} style={ui.td}>Loading...</td></tr>
              ) : feeds.length ? feeds.map((f) => (
                <tr key={f.id} style={ui.tr}>
                    <td style={ui.td}>
                      <span style={{ fontWeight: 600 }}>{f.name}</span>
                      {!f.enabled ? <span style={ui.badge(false)}>disabled</span> : null}
                      <span style={{ ...ui.badge(true), marginLeft: 6, background: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', border: '1px solid #1e40af' }}>txt</span>
                      {f.last_error ? <div style={{ color: '#fca5a5', fontSize: 11, marginTop: 4 }}>Last error: {f.last_error}</div> : null}
                    </td>
                    <td style={ui.td}>{f.ioc_type}</td>
                    <td style={ui.td}>{windowLabel(f.time_window)}</td>
                    <td style={ui.td}>{f.max_items ?? '—'}</td>
                    <td style={ui.td}>{formatUserDateTime(f.last_generated_at)}</td>
                    <td style={{
                      ...ui.td,
                      color: f.last_status === 'success' ? '#86efac' : f.last_status === 'failed' ? '#fca5a5' : '#fcd34d',
                      fontWeight: 600
                    }}>{f.last_status || '—'}</td>
                    <td style={ui.td}>{f.last_item_count ?? '—'}</td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>
                      {canWrite ? (
                        <button type="button" style={ui.btn} onClick={() => openEditForm(f)}>Edit</button>
                      ) : null}
                      {canWrite ? (
                        <button type="button" style={{ ...ui.btn, marginLeft: 6 }} disabled={regenerating[f.id]} onClick={() => regenerateFeed(f.id)}>
                          {regenerating[f.id] ? '...' : 'Regenerate'}
                        </button>
                      ) : null}
                      {canWrite ? (
                        <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => deleteFeed(f.id)}>Delete</button>
                      ) : null}
                      {canWrite ? (
                        <Link
                          to={`/administration/api-keys?feed_id=${f.id}`}
                          style={{ ...ui.btn, marginLeft: 6, display: 'inline-block', textDecoration: 'none', fontSize: 12 }}
                        >
                          Create API Key
                        </Link>
                      ) : null}
                    </td>
                  </tr>
              )) : (
                <tr>
                  <td colSpan={8} style={{ ...ui.td, padding: '28px 12px', textAlign: 'center' }}>
                    <p style={{ margin: '0 0 12px', color: '#94a3b8', lineHeight: 1.5 }}>
                      No published feeds yet. Create a feed to publish filtered IOC snapshots for internal security products.
                    </p>
                    {canWrite ? (
                      <button type="button" style={ui.btnPrimary} onClick={openCreateForm}>Create Feed</button>
                    ) : null}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {showFormModal ? (
        <div
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}
          onClick={closeFormModal}
        >
          <div style={ui.formModal} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
            <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>
              {editing ? 'Edit Published Feed' : 'Create Published Feed'}
            </h3>
            <p style={ui.modalSub}>
              {editing
                ? 'Update filters and delivery settings. Regenerate snapshots after changing filters.'
                : 'Create a filtered IOC snapshot feed. Add a Feed Access Key under Administration > API Keys to generate a pull URL.'}
            </p>
            {!editing ? (
              <p style={{ ...ui.modalSub, marginTop: -6 }}>
                Choose the IOC type, filters, default time window, and delivery limits. After creation, generate a Feed Access Key on Administration > API Keys.
              </p>
            ) : null}

            <form onSubmit={saveFeed}>
              <FeedFormSection title="Basic">
                <FeedFormField ui={ui} label="Name">
                  <input required value={form.name} onChange={(e) => setForm((x) => ({ ...x, name: e.target.value }))} style={ui.input} />
                </FeedFormField>
                <FeedFormField ui={ui} label="Enabled">
                  <label style={ui.checkLabel}>
                    <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((x) => ({ ...x, enabled: e.target.checked }))} />
                    Feed is active
                  </label>
                </FeedFormField>
                <FeedFormField ui={ui} label="Description" fullWidth>
                  <textarea value={form.description} onChange={(e) => setForm((x) => ({ ...x, description: e.target.value }))} style={ui.textarea} rows={2} />
                </FeedFormField>
              </FeedFormSection>

              <FeedFormSection title="Feed content">
                <FeedFormField ui={ui} label="IOC Type" helper="The type of indicators this feed will publish. One feed publishes one IOC type.">
                  <select required value={form.ioc_type} onChange={(e) => setForm((x) => ({ ...x, ioc_type: e.target.value }))} style={ui.select}>
                    <option value="ip">ip</option>
                    <option value="domain">domain</option>
                    <option value="url">url</option>
                    <option value="hash">hash</option>
                  </select>
                </FeedFormField>
                <FeedFormField ui={ui} label="Default Window" helper="Default time range used when the consumer does not pass ?window=.">
                  <select value={form.time_window} onChange={(e) => setForm((x) => ({ ...x, time_window: e.target.value }))} style={ui.select}>
                    {FEED_WINDOW_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </FeedFormField>
                <FeedFormField
                  ui={ui}
                  label="Verdict Filter"
                  helper="Default is All (no verdict filter). Hold Ctrl or Cmd to select multiple types."
                  fullWidth
                >
                  <FeedVerdictMultiSelect
                    ui={ui}
                    value={form.verdict_filter}
                    onChange={(next) => setForm((x) => ({ ...x, verdict_filter: next }))}
                  />
                </FeedFormField>
              </FeedFormSection>

              <FeedFormSection title="Safety filters">
                <div style={{ gridColumn: '1 / -1', display: 'flex', flexWrap: 'wrap', gap: 16 }}>
                  <label style={ui.checkLabel}>
                    <input type="checkbox" checked={form.exclude_false_positive} onChange={(e) => setForm((x) => ({ ...x, exclude_false_positive: e.target.checked }))} />
                    Exclude false positives
                  </label>
                  <label style={ui.checkLabel}>
                    <input type="checkbox" checked={form.exclude_expired} onChange={(e) => setForm((x) => ({ ...x, exclude_expired: e.target.checked }))} />
                    Exclude expired
                  </label>
                </div>
                <FeedFormField ui={ui} label="Sources" helper="Optional. Comma-separated source names.">
                  <input value={form.include_sources} onChange={(e) => setForm((x) => ({ ...x, include_sources: e.target.value }))} style={ui.input} placeholder="source_a, source_b" />
                </FeedFormField>
                <FeedFormField ui={ui} label="Include Tags" helper="Optional. Comma-separated tag names.">
                  <input value={form.include_tags} onChange={(e) => setForm((x) => ({ ...x, include_tags: e.target.value }))} style={ui.input} />
                </FeedFormField>
                <FeedFormField ui={ui} label="Exclude Tags" helper="Optional. Comma-separated tag names.">
                  <input value={form.exclude_tags} onChange={(e) => setForm((x) => ({ ...x, exclude_tags: e.target.value }))} style={ui.input} />
                </FeedFormField>
              </FeedFormSection>

              <FeedFormSection title="Delivery">
                <FeedFormField ui={ui} label="Max Items" helper="Optional cap for products that support limited feed size, e.g. 40,000 IPs.">
                  <input type="number" min={1} placeholder="optional" value={form.max_items} onChange={(e) => setForm((x) => ({ ...x, max_items: e.target.value }))} style={ui.input} />
                </FeedFormField>
                <FeedFormField ui={ui} label="Refresh (minutes)" helper="How often snapshots should be regenerated. Minimum 5 minutes.">
                  <input type="number" min={5} value={form.refresh_interval_minutes} onChange={(e) => setForm((x) => ({ ...x, refresh_interval_minutes: e.target.value }))} style={ui.input} />
                </FeedFormField>
              </FeedFormSection>

              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 8, paddingTop: 16, borderTop: '1px solid #334155' }}>
                <button type="button" style={ui.btn} onClick={closeFormModal}>Cancel</button>
                <button type="submit" style={ui.btnPrimary} disabled={!canWrite}>
                  {editing ? 'Save changes' : 'Create Feed'}
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

    </AppShell>
  );
}

function ApiKeysPage() {
  const { canWrite } = useSession();
  const [searchParams] = useSearchParams();
  const preselectedFeedId = searchParams.get('feed_id');
  const ui = PUBLISHED_FEEDS_UI;
  const [loading, setLoading] = useState(true);
  const [keys, setKeys] = useState([]);
  const [feeds, setFeeds] = useState([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [expandedKeyId, setExpandedKeyId] = useState(null);
  const [tokenReveal, setTokenReveal] = useState(null);
  const [form, setForm] = useState({
    name: '',
    key_type: 'feed_access',
    feed_id: '',
    enabled: true
  });
  const didAutoOpenFromQuery = useRef(false);

  async function loadAll() {
    setLoading(true);
    try {
      const [keysRes, feedsRes] = await Promise.all([
        api.get('/api-keys'),
        api.get('/published-feeds')
      ]);
      setKeys(keysRes.data?.api_keys || []);
      setFeeds(feedsRes.data?.feeds || []);
    } catch {
      setKeys([]);
      setFeeds([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAll().catch(() => {}); }, []);

  useEffect(() => {
    if (didAutoOpenFromQuery.current) return;
    if (!preselectedFeedId || !feeds.some((f) => String(f.id) === String(preselectedFeedId))) return;
    setForm((x) => ({ ...x, feed_id: String(preselectedFeedId) }));
    if (canWrite) {
      setShowCreateModal(true);
      didAutoOpenFromQuery.current = true;
    }
  }, [preselectedFeedId, feeds, canWrite]);

  function openCreateModal() {
    const presetFeedId = preselectedFeedId && feeds.some((f) => String(f.id) === String(preselectedFeedId))
      ? String(preselectedFeedId)
      : '';
    setForm({
      name: '',
      key_type: 'feed_access',
      feed_id: feeds.length === 1 ? String(feeds[0].id) : presetFeedId,
      enabled: true
    });
    setShowCreateModal(true);
  }

  function keyTypeLabel(t) {
    return t === 'feed_access' ? 'Feed Access Key' : t;
  }

  function copyText(text) {
    navigator.clipboard?.writeText(text).then(() => alert('Copied')).catch(() => alert(text));
  }

  async function createKey(e) {
    e.preventDefault();
    if (!canWrite) return;
    const feedId = Number(form.feed_id);
    if (!feedId) {
      alert('Select a published feed.');
      return;
    }
    try {
      const { data } = await api.post('/api-keys', {
        name: form.name.trim(),
        key_type: 'feed_access',
        feed_id: feedId,
        enabled: Boolean(form.enabled)
      });
      const feed = feeds.find((f) => f.id === feedId);
      setShowCreateModal(false);
      setTokenReveal({
        title: 'API key created',
        feed_url: data.feed_url,
        token: data.token,
        ioc_type: feed?.ioc_type || data.api_key?.feed_ioc_type
      });
      await loadAll();
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to create API key');
    }
  }

  async function rotateKey(keyId) {
    if (!canWrite || !window.confirm('Rotate this key? The old token stops working immediately.')) return;
    try {
      const { data } = await api.post(`/api-keys/${keyId}/rotate`);
      const key = keys.find((k) => k.id === keyId);
      setTokenReveal({
        title: 'API key rotated',
        feed_url: data.feed_url,
        token: data.token,
        ioc_type: key?.feed_ioc_type
      });
      await loadAll();
    } catch {
      alert('Failed to rotate API key');
    }
  }

  async function revokeKey(keyId) {
    if (!canWrite || !window.confirm('Revoke this API key? Pull access stops immediately.')) return;
    try {
      await api.post(`/api-keys/${keyId}/revoke`);
      await loadAll();
    } catch {
      alert('Failed to revoke API key');
    }
  }

  async function toggleEnabled(key) {
    if (!canWrite || key.status === 'revoked') return;
    try {
      await api.patch(`/api-keys/${key.id}`, { enabled: !key.enabled });
      await loadAll();
    } catch {
      alert('Failed to update API key');
    }
  }

  const hasFeeds = feeds.length > 0;

  return (
    <AppShell>
      <section className="published-feeds-page api-keys-page" style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, marginBottom: 8, flexWrap: 'wrap' }}>
          <div>
            <h2 style={ui.pageTitle}>API Keys</h2>
            <p style={ui.pageSub}>
              Manage low-privilege access keys used by internal tools to pull published threat feeds. These keys do not grant access to admin APIs.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button type="button" style={ui.btn} onClick={() => loadAll().catch(() => {})}>Refresh</button>
            {canWrite && hasFeeds ? (
              <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Create API Key</button>
            ) : null}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="ioc-table published-feeds-table" width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 13, background: 'transparent' }}>
            <thead>
              <tr style={ui.thead}>
                <th style={ui.th}>Name</th>
                <th style={ui.th}>Type</th>
                <th style={ui.th}>Published Feed</th>
                <th style={ui.th}>IOC Type</th>
                <th style={ui.th}>Status</th>
                <th style={ui.th}>Last Used</th>
                <th style={ui.th}>Last IP</th>
                <th style={ui.th}>Created At</th>
                <th style={ui.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr style={ui.tr}><td colSpan={9} style={ui.td}>Loading...</td></tr>
              ) : keys.length ? keys.map((k) => (
                <React.Fragment key={k.id}>
                  <tr style={ui.tr}>
                    <td style={ui.td}>{k.name}</td>
                    <td style={ui.td}>{keyTypeLabel(k.key_type)}</td>
                    <td style={ui.td}>{k.feed_name || '—'}</td>
                    <td style={ui.td}>{k.feed_ioc_type || '—'}</td>
                    <td style={ui.td}>{k.status}</td>
                    <td style={ui.td}>{formatUserDateTime(k.last_used_at)}</td>
                    <td style={ui.td}>{k.last_used_ip || '—'}</td>
                    <td style={ui.td}>{formatUserDateTime(k.created_at)}</td>
                    <td style={{ ...ui.td, whiteSpace: 'nowrap' }}>
                      <button type="button" style={ui.btn} onClick={() => setExpandedKeyId((prev) => (prev === k.id ? null : k.id))}>
                        {expandedKeyId === k.id ? 'Hide URLs' : 'URL examples'}
                      </button>
                      {canWrite && k.status !== 'revoked' ? (
                        <>
                          <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => rotateKey(k.id)}>Rotate</button>
                          <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => revokeKey(k.id)}>Revoke</button>
                          <button type="button" style={{ ...ui.btn, marginLeft: 6 }} onClick={() => toggleEnabled(k)}>
                            {k.enabled ? 'Disable' : 'Enable'}
                          </button>
                        </>
                      ) : null}
                    </td>
                  </tr>
                  {expandedKeyId === k.id ? (
                    <tr>
                      <td colSpan={9} style={ui.expandCell}>
                        <strong style={{ color: '#cbd5e1', fontSize: 13 }}>Pull URL examples</strong>
                        <p style={{ ...ui.helper, marginTop: 4, marginBottom: 8 }}>
                          Token is masked. Copy the full URL only right after create or rotate.
                        </p>
                        <PullUrlExamplesList ui={ui} token={null} iocType={k.feed_ioc_type || 'ip'} />
                      </td>
                    </tr>
                  ) : null}
                </React.Fragment>
              )) : (
                <tr>
                  <td colSpan={9} style={{ ...ui.td, padding: '28px 12px', textAlign: 'center' }}>
                    <p style={{ margin: '0 0 12px', color: '#94a3b8', lineHeight: 1.5 }}>
                      No API keys yet. Create a Feed Access Key to let internal tools pull a published feed.
                    </p>
                    {canWrite && hasFeeds ? (
                      <button type="button" style={ui.btnPrimary} onClick={openCreateModal}>Create API Key</button>
                    ) : null}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {!hasFeeds && !loading ? (
          <div style={{ ...ui.banner, marginTop: 16 }}>
            Create a Published Feed first before generating a Feed Access Key.{' '}
            <Link to="/threat-intelligence/published-feeds" style={{ color: '#93c5fd', fontWeight: 600 }}>Go to Published Feeds</Link>
          </div>
        ) : null}
      </section>

      {showCreateModal ? (
        <div
          style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}
          onClick={() => setShowCreateModal(false)}
        >
          <div style={ui.formModal} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
            <h3 style={{ ...ui.formTitle, fontSize: 18, marginBottom: 6 }}>Create API Key</h3>
            {!hasFeeds ? (
              <p style={ui.modalSub}>
                Create a Published Feed first before generating a Feed Access Key.{' '}
                <Link to="/threat-intelligence/published-feeds">Go to Published Feeds</Link>
              </p>
            ) : (
              <form onSubmit={createKey}>
                <FeedFormField ui={ui} label="Key name" fullWidth>
                  <input required value={form.name} onChange={(e) => setForm((x) => ({ ...x, name: e.target.value }))} style={ui.input} placeholder="e.g. Fortigate-01" />
                </FeedFormField>
                <FeedFormField ui={ui} label="Key type" fullWidth>
                  <select value={form.key_type} style={ui.select} disabled>
                    <option value="feed_access">Feed Access Key</option>
                  </select>
                </FeedFormField>
                <FeedFormField ui={ui} label="Published Feed" helper="Feed this key can pull." fullWidth>
                  <select
                    required
                    value={form.feed_id}
                    onChange={(e) => setForm((x) => ({ ...x, feed_id: e.target.value }))}
                    style={ui.select}
                  >
                    <option value="">Select feed…</option>
                    {feeds.map((f) => (
                      <option key={f.id} value={f.id}>{f.name} ({f.ioc_type})</option>
                    ))}
                  </select>
                </FeedFormField>
                <FeedFormField ui={ui} label="Enabled" fullWidth>
                  <label style={ui.checkLabel}>
                    <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((x) => ({ ...x, enabled: e.target.checked }))} />
                    Key is active
                  </label>
                </FeedFormField>
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16, paddingTop: 16, borderTop: '1px solid #334155' }}>
                  <button type="button" style={ui.btn} onClick={() => setShowCreateModal(false)}>Cancel</button>
                  <button type="submit" style={ui.btnPrimary} disabled={!canWrite}>Create API Key</button>
                </div>
              </form>
            )}
          </div>
        </div>
      ) : null}

      {tokenReveal ? (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1001, padding: 16 }}>
          <div style={{ ...ui.modal, maxWidth: 560, width: '100%' }}>
            <h3 style={{ marginTop: 0, color: '#f1f5f9' }}>{tokenReveal.title}</h3>
            <p style={ui.modalSub}>Copy this URL now. The token will not be shown again.</p>
            <code style={ui.code}>{tokenReveal.feed_url}</code>
            <button type="button" style={{ ...ui.btnPrimary, marginTop: 10 }} onClick={() => copyText(tokenReveal.feed_url)}>Copy URL</button>
            <div style={{ marginTop: 20 }}>
              <strong style={{ color: '#cbd5e1', fontSize: 13 }}>Pull URL examples</strong>
              <div style={{ marginTop: 10 }}>
                <PullUrlExamplesList ui={ui} token={tokenReveal.token} iocType={tokenReveal.ioc_type} onCopy={copyText} />
              </div>
            </div>
            <button type="button" style={{ ...ui.btn, marginTop: 16, width: '100%' }} onClick={() => setTokenReveal(null)}>Done</button>
          </div>
        </div>
      ) : null}
    </AppShell>
  );
}

function EnrichmentProvidersPage() {
  const { canWrite } = useSession();
  const [loading, setLoading] = useState(true);
  const [p, setP] = useState(null);
  const [form, setForm] = useState({ enabled: true, ttl_hours: 24, timeout_ms: 12000, api_key: '' });
  const [feedback, setFeedback] = useState({ type: '', text: '' });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [removing, setRemoving] = useState(false);

  const statusMeta = (status) => {
    const s = String(status || '').toLowerCase();
    if (s === 'healthy') return { label: 'Healthy', bg: 'rgba(22,163,74,0.18)', color: '#86efac', border: '#166534' };
    if (s === 'error') return { label: 'Error', bg: 'rgba(220,38,38,0.18)', color: '#fca5a5', border: '#7f1d1d' };
    if (s === 'rate_limited') return { label: 'Rate limited', bg: 'rgba(217,119,6,0.18)', color: '#fcd34d', border: '#b45309' };
    if (s === 'configured') return { label: 'Configured', bg: 'rgba(37,99,235,0.18)', color: '#93c5fd', border: '#1d4ed8' };
    return { label: 'Not configured', bg: 'rgba(100,116,139,0.2)', color: '#cbd5e1', border: '#475569' };
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/admin/enrichment-providers');
      const vt = (data?.providers || []).find((x) => x.provider === 'virustotal') || null;
      setP(vt);
      if (vt) setForm((f) => ({ ...f, enabled: vt.enabled, ttl_hours: vt.ttl_hours || 24, timeout_ms: vt.timeout_ms || 12000 }));
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { load().catch(()=>{}); }, [load]);

  async function save() {
    setSaving(true);
    setFeedback({ type: '', text: '' });
    try {
      await api.put('/admin/enrichment-providers/virustotal', form);
      setFeedback({ type: 'success', text: 'Settings saved successfully.' });
      setForm((f) => ({ ...f, api_key: '' }));
      await load();
    } catch (e) {
      setFeedback({ type: 'error', text: e?.response?.data?.message || 'Save failed' });
    } finally { setSaving(false); }
  }

  async function testConn() {
    setTesting(true);
    setFeedback({ type: '', text: '' });
    try {
      const { data } = await api.post('/admin/enrichment-providers/virustotal/test');
      setFeedback({ type: 'success', text: data?.message || 'Connection successful' });
      await load();
    } catch (e) {
      const msg = e?.response?.data?.message || 'Test failed';
      const t = /rate limit/i.test(msg) ? 'warn' : 'error';
      setFeedback({ type: t, text: msg });
      await load();
    } finally { setTesting(false); }
  }

  async function removeKey() {
    setRemoving(true);
    setFeedback({ type: '', text: '' });
    try {
      await api.post('/admin/enrichment-providers/virustotal/remove-key');
      setFeedback({ type: 'success', text: 'API key removed.' });
      await load();
    } catch {
      setFeedback({ type: 'error', text: 'Remove failed' });
    } finally { setRemoving(false); }
  }

  const sm = statusMeta(p?.status);

  return <AppShell><section style={{ border:'1px solid #334155', borderRadius:12, background:'#111827', padding:20 }}>
    <h2 style={{ margin:'0 0 6px', color:'#f1f5f9' }}>Enrichment Providers</h2>
    <p style={{ margin:'0 0 18px', color:'#94a3b8', fontSize:14 }}>Manage external intelligence providers used for IOC enrichment.</p>

    {!canWrite ? <div style={{ marginBottom:12, padding:'10px 12px', borderRadius:8, border:'1px solid #475569', color:'#cbd5e1', background:'rgba(100,116,139,0.15)', fontSize:13 }}>Readonly users can view provider status but cannot modify settings.</div> : null}

    {feedback.text ? <div style={{ marginBottom:12, padding:'10px 12px', borderRadius:8, border:`1px solid ${feedback.type==='success' ? '#166534' : feedback.type==='warn' ? '#b45309' : '#7f1d1d'}`, color: feedback.type==='success' ? '#86efac' : feedback.type==='warn' ? '#fcd34d' : '#fca5a5', background: feedback.type==='success' ? 'rgba(22,163,74,0.18)' : feedback.type==='warn' ? 'rgba(217,119,6,0.18)' : 'rgba(220,38,38,0.18)', fontSize:13 }}>{feedback.text}</div> : null}

    {loading ? <div style={{ color:'#94a3b8' }}>Loading...</div> : !p ? <div style={{ color:'#94a3b8' }}>No provider config.</div> : <div style={{ border:'1px solid #334155', borderRadius:12, padding:16, background:'#0f172a' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:12, flexWrap:'wrap' }}>
        <div>
          <h3 style={{ margin:'0 0 4px', color:'#e2e8f0' }}>VirusTotal</h3>
          <div style={{ color:'#94a3b8', fontSize:13 }}>IOC reputation and analysis enrichment</div>
        </div>
        <div style={{ display:'flex', gap:10, alignItems:'center' }}>
          <span style={{ border:`1px solid ${sm.border}`, background:sm.bg, color:sm.color, borderRadius:999, padding:'4px 10px', fontSize:12, fontWeight:700 }}>{sm.label}</span>
          <label style={{ color:'#cbd5e1', fontSize:13, display:'inline-flex', alignItems:'center', gap:6 }}><input type='checkbox' checked={form.enabled} onChange={(e)=>setForm((x)=>({...x, enabled:e.target.checked}))} disabled={!canWrite}/> Enabled</label>
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:10, marginTop:14 }}>
        <div style={{ border:'1px solid #334155', borderRadius:8, padding:10, background:'#0b1220' }}><div style={{ color:'#94a3b8', fontSize:12 }}>API Key</div><div style={{ color:'#e2e8f0', fontSize:13, marginTop:4 }}>{p.masked_key ? (p.source === 'env' ? 'Configured via env' : 'Configured via db') : 'Not configured'}</div></div>
        <div style={{ border:'1px solid #334155', borderRadius:8, padding:10, background:'#0b1220' }}><div style={{ color:'#94a3b8', fontSize:12 }}>Last test</div><div style={{ color:'#e2e8f0', fontSize:13, marginTop:4 }}>{formatUserDateTime(p.last_test_at)}</div></div>
        <div style={{ border:'1px solid #334155', borderRadius:8, padding:10, background:'#0b1220' }}><div style={{ color:'#94a3b8', fontSize:12 }}>Last success</div><div style={{ color:'#e2e8f0', fontSize:13, marginTop:4 }}>{formatUserDateTime(p.last_success_at)}</div></div>
        <div style={{ border:'1px solid #334155', borderRadius:8, padding:10, background:'#0b1220' }}><div style={{ color:'#94a3b8', fontSize:12 }}>Cache TTL</div><div style={{ color:'#e2e8f0', fontSize:13, marginTop:4 }}>{form.ttl_hours} hours</div></div>
        <div style={{ border:'1px solid #334155', borderRadius:8, padding:10, background:'#0b1220' }}><div style={{ color:'#94a3b8', fontSize:12 }}>Timeout</div><div style={{ color:'#e2e8f0', fontSize:13, marginTop:4 }}>{form.timeout_ms} ms</div></div>
      </div>

      <div style={{ marginTop:14 }}>
        <label style={{ display:'block', color:'#cbd5e1', fontSize:13, marginBottom:6 }}>VirusTotal API Key</label>
        <input type='password' value={form.api_key} onChange={(e)=>setForm((x)=>({...x, api_key:e.target.value}))} placeholder={p.masked_key ? 'Leave blank to keep current key' : 'Paste VirusTotal API key'} disabled={!canWrite} style={{ width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0', boxSizing:'border-box' }} />
        {p.masked_key ? <div style={{ marginTop:6, color:'#94a3b8', fontSize:12 }}>Current key: {p.masked_key}</div> : null}
        <div style={{ marginTop:4, color:'#64748b', fontSize:12 }}>API key is never returned to the frontend.</div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(180px, 1fr))', gap:10, marginTop:14 }}>
        <label style={{ color:'#cbd5e1', fontSize:13 }}>Cache TTL (hours)
          <input type='number' min='1' value={form.ttl_hours} onChange={(e)=>setForm((x)=>({...x, ttl_hours:Number(e.target.value)}))} disabled={!canWrite} style={{ marginTop:6, width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0' }} />
        </label>
        <label style={{ color:'#cbd5e1', fontSize:13 }}>Timeout (ms)
          <input type='number' min='3000' value={form.timeout_ms} onChange={(e)=>setForm((x)=>({...x, timeout_ms:Number(e.target.value)}))} disabled={!canWrite} style={{ marginTop:6, width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid #334155', background:'#020617', color:'#e2e8f0' }} />
        </label>
      </div>

      <div style={{ display:'flex', gap:8, marginTop:14, flexWrap:'wrap' }}>
        <button onClick={()=>save().catch(()=>{})} disabled={!canWrite || saving || testing || removing} style={{ padding:'8px 14px', borderRadius:8, border:'1px solid #2563eb', background:'#2563eb', color:'#fff', fontWeight:600 }}>{saving ? 'Saving...' : 'Save settings'}</button>
        <button onClick={()=>testConn().catch(()=>{})} disabled={!canWrite || saving || testing || removing} style={{ padding:'8px 14px', borderRadius:8, border:'1px solid #475569', background:'#1f2937', color:'#e2e8f0', fontWeight:600 }}>{testing ? 'Testing...' : 'Test Connection'}</button>
        <button onClick={()=>removeKey().catch(()=>{})} disabled={!canWrite || saving || testing || removing} style={{ padding:'8px 14px', borderRadius:8, border:'1px solid #7f1d1d', background:'rgba(127,29,29,0.25)', color:'#fca5a5', fontWeight:600 }}>{removing ? 'Removing...' : 'Remove key'}</button>
      </div>

      {p.last_error_message ? <div style={{ marginTop:12, padding:'10px 12px', borderRadius:8, border:'1px solid #7f1d1d', background:'rgba(220,38,38,0.14)', color:'#fca5a5', fontSize:13 }}><b>Last provider error:</b> {p.last_error_message}</div> : null}
    </div>}
  </section></AppShell>;
}

function AdministrationPage() {
  const { canWrite, role, userId, refreshSession } = useSession();
  const [timezone, setTimezone] = useState(localStorage.getItem('demo_timezone') || 'UTC');
  const [saving, setSaving] = useState(false);
  const [users, setUsers] = useState([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [profile, setProfile] = useState({ first_name: '', last_name: '' });
  const [profileBusy, setProfileBusy] = useState(false);
  const [statusBusyId, setStatusBusyId] = useState(null);

  const ui = {
    pageTitle: { margin: '0 0 6px', fontSize: 22, fontWeight: 700, color: '#f1f5f9', letterSpacing: '-0.02em' },
    pageSub: { margin: '0 0 28px', fontSize: 14, color: '#94a3b8', lineHeight: 1.5, maxWidth: 560 },
    card: {
      border: '1px solid #334155',
      borderRadius: 12,
      background: '#111827',
      padding: 24,
      marginBottom: 24,
      boxSizing: 'border-box'
    },
    cardTitle: { margin: '0 0 4px', fontSize: 16, fontWeight: 600, color: '#e2e8f0' },
    cardDesc: { margin: '0 0 20px', fontSize: 13, color: '#94a3b8', lineHeight: 1.45 },
    label: {
      display: 'block',
      fontSize: 12,
      fontWeight: 600,
      color: '#94a3b8',
      marginBottom: 8,
      letterSpacing: '0.03em'
    },
    input: {
      width: '100%',
      padding: '10px 12px',
      borderRadius: 8,
      border: '1px solid #334155',
      background: '#0f172a',
      color: '#e2e8f0',
      fontSize: 14,
      boxSizing: 'border-box'
    },
    select: {
      width: '100%',
      padding: '10px 12px',
      borderRadius: 8,
      border: '1px solid #334155',
      background: '#0f172a',
      color: '#e2e8f0',
      fontSize: 14,
      boxSizing: 'border-box',
      cursor: 'pointer'
    },
    btnPrimary: {
      padding: '10px 22px',
      borderRadius: 8,
      border: 'none',
      background: '#2563eb',
      color: '#fff',
      fontWeight: 600,
      fontSize: 14,
      cursor: 'pointer',
      boxShadow: '0 1px 2px rgba(0,0,0,0.2)'
    },
    btnDanger: {
      padding: '6px 12px',
      borderRadius: 8,
      border: '1px solid #7f1d1d',
      background: 'rgba(127,29,29,0.25)',
      color: '#fca5a5',
      fontSize: 12,
      fontWeight: 600,
      cursor: 'pointer',
      display: 'inline-flex',
      alignItems: 'center',
      gap: 6
    },
    btnDeactivate: {
      padding: '6px 10px',
      borderRadius: 8,
      border: '1px solid #b45309',
      background: 'rgba(180,83,9,0.2)',
      color: '#fcd34d',
      fontSize: 12,
      fontWeight: 600,
      cursor: 'pointer'
    },
    btnActivate: {
      padding: '6px 10px',
      borderRadius: 8,
      border: '1px solid #166534',
      background: 'rgba(22,101,52,0.25)',
      color: '#86efac',
      fontSize: 12,
      fontWeight: 600,
      cursor: 'pointer'
    },
    actionsCell: {
      display: 'flex',
      flexWrap: 'wrap',
      gap: 8,
      justifyContent: 'flex-end',
      alignItems: 'center'
    },
    table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
    th: {
      textAlign: 'left',
      padding: '12px 14px',
      borderBottom: '1px solid #334155',
      color: '#94a3b8',
      fontSize: 11,
      fontWeight: 700,
      textTransform: 'uppercase',
      letterSpacing: '0.06em'
    },
    td: { padding: '14px', borderBottom: '1px solid #1e293b', color: '#e2e8f0', verticalAlign: 'middle' }
  };

  async function loadUsers() {
    if (!canWrite) return;
    setUsersLoading(true);
    try {
      const { data } = await api.get('/users');
      setUsers(data?.users || []);
    } catch {
      setUsers([]);
    } finally {
      setUsersLoading(false);
    }
  }

  useEffect(() => {
    loadUsers().catch(() => {});
  }, [canWrite]);

  async function loadSelfProfile() {
    if (canWrite || userId == null) return;
    try {
      const { data } = await api.get('/users');
      const u = (data?.users || [])[0];
      if (u) setProfile({ first_name: u.first_name || '', last_name: u.last_name || '' });
    } catch {
      /* ignore */
    }
  }

  useEffect(() => {
    loadSelfProfile().catch(() => {});
  }, [canWrite, userId]);

  async function save() {
    if (!canWrite) {
      localStorage.setItem('demo_timezone', timezone);
      alert('Timezone stored locally (read-only account).');
      return;
    }
    setSaving(true);
    try {
      const { data } = await api.put('/users/me/preferences', { timezone });
      localStorage.setItem('demo_timezone', data?.timezone || timezone);
      alert('Timezone updated');
    } catch {
      alert('Failed to update timezone');
    } finally {
      setSaving(false);
    }
  }

  async function createUser(e) {
    e.preventDefault();
    if (!canWrite) return;
    const form = e.currentTarget;
    const fd = new FormData(form);
    const username = String(fd.get('username') || '').trim();
    const password = fd.get('password');
    const first_name = String(fd.get('first_name') || '').trim();
    const last_name = String(fd.get('last_name') || '').trim();
    const r = String(fd.get('role') || 'readonly').trim();
    if (!username || !password) {
      alert('Username and password required');
      return;
    }
    setCreateBusy(true);
    try {
      await api.post('/users', { username, password, first_name, last_name, role: r });
      form.reset();
      await loadUsers();
      alert('User created');
    } catch (err) {
      const status = Number(err?.response?.status || 0);
      const backendMsg = String(err?.response?.data?.message || '').trim();
      if (status === 409 || /already exists/i.test(backendMsg)) {
        alert('This username is already in use. Please choose another one.');
      } else {
        const msg = backendMsg || err?.message || 'Failed to create user';
        alert(msg);
      }
    } finally {
      setCreateBusy(false);
    }
  }

  async function saveProfile(e) {
    e.preventDefault();
    if (userId == null) return;
    setProfileBusy(true);
    try {
      await api.put(`/users/${userId}`, {
        first_name: profile.first_name,
        last_name: profile.last_name
      });
      await refreshSession();
      alert('Profile updated');
    } catch (err) {
      const msg = err?.response?.data?.message || err?.message || 'Failed to update profile';
      alert(msg);
    } finally {
      setProfileBusy(false);
    }
  }

  async function removeUser(id) {
    if (!canWrite) return;
    if (!window.confirm('Are you sure you want to delete this user?')) return;
    try {
      await api.delete(`/users/${id}`);
      await loadUsers();
    } catch (err) {
      const msg = err?.response?.data?.message || err?.message || 'Failed to delete user';
      alert(msg);
    }
  }

  async function setUserStatus(targetId, next) {
    if (!canWrite) return;
    const confirmMsg =
      next === 'passive'
        ? 'Are you sure you want to deactivate this user?'
        : 'Are you sure you want to activate this user?';
    if (!window.confirm(confirmMsg)) return;
    setStatusBusyId(targetId);
    try {
      await api.patch(`/users/${targetId}/status`, { status: next });
      await loadUsers();
    } catch (err) {
      const msg = err?.response?.data?.message || err?.message || 'Failed to update status';
      alert(msg);
    } finally {
      setStatusBusyId(null);
    }
  }

  function formatDisplayName(u) {
    const t = `${u.first_name || ''} ${u.last_name || ''}`.trim();
    return t || 'Not set';
  }

  function accountStatusBadgeStyle(st) {
    if (String(st || 'active') === 'passive') {
      return {
        display: 'inline-block',
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: '0.03em',
        padding: '4px 10px',
        borderRadius: 6,
        background: 'rgba(71, 85, 105, 0.45)',
        color: '#cbd5e1',
        border: '1px solid #64748b'
      };
    }
    return {
      display: 'inline-block',
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: '0.04em',
      padding: '4px 10px',
      borderRadius: 6,
      background: 'rgba(22, 163, 74, 0.2)',
      color: '#86efac',
      border: '1px solid rgba(22, 101, 52, 0.85)'
    };
  }

  function roleBadgeStyle(r) {
    if (r === 'admin') {
      return {
        display: 'inline-block',
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: '0.04em',
        padding: '4px 10px',
        borderRadius: 6,
        background: 'rgba(185, 28, 28, 0.2)',
        color: '#fca5a5',
        border: '1px solid rgba(127, 29, 29, 0.8)'
      };
    }
    return {
      display: 'inline-block',
      fontSize: 11,
      fontWeight: 600,
      letterSpacing: '0.03em',
      padding: '4px 10px',
      borderRadius: 6,
      background: 'rgba(51, 65, 85, 0.5)',
      color: '#cbd5e1',
      border: '1px solid #475569'
    };
  }

  return (
    <AppShell>
      <div style={{ width: '100%', maxWidth: 960, margin: 0, boxSizing: 'border-box' }}>
        <h1 style={ui.pageTitle}>Administration</h1>
        <p style={ui.pageSub}>
          Manage your session timezone and, when permitted, platform users and roles.
        </p>

        <div style={ui.card}>
          <h2 style={ui.cardTitle}>Timezone</h2>
          <p style={ui.cardDesc}>Used for timestamps across the application.</p>
          <label htmlFor="admin-tz" style={ui.label}>Display timezone</label>
          <select
            id="admin-tz"
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            style={{ ...ui.select, maxWidth: 400 }}
          >
            {COMMON_TIMEZONES.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
          </select>
          <div style={{ marginTop: 16 }}>
            <button
              type="button"
              onClick={save}
              disabled={saving}
              style={{
                ...ui.btnPrimary,
                opacity: saving ? 0.75 : 1,
                cursor: saving ? 'wait' : 'pointer'
              }}
            >
              {saving ? 'Saving…' : 'Save timezone'}
            </button>
          </div>
        </div>

        {role === 'readonly' && userId != null ? (
          <div style={ui.card}>
            <h2 style={ui.cardTitle}>Your profile</h2>
            <p style={ui.cardDesc}>Update the name shown on your account.</p>
            <form onSubmit={saveProfile} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 20, maxWidth: 560 }}>
              <div>
                <label htmlFor="profile-fn" style={ui.label}>First name</label>
                <input
                  id="profile-fn"
                  value={profile.first_name}
                  onChange={(e) => setProfile((p) => ({ ...p, first_name: e.target.value }))}
                  style={ui.input}
                  autoComplete="given-name"
                />
              </div>
              <div>
                <label htmlFor="profile-ln" style={ui.label}>Last name</label>
                <input
                  id="profile-ln"
                  value={profile.last_name}
                  onChange={(e) => setProfile((p) => ({ ...p, last_name: e.target.value }))}
                  style={ui.input}
                  autoComplete="family-name"
                />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <button
                  type="submit"
                  disabled={profileBusy}
                  style={{
                    ...ui.btnPrimary,
                    opacity: profileBusy ? 0.75 : 1,
                    cursor: profileBusy ? 'wait' : 'pointer'
                  }}
                >
                  {profileBusy ? 'Saving…' : 'Update name'}
                </button>
              </div>
            </form>
          </div>
        ) : null}

        {canWrite ? (
          <>
            <div style={ui.card}>
              <h2 style={ui.cardTitle}>Create User</h2>
              <p style={ui.cardDesc}>Create a new user and assign role.</p>
              <form onSubmit={createUser} style={{ display: 'grid', gap: 20, maxWidth: 520 }}>
                <div>
                  <label htmlFor="new-first" style={ui.label}>First name</label>
                  <input id="new-first" name="first_name" style={ui.input} autoComplete="given-name" />
                </div>
                <div>
                  <label htmlFor="new-last" style={ui.label}>Last name</label>
                  <input id="new-last" name="last_name" style={ui.input} autoComplete="family-name" />
                </div>
                <div>
                  <label htmlFor="new-username" style={ui.label}>Username</label>
                  <input id="new-username" name="username" required style={ui.input} autoComplete="username" />
                </div>
                <div>
                  <label htmlFor="new-password" style={ui.label}>Password</label>
                  <input id="new-password" name="password" type="password" required style={ui.input} autoComplete="new-password" />
                </div>
                <div>
                  <label htmlFor="new-role" style={ui.label}>User Role</label>
                  <select id="new-role" name="role" defaultValue="readonly" style={ui.select}>
                    <option value="admin">Admin (Full Access)</option>
                    <option value="readonly">Read Only (View Only)</option>
                  </select>
                </div>
                <div>
                  <button
                    type="submit"
                    disabled={createBusy}
                    style={{
                      ...ui.btnPrimary,
                      opacity: createBusy ? 0.8 : 1,
                      cursor: createBusy ? 'wait' : 'pointer'
                    }}
                  >
                    {createBusy ? 'Creating…' : 'Create User'}
                  </button>
                </div>
              </form>
            </div>

            <div style={ui.card}>
              <h2 style={ui.cardTitle}>Users</h2>
              <p style={ui.cardDesc}>All accounts on this instance.</p>
              {usersLoading ? (
                <div style={{ color: '#94a3b8', padding: '8px 0' }}>Loading…</div>
              ) : users.length === 0 ? (
                <div style={{ color: '#64748b', fontSize: 14, padding: '12px 0' }}>No users yet.</div>
              ) : (
                <div style={{ overflowX: 'auto', margin: '4px -4px 0' }}>
                  <table className="ioc-table" style={ui.table}>
                    <thead>
                      <tr>
                        <th style={ui.th}>Username</th>
                        <th style={ui.th}>Name</th>
                        <th style={ui.th}>Role</th>
                        <th style={ui.th}>Status</th>
                        <th style={{ ...ui.th, textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((u) => {
                        const isPassive = String(u.status || 'active') === 'passive';
                        const isOwnRow = userId != null && String(userId) === String(u.id);
                        const busy = statusBusyId === u.id;
                        return (
                        <tr
                          key={u.id}
                          style={{
                            background: 'transparent',
                            opacity: isPassive ? 0.62 : 1
                          }}
                        >
                          <td style={{ ...ui.td, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace", fontSize: 13 }}>{u.username}</td>
                          <td style={ui.td}>{formatDisplayName(u)}</td>
                          <td style={ui.td}>
                            <span style={roleBadgeStyle(u.role)}>
                              {u.role === 'admin' ? 'Admin' : 'Read only'}
                            </span>
                          </td>
                          <td style={ui.td}>
                            <span style={accountStatusBadgeStyle(u.status)}>
                              {isPassive ? 'Passive' : 'Active'}
                            </span>
                          </td>
                          <td style={{ ...ui.td, textAlign: 'right' }}>
                            <div style={ui.actionsCell}>
                              {!isPassive ? (
                                <button
                                  type="button"
                                  onClick={() => setUserStatus(u.id, 'passive')}
                                  disabled={isOwnRow || busy}
                                  style={{
                                    ...ui.btnDeactivate,
                                    opacity: isOwnRow || busy ? 0.4 : 1,
                                    cursor: isOwnRow || busy ? 'not-allowed' : 'pointer'
                                  }}
                                  title={isOwnRow ? 'You cannot deactivate your own account' : 'Deactivate user'}
                                >
                                  {busy ? '…' : 'Deactivate'}
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => setUserStatus(u.id, 'active')}
                                  disabled={busy}
                                  style={{
                                    ...ui.btnActivate,
                                    opacity: busy ? 0.4 : 1,
                                    cursor: busy ? 'wait' : 'pointer'
                                  }}
                                  title="Activate user"
                                >
                                  {busy ? '…' : 'Activate'}
                                </button>
                              )}
                              <button
                                type="button"
                                onClick={() => removeUser(u.id)}
                                style={ui.btnDanger}
                                title="Delete user"
                              >
                                <span aria-hidden style={{ fontSize: 14, lineHeight: 1 }}>×</span>
                                Delete
                              </button>
                            </div>
                          </td>
                        </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        ) : null}
      </div>
    </AppShell>
  );
}

function isNewlyActiveHotIoc(firstSeenLog) {
  if (!firstSeenLog) return false;
  const t = new Date(firstSeenLog).getTime();
  if (Number.isNaN(t)) return false;
  return Date.now() - t <= 60 * 60 * 1000;
}

function IOCHotListPage() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [summary, setSummary] = useState({ total: 0, by_type: [], by_source: [] });
  const [loading, setLoading] = useState(false);
  const [banner, setBanner] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [typeFilter, setTypeFilter] = useState('');
  const [sinceFilter, setSinceFilter] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [pagination, setPagination] = useState({ page: 1, page_size: 50, total: 0, total_pages: 1 });

  const loadHot = useCallback(async () => {
    setLoading(true);
    setBanner('');
    try {
      const params = { page, limit: pageSize };
      if (typeFilter) params.type = typeFilter;
      if (sinceFilter) params.last_seen_since = sinceFilter;
      if (search) params.q = search;
      const { data } = await api.get('/ioc/hot', { params });
      setItems(data.items || []);
      setSummary(data.summary || { total: 0, by_type: [], by_source: [] });
      setPagination(data.pagination || { page: 1, page_size: pageSize, total: 0, total_pages: 1 });
    } catch {
      setItems([]);
      setSummary({ total: 0, by_type: [], by_source: [] });
      setBanner('Failed to load hot IOC list.');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, typeFilter, sinceFilter, search]);

  useEffect(() => {
    loadHot();
  }, [loadHot]);

  const hotBadge = (bg, color) => ({
    display: 'inline-block',
    marginLeft: 6,
    marginTop: 4,
    padding: '2px 8px',
    borderRadius: 999,
    fontSize: 11,
    fontWeight: 700,
    background: bg,
    color
  });

  function applySearch() {
    setPage(1);
    setSearch(String(searchInput || '').trim());
  }

  const typeCounts = {
    ip: summary.by_type?.find((x) => x.observable_type === 'ip')?.count || 0,
    url: summary.by_type?.find((x) => x.observable_type === 'url')?.count || 0,
    domain: summary.by_type?.find((x) => x.observable_type === 'domain')?.count || 0,
    ip6: summary.by_type?.find((x) => x.observable_type === 'ip6')?.count || 0,
    hash: summary.by_type?.find((x) => x.observable_type === 'hash')?.count || 0
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
        <h2 style={{ marginTop: 0 }}>Hot IOC List</h2>
        <div style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
          Indicators with at least one environment match (hits &gt; 0), from PostgreSQL snapshot. Sorted by last seen in logs.
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(120px, 1fr))', gap: 10, marginBottom: 16 }}>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Records</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{summary.total}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>IP</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.ip}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>URL</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.url}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Hash (MD5/SHA*)</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.hash}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>Domain</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.domain}</div>
          </div>
          <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
            <div style={{ fontSize: 12, color: '#94a3b8' }}>IPv6</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.ip6}</div>
          </div>
        </div>

        <div style={{ marginBottom: 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 8, background: '#0f172a' }}>
          <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8 }}>Top 5 sources</div>
          <div style={{ marginTop: 6, fontSize: 14, display: 'grid', gap: 6 }}>
            {summary.by_source?.length ? summary.by_source.map((s, idx) => (
              <div key={s.source_name || idx} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, borderBottom: '1px dashed #334155', paddingBottom: 4 }}>
                <span style={{ color: '#cbd5e1' }}>{idx + 1}. {s.source_name}</span>
                <b style={{ color: '#e2e8f0' }}>{s.count}</b>
              </div>
            )) : <span style={{ color: '#94a3b8' }}>No data</span>}
          </div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginBottom: 14, alignItems: 'center' }}>
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') applySearch(); }}
            placeholder="Search by IOC value or public ID"
            style={{ minWidth: 320 }}
          />
          <button onClick={applySearch}>Search</button>
          <button
            onClick={() => {
              setSearchInput('');
              setSearch('');
              setPage(1);
            }}
          >
            Clear
          </button>

          <label style={{ fontSize: 14, color: '#cbd5e1' }}>
            Type{' '}
            <select
              value={typeFilter}
              onChange={(e) => {
                setPage(1);
                setTypeFilter(e.target.value);
              }}
              style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', fontWeight: 600, background: '#111827', color: '#e2e8f0', marginLeft: 6 }}
            >
              <option value="">All</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
            </select>
          </label>
          <label style={{ fontSize: 14, color: '#cbd5e1' }}>
            Last seen in logs{' '}
            <select
              value={sinceFilter}
              onChange={(e) => {
                setPage(1);
                setSinceFilter(e.target.value);
              }}
              style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', fontWeight: 600, background: '#111827', color: '#e2e8f0', marginLeft: 6 }}
            >
              <option value="">Any time</option>
              <option value="1h">Last hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
          </label>
          <label style={{ fontSize: 14, color: '#cbd5e1' }}>
            Page size{' '}
            <select
              value={pageSize}
              onChange={(e) => {
                setPage(1);
                setPageSize(Number(e.target.value));
              }}
              style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', fontWeight: 600, background: '#111827', color: '#e2e8f0', marginLeft: 6 }}
            >
              {[25, 50, 100, 200].map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </label>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 10, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: '#e2e8f0' }}>
            Hot IOCs <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: 0.2 }}>{pagination.total}</span>
            <span style={{ margin: '0 8px', color: '#94a3b8' }}>|</span>
            Page <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.page}</span> / <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.total_pages}</span>
          </div>
        </div>

        {(loading || banner) && (
          <div style={{ marginBottom: 10, padding: 10, background: loading ? '#e0f2fe' : '#fee2e2', border: `1px solid ${loading ? '#7dd3fc' : '#fecaca'}`, borderRadius: 6, color: '#0f172a' }}>
            {loading ? 'Loading hot IOCs...' : banner}
          </div>
        )}

        {!loading && !banner && items.length === 0 && (
          <div style={{ marginBottom: 10, padding: 10, background: '#fff8e1', border: '1px solid #ffe0a3', borderRadius: 6, color: '#0f172a' }}>
            No hot IOCs yet — nothing in your environment has matched a listed indicator.
          </div>
        )}

        <div style={{ overflowX: 'auto', border: '1px solid #e5e7eb', borderRadius: 10 }}>
          <table
            className="ioc-table"
            width="100%"
            cellPadding="10"
            style={{
              borderCollapse: 'collapse',
              minWidth: 720,
              background: '#fff',
              tableLayout: 'fixed',
              fontSize: 13,
              fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace"
            }}
          >
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
                <th>IOC</th>
                <th style={{ width: 110 }}>Type</th>
                <th style={{ width: 110 }}>Evidence Logs</th>
                <th style={{ width: 96 }}>Sources</th>
                <th style={{ width: 200 }}>First Seen</th>
                <th style={{ width: 200 }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr
                  key={`${r.observable_type || ''}:${r.observable || ''}:${r.public_id || r.id}`}
                  style={{ borderBottom: '1px solid #f1f5f9', cursor: r.public_id ? 'pointer' : 'default' }}
                  onClick={() => {
                    if (r.public_id) navigate(`/ioc/details/${encodeURIComponent(r.public_id)}`);
                  }}
                >
                  <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                    <span style={{ color: '#93c5fd', textDecoration: 'underline', fontWeight: 600 }}>{r.observable || '-'}</span>
                    <span style={{ display: 'block' }}>
                      {isNewlyActiveHotIoc(r.first_seen_log) ? (
                        <span style={hotBadge('#312e81', '#c7d2fe')}>Newly active</span>
                      ) : null}
                      {Number(r.evidence_logs ?? 0) > 100 ? (
                        <span style={hotBadge('#78350f', '#fcd34d')}>High activity</span>
                      ) : null}
                    </span>
                  </td>
                  <td style={{ textTransform: 'lowercase' }}>{r.observable_type || '-'}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{Number.isFinite(Number(r.evidence_logs)) ? Number(r.evidence_logs) : '-'}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{Number(r.source_count ?? 0)}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>{formatUserDateTime(r.first_seen_log)}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>{formatUserDateTime(r.last_seen_log)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
          <button style={{ minWidth: 92, fontWeight: 600 }} disabled={pagination.page <= 1} onClick={() => setPage((p) => Math.max(p - 1, 1))}>
            Previous
          </button>
          <button
            style={{ minWidth: 92, fontWeight: 600 }}
            disabled={pagination.page >= pagination.total_pages}
            onClick={() => setPage((p) => Math.min(p + 1, pagination.total_pages))}
          >
            Next
          </button>
        </div>
      </section>
    </AppShell>
  );
}

function IOCListPage() {
  const navigate = useNavigate();
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState({ total: 0, unique_ips: 0, by_source: [], by_confidence: [] });
  const [pageSize, setPageSize] = useState(5);
  const [page, setPage] = useState(1);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [columnWidths, setColumnWidths] = useState({
    index: 52,
    ip: 360,
    asn: 84,
    country: 90,
    source: 260,
    confidence: 120,
    category: 120,
    timestamp: 170
  });
  const [sortState, setSortState] = useState({ key: null, dir: null });
  const [resizeState, setResizeState] = useState(null);
  const [pagination, setPagination] = useState({ page: 1, page_size: 5, total: 0, total_pages: 1 });
  const [detailObservable, setDetailObservable] = useState('');
  const [detailType, setDetailType] = useState('');
  const [detailSources, setDetailSources] = useState([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [listLoading, setListLoading] = useState(false);
  const [listStatusText, setListStatusText] = useState('');
  const [searchError, setSearchError] = useState('');
  const [summaryLoading, setSummaryLoading] = useState(false);

  const loadSummary = useCallback(async () => {
    setSummaryLoading(true);
    try {
      const { data } = await api.get('/ioc/stats');
      setSummary(data || { total: 0, by_source: [], by_type: [] });
    } catch {
      setSummary({ total: 0, by_source: [], by_type: [] });
    } finally {
      setSummaryLoading(false);
    }
  }, []);

  const loadData = useCallback(async (targetPage, targetSize) => {
    setListLoading(true);
    setListStatusText('Query is running. Please wait while IOC results are being processed...');
    try {
      const listRes = await api.get('/ioc/list', {
        params: {
          page: targetPage,
          page_size: targetSize,
          q: search || undefined,
        }
      });
      const items = listRes.data.items || [];
      setRows(items);
      setPagination(listRes.data.pagination || { page: 1, page_size: 5, total: 0, total_pages: 1 });
      setListStatusText('');
    } catch {
      setRows([]);
      setListStatusText('Query failed. Please try again.');
    } finally {
      setListLoading(false);
    }
  }, [search]);

  useEffect(() => {
    loadSummary().catch(() => {});
  }, [loadSummary]);

  useEffect(() => {
    loadData(page, pageSize);
  }, [page, pageSize, loadData]);

  // Search is triggered only by Enter or Search button.

  useEffect(() => {
    if (!resizeState) return undefined;

    function onMove(e) {
      const delta = e.clientX - resizeState.startX;
      const next = Math.max(60, resizeState.startWidth + delta);
      setColumnWidths((prev) => ({ ...prev, [resizeState.key]: next }));
    }

    function onUp() {
      setResizeState(null);
    }

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);

    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [resizeState]);

  function startResize(key, e) {
    e.preventDefault();
    e.stopPropagation();
    setResizeState({ key, startX: e.clientX, startWidth: columnWidths[key] || 120 });
  }

  function nextSort(key) {
    setSortState((prev) => {
      if (prev.key !== key) return { key, dir: 'asc' };
      if (prev.dir === 'asc') return { key, dir: 'desc' };
      if (prev.dir === 'desc') return { key: null, dir: null };
      return { key, dir: 'asc' };
    });
  }

  function sortIndicator(key) {
    if (sortState.key !== key || !sortState.dir) return '';
    return sortState.dir === 'asc' ? ' ▲' : ' ▼';
  }

  const sortedRows = useMemo(() => {
    if (!sortState.key || !sortState.dir) return rows;

    const val = (r) => {
      if (sortState.key === 'ip') return String(r.ip || '');
      if (sortState.key === 'source') return String((r.source_names && r.source_names[0]) || '');
      if (sortState.key === 'confidence') return String((r.confidence_set && r.confidence_set[0]) || '');
      if (sortState.key === 'category') return String(r.observable_type || 'ip');
      if (sortState.key === 'timestamp') return new Date(r.last_seen_at || 0).getTime();
      return '';
    };

    const copy = [...rows];
    copy.sort((a, b) => {
      const av = val(a);
      const bv = val(b);
      const cmp = typeof av === 'number' && typeof bv === 'number'
        ? av - bv
        : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: 'base' });
      return sortState.dir === 'asc' ? cmp : -cmp;
    });
    return copy;
  }, [rows, sortState]);

  async function openSourceDetails(row) {
    const obs = row.observable || row.ip;
    const obsType = row.observable_type || 'ip';
    setDetailObservable(obs);
    setDetailType(obsType);
    setDetailSources([]);
    setDetailLoading(true);
    try {
      const res = await api.get('/ioc/observable/sources', { params: { observable: obs, type: obsType } });
      setDetailSources(res.data?.sources || []);
    } catch {
      setDetailSources([]);
    } finally {
      setDetailLoading(false);
    }
  }

  const typeCounts = {
    ip: summary.by_type?.find((x) => x.observable_type === 'ip')?.count || 0,
    url: summary.by_type?.find((x) => x.observable_type === 'url')?.count || 0,
    domain: summary.by_type?.find((x) => x.observable_type === 'domain')?.count || 0,
    ip6: summary.by_type?.find((x) => x.observable_type === 'ip6')?.count || 0,
    hash: summary.by_type?.reduce((acc, x) => acc + (FILE_HASH_TYPES.has(x.observable_type) ? Number(x.count || 0) : 0), 0) || 0
  };

  const confidenceBadgeStyle = (confidence) => ({
    display: 'inline-block',
    borderRadius: 999,
    padding: '4px 10px',
    fontSize: 12,
    fontWeight: 700,
    textTransform: 'capitalize',
    background: confidence === 'high' ? '#fee2e2' : confidence === 'medium' ? '#fef3c7' : '#dcfce7',
    color: confidence === 'high' ? '#991b1b' : confidence === 'medium' ? '#92400e' : '#166534'
  });

  function normalizeSearchQuery(rawInput) {
    const trimmed = String(rawInput || '').trim();
    if (!trimmed) return { ok: true, value: '' };

    const match = trimmed.match(/^(ip|sha1|sha256|md5|domain|ipv6|url)\s*:\s*(.+)$/i);
    if (!match) {
      return {
        ok: false,
        message: 'Syntax error. Use one of: ip:, sha1:, sha256:, md5:, domain:, ipv6:, url:'
      };
    }

    const prefix = match[1].toLowerCase();
    const value = String(match[2] || '').trim();
    if (!value) {
      return {
        ok: false,
        message: 'Syntax error. Query value cannot be empty.'
      };
    }

    const backendPrefix = prefix === 'ipv6' ? 'ip6' : prefix;
    return { ok: true, value: `${backendPrefix}:${value}` };
  }

  function applySearch() {
    const parsed = normalizeSearchQuery(searchInput);
    if (!parsed.ok) {
      setSearchError(parsed.message || 'Syntax error.');
      return;
    }

    setSearchError('');
    setPage(1);
    setSearch(parsed.value);
  }

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
      <h2 style={{ marginTop: 0 }}>IOC List</h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(120px, 1fr))', gap: 10, marginBottom: 16 }}>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Records</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{summary.total}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>IP</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.ip}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>URL</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.url}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>Hash (MD5/SHA*)</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.hash}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>Domain</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.domain}</div>
        </div>
        <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>IPv6</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0' }}>{typeCounts.ip6}</div>
        </div>
      </div>

      <div style={{ marginBottom: 14, padding: '10px 12px', border: '1px solid #334155', borderRadius: 8, background: '#0f172a' }}>
        <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8 }}>
          {summaryLoading ? 'Loading stats…' : 'Top 5 sources'}
        </div>
        <div style={{ marginTop: 6, fontSize: 14, display: 'grid', gap: 6 }}>
          {summary.by_source.length ? summary.by_source.slice(0, 5).map((s, idx) => (
            <div key={s.source_name} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, borderBottom: '1px dashed #334155', paddingBottom: 4 }}>
              <span style={{ color: '#cbd5e1' }}>{idx + 1}. {s.source_name}</span>
              <b style={{ color: '#e2e8f0' }}>{s.count}</b>
            </div>
          )) : <span style={{ color: '#94a3b8' }}>No data</span>}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: 8, marginBottom: 10, alignItems: 'center' }}>
        <input
          placeholder="Search (ip:, sha1:, sha256:, md5:, domain:, ipv6:, url:)"
          value={searchInput}
          onChange={(e) => {
            setSearchInput(e.target.value);
            if (searchError) setSearchError('');
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              applySearch();
            }
          }}
        />
        <button onClick={applySearch}>
          Search
        </button>
        <button
          onClick={() => {
            setSearchInput('');
            setSearchError('');
            setSearch('');
            setPage(1);
          }}
        >
          Clear
        </button>
      </div>

      {searchError && (
        <div style={{ marginBottom: 10, padding: 10, background: '#fee2e2', border: '1px solid #fecaca', borderRadius: 6, color: '#991b1b', fontWeight: 600 }}>
          {searchError}
        </div>
      )}

      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 10, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <label style={{ fontSize: 14, color: '#cbd5e1' }}>Page size:</label>
          <select
            value={pageSize}
            onChange={(e) => {
              const nextSize = Number(e.target.value);
              setPageSize(nextSize);
              setPage(1);
            }}
            style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #334155', fontWeight: 600, background: '#111827', color: '#e2e8f0' }}
          >
            {[5, 10, 25, 100].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>

        </div>
        <div style={{ fontSize: 15, fontWeight: 600, color: '#e2e8f0' }}>
          Listed Items <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: 0.2 }}>{pagination.total}</span>
          <span style={{ margin: '0 8px', color: '#94a3b8' }}>|</span>
          Page <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.page}</span> / <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.total_pages}</span>
        </div>
      </div>

      {(listLoading || listStatusText) && (
        <div style={{ marginBottom: 10, padding: 10, background: listLoading ? '#e0f2fe' : '#fff8e1', border: `1px solid ${listLoading ? '#7dd3fc' : '#ffe0a3'}`, borderRadius: 6, color: '#0f172a' }}>
          {listLoading ? 'Query is running. Please wait while IOC results are being processed...' : listStatusText}
        </div>
      )}

      {!listLoading && !listStatusText && rows.length === 0 && (
        <div style={{ marginBottom: 10, padding: 10, background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#94a3b8' }}>
          No IOC records found.
        </div>
      )}

      <div style={{ overflowX: 'auto', border: '1px solid #e5e7eb', borderRadius: 10 }}>
        <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 980, background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
          <colgroup>
            <col style={{ width: columnWidths.index }} />
            <col style={{ width: columnWidths.ip }} />
            <col style={{ width: columnWidths.category }} />
            <col style={{ width: columnWidths.source }} />
            <col style={{ width: columnWidths.confidence }} />
            <col style={{ width: columnWidths.timestamp }} />
          </colgroup>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
              <th style={{ position: 'relative' }}>
                #
                <div onMouseDown={(e) => startResize('index', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} />
              </th>
              <th onClick={() => nextSort('ip')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>IOC{sortIndicator('ip')}<div onMouseDown={(e) => startResize('ip', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('category')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>IOC Type{sortIndicator('category')}<div onMouseDown={(e) => startResize('category', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('source')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Source{sortIndicator('source')}<div onMouseDown={(e) => startResize('source', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('confidence')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Confidence{sortIndicator('confidence')}<div onMouseDown={(e) => startResize('confidence', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('timestamp')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Timestamp{sortIndicator('timestamp')}<div onMouseDown={(e) => startResize('timestamp', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
            </tr>
          </thead>
          <tbody>
            {sortedRows.map((r, idx) => (
              <tr key={`${r.observable_type || 'ip'}:${r.observable || r.ip}`} style={{ borderBottom: '1px solid #f1f5f9' }}>
                <td style={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{(pagination.page - 1) * pagination.page_size + idx + 1}</td>
                <td title={r.observable || r.ip} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                  <button
                    onClick={() => r.public_id && navigate(`/ioc/details/${encodeURIComponent(r.public_id)}`)}
                    style={{ background: 'transparent', border: 'none', color: '#93c5fd', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit', textAlign: 'left' }}
                  >
                    {r.observable || r.ip}
                  </button>
                </td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.observable_type || 'ip'}</td>
                <td title={(r.source_names && r.source_names[0]) || '-'} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                  {r.source_count > 1 ? (
                    <button onClick={() => openSourceDetails(r)} style={{ background: 'transparent', border: 'none', color: '#0f172a', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit', textAlign: 'left' }}>
                      {(r.source_names && r.source_names[0]) || '-'}{r.source_count > 1 ? ` +${r.source_count - 1}` : ''}
                    </button>
                  ) : (
                    <span>{(r.source_names && r.source_names[0]) || '-'}</span>
                  )}
                </td>
                <td><span style={confidenceBadgeStyle((r.confidence_set && r.confidence_set[0]) || 'low')}>{(r.confidence_set && r.confidence_set[0]) || 'low'}</span></td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontVariantNumeric: 'tabular-nums' }}>{formatUserDateTime(r.last_seen_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
        <button style={{ minWidth: 92, fontWeight: 600 }} disabled={pagination.page <= 1} onClick={() => setPage((p) => Math.max(p - 1, 1))}>Previous</button>
        <button
          style={{ minWidth: 92, fontWeight: 600 }}
          disabled={pagination.page >= pagination.total_pages}
          onClick={() => setPage((p) => Math.min(p + 1, pagination.total_pages))}
        >
          Next
        </button>
      </div>

      {detailObservable && (
        <div style={{ marginTop: 14, border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <b>Sources for {detailObservable}</b>
            <button onClick={() => { setDetailObservable(''); setDetailType(''); setDetailSources([]); }}>Close</button>
          </div>
          {detailLoading ? <div>Loading...</div> : (
            <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 13, background: '#0f172a', color: '#e2e8f0' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', background: '#111827' }}>
                  <th>Source</th><th>URL</th><th>Confidence</th><th>Category</th><th>Reported At</th>
                </tr>
              </thead>
              <tbody>
                {detailSources.map((s) => (
                  <tr key={s.id} style={{ borderBottom: '1px solid #334155' }}>
                    <td>{s.source_name}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 260 }}>{s.source_url || '-'}</td>
                    <td>{s.confidence || '-'}</td>
                    <td>{s.category || '-'}</td>
                    <td>{formatUserDateTime(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
      </section>
    </AppShell>
  );
}

function LegacyIOCDetailsRedirect() {
  const { type, observable } = useParams();
  const navigate = useNavigate();

  useEffect(() => {
    let active = true;
    async function resolveAndRedirect() {
      try {
        const decodedType = decodeURIComponent(type || 'ip');
        const decodedObservable = decodeURIComponent(observable || '');
        if (!decodedObservable) {
          navigate('/ioc', { replace: true });
          return;
        }
        const res = await api.get('/ioc/details/resolve', { params: { type: decodedType, observable: decodedObservable } });
        const resolvedPublicId = String(res.data?.public_id || '').trim();
        if (active && resolvedPublicId) {
          navigate(`/ioc/details/${resolvedPublicId}`, { replace: true });
        } else if (active) {
          navigate('/ioc', { replace: true });
        }
      } catch {
        if (active) navigate('/ioc', { replace: true });
      }
    }
    resolveAndRedirect().catch(() => {});
    return () => { active = false; };
  }, [type, observable, navigate]);

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
        <div>Redirecting to IOC details...</div>
      </section>
    </AppShell>
  );
}

function VirusTotalEnrichmentCard({ iocId }) {
  const [state, setState] = useState({ status: 'loading', summary: null, message: '', fetchedAt: null, expiresAt: null });
  const [open, setOpen] = useState(true);
  const [showAll, setShowAll] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    if (!iocId) return;
    setState((s) => ({ ...s, status: 'loading' }));
    try {
      const { data } = await api.get(`/ioc/${iocId}/enrichments/virustotal`);
      if (data?.status === 'api_key_missing') return setState({ status: 'api_key_missing', summary: null, message: 'VirusTotal API key is not configured.', fetchedAt: null, expiresAt: null });
      if (data?.status === 'not_found') return setState({ status: 'not_found', summary: null, message: 'No VirusTotal enrichment yet.', fetchedAt: null, expiresAt: null });
      return setState({ status: 'success', summary: data?.summary || null, message: '', fetchedAt: data?.fetched_at || null, expiresAt: data?.expires_at || null });
    } catch {
      setState({ status: 'error', summary: null, message: 'VirusTotal enrichment failed', fetchedAt: null, expiresAt: null });
    }
  }, [iocId]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  async function refresh() {
    setRefreshing(true);
    try {
      const { data } = await api.post(`/ioc/${iocId}/enrichments/virustotal/refresh`);
      setOpen(true);
      setState({ status: 'success', summary: data?.summary || null, message: '', fetchedAt: data?.fetched_at || null, expiresAt: data?.expires_at || null });
    } catch (err) {
      const msg = err?.response?.status === 429 ? 'VirusTotal rate limit reached. Try again later.' : (err?.response?.data?.message || 'VirusTotal enrichment failed');
      setState({ status: 'error', summary: null, message: msg, fetchedAt: null, expiresAt: null });
    } finally { setRefreshing(false); }
  }

  const s = state.summary || {};
  const stats = s.stats || {};
  const detected = Number(s?.detection_ratio?.detected || 0);
  const total = Number(s?.detection_ratio?.total || 0);
  const severityDetected = detected > 0;
  const vendorResults = Array.isArray(s.vendor_results) ? s.vendor_results : [];
  const topDetections = (vendorResults.length ? vendorResults.filter((v) => v.category === 'malicious' || v.category === 'suspicious').slice(0, 5) : (Array.isArray(s.top_engines) ? s.top_engines : []));

  const chip = (label, value, c) => <span key={label} style={{ padding:'6px 10px', borderRadius:999, border:`1px solid ${c.b}`, background:c.bg, color:c.t, fontSize:12 }}>{label}: <b>{value}</b></span>;

  return <div style={{ marginBottom: 14, padding: 14, border: '1px solid #334155', borderRadius: 12, background: '#0f172a' }}>
    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:10 }}>
      <div>
        <div style={{ fontWeight:700, color:'#e2e8f0' }}>VirusTotal Intelligence <span style={{ marginLeft:8, border:'1px solid #1d4ed8', color:'#93c5fd', borderRadius:999, padding:'2px 8px', fontSize:11 }}>VirusTotal</span></div>
        <div style={{ color:'#94a3b8', fontSize:12, marginTop:4 }}>External reputation and analysis summary</div>
      </div>
      <button onClick={() => setOpen((v) => !v)} style={{ padding:'6px 10px' }}>{open ? 'Collapse' : 'Expand'}</button>
    </div>

    {state.status === 'loading' ? <div style={{ color:'#94a3b8', marginTop:10 }}>Loading...</div> : null}
    {state.status === 'api_key_missing' ? <div style={{ marginTop:10, color:'#fbbf24' }}>VirusTotal API key is not configured.<div><Link to="/administration/enrichment-providers" style={{ color:'#93c5fd' }}>Configure in Administration</Link></div></div> : null}
    {state.status === 'not_found' ? <div style={{ marginTop:10, color:'#94a3b8' }}>No VirusTotal enrichment yet.<div style={{ marginTop:4 }}>Run enrichment to fetch external reputation data for this IOC.</div><button onClick={() => refresh().catch(()=>{})} style={{marginTop:8}} disabled={refreshing}>{refreshing ? 'Refreshing...' : 'Enrich with VirusTotal'}</button></div> : null}
    {state.status === 'error' ? <div style={{ marginTop:10, color:'#fca5a5' }}>{state.message}<div><button onClick={() => refresh().catch(()=>{})} style={{marginTop:8}} disabled={refreshing}>{refreshing ? 'Refreshing...' : 'Retry'}</button></div></div> : null}

    {state.status === 'success' && open ? <>
      <div style={{ display:'grid', gridTemplateColumns:'1.2fr 1fr', gap:12, marginTop:12 }}>
        <div style={{ border:'1px solid #334155', borderRadius:10, padding:12, background:'#0b1220' }}>
          <div style={{ fontSize:30, fontWeight:800 }}>{detected} / {total}</div>
          <div style={{ color:'#94a3b8', fontSize:12 }}>engines flagged this IOC</div>
          <div style={{ marginTop:8, display:'inline-block', border:'1px solid #475569', borderRadius:999, padding:'3px 10px', fontSize:12, color: severityDetected ? '#fca5a5' : '#86efac' }}>{severityDetected ? 'Detected' : 'No detections'}</div>
        </div>
        <div style={{ border:'1px solid #334155', borderRadius:10, padding:12, background:'#0b1220' }}>
          <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
            {chip('Malicious', stats.malicious ?? 0, { bg:'rgba(220,38,38,.14)', b:'#7f1d1d', t:'#fca5a5' })}
            {chip('Suspicious', stats.suspicious ?? 0, { bg:'rgba(217,119,6,.14)', b:'#92400e', t:'#fcd34d' })}
            {chip('Harmless', stats.harmless ?? 0, { bg:'rgba(22,163,74,.14)', b:'#166534', t:'#86efac' })}
            {chip('Undetected', stats.undetected ?? 0, { bg:'rgba(71,85,105,.18)', b:'#475569', t:'#cbd5e1' })}
          </div>
          <div style={{ marginTop:10, fontSize:12, color:'#94a3b8' }}>Last analysis: {formatUserDateTime(s.last_analysis_date)} • Fetched: {formatUserDateTime(state.fetchedAt)}</div>
        </div>
      </div>

      <div style={{ marginTop:12, border:'1px solid #334155', borderRadius:10, overflow:'hidden' }}>
        <div style={{ padding:10, background:'#111827', borderBottom:'1px solid #334155', fontWeight:700 }}>Top detections</div>
        {topDetections.length ? <table width='100%' cellPadding='8' style={{ borderCollapse:'collapse', fontSize:13 }}><thead><tr style={{ textAlign:'left', background:'#0b1220' }}><th>Engine</th><th>Category</th><th>Result</th></tr></thead><tbody>{topDetections.map((r, i)=><tr key={`${r.engine}-${i}`} style={{ borderTop:'1px solid #334155' }}><td>{r.engine}</td><td>{r.category || '-'}</td><td style={{ whiteSpace:'normal', overflowWrap:'anywhere' }}>{r.result || '-'}</td></tr>)}</tbody></table> : <div style={{ padding:10, color:'#94a3b8' }}>Top detections are not available for this IOC.</div>}
      </div>

      {vendorResults.length > 5 ? <div style={{ marginTop:8 }}><button onClick={() => setShowAll((v) => !v)}>{showAll ? 'Hide vendor results' : 'Show all vendor results'}</button></div> : null}
      {showAll ? <div style={{ marginTop:8, border:'1px solid #334155', borderRadius:10, maxHeight:260, overflow:'auto' }}><div style={{ padding:10, background:'#111827', borderBottom:'1px solid #334155', fontWeight:700 }}>Security vendors' analysis</div><table width='100%' cellPadding='8' style={{ borderCollapse:'collapse', fontSize:12 }}><thead><tr style={{ textAlign:'left', background:'#0b1220' }}><th>Vendor</th><th>Category</th><th>Result</th><th>Method</th></tr></thead><tbody>{vendorResults.map((r, i)=><tr key={`${r.engine}-${i}`} style={{ borderTop:'1px solid #334155' }}><td>{r.engine}</td><td>{r.category || '-'}</td><td style={{ maxWidth:360, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>{r.result || '-'}</td><td>{r.method || '-'}</td></tr>)}</tbody></table></div> : null}

      <div style={{ display:'flex', justifyContent:'flex-end', gap:8, marginTop:10 }}>
        <button onClick={() => refresh().catch(()=>{})} disabled={refreshing}>{refreshing ? 'Refreshing...' : 'Refresh'}</button>
        {s.permalink ? <a href={s.permalink} target='_blank' rel='noopener noreferrer' style={{ padding:'7px 10px', border:'1px solid #334155', borderRadius:8, textDecoration:'none', color:'#93c5fd' }}>Open in VirusTotal</a> : null}
      </div>
    </> : null}
  </div>;
}

function IOCDetailsPage() {
  const { publicId } = useParams();
  const navigate = useNavigate();
  const detailsPublicId = String(publicId || '').trim();

  const [loading, setLoading] = useState(true);
  const [data, setData] = useState({ summary: null, sources: [], matches: [] });
  const [iocTags, setIocTags] = useState([]);
  const [allTags, setAllTags] = useState([]);
  const [tagSearch, setTagSearch] = useState('');
  const [tagsLoading, setTagsLoading] = useState(false);
  const [tagsSaving, setTagsSaving] = useState(false);
  const [tagDropdownOpen, setTagDropdownOpen] = useState(false);
  const tagDropdownRef = useRef(null);

  async function load() {
    setLoading(true);
    if (!detailsPublicId) {
      setData({ summary: null, sources: [], matches: [] });
      setLoading(false);
      return;
    }
    try {
      const res = await api.get('/ioc/details', { params: { public_id: detailsPublicId } });
      setData(res.data || { summary: null, sources: [], matches: [] });
    } catch {
      setData({ summary: null, sources: [], matches: [] });
    } finally {
      setLoading(false);
    }
  }

  async function loadIocTags(iocId) {
    if (!iocId) {
      setIocTags([]);
      return;
    }

    try {
      const res = await api.get(`/ioc/${iocId}/tags`);
      setIocTags(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.log('[ioc-tags] load failed', err);
      setIocTags([]);
    }
  }

  async function loadEnabledTags() {
    setTagsLoading(true);
    try {
      const res = await api.get('/tags');
      console.log('[ioc-tags] /tags response', res.data);
      setAllTags(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.log('[ioc-tags] list failed', err);
      setAllTags([]);
    } finally {
      setTagsLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    (async () => {
      await load().catch(() => {});
      if (!active) return;
    })();
    return () => { active = false; };
  }, [detailsPublicId]);

  useEffect(() => {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      setIocTags([]);
      return;
    }
    loadIocTags(iocId).catch(() => {});
  }, [data?.summary?.id]);

  useEffect(() => {
    if (!tagDropdownOpen) return;
    loadEnabledTags().catch(() => {});
  }, [tagDropdownOpen]);

  useEffect(() => {
    if (!tagDropdownOpen) return;
    console.log('[ioc-tags] dropdown data', allTags);
  }, [tagDropdownOpen, allTags]);

  useEffect(() => {
    if (!tagDropdownOpen) return;
    const onDocMouseDown = (evt) => {
      if (!tagDropdownRef.current) return;
      if (!tagDropdownRef.current.contains(evt.target)) {
        setTagDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', onDocMouseDown);
    return () => document.removeEventListener('mousedown', onDocMouseDown);
  }, [tagDropdownOpen]);

  async function addIocTag(tagId) {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) return;
    if (!Number.isFinite(Number(tagId)) || Number(tagId) <= 0) return;
    if (iocTags.some((t) => Number(t.id) === Number(tagId))) return;

    setTagsSaving(true);
    try {
      await api.post(`/ioc/${iocId}/tags`, { tag_id: Number(tagId) });
      const selected = allTags.find((t) => Number(t.id) === Number(tagId));
      if (selected) {
        setIocTags((prev) => prev.some((t) => Number(t.id) === Number(tagId)) ? prev : [...prev, {
          id: selected.id,
          name: selected.name,
          type: selected.type
        }]);
      }
    } catch (err) {
      console.log('[ioc-tags] add failed', err);
    } finally {
      setTagsSaving(false);
    }
  }

  async function removeIocTag(tagId) {
    const iocId = Number(data?.summary?.id);
    if (!Number.isFinite(iocId) || iocId <= 0) return;

    setTagsSaving(true);
    try {
      await api.delete(`/ioc/${iocId}/tags/${Number(tagId)}`);
      setIocTags((prev) => prev.filter((t) => Number(t.id) !== Number(tagId)));
    } catch (err) {
      console.log('[ioc-tags] delete failed', err);
    } finally {
      setTagsSaving(false);
    }
  }

  const summary = data.summary;
  const displayObservable = summary?.observable || '-';
  const observableType = String(summary?.observable_type || '').toLowerCase();
  const isHashObservable = FILE_HASH_TYPES.has(observableType);
  const networkInfoTitle = observableType === 'domain'
    ? 'Domain Information'
    : (observableType === 'url' ? 'URL Information' : 'IP Information');
  const resolvedFromLabel = observableType === 'url'
    ? 'url-host'
    : ((observableType === 'ip' || observableType === 'ip6') ? 'direct-ip' : (observableType === 'domain' ? 'domain' : '-'));
  const fileInfo = summary?.file_information || null;
  const hasMeaningfulFileInfo = Boolean(fileInfo && Object.values(fileInfo).some((v) => {
    if (v == null) return false;
    const t = String(v).trim();
    return t && t !== "-";
  }));

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <div>
            <h2 style={{ margin: 0 }}>IOC Details</h2>
            <div style={{ marginTop: 6, color: '#94a3b8', fontSize: 13 }}>Analyst-focused detail page for faster triage</div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => navigate('/ioc')}>Back to IOC List</button>
            <button onClick={() => load().catch(() => {})}>Refresh</button>
          </div>
        </div>

        <div style={{ marginBottom: 14, padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
          <div style={{ fontSize: 12, color: '#94a3b8' }}>IOC</div>
          <div style={{ fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace", fontSize: 15, overflowWrap: 'anywhere' }}><b>{displayObservable}</b></div>
        </div>

        {loading ? <div>Loading...</div> : !summary ? (
          <div style={{ padding: 12, border: '1px solid #334155', borderRadius: 10 }}>No IOC detail found.</div>
        ) : (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(120px, 1fr))', gap: 10, marginBottom: 14 }}>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>Type</div><div style={{ fontSize: 18, fontWeight: 700 }}>{summary.observable_type || '-'}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>Source Count</div><div style={{ fontSize: 18, fontWeight: 700 }}>{summary.source_count || 0}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>First Seen</div><div style={{ fontSize: 13, fontWeight: 700 }}>{formatUserDateTime(summary.first_seen_at)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>Last Seen</div><div style={{ fontSize: 13, fontWeight: 700 }}>{formatUserDateTime(summary.last_seen_at)}</div></div>
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>Evidence Logs</div><div style={{ fontSize: 18, fontWeight: 700 }}>{Number(data.summary?.evidence_logs_count || 0)}</div></div>
            </div>

            <VirusTotalEnrichmentCard iocId={summary.id} iocValue={summary.observable} iocType={summary.observable_type} />

            {!isHashObservable ? (
              <div style={{ marginBottom: 14, border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
                <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>{networkInfoTitle}</div>
                <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 900, fontSize: 13 }}>
                  <thead>
                    <tr style={{ textAlign: 'left', background: '#111827' }}>
                      <th>Parsed IP</th><th>Country</th><th>ASN</th><th>ASN Owner</th><th>Resolved From</th><th>First Seen</th><th>Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr style={{ borderTop: '1px solid #334155' }}>
                      <td>{summary.geo?.ip || '-'}</td>
                      <td>{summary.geo?.country_code || '-'}</td>
                      <td>{summary.geo?.asn ?? '-'}</td>
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.geo?.as_name || '-'}</td>
                      <td>{resolvedFromLabel}</td>
                      <td>{formatUserDateTime(summary.first_seen_at)}</td>
                      <td>{formatUserDateTime(summary.last_seen_at)}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            ) : null}

            {isHashObservable && hasMeaningfulFileInfo ? (
              <div style={{ marginBottom: 14, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
                <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>File Information</div>
                <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', fontSize: 13 }}>
                  <tbody>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>File Name</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.file_name || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>File Type</th><td>{summary.file_information.file_type || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>MIME</th><td>{summary.file_information.mime || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>MD5</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.md5 || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SHA1</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.sha1 || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SHA256</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.sha256 || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>IMPHASH</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.imphash || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>TLSH</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.tlsh || '-'}</td></tr>
                    <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SSDEEP</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{summary.file_information.ssdeep || '-'}</td></tr>
                  </tbody>
                </table>
              </div>
            ) : null}

            <div style={{ marginBottom: 14, padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
              <div style={{ fontSize: 13, marginBottom: 6, color: '#94a3b8' }}>Confidence Set</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {(summary.confidence_set || []).length ? summary.confidence_set.map((c) => <span key={c} style={{ padding: '4px 8px', borderRadius: 999, border: '1px solid #475569' }}>{c}</span>) : <span>-</span>}
              </div>
            </div>

            <div style={{ marginBottom: 14, padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
              <div style={{ fontSize: 13, marginBottom: 8, color: '#94a3b8' }}>Tags</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                {iocTags.length ? iocTags.map((tag) => (
                  <span key={`tag-${tag.id}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 8px', borderRadius: 999, border: '1px solid #475569', fontSize: 12 }}>
                    {tag.name}
                    <button
                      type="button"
                      onClick={() => removeIocTag(tag.id).catch(() => {})}
                      title="Remove tag"
                      aria-label={`Remove ${tag.name}`}
                      style={{ padding: 0, border: 'none', background: 'transparent', color: '#94a3b8', cursor: tagsSaving ? 'wait' : 'pointer', lineHeight: 1 }}
                      disabled={tagsSaving}
                    >
                      ×
                    </button>
                  </span>
                )) : <span style={{ color: '#94a3b8', fontSize: 12 }}>No tags</span>}

                <div style={{ position: 'relative' }} ref={tagDropdownRef}>
                  <button type="button" onClick={() => setTagDropdownOpen((v) => !v)} disabled={tagsSaving}>
                    + Add Tag {tagsLoading || tagsSaving ? '⏳' : ''}
                  </button>

                  {tagDropdownOpen ? (
                    <div style={{ position: 'absolute', top: 'calc(100% + 6px)', left: 0, width: 260, maxHeight: 260, overflow: 'auto', border: '1px solid #334155', borderRadius: 10, background: '#0b1220', zIndex: 30, padding: 8 }}>
                      <input
                        value={tagSearch}
                        onChange={(e) => setTagSearch(e.target.value)}
                        placeholder="Search tag..."
                        style={{ width: '100%', marginBottom: 8 }}
                      />
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {allTags
                          .filter((t) => !iocTags.some((it) => Number(it.id) === Number(t.id)))
                          .filter((t) => {
                            const q = String(tagSearch || '').trim().toLowerCase();
                            if (!q) return true;
                            return String(t.name || '').toLowerCase().includes(q);
                          })
                          .map((t) => (
                            <button
                              key={`opt-tag-${t.id}`}
                              type="button"
                              onClick={() => addIocTag(t.id).catch(() => {})}
                              disabled={tagsSaving}
                              style={{ textAlign: 'left', border: '1px solid #334155', borderRadius: 8, padding: '6px 8px', background: '#111827', color: '#e5e7eb', cursor: tagsSaving ? 'wait' : 'pointer' }}
                            >
                              {t.name}
                            </button>
                          ))}
                        {!tagsLoading && allTags.length === 0 ? (
                          <div style={{ color: '#94a3b8', fontSize: 12, padding: '4px 2px' }}>No tags available</div>
                        ) : null}
                        {!tagsLoading && allTags.length > 0 && allTags.filter((t) => !iocTags.some((it) => Number(it.id) === Number(t.id))).filter((t) => {
                          const q = String(tagSearch || '').trim().toLowerCase();
                          if (!q) return true;
                          return String(t.name || '').toLowerCase().includes(q);
                        }).length === 0 ? <div style={{ color: '#94a3b8', fontSize: 12, padding: '4px 2px' }}>No tag found</div> : null}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            </div>

            <div style={{ marginBottom: 14, border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
              <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Source Evidence</div>
              <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 900, fontSize: 13 }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#111827' }}>
                    <th>Source</th><th>URL</th><th>Confidence</th><th>Category</th><th>Note</th><th>Created At</th>
                  </tr>
                </thead>
                <tbody>
                  {data.sources.map((s) => (
                    <tr key={`${s.id}-${s.created_at}`} style={{ borderTop: '1px solid #334155' }}>
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{s.source_name || '-'}</td>
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{s.source_url || '-'}</td>
                      <td>{s.confidence || '-'}</td>
                      <td>{s.category || '-'}</td>
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{sanitizeSourceNote(s.note)}</td>
                      <td>{formatUserDateTime(s.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
              <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Related Incidents</div>
              <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 1380, fontSize: 13 }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#111827' }}>
                    <th style={{ width: 100 }}>Incident ID</th>
                    <th style={{ width: 160 }}>First Seen</th>
                    <th style={{ width: 160 }}>Last Seen</th>
                    <th style={{ width: 120 }}>Detection Events</th>
                    <th style={{ width: 110 }}>Evidence Logs</th>
                    <th style={{ width: 120 }}>Observed Hosts</th>
                    <th style={{ width: 120 }}>Verdict</th>
                    <th style={{ width: 100 }}>Status</th>
                    <th style={{ width: 100 }}>Risk Score</th>
                    <th style={{ width: 120 }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.incidents || []).length ? (data.incidents || []).map((inc) => (
                    <tr key={`inc-${inc.id}`} style={{ borderTop: '1px solid #334155' }}>
                      <td>#{inc.incident_id ?? '-'}</td>
                      <td>{formatUserDateTime(inc.first_seen)}</td>
                      <td>{formatUserDateTime(inc.last_seen)}</td>
                      <td>{Number(inc.detection_events || 0)}</td>
                      <td>{Number.isFinite(Number(inc.evidence_logs)) ? Number(inc.evidence_logs) : '-'}</td>
                      <td>{Number(inc.observed_hosts || 0)}</td>
                      <td>{inc.verdict || 'Unreviewed'}</td>
                      <td>{inc.status || '-'}</td>
                      <td>{Number.isFinite(Number(inc.risk_score)) ? Number(inc.risk_score).toFixed(2) : '-'}</td>
                      <td>
                        <button type="button" onClick={() => navigate(`/incidents/${inc.incident_id || inc.id}`)} title="View incident" aria-label="View incident" style={{ minWidth: 32, padding: '4px 8px' }}>🔍</button>
                      </td>
                    </tr>
                  )) : <tr><td colSpan={10} style={{ color: '#94a3b8' }}>No related incidents found for this IOC.</td></tr>}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>
    </AppShell>
  );
}

function IOCAddPage() {
  const navigate = useNavigate();
  const { canWrite } = useSession();
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState(null);
  const [recentRows, setRecentRows] = useState([]);
  const [recentSort, setRecentSort] = useState({ key: null, dir: null });
  const [recentWidths, setRecentWidths] = useState({ idx: 50, observable: 420, type: 110, source: 220, confidence: 110, ts: 170 });
  const [recentResize, setRecentResize] = useState(null);
  const [iocValue, setIocValue] = useState('');
  const [confidenceValue, setConfidenceValue] = useState('medium');
  const iocFormRef = useRef(null);

  useEffect(() => {
    if (!message) return;
    const t = setTimeout(() => setMessage(null), 4000);
    return () => clearTimeout(t);
  }, [message]);


  function detectIocType(value) {
    const v = String(value || '').trim();
    if (!v) return null;
    const ipv4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    const ipv6 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::)$/;
    const url = /^(https?:\/\/)[^\s/$.?#].[^\s]*$/i;
    const hash = /^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$/;
    const domain = /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;

    if (url.test(v)) return 'url';
    if (ipv4.test(v) || ipv6.test(v)) return 'ip';
    if (hash.test(v)) return 'hash';
    if (domain.test(v)) return 'domain';
    return 'unknown';
  }

  function iocTypeStyle(type) {
    const map = {
      url: { color: '#60a5fa', border: '#2563eb', bg: 'rgba(37,99,235,0.15)' },
      domain: { color: '#22d3ee', border: '#0891b2', bg: 'rgba(8,145,178,0.18)' },
      ip: { color: '#34d399', border: '#059669', bg: 'rgba(5,150,105,0.18)' },
      hash: { color: '#f472b6', border: '#db2777', bg: 'rgba(219,39,119,0.16)' },
      unknown: { color: '#94a3b8', border: '#475569', bg: 'rgba(71,85,105,0.2)' }
    };
    return map[type] || map.unknown;
  }

  function confidencePillStyle(value) {
    if (value === 'high') return { color: '#991b1b', bg: '#fee2e2' };
    if (value === 'medium') return { color: '#92400e', bg: '#fef3c7' };
    return { color: '#166534', bg: '#dcfce7' };
  }

  function sourceBadgeStyle(source) {
    const seed = String(source || 'source').length;
    const hue = (seed * 23) % 360;
    return {
      color: '#cbd5e1',
      border: `1px solid hsl(${hue} 60% 35%)`,
      background: `hsla(${hue}, 75%, 20%, 0.45)`
    };
  }

  function relativeTime(dateVal) {
    const ts = new Date(dateVal || 0).getTime();
    if (!Number.isFinite(ts) || ts <= 0) return '-';
    const diffSec = Math.max(1, Math.floor((Date.now() - ts) / 1000));
    if (diffSec < 60) return `${diffSec}s ago`;
    const min = Math.floor(diffSec / 60);
    if (min < 60) return `${min} min ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.floor(hr / 24);
    if (day < 7) return `${day}d ago`;
    return formatUserDateTime(dateVal);
  }

  async function loadRecent() {
    const res = await api.get('/ioc/recent', { params: { limit: 10 } });
    setRecentRows(res.data?.items || []);
  }

  useEffect(() => {
    loadRecent().catch(() => {});
  }, []);

  useEffect(() => {
    if (!recentResize) return undefined;
    function onMove(e) {
      const delta = e.clientX - recentResize.startX;
      const next = Math.max(70, recentResize.startWidth + delta);
      setRecentWidths((prev) => ({ ...prev, [recentResize.col]: next }));
    }
    function onUp() { setRecentResize(null); }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [recentResize]);

  function toggleRecentSort(key) {
    setRecentSort((prev) => {
      if (prev.key !== key) return { key, dir: 'asc' };
      if (prev.dir === 'asc') return { key, dir: 'desc' };
      if (prev.dir === 'desc') return { key: null, dir: null };
      return { key, dir: 'asc' };
    });
  }

  function recentIndicator(key) {
    if (recentSort.key !== key || !recentSort.dir) return '';
    return recentSort.dir === 'asc' ? ' ▲' : ' ▼';
  }

  function startRecentResize(col, e) {
    e.preventDefault();
    e.stopPropagation();
    setRecentResize({ col, startX: e.clientX, startWidth: recentWidths[col] || 120 });
  }


  const sortedRecentRows = useMemo(() => {
    if (!recentSort.key || !recentSort.dir) return recentRows;
    const copy = [...recentRows];
    const value = (r, k) => {
      if (k === 'observable') return r.observable;
      if (k === 'type') return r.observable_type;
      if (k === 'source') return r.source_name || '';
      if (k === 'confidence') return r.confidence || '';
      if (k === 'ts') return new Date(r.created_at || 0).getTime();
      return '';
    };
    copy.sort((a, b) => {
      const av = value(a, recentSort.key);
      const bv = value(b, recentSort.key);
      const cmp = (typeof av === 'number' && typeof bv === 'number') ? av - bv : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: 'base' });
      return recentSort.dir === 'asc' ? cmp : -cmp;
    });
    return copy;
  }, [recentRows, recentSort]);

  async function onSubmit(e) {
    e.preventDefault();
    if (!canWrite || submitting) return;
    setSubmitting(true);

    const formEl = iocFormRef.current || e.currentTarget;
    const form = new FormData(formEl);
    const payload = {
      ip: String(form.get('ip') || '').trim(),
      source_name: String(form.get('source_name') || '').trim(),
      source_url: String(form.get('source_url') || '').trim(),
      confidence: form.get('confidence'),
      category: String(form.get('category') || '').trim(),
      note: String(form.get('note') || '').trim()
    };

    try {
      const { data } = await api.post('/ioc/ip', payload);
      formEl?.reset?.();
      setIocValue('');
      setConfidenceValue('medium');
      loadRecent().catch(() => {});
      if (data?.skipped) {
        setMessage({ type: 'duplicate', text: 'Already in list (duplicate).' });
      } else {
        setMessage({ type: 'success', text: 'IOC saved successfully.' });
      }
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.response?.data?.message || err?.message || 'Failed to save record';
      setMessage({ type: 'error', text: msg });
    } finally {
      setSubmitting(false);
    }
  }

  const detectedType = detectIocType(iocValue);
  const detectedStyle = iocTypeStyle(detectedType || 'unknown');

  const messageStyle = message?.type === 'success'
    ? { background: 'rgba(34,197,94,0.16)', border: '1px solid #22c55e', color: '#86efac' }
    : message?.type === 'duplicate'
      ? { background: 'rgba(234,179,8,0.16)', border: '1px solid #eab308', color: '#fde68a' }
      : { background: 'rgba(239,68,68,0.16)', border: '1px solid #ef4444', color: '#fca5a5' };

  const confidenceStyle = confidencePillStyle(confidenceValue);
  const inputStyle = { width: '100%', minWidth: 0, height: 42, padding: '10px 12px', borderRadius: 10, border: '1px solid #334155', background: '#020617', color: '#e2e8f0', boxSizing: 'border-box' };
  const fieldLabelStyle = { display: 'block', marginBottom: 6, fontSize: 12, color: '#cbd5e1', fontWeight: 600 };
  const twoColRowStyle = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14, alignItems: 'end' };

  return (
    <AppShell>
      <section style={{ display: 'grid', gap: 14 }}>
        <div style={{ border: '1px solid #334155', borderRadius: 14, background: '#0f172a', padding: 18, boxShadow: '0 8px 28px rgba(2, 6, 23, 0.35)' }}>
          <h2 style={{ marginTop: 0, marginBottom: 4 }}>Add IOC</h2>
          <p style={{ marginTop: 0, marginBottom: 14, color: '#94a3b8', fontSize: 13 }}>Insert indicator data with confidence and source metadata.</p>
          {!canWrite && (
            <div style={{ marginBottom: 12, padding: 10, borderRadius: 8, border: '1px solid #475569', color: '#94a3b8', fontSize: 14 }}>
              Read-only role: adding IOCs is disabled.
            </div>
          )}
          {message && (
            <div role="alert" style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, fontSize: 14, ...messageStyle }}>
              {message.text}
            </div>
          )}

          <form ref={iocFormRef} onSubmit={onSubmit} style={{ display: 'grid', gap: 14 }}>
            <div>
              <label htmlFor="ioc-value" style={{ ...fieldLabelStyle, letterSpacing: 0.3 }}>IOC Value</label>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <input id="ioc-value" name="ip" value={iocValue} onChange={(e) => setIocValue(e.target.value)} required disabled={!canWrite} spellCheck={false} style={{ ...inputStyle, flex: 1 }} />
                {detectedType && (
                  <span style={{ display: 'inline-flex', alignItems: 'center', whiteSpace: 'nowrap', padding: '6px 9px', borderRadius: 999, border: `1px solid ${detectedStyle.border}`, background: detectedStyle.bg, color: detectedStyle.color, fontWeight: 700, fontSize: 12, textTransform: 'uppercase', letterSpacing: 0.4 }}>
                    {detectedType}
                  </span>
                )}
              </div>
            </div>

            <div style={twoColRowStyle}>
              <div>
                <label htmlFor="source-name" style={fieldLabelStyle}>Source Name</label>
                <input id="source-name" name="source_name" required disabled={!canWrite} style={inputStyle} />
              </div>
              <div>
                <label htmlFor="source-url" style={fieldLabelStyle}>Source URL</label>
                <input id="source-url" name="source_url" disabled={!canWrite} style={inputStyle} />
              </div>
            </div>

            <div style={twoColRowStyle}>
              <div>
                <label htmlFor="confidence" style={fieldLabelStyle}>Confidence</label>
                <select id="confidence" name="confidence" value={confidenceValue} onChange={(e) => setConfidenceValue(e.target.value)} disabled={!canWrite} style={{ ...inputStyle, background: confidenceStyle.bg, color: confidenceStyle.color, fontWeight: 700, fontSize: 12, textTransform: 'capitalize' }}>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div>
                <label htmlFor="category" style={fieldLabelStyle}>Category</label>
                <input id="category" name="category" disabled={!canWrite} style={inputStyle} />
              </div>
            </div>

            <div>
              <label htmlFor="note" style={fieldLabelStyle}>Note</label>
              <input id="note" name="note" disabled={!canWrite} style={inputStyle} />
            </div>

            <button type="submit" disabled={submitting || !canWrite} style={{ width: '100%', padding: '11px 14px', borderRadius: 10, border: '1px solid #1d4ed8', background: submitting || !canWrite ? '#1e3a8a' : '#2563eb', color: '#dbeafe', fontWeight: 700, letterSpacing: 0.3, cursor: submitting || !canWrite ? 'not-allowed' : 'pointer', opacity: submitting || !canWrite ? 0.7 : 1 }}>
              {submitting ? 'Adding...' : '+ Add IOC'}
            </button>
          </form>
        </div>

        <div style={{ border: '1px solid #334155', borderRadius: 14, background: '#0f172a', boxShadow: '0 8px 28px rgba(2, 6, 23, 0.35)' }}>
          <div style={{ padding: '14px 16px 10px', borderBottom: '1px solid #334155' }}>
            <h3 style={{ margin: 0 }}>Last 10 IOC entries</h3>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 860, background: '#0f172a', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
              <colgroup>
                <col style={{ width: recentWidths.idx }} /><col style={{ width: recentWidths.observable }} /><col style={{ width: recentWidths.type }} /><col style={{ width: recentWidths.source }} /><col style={{ width: recentWidths.confidence }} /><col style={{ width: recentWidths.ts }} />
              </colgroup>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', background: '#111827' }}>
                  <th style={{ position: 'relative' }}>#<div onMouseDown={(e) => startRecentResize('idx', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('observable')} style={{ position: 'relative', cursor:'pointer' }}>IOC{recentIndicator('observable')}<div onMouseDown={(e) => startRecentResize('observable', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('type')} style={{ position: 'relative', cursor:'pointer' }}>IOC Type{recentIndicator('type')}<div onMouseDown={(e) => startRecentResize('type', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('source')} style={{ position: 'relative', cursor:'pointer' }}>Source{recentIndicator('source')}<div onMouseDown={(e) => startRecentResize('source', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('confidence')} style={{ position: 'relative', cursor:'pointer' }}>Confidence{recentIndicator('confidence')}<div onMouseDown={(e) => startRecentResize('confidence', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                  <th onClick={() => toggleRecentSort('ts')} style={{ position: 'relative', cursor:'pointer' }}>Timestamp{recentIndicator('ts')}<div onMouseDown={(e) => startRecentResize('ts', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                </tr>
              </thead>
              <tbody>
                {sortedRecentRows.map((r, idx) => {
                  const conf = confidencePillStyle(r.confidence);
                  const sourceStyle = sourceBadgeStyle(r.source_name);
                  return (
                    <tr key={`${r.observable_type}-${r.id}-${idx}`} style={{ borderBottom: '1px solid #1f2937', transition: 'background 0.15s ease-in-out' }} onMouseEnter={(e) => { e.currentTarget.style.background = '#111827'; }} onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}>
                      <td>{idx + 1}</td>
                      <td title={r.observable} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <button
                            onClick={() => r.public_id ? navigate(`/ioc/details/${encodeURIComponent(r.public_id)}`) : navigate('/ioc')}
                            style={{ background: 'transparent', border: 'none', color: '#93c5fd', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit', textAlign: 'left' }}
                          >
                            <code style={{ whiteSpace: 'inherit', overflowWrap: 'anywhere', wordBreak: 'break-word' }}>{r.observable}</code>
                          </button>
                        </div>
                      </td>
                      <td>{r.observable_type || '-'}</td>
                      <td title={r.source_name} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                        <span style={{ display: 'inline-flex', borderRadius: 999, padding: '3px 10px', fontSize: 12, fontWeight: 700, ...sourceStyle }}>{r.source_name || '-'}</span>
                      </td>
                      <td>
                        <span style={{ display: 'inline-flex', borderRadius: 999, padding: '4px 10px', fontSize: 12, fontWeight: 700, textTransform: 'capitalize', color: conf.color, background: conf.bg }}>{r.confidence || '-'}</span>
                      </td>
                      <td>{formatUserDateTime(r.created_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </AppShell>
  );
}

function Protected({ children }) {
  const { authState } = useSession();

  if (authState === 'loading') {
    return <div style={{ padding: 24, fontFamily: 'sans-serif', color: '#94a3b8' }}>Loading…</div>;
  }
  if (authState === 'anon') return <Navigate to="/login" replace />;
  return children;
}

function DefaultRedirect() {
  const { authState } = useSession();

  if (authState === 'loading') {
    return <div style={{ padding: 24, fontFamily: 'sans-serif', color: '#94a3b8' }}>Loading…</div>;
  }
  if (authState === 'anon') return <Navigate to="/login" replace />;
  return <Navigate to="/analytics" replace />;
}

function App() {
  return (
    <>
      <style>{`
        :root { color-scheme: dark; }
        html, body, #root {
          background: #0b1220 !important;
          color: #e2e8f0 !important;
        }
        * { scrollbar-color: #334155 #0b1220; }
        aside, section, main, table, thead, tbody, tr, th, td, div {
          border-color: #334155 !important;
        }
        section, aside, table, .card, [style*='background: #fff'], [style*='background: #ffffff'], [style*='background: #f8fafc'] {
          background: #111827 !important;
          color: #e2e8f0 !important;
        }
        input, select, textarea {
          background: #0f172a !important;
          color: #e2e8f0 !important;
          border: 1px solid #334155 !important;
        }
        button {
          background: #1f2937 !important;
          color: #e2e8f0 !important;
          border: 1px solid #475569 !important;
        }
        button:hover { background: #334155 !important; }
        a { color: #93c5fd !important; }
        thead tr { background: #1f2937 !important; }
        tbody tr { background: #111827 !important; }
        code { color: #93c5fd !important; }
        table th, table td { border-right: 1px solid #334155 !important; }
        table th:last-child, table td:last-child { border-right: none !important; }
        .ioc-table th, .ioc-table td { border-right: 1px solid #334155 !important; }
        .ioc-table th:last-child, .ioc-table td:last-child { border-right: none !important; }
        .published-feeds-page input:focus,
        .published-feeds-page select:focus,
        .published-feeds-page textarea:focus {
          outline: none !important;
          border-color: #3b82f6 !important;
          box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.35) !important;
        }
        .published-feeds-page input::placeholder,
        .published-feeds-page textarea::placeholder {
          color: #64748b !important;
          opacity: 1;
        }
        .published-feeds-page .published-feeds-table thead tr {
          background: #0f172a !important;
        }
      `}</style>
      <BrowserRouter>
        <SessionProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/system" element={<Protected><SystemStatusPage /></Protected>} />
          
          <Route path="/analytics" element={<Protected><AnalyticsPage /></Protected>} />
          <Route path="/analytics/statistics" element={<Protected><AnalyticsStatisticsPage /></Protected>} />
          <Route path="/analytics/detection-events" element={<Protected><IOCMatchEventsPage /></Protected>} />
          <Route path="/analytics/detection-events/:id" element={<Protected><IOCMatchEventDetailsPage /></Protected>} />
          <Route path="/risk-overview" element={<Protected><RiskOverviewPage /></Protected>} />
          <Route path="/incidents" element={<Protected><IncidentPage /></Protected>} />
          <Route path="/incidents/:id" element={<Protected><IncidentDetailsPage /></Protected>} />
          <Route path="/incident" element={<Navigate to="/incidents" replace />} />
          <Route path="/ioc" element={<Protected><IOCListPage /></Protected>} />
          <Route path="/ioc/hot" element={<Protected><IOCHotListPage /></Protected>} />
          <Route path="/ioc/details/:publicId" element={<Protected><IOCDetailsPage /></Protected>} />
          <Route path="/ioc/details/:type/:observable" element={<Protected><LegacyIOCDetailsRedirect /></Protected>} />
          <Route path="/ioc/new" element={<Protected><IOCAddPage /></Protected>} />
          <Route path="/threat-intelligence" element={<Navigate to="/threat-intelligence/feeds" replace />} />
          <Route path="/threat-intelligence/feeds" element={<Protected><IntegrationsPage hideKeys={["asn_enrichment"]} /></Protected>} />
          <Route path="/threat-intelligence/enrichment" element={<Protected><IntegrationsEnrichmentPage /></Protected>} />
          <Route path="/threat-intelligence/queue" element={<Protected><IntegrationsQueueStatusPage /></Protected>} />
          <Route path="/threat-intelligence/runs" element={<Protected><IntegrationsRecentRunsPage /></Protected>} />
          <Route path="/threat-intelligence/published-feeds" element={<Protected><PublishedFeedsPage /></Protected>} />
          <Route path="/administration/api-keys" element={<Protected><ApiKeysPage /></Protected>} />
          <Route path="/administration/enrichment-providers" element={<Protected><EnrichmentProvidersPage /></Protected>} />
          <Route path="/administration" element={<Protected><AdministrationPage /></Protected>} />
          <Route path="/settings" element={<Navigate to="/administration" replace />} />
          <Route path="*" element={<DefaultRedirect />} />
        </Routes>
        </SessionProvider>
      </BrowserRouter>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
