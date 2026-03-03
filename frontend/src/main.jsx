import React, { useEffect, useMemo, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import { ComposableMap, Geographies, Geography, ZoomableGroup } from 'react-simple-maps';

const api = axios.create({ baseURL: '/api' });

api.interceptors.request.use((config) => {
  const email = localStorage.getItem('demo_user');
  if (email) {
    config.headers = config.headers || {};
    config.headers['x-user-email'] = email;
  }
  return config;
});

const COMMON_TIMEZONES = [
  'UTC',
  'Europe/Istanbul',
  'Europe/Berlin',
  'Europe/London',
  'America/New_York',
  'Asia/Dubai'
];

function formatUserDateTime(value) {
  if (!value) return '-';
  const timeZone = localStorage.getItem('demo_timezone') || 'UTC';
  return new Date(value).toLocaleString('en-GB', {
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

function isAuthed() {
  return Boolean(localStorage.getItem('demo_token'));
}

function LoginPage() {
  const navigate = useNavigate();

  async function onSubmit(e) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const email = form.get('email');
    const password = form.get('password');

    try {
      const { data } = await api.post('/auth/login', { email, password });
      localStorage.setItem('demo_token', data.token);
      localStorage.setItem('demo_user', data.user.email);
      localStorage.removeItem('demo_timezone');
      navigate('/analytics');
    } catch {
      alert('Invalid email or password');
    }
  }

  return (
    <div style={{ maxWidth: 360, margin: '80px auto', fontFamily: 'sans-serif' }}>
      <h2>Demo Login</h2>
      <form onSubmit={onSubmit}>
        <input name="email" type="email" placeholder="email" required style={{ width: '100%', marginBottom: 8, padding: 8 }} />
        <input name="password" type="password" placeholder="password" required style={{ width: '100%', marginBottom: 8, padding: 8 }} />
        <button type="submit" style={{ width: '100%', padding: 10 }}>Sign In</button>
      </form>
      <p style={{ fontSize: 12, color: '#555' }}>Demo user: demo@demo.local / Password1!</p>
    </div>
  );
}

function AppShell({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const user = localStorage.getItem('demo_user');
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

  function logout() {
    localStorage.removeItem('demo_token');
    localStorage.removeItem('demo_user');
    localStorage.removeItem('demo_timezone');
    navigate('/login');
  }

  const isActive = (path) => location.pathname === path;
  const isOpsActive = location.pathname.startsWith('/ioc');
  const isIntegrationsActive = location.pathname.startsWith('/integrations');

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
        <div style={{ marginBottom: 14, fontSize: 14 }}>User: <b>{user || 'demo user'}</b></div>

        <nav>
          <Link to="/dashboard" style={menuStyle(isActive('/dashboard'))}>1. Dashboard</Link>
          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(location.pathname.startsWith('/analytics'))}>2. Analytics</div>
            <Link to="/analytics" style={subMenuStyle(isActive('/analytics'))}>Overview</Link>
            <Link to="/analytics/statistics" style={subMenuStyle(isActive('/analytics/statistics'))}>Statistics</Link>
          </div>
          <Link to="/incident" style={menuStyle(isActive('/incident'))}>3. Incident</Link>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(isOpsActive)}>4. Operations</div>
            <Link to="/ioc" style={subMenuStyle(isActive('/ioc'))}>IOC List</Link>
            <Link to="/ioc/new" style={subMenuStyle(isActive('/ioc/new'))}>Add IOC</Link>
          </div>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(isIntegrationsActive)}>5. Integrations</div>
            <Link to="/integrations" style={subMenuStyle(isActive('/integrations'))}>Overview</Link>
            <Link to="/integrations/queue" style={subMenuStyle(isActive('/integrations/queue'))}>Job Queue Status</Link>
            <Link to="/integrations/runs" style={subMenuStyle(isActive('/integrations/runs'))}>Recent Runs</Link>
          </div>

          <div style={{ marginTop: 8 }}>
            <Link to="/settings" style={menuStyle(isActive('/settings'))}>6. Settings</Link>
          </div>
        </nav>

        <div style={{ marginTop: 16, fontSize: 12, color: '#475569' }}>Timezone: <b>{timezone}</b></div>
        <button onClick={logout} style={{ marginTop: 10, width: '100%', padding: 9 }}>Logout</button>
      </aside>

      <main style={{ flex: 1, minWidth: 0 }}>
        {children}
      </main>

      {needsTimezoneSelection && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(15,23,42,0.45)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ width: 420, maxWidth: '92vw', background: '#fff', borderRadius: 12, padding: 16, border: '1px solid #e2e8f0' }}>
            <h3 style={{ marginTop: 0 }}>Select Timezone</h3>
            <p style={{ fontSize: 14, color: '#475569' }}>This is required once. You can change it later from Settings.</p>
            <select value={timezone} onChange={(e) => setTimezone(e.target.value)} style={{ width: '100%', padding: 10, borderRadius: 8, border: '1px solid #cbd5e1', marginBottom: 10 }}>
              {COMMON_TIMEZONES.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
            </select>
            <button onClick={() => saveTimezone(timezone)} style={{ width: '100%', padding: 10, fontWeight: 600 }}>Save Timezone</button>
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
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#111827' }}>
                <th style={{ width: 80 }}>ID</th>
                <th>Time</th>
                <th>Host</th>
                <th>Process</th>
                <th>Destination</th>
                <th style={{ width: 90 }}>Port</th>
                <th style={{ width: 110 }}>Protocol</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} style={{ color: '#94a3b8' }}>Loading raw events...</td></tr>
              ) : rawEvents.length ? rawEvents.map((evt) => (
                <tr key={evt.id} style={{ borderTop: '1px solid #334155' }}>
                  <td>{evt.id}</td>
                  <td>{formatUserDateTime(evt.event_time || evt.created_at)}</td>
                  <td>{evt.host_name || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{evt.process_name || '-'}</td>
                  <td>{evt.destination_ip || '-'}</td>
                  <td>{evt.destination_port || '-'}</td>
                  <td>{evt.protocol || '-'}</td>
                </tr>
              )) : (
                <tr><td colSpan={7} style={{ color: '#94a3b8' }}>No raw events yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 16, border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>
            Last 10 IOC Match Events
          </div>
          <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <thead>
              <tr style={{ textAlign: 'left', background: '#111827' }}>
                <th style={{ width: 80 }}>ID</th>
                <th>Time</th>
                <th>Host</th>
                <th>Process</th>
                <th>Destination</th>
                <th>Matched IOC</th>
                <th>Source</th>
                <th style={{ width: 110 }}>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {iocLoading ? (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>Loading IOC matches...</td></tr>
              ) : iocMatches.length ? iocMatches.map((evt) => (
                <tr key={`ioc-${evt.id}-${evt.event_time}`} style={{ borderTop: '1px solid #334155' }}>
                  <td>{evt.id}</td>
                  <td>{formatUserDateTime(evt.event_time || evt.created_at)}</td>
                  <td>{evt.host_name || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{evt.process_name || '-'}</td>
                  <td>{evt.destination_ip || '-'}</td>
                  <td>{evt.matched_ioc || '-'}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{evt.source_name || '-'}</td>
                  <td>{evt.confidence || '-'}</td>
                </tr>
              )) : (
                <tr><td colSpan={8} style={{ color: '#94a3b8' }}>No IOC match events yet.</td></tr>
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

  const maxSource = Math.max(...topSources.map((x) => Number(x.event_count || 0)), 1);
  const maxClient = Math.max(...topClients.map((x) => Number(x.event_count || 0)), 1);
  const maxRiskyClient = Math.max(...riskyClients.map((x) => Number(x.risky_event_count || 0)), 1);

  const timelineByBucket = timeline.reduce((acc, row) => {
    const key = formatUserDateTime(row.bucket);
    acc[key] = (acc[key] || 0) + Number(row.event_count || 0);
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
                    const count = Number(row.event_count || 0);
                    const w = Math.max(6, Math.round((count / maxSource) * 100));
                    return (
                      <tr key={row.source_key} style={{ borderTop: '1px solid #334155' }}>
                        <td>{row.source_key}</td>
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
                    const count = Number(row.event_count || 0);
                    const w = Math.max(6, Math.round((count / maxClient) * 100));
                    return (
                      <tr key={row.host_name} style={{ borderTop: '1px solid #334155' }}>
                        <td>{row.host_name}</td>
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

function IncidentPage() {
  return (
    <AppShell>
      <section style={{ border: '1px dashed #334155', borderRadius: 12, background: '#111827', padding: 24, minHeight: 220, display: 'grid', placeItems: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <h2 style={{ marginTop: 0, marginBottom: 8 }}>Incident</h2>
          <p style={{ margin: 0, color: '#94a3b8' }}>This page is intentionally left blank for now.</p>
        </div>
      </section>
    </AppShell>
  );
}

function IntegrationsPage() {
  const [loading, setLoading] = useState(true);
  const [integrations, setIntegrations] = useState([]);
  const [runningNowAll, setRunningNowAll] = useState(false);
  const [runningKeys, setRunningKeys] = useState({});

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
    try {
      await api.put(`/integrations/${encodeURIComponent(key)}/trust-level`, { trust_level: trustLevel });
      setIntegrations((prev) => prev.map((i) => (i.key === key ? { ...i, trust_level: trustLevel } : i)));
    } catch {
      alert('Failed to update trust level');
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

  const humanSchedule = (cron) => {
    const c = String(cron || '').trim();
    if (c === '0 * * * *') return 'Every hour';
    if (c === '*/30 * * * *') return 'Every 30 minutes';
    if (c === '*/15 * * * *') return 'Every 15 minutes';
    return c || '-';
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
          <h2 style={{ marginTop: 0, marginBottom: 10 }}>Integrations Overview</h2>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={runNowAll} disabled={runningNowAll}>{runningNowAll ? 'Queueing...' : 'Run now (all)'}</button>
            <button onClick={() => load().catch(() => {})}>Refresh</button>
          </div>
        </div>

        {loading ? <div>Loading...</div> : (
          <div style={{ overflowX: 'auto' }}>
            <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
                  <th>Name</th><th>Integration ID</th><th>Source</th><th>Added At</th><th>Schedule</th><th>Trust Level</th><th>Last status</th><th>Last run start</th><th>Total Records</th><th>Action</th>
                </tr>
              </thead>
              <tbody>
                {integrations.map((i) => (
                  <tr key={i.key} style={{ borderBottom: '1px solid #f1f5f9' }}>
                    <td>{i.name}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{i.integration_id || '-'}</td>
                    <td style={{ maxWidth: 360, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{i.source_url}</td>
                    <td>{formatUserDateTime(i.created_at)}</td>
                    <td>{humanSchedule(i.schedule)}</td>
                    <td>
                      <select value={i.trust_level || 'not_categorized'} onChange={(e) => updateTrustLevel(i.key, e.target.value)} style={{ width: '100%', minWidth: 0, padding: '6px 8px', borderRadius: 8, border: '1px solid #cbd5e1', boxSizing: 'border-box' }}>
                        <option value="guvenilir">Reliable</option>
                        <option value="orta">Medium</option>
                        <option value="not_categorized">Not Categorized</option>
                      </select>
                    </td>
                    <td style={{ color: statusColor(i.last_status), fontWeight: 700, textTransform: 'capitalize' }}>{statusLabel(i.last_status)}</td>
                    <td>{formatUserDateTime(i.last_started_at)}</td>
                    <td>{i.total_records ?? 0}</td>
                    <td><button onClick={() => runNowOne(i.key, i.name)} disabled={Boolean(runningKeys[i.key])}>{runningKeys[i.key] ? 'Queueing...' : 'Run now'}</button></td>
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

function IntegrationsQueueStatusPage() {
  const [loading, setLoading] = useState(true);
  const [queue, setQueue] = useState({ counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [] });
  const [tableWidths, setTableWidths] = useState({ id: 130, integration: 180, name: 140, state: 100, queued: 170, reason: 320 });
  const [resizeState, setResizeState] = useState(null);

  async function load() {
    setLoading(true);
    try {
      const { data } = await api.get('/integrations');
      setQueue(data?.queue || { counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [] });
    } catch {
      setQueue({ counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 }, jobs: [] });
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

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16, marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
          <h2 style={{ marginTop: 0 }}>Job Queue Status</h2>
          <button onClick={() => load().catch(() => {})}>Refresh</button>
        </div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 10, fontSize: 14 }}>
          <span>Waiting: <b>{queue.counts?.waiting || 0}</b></span>
          <span>Active: <b>{queue.counts?.active || 0}</b></span>
          <span>Delayed: <b>{queue.counts?.delayed || 0}</b></span>
          <span>Failed: <b>{queue.counts?.failed || 0}</b></span>
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
                  <td>{j.state}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(j.timestamp)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{j.failed_reason || (j.state === 'success' ? 'Completed successfully' : '-')}</td>
                </tr>
              )) : <tr><td colSpan={6} style={{ color: '#64748b' }}>No queued jobs</td></tr>)}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}

function IntegrationsRecentRunsPage() {
  const [loading, setLoading] = useState(true);
  const [recentRuns, setRecentRuns] = useState([]);
  const [tableWidths, setTableWidths] = useState({ id: 90, integration: 190, status: 110, started: 170, finished: 170, imported: 130 });
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
    return '#334155';
  };

  const statusLabel = (status) => {
    if (status === 'success') return 'success';
    if (status === 'failed' || status === 'fail') return 'fail';
    if (status === 'running') return 'running';
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
              <col style={{ width: tableWidths.status }} />
              <col style={{ width: tableWidths.started }} />
              <col style={{ width: tableWidths.finished }} />
              <col style={{ width: tableWidths.imported }} />
            </colgroup>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
                <th style={{ position: 'relative' }}>ID<div onMouseDown={(e) => startResize('id', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Integration<div onMouseDown={(e) => startResize('integration', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Status<div onMouseDown={(e) => startResize('status', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Started<div onMouseDown={(e) => startResize('started', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Finished<div onMouseDown={(e) => startResize('finished', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
                <th style={{ position: 'relative' }}>Imported IOCs<div onMouseDown={(e) => startResize('imported', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              </tr>
            </thead>
            <tbody>
              {loading ? <tr><td colSpan={6}>Loading...</td></tr> : (recentRuns.length ? recentRuns.map((r) => (
                <tr key={r.id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <td>{r.id}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.integration_name || r.integration_key || '-'}</td>
                  <td style={{ color: statusColor(r.status), fontWeight: 700, textTransform: 'capitalize' }}>{statusLabel(r.status)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(r.started_at)}</td>
                  <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{formatUserDateTime(r.finished_at)}</td>
                  <td>{r.records_processed ?? 0}</td>
                </tr>
              )) : <tr><td colSpan={6} style={{ color: '#64748b' }}>No runs yet</td></tr>)}
            </tbody>
          </table>
        </div>
      </section>
    </AppShell>
  );
}

function SettingsPage() {
  const [timezone, setTimezone] = useState(localStorage.getItem('demo_timezone') || 'UTC');
  const [saving, setSaving] = useState(false);

  async function save() {
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

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16, maxWidth: 520 }}>
        <h2 style={{ marginTop: 0 }}>Settings</h2>
        <label style={{ display: 'block', fontSize: 14, marginBottom: 6 }}>Timezone</label>
        <select value={timezone} onChange={(e) => setTimezone(e.target.value)} style={{ width: '100%', padding: 10, borderRadius: 8, border: '1px solid #cbd5e1', marginBottom: 12 }}>
          {COMMON_TIMEZONES.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
        </select>
        <button onClick={save} disabled={saving} style={{ padding: '10px 14px' }}>{saving ? 'Saving...' : 'Save'}</button>
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
  const [detailIp, setDetailIp] = useState('');
  const [detailSources, setDetailSources] = useState([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [listLoading, setListLoading] = useState(false);
  const [listStatusText, setListStatusText] = useState('');

  async function loadData(targetPage = page, targetSize = pageSize) {
    setListLoading(true);
    setListStatusText('Query is running. Please wait while IOC results are being processed...');
    try {
      const [listRes, summaryRes] = await Promise.all([
        api.get('/ioc/list', {
          params: {
            page: targetPage,
            page_size: targetSize,
            q: search || undefined,
          }
        }),
        api.get('/ioc/summary/today')
      ]);
      const items = listRes.data.items || [];
      setRows(items);
      setPagination(listRes.data.pagination || { page: 1, page_size: 5, total: 0, total_pages: 1 });
      setSummary(summaryRes.data);
      setListStatusText('');
    } catch {
      setRows([]);
      setListStatusText('Query failed. Please try again.');
    } finally {
      setListLoading(false);
    }
  }

  useEffect(() => {
    loadData(page, pageSize);
  }, [page, pageSize, search]);

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

  async function openSourceDetails(ip) {
    setDetailIp(ip);
    setDetailSources([]);
    setDetailLoading(true);
    try {
      const res = await api.get('/ioc/ip/sources', { params: { ip } });
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
    ip6: summary.by_type?.find((x) => x.observable_type === 'ip6')?.count || 0
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

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
      <h2 style={{ marginTop: 0 }}>IOC List</h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(120px, 1fr))', gap: 10, marginBottom: 16 }}>
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
          placeholder="IOC (e.g. 1.2.3.4 / malicious.example / http://bad.site)"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              setPage(1);
              setSearch(searchInput.trim());
            }
          }}
        />
        <button onClick={() => { setPage(1); setSearch(searchInput.trim()); }}>Search</button>
        <button onClick={() => { setSearchInput(''); setSearch(''); setPage(1); }}>Clear</button>
      </div>

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
        <div style={{ marginBottom: 10, padding: 10, background: '#fff8e1', border: '1px solid #ffe0a3', borderRadius: 6 }}>
          No IOC records found.
        </div>
      )}

      <div style={{ overflowX: 'auto', border: '1px solid #e5e7eb', borderRadius: 10 }}>
        <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 980, background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
          <colgroup>
            <col style={{ width: columnWidths.index }} />
            <col style={{ width: columnWidths.ip }} />
            <col style={{ width: columnWidths.source }} />
            <col style={{ width: columnWidths.confidence }} />
            <col style={{ width: columnWidths.category }} />
            <col style={{ width: columnWidths.timestamp }} />
          </colgroup>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
              <th style={{ position: 'relative' }}>
                #
                <div onMouseDown={(e) => startResize('index', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} />
              </th>
              <th onClick={() => nextSort('ip')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>IOC{sortIndicator('ip')}<div onMouseDown={(e) => startResize('ip', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('source')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Source{sortIndicator('source')}<div onMouseDown={(e) => startResize('source', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('confidence')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Confidence{sortIndicator('confidence')}<div onMouseDown={(e) => startResize('confidence', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('category')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>IOC Type{sortIndicator('category')}<div onMouseDown={(e) => startResize('category', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
              <th onClick={() => nextSort('timestamp')} style={{ position: 'relative', cursor: 'pointer', userSelect: 'none' }}>Timestamp{sortIndicator('timestamp')}<div onMouseDown={(e) => startResize('timestamp', e)} style={{ position: 'absolute', top: 0, right: 0, width: 8, height: '100%', cursor: 'col-resize' }} /></th>
            </tr>
          </thead>
          <tbody>
            {sortedRows.map((r, idx) => (
              <tr key={`${r.observable_type || 'ip'}:${r.observable || r.ip}`} style={{ borderBottom: '1px solid #f1f5f9' }}>
                <td style={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{(pagination.page - 1) * pagination.page_size + idx + 1}</td>
                <td title={r.observable || r.ip} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                  <button
                    onClick={() => r.id && navigate(`/ioc/details/${encodeURIComponent(r.id)}`)}
                    style={{ background: 'transparent', border: 'none', color: '#93c5fd', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit', textAlign: 'left' }}
                  >
                    {r.observable || r.ip}
                  </button>
                </td>
                <td title={(r.source_names && r.source_names[0]) || '-'} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                  {(r.observable_type || 'ip') === 'ip' ? (
                    <button onClick={() => openSourceDetails(r.ip)} style={{ background: 'transparent', border: 'none', color: '#0f172a', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit', textAlign: 'left' }}>
                      {(r.source_names && r.source_names[0]) || '-'}{r.source_count > 1 ? ` +${r.source_count - 1}` : ''}
                    </button>
                  ) : (
                    <span>{(r.source_names && r.source_names[0]) || '-'}</span>
                  )}
                </td>
                <td><span style={confidenceBadgeStyle((r.confidence_set && r.confidence_set[0]) || 'low')}>{(r.confidence_set && r.confidence_set[0]) || 'low'}</span></td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.observable_type || 'ip'}</td>
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

      {detailIp && (
        <div style={{ marginTop: 14, border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0f172a' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <b>Sources for {detailIp}</b>
            <button onClick={() => { setDetailIp(''); setDetailSources([]); }}>Close</button>
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
        const resolvedId = Number(res.data?.id || 0);
        if (active && resolvedId > 0) {
          navigate(`/ioc/details/${resolvedId}`, { replace: true });
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

function IOCDetailsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const detailsId = Number(id || 0);

  const [loading, setLoading] = useState(true);
  const [data, setData] = useState({ summary: null, sources: [], matches: [] });

  async function load() {
    setLoading(true);
    if (!(detailsId > 0)) {
      setData({ summary: null, sources: [], matches: [] });
      setLoading(false);
      return;
    }
    try {
      const res = await api.get('/ioc/details', { params: { id: detailsId } });
      setData(res.data || { summary: null, sources: [], matches: [] });
    } catch {
      setData({ summary: null, sources: [], matches: [] });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load().catch(() => {});
  }, [detailsId]);

  const summary = data.summary;
  const displayObservable = summary?.observable || '-';

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
              <div style={{ border: '1px solid #334155', borderRadius: 10, padding: '10px 12px', background: '#0f172a' }}><div style={{ fontSize: 12, color: '#94a3b8' }}>IOC Match Events</div><div style={{ fontSize: 18, fontWeight: 700 }}>{data.matches.length}</div></div>
            </div>

            <div style={{ marginBottom: 14, border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
              <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>IP Information</div>
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
                    <td>{summary.observable_type === 'url' ? 'url-host' : (summary.observable_type === 'ip' ? 'direct-ip' : '-')}</td>
                    <td>{formatUserDateTime(summary.first_seen_at)}</td>
                    <td>{formatUserDateTime(summary.last_seen_at)}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div style={{ marginBottom: 14, padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
              <div style={{ fontSize: 13, marginBottom: 6, color: '#94a3b8' }}>Confidence Set</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {(summary.confidence_set || []).length ? summary.confidence_set.map((c) => <span key={c} style={{ padding: '4px 8px', borderRadius: 999, border: '1px solid #475569' }}>{c}</span>) : <span>-</span>}
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
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{s.note || '-'}</td>
                      <td>{formatUserDateTime(s.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
              <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Recent IOC Match Events (Top 20)</div>
              <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 900, fontSize: 13 }}>
                <thead>
                  <tr style={{ textAlign: 'left', background: '#111827' }}>
                    <th>Time</th><th>Host</th><th>Process</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Source</th><th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.matches.length ? data.matches.map((m) => (
                    <tr key={`m-${m.id}-${m.created_at}`} style={{ borderTop: '1px solid #334155' }}>
                      <td>{formatUserDateTime(m.event_time || m.created_at)}</td>
                      <td>{m.host_name || '-'}</td>
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{m.process_name || '-'}</td>
                      <td>{m.destination_ip || '-'}</td>
                      <td>{m.destination_port || '-'}</td>
                      <td>{m.protocol || '-'}</td>
                      <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{m.source_name || '-'}</td>
                      <td>{m.confidence || '-'}</td>
                    </tr>
                  )) : <tr><td colSpan={8} style={{ color: '#94a3b8' }}>No IOC match event for this IOC yet.</td></tr>}
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
  const [submitting, setSubmitting] = useState(false);
  const [recentRows, setRecentRows] = useState([]);
  const [recentSort, setRecentSort] = useState({ key: null, dir: null });
  const [recentWidths, setRecentWidths] = useState({ idx: 50, observable: 420, type: 110, source: 220, confidence: 110, ts: 170 });
  const [recentResize, setRecentResize] = useState(null);
  const iocFormRef = useRef(null);

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
    if (submitting) return;
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
      await api.post('/ioc/ip', payload);
      formEl?.reset?.();
      loadRecent().catch(() => {});
      alert('IOC saved successfully');
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.response?.data?.message || err?.message || 'Failed to save record';
      alert(msg);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#ffffff', padding: 16 }}>
      <h2 style={{ marginTop: 0 }}>Add IOC</h2>
      <form ref={iocFormRef} onSubmit={onSubmit} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 8, marginBottom: 20 }}>
        <input name="ip" placeholder="IOC (e.g. 1.2.3.4 / malicious.example / http://bad.site)" required />
        <input name="source_name" placeholder="Source name" required />
        <input name="source_url" placeholder="Source URL" />
        <select name="confidence" defaultValue="medium">
          <option value="low">low</option>
          <option value="medium">medium</option>
          <option value="high">high</option>
        </select>
        <input name="category" placeholder="Category" />
        <input name="note" placeholder="Note" />
        <button type="submit" disabled={submitting} style={{ gridColumn: '1 / -1', padding: 10, opacity: submitting ? 0.7 : 1 }}>
          {submitting ? 'Saving...' : 'Save IOC'}
        </button>
      </form>

      <h3>Last 10 IOC entries</h3>
      <div style={{ overflowX: 'auto', border: '1px solid #e5e7eb', borderRadius: 10 }}>
        <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 860, background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
          <colgroup>
            <col style={{ width: recentWidths.idx }} /><col style={{ width: recentWidths.observable }} /><col style={{ width: recentWidths.type }} /><col style={{ width: recentWidths.source }} /><col style={{ width: recentWidths.confidence }} /><col style={{ width: recentWidths.ts }} />
          </colgroup>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
              <th style={{ position: 'relative' }}>#<div onMouseDown={(e) => startRecentResize('idx', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              <th onClick={() => toggleRecentSort('observable')} style={{ position: 'relative', cursor:'pointer' }}>IOC{recentIndicator('observable')}<div onMouseDown={(e) => startRecentResize('observable', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              <th onClick={() => toggleRecentSort('type')} style={{ position: 'relative', cursor:'pointer' }}>IOC Type{recentIndicator('type')}<div onMouseDown={(e) => startRecentResize('type', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              <th onClick={() => toggleRecentSort('source')} style={{ position: 'relative', cursor:'pointer' }}>Source{recentIndicator('source')}<div onMouseDown={(e) => startRecentResize('source', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              <th onClick={() => toggleRecentSort('confidence')} style={{ position: 'relative', cursor:'pointer' }}>Confidence{recentIndicator('confidence')}<div onMouseDown={(e) => startRecentResize('confidence', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
              <th onClick={() => toggleRecentSort('ts')} style={{ position: 'relative', cursor:'pointer' }}>Timestamp{recentIndicator('ts')}<div onMouseDown={(e) => startRecentResize('ts', e)} style={{ position:'absolute', right:0, top:0, width:8, height:'100%', cursor:'col-resize' }} /></th>
            </tr>
          </thead>
          <tbody>
            {sortedRecentRows.map((r, idx) => (
              <tr key={`${r.observable_type}-${r.id}-${idx}`} style={{ borderBottom: '1px solid #f0f0f0' }}>
                <td>{idx + 1}</td>
                <td title={r.observable} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>
                  <button
                    onClick={() => r.id ? navigate(`/ioc/details/${encodeURIComponent(r.id)}`) : navigate('/ioc')}
                    style={{ background: 'transparent', border: 'none', color: '#93c5fd', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit', textAlign: 'left' }}
                  >
                    <code style={{ whiteSpace: 'inherit', overflowWrap: 'anywhere', wordBreak: 'break-word' }}>{r.observable}</code>
                  </button>
                </td>
                <td>{r.observable_type || '-'}</td>
                <td title={r.source_name} style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word', lineHeight: 1.35 }}>{r.source_name}</td>
                <td>{r.confidence}</td>
                <td>{formatUserDateTime(r.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      </section>
    </AppShell>
  );
}

function Protected({ children }) {
  if (!isAuthed()) return <Navigate to="/login" replace />;
  return children;
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
        .ioc-table th, .ioc-table td { border-right: 1px solid #334155; }
        .ioc-table th:last-child, .ioc-table td:last-child { border-right: none; }
      `}</style>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/dashboard" element={<Protected><DashboardPage /></Protected>} />
          <Route path="/analytics" element={<Protected><AnalyticsPage /></Protected>} />
          <Route path="/analytics/statistics" element={<Protected><AnalyticsStatisticsPage /></Protected>} />
          <Route path="/incident" element={<Protected><IncidentPage /></Protected>} />
          <Route path="/ioc" element={<Protected><IOCListPage /></Protected>} />
          <Route path="/ioc/details/:id" element={<Protected><IOCDetailsPage /></Protected>} />
          <Route path="/ioc/details/:type/:observable" element={<Protected><LegacyIOCDetailsRedirect /></Protected>} />
          <Route path="/ioc/new" element={<Protected><IOCAddPage /></Protected>} />
          <Route path="/integrations" element={<Protected><IntegrationsPage /></Protected>} />
          <Route path="/integrations/queue" element={<Protected><IntegrationsQueueStatusPage /></Protected>} />
          <Route path="/integrations/runs" element={<Protected><IntegrationsRecentRunsPage /></Protected>} />
          <Route path="/settings" element={<Protected><SettingsPage /></Protected>} />
          <Route path="*" element={<Navigate to={isAuthed() ? '/analytics' : '/login'} replace />} />
        </Routes>
      </BrowserRouter>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
