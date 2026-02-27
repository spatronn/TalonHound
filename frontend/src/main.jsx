import React, { useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
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
      navigate('/dashboard');
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

  const menuStyle = (active) => ({
    display: 'block',
    padding: '10px 12px',
    borderRadius: 6,
    textDecoration: 'none',
    color: active ? '#fff' : '#111',
    background: active ? '#111' : 'transparent',
    fontWeight: active ? 600 : 500
  });

  const subMenuStyle = (active) => ({
    display: 'block',
    padding: '8px 10px',
    marginLeft: 8,
    borderRadius: 6,
    textDecoration: 'none',
    color: active ? '#fff' : '#333',
    background: active ? '#333' : 'transparent',
    fontSize: 14
  });

  return (
    <div style={{ width: '100%', margin: '16px 0', fontFamily: 'sans-serif', display: 'flex', gap: 16, alignItems: 'flex-start', padding: '0 16px', boxSizing: 'border-box' }}>
      <aside style={{ flex: '0 0 240px', border: '1px solid #e5e5e5', borderRadius: 10, padding: 12, height: 'fit-content', position: 'sticky', top: 16, background: '#fff' }}>
        <div style={{ marginBottom: 14, fontSize: 14 }}>User: <b>{user || 'demo user'}</b></div>

        <nav>
          <Link to="/dashboard" style={menuStyle(isActive('/dashboard'))}>1. Dashboard</Link>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(isOpsActive)}>2. Operations</div>
            <Link to="/ioc" style={subMenuStyle(isActive('/ioc'))}>IOC List</Link>
            <Link to="/ioc/new" style={subMenuStyle(isActive('/ioc/new'))}>Add IOC</Link>
          </div>

          <div style={{ marginTop: 8 }}>
            <Link to="/settings" style={menuStyle(isActive('/settings'))}>3. Settings</Link>
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
  const [mapData, setMapData] = useState({ total: 0, countries: [] });
  const [hoverInfo, setHoverInfo] = useState(null);
  const [zoom, setZoom] = useState(1);

  useEffect(() => {
    api.get('/ioc/map/countries', { params: { day: 'all' } })
      .then(({ data }) => setMapData({ total: data?.total || 0, countries: data?.countries || [] }))
      .catch(() => setMapData({ total: 0, countries: [] }));
  }, []);

  const normalizeCode = (value) => String(value || '').trim().toUpperCase();

  const countryCounts = mapData.countries.reduce((acc, row) => {
    acc[normalizeCode(row.country_code)] = row.total;
    return acc;
  }, {});
  const maxCount = Math.max(...Object.values(countryCounts), 0);

  const countryColor = (count) => {
    if (!count || maxCount === 0) return '#f8fafc';
    const ratio = count / maxCount;
    if (ratio <= 0.2) return '#fde047';
    if (ratio <= 0.4) return '#facc15';
    if (ratio <= 0.6) return '#fb923c';
    if (ratio <= 0.8) return '#f97316';
    return '#ef4444';
  };

  const resolveIso2 = (geo) => {
    const p = geo.properties || {};
    return normalizeCode(
      p.ISO_A2
      || p.iso_a2
      || p['ISO3166-1-Alpha-2']
      || p.ISO2
      || p.ADM0_A2
      || p.WB_A2
      || p.gu_a2
      || p.brk_a2
    );
  };

  return (
    <AppShell>
      <section style={{ border: '1px solid #e5e7eb', borderRadius: 12, background: '#fff', padding: 16 }}>
        <h2 style={{ marginTop: 0 }}>Threat World Map</h2>
        <div style={{ marginBottom: 12, fontSize: 15 }}>
          Total malicious IPs in database: <b style={{ fontSize: 22 }}>{mapData.total}</b>
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
          <button onClick={() => setZoom((z) => Math.max(1, Number((z - 0.2).toFixed(2))))}>- Zoom out</button>
          <button onClick={() => setZoom((z) => Math.min(4, Number((z + 0.2).toFixed(2))))}>+ Zoom in</button>
          <button onClick={() => setZoom(1)}>Reset</button>
        </div>

        <div style={{ border: '1px solid #e5e7eb', borderRadius: 10, background: '#f8fafc', padding: 8, position: 'relative' }}>
          <ComposableMap projectionConfig={{ scale: 155 }} width={1080} height={420} style={{ width: '100%', height: 'auto', display: 'block' }}>
            <ZoomableGroup zoom={zoom} center={[0, 12]}>
              <Geographies geography="https://raw.githubusercontent.com/datasets/geo-countries/master/data/countries.geojson">
                {({ geographies }) => geographies.map((geo) => {
                  const iso2 = resolveIso2(geo);
                  const count = countryCounts[iso2] || 0;
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={countryColor(count)}
                      stroke="#94a3b8"
                      strokeWidth={0.35}
                      onMouseEnter={() => setHoverInfo({
                        name: geo.properties?.ADMIN || geo.properties?.name || 'Unknown',
                        countryCount: count,
                        globalTotal: mapData.total,
                        code: iso2 || '-'
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
              <div><b>{hoverInfo.name} ({hoverInfo.code})</b></div>
              <div>Total in malicious DB: <b>{hoverInfo.globalTotal}</b></div>
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
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState({ total: 0, by_source: [], by_confidence: [] });
  const [pageSize, setPageSize] = useState(5);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [confidenceFilter, setConfidenceFilter] = useState('');
  const [asnFilter, setAsnFilter] = useState('');
  const [countryFilter, setCountryFilter] = useState('');
  const [pagination, setPagination] = useState({ page: 1, page_size: 5, total: 0, total_pages: 1 });
  const [timeRange, setTimeRange] = useState('today');
  const [selectedIps, setSelectedIps] = useState([]);
  const [detailIp, setDetailIp] = useState('');
  const [detailSources, setDetailSources] = useState([]);
  const [detailLoading, setDetailLoading] = useState(false);

  async function loadData(targetPage = page, targetSize = pageSize) {
    const [listRes, summaryRes] = await Promise.all([
      api.get('/ioc/ip', {
        params: {
          page: targetPage,
          page_size: targetSize,
          q: search || undefined,
          source_name: sourceFilter || undefined,
          confidence: confidenceFilter || undefined,
          asn: asnFilter || undefined,
          country: countryFilter || undefined,
          day: timeRange || 'today'
        }
      }),
      api.get('/ioc/summary/today', { params: { day: timeRange || 'today' } })
    ]);
    const items = listRes.data.items || [];
    setRows(items);
    setSelectedIps((prev) => prev.filter((ip) => items.some((r) => r.ip === ip)));
    setPagination(listRes.data.pagination || { page: 1, page_size: 5, total: 0, total_pages: 1 });
    setSummary(summaryRes.data);
  }

  useEffect(() => {
    loadData(page, pageSize).catch(() => {});
  }, [page, pageSize, search, sourceFilter, confidenceFilter, asnFilter, countryFilter, timeRange]);

  const allOnPageSelected = rows.length > 0 && rows.every((r) => selectedIps.includes(r.ip));

  function toggleSelectAllOnPage() {
    if (allOnPageSelected) {
      setSelectedIps((prev) => prev.filter((ip) => !rows.some((r) => r.ip === ip)));
      return;
    }
    setSelectedIps((prev) => Array.from(new Set([...prev, ...rows.map((r) => r.ip)])));
  }

  function toggleRow(ip) {
    setSelectedIps((prev) => (prev.includes(ip) ? prev.filter((x) => x !== ip) : [...prev, ip]));
  }

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

  async function deleteOne(ip) {
    const ok = window.confirm(`Delete IOC ${ip} and all linked sources?`);
    if (!ok) return;

    try {
      await api.delete(`/ioc/ip/${encodeURIComponent(ip)}`);
      await loadData(page, pageSize);
    } catch (err) {
      alert(err?.response?.data?.message || 'Failed to delete record');
    }
  }

  async function deleteSelected() {
    if (!selectedIps.length) return;
    const ok = window.confirm(`Delete ${selectedIps.length} selected IOC(s) with all linked sources?`);
    if (!ok) return;

    try {
      await api.post('/ioc/ip/bulk-delete', { ips: selectedIps });
      setSelectedIps([]);
      await loadData(page, pageSize);
    } catch (err) {
      alert(err?.response?.data?.message || 'Failed to bulk delete records');
    }
  }

  const confidenceCounts = {
    high: summary.by_confidence.find((x) => x.confidence === 'high')?.count || 0,
    medium: summary.by_confidence.find((x) => x.confidence === 'medium')?.count || 0,
    low: summary.by_confidence.find((x) => x.confidence === 'low')?.count || 0
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

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(120px, 1fr))', gap: 10, marginBottom: 16 }}>
        <div style={{ border: '1px solid #e5e7eb', borderRadius: 10, padding: '10px 12px', background: '#f8fafc' }}>
          <div style={{ fontSize: 12, color: '#64748b' }}>Total</div>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{summary.total}</div>
        </div>
        <div style={{ border: '1px solid #fecaca', borderRadius: 10, padding: '10px 12px', background: '#fff1f2' }}>
          <div style={{ fontSize: 12, color: '#9f1239' }}>High</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#9f1239' }}>{confidenceCounts.high}</div>
        </div>
        <div style={{ border: '1px solid #fde68a', borderRadius: 10, padding: '10px 12px', background: '#fffbeb' }}>
          <div style={{ fontSize: 12, color: '#92400e' }}>Medium</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#92400e' }}>{confidenceCounts.medium}</div>
        </div>
        <div style={{ border: '1px solid #bbf7d0', borderRadius: 10, padding: '10px 12px', background: '#f0fdf4' }}>
          <div style={{ fontSize: 12, color: '#166534' }}>Low</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#166534' }}>{confidenceCounts.low}</div>
        </div>
      </div>

      <div style={{ marginBottom: 14, padding: '10px 12px', border: '1px solid #e5e7eb', borderRadius: 8, background: '#fff' }}>
        <div style={{ fontSize: 13, color: '#475569', marginBottom: 6 }}>Top sources</div>
        <div style={{ marginTop: 6, fontSize: 14 }}>
          {summary.by_source.length ? summary.by_source.slice(0, 6).map((s) => (
            <span key={s.source_name} style={{ marginRight: 12 }}>{s.source_name}: <b>{s.count}</b></span>
          )) : <span style={{ color: '#94a3b8' }}>No data</span>}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8, marginBottom: 8 }}>
        <input
          placeholder="Search IP / subnet (e.g. 1.2.3.0/24) / source / category"
          value={search}
          onChange={(e) => {
            setPage(1);
            setSearch(e.target.value);
          }}
          style={{ gridColumn: 'span 2' }}
        />
        <input
          placeholder="Filter by source"
          value={sourceFilter}
          onChange={(e) => {
            setPage(1);
            setSourceFilter(e.target.value);
          }}
        />
        <input
          placeholder="ASN (e.g. 15169)"
          value={asnFilter}
          onChange={(e) => {
            setPage(1);
            setAsnFilter(e.target.value.replace(/[^0-9]/g, ''));
          }}
        />
        <input
          placeholder="Country (e.g. US)"
          value={countryFilter}
          onChange={(e) => {
            setPage(1);
            setCountryFilter(e.target.value);
          }}
        />
        <select
          value={confidenceFilter}
          onChange={(e) => {
            setPage(1);
            setConfidenceFilter(e.target.value);
          }}
        >
          <option value="">All confidence</option>
          <option value="low">low</option>
          <option value="medium">medium</option>
          <option value="high">high</option>
        </select>
        <select
          value={timeRange}
          onChange={(e) => {
            setPage(1);
            setTimeRange(e.target.value);
          }}
        >
          <option value="today">Today</option>
          <option value="24h">Last 24h</option>
          <option value="7d">Last 7d</option>
          <option value="all">All (may be slower)</option>
        </select>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginBottom: 10 }}>
        <button onClick={() => { setPage(1); loadData(1, pageSize).catch(() => {}); }}>Search</button>
        <button onClick={() => { setSearch(''); setSourceFilter(''); setConfidenceFilter(''); setAsnFilter(''); setCountryFilter(''); setTimeRange('today'); setPage(1); }}>Clear</button>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 10, padding: '10px 12px', border: '1px solid #e5e7eb', borderRadius: 10, background: '#f8fafc' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <label style={{ fontSize: 14, color: '#334155' }}>Page size:</label>
          <select
            value={pageSize}
            onChange={(e) => {
              const nextSize = Number(e.target.value);
              setPageSize(nextSize);
              setPage(1);
            }}
            style={{ padding: '6px 8px', borderRadius: 8, border: '1px solid #cbd5e1', fontWeight: 600 }}
          >
            {[5, 10, 25, 100].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>

          <button onClick={deleteSelected} disabled={!selectedIps.length}>
            Delete selected ({selectedIps.length})
          </button>
        </div>
        <div style={{ fontSize: 15, fontWeight: 600, color: '#0f172a' }}>
          Found <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: 0.2 }}>{pagination.total}</span> IOC(s)
          <span style={{ margin: '0 8px', color: '#94a3b8' }}>|</span>
          Page <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.page}</span> / <span style={{ fontSize: 18, fontWeight: 800 }}>{pagination.total_pages}</span>
        </div>
      </div>

      {rows.length === 0 && (
        <div style={{ marginBottom: 10, padding: 10, background: '#fff8e1', border: '1px solid #ffe0a3', borderRadius: 6 }}>
          No IOC records found for selected time range. Try <b>Last 7d</b> or <b>All</b>.
        </div>
      )}

      <div style={{ overflowX: 'auto', border: '1px solid #e5e7eb', borderRadius: 10 }}>
        <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', background: '#fff', tableLayout: 'fixed', fontSize: 13, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace" }}>
          <colgroup>
            <col style={{ width: 38 }} />
            <col style={{ width: 52 }} />
            <col style={{ width: '19%' }} />
            <col style={{ width: 84 }} />
            <col style={{ width: 72 }} />
            <col style={{ width: '15%' }} />
            <col style={{ width: 110 }} />
            <col style={{ width: '12%' }} />
            <col style={{ width: 170 }} />
            <col style={{ width: 92 }} />
          </colgroup>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
              <th>
                <input type="checkbox" checked={allOnPageSelected} onChange={toggleSelectAllOnPage} />
              </th>
              <th>#</th><th>IP</th><th>ASN</th><th>CC</th><th>Source</th><th>Confidence</th><th>Category</th><th>Timestamp</th><th>Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, idx) => (
              <tr key={r.ip} style={{ borderBottom: '1px solid #f1f5f9' }}>
                <td>
                  <input
                    type="checkbox"
                    checked={selectedIps.includes(r.ip)}
                    onChange={() => toggleRow(r.ip)}
                  />
                </td>
                <td style={{ fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{(pagination.page - 1) * pagination.page_size + idx + 1}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.ip}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontVariantNumeric: 'tabular-nums', fontWeight: 700 }}>{r.asn ?? '-'}</td>
                <td>{r.country_code || '-'}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  <button onClick={() => openSourceDetails(r.ip)} style={{ background: 'transparent', border: 'none', color: '#0f172a', cursor: 'pointer', textDecoration: 'underline', padding: 0, font: 'inherit' }}>
                    {(r.source_names && r.source_names[0]) || '-'}{r.source_count > 1 ? ` +${r.source_count - 1}` : ''}
                  </button>
                </td>
                <td><span style={confidenceBadgeStyle((r.confidence_set && r.confidence_set[0]) || 'low')}>{(r.confidence_set && r.confidence_set[0]) || 'low'}</span></td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{(r.category_set && r.category_set[0]) || '-'}</td>
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontVariantNumeric: 'tabular-nums' }}>{formatUserDateTime(r.last_seen_at)}</td>
                <td>
                  <button onClick={() => deleteOne(r.ip)}>Delete</button>
                </td>
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
        <div style={{ marginTop: 14, border: '1px solid #e2e8f0', borderRadius: 10, padding: 12, background: '#f8fafc' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <b>Sources for {detailIp}</b>
            <button onClick={() => { setDetailIp(''); setDetailSources([]); }}>Close</button>
          </div>
          {detailLoading ? <div>Loading...</div> : (
            <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #cbd5e1' }}>
                  <th>Source</th><th>URL</th><th>Confidence</th><th>Category</th><th>Reported At</th>
                </tr>
              </thead>
              <tbody>
                {detailSources.map((s) => (
                  <tr key={s.id} style={{ borderBottom: '1px solid #e2e8f0' }}>
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

function IOCAddPage() {
  const [submitting, setSubmitting] = useState(false);
  const [recentRows, setRecentRows] = useState([]);
  const iocFormRef = useRef(null);

  async function loadRecent() {
    const res = await api.get('/ioc/ip/recent-raw', { params: { limit: 10 } });
    setRecentRows(res.data?.items || []);
  }

  useEffect(() => {
    loadRecent().catch(() => {});
  }, []);

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
        <input name="ip" placeholder="IP (e.g. 1.2.3.4)" required />
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
        <table width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', minWidth: 760, background: '#fff' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd', background: '#f8fafc' }}>
              <th>#</th><th>IP</th><th>ASN</th><th>Country</th><th>Source</th><th>Confidence</th><th>Timestamp (UTC)</th>
            </tr>
          </thead>
          <tbody>
            {recentRows.map((r, idx) => (
              <tr key={r.id} style={{ borderBottom: '1px solid #f0f0f0' }}>
                <td>{idx + 1}</td>
                <td><code>{r.ip}</code></td>
                <td>{r.asn ?? '-'}</td>
                <td>{r.country_code || '-'}</td>
                <td>{r.source_name}</td>
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
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={<Protected><DashboardPage /></Protected>} />
        <Route path="/ioc" element={<Protected><IOCListPage /></Protected>} />
        <Route path="/ioc/new" element={<Protected><IOCAddPage /></Protected>} />
        <Route path="/settings" element={<Protected><SettingsPage /></Protected>} />
        <Route path="*" element={<Navigate to={isAuthed() ? '/dashboard' : '/login'} replace />} />
      </Routes>
    </BrowserRouter>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
