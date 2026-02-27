import React, { useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';

const api = axios.create({ baseURL: '/api' });

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

  function logout() {
    localStorage.removeItem('demo_token');
    localStorage.removeItem('demo_user');
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
    <div style={{ maxWidth: 1240, margin: '24px auto', fontFamily: 'sans-serif', display: 'flex', gap: 20, alignItems: 'flex-start', padding: '0 12px' }}>
      <aside style={{ flex: '0 0 240px', border: '1px solid #e5e5e5', borderRadius: 10, padding: 12, height: 'fit-content', position: 'sticky', top: 16, background: '#fff' }}>
        <div style={{ marginBottom: 14, fontSize: 14 }}>User: <b>{user || 'demo user'}</b></div>

        <nav>
          <Link to="/dashboard" style={menuStyle(isActive('/dashboard'))}>1. Dashboard</Link>

          <div style={{ marginTop: 8 }}>
            <div style={menuStyle(isOpsActive)}>2. Operations</div>
            <Link to="/ioc" style={subMenuStyle(isActive('/ioc'))}>IOC List</Link>
            <Link to="/ioc/new" style={subMenuStyle(isActive('/ioc/new'))}>Add IOC</Link>
          </div>
        </nav>

        <button onClick={logout} style={{ marginTop: 16, width: '100%', padding: 9 }}>Logout</button>
      </aside>

      <main style={{ flex: 1, minWidth: 0 }}>
        {children}
      </main>
    </div>
  );
}

function DashboardPage() {
  return (
    <AppShell>
      <h2>Dashboard</h2>
      <p>Dashboard content will be added in the next phase.</p>
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
                <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontVariantNumeric: 'tabular-nums' }}>{new Date(r.last_seen_at).toLocaleString('en-GB', { timeZone: 'UTC' })}</td>
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
                  <th>Source</th><th>URL</th><th>Confidence</th><th>Category</th><th>Reported At (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {detailSources.map((s) => (
                  <tr key={s.id} style={{ borderBottom: '1px solid #e2e8f0' }}>
                    <td>{s.source_name}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 260 }}>{s.source_url || '-'}</td>
                    <td>{s.confidence || '-'}</td>
                    <td>{s.category || '-'}</td>
                    <td>{new Date(s.created_at).toLocaleString('en-GB', { timeZone: 'UTC', month: 'short' })}</td>
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
    const res = await api.get('/ioc/ip', { params: { page: 1, page_size: 10, day: 'all' } });
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
                <td>{new Date(r.created_at).toLocaleString('en-GB', { timeZone: 'UTC' })}</td>
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
