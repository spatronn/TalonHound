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

  const linkStyle = (path) => ({
    padding: '8px 12px',
    borderRadius: 6,
    textDecoration: 'none',
    color: location.pathname === path ? '#fff' : '#111',
    background: location.pathname === path ? '#111' : '#eee'
  });

  return (
    <div style={{ maxWidth: 1100, margin: '24px auto', fontFamily: 'sans-serif' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Link to="/dashboard" style={linkStyle('/dashboard')}>Dashboard</Link>
          <div style={{ display: 'flex', gap: 6, padding: '6px 8px', borderRadius: 6, background: '#f3f3f3' }}>
            <span style={{ fontWeight: 600, marginRight: 6 }}>Operations:</span>
            <Link to="/ioc" style={linkStyle('/ioc')}>IOC List</Link>
            <Link to="/ioc/new" style={linkStyle('/ioc/new')}>Add IOC</Link>
          </div>
        </div>
        <div>
          <span style={{ marginRight: 12 }}>User: <b>{user || 'demo user'}</b></span>
          <button onClick={logout}>Logout</button>
        </div>
      </div>
      {children}
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
  const [summary, setSummary] = useState({ total: 0, by_source: [] });
  const [pageSize, setPageSize] = useState(5);
  const [page, setPage] = useState(1);
  const [pagination, setPagination] = useState({ page: 1, page_size: 5, total: 0, total_pages: 1 });

  async function loadData(targetPage = page, targetSize = pageSize) {
    const [listRes, summaryRes] = await Promise.all([
      api.get('/ioc/ip', { params: { page: targetPage, page_size: targetSize } }),
      api.get('/ioc/summary/today')
    ]);
    setRows(listRes.data.items || []);
    setPagination(listRes.data.pagination || { page: 1, page_size: 5, total: 0, total_pages: 1 });
    setSummary(summaryRes.data);
  }

  useEffect(() => {
    loadData(page, pageSize).catch(() => {});
  }, [page, pageSize]);

  return (
    <AppShell>
      <h2>IOC List</h2>

      <div style={{ marginBottom: 16, padding: 12, border: '1px solid #ddd', borderRadius: 8 }}>
        <b>Total records today:</b> {summary.total}
        <div style={{ marginTop: 6, fontSize: 14 }}>
          {summary.by_source.map((s) => (
            <span key={s.source_name} style={{ marginRight: 12 }}>{s.source_name}: {s.count}</span>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <div>
          <label>Page size: </label>
          <select
            value={pageSize}
            onChange={(e) => {
              const nextSize = Number(e.target.value);
              setPageSize(nextSize);
              setPage(1);
            }}
          >
            {[5, 10, 25, 100].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </div>
        <div style={{ fontSize: 14 }}>
          Total: <b>{pagination.total}</b> | Page: <b>{pagination.page}</b> / <b>{pagination.total_pages}</b>
        </div>
      </div>

      <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd' }}>
            <th>#</th><th>IP</th><th>Source</th><th>Confidence</th><th>Category</th><th>Timestamp (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, idx) => (
            <tr key={r.id} style={{ borderBottom: '1px solid #f0f0f0' }}>
              <td>{(pagination.page - 1) * pagination.page_size + idx + 1}</td>
              <td>{r.ip}</td>
              <td>{r.source_name}</td>
              <td>{r.confidence}</td>
              <td>{r.category || '-'}</td>
              <td>{new Date(r.created_at).toLocaleString('en-GB', { timeZone: 'UTC' })}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
        <button disabled={pagination.page <= 1} onClick={() => setPage((p) => Math.max(p - 1, 1))}>Previous</button>
        <button
          disabled={pagination.page >= pagination.total_pages}
          onClick={() => setPage((p) => Math.min(p + 1, pagination.total_pages))}
        >
          Next
        </button>
      </div>
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
      <h2>Add IOC</h2>
      <form ref={iocFormRef} onSubmit={onSubmit} style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 20 }}>
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
        <button type="submit" disabled={submitting} style={{ gridColumn: '1 / 4', padding: 10, opacity: submitting ? 0.7 : 1 }}>
          {submitting ? 'Saving...' : 'Save IOC'}
        </button>
      </form>

      <h3>Last 10 IOC entries</h3>
      <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd' }}>
            <th>#</th><th>IP</th><th>Source</th><th>Confidence</th><th>Timestamp (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {recentRows.map((r, idx) => (
            <tr key={r.id} style={{ borderBottom: '1px solid #f0f0f0' }}>
              <td>{idx + 1}</td>
              <td>{r.ip}</td>
              <td>{r.source_name}</td>
              <td>{r.confidence}</td>
              <td>{new Date(r.created_at).toLocaleString('en-GB', { timeZone: 'UTC' })}</td>
            </tr>
          ))}
        </tbody>
      </table>
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
