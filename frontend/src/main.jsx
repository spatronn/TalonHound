import React, { useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes, useNavigate } from 'react-router-dom';
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
      alert('Email veya şifre hatalı');
    }
  }

  return (
    <div style={{ maxWidth: 360, margin: '80px auto', fontFamily: 'sans-serif' }}>
      <h2>Demo Login</h2>
      <form onSubmit={onSubmit}>
        <input name="email" type="email" placeholder="email" required style={{ width: '100%', marginBottom: 8, padding: 8 }} />
        <input name="password" type="password" placeholder="şifre" required style={{ width: '100%', marginBottom: 8, padding: 8 }} />
        <button type="submit" style={{ width: '100%', padding: 10 }}>Giriş Yap</button>
      </form>
      <p style={{ fontSize: 12, color: '#555' }}>Demo kullanıcı: demo@demo.local / Password1!</p>
    </div>
  );
}

function Dashboard() {
  const navigate = useNavigate();
  const user = localStorage.getItem('demo_user');
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState({ total: 0, by_source: [] });
  const [submitting, setSubmitting] = useState(false);
  const iocFormRef = useRef(null);

  async function loadData() {
    const [listRes, summaryRes] = await Promise.all([
      api.get('/ioc/ip'),
      api.get('/ioc/summary/today')
    ]);
    setRows(listRes.data);
    setSummary(summaryRes.data);
  }

  useEffect(() => {
    loadData().catch(() => {});
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
      const res = await api.post('/ioc/ip', payload);
      const data = res?.data;

      formEl?.reset?.();
      if (data?.id) {
        setRows((prev) => [data, ...prev]);
      }
      setSummary((prev) => ({ ...prev, total: (prev.total || 0) + 1 }));

      loadData().catch((refreshErr) => {
        console.warn('Background refresh failed:', refreshErr?.message || refreshErr);
      });

      alert('IOC kaydedildi');
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.response?.data?.message || err?.message || 'Kayıt eklenemedi';
      alert(msg);
      console.error('IOC submit error:', err?.response?.status, err?.response?.data || err?.message);
    } finally {
      setSubmitting(false);
    }
  }

  function logout() {
    localStorage.removeItem('demo_token');
    localStorage.removeItem('demo_user');
    navigate('/login');
  }

  return (
    <div style={{ maxWidth: 1000, margin: '24px auto', fontFamily: 'sans-serif' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2>IOC Dashboard</h2>
        <div>
          <span style={{ marginRight: 12 }}>Kullanıcı: <b>{user || 'demo user'}</b></span>
          <button onClick={logout}>Çıkış</button>
        </div>
      </div>

      <div style={{ marginBottom: 16, padding: 12, border: '1px solid #ddd', borderRadius: 8 }}>
        <b>Bugün toplam kayıt:</b> {summary.total}
        <div style={{ marginTop: 6, fontSize: 14 }}>
          {summary.by_source.map((s) => (
            <span key={s.source_name} style={{ marginRight: 12 }}>{s.source_name}: {s.count}</span>
          ))}
        </div>
      </div>

      <form ref={iocFormRef} onSubmit={onSubmit} style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 20 }}>
        <input name="ip" placeholder="IP (örn 1.2.3.4)" required />
        <input name="source_name" placeholder="Kaynak adı" required />
        <input name="source_url" placeholder="Kaynak linki" />
        <select name="confidence" defaultValue="medium">
          <option value="low">low</option>
          <option value="medium">medium</option>
          <option value="high">high</option>
        </select>
        <input name="category" placeholder="Kategori" />
        <input name="note" placeholder="Not" />
        <button type="submit" disabled={submitting} style={{ gridColumn: '1 / 4', padding: 10, opacity: submitting ? 0.7 : 1 }}>
          {submitting ? 'Kaydediliyor...' : 'IOC Kaydet'}
        </button>
      </form>

      <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd' }}>
            <th>IP</th><th>Kaynak</th><th>Confidence</th><th>Kategori</th><th>Zaman</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} style={{ borderBottom: '1px solid #f0f0f0' }}>
              <td>{r.ip}</td>
              <td>{r.source_name}</td>
              <td>{r.confidence}</td>
              <td>{r.category || '-'}</td>
              <td>{new Date(r.created_at).toLocaleString('tr-TR', { timeZone: 'UTC' })}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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
        <Route path="/dashboard" element={<Protected><Dashboard /></Protected>} />
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
