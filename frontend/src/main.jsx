import React from 'react';
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

  function logout() {
    localStorage.removeItem('demo_token');
    localStorage.removeItem('demo_user');
    navigate('/login');
  }

  return (
    <div style={{ maxWidth: 600, margin: '80px auto', fontFamily: 'sans-serif' }}>
      <h2>Dashboard</h2>
      <p>Hoş geldin: <b>{user || 'demo user'}</b></p>
      <button onClick={logout}>Çıkış</button>
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
