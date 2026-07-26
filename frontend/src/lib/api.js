import axios from 'axios';

const CSRF_COOKIE_NAME = 'demo_csrf';

function readCookie(name) {
  const parts = `; ${document.cookie}`.split(`; ${name}=`);
  if (parts.length === 2) return decodeURIComponent(parts.pop().split(';').shift() || '');
  return '';
}

export const api = axios.create({ baseURL: '/api', withCredentials: true });

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
    const code = err.response?.data?.code;
    if (st === 428 || code === 'INITIAL_SETUP_REQUIRED' || code === 'TIMEZONE_CONFIGURATION_REQUIRED') {
      if (typeof window !== 'undefined' && window.location.pathname !== '/setup') {
        window.location.assign('/setup');
      }
      return Promise.reject(err);
    }
    if (st === 401 && !url.includes('/auth/login')) {
      if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
        window.location.assign('/login');
      }
    }
    return Promise.reject(err);
  }
);
