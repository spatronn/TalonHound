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

// Reason surfaced on the login screen after an involuntary logout. Kept in
// sessionStorage so a full-page redirect can still show a helpful message.
export const SESSION_EXPIRED_STORAGE_KEY = 'talonhound.sessionExpiredReason';

function messageForCode(code) {
  if (code === 'SESSION_EXPIRED_IDLE') {
    return 'Your session expired due to inactivity. Please sign in again.';
  }
  if (code === 'SESSION_EXPIRED_ABSOLUTE') {
    return 'Your session has ended. Please sign in again.';
  }
  return '';
}

function redirectToLogin(code) {
  if (typeof window === 'undefined') return;
  // Only surface a banner for a genuine timeout of an established session — never for a
  // user who was simply never logged in (SESSION_INVALID / missing refresh cookie).
  const msg = messageForCode(code);
  if (msg) {
    try {
      window.sessionStorage.setItem(SESSION_EXPIRED_STORAGE_KEY, msg);
    } catch {
      /* storage may be unavailable; message is best-effort */
    }
  }
  if (window.location.pathname !== '/login') {
    window.location.assign('/login');
  }
}

// Single-flight refresh: a burst of concurrent 401s triggers exactly ONE POST
// /api/auth/refresh; every waiter reuses the same promise, then retries once. This
// prevents a refresh storm and keeps auth state consistent.
let refreshPromise = null;

function runRefresh() {
  if (!refreshPromise) {
    refreshPromise = api
      .post('/auth/refresh', null, { _isRefresh: true })
      .finally(() => {
        refreshPromise = null;
      });
  }
  return refreshPromise;
}

api.interceptors.response.use(
  (res) => res,
  async (err) => {
    const config = err.config || {};
    const url = String(config.url || '');
    const st = err.response?.status;
    const code = err.response?.data?.code;

    if (st === 428 || code === 'INITIAL_SETUP_REQUIRED' || code === 'TIMEZONE_CONFIGURATION_REQUIRED') {
      if (typeof window !== 'undefined' && window.location.pathname !== '/setup') {
        window.location.assign('/setup');
      }
      return Promise.reject(err);
    }
    if (st === 403 && code === 'PASSWORD_CHANGE_REQUIRED') {
      if (typeof window !== 'undefined' && window.location.pathname !== '/change-password') {
        window.location.assign('/change-password');
      }
      return Promise.reject(err);
    }

    // A failed refresh (or a 401 on login itself) is terminal — never loop.
    if (st === 401 && config._isRefresh) {
      redirectToLogin(code);
      return Promise.reject(err);
    }
    if (st === 401 && url.includes('/auth/login')) {
      return Promise.reject(err);
    }

    // Access token likely expired: try one silent refresh, then replay the request.
    if (st === 401 && !config._retried) {
      try {
        await runRefresh();
      } catch {
        // redirect already handled by the refresh's own 401 branch
        return Promise.reject(err);
      }
      config._retried = true;
      return api(config);
    }

    // Any other 401 (e.g. after a failed retry): send to login.
    if (st === 401) {
      redirectToLogin(code);
    }
    return Promise.reject(err);
  }
);
