import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  isForbiddenFeedDestinationIp,
  validateFeedUrlPolicy,
  resolveSafeFeedHost,
  assertSafeFeedDestination,
  isSameFeedOrigin,
  stripUrlUserinfo,
  DEFAULT_MAX_FEED_REDIRECTS
} from './customThreatFeedSsrf.js';
import { fetchFeedUrl } from './customThreatFeedFetch.js';

test('isForbiddenFeedDestinationIp rejects loopback / unspecified / link-local / RFC1918', () => {
  for (const ip of [
    '127.0.0.1',
    '127.255.255.254',
    '0.0.0.0',
    '0.1.2.3',
    '10.0.0.1',
    '10.255.255.255',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.0.1',
    '192.168.255.255',
    '169.254.169.254',
    '169.254.0.1',
    '224.0.0.1',
    '255.255.255.255'
  ]) {
    assert.equal(isForbiddenFeedDestinationIp(ip), true, ip);
  }
  assert.equal(isForbiddenFeedDestinationIp('8.8.8.8'), false);
  assert.equal(isForbiddenFeedDestinationIp('1.1.1.1'), false);
});

test('isForbiddenFeedDestinationIp rejects IPv6 ULA / link-local / loopback / unspecified', () => {
  for (const ip of ['::1', '::', 'fe80::1', 'FE80::abcd', 'fc00::1', 'fd12:3456::1', 'ff02::1']) {
    assert.equal(isForbiddenFeedDestinationIp(ip), true, ip);
  }
  assert.equal(isForbiddenFeedDestinationIp('2001:4860:4860::8888'), false);
});

test('isForbiddenFeedDestinationIp rejects IPv4-mapped IPv6 to forbidden IPv4 only', () => {
  for (const ip of [
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::ffff:10.0.0.1',
    '::ffff:a00:1',
    '::ffff:169.254.169.254',
    '::ffff:a9fe:a9fe',
    '::ffff:192.168.1.1',
    '::ffff:c0a8:101'
  ]) {
    assert.equal(isForbiddenFeedDestinationIp(ip), true, ip);
  }
  assert.equal(isForbiddenFeedDestinationIp('::ffff:8.8.8.8'), false);
  assert.equal(isForbiddenFeedDestinationIp('::ffff:808:808'), false);
});

test('validateFeedUrlPolicy allows only http/https and rejects private literals', () => {
  assert.equal(validateFeedUrlPolicy('file:///etc/passwd').ok, false);
  assert.equal(validateFeedUrlPolicy('ftp://ti.example.com/feed.txt').ok, false);
  assert.equal(validateFeedUrlPolicy('gopher://ti.example.com/').ok, false);
  assert.equal(validateFeedUrlPolicy('http://127.0.0.1/feed.txt').ok, false);
  assert.equal(validateFeedUrlPolicy('http://[::1]/feed.txt').ok, false);
  assert.equal(validateFeedUrlPolicy('http://[::ffff:127.0.0.1]/feed.txt').ok, false);
  assert.equal(validateFeedUrlPolicy('http://[::ffff:169.254.169.254]/').ok, false);
  assert.equal(validateFeedUrlPolicy('http://192.168.1.1/feed.txt').ok, false);
  assert.equal(validateFeedUrlPolicy('http://169.254.169.254/latest/meta-data/').ok, false);
  assert.equal(validateFeedUrlPolicy('http://localhost/feed.txt').ok, false);
  assert.equal(validateFeedUrlPolicy('http://feed.localhost/feed.txt').ok, false);
  assert.equal(validateFeedUrlPolicy('http://printer.local/feed.txt').ok, false);
  assert.equal(validateFeedUrlPolicy('https://ti.example.com/feed.txt').ok, true);
  assert.equal(validateFeedUrlPolicy('http://1.1.1.1/feed.txt').ok, true);
  assert.equal(validateFeedUrlPolicy('http://[::ffff:8.8.8.8]/feed.txt').ok, true);
});

test('resolveSafeFeedHost rejects when any resolved address is forbidden', async () => {
  await assert.rejects(
    () => resolveSafeFeedHost('evil.example', {
      lookup: async () => [
        { address: '8.8.8.8', family: 4 },
        { address: '10.0.0.1', family: 4 }
      ]
    }),
    (err) => err.code === 'destination_blocked'
  );
});

test('resolveSafeFeedHost accepts host when every address is public', async () => {
  const addrs = await resolveSafeFeedHost('ti.example.com', {
    lookup: async () => [
      { address: '8.8.8.8', family: 4 },
      { address: '2001:4860:4860::8888', family: 6 }
    ]
  });
  assert.equal(addrs.length, 2);
});

test('assertSafeFeedDestination uses shared policy before DNS', async () => {
  await assert.rejects(
    () => assertSafeFeedDestination('file:///tmp/x'),
    (err) => err.code === 'invalid_url'
  );
  await assert.rejects(
    () => assertSafeFeedDestination('http://127.0.0.1/'),
    (err) => err.code === 'invalid_url' || err.code === 'destination_blocked'
  );
});

test('isSameFeedOrigin and stripUrlUserinfo helpers', () => {
  const a = new URL('https://ti.example.com/a');
  const b = new URL('https://ti.example.com/b');
  const c = new URL('https://other.example.com/a');
  assert.equal(isSameFeedOrigin(a, b), true);
  assert.equal(isSameFeedOrigin(a, c), false);
  const withCreds = stripUrlUserinfo(new URL('https://user:secret@ti.example.com/path'));
  assert.equal(withCreds.username, '');
  assert.equal(withCreds.password, '');
  assert.equal(DEFAULT_MAX_FEED_REDIRECTS, 5);
});

function listen(server) {
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve(port);
    });
    server.on('error', reject);
  });
}

function close(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

test('fetchFeedUrl serves body via pinned local hop when policy overridden for test', async () => {
  const seenHosts = [];
  const server = http.createServer((req, res) => {
    seenHosts.push(req.headers.host);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('evil.com\n');
  });
  const port = await listen(server);
  try {
    const result = await fetchFeedUrl(`http://ti.example.com:${port}/feed.txt`, {
      lookup: async () => [{ address: '127.0.0.1', family: 4 }],
      // Local loopback server only — production policy remains deny-by-default.
      isForbiddenAddress: () => false,
      timeoutMs: 5000,
      maxBytes: 1024
    });
    assert.equal(result.ok, true);
    assert.equal(result.httpStatus, 200);
    assert.match(result.bodyText, /evil\.com/);
    assert.ok(seenHosts[0].startsWith('ti.example.com'));
  } finally {
    await close(server);
  }
});

test('fetchFeedUrl rejects DNS resolution to private address before connect', async () => {
  let connected = false;
  const server = http.createServer((_req, res) => {
    connected = true;
    res.end('should-not-reach');
  });
  const port = await listen(server);
  try {
    await assert.rejects(
      () => fetchFeedUrl(`http://rebinding.example:${port}/feed.txt`, {
        lookup: async () => [{ address: '169.254.169.254', family: 4 }],
        timeoutMs: 5000
      }),
      (err) => err.code === 'destination_blocked'
    );
    assert.equal(connected, false);
  } finally {
    await close(server);
  }
});

test('fetchFeedUrl validates every redirect hop and refuses private Location', async () => {
  let secondHit = false;
  const server = http.createServer((req, res) => {
    if (req.url === '/start') {
      res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
      res.end();
      return;
    }
    secondHit = true;
    res.end('nope');
  });
  const port = await listen(server);
  try {
    await assert.rejects(
      () => fetchFeedUrl(`http://ti.example.com:${port}/start`, {
        lookup: async (hostname) => {
          if (hostname === 'ti.example.com') return [{ address: '127.0.0.1', family: 4 }];
          return [{ address: '8.8.8.8', family: 4 }];
        },
        isForbiddenAddress: (address) => address !== '127.0.0.1',
        timeoutMs: 5000
      }),
      (err) => err.code === 'redirect_blocked' || err.code === 'destination_blocked' || err.code === 'invalid_url'
    );
    assert.equal(secondHit, false);
  } finally {
    await close(server);
  }
});

test('fetchFeedUrl does not forward Authorization on cross-origin redirect', async () => {
  const authSeen = [];
  const serverA = http.createServer((req, res) => {
    authSeen.push({ hop: 'a', authorization: req.headers.authorization || null });
    res.writeHead(302, { Location: `http://other.example:${portB}/final` });
    res.end();
  });
  let portB;
  const serverB = http.createServer((req, res) => {
    authSeen.push({ hop: 'b', authorization: req.headers.authorization || null });
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok\n');
  });
  const portA = await listen(serverA);
  portB = await listen(serverB);
  try {
    const result = await fetchFeedUrl(`http://first.example:${portA}/start`, {
      credentials: { auth_type: 'bearer_token', token: 'super-secret-token' },
      lookup: async (hostname) => {
        if (hostname === 'first.example') return [{ address: '127.0.0.1', family: 4 }];
        if (hostname === 'other.example') return [{ address: '127.0.0.1', family: 4 }];
        return [{ address: '8.8.8.8', family: 4 }];
      },
      isForbiddenAddress: () => false,
      timeoutMs: 5000
    });
    assert.equal(result.ok, true);
    assert.equal(authSeen[0].authorization, 'Bearer super-secret-token');
    assert.equal(authSeen[1].authorization, null);
  } finally {
    await close(serverA);
    await close(serverB);
  }
});

test('fetchFeedUrl keeps Authorization on same-origin redirect', async () => {
  const authSeen = [];
  const server = http.createServer((req, res) => {
    authSeen.push({ path: req.url, authorization: req.headers.authorization || null });
    if (req.url === '/start') {
      res.writeHead(302, { Location: '/final' });
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('same-origin\n');
  });
  const port = await listen(server);
  try {
    const result = await fetchFeedUrl(`http://ti.example.com:${port}/start`, {
      credentials: { auth_type: 'bearer_token', token: 'keep-me' },
      lookup: async () => [{ address: '127.0.0.1', family: 4 }],
      isForbiddenAddress: () => false,
      timeoutMs: 5000
    });
    assert.equal(result.ok, true);
    assert.equal(authSeen.length, 2);
    assert.equal(authSeen[0].authorization, 'Bearer keep-me');
    assert.equal(authSeen[1].authorization, 'Bearer keep-me');
  } finally {
    await close(server);
  }
});

test('fetchFeedUrl enforces redirect bound', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(302, { Location: '/next' });
    res.end();
  });
  const port = await listen(server);
  try {
    await assert.rejects(
      () => fetchFeedUrl(`http://ti.example.com:${port}/start`, {
        lookup: async () => [{ address: '127.0.0.1', family: 4 }],
        isForbiddenAddress: () => false,
        maxRedirects: 2,
        timeoutMs: 5000
      }),
      (err) => err.code === 'redirect_limit'
    );
  } finally {
    await close(server);
  }
});

test('fetchFeedUrl enforces maxBytes', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('x'.repeat(2048));
  });
  const port = await listen(server);
  try {
    await assert.rejects(
      () => fetchFeedUrl(`http://ti.example.com:${port}/big`, {
        lookup: async () => [{ address: '127.0.0.1', family: 4 }],
        isForbiddenAddress: () => false,
        maxBytes: 1024,
        timeoutMs: 5000
      }),
      (err) => err.code === 'response_too_large'
    );
  } finally {
    await close(server);
  }
});
