// Vaultbit server — a single-owner, zero-knowledge vault.
// The server never sees the master password or any decrypted data.
// It stores encrypted blobs and gates access with: password proof + email code.

const SESSION_DAYS = 30;
const CODE_MINUTES = 10;
const MAX_CODE_ATTEMPTS = 5;
const MAX_CHUNK = 1_950_000; // D1 row limit is 2 MB
const ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; frame-src blob:; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) {
      const res = await env.ASSETS.fetch(req);
      const out = new Response(res.body, res);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
      return out;
    }
    try {
      const res = await route(req, env, url);
      res.headers.set('Cache-Control', 'no-store');
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.headers.set(k, v);
      return res;
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e);
      return json({ error: 'Something went wrong on the server.' }, 500);
    }
  },
};

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, msg) => { throw new HttpError(status, msg); };
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
const now = () => Date.now();

async function body(req) {
  try { return await req.json(); } catch { fail(400, 'Bad request.'); }
}

// ---------- crypto helpers ----------
const enc = new TextEncoder();
function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function sha256(s) { return hex(await crypto.subtle.digest('SHA-256', typeof s === 'string' ? enc.encode(s) : s)); }
function randomId(bytes = 24) {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function randomCode() {
  // unbiased 6-digit code
  const a = new Uint32Array(1);
  do { crypto.getRandomValues(a); } while (a[0] >= 4294000000);
  return String(a[0] % 1_000_000).padStart(6, '0');
}
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---------- storage helpers ----------
async function getMeta(env, k) {
  const r = await env.DB.prepare('SELECT v FROM meta WHERE k=?').bind(k).first();
  return r ? r.v : null;
}
const isSetUp = async env => (await getMeta(env, 'auth_hash')) !== null;

async function rateLimit(env, key, limit, windowMs, msg) {
  const t = now();
  const row = await env.DB.prepare('SELECT count, window_start FROM ratelimit WHERE k=?').bind(key).first();
  if (!row || t - row.window_start > windowMs) {
    await env.DB.prepare('INSERT OR REPLACE INTO ratelimit (k,count,window_start) VALUES (?,1,?)').bind(key, t).run();
    return;
  }
  if (row.count >= limit) {
    const mins = Math.ceil((row.window_start + windowMs - t) / 60000);
    fail(429, `${msg} Try again in ${mins} minute${mins === 1 ? '' : 's'}.`);
  }
  await env.DB.prepare('UPDATE ratelimit SET count=count+1 WHERE k=?').bind(key).run();
}
const clientIp = req => req.headers.get('CF-Connecting-IP') || 'local';

// ---------- email ----------
async function sendCode(env, purpose) {
  await rateLimit(env, 'email', 6, 15 * 60_000, 'Too many codes requested.');
  const id = randomId();
  const code = randomCode();
  await env.DB.prepare('DELETE FROM challenges WHERE expires < ?').bind(now()).run();
  await env.DB.prepare('INSERT INTO challenges (id, code_hash, purpose, expires) VALUES (?,?,?,?)')
    .bind(id, await sha256(id + ':' + code), purpose, now() + CODE_MINUTES * 60_000).run();

  if (env.DEV_MODE === '1') {
    console.log(`[DEV] Vaultbit code for ${purpose}: ${code}`);
    return { challenge: id, devCode: code };
  }
  if (!env.RESEND_API_KEY || !env.OWNER_EMAIL) fail(500, 'Email is not configured on the server.');
  const what = purpose === 'setup' ? 'set up your vault' : 'sign in on a new device';
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'Vaultbit <onboarding@resend.dev>',
      to: [env.OWNER_EMAIL],
      subject: `Vaultbit code: ${code}`,
      text: `Your Vaultbit code is ${code}\n\nUse it to ${what}. It expires in ${CODE_MINUTES} minutes.\n\nIf you didn't just try to sign in, someone knows your master password — change it right away in Vaultbit > Settings.`,
    }),
  });
  if (!res.ok) {
    console.error('Resend error', res.status, await res.text());
    fail(502, "Couldn't send the email code. Check the Resend key.");
  }
  return { challenge: id };
}

async function checkCode(env, challenge, code, purpose) {
  if (typeof challenge !== 'string' || typeof code !== 'string') fail(400, 'Bad request.');
  const row = await env.DB.prepare('SELECT * FROM challenges WHERE id=?').bind(challenge).first();
  if (!row || row.purpose !== purpose || row.expires < now()) fail(401, 'That code expired. Request a new one.');
  if (row.attempts >= MAX_CODE_ATTEMPTS) {
    await env.DB.prepare('DELETE FROM challenges WHERE id=?').bind(challenge).run();
    fail(401, 'Too many wrong codes. Request a new one.');
  }
  const ok = safeEqual(await sha256(challenge + ':' + code.trim()), row.code_hash);
  if (!ok) {
    await env.DB.prepare('UPDATE challenges SET attempts=attempts+1 WHERE id=?').bind(challenge).run();
    fail(401, 'Wrong code.');
  }
  await env.DB.prepare('DELETE FROM challenges WHERE id=?').bind(challenge).run();
}

async function newSession(env, device) {
  const token = randomId(32);
  await env.DB.prepare('DELETE FROM sessions WHERE expires < ?').bind(now()).run();
  await env.DB.prepare('INSERT INTO sessions (token_hash, created, expires, device) VALUES (?,?,?,?)')
    .bind(await sha256(token), now(), now() + SESSION_DAYS * 86_400_000, String(device || 'Unknown').slice(0, 80)).run();
  return token;
}

async function requireSession(req, env) {
  const h = req.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) fail(401, 'Please sign in.');
  const row = await env.DB.prepare('SELECT expires FROM sessions WHERE token_hash=?').bind(await sha256(token)).first();
  if (!row || row.expires < now()) fail(401, 'Your session ended. Please sign in again.');
  return await sha256(token);
}

function checkAccountFields(b) {
  const s = v => typeof v === 'string' && v.length > 0 && v.length < 4000;
  if (!s(b.salt) || !s(b.kdf) || !s(b.authKey) || !s(b.wrappedKey)) fail(400, 'Bad request.');
}

// ---------- routes ----------
async function route(req, env, url) {
  const p = url.pathname;
  const m = req.method;

  if (p === '/api/status' && m === 'GET') {
    return json({ setup: await isSetUp(env), salt: await getMeta(env, 'salt'), kdf: await getMeta(env, 'kdf') });
  }

  // First-time setup: needs an email code so nobody else can claim the vault.
  if (p === '/api/setup/start' && m === 'POST') {
    if (await isSetUp(env)) fail(409, 'This vault is already set up.');
    return json(await sendCode(env, 'setup'));
  }
  if (p === '/api/setup/finish' && m === 'POST') {
    if (await isSetUp(env)) fail(409, 'This vault is already set up.');
    const b = await body(req);
    checkAccountFields(b);
    await checkCode(env, b.challenge, b.code, 'setup');
    await env.DB.batch([
      env.DB.prepare('INSERT OR REPLACE INTO meta (k,v) VALUES (?,?)').bind('salt', b.salt),
      env.DB.prepare('INSERT OR REPLACE INTO meta (k,v) VALUES (?,?)').bind('kdf', b.kdf),
      env.DB.prepare('INSERT OR REPLACE INTO meta (k,v) VALUES (?,?)').bind('wrapped_key', b.wrappedKey),
      env.DB.prepare('INSERT OR REPLACE INTO meta (k,v) VALUES (?,?)').bind('auth_hash', await sha256(b.authKey)),
    ]);
    return json({ token: await newSession(env, b.device) });
  }

  // Sign in: step 1 = prove you know the password, step 2 = email code.
  if (p === '/api/login/start' && m === 'POST') {
    if (!(await isSetUp(env))) fail(409, 'Vault is not set up yet.');
    const b = await body(req);
    if (typeof b.authKey !== 'string') fail(400, 'Bad request.');
    await rateLimit(env, 'login:' + clientIp(req), 8, 15 * 60_000, 'Too many sign-in attempts.');
    await rateLimit(env, 'login:all', 30, 60 * 60_000, 'Too many sign-in attempts.');
    const ok = safeEqual(await sha256(b.authKey), await getMeta(env, 'auth_hash'));
    if (!ok) fail(401, 'Wrong master password.');
    return json(await sendCode(env, 'login'));
  }
  if (p === '/api/login/verify' && m === 'POST') {
    const b = await body(req);
    await checkCode(env, b.challenge, b.code, 'login');
    return json({ token: await newSession(env, b.device) });
  }

  // ---- everything below needs a session ----
  const sess = await requireSession(req, env);

  if (p === '/api/vault' && m === 'GET') {
    const { results } = await env.DB.prepare('SELECT id, blob, updated FROM items ORDER BY updated DESC').all();
    return json({ wrappedKey: await getMeta(env, 'wrapped_key'), items: results });
  }

  if (p === '/api/usage' && m === 'GET') {
    const a = await env.DB.prepare('SELECT COALESCE(SUM(LENGTH(data)),0) AS b FROM chunks').first();
    const i = await env.DB.prepare('SELECT COALESCE(SUM(LENGTH(blob)),0) AS b, COUNT(*) AS n FROM items').first();
    return json({ bytes: a.b + i.b, items: i.n, limit: 500 * 1024 * 1024 });
  }

  let mm;
  if ((mm = p.match(/^\/api\/items\/([^/]+)$/))) {
    const id = mm[1];
    if (!ID_RE.test(id)) fail(400, 'Bad id.');
    if (m === 'PUT') {
      const b = await body(req);
      if (typeof b.blob !== 'string' || b.blob.length > MAX_CHUNK) fail(400, 'Entry is too large.');
      await env.DB.prepare('INSERT OR REPLACE INTO items (id, blob, updated) VALUES (?,?,?)').bind(id, b.blob, now()).run();
      return json({ ok: true });
    }
    if (m === 'DELETE') {
      await env.DB.prepare('DELETE FROM items WHERE id=?').bind(id).run();
      return json({ ok: true });
    }
  }

  if ((mm = p.match(/^\/api\/files\/([^/]+)\/(\d{1,5})$/))) {
    const [fid, n] = [mm[1], Number(mm[2])];
    if (!ID_RE.test(fid)) fail(400, 'Bad id.');
    if (m === 'PUT') {
      const data = await req.arrayBuffer();
      if (data.byteLength === 0 || data.byteLength > MAX_CHUNK) fail(400, 'Chunk too large.');
      await env.DB.prepare('INSERT OR REPLACE INTO chunks (fid, n, data) VALUES (?,?,?)').bind(fid, n, data).run();
      return json({ ok: true });
    }
    if (m === 'GET') {
      const row = await env.DB.prepare('SELECT data FROM chunks WHERE fid=? AND n=?').bind(fid, n).first();
      if (!row) fail(404, 'File part missing.');
      return new Response(new Uint8Array(row.data), { headers: { 'Content-Type': 'application/octet-stream' } });
    }
  }
  if ((mm = p.match(/^\/api\/files\/([^/]+)$/)) && m === 'DELETE') {
    if (!ID_RE.test(mm[1])) fail(400, 'Bad id.');
    await env.DB.prepare('DELETE FROM chunks WHERE fid=?').bind(mm[1]).run();
    return json({ ok: true });
  }

  // Change master password: must prove the current one again.
  if (p === '/api/account' && m === 'PUT') {
    const b = await body(req);
    checkAccountFields(b);
    if (typeof b.currentAuthKey !== 'string') fail(400, 'Bad request.');
    await rateLimit(env, 'pwchange', 5, 15 * 60_000, 'Too many attempts.');
    if (!safeEqual(await sha256(b.currentAuthKey), await getMeta(env, 'auth_hash'))) fail(401, 'Current master password is wrong.');
    await env.DB.batch([
      env.DB.prepare('UPDATE meta SET v=? WHERE k=?').bind(b.salt, 'salt'),
      env.DB.prepare('UPDATE meta SET v=? WHERE k=?').bind(b.kdf, 'kdf'),
      env.DB.prepare('UPDATE meta SET v=? WHERE k=?').bind(b.wrappedKey, 'wrapped_key'),
      env.DB.prepare('UPDATE meta SET v=? WHERE k=?').bind(await sha256(b.authKey), 'auth_hash'),
      env.DB.prepare('DELETE FROM sessions WHERE token_hash != ?').bind(sess),
    ]);
    return json({ ok: true });
  }

  if (p === '/api/sessions' && m === 'GET') {
    const { results } = await env.DB.prepare('SELECT token_hash, created, device FROM sessions WHERE expires > ? ORDER BY created DESC').bind(now()).all();
    return json({ sessions: results.map(r => ({ device: r.device, created: r.created, current: r.token_hash === sess })) });
  }
  if (p === '/api/logout' && m === 'POST') {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(sess).run();
    return json({ ok: true });
  }
  if (p === '/api/logout-all' && m === 'POST') {
    await env.DB.prepare('DELETE FROM sessions').run();
    return json({ ok: true });
  }

  fail(404, 'Not found.');
}
