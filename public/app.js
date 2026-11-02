// Vaultbit app — everything is encrypted and decrypted here, on your device.
// Master password -> Argon2id -> HKDF -> (encryption key, login proof).
// A random vault key encrypts every entry and file; it is stored wrapped by the encryption key.

const KDF = { alg: 'argon2id', m: 65536, t: 3, p: 1, v: 1 }; // 64 MiB, 3 passes
const CHUNK = 1_500_000;          // plaintext bytes per file part
const MAX_FILE = 100 * 1024 * 1024;
const IDLE_LOCK_MS = 5 * 60_000;  // lock after 5 min of no activity
const HIDDEN_LOCK_MS = 2 * 60_000; // lock if the app was in the background 2+ min
const CLIP_CLEAR_MS = 30_000;

const TYPES = {
  login: { icon: '🔑', name: 'Login', fields: [['Username', false], ['Email', false], ['Password', true], ['Website', false]] },
  wifi:  { icon: '📶', name: 'WiFi', fields: [['Network name', false], ['Password', true]] },
  code:  { icon: '🔢', name: 'Codes / PIN', fields: [['Code', true]] },
  note:  { icon: '📝', name: 'Secure note', fields: [] },
  file:  { icon: '📁', name: 'Files', fields: [] },
  custom:{ icon: '🗂️', name: 'Custom', fields: [['Field', false]] },
};

const S = { token: null, vk: null, items: [], filter: 'all', q: '', lastActive: Date.now(), hiddenAt: 0 };
try { S.token = localStorage.getItem('vb_token'); } catch {}

// ---------------- small helpers ----------------
const $ = s => document.querySelector(s);
const te = new TextEncoder(), td = new TextDecoder();
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c.nodeType ? c : String(c));
  return el;
}
function mount(...nodes) { const a = $('#app'); a.replaceChildren(...nodes); }
let toastT;
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 2600);
}
const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const newId = () => b64(rand(18)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}
function deviceName() {
  const ua = navigator.userAgent;
  const os = /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /iPhone|iPad/.test(ua) ? 'iPhone/iPad' : /Mac/.test(ua) ? 'Mac' : /Linux/.test(ua) ? 'Linux' : 'Device';
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  return `${br} on ${os}`;
}

// ---------------- API ----------------
async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (S.token) headers.Authorization = 'Bearer ' + S.token;
  let body = opts.body;
  if (body && !(body instanceof Uint8Array) && !(body instanceof ArrayBuffer)) {
    headers['Content-Type'] = 'application/json'; body = JSON.stringify(body);
  }
  let res;
  try { res = await fetch(path, { method: opts.method || 'GET', headers, body }); }
  catch { throw new Error("Can't reach the server. Check your internet connection."); }
  if (opts.raw && res.ok) return new Uint8Array(await res.arrayBuffer());
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && S.token && !opts.noAuthReset && !path.startsWith('/api/login')) {
    setToken(null); lock(); throw new Error(data.error || 'Please sign in again.');
  }
  if (!res.ok) throw new Error(data.error || 'Request failed.');
  return data;
}
function setToken(t) {
  S.token = t;
  try { t ? localStorage.setItem('vb_token', t) : localStorage.removeItem('vb_token'); } catch {}
  if (!t) bioClear(); // signing out of a device also removes its fingerprint unlock
}

// ---------------- fingerprint unlock ----------------
// Uses a passkey with the PRF extension: the phone's secure hardware returns a secret only after
// your fingerprint. That secret encrypts a copy of the vault key kept on THIS device only.
// The server never sees it, and it's useless without your finger on this exact device.
const BIO_KEY = 'vb_bio';
function bioGet() { try { return JSON.parse(localStorage.getItem(BIO_KEY) || 'null'); } catch { return null; } }
function bioClear() { try { localStorage.removeItem(BIO_KEY); } catch {} }
const bioCapable = async () => !!(window.PublicKeyCredential && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false));

async function prfKey(prfOut) {
  const base = await crypto.subtle.importKey('raw', prfOut, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode('vaultbit-bio') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function bioAssert(credId, prfSalt) {
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey: {
      challenge: rand(32), rpId: location.hostname, userVerification: 'required', timeout: 60000,
      allowCredentials: [{ type: 'public-key', id: unb64(credId) }],
      extensions: { prf: { eval: { first: unb64(prfSalt) } } },
    } });
  } catch (e) { throw new Error(e.name === 'NotAllowedError' ? 'Fingerprint cancelled.' : 'Fingerprint failed: ' + e.message); }
  const out = cred && cred.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error("This device doesn't support fingerprint unlock for Vaultbit.");
  return new Uint8Array(out);
}

async function bioEnable(masterPassword) {
  if (!(await bioCapable())) throw new Error('No fingerprint or screen lock is set up on this device.');
  // re-check the master password and get the raw vault key to protect
  const st = await api('/api/status');
  const { kek } = await deriveKeys(masterPassword, st.salt, JSON.parse(st.kdf));
  const v = await api('/api/vault');
  const raw = await open_(kek, unb64(v.wrappedKey), 'vaultbit-vk').catch(() => { throw new Error('Wrong master password.'); });
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: {
      challenge: rand(32),
      rp: { id: location.hostname, name: 'Vaultbit' },
      user: { id: rand(16), name: 'vaultbit-' + deviceName().replace(/\s+/g, '-').toLowerCase(), displayName: 'Vaultbit unlock (' + deviceName() + ')' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required' },
      timeout: 60000, extensions: { prf: {} },
    } });
  } catch (e) { raw.fill(0); throw new Error(e.name === 'NotAllowedError' ? 'Fingerprint setup cancelled.' : 'Fingerprint setup failed: ' + e.message); }
  if (!cred.getClientExtensionResults().prf?.enabled) { raw.fill(0); throw new Error("This device doesn't support fingerprint unlock for Vaultbit (needs Chrome on Android, Windows Hello, or similar)."); }
  const credId = b64(new Uint8Array(cred.rawId));
  const prfSalt = b64(rand(32));
  const key = await prfKey(await bioAssert(credId, prfSalt)); // touch #2: proves it works before saving
  const wrapped = b64(await seal(key, raw, 'vaultbit-bio-vk')); raw.fill(0);
  localStorage.setItem(BIO_KEY, JSON.stringify({ credId, prfSalt, wrapped }));
}

async function bioUnlock() {
  const b = bioGet(); if (!b) throw new Error('Fingerprint unlock is not set up on this device.');
  const key = await prfKey(await bioAssert(b.credId, b.prfSalt));
  const raw = await open_(key, unb64(b.wrapped), 'vaultbit-bio-vk').catch(() => { throw new Error('Fingerprint unlock stopped working — use your master password and set it up again in Settings.'); });
  const vk = await importVK(raw); raw.fill(0); return vk;
}

// ---------------- crypto ----------------
async function deriveKeys(password, saltB64, kdf) {
  const master = await hashwasm.argon2id({
    password: password.normalize('NFKC'), salt: unb64(saltB64),
    parallelism: kdf.p, iterations: kdf.t, memorySize: kdf.m, hashLength: 32, outputType: 'binary',
  });
  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits', 'deriveKey']);
  master.fill(0);
  const hk = info => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode(info) });
  const kek = await crypto.subtle.deriveKey(hk('vaultbit-enc'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const auth = new Uint8Array(await crypto.subtle.deriveBits(hk('vaultbit-auth'), base, 256));
  return { kek, authKey: b64(auth) };
}
async function seal(key, bytes, aad) {
  const iv = rand(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad) }, key, bytes));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out;
}
async function open_(key, data, aad) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.subarray(0, 12), additionalData: te.encode(aad) }, key, data.subarray(12)));
}
const importVK = raw => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
async function unwrapVK(kek, wrapped) {
  const raw = await open_(kek, unb64(wrapped), 'vaultbit-vk');
  const k = await importVK(raw); raw.fill(0); return k;
}
const encItem = async (id, obj) => b64(await seal(S.vk, te.encode(JSON.stringify(obj)), 'item:' + id));
const decItem = async (id, blob) => JSON.parse(td.decode(await open_(S.vk, unb64(blob), 'item:' + id)));

function genPassword(len = 20) {
  const cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_=+?';
  const out = []; const buf = new Uint32Array(1);
  const lim = Math.floor(2 ** 32 / cs.length) * cs.length;
  while (out.length < len) { crypto.getRandomValues(buf); if (buf[0] < lim) out.push(cs[buf[0] % cs.length]); }
  return out.join('');
}
function strength(pw) {
  let s = 0;
  if (pw.length >= 12) s++; if (pw.length >= 16) s++; if (pw.length >= 22) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++; if (/\d/.test(pw)) s++; if (/[^A-Za-z0-9]/.test(pw) || / /.test(pw)) s++;
  return Math.min(4, Math.floor(s * 4 / 6));
}

// ---------------- screens: setup / sign in / unlock ----------------
function brand() { return h('div', { class: 'brand' }, h('img', { src: '/icon.svg', alt: '' }), 'Vaultbit'); }
function busy(btn, on, label) { btn.disabled = on; if (label) btn.textContent = label; }

async function start() {
  let st;
  try { st = await api('/api/status'); }
  catch (e) { mount(h('div', { class: 'auth' }, brand(), h('h1', {}, 'Offline'), h('p', {}, e.message), h('button', { class: 'btn wide', onclick: start }, 'Try again'))); return; }
  S.status = st;
  if (!st.setup) return setupScreen();
  if (S.token) return unlockScreen();
  return loginScreen();
}

function setupScreen() {
  const err = h('div', { class: 'err' });
  const send = h('button', { class: 'btn primary wide', onclick: async () => {
    busy(send, true, 'Sending…'); err.textContent = '';
    try { const r = await api('/api/setup/start', { method: 'POST' }); setupStep2(r); }
    catch (e) { err.textContent = e.message; busy(send, false, 'Send me a code'); }
  } }, 'Send me a code');
  mount(h('div', { class: 'auth' }, brand(),
    h('h1', {}, 'Set up your vault'),
    h('p', {}, "First, we'll email a code to your inbox to prove it's you."), send, err));
}

function passwordPair(onEnter) {
  const p1 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Long passphrase, e.g. 4–5 random words' });
  const p2 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Type it again' });
  const bar = h('i'); const meter = h('div', { class: 'meter' }, bar);
  const words = ['Too weak', 'Weak', 'Okay', 'Good', 'Strong'];
  const note = h('div', { class: 'hint' }, 'At least 12 characters.');
  p1.addEventListener('input', () => {
    const s = strength(p1.value);
    bar.style.width = (p1.value ? (s + 1) * 20 : 0) + '%';
    bar.style.background = s >= 3 ? 'var(--accent)' : s === 2 ? '#f59e0b' : 'var(--danger)';
    note.textContent = p1.value ? words[s] : 'At least 12 characters.';
  });
  p2.addEventListener('keydown', e => { if (e.key === 'Enter') onEnter(); });
  return { p1, p2, nodes: [h('label', {}, 'Master password'), p1, meter, note, h('label', {}, 'Confirm master password'), p2] };
}
function checkNewPassword(p1, p2) {
  if (p1.value.length < 12) return 'Use at least 12 characters.';
  if (strength(p1.value) < 2) return 'Make it stronger — a longer passphrase is easiest.';
  if (p1.value !== p2.value) return "The two passwords don't match.";
  return '';
}

function setupStep2(r) {
  const err = h('div', { class: 'err' });
  const code = h('input', { class: 'code-input mono', inputmode: 'numeric', maxlength: 6, autocomplete: 'one-time-code', placeholder: '••••••' });
  const go = h('button', { class: 'btn primary wide', onclick: () => finish() }, 'Create vault');
  const pw = passwordPair(() => finish());
  if (r.devCode) code.value = r.devCode;
  async function finish() {
    err.textContent = '';
    const bad = checkNewPassword(pw.p1, pw.p2); if (bad) { err.textContent = bad; return; }
    if (!/^\d{6}$/.test(code.value.trim())) { err.textContent = 'Enter the 6-digit code from your email.'; return; }
    busy(go, true, 'Creating… (this takes a few seconds)');
    try {
      const salt = b64(rand(16));
      const { kek, authKey } = await deriveKeys(pw.p1.value, salt, KDF);
      const raw = rand(32);
      const wrappedKey = b64(await seal(kek, raw, 'vaultbit-vk'));
      S.vk = await importVK(raw); raw.fill(0);
      const res = await api('/api/setup/finish', { method: 'POST', body: { challenge: r.challenge, code: code.value.trim(), salt, kdf: JSON.stringify(KDF), authKey, wrappedKey, device: deviceName() } });
      setToken(res.token); S.items = []; S.status = await api('/api/status'); toast('Vault created');
      mainScreen();
    } catch (e) { err.textContent = e.message; busy(go, false, 'Create vault'); }
  }
  mount(h('div', { class: 'auth' }, brand(),
    h('h1', {}, 'Check your email'),
    h('p', {}, 'Enter the code we sent, then choose your master password.'),
    h('label', {}, 'Email code'), code, ...pw.nodes,
    h('div', { class: 'hint' }, "⚠️ Nobody can reset this password — not even you. If you forget it, the vault can't be opened. Write it down once and keep the paper somewhere safe."),
    go, err));
}

function loginScreen() {
  const err = h('div', { class: 'err' });
  const pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Master password' });
  const go = h('button', { class: 'btn primary wide', onclick: () => next() }, 'Continue');
  pw.addEventListener('keydown', e => { if (e.key === 'Enter') next(); });
  async function next() {
    err.textContent = ''; if (!pw.value) return;
    busy(go, true, 'Checking…');
    try {
      const st = S.status;
      const { kek, authKey } = await deriveKeys(pw.value, st.salt, JSON.parse(st.kdf));
      const r = await api('/api/login/start', { method: 'POST', body: { authKey } });
      loginCode(r, kek);
    } catch (e) { err.textContent = e.message; busy(go, false, 'Continue'); }
  }
  mount(h('div', { class: 'auth' }, brand(), h('h1', {}, 'Sign in'),
    h('p', {}, 'New device or signed out — enter your master password, then the code from your email.'),
    h('label', {}, 'Master password'), pw, go, err));
  pw.focus();
}

function loginCode(r, kek) {
  const err = h('div', { class: 'err' });
  const code = h('input', { class: 'code-input mono', inputmode: 'numeric', maxlength: 6, autocomplete: 'one-time-code', placeholder: '••••••' });
  const go = h('button', { class: 'btn primary wide', onclick: () => verify() }, 'Sign in');
  if (r.devCode) code.value = r.devCode;
  code.addEventListener('keydown', e => { if (e.key === 'Enter') verify(); });
  async function verify() {
    err.textContent = '';
    busy(go, true, 'Signing in…');
    try {
      const res = await api('/api/login/verify', { method: 'POST', body: { challenge: r.challenge, code: code.value.trim(), device: deviceName() } });
      setToken(res.token);
      await loadVault(kek);
      mainScreen();
    } catch (e) { err.textContent = e.message; busy(go, false, 'Sign in'); }
  }
  mount(h('div', { class: 'auth' }, brand(), h('h1', {}, 'Check your email'),
    h('p', {}, 'We sent a 6-digit code to your inbox. It expires in 10 minutes.'),
    h('label', {}, 'Email code'), code, go, err,
    h('button', { class: 'btn ghost small', onclick: loginScreen }, '← Back')));
  code.focus();
}

function unlockScreen(msg) {
  const err = h('div', { class: 'err' }, msg || '');
  const pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Master password' });
  const go = h('button', { class: 'btn primary wide', onclick: () => unlock() }, 'Unlock');
  pw.addEventListener('keydown', e => { if (e.key === 'Enter') unlock(); });
  async function unlock() {
    err.textContent = ''; if (!pw.value) return;
    busy(go, true, 'Unlocking…');
    try {
      const st = S.status || await api('/api/status');
      const { kek } = await deriveKeys(pw.value, st.salt, JSON.parse(st.kdf));
      await loadVault(kek);
      mainScreen();
    } catch (e) {
      if (!S.token) return loginScreen();
      err.textContent = e.name === 'OperationError' ? 'Wrong master password.' : e.message;
      busy(go, false, 'Unlock');
    }
  }
  const bio = bioGet();
  const fp = bio ? h('button', { class: 'btn primary wide', onclick: async () => {
    err.textContent = ''; busy(fp, true, 'Waiting for fingerprint…');
    try { await loadVault(null, await bioUnlock()); mainScreen(); }
    catch (e) {
      if (!S.token) return loginScreen();
      err.textContent = e.message; busy(fp, false, '👆 Unlock with fingerprint');
    }
  } }, '👆 Unlock with fingerprint') : null;
  mount(h('div', { class: 'auth' }, brand(), h('h1', {}, 'Vault locked'),
    fp, bio ? h('p', { class: 'hint center' }, 'or use your master password') : null,
    h('label', {}, 'Master password'), pw, bio ? h('button', { class: 'btn wide', onclick: () => unlock() }, 'Unlock') : go, err,
    h('button', { class: 'btn ghost small', onclick: async () => { try { await api('/api/logout', { method: 'POST' }); } catch {} setToken(null); loginScreen(); } }, 'Sign out of this device')));
  if (!bio) pw.focus();
}

async function loadVault(kek, vkDirect) {
  const v = await api('/api/vault');
  S.vk = vkDirect || await unwrapVK(kek, v.wrappedKey); // throws OperationError if password is wrong
  const items = [];
  for (const r of v.items) {
    try { items.push({ id: r.id, updated: r.updated, ...(await decItem(r.id, r.blob)) }); }
    catch { console.warn('Could not decrypt entry', r.id); }
  }
  S.items = items;
  S.lastActive = Date.now();
}

function lock() {
  S.vk = null; S.items = [];
  closeViewer(); closeSheet();
  S.token ? unlockScreen() : loginScreen();
}

// ---------------- main vault screen ----------------
function mainScreen() {
  const search = h('input', { type: 'search', placeholder: 'Search your vault', value: S.q, oninput: e => { S.q = e.target.value; renderList(); } });
  const filters = [['all', 'All'], ['fav', '★ Favorites'], ...Object.entries(TYPES).map(([k, t]) => [k, t.icon + ' ' + t.name])];
  const chips = h('div', { class: 'chips' }, filters.map(([k, label]) =>
    h('button', { class: 'chip' + (S.filter === k ? ' on' : ''), onclick: () => { S.filter = k; mainScreen(); } }, label)));
  mount(
    h('header', { class: 'top' },
      h('div', { class: 'top-row' }, brand(),
        h('button', { class: 'btn iconbtn ghost', title: 'Settings', 'aria-label': 'Settings', onclick: settingsSheet }, '⚙️'),
        h('button', { class: 'btn small', onclick: lock }, '🔒 Lock')),
      h('div', { class: 'search' }, search), chips),
    h('section', { class: 'list', id: 'list' }),
    h('button', { class: 'btn primary fab', onclick: newSheet }, '+ New'));
  renderList();
}

function subtitle(it) {
  const f = (it.fields || []).find(f => !f.secret && f.value);
  if (f) return f.value;
  if (it.files && it.files.length) return it.files.map(x => x.name).join(', ');
  if (it.notes) return it.notes.split('\n')[0];
  return TYPES[it.type]?.name || '';
}

function renderList() {
  const list = $('#list'); if (!list) return;
  const q = S.q.trim().toLowerCase();
  let items = S.items.filter(it =>
    (S.filter === 'all' || (S.filter === 'fav' ? it.fav : it.type === S.filter)) &&
    (!q || [it.title, it.notes, ...(it.fields || []).filter(f => !f.secret).map(f => f.label + ' ' + f.value), ...(it.files || []).map(f => f.name)]
      .join(' ').toLowerCase().includes(q)));
  items.sort((a, b) => (b.fav ? 1 : 0) - (a.fav ? 1 : 0) || (a.title || '').localeCompare(b.title || ''));
  if (!items.length) {
    list.replaceChildren(h('div', { class: 'empty' }, S.items.length ? 'Nothing matches.' : 'Your vault is empty. Tap “+ New” to add your first entry.'));
    return;
  }
  list.replaceChildren(...items.map(it => h('button', { class: 'row', onclick: () => viewSheet(it) },
    h('div', { class: 'ricon' }, TYPES[it.type]?.icon || '🗂️'),
    h('div', { class: 'rtext' }, h('div', { class: 'rtitle' }, (it.fav ? '★ ' : '') + (it.title || 'Untitled')), h('div', { class: 'rsub' }, subtitle(it))),
    it.files && it.files.length ? h('span', { class: 'badge' }, '📎 ' + it.files.length) : null)));
}

// ---------------- sheets ----------------
function sheet(...kids) {
  closeSheet();
  const ov = h('div', { class: 'overlay', id: 'overlay', onclick: e => { if (e.target === ov) closeSheet(); } }, h('div', { class: 'sheet' }, ...kids));
  document.body.append(ov);
  document.body.style.overflow = 'hidden';
  return ov;
}
function closeSheet() {
  const o = $('#overlay'); if (o) { o.querySelectorAll('img[src^="blob:"]').forEach(i => URL.revokeObjectURL(i.src)); o.remove(); }
  document.body.style.overflow = '';
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeSheet(); });

let clipT;
async function copy(text, what = 'Copied') {
  try { await navigator.clipboard.writeText(text); } catch { toast("Couldn't copy"); return; }
  toast(what + ' — clears in 30s');
  clearTimeout(clipT);
  clipT = setTimeout(() => { if (document.hasFocus()) navigator.clipboard.writeText('').catch(() => {}); }, CLIP_CLEAR_MS);
}

function newSheet() {
  sheet(h('div', { class: 'sheet-head' }, h('h2', {}, 'New entry'), h('button', { class: 'btn ghost iconbtn', onclick: closeSheet, 'aria-label': 'Close' }, '✕')),
    h('p', { class: 'hint' }, 'Pick a starting point. You can add or remove any fields after.'),
    h('div', { class: 'typepick' }, Object.entries(TYPES).map(([k, t]) =>
      h('button', { onclick: () => editSheet({ type: k, title: '', fields: t.fields.map(([label, secret]) => ({ label, value: '', secret })), notes: '', files: [] }, true) },
        h('span', {}, t.icon), t.name))));
}

function viewSheet(it) {
  const fields = (it.fields || []).filter(f => f.value !== '').map(f => {
    const val = h('div', { class: 'fval' + (f.secret ? ' mono' : '') }, f.secret ? '••••••••••' : f.value);
    let shown = false;
    const isUrl = /^https?:\/\//i.test(f.value);
    return h('div', { class: 'field' }, h('div', { class: 'flabel' }, f.label),
      h('div', { class: 'fval-row' }, val,
        f.secret ? h('button', { class: 'btn small ghost', onclick: e => { shown = !shown; val.textContent = shown ? f.value : '••••••••••'; e.target.textContent = shown ? 'Hide' : 'Show'; } }, 'Show') : null,
        isUrl ? h('a', { class: 'btn small ghost', href: f.value, target: '_blank', rel: 'noopener noreferrer' }, 'Open') : null,
        h('button', { class: 'btn small', onclick: () => copy(f.value, f.label + ' copied') }, 'Copy')));
  });
  const files = (it.files || []).map((f, i) => {
    const kind = viewKind(f);
    return h('div', { class: 'filecard', 'data-i': i },
      h('button', { class: 'file fileopen', title: kind ? 'Open' : 'This type can only be downloaded', onclick: e => kind ? openViewer(f) : downloadFile(f, e.currentTarget.querySelector('.fsize')) },
        h('span', {}, fileIcon(f.mime, f.name)), h('span', { class: 'fname' }, f.name), h('span', { class: 'fsize' }, fmtSize(f.size))),
      h('div', { class: 'filebtns' },
        kind ? h('button', { class: 'btn small primary', onclick: () => openViewer(f) }, 'Open') : null,
        editButtons(it, i, f),
        h('button', { class: 'btn small', title: 'Upload a newer version of this file', onclick: () => replaceFile(it, i) }, '⟳ Replace'),
        h('button', { class: 'btn small ghost', onclick: e => downloadFile(f, e.target) }, 'Download'),
        f.replaced ? h('span', { class: 'hint fileupd' }, 'updated ' + new Date(f.replaced).toLocaleDateString()) : null));
  });
  sheet(
    h('div', { class: 'sheet-head' }, h('div', { class: 'ricon' }, TYPES[it.type]?.icon || '🗂️'), h('h2', {}, it.title || 'Untitled'),
      h('button', { class: 'btn ghost iconbtn', title: it.fav ? 'Remove favorite' : 'Favorite', onclick: async () => { await saveItem({ ...it, fav: !it.fav }); viewSheet(S.items.find(x => x.id === it.id)); renderList(); } }, it.fav ? '★' : '☆'),
      h('button', { class: 'btn ghost iconbtn', onclick: closeSheet, 'aria-label': 'Close' }, '✕')),
    fields,
    it.notes ? [h('div', { class: 'section' }, 'Notes'), h('div', { class: 'field' }, h('div', { class: 'fval' }, it.notes))] : null,
    files.length ? [h('div', { class: 'section' }, 'Files'), ...files.flat()] : null,
    h('div', { class: 'actions' },
      h('button', { class: 'btn danger', onclick: () => deleteItem(it) }, 'Delete'), h('span', { class: 'spacer' }),
      h('button', { class: 'btn primary', onclick: () => editSheet(structuredClone(it), false) }, 'Edit')),
    h('p', { class: 'hint' }, 'Last changed ' + new Date(it.updated || Date.now()).toLocaleString()));
}

function fileIcon(mime = '', name = '') {
  const e = ext(name);
  if (['xlsx', 'xlsm', 'xls', 'ods', 'csv'].includes(e)) return '📊';
  if (e === 'pdf') return '📕';
  if (mime.startsWith('image/')) return '🖼️';
  if (mime.startsWith('video/')) return '🎞️';
  if (mime.startsWith('audio/')) return '🎵';
  if (mime === 'application/pdf') return '📕';
  if (/zip|compressed|tar|rar|7z/.test(mime)) return '🗜️';
  if (/sheet|excel|csv/.test(mime)) return '📊';
  if (/word|document|text/.test(mime)) return '📄';
  return '📦';
}

function editSheet(d, isNew) {
  d.fields = d.fields || []; d.files = d.files || [];
  const pending = []; const removed = [];
  const title = h('input', { value: d.title, placeholder: 'e.g. Gmail, Home WiFi, Passport scan' });
  const fieldBox = h('div'); const fileBox = h('div');
  const notes = h('textarea', { placeholder: 'Anything else you want to keep here' }); notes.value = d.notes || '';
  const err = h('div', { class: 'err' }); const prog = h('div', { class: 'progress hidden' }, h('i'));

  function drawFields() {
    fieldBox.replaceChildren(...d.fields.map((f, i) => {
      const label = h('input', { value: f.label, placeholder: 'Label', oninput: e => f.label = e.target.value });
      const val = h('input', { value: f.value, placeholder: 'Value', type: f.secret ? 'password' : 'text', class: f.secret ? 'mono' : '', autocomplete: 'off', oninput: e => f.value = e.target.value });
      return h('div', { class: 'edit-field' }, label,
        h('div', { class: 'tools' },
          h('button', { class: 'btn small ghost', title: f.secret ? 'Hidden field (tap to make visible)' : 'Visible field (tap to hide)', onclick: () => { f.secret = !f.secret; drawFields(); } }, f.secret ? '🙈' : '👁️'),
          h('button', { class: 'btn small ghost', title: 'Remove field', onclick: () => { d.fields.splice(i, 1); drawFields(); } }, '✕')),
        h('div', { class: 'full fval-row' }, val,
          f.secret ? h('button', { class: 'btn small', title: 'Generate a strong password', onclick: () => { f.value = genPassword(); val.type = 'text'; val.value = f.value; } }, '🎲') : null,
          f.secret ? h('button', { class: 'btn small ghost', onclick: () => { val.type = val.type === 'password' ? 'text' : 'password'; } }, 'Show') : null));
    }));
  }
  function drawFiles() {
    fileBox.replaceChildren(
      ...d.files.map((f, i) => h('div', { class: 'file' }, h('span', {}, fileIcon(f.mime)), h('span', { class: 'fname' }, f.name), h('span', { class: 'fsize' }, fmtSize(f.size)),
        h('button', { class: 'btn small ghost', onclick: () => { removed.push(f.fid); d.files.splice(i, 1); drawFiles(); } }, 'Remove'))),
      ...pending.map((f, i) => h('div', { class: 'file' }, h('span', {}, '⬆️'), h('span', { class: 'fname' }, f.name), h('span', { class: 'fsize' }, fmtSize(f.size) + ' · new'),
        h('button', { class: 'btn small ghost', onclick: () => { pending.splice(i, 1); drawFiles(); } }, 'Remove'))));
  }
  const picker = h('input', { type: 'file', multiple: true, class: 'hidden', onchange: e => {
    for (const f of e.target.files) {
      if (f.size > MAX_FILE) { toast(`${f.name} is over ${fmtSize(MAX_FILE)} — too big`); continue; }
      if (f.size === 0) { toast(`${f.name} is empty`); continue; }
      pending.push(f);
    }
    picker.value = ''; drawFiles();
  } });

  const save = h('button', { class: 'btn primary', onclick: async () => {
    err.textContent = '';
    d.title = title.value.trim(); d.notes = notes.value;
    d.fields = d.fields.filter(f => f.label.trim() || f.value);
    if (!d.title) { err.textContent = 'Give it a name.'; return; }
    busy(save, true, 'Saving…');
    try {
      const total = pending.reduce((a, f) => a + f.size, 0); let done = 0;
      if (pending.length) prog.classList.remove('hidden');
      for (const f of pending) {
        const meta = await uploadFile(f, n => { done += n; prog.firstChild.style.width = Math.round(done / total * 100) + '%'; });
        d.files.push(meta);
      }
      await saveItem(d);
      for (const fid of removed) api('/api/files/' + fid, { method: 'DELETE' }).catch(() => {});
      toast('Saved'); renderList(); viewSheet(S.items.find(x => x.id === d.id));
    } catch (e) { err.textContent = e.message; busy(save, false, 'Save'); }
  } }, 'Save');

  drawFields(); drawFiles();
  sheet(
    h('div', { class: 'sheet-head' }, h('div', { class: 'ricon' }, TYPES[d.type]?.icon || '🗂️'), h('h2', {}, isNew ? 'New ' + (TYPES[d.type]?.name || 'entry') : 'Edit'),
      h('button', { class: 'btn ghost iconbtn', onclick: () => isNew ? closeSheet() : viewSheet(S.items.find(x => x.id === d.id)), 'aria-label': 'Close' }, '✕')),
    h('label', {}, 'Name'), title,
    h('div', { class: 'section' }, 'Fields'), fieldBox,
    h('div', { class: 'actions' },
      h('button', { class: 'btn small', onclick: () => { d.fields.push({ label: '', value: '', secret: false }); drawFields(); } }, '+ Add field'),
      h('button', { class: 'btn small', onclick: () => { d.fields.push({ label: 'Password', value: '', secret: true }); drawFields(); } }, '+ Hidden field')),
    h('div', { class: 'section' }, 'Notes'), notes,
    h('div', { class: 'section' }, 'Files'), fileBox,
    h('div', { class: 'actions' }, h('button', { class: 'btn small', onclick: () => picker.click() }, '📎 Add files'), picker),
    prog, err,
    h('div', { class: 'actions' }, h('span', { class: 'spacer' }), save));
  if (isNew) title.focus();
}

async function saveItem(d) {
  const id = d.id || newId();
  const obj = { type: d.type, title: d.title, fields: d.fields || [], notes: d.notes || '', files: d.files || [], fav: !!d.fav };
  await api('/api/items/' + id, { method: 'PUT', body: { blob: await encItem(id, obj) } });
  const full = { id, updated: Date.now(), ...obj };
  const i = S.items.findIndex(x => x.id === id);
  if (i >= 0) S.items[i] = full; else S.items.push(full);
  d.id = id;
  return full;
}

async function deleteItem(it) {
  const n = (it.files || []).length;
  if (!confirm(`Delete “${it.title}”${n ? ` and its ${n} file${n > 1 ? 's' : ''}` : ''}? This can't be undone.`)) return;
  try {
    await api('/api/items/' + it.id, { method: 'DELETE' });
    for (const f of it.files || []) await api('/api/files/' + f.fid, { method: 'DELETE' }).catch(() => {});
    S.items = S.items.filter(x => x.id !== it.id);
    closeSheet(); renderList(); toast('Deleted');
  } catch (e) { toast(e.message); }
}

// ---------------- files ----------------
async function uploadFile(file, onProgress) {
  const fid = newId();
  const chunks = Math.ceil(file.size / CHUNK);
  for (let n = 0; n < chunks; n++) {
    const part = new Uint8Array(await file.slice(n * CHUNK, (n + 1) * CHUNK).arrayBuffer());
    const sealed = await seal(S.vk, part, `file:${fid}:${n}:${chunks}`);
    await api(`/api/files/${fid}/${n}`, { method: 'PUT', body: sealed, headers: { 'Content-Type': 'application/octet-stream' } });
    onProgress(part.length);
  }
  return { fid, name: file.name, size: file.size, mime: file.type || 'application/octet-stream', chunks };
}
async function fetchFile(f) {
  const parts = [];
  for (let n = 0; n < f.chunks; n++) {
    const data = await api(`/api/files/${f.fid}/${n}`, { raw: true });
    parts.push(await open_(S.vk, data, `file:${f.fid}:${n}:${f.chunks}`));
  }
  return new Blob(parts, { type: f.mime });
}
async function downloadFile(f, btn) {
  const label = btn.textContent; busy(btn, true, 'Decrypting…');
  try {
    const url = URL.createObjectURL(await fetchFile(f));
    const a = h('a', { href: url, download: f.name }); document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  } catch (e) { toast(e.message || "Couldn't open the file"); }
  busy(btn, false, label);
}
// ---- built-in viewer: opens files in memory only, nothing is saved to the device ----
const ext = n => (n.match(/\.([a-z0-9]+)$/i)?.[1] || '').toLowerCase();
function viewKind(f) {
  const m = f.mime || '', e = ext(f.name);
  if (['xlsx', 'xlsm', 'xls', 'xlsb', 'ods', 'numbers'].includes(e) || /spreadsheet|ms-excel/.test(m)) return 'sheet';
  if (e === 'csv' || m === 'text/csv') return 'sheet';
  if (e === 'pdf' || m === 'application/pdf') return 'pdf';
  if (/^image\/(png|jpe?g|gif|webp|bmp|avif|svg\+xml)$/.test(m) || ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'avif'].includes(e)) return 'image';
  if (/^video\//.test(m) || ['mp4', 'webm', 'mov', 'm4v'].includes(e)) return 'video';
  if (/^audio\//.test(m) || ['mp3', 'wav', 'm4a', 'ogg', 'flac', 'aac'].includes(e)) return 'audio';
  if (/^text\//.test(m) || /json|xml|javascript/.test(m) || ['txt', 'md', 'json', 'log', 'ini', 'cfg', 'conf', 'yml', 'yaml', 'xml', 'env', 'py', 'js', 'html', 'css', 'sql'].includes(e)) return 'text';
  return null;
}
function loadScript(src) {
  return new Promise((ok, no) => {
    if (document.querySelector(`script[src="${src}"]`)) return ok();
    const s = h('script', { src }); s.onload = ok; s.onerror = () => no(new Error("Couldn't load the viewer.")); document.head.append(s);
  });
}
let viewerUrls = [];
function closeViewer() {
  const v = $('#viewer'); if (v) v.remove();
  viewerUrls.forEach(u => URL.revokeObjectURL(u)); viewerUrls = [];
  if (!$('#overlay')) document.body.style.overflow = '';
}
document.addEventListener('keydown', e => { if (e.key === 'Escape' && $('#viewer')) { e.stopImmediatePropagation(); closeViewer(); } }, true);

async function openViewer(f) {
  closeViewer();
  const body = h('div', { class: 'vbody' }, h('div', { class: 'empty' }, 'Decrypting…'));
  const dl = h('button', { class: 'btn small ghost', onclick: e => downloadFile(f, e.target) }, 'Download');
  const v = h('div', { class: 'viewer', id: 'viewer' },
    h('div', { class: 'vhead' }, h('span', {}, fileIcon(f.mime, f.name)), h('span', { class: 'vtitle' }, f.name), dl,
      h('button', { class: 'btn ghost iconbtn', 'aria-label': 'Close viewer', onclick: closeViewer }, '✕')),
    body);
  document.body.append(v); document.body.style.overflow = 'hidden';
  try {
    const blob = await fetchFile(f);
    if (!$('#viewer')) return; // closed while loading
    const kind = viewKind(f);
    if (kind === 'image') {
      const u = URL.createObjectURL(blob); viewerUrls.push(u);
      body.replaceChildren(h('img', { class: 'vimg', src: u, alt: f.name }));
    } else if (kind === 'video' || kind === 'audio') {
      const u = URL.createObjectURL(blob); viewerUrls.push(u);
      body.replaceChildren(h(kind, { class: 'vmedia', src: u, controls: true, playsinline: true }));
    } else if (kind === 'text') {
      const t = await blob.text();
      body.replaceChildren(h('pre', { class: 'vtext' }, t.length > 2_000_000 ? t.slice(0, 2_000_000) + '\n\n… (file too long, download to see the rest)' : t));
    } else if (kind === 'sheet') {
      await renderSheet(blob, f, body);
    } else if (kind === 'pdf') {
      await renderPdf(blob, body);
    }
  } catch (e) {
    console.error(e);
    body.replaceChildren(h('div', { class: 'empty' }, "Couldn't open this file here. ", h('br'), 'You can still download it.'));
  }
}

const MAX_ROWS = 3000, MAX_COLS = 60;
async function renderSheet(blob, f, body) {
  await loadScript('/lib/xlsx.min.js');
  const buf = new Uint8Array(await blob.arrayBuffer());
  const wb = ext(f.name) === 'csv' || f.mime === 'text/csv'
    ? XLSX.read(new TextDecoder().decode(buf), { type: 'string', raw: false })
    : XLSX.read(buf, { type: 'array', cellDates: true, cellNF: true, cellStyles: false, dense: false });
  const tabs = h('div', { class: 'vtabs' });
  const area = h('div', { class: 'vtable-wrap' });
  const search = h('input', { type: 'search', class: 'vsearch', placeholder: 'Find in sheet' });
  let current = wb.SheetNames[0], q = '';
  function draw() {
    const ws = wb.Sheets[current];
    const rows = XLSX.utils.sheet_to_json(ws, { header: 1, raw: false, defval: '', blankrows: false });
    const width = Math.min(MAX_COLS, rows.reduce((m, r) => Math.max(m, r.length), 0));
    const ql = q.trim().toLowerCase();
    let shown = rows.map((r, i) => [i, r]);
    if (ql) shown = shown.filter(([, r]) => r.some(c => String(c).toLowerCase().includes(ql)));
    const cut = shown.length > MAX_ROWS;
    shown = shown.slice(0, MAX_ROWS);
    if (!rows.length) { area.replaceChildren(h('div', { class: 'empty' }, 'This sheet is empty.')); return; }
    const colName = n => { let s = ''; n++; while (n) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - 1) / 26); } return s; };
    const table = h('table', { class: 'vtable' },
      h('thead', {}, h('tr', {}, h('th', { class: 'rn' }, ''), Array.from({ length: width }, (_, c) => h('th', {}, colName(c))))),
      h('tbody', {}, shown.map(([i, r]) => h('tr', {}, h('td', { class: 'rn' }, i + 1),
        Array.from({ length: width }, (_, c) => {
          const val = r[c] ?? '';
          const td = h('td', { title: String(val).length > 40 ? String(val) : null }, String(val));
          if (ql && String(val).toLowerCase().includes(ql)) td.className = 'hit';
          td.addEventListener('dblclick', () => copy(String(val), 'Cell copied'));
          return td;
        })))));
    area.replaceChildren(table, cut ? h('p', { class: 'hint' }, `Showing the first ${MAX_ROWS} rows. Use Find or download for the rest.`) : null,
      ql && !shown.length ? h('div', { class: 'empty' }, 'No matches.') : null);
    tabs.querySelectorAll('button').forEach(b => b.classList.toggle('on', b.dataset.s === current));
  }
  wb.SheetNames.forEach(n => tabs.append(h('button', { class: 'chip', 'data-s': n, onclick: () => { current = n; draw(); } }, n)));
  let t; search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { q = search.value; draw(); }, 150); });
  body.replaceChildren(h('div', { class: 'vbar' }, search, wb.SheetNames.length > 1 ? tabs : null), area,
    h('p', { class: 'hint vfoot' }, 'Read-only here. Double-tap a cell to copy it. To change it, use ✏️ Edit on your PC.'));
  draw();
}

async function renderPdf(blob, body) {
  const pdfjs = await import('/lib/pdf.min.mjs');
  pdfjs.GlobalWorkerOptions.workerSrc = '/lib/pdf.worker.min.mjs';
  const doc = await pdfjs.getDocument({ data: new Uint8Array(await blob.arrayBuffer()), isEvalSupported: false,
    cMapUrl: '/lib/cmaps/', cMapPacked: true, standardFontDataUrl: '/lib/standard_fonts/' }).promise;
  const pages = h('div', { class: 'vpdf' });
  body.replaceChildren(pages, h('p', { class: 'hint vfoot' }, `${doc.numPages} page${doc.numPages > 1 ? 's' : ''}`));
  const width = Math.min(body.clientWidth - 24, 1000);
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  // render pages as they scroll into view
  const io = new IntersectionObserver(entries => entries.forEach(async en => {
    if (!en.isIntersecting || en.target.dataset.done) return;
    en.target.dataset.done = '1'; io.unobserve(en.target);
    const page = await doc.getPage(Number(en.target.dataset.n));
    const vp1 = page.getViewport({ scale: 1 });
    const vp = page.getViewport({ scale: (width / vp1.width) * dpr });
    const c = en.target.querySelector('canvas'); c.width = vp.width; c.height = vp.height;
    await page.render({ canvasContext: c.getContext('2d'), viewport: vp }).promise;
  }), { root: body, rootMargin: '600px 0px' });
  for (let n = 1; n <= doc.numPages; n++) {
    const p1 = n === 1 ? await doc.getPage(1) : null;
    const ratio = p1 ? p1.getViewport({ scale: 1 }).height / p1.getViewport({ scale: 1 }).width : 1.414;
    const c = h('canvas', { class: 'vpage' }); c.style.aspectRatio = String(1 / ratio);
    const holder = h('div', { 'data-n': n }, c);
    pages.append(holder); io.observe(holder);
  }
}

// ---- replace a file with a newer version (keeps the entry, removes the old copy) ----
async function doReplace(it, i, file, opts = {}) {
  if (file.size > MAX_FILE) throw new Error(`Too big — max ${fmtSize(MAX_FILE)}`);
  if (file.size === 0) throw new Error('That file is empty.');
  const old = it.files[i];
  const prog = h('div', { class: 'progress' }, h('i'));
  const card = $(`#overlay .filecard[data-i="${i}"]`) || $('#overlay .sheet');
  if (card) card.append(prog);
  try {
    let done = 0;
    const meta = await uploadFile(file, n => { done += n; prog.firstChild.style.width = Math.round(done / file.size * 100) + '%'; });
    meta.replaced = Date.now();
    if (opts.keepName) { meta.name = old.name; if (!file.type) meta.mime = old.mime; }
    const files = it.files.slice(); files[i] = meta;
    await saveItem({ ...it, files });
    api('/api/files/' + old.fid, { method: 'DELETE' }).catch(() => {});
    return meta;
  } finally { prog.remove(); }
}
function replaceFile(it, i) {
  const picker = h('input', { type: 'file', class: 'hidden' });
  picker.addEventListener('change', async () => {
    const file = picker.files[0]; picker.remove(); if (!file) return;
    try {
      const old = it.files[i];
      const meta = await doReplace(it, i, file);
      await editMove(old.fid, meta.fid);
      toast('Updated — your other devices get it automatically');
      renderList(); viewSheet(S.items.find(x => x.id === it.id));
    } catch (e) { toast(e.message); }
  });
  document.body.append(picker); picker.click();
}

// ---- Edit on this PC: save a working copy, then push changes back with one click ----
// Uses the browser's file access (Chrome/Edge on a computer). The vault remembers WHERE you
// saved the copy (not its contents), so "Save changes" finds the file by itself.
const canEditLocal = () => 'showSaveFilePicker' in window && !/Android|iPhone|iPad/.test(navigator.userAgent);
function idb() {
  return new Promise((ok, no) => {
    const r = indexedDB.open('vaultbit-edit', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('h');
    r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error);
  });
}
async function idbDo(mode, fn) {
  const db = await idb();
  return new Promise((ok, no) => {
    const tx = db.transaction('h', mode); const st = tx.objectStore('h'); const req = fn(st);
    tx.oncomplete = () => { ok(req && req.result); db.close(); }; tx.onerror = () => { no(tx.error); db.close(); };
  });
}
const editGet = fid => idbDo('readonly', st => st.get(fid)).catch(() => null);
const editPut = (fid, v) => idbDo('readwrite', st => st.put(v, fid));
const editDel = fid => idbDo('readwrite', st => st.delete(fid)).catch(() => {});
async function editMove(from, to) { const v = await editGet(from); if (v) { await editPut(to, v); await editDel(from); } }

function editButtons(it, i, f) {
  const box = h('span', { class: 'editbox' });
  if (!canEditLocal()) return box;
  (async () => {
    const rec = await editGet(f.fid);
    if (!rec) {
      box.replaceChildren(h('button', { class: 'btn small', title: 'Save a copy to this PC to edit it', onclick: e => startEdit(it, i, e.currentTarget) }, '✏️ Edit'));
    } else {
      box.replaceChildren(
        h('button', { class: 'btn small primary', title: 'Upload the edited file from ' + rec.where, onclick: e => saveEdit(it, i, e.currentTarget) }, '💾 Save changes'),
        h('button', { class: 'btn small ghost', title: 'Stop tracking the copy on this PC', onclick: async () => { await editDel(f.fid); toast('Stopped editing — delete the copy on your PC if you no longer need it'); viewSheet(S.items.find(x => x.id === it.id)); } }, 'Stop editing'));
    }
  })();
  return box;
}

async function startEdit(it, i, btn) {
  const f = it.files[i];
  let handle;
  try {
    handle = await window.showSaveFilePicker({ suggestedName: f.name, id: 'vaultbit-edit', startIn: 'documents' });
  } catch (e) { if (e.name !== 'AbortError') toast("Couldn't save: " + e.message); return; }
  busy(btn, true, 'Saving…');
  try {
    const blob = await fetchFile(f);
    const w = await handle.createWritable(); await w.write(blob); await w.close();
    const saved = await handle.getFile();
    await editPut(f.fid, { handle, lastModified: saved.lastModified, size: saved.size, where: handle.name });
    toast(`Saved as ${handle.name} — open it in Excel, edit, save, then press 💾 Save changes`);
    viewSheet(S.items.find(x => x.id === it.id));
  } catch (e) { toast("Couldn't save: " + e.message); busy(btn, false, '✏️ Edit'); }
}

async function saveEdit(it, i, btn) {
  const f = it.files[i];
  const rec = await editGet(f.fid); if (!rec) return;
  busy(btn, true, 'Uploading…');
  const reset = () => busy(btn, false, '💾 Save changes');
  try {
    let perm = await rec.handle.queryPermission({ mode: 'read' });
    if (perm !== 'granted') perm = await rec.handle.requestPermission({ mode: 'read' });
    if (perm !== 'granted') { toast('Allow access to the file so Vaultbit can read your changes.'); return reset(); }
    let file;
    try { file = await rec.handle.getFile(); }
    catch (e) {
      if (e.name === 'NotFoundError') { await editDel(f.fid); toast("Couldn't find the copy on your PC (moved or deleted). Use ⟳ Replace instead."); viewSheet(S.items.find(x => x.id === it.id)); return; }
      if (e.name === 'NotReadableError') { toast('The file is busy — save it in Excel and try again.'); return reset(); }
      throw e;
    }
    if (file.lastModified === rec.lastModified && file.size === rec.size) { toast('No changes yet — save the file in Excel first.'); return reset(); }
    const meta = await doReplace(it, i, file, { keepName: true });
    await editDel(f.fid);
    await editPut(meta.fid, { ...rec, lastModified: file.lastModified, size: file.size });
    toast('Changes saved — your other devices get them automatically');
    renderList(); viewSheet(S.items.find(x => x.id === it.id));
  } catch (e) { toast(e.message || "Couldn't save changes"); reset(); }
}

// ---- keep other devices fresh: re-sync when the app comes back to the front ----
async function refreshVault() {
  if (!S.vk || !S.token || $('#overlay') || $('#viewer')) return;
  try {
    const v = await api('/api/vault');
    const items = [];
    for (const r of v.items) { try { items.push({ id: r.id, updated: r.updated, ...(await decItem(r.id, r.blob)) }); } catch {} }
    S.items = items; renderList();
  } catch {}
}

// ---------------- settings ----------------
// ---------------- backup / restore ----------------
// The backup file holds the vault exactly as the server stores it: every entry and file part is
// still encrypted, and the key is still locked with the master password you had when you made it.
// Format: "VAULTBIT-BACKUP-1\n" + 4-byte header length + JSON header + raw encrypted file parts.
const MAGIC = 'VAULTBIT-BACKUP-1\n';
const lastBackup = () => { try { return Number(localStorage.getItem('vb_lastbackup')) || 0; } catch { return 0; } };

function backupBox() {
  const box = h('div');
  const prog = h('div', { class: 'progress hidden' }, h('i'));
  const status = h('p', { class: 'hint' });
  const lb = lastBackup();
  const age = lb ? Math.floor((Date.now() - lb) / 86400000) : null;
  status.textContent = lb ? `Last backup from this device: ${new Date(lb).toLocaleDateString()}${age > 30 ? ' — time for a new one' : ''}` : 'No backup made from this device yet.';
  const exp = h('button', { class: 'btn small primary', onclick: () => exportBackup(exp, prog, status) }, '⬇️ Export backup');
  const picker = h('input', { type: 'file', accept: '.vbk', class: 'hidden', onchange: () => { const f = picker.files[0]; picker.value = ''; if (f) restoreSheet(f); } });
  box.append(
    h('p', { class: 'hint' }, 'Saves your whole vault as one encrypted file. Keep it on a USB stick and make a new one about once a month.'),
    h('div', { class: 'actions' }, exp, h('button', { class: 'btn small', onclick: () => picker.click() }, '⬆️ Restore from backup'), picker),
    prog, status);
  return box;
}

async function exportBackup(btn, prog, status) {
  busy(btn, true, 'Preparing…');
  const bar = prog.firstChild; prog.classList.remove('hidden'); bar.style.width = '0%';
  try {
    const st = await api('/api/status');
    const v = await api('/api/vault');
    // collect file list from the decrypted entries
    const files = [];
    for (const it of S.items) for (const f of it.files || []) files.push(f);
    const totalParts = files.reduce((a, f) => a + f.chunks, 0) || 1;
    const parts = []; const index = []; let done = 0;
    for (const f of files) {
      const sizes = [];
      for (let n = 0; n < f.chunks; n++) {
        const data = await api(`/api/files/${f.fid}/${n}`, { raw: true });
        parts.push(data); sizes.push(data.length);
        bar.style.width = Math.round(++done / totalParts * 100) + '%';
        btn.textContent = `Exporting… ${Math.round(done / totalParts * 100)}%`;
      }
      index.push({ fid: f.fid, chunks: f.chunks, sizes });
    }
    const header = te.encode(JSON.stringify({
      format: 'vaultbit-backup', version: 1, created: Date.now(),
      salt: st.salt, kdf: st.kdf, wrappedKey: v.wrappedKey, items: v.items, files: index,
    }));
    const len = new Uint8Array(4); new DataView(len.buffer).setUint32(0, header.length);
    const blob = new Blob([te.encode(MAGIC), len, header, ...parts], { type: 'application/octet-stream' });
    const name = `vaultbit-backup-${new Date().toISOString().slice(0, 10)}.vbk`;
    const url = URL.createObjectURL(blob);
    const a = h('a', { href: url, download: name }); document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 120_000);
    try { localStorage.setItem('vb_lastbackup', String(Date.now())); } catch {}
    status.textContent = `Backup saved as ${name} (${fmtSize(blob.size)}). Move it to your USB stick.`;
    toast('Backup ready');
  } catch (e) { status.textContent = "Backup failed: " + e.message; }
  busy(btn, false, '⬇️ Export backup'); prog.classList.add('hidden');
}

async function readBackup(file) {
  const head = new Uint8Array(await file.slice(0, MAGIC.length + 4).arrayBuffer());
  if (td.decode(head.subarray(0, MAGIC.length)) !== MAGIC) throw new Error("That isn't a Vaultbit backup file.");
  const hlen = new DataView(head.buffer).getUint32(MAGIC.length);
  const start = MAGIC.length + 4;
  const hdr = JSON.parse(td.decode(new Uint8Array(await file.slice(start, start + hlen).arrayBuffer())));
  if (hdr.format !== 'vaultbit-backup' || hdr.version !== 1) throw new Error('This backup is from an unknown version.');
  // work out where each file part sits in the backup
  let off = start + hlen; const where = {};
  for (const f of hdr.files) { where[f.fid] = f.sizes.map(sz => { const r = [off, off + sz]; off += sz; return r; }); }
  if (off > file.size) throw new Error('This backup file is incomplete or damaged.');
  return { hdr, where };
}

function restoreSheet(file) {
  const pw = h('input', { type: 'password', autocomplete: 'off', placeholder: 'Master password used when the backup was made' });
  const err = h('div', { class: 'err' }); const info = h('p', { class: 'hint' }, 'Reading backup…');
  const prog = h('div', { class: 'progress hidden' }, h('i'));
  let parsed;
  const go = h('button', { class: 'btn primary wide', disabled: true, onclick: async () => {
    err.textContent = ''; if (!pw.value) { err.textContent = 'Enter the master password.'; return; }
    busy(go, true, 'Checking password…');
    try {
      const { hdr, where } = parsed;
      const { kek } = await deriveKeys(pw.value, hdr.salt, JSON.parse(hdr.kdf));
      const raw = await open_(kek, unb64(hdr.wrappedKey), 'vaultbit-vk').catch(() => { throw new Error('Wrong master password for this backup.'); });
      const oldVK = await importVK(raw); raw.fill(0);
      const have = new Set(S.items.map(i => i.id));
      const todo = [];
      for (const r of hdr.items) {
        if (have.has(r.id)) continue;
        try { todo.push({ id: r.id, ...JSON.parse(td.decode(await open_(oldVK, unb64(r.blob), 'item:' + r.id))) }); }
        catch { /* skip anything unreadable */ }
      }
      const totalParts = todo.reduce((a, it) => a + (it.files || []).reduce((b, f) => b + f.chunks, 0), 0) || 1;
      let done = 0; prog.classList.remove('hidden');
      for (const it of todo) {
        busy(go, true, `Restoring “${it.title}”…`);
        const newFiles = [];
        for (const f of it.files || []) {
          const pos = where[f.fid]; if (!pos) continue; // file missing from backup
          const fid = newId();
          for (let n = 0; n < f.chunks; n++) {
            const enc = new Uint8Array(await file.slice(pos[n][0], pos[n][1]).arrayBuffer());
            const plain = await open_(oldVK, enc, `file:${f.fid}:${n}:${f.chunks}`);
            const sealed = await seal(S.vk, plain, `file:${fid}:${n}:${f.chunks}`);
            await api(`/api/files/${fid}/${n}`, { method: 'PUT', body: sealed, headers: { 'Content-Type': 'application/octet-stream' } });
            prog.firstChild.style.width = Math.round(++done / totalParts * 100) + '%';
          }
          newFiles.push({ ...f, fid });
        }
        await saveItem({ ...it, files: newFiles });
      }
      renderList(); closeSheet();
      toast(todo.length ? `Restored ${todo.length} entr${todo.length === 1 ? 'y' : 'ies'}` : 'Nothing to restore — everything in the backup is already in your vault');
    } catch (e) { err.textContent = e.message; busy(go, false, 'Restore'); }
  } }, 'Restore');
  pw.addEventListener('keydown', e => { if (e.key === 'Enter' && !go.disabled) go.click(); });
  sheet(h('div', { class: 'sheet-head' }, h('h2', {}, 'Restore from backup'), h('button', { class: 'btn ghost iconbtn', onclick: settingsSheet, 'aria-label': 'Back' }, '✕')),
    info,
    h('p', { class: 'hint' }, "Anything in the backup that's missing from your vault is added back. Entries you already have are left as they are."),
    h('label', {}, 'Master password of the backup'), pw, go, prog, err);
  readBackup(file).then(r => {
    parsed = r;
    const nFiles = r.hdr.files.length;
    info.textContent = `${file.name} — made ${new Date(r.hdr.created).toLocaleString()} · ${r.hdr.items.length} entries · ${nFiles} file${nFiles === 1 ? '' : 's'}`;
    go.disabled = false; pw.focus();
  }).catch(e => { info.textContent = ''; err.textContent = e.message; });
}

async function settingsSheet() {
  const usage = h('div', { class: 'hint' }, 'Checking storage…'); const bar = h('div', { class: 'bar' }, h('i'));
  const sessBox = h('div', { class: 'hint' }, 'Loading devices…');
  const bioBox = h('div');
  const drawBio = async () => {
    if (bioGet()) {
      bioBox.replaceChildren(h('div', { class: 'settings-row' }, h('span', {}, '✅ On — unlock with your fingerprint'),
        h('button', { class: 'btn small danger', onclick: () => { bioClear(); toast('Fingerprint unlock turned off'); drawBio(); } }, 'Turn off')));
    } else if (!(await bioCapable())) {
      bioBox.replaceChildren(h('p', { class: 'hint' }, 'Not available here — this device has no fingerprint or screen lock set up.'));
    } else {
      const pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Master password to confirm' });
      const err = h('div', { class: 'err' });
      const on = h('button', { class: 'btn primary small', onclick: async () => {
        err.textContent = ''; if (!pw.value) { err.textContent = 'Enter your master password first.'; return; }
        busy(on, true, 'Touch the sensor…');
        try { await bioEnable(pw.value); toast('Fingerprint unlock is on'); drawBio(); }
        catch (e) { err.textContent = e.message; busy(on, false, 'Turn on'); }
      } }, 'Turn on');
      bioBox.replaceChildren(h('p', { class: 'hint' }, "Unlock with your fingerprint instead of typing the master password. You'll be asked to touch the sensor twice."),
        h('div', { class: 'fval-row mt8' }, pw, on), err);
    }
  };
  drawBio();
  sheet(
    h('div', { class: 'sheet-head' }, h('h2', {}, 'Settings'), h('button', { class: 'btn ghost iconbtn', onclick: closeSheet, 'aria-label': 'Close' }, '✕')),
    h('div', { class: 'section' }, 'Storage'), bar, usage,
    h('div', { class: 'section' }, 'Signed-in devices'), sessBox,
    h('div', { class: 'actions' },
      h('button', { class: 'btn danger small', onclick: async () => {
        if (!confirm('Sign out every device, including this one? You will need your password and an email code on each device again.')) return;
        try { await api('/api/logout-all', { method: 'POST' }); } catch {}
        setToken(null); lock();
      } }, 'Sign out all devices')),
    h('div', { class: 'section' }, 'Fingerprint unlock (this device)'), bioBox,
    h('div', { class: 'section' }, 'Backup'), backupBox(),
    h('div', { class: 'section' }, 'Security'),
    h('div', { class: 'actions' }, h('button', { class: 'btn small', onclick: changePasswordSheet }, 'Change master password')),
    h('p', { class: 'hint' }, 'Vaultbit locks itself after 5 minutes without activity, or 2 minutes in the background. Everything is encrypted on this device before it is uploaded.'));
  try {
    const u = await api('/api/usage');
    usage.textContent = `${fmtSize(u.bytes)} of ${fmtSize(u.limit)} used · ${u.items} entries`;
    bar.firstChild.style.width = Math.min(100, u.bytes / u.limit * 100).toFixed(1) + '%';
  } catch (e) { usage.textContent = e.message; }
  try {
    const { sessions } = await api('/api/sessions');
    sessBox.replaceChildren(...sessions.map(s => h('div', { class: 'settings-row' },
      h('span', {}, s.device + (s.current ? ' (this device)' : '')), h('span', { class: 'hint' }, new Date(s.created).toLocaleDateString()))));
  } catch (e) { sessBox.textContent = e.message; }
}

function changePasswordSheet() {
  const cur = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Current master password' });
  const err = h('div', { class: 'err' });
  const pw = passwordPair(() => go.click());
  const go = h('button', { class: 'btn primary wide', onclick: async () => {
    err.textContent = '';
    const bad = checkNewPassword(pw.p1, pw.p2); if (bad) { err.textContent = bad; return; }
    busy(go, true, 'Changing…');
    try {
      const st = await api('/api/status');
      const old = await deriveKeys(cur.value, st.salt, JSON.parse(st.kdf));
      const v = await api('/api/vault');
      const raw = await open_(old.kek, unb64(v.wrappedKey), 'vaultbit-vk').catch(() => { throw new Error('Current master password is wrong.'); });
      const salt = b64(rand(16));
      const nk = await deriveKeys(pw.p1.value, salt, KDF);
      const wrappedKey = b64(await seal(nk.kek, raw, 'vaultbit-vk')); raw.fill(0);
      await api('/api/account', { method: 'PUT', body: { currentAuthKey: old.authKey, salt, kdf: JSON.stringify(KDF), authKey: nk.authKey, wrappedKey } });
      S.status = await api('/api/status');
      toast('Master password changed. Other devices were signed out.'); closeSheet();
    } catch (e) { err.textContent = e.message; busy(go, false, 'Change password'); }
  } }, 'Change password');
  sheet(h('div', { class: 'sheet-head' }, h('h2', {}, 'Change master password'), h('button', { class: 'btn ghost iconbtn', onclick: settingsSheet, 'aria-label': 'Back' }, '✕')),
    h('label', {}, 'Current master password'), cur, ...pw.nodes, go, err);
}

// ---------------- auto-lock ----------------
['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach(ev => addEventListener(ev, () => { S.lastActive = Date.now(); }, { passive: true }));
setInterval(() => { if (S.vk && Date.now() - S.lastActive > IDLE_LOCK_MS) { lock(); toast('Locked after inactivity'); } }, 15_000);
document.addEventListener('visibilitychange', () => {
  if (document.hidden) S.hiddenAt = Date.now();
  else if (S.vk && S.hiddenAt && Date.now() - S.hiddenAt > HIDDEN_LOCK_MS) { closeViewer(); lock(); }
  else refreshVault();
});

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
start();
