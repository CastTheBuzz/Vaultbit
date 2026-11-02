// End-to-end API test: runs the real client-side crypto against a local server (npx wrangler dev).
import { randomBytes } from 'crypto';
import { createRequire } from 'module';
const require = createRequire(new URL('../package.json', import.meta.url));
const { argon2id } = require('hash-wasm');
const B = 'http://127.0.0.1:8787';
const te = new TextEncoder(), td = new TextDecoder();
const b64 = u => Buffer.from(u).toString('base64'), unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));
const rand = n => new Uint8Array(randomBytes(n));
const KDF = { alg: 'argon2id', m: 65536, t: 3, p: 1, v: 1 };
let pass = 0, failN = 0;
const ok = (c, m) => { c ? pass++ : failN++; console.log((c ? 'PASS ' : 'FAIL ') + m); };

async function derive(pw, salt, kdf) {
  const master = await argon2id({ password: pw.normalize('NFKC'), salt: unb64(salt), parallelism: kdf.p, iterations: kdf.t, memorySize: kdf.m, hashLength: 32, outputType: 'binary' });
  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const hk = i => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode(i) });
  return { kek: await crypto.subtle.deriveKey(hk('vaultbit-enc'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
    authKey: b64(new Uint8Array(await crypto.subtle.deriveBits(hk('vaultbit-auth'), base, 256))) };
}
async function seal(k, bytes, aad) { const iv = rand(12); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad) }, k, bytes)); const o = new Uint8Array(12 + ct.length); o.set(iv); o.set(ct, 12); return o; }
async function open(k, d, aad) { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: d.subarray(0, 12), additionalData: te.encode(aad) }, k, d.subarray(12))); }
let token = null;
async function api(p, o = {}) {
  const h = { ...(o.headers || {}) }; if (token && !o.noauth) h.Authorization = 'Bearer ' + token;
  let body = o.body; if (body && !(body instanceof Uint8Array)) { h['Content-Type'] = 'application/json'; body = JSON.stringify(body); }
  const r = await fetch(B + p, { method: o.method || 'GET', headers: h, body });
  if (o.raw) return { status: r.status, data: new Uint8Array(await r.arrayBuffer()) };
  return { status: r.status, data: await r.json().catch(() => ({})), headers: r.headers };
}

const PW = 'correct horse battery staple vault';
let r = await api('/api/status'); ok(r.status === 200 && r.data.setup === false, 'status: not set up');
r = await api('/api/vault'); ok(r.status === 401, 'vault blocked without session');
r = await api('/api/setup/start', { method: 'POST' }); ok(r.data.challenge && /^\d{6}$/.test(r.data.devCode), 'setup code sent');
const ch = r.data;
const salt = b64(rand(16)); const { kek, authKey } = await derive(PW, salt, KDF);
const vkRaw = rand(32); const wrappedKey = b64(await seal(kek, vkRaw, 'vaultbit-vk'));
const vk = await crypto.subtle.importKey('raw', vkRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
r = await api('/api/setup/finish', { method: 'POST', body: { challenge: ch.challenge, code: '000000' === ch.devCode ? '111111' : '000000', salt, kdf: JSON.stringify(KDF), authKey, wrappedKey } });
ok(r.status === 401, 'setup rejects wrong code');
r = await api('/api/setup/finish', { method: 'POST', body: { challenge: ch.challenge, code: ch.devCode, salt, kdf: JSON.stringify(KDF), authKey, wrappedKey, device: 'test' } });
ok(r.status === 200 && r.data.token, 'setup finished'); token = r.data.token;
r = await api('/api/setup/start', { method: 'POST' }); ok(r.status === 409, 'cannot set up twice');

// item round trip
const id = 'item_abcdefgh123';
const item = { type: 'wifi', title: 'Home WiFi', fields: [{ label: 'Password', value: 's3cret', secret: true }] };
r = await api('/api/items/' + id, { method: 'PUT', body: { blob: b64(await seal(vk, te.encode(JSON.stringify(item)), 'item:' + id)) } });
ok(r.status === 200, 'item saved');
r = await api('/api/vault');
const got = JSON.parse(td.decode(await open(vk, unb64(r.data.items[0].blob), 'item:' + id)));
ok(got.title === 'Home WiFi' && !r.data.items[0].blob.includes('Home'), 'item decrypts, server copy is unreadable');
let swapped = false; try { await open(vk, unb64(r.data.items[0].blob), 'item:other'); swapped = true; } catch {}
ok(!swapped, 'entry cannot be swapped to another id');

// file round trip: 3.2 MB in 1.5 MB parts
const big = rand(3_200_000); const fid = 'file_abcdefgh123'; const CH = 1_500_000; const n = Math.ceil(big.length / CH);
for (let i = 0; i < n; i++) {
  const s = await seal(vk, big.subarray(i * CH, (i + 1) * CH), `file:${fid}:${i}:${n}`);
  r = await api(`/api/files/${fid}/${i}`, { method: 'PUT', body: s, headers: { 'Content-Type': 'application/octet-stream' } });
  if (r.status !== 200) console.log(r.data);
}
const parts = [];
for (let i = 0; i < n; i++) { const x = await api(`/api/files/${fid}/${i}`, { raw: true }); parts.push(await open(vk, x.data, `file:${fid}:${i}:${n}`)); }
const back = Buffer.concat(parts);
ok(Buffer.compare(back, Buffer.from(big)) === 0, `3.2 MB file in ${n} parts round-trips exactly`);
r = await api(`/api/files/${fid}/9`, { method: 'PUT', body: rand(2_100_000), headers: { 'Content-Type': 'application/octet-stream' } });
ok(r.status === 400, 'oversized part rejected');
r = await api('/api/usage'); ok(r.data.bytes > 3_200_000, 'usage counts storage: ' + r.data.bytes);

// login on a "new device"
const t1 = token; token = null;
const st = (await api('/api/status')).data;
const wrong = await derive('wrong password here!!', st.salt, JSON.parse(st.kdf));
r = await api('/api/login/start', { method: 'POST', body: { authKey: wrong.authKey } }); ok(r.status === 401, 'wrong password rejected before any email');
const right = await derive(PW, st.salt, JSON.parse(st.kdf));
r = await api('/api/login/start', { method: 'POST', body: { authKey: right.authKey } }); ok(r.data.challenge, 'right password -> email code');
const lc = r.data;
for (let i = 0; i < 5; i++) await api('/api/login/verify', { method: 'POST', body: { challenge: lc.challenge, code: String((Number(lc.devCode) + 1 + i) % 1e6).padStart(6, '0') } });
r = await api('/api/login/verify', { method: 'POST', body: { challenge: lc.challenge, code: lc.devCode } });
ok(r.status === 401, 'code is burned after 5 wrong tries');
r = await api('/api/login/start', { method: 'POST', body: { authKey: right.authKey } });
r = await api('/api/login/verify', { method: 'POST', body: { challenge: r.data.challenge, code: r.data.devCode, device: 'phone' } });
ok(r.status === 200 && r.data.token, 'new device signed in'); token = r.data.token;
r = await api('/api/vault');
const vk2raw = await open(right.kek, unb64(r.data.wrappedKey), 'vaultbit-vk');
ok(Buffer.compare(Buffer.from(vk2raw), Buffer.from(vkRaw)) === 0, 'new device unwraps the same vault key');
r = await api('/api/sessions'); ok(r.data.sessions.length === 2, 'two devices listed');

// change password
const salt2 = b64(rand(16)); const nk = await derive('a brand new long passphrase', salt2, KDF);
r = await api('/api/account', { method: 'PUT', body: { currentAuthKey: wrong.authKey, salt: salt2, kdf: JSON.stringify(KDF), authKey: nk.authKey, wrappedKey: b64(await seal(nk.kek, vkRaw, 'vaultbit-vk')) } });
ok(r.status === 401, 'password change needs the current password');
r = await api('/api/account', { method: 'PUT', body: { currentAuthKey: right.authKey, salt: salt2, kdf: JSON.stringify(KDF), authKey: nk.authKey, wrappedKey: b64(await seal(nk.kek, vkRaw, 'vaultbit-vk')) } });
ok(r.status === 200, 'password changed');
r = await api('/api/vault', { headers: { Authorization: 'Bearer ' + t1 }, noauth: true }); ok(r.status === 401, 'other devices signed out after change');
r = await api('/api/login/start', { method: 'POST', body: { authKey: right.authKey } }); ok(r.status === 401, 'old password no longer works');

// delete + logout
r = await api('/api/files/' + fid, { method: 'DELETE' }); r = await api(`/api/files/${fid}/0`, { raw: true }); ok(r.status === 404, 'file deleted');
r = await api('/api/items/' + id, { method: 'DELETE' }); r = await api('/api/vault'); ok(r.data.items.length === 0, 'item deleted');
r = await api('/api/items/bad%27id', { method: 'PUT', body: { blob: 'x' } }); ok(r.status === 400, 'bad ids rejected');
r = await api('/api/logout-all', { method: 'POST' }); r = await api('/api/vault'); ok(r.status === 401, 'sign out all devices works');

// headers on the page
const page = await fetch(B + '/');
ok(page.status === 200 && (page.headers.get('content-security-policy') || '').includes("frame-ancestors 'none'"), 'page served with security headers');
const html = await page.text(); ok(html.includes('Vaultbit'), 'page loads');

// rate limit on wrong passwords
let limited = false;
for (let i = 0; i < 12; i++) { r = await api('/api/login/start', { method: 'POST', body: { authKey: wrong.authKey } }); if (r.status === 429) { limited = true; break; } }
ok(limited, 'brute force gets rate limited: ' + r.data.error);
console.log(`\n${pass} passed, ${failN} failed`);
