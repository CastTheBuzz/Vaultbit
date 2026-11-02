// Vaultbit setup + deploy. Run by deploy.bat — safe to run again any time to update.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CFG = join(ROOT, 'wrangler.jsonc');
const STATE = join(ROOT, 'setup', 'state.json');
const rl = createInterface({ input: process.stdin, output: process.stdout });
const ask = async q => (await rl.question(q)).trim();
const say = (...a) => console.log(...a);
const env = { ...process.env };

function run(args, { capture = false, input } = {}) {
  const r = spawnSync('npx', ['wrangler', ...args], {
    cwd: ROOT, env, shell: true, encoding: 'utf8',
    stdio: capture ? ['pipe', 'pipe', 'pipe'] : 'inherit', input,
  });
  return { ok: r.status === 0, out: (r.stdout || '') + (r.stderr || '') };
}
function die(msg) { say('\n❌ ' + msg + '\n'); rl.close(); process.exit(1); }

const state = existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : {};
const save = () => writeFileSync(STATE, JSON.stringify(state, null, 2));

say('\n=== Vaultbit setup ===\n');

// 1. Tools
if (!existsSync(join(ROOT, 'node_modules', 'wrangler'))) {
  say('Installing Cloudflare tools (one time, about a minute)...');
  const r = spawnSync('npm', ['install', '--no-audit', '--no-fund'], { cwd: ROOT, shell: true, stdio: 'inherit' });
  if (r.status !== 0) die('Install failed. Check your internet and run deploy.bat again.');
}

// 2. Log in to the PERSONAL Cloudflare account
let who = run(['whoami', '--json'], { capture: true });
if (!who.ok || state.relogin) {
  say('\nA browser window will open. Log in to the Cloudflare account you want Vaultbit on, then click Allow.\nTip: use a personal account, not a work/business one.\n');
  await ask('Press Enter to open the browser...');
  if (!run(['login']).ok) die('Login did not finish. Run deploy.bat again.');
  who = run(['whoami', '--json'], { capture: true });
  if (!who.ok) die('Still not logged in. Run deploy.bat again.');
}
let info = {};
try { info = JSON.parse(who.out.slice(who.out.indexOf('{'))); } catch {}
const accounts = info.accounts || [];
if (!accounts.length) die("Couldn't read your Cloudflare accounts. Run deploy.bat again.");

let acct = accounts.find(a => a.id === state.accountId);
if (!acct) {
  say('\nLogged in as: ' + (info.email || 'unknown'));
  accounts.forEach((a, i) => say(`  ${i + 1}) ${a.name}`));
  const pick = accounts.length === 1 ? 1 : Number(await ask('Which account number should Vaultbit use? '));
  acct = accounts[pick - 1];
  if (!acct) die('Not a valid choice.');
  if ((await ask(`Use "${acct.name}" for Vaultbit? (y/n) `)).toLowerCase() !== 'y') {
    say('\nOK — logging you out so you can log in with a different account.');
    run(['logout']);
    state.relogin = true; save();
    die('Run deploy.bat again and log in with the right account.');
  }
  state.accountId = acct.id; delete state.relogin; save();
}
env.CLOUDFLARE_ACCOUNT_ID = acct.id;
say(`\n✓ Using Cloudflare account: ${acct.name}`);

// 3. Your email (where the codes go)
if (!state.email) {
  say('\nCodes are emailed with Resend (free). Your Resend account must use the SAME email as below.');
  state.email = await ask('Email to receive your login codes: ');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(state.email)) die('That does not look like an email address.');
  save();
}
say('✓ Codes will go to: ' + state.email);

// 4. Database
if (!state.dbId) {
  say('\nCreating the vault database...');
  let r = run(['d1', 'create', 'vaultbit'], { capture: true });
  let m = r.out.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  if (!m) {
    const l = run(['d1', 'list', '--json'], { capture: true });
    try { const dbs = JSON.parse(l.out.slice(l.out.indexOf('['))); const db = dbs.find(d => d.name === 'vaultbit'); if (db) m = [db.uuid]; } catch {}
  }
  if (!m) { say(r.out); die('Could not create the database.'); }
  state.dbId = m[0]; save();
}
say('✓ Database ready');

// 5. Write config
let cfg = readFileSync(CFG, 'utf8');
cfg = cfg.replace(/"database_id":\s*"[^"]*"/, `"database_id": "${state.dbId}"`)
         .replace(/"OWNER_EMAIL":\s*"[^"]*"/, `"OWNER_EMAIL": "${state.email}"`);
writeFileSync(CFG, cfg);

// 6. Tables (safe to repeat — only creates what's missing)
if (!run(['d1', 'execute', 'vaultbit', '--remote', '--file=schema.sql', '--yes'], { capture: true }).ok)
  die('Could not create the tables. Run deploy.bat again.');
say('✓ Tables ready');

// 7. Resend key (stored as an encrypted secret on Cloudflare, never in these files)
if (!state.resendSet) {
  say('\nNow the Resend key:');
  say('  1. Go to https://resend.com and sign up with ' + state.email);
  say('  2. Open "API Keys" > "Create API key" (permission: Sending access), copy it');
  say('  3. Paste it below when asked (it will not be shown)\n');
  // first deploy so the secret has a worker to attach to
  if (!run(['deploy']).ok) die('Deploy failed. Run deploy.bat again.');
  if (!run(['secret', 'put', 'RESEND_API_KEY']).ok) die('Saving the key failed. Run deploy.bat again.');
  state.resendSet = true; save();
}

// 8. Deploy
say('\nPublishing Vaultbit...');
const d = run(['deploy'], { capture: true });
if (!d.ok) { say(d.out); die('Deploy failed. Run deploy.bat again.'); }
const url = (d.out.match(/https:\/\/vaultbit\.[a-z0-9-]+\.workers\.dev/i) || [])[0] || state.url;
if (url) { state.url = url; save(); writeFileSync(join(ROOT, 'VAULTBIT-LINK.txt'), url + '\n'); }

say('\n✅ Vaultbit is live: ' + (url || '(see the Cloudflare dashboard > Workers)'));
say('\nNext:');
say('  • It opens in your browser now — tap "Send me a code" to create your vault.');
say('  • On your Android phone: open the same link in Chrome > menu ⋮ > "Add to Home screen" / "Install app".');
say('  • To update later, just run deploy.bat again.\n');
if (url) spawnSync('cmd', ['/c', 'start', '', url], { shell: false });
rl.close();
