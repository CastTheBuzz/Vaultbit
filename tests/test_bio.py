from playwright.sync_api import sync_playwright
import os
HERE = os.path.dirname(os.path.abspath(__file__))
S = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'out'); os.makedirs(OUT, exist_ok=True)
ROOT = os.path.dirname(HERE)
B = 'http://localhost:8787'
PW = 'my long test passphrase 42'
errs, res = [], []
def ok(c, m): res.append((c, m)); print(('PASS ' if c else 'FAIL ') + m)

with sync_playwright() as p:
    br = p.chromium.launch()
    ctx = br.new_context(viewport={'width': 400, 'height': 860}, device_scale_factor=2)
    pg = ctx.new_page()
    pg.on('pageerror', lambda e: errs.append(str(e)))
    pg.on('console', lambda m: errs.append(m.text) if m.type == 'error' else None)
    cdp = ctx.new_cdp_session(pg)
    cdp.send('WebAuthn.enable')
    auth = cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
        'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': True,
        'hasUserVerification': True, 'isUserVerified': True, 'hasPrf': True, 'automaticPresenceSimulation': True}})
    pg.goto(B)
    pg.get_by_text('Send me a code').click(); pg.wait_for_selector('text=Check your email')
    pw = pg.locator('input[type=password]'); pw.nth(0).fill(PW); pw.nth(1).fill(PW)
    pg.get_by_text('Create vault').click(); pg.wait_for_selector('text=Your vault is empty', timeout=30000)
    pg.locator('.fab').click(); pg.locator('.typepick button', has_text='WiFi').click()
    pg.locator('input[placeholder^="e.g."]').fill('Home WiFi')
    pg.locator('.edit-field input[placeholder=Value]').nth(1).fill('wifipass123')
    pg.locator('.sheet button', has_text='Save').click(); pg.wait_for_selector('.sheet h2:has-text("Home WiFi")')
    pg.locator('button[aria-label=Close]').click()

    # turn on fingerprint
    pg.locator('button[aria-label=Settings]').click()
    pg.wait_for_selector('text=Fingerprint unlock (this device)')
    pg.locator('.sheet input[placeholder="Master password to confirm"]').fill('wrong password!!')
    pg.locator('.sheet button', has_text='Turn on').click()
    pg.wait_for_selector('.sheet .err:has-text("Wrong master password")', timeout=30000); ok(True, 'enable refuses wrong master password')
    pg.locator('.sheet input[placeholder="Master password to confirm"]').fill(PW)
    pg.locator('.sheet button', has_text='Turn on').click()
    pg.wait_for_selector('text=On — unlock with your fingerprint', timeout=30000); ok(True, 'fingerprint unlock turned on')
    stored = pg.evaluate("localStorage.getItem('vb_bio')")
    ok(stored and 'wrapped' in stored, 'encrypted unlock key stored on device only')
    pg.screenshot(path=f'{OUT}/b1-settings.png', full_page=True)
    pg.locator('button[aria-label=Close]').click()

    # lock, unlock with fingerprint
    pg.get_by_text('🔒 Lock').click(); pg.wait_for_timeout(1500); pg.screenshot(path=f'{OUT}/dbg.png'); print('BODY', pg.locator('#app').inner_text()[:300]); pg.wait_for_selector('text=Unlock with fingerprint')
    pg.screenshot(path=f'{OUT}/b2-locked.png')
    pg.get_by_text('👆 Unlock with fingerprint').click()
    pg.wait_for_selector('.row:has-text("Home WiFi")', timeout=30000); ok(True, 'fingerprint unlock opens the vault')
    pg.locator('.row').first.click(); pg.locator('.field', has_text='Password').get_by_text('Show').click()
    ok(pg.locator('.field', has_text='Password').locator('.fval').inner_text() == 'wifipass123', 'data decrypts after fingerprint unlock')
    pg.locator('button[aria-label=Close]').click()

    # reload page -> still offers fingerprint
    pg.reload(); pg.wait_for_selector('text=Unlock with fingerprint'); ok(True, 'fingerprint offered after reload')
    # password still works too
    pg.locator('input[type=password]').fill(PW); pg.get_by_text('Unlock', exact=True).click()
    pg.wait_for_selector('.row', timeout=30000); ok(True, 'master password still works alongside')

    # repeated use: lock + fingerprint 3 times in a row
    for i in range(3):
        pg.get_by_text('🔒 Lock').click(); pg.wait_for_selector('text=Unlock with fingerprint')
        pg.get_by_text('👆 Unlock with fingerprint').click(); pg.wait_for_selector('.row', timeout=30000)
    ok(True, 'fingerprint unlock works repeatedly')

    # turn off
    pg.locator('button[aria-label=Settings]').click(); pg.locator('.sheet button', has_text='Turn off').click()
    ok(pg.evaluate("localStorage.getItem('vb_bio')") is None, 'turning off removes it')
    pg.locator('button[aria-label=Close]').click()
    pg.get_by_text('🔒 Lock').click(); pg.wait_for_selector('text=Vault locked')
    ok(pg.get_by_text('Unlock with fingerprint').count() == 0, 'no fingerprint button once off')

    # sign out clears it
    pg.locator('input[type=password]').fill(PW); pg.get_by_text('Unlock', exact=True).click(); pg.wait_for_selector('.row', timeout=30000)
    pg.locator('button[aria-label=Settings]').click()
    pg.locator('.sheet input[placeholder="Master password to confirm"]').fill(PW)
    pg.locator('.sheet button', has_text='Turn on').click(); pg.wait_for_selector('text=On — unlock', timeout=30000)
    pg.locator('button[aria-label=Close]').click()
    pg.get_by_text('🔒 Lock').click(); pg.get_by_text('Sign out of this device').click(); pg.wait_for_selector('h1:has-text("Sign in")')
    ok(pg.evaluate("localStorage.getItem('vb_bio')") is None, 'signing out of the device removes fingerprint unlock')
    br.close()

ok(not [e for e in errs if 'Failed to load resource' not in e], 'no page errors: ' + '; '.join(errs[:4]))
print(f"\n{sum(c for c, _ in res)} passed, {sum(not c for c, _ in res)} failed")
