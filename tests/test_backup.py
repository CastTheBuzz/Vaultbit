import subprocess, shutil
from playwright.sync_api import sync_playwright
import os
HERE = os.path.dirname(os.path.abspath(__file__))
S = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'out'); os.makedirs(OUT, exist_ok=True)
ROOT = os.path.dirname(HERE)
B = 'http://localhost:8787'
PW, PW2 = 'my long test passphrase 42', 'a totally new vault password 9'
errs, res = [], []
def ok(c, m): res.append((c, m)); print(('PASS ' if c else 'FAIL ') + m)
def wipe():
    subprocess.run(f"cd {ROOT} && npx wrangler d1 execute vaultbit --local --command \"DELETE FROM meta; DELETE FROM items; DELETE FROM chunks; DELETE FROM sessions; DELETE FROM challenges; DELETE FROM ratelimit;\"", shell=True, capture_output=True)
def setup(pg, pw):
    pg.goto(B); pg.get_by_text('Send me a code').click(); pg.wait_for_selector('text=Check your email')
    f = pg.locator('input[type=password]'); f.nth(0).fill(pw); f.nth(1).fill(pw)
    pg.get_by_text('Create vault').click(); pg.wait_for_selector('text=Your vault is empty', timeout=30000)
def settings(pg): pg.locator('button[aria-label=Settings]').click(); pg.wait_for_selector('text=Export backup')

with sync_playwright() as p:
    br = p.chromium.launch()
    def page():
        c = br.new_context(viewport={'width': 1100, 'height': 820}, accept_downloads=True); pg = c.new_page()
        pg.on('pageerror', lambda e: errs.append(str(e))); pg.on('console', lambda m: errs.append(m.text) if m.type == 'error' else None)
        return pg
    wipe(); pg = page(); setup(pg, PW)
    # entry 1: login
    pg.locator('.fab').click(); pg.locator('.typepick button', has_text='Login').click()
    pg.locator('input[placeholder^="e.g."]').fill('Gmail'); pg.locator('.edit-field input[placeholder=Value]').nth(2).fill('secret-pass-1')
    pg.locator('.sheet button', has_text='Save').click(); pg.wait_for_selector('.sheet h2:has-text("Gmail")'); pg.locator('button[aria-label=Close]').click()
    # entry 2: files (excel + 4MB)
    pg.locator('.fab').click(); pg.locator('.typepick button', has_text='Files').click()
    pg.locator('input[placeholder^="e.g."]').fill('Docs')
    pg.locator('input[type=file]').set_input_files([f'{S}/passwords.xlsx', f'{S}/big.bin'])
    pg.locator('.sheet button', has_text='Save').click(); pg.wait_for_selector('.sheet h2:has-text("Docs")', timeout=60000); pg.locator('button[aria-label=Close]').click()

    settings(pg)
    ok('No backup made' in pg.locator('.sheet').inner_text(), 'settings says no backup yet')
    with pg.expect_download() as d: pg.get_by_text('⬇️ Export backup').click()
    bk = f'{OUT}/test.vbk'; d.value.save_as(bk)
    pg.wait_for_selector('text=Backup saved as'); ok(d.value.suggested_filename.startswith('vaultbit-backup-') and d.value.suggested_filename.endswith('.vbk'), 'backup file downloaded: ' + d.value.suggested_filename)
    raw = open(bk, 'rb').read()
    ok(b'secret-pass-1' not in raw and b'Gmail' not in raw and b'hunter2' not in raw, 'backup file contents are encrypted')
    ok(len(raw) > 4_000_000, f'backup includes the files ({len(raw)} bytes)')
    pg.locator('button[aria-label=Close]').click(); settings(pg); pg.wait_for_timeout(300)
    ok('Last backup from this device' in pg.locator('.sheet').inner_text(), 'settings remembers last backup date')
    pg.screenshot(path=f'{OUT}/k1-settings.png', full_page=True)
    pg.locator('button[aria-label=Close]').click()

    # accident: delete Docs, then restore into same vault
    pg.locator('.row', has_text='Docs').click(); pg.once('dialog', lambda dl: dl.accept()); pg.locator('.sheet button', has_text='Delete').click()
    pg.wait_for_selector('#overlay', state='detached'); ok(pg.locator('.row').count() == 1, 'Docs deleted')
    settings(pg)
    with pg.expect_file_chooser() as fc: pg.get_by_text('⬆️ Restore from backup').click()
    fc.value.set_files(bk); pg.wait_for_selector('text=2 entries')
    pg.locator('.sheet input[type=password]').fill('wrong password here'); pg.locator('.sheet button', has_text='Restore').click()
    pg.wait_for_selector('.err:has-text("Wrong master password")', timeout=30000); ok(True, 'wrong backup password refused')
    pg.locator('.sheet input[type=password]').fill(PW); pg.locator('.sheet button', has_text='Restore').click()
    pg.wait_for_selector('#toast:has-text("Restored 1 entry")', timeout=60000); ok(True, 'restore brings back only the missing entry')
    ok(pg.locator('.row').count() == 2, 'two entries again, no duplicates')
    pg.locator('.row', has_text='Docs').click(); pg.locator('.filecard', has_text='passwords.xlsx').get_by_text('Open').click()
    pg.wait_for_selector('.vtable', timeout=30000); ok('hunter2!' in pg.locator('.vtable').inner_text(), 'restored Excel opens')
    pg.locator('button[aria-label="Close viewer"]').click()
    with pg.expect_download() as d2: pg.locator('.filecard', has_text='big.bin').locator('.filebtns').get_by_text('Download').click()
    ok(open(d2.value.path(), 'rb').read() == open(f'{S}/big.bin', 'rb').read(), 'restored 4 MB file is byte-identical')
    pg.locator('button[aria-label=Close]').click()

    # disaster: brand new vault (different password), restore everything
    wipe(); pg2 = page(); setup(pg2, PW2)
    settings(pg2)
    with pg2.expect_file_chooser() as fc: pg2.get_by_text('⬆️ Restore from backup').click()
    fc.value.set_files(bk); pg2.wait_for_selector('text=2 entries')
    pg2.locator('.sheet input[type=password]').fill(PW); pg2.locator('.sheet button', has_text='Restore').click()
    pg2.wait_for_selector('#toast:has-text("Restored 2 entries")', timeout=60000)
    ok(pg2.locator('.row').count() == 2, 'new vault gets everything back from the backup')
    pg2.locator('.row', has_text='Gmail').click(); pg2.locator('.field', has_text='Password').get_by_text('Show').click()
    ok(pg2.locator('.field', has_text='Password').locator('.fval').inner_text() == 'secret-pass-1', 'restored password is correct')
    pg2.locator('button[aria-label=Close]').click()
    # new vault still opens with its NEW password
    pg2.reload(); pg2.locator('input[type=password]').fill(PW2); pg2.get_by_text('Unlock', exact=True).click()
    pg2.wait_for_selector('.row', timeout=30000); ok(pg2.locator('.row').count() == 2, 'restored data opens with the new vault password')

    # not a backup file
    settings(pg2)
    with pg2.expect_file_chooser() as fc: pg2.get_by_text('⬆️ Restore from backup').click()
    fc.value.set_files(f'{S}/notes.txt'); pg2.wait_for_selector('.err:has-text("isn\'t a Vaultbit backup")', timeout=10000)
    ok(True, 'random file is rejected')
    br.close()
bad = [e for e in errs if 'Failed to load resource' not in e]
ok(not bad, 'no page errors: ' + '; '.join(bad[:4]))
print(f"\n{sum(c for c, _ in res)} passed, {sum(not c for c, _ in res)} failed")
