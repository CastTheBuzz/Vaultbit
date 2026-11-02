import os, sys
from playwright.sync_api import sync_playwright
import os
HERE = os.path.dirname(os.path.abspath(__file__))
S = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'out'); os.makedirs(OUT, exist_ok=True)
ROOT = os.path.dirname(HERE)
B = 'http://127.0.0.1:8787'
PW = 'my long test passphrase 42'
errs = []
res = []
def ok(c, m): res.append((c, m)); print(('PASS ' if c else 'FAIL ') + m)

with sync_playwright() as p:
    br = p.chromium.launch()
    ctx = br.new_context(viewport={'width': 400, 'height': 860}, device_scale_factor=2, accept_downloads=True,
                         permissions=['clipboard-read', 'clipboard-write'])
    pg = ctx.new_page()
    pg.on('console', lambda m: errs.append(m.text) if m.type == 'error' else None)
    pg.on('pageerror', lambda e: errs.append(str(e)))
    pg.goto(B)
    pg.get_by_text('Send me a code').click()
    pg.wait_for_selector('text=Check your email')
    pg.screenshot(path=f'{OUT}/1-setup.png')
    pw = pg.locator('input[type=password]')
    pw.nth(0).fill('short'); pw.nth(1).fill('short')
    pg.get_by_text('Create vault').click()
    ok(pg.locator('.err').inner_text().startswith('Use at least'), 'weak password refused')
    pw.nth(0).fill(PW); pw.nth(1).fill(PW)
    pg.get_by_text('Create vault').click()
    pg.wait_for_selector('text=Your vault is empty', timeout=30000)
    ok(True, 'vault created, empty list shown')

    # new login entry
    pg.locator('.fab').click(); pg.locator('.typepick button', has_text='Login').click()
    pg.locator('input[placeholder^="e.g."]').fill('Gmail')
    vals = pg.locator('.edit-field input[placeholder=Value]')
    vals.nth(0).fill('alex.morgan'); vals.nth(1).fill('alex@example.com')
    pg.locator('button[title="Generate a strong password"]').click()
    gen = vals.nth(2).input_value(); ok(len(gen) == 20, 'password generator gives 20 chars')
    pg.get_by_text('+ Add field').click()
    pg.locator('.edit-field input[placeholder=Label]').last.fill('Recovery code')
    pg.locator('.edit-field input[placeholder=Value]').last.fill('ABCD-1234')
    pg.screenshot(path=f'{OUT}/2-edit.png', full_page=True)
    pg.locator('.sheet button', has_text='Save').click()
    pg.wait_for_selector('.sheet h2:has-text("Gmail")')
    ok(pg.locator('.fval', has_text='••••').count() == 1, 'password hidden by default in view')
    pg.locator('.field', has_text='Password').get_by_text('Show').click()
    ok(pg.locator('.field', has_text='Password').locator('.fval').inner_text() == gen, 'Show reveals password')
    pg.locator('.field', has_text='Password').get_by_text('Copy').click()
    ok(pg.evaluate('navigator.clipboard.readText()') == gen, 'Copy puts password on clipboard')
    pg.screenshot(path=f'{OUT}/3-view.png', full_page=True)
    pg.locator('button[aria-label=Close]').click()

    # files entry with an image + a binary file
    pg.locator('.fab').click(); pg.locator('.typepick button', has_text='Files').click()
    pg.locator('input[placeholder^="e.g."]').fill('Passport scan')
    pg.locator('input[type=file]').set_input_files([os.path.join(ROOT, 'public', 'icon-512.png'), f'{S}/big.bin'])
    pg.locator('.sheet button', has_text='Save').click()
    pg.wait_for_selector('.sheet h2:has-text("Passport scan")', timeout=60000)
    ok(pg.locator('.filecard').count() == 2, 'two files attached')
    pg.locator('.filecard', has_text='icon-512.png').get_by_text('Open').click()
    pg.wait_for_selector('img.vimg'); pg.wait_for_timeout(300)
    ok(pg.evaluate("document.querySelector('img.vimg').naturalWidth") == 512, 'image preview decrypts and renders')
    pg.locator('button[aria-label="Close viewer"]').click()
    with pg.expect_download() as d:
        pg.locator('.filecard', has_text='big.bin').locator('.filebtns').get_by_text('Download').click()
    path = d.value.path()
    ok(open(path, 'rb').read() == open(f'{S}/big.bin', 'rb').read(), 'downloaded 4 MB file is byte-identical')
    pg.screenshot(path=f'{OUT}/4-files.png', full_page=True)
    pg.locator('button[aria-label=Close]').click()

    # list, search, filter
    ok(pg.locator('.row').count() == 2, 'two entries in list')
    pg.locator('input[type=search]').fill('pass')
    ok(pg.locator('.row').count() == 1, 'search filters')
    pg.locator('input[type=search]').fill('')
    pg.screenshot(path=f'{OUT}/5-list.png')

    # reload -> unlock screen, wrong + right password
    pg.reload(); pg.wait_for_selector('text=Vault locked')
    pg.locator('input[type=password]').fill('nope nope nope'); pg.get_by_text('Unlock', exact=True).click()
    pg.wait_for_selector('.err:has-text("Wrong master password")', timeout=30000)
    ok(True, 'wrong password on unlock is refused')
    pg.locator('input[type=password]').fill(PW); pg.get_by_text('Unlock', exact=True).click()
    pg.wait_for_selector('.row', timeout=30000)
    ok(pg.locator('.row').count() == 2, 'unlock restores both entries')

    # settings
    pg.locator('button[aria-label=Settings]').click()
    pg.wait_for_selector('text=used ·')
    ok('this device' in pg.locator('.sheet').inner_text(), 'settings shows devices + storage')
    pg.screenshot(path=f'{OUT}/6-settings.png', full_page=True)
    pg.locator('button[aria-label=Close]').click()

    # edit: remove a field, delete entry
    pg.locator('.row', has_text='Gmail').click(); pg.locator('.sheet button', has_text='Edit').click()
    pg.locator('.edit-field').last.locator('button[title="Remove field"]').click()
    pg.locator('.sheet button', has_text='Save').click(); pg.wait_for_selector('.sheet h2:has-text("Gmail")')
    ok(pg.locator('.field', has_text='Recovery code').count() == 0, 'field removed on edit')
    pg.once('dialog', lambda dlg: dlg.accept())
    pg.locator('.sheet button', has_text='Delete').click()
    pg.wait_for_selector('#overlay', state='detached'); pg.wait_for_timeout(300); assert pg.locator('.row').count() == 1
    ok(True, 'entry deleted')

    # desktop look
    pg.set_viewport_size({'width': 1280, 'height': 800})
    pg.locator('.row').first.click(); pg.wait_for_timeout(300)
    pg.screenshot(path=f'{OUT}/7-desktop.png')
    pg.locator('button[aria-label=Close]').click()
    pg.get_by_text('🔒 Lock').click(); pg.wait_for_selector('text=Vault locked')
    ok(True, 'lock button works')
    br.close()

ok(not errs, 'no console errors: ' + '; '.join(errs[:5]))
print(f"\n{sum(c for c, _ in res)} passed, {sum(not c for c, _ in res)} failed")
