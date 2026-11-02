import openpyxl
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
    def mk(w, h):
        c = br.new_context(viewport={'width': w, 'height': h}, device_scale_factor=2, accept_downloads=True)
        pg = c.new_page()
        pg.on('pageerror', lambda e: errs.append(str(e)))
        pg.on('console', lambda m: errs.append(m.text) if m.type == 'error' else None)
        return c, pg
    pc_ctx, pg = mk(1280, 820)
    pg.goto(B)
    pg.get_by_text('Send me a code').click(); pg.wait_for_selector('text=Check your email')
    pw = pg.locator('input[type=password]'); pw.nth(0).fill(PW); pw.nth(1).fill(PW)
    pg.get_by_text('Create vault').click(); pg.wait_for_selector('text=Your vault is empty', timeout=30000)
    pg.locator('.fab').click(); pg.locator('.typepick button', has_text='Files').click()
    pg.locator('input[placeholder^="e.g."]').fill('My stuff')
    pg.locator('input[type=file]').set_input_files([f'{S}/passwords.xlsx', f'{S}/doc.pdf', f'{S}/notes.txt', os.path.join(ROOT, 'public', 'icon-512.png'), f'{S}/big.bin'])
    pg.locator('.sheet button', has_text='Save').click()
    pg.wait_for_selector('.sheet h2:has-text("My stuff")', timeout=60000)
    ok(pg.locator('.filecard').count() == 5, '5 files attached')
    ok(pg.locator('.filecard', has_text='big.bin').locator('button', has_text='Open').count() == 0, 'unknown file type has no Open, only Download')
    pg.screenshot(path=f'{OUT}/v1-entry.png')

    # Excel
    pg.locator('.filecard', has_text='passwords.xlsx').locator('button', has_text='Open').click()
    pg.wait_for_selector('.vtable', timeout=30000)
    txt = pg.locator('.vtable').inner_text()
    ok('hunter2!' in txt and 'Site 199' in txt, 'Excel opens in viewer with all rows')
    pg.screenshot(path=f'{OUT}/v2-excel.png')
    pg.locator('.vsearch').fill('gmail'); pg.wait_for_timeout(400)
    ok(pg.locator('.vtable tbody tr').count() == 1, 'find filters rows')
    pg.locator('.vsearch').fill('')
    pg.locator('.vtabs button', has_text='Bank').click(); pg.wait_for_timeout(200)
    ok('4321' in pg.locator('.vtable').inner_text(), 'second sheet tab works')
    ok(len(pc_ctx.pages) == 1, 'nothing downloaded to view')
    pg.locator('button[aria-label="Close viewer"]').click()

    # PDF
    pg.locator('.filecard', has_text='doc.pdf').locator('button', has_text='Open').click()
    pg.wait_for_selector('canvas.vpage', timeout=30000); pg.wait_for_timeout(2500)
    ok(pg.locator('canvas.vpage').count() == 3, 'PDF shows 3 pages')
    drawn = pg.evaluate("(() => { const c = document.querySelector('canvas.vpage'); const d = c.getContext('2d').getImageData(0,0,c.width,c.height).data; let n=0; for (let i=0;i<d.length;i+=4) if (d[i]<128) n++; return [c.width, n]; })()")
    ok(drawn[0] > 300 and drawn[1] > 50, f'PDF page actually rendered (width {drawn[0]}, dark px {drawn[1]})')
    pg.screenshot(path=f'{OUT}/v3-pdf.png')
    pg.keyboard.press('Escape')
    ok(pg.locator('#viewer').count() == 0 and pg.locator('#overlay').count() == 1, 'Esc closes viewer but keeps entry open')

    # text + image
    pg.locator('.filecard', has_text='notes.txt').locator('button', has_text='Open').click()
    pg.wait_for_selector('.vtext'); ok('hello from a text file' in pg.locator('.vtext').inner_text(), 'text file opens')
    pg.locator('button[aria-label="Close viewer"]').click()
    pg.locator('.filecard', has_text='icon-512').locator('.fileopen').click()
    pg.wait_for_selector('.vimg'); pg.wait_for_timeout(300)
    ok(pg.evaluate("document.querySelector('.vimg').naturalWidth") == 512, 'tapping the file row opens image')
    pg.locator('button[aria-label="Close viewer"]').click()

    # phone signs in, sees the Excel
    ph_ctx, ph = mk(400, 860)
    ph.goto(B)
    ph.locator('input[type=password]').fill(PW); ph.get_by_text('Continue').click()
    ph.wait_for_selector('text=Check your email', timeout=30000); ph.get_by_text('Sign in', exact=True).click()
    ph.wait_for_selector('.row', timeout=30000)
    ph.locator('.row').first.click()
    ph.locator('.filecard', has_text='passwords.xlsx').locator('button', has_text='Open').click()
    ph.wait_for_selector('.vtable', timeout=30000)
    ok('hunter2!' in ph.locator('.vtable').inner_text(), 'phone opens the Excel too')
    ph.screenshot(path=f'{OUT}/v4-phone-excel.png')
    ph.locator('button[aria-label="Close viewer"]').click(); ph.locator('button[aria-label=Close]').click()

    # PC edits Excel and replaces it
    wb = openpyxl.load_workbook(f'{S}/passwords.xlsx'); wb['Passwords']['C2'] = 'NEWPASS-2026'; wb.save(f'{S}/passwords-v2.xlsx')
    with pg.expect_file_chooser() as fc:
        pg.locator('.filecard', has_text='passwords.xlsx').locator('button', has_text='Replace').click()
    fc.value.set_files(f'{S}/passwords-v2.xlsx')
    pg.wait_for_selector('.filecard:has-text("passwords-v2.xlsx")', timeout=30000)
    ok(pg.locator('.filecard').count() == 5, 'replace keeps the same number of files')
    ok('updated' in pg.locator('.filecard', has_text='passwords-v2').inner_text(), 'shows when the file was updated')
    pg.screenshot(path=f'{OUT}/v5-replaced.png')

    # phone comes back to the app -> refreshed
    ph.evaluate("document.dispatchEvent(new Event('visibilitychange'))"); ph.wait_for_timeout(1500)
    ph.locator('.row').first.click()
    ph.locator('.filecard', has_text='passwords-v2').locator('button', has_text='Open').click()
    ph.wait_for_selector('.vtable', timeout=30000)
    ok('NEWPASS-2026' in ph.locator('.vtable').inner_text(), 'phone gets the updated Excel automatically')
    br.close()

bad = [e for e in errs if 'Failed to load resource' not in e]
ok(not bad, 'no page errors: ' + '; '.join(bad[:4]))
print(f"\n{sum(c for c, _ in res)} passed, {sum(not c for c, _ in res)} failed")
