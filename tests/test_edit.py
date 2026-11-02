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
# Stand-in for Windows' "Save as" dialog: a real browser file handle in private storage.
MOCK = """
window.showSaveFilePicker = async (o) => {
  const d = await navigator.storage.getDirectory();
  window.__lastName = o.suggestedName;
  return d.getFileHandle(o.suggestedName, { create: true });
};
"""
with sync_playwright() as p:
    import tempfile
    ctx = p.chromium.launch_persistent_context(tempfile.mkdtemp(), channel='chromium', viewport={'width': 1280, 'height': 820}); br = ctx
    ctx.add_init_script(MOCK)
    pg = ctx.pages[0] if ctx.pages else ctx.new_page()
    pg.on('pageerror', lambda e: errs.append(str(e))); pg.on('crash', lambda: print('CRASH')); pg.on('close', lambda: print('CLOSED')); ctx.on('page', lambda np: print('NEWPAGE', np.url))
    pg.on('console', lambda m: errs.append(m.text) if m.type == 'error' else None)
    pg.goto(B)
    pg.get_by_text('Send me a code').click(); pg.wait_for_selector('text=Check your email')
    pw = pg.locator('input[type=password]'); pw.nth(0).fill(PW); pw.nth(1).fill(PW)
    pg.get_by_text('Create vault').click(); pg.wait_for_selector('text=Your vault is empty', timeout=30000)
    pg.locator('.fab').click(); pg.locator('.typepick button', has_text='Files').click()
    pg.locator('input[placeholder^="e.g."]').fill('Passwords')
    pg.locator('input[type=file]').set_input_files([f'{S}/notes.txt'])
    pg.locator('.sheet button', has_text='Save').click(); pg.wait_for_selector('.sheet h2:has-text("Passwords")', timeout=30000)

    pg.locator('.filecard').get_by_text('✏️ Edit').click()
    pg.wait_for_selector('.filecard button:has-text("Save changes")', timeout=15000); ok(True, 'Edit saves a copy and shows Save changes')
    local = pg.evaluate("(async () => (await (await (await navigator.storage.getDirectory()).getFileHandle('notes.txt')).getFile()).text())()")
    ok(local == 'hello from a text file\nline 2', 'copy on PC has the right contents')
    pg.screenshot(path=f'{OUT}/e1-editing.png')

    pg.locator('.filecard button', has_text='Save changes').click(); pg.wait_for_timeout(800)
    ok('No changes yet' in pg.locator('#toast').inner_text(), 'Save without editing says no changes')

    # "edit in Excel": change the local file
    pg.wait_for_timeout(1100)
    pg.evaluate("(async () => { const h = await (await navigator.storage.getDirectory()).getFileHandle('notes.txt'); const w = await h.createWritable(); await w.write('EDITED ON PC'); await w.close(); })()")
    pg.locator('.filecard button', has_text='Save changes').click()
    pg.wait_for_selector('#toast:has-text("Changes saved")', timeout=15000); ok(True, 'Save changes uploads the edit')
    pg.wait_for_selector('.filecard:has-text("notes.txt")')
    ok(pg.locator('.filecard', has_text='notes.txt').count() == 1, 'keeps the original file name')
    pg.locator('.filecard').get_by_text('Open').click(); pg.wait_for_selector('.vtext')
    ok(pg.locator('.vtext').inner_text() == 'EDITED ON PC', 'vault now has the edited version')
    pg.locator('button[aria-label="Close viewer"]').click()
    ok(pg.locator('.filecard button', has_text='Save changes').count() == 1, 'still in edit mode for the next round')

    # second round of edits
    pg.wait_for_selector('#toast.show', state='detached', timeout=10000)
    pg.evaluate("(async () => { const h = await (await navigator.storage.getDirectory()).getFileHandle('notes.txt'); const w = await h.createWritable(); await w.write('SECOND EDIT'); await w.close(); })()")
    pg.locator('.filecard button', has_text='Save changes').click(); pg.wait_for_selector('#toast:has-text("Changes saved")', timeout=15000)
    pg.wait_for_selector('.filecard button:has-text("Save changes"):not([disabled])')
    pg.locator('.filecard').get_by_text('Open').click(); pg.wait_for_selector('.vtext')
    ok(pg.locator('.vtext').inner_text() == 'SECOND EDIT', 'second save works too')
    pg.locator('button[aria-label="Close viewer"]').click()

    # survives lock / reload
    pg.reload(); pg.wait_for_selector('text=Vault locked')
    pg.locator('input[type=password]').fill(PW); pg.get_by_text('Unlock', exact=True).click(); pg.wait_for_selector('.row', timeout=30000)
    pg.locator('.row').first.click(); pg.wait_for_timeout(800)
    ok(pg.locator('.filecard button', has_text='Save changes').count() == 1, 'edit mode remembered after reload')

    # local copy deleted -> friendly message
    pg.evaluate("(async () => { await (await navigator.storage.getDirectory()).removeEntry('notes.txt'); })()")
    pg.locator('.filecard button', has_text='Save changes').click(); pg.wait_for_selector('#toast:has-text("find the copy")', timeout=15000)
    ok(pg.locator('.filecard button', has_text='Edit').count() == 1, 'missing local copy resets to Edit')

    # Done button
    pg.locator('.filecard button', has_text='Edit').click(); pg.wait_for_selector('.filecard button:has-text("Save changes")')
    pg.locator('.filecard').get_by_text('Stop editing', exact=True).click(); pg.wait_for_timeout(500)
    ok(pg.locator('.filecard button', has_text='Edit').count() == 1, 'Done stops edit mode')
    pg.screenshot(path=f'{OUT}/e2-done.png')
    br.close()

    # phone: no Edit button
    ctx2 = p.chromium.launch().new_context(viewport={'width': 400, 'height': 860}, user_agent='Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36')
    ph = ctx2.new_page(); ph.goto(B)
    ph.locator('input[type=password]').fill(PW); ph.get_by_text('Continue').click()
    ph.wait_for_selector('text=Check your email', timeout=30000); ph.get_by_text('Sign in', exact=True).click()
    ph.wait_for_selector('.row', timeout=30000); ph.locator('.row').first.click(); ph.wait_for_timeout(500)
    ok(ph.locator('.filecard button', has_text='Edit').count() == 0 and ph.get_by_text('Open').count() == 1, 'phone shows Open but no Edit')

bad = [e for e in errs if 'Failed to load resource' not in e]
ok(not bad, 'no page errors: ' + '; '.join(bad[:4]))
print(f"\n{sum(c for c, _ in res)} passed, {sum(not c for c, _ in res)} failed")
