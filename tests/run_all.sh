#!/usr/bin/env bash
# Runs every test against a fresh local server. Needs: Node 18+, Python 3 with playwright, openpyxl, reportlab.
set -e
cd "$(dirname "$0")/.."
npm install --no-audit --no-fund >/dev/null
printf 'DEV_MODE=1\n' > .dev.vars      # email codes are shown on screen instead of sent
npx wrangler d1 execute vaultbit --local --file=schema.sql >/dev/null
python3 tests/make_fixtures.py
npx wrangler dev --port 8787 --ip 127.0.0.1 >/tmp/vaultbit-dev.log 2>&1 &
SERVER=$!; trap 'kill $SERVER 2>/dev/null || true' EXIT
until curl -s localhost:8787/api/status >/dev/null; do sleep 1; done
reset() { npx wrangler d1 execute vaultbit --local --command "DELETE FROM meta; DELETE FROM items; DELETE FROM chunks; DELETE FROM sessions; DELETE FROM challenges; DELETE FROM ratelimit;" >/dev/null; }
reset; node tests/api.test.mjs
for t in ui view edit bio backup; do reset; echo "== $t"; python3 tests/test_$t.py; done
