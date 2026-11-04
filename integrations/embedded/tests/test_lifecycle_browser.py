"""Real Edge tests. Requires explicitly provided desktop playwright-core and Node.

All credentials are synthetic. The UI/controller/SQLite stack is real; the
third-party auth endpoint is a controlled local HTTP service, not a real account.
"""
import contextlib
import http.server
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
try:
    from lifecycle_core import LifecycleEngine
    from lifecycle_http import LifecycleController, make_server
    from credential_verifier import probe_and_verify_credential
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

@unittest.skipUnless(HAS_CRYPTO and os.environ.get('HERMES_DESKTOP_PACKAGE') and os.environ.get('NODE_BIN'),
                     'Set desktop package and NODE_BIN; requires cryptography (no -S)')
class LifecycleBrowser(unittest.TestCase):
    def test_card_modes_and_failure_feedback(self):
        result = subprocess.run([os.environ['NODE_BIN'], str(ROOT / 'tests/lifecycle_card_browser.mjs')],
            capture_output=True, text=True, encoding='utf8', timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('LIFECYCLE_CARD_BROWSER_OK 22 scenarios', result.stdout)
        print(result.stdout, end='')

    def test_real_controller_sqlite_and_nested_mcp_apps_bridge(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            class Upstream(http.server.BaseHTTPRequestHandler):
                def log_message(self, format, *args): pass
                def do_GET(self):
                    accepted = self.headers.get('Authorization') == 'Bearer SYNTHETIC-browser-good-credential'
                    data = json.dumps({'id': 123, 'login': 'synthetic'} if accepted else {'error': 'unauthorized'}).encode()
                    self.send_response(200 if accepted else 401)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers(); self.wfile.write(data)
            upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
            upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            upstream_thread.start()
            def transport(official_url, secret):
                # Explicit test seam: production verifier default still uses fixed HTTPS official URLs.
                request = urllib.request.Request('http://127.0.0.1:%d/user' % upstream.server_port,
                    headers={'Authorization': 'Bearer ' + secret})
                try:
                    with urllib.request.urlopen(request, timeout=3) as response:
                        return response.status, json.loads(response.read())
                except urllib.error.HTTPError as error:
                    code = error.code; error.close(); return code, None
            engine = LifecycleEngine(directory / 'vault.db', directory / 'vault_client.json',
                verifier=lambda s, a, p: probe_and_verify_credential(s, a, p, transport=transport))
            admin = 'SYNTHETIC-test-controller-token' * 2
            server = make_server(LifecycleController(engine), admin)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            env = os.environ.copy()
            env.update(LIFECYCLE_TEST_ORIGIN='http://127.0.0.1:%d' % server.server_port,
                       LIFECYCLE_TEST_ADMIN_TOKEN=admin)
            try:
                result = subprocess.run([env['NODE_BIN'], str(ROOT / 'tests/lifecycle_real_browser.mjs')],
                    env=env, capture_output=True, text=True, encoding='utf8', timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('LIFECYCLE_REAL_INTEGRATION_OK 5 flows', result.stdout)
                with contextlib.closing(sqlite3.connect(engine.db)) as con:
                    self.assertEqual(con.execute('SELECT count(*) FROM credentials').fetchone()[0], 2)
                    self.assertEqual(con.execute("SELECT count(*) FROM lifecycle_validation WHERE status='valid'").fetchone()[0], 2)
                self.assertNotIn(b'SYNTHETIC-browser-good-credential', engine.db.read_bytes())
                self.assertNotIn(b'SYNTHETIC-browser-master-password', engine.sessions.path.read_bytes())
                print(result.stdout, end='')
            finally:
                server.shutdown(); server.server_close(); thread.join(5)
                upstream.shutdown(); upstream.server_close(); upstream_thread.join(5)

if __name__ == '__main__': unittest.main(verbosity=2)
