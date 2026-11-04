"""Behavior tests: real SQLite, real loopback HTTP/MCP, controlled upstream auth."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
try:
    from lifecycle_core import LifecycleEngine, LifecycleError, SessionFile
    from lifecycle_http import LifecycleController, make_server
    from credential_verifier import probe_and_verify_credential
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

PASSWORD = 'SYNTHETIC-master-passphrase'
SECRET = 'SYNTHETIC-service-credential'

@unittest.skipUnless(HAS_CRYPTO, 'Requires cryptography (run without -S)')
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / 'vault.db'
        self.session = self.root / 'vault_client.json'
        self.engine = LifecycleEngine(self.db, self.session)

    def create(self):
        return self.engine.create('owner', PASSWORD, PASSWORD, consent=True)

    def rows(self):
        with contextlib.closing(sqlite3.connect(self.db)) as con:
            return con.execute('SELECT * FROM credentials').fetchall()

    def test_probe_and_guide_never_create_without_consent(self):
        self.assertEqual(self.engine.guide()['status'], 'needs_target')
        self.assertEqual(self.engine.guide(target='local')['status'], 'needs_create_consent')
        self.assertFalse(self.db.exists())
        spec = self.engine.guide(target='local', consent=True)
        self.assertEqual((spec['mode'], spec['account'], spec['name']), ('create', '', ''))
        self.assertFalse(self.db.exists())
        with self.assertRaises(LifecycleError):
            self.engine.create('owner', PASSWORD, PASSWORD)
        self.assertFalse(self.db.exists())

    def test_create_requires_matching_passwords(self):
        with self.assertRaises(LifecycleError):
            self.engine.create('owner', PASSWORD, PASSWORD + 'x', consent=True)
        self.assertFalse(self.db.exists())

    def test_session_survives_restart_without_storing_master_password(self):
        self.assertEqual(self.create()['status'], 'ready')
        self.assertNotIn(PASSWORD.encode(), self.session.read_bytes())
        self.assertNotIn(PASSWORD.encode(), self.db.read_bytes())
        restarted = LifecycleEngine(self.db, self.session)
        self.assertEqual(restarted.status()['status'], 'ready')
        self.assertEqual(restarted.guide()['status'], 'ready')
        self.assertEqual(restarted.guide(target='local')['status'], 'needs_login_consent')
        self.assertEqual(restarted.revoke()['status'], 'needs_login')
        self.assertNotEqual(restarted.status()['status'], 'ready')

    def test_wrong_relogin_preserves_current_session(self):
        self.create()
        before = self.session.read_bytes()
        with self.assertRaises(LifecycleError):
            self.engine.login('owner', 'Wrong-Password')
        self.assertEqual(self.session.read_bytes(), before)
        self.assertEqual(self.engine.status()['status'], 'ready')
        self.assertEqual(self.engine.login('owner', PASSWORD)['status'], 'ready')

    def test_damaged_database_not_treated_as_empty(self):
        self.db.write_bytes(b'damaged database')
        self.assertEqual(self.engine.probe()['status'], 'incompatible')
        with self.assertRaises(LifecycleError): self.create()
        self.assertEqual(self.db.read_bytes(), b'damaged database')

    def test_cloud_timeout_offers_network_hint_without_creating(self):
        def timeout(*args, **kwargs): raise LifecycleError('remote_unreachable')
        self.engine.remote = timeout
        result = self.engine.guide(target='cloud', origin='https://vault.example')
        self.assertEqual(result['status'], 'unreachable')
        self.assertIn('3210', result['message'])
        self.assertFalse(self.db.exists())

    def test_cloud_unauthorized_is_not_missing_database(self):
        self.engine.remote = lambda *a, **kw: (401, {})
        self.assertEqual(self.engine.guide(target='cloud', origin='https://vault.example')['status'], 'unauthorized')
        self.assertFalse(self.db.exists())

    def test_switch_intents_reopen_login_and_cancel_keeps_session(self):
        self.create()
        before = self.session.read_bytes()
        spec = self.engine.guide(intent='switch_account', consent=True)
        self.assertEqual(spec['mode'], 'login')
        self.assertEqual(self.engine.guide(intent='switch_server')['status'], 'needs_target')
        self.assertEqual(self.session.read_bytes(), before)

    def test_auth_rejection_removes_only_new_candidate(self):
        self.create()
        self.engine.verify = lambda *a: {'status': 'valid', 'message': 'OK'}
        self.assertEqual(self.engine.save_and_verify('github', 'main', SECRET)['status'], 'valid')
        previous = self.rows()
        self.engine.verify = lambda *a: {'status': 'rejected', 'message': 'reenter'}
        result = self.engine.save_and_verify('github', 'main', 'SYNTHETIC-wrong')
        self.assertEqual(result['status'], 'rejected')
        self.assertNotIn('ref', result)
        self.assertEqual(self.rows(), previous)

    def test_real_probe_runs_after_encrypted_disk_write(self):
        self.create()
        def controlled_http(url, secret):
            rows = self.rows()
            self.assertEqual(len(rows), 1)
            self.assertNotIn(secret.encode(), self.db.read_bytes())
            self.assertEqual((len(rows[0][5]), len(rows[0][6])), (12, 16))
            self.assertEqual(url, 'https://api.deepseek.com/models')
            return 200, {'object': 'list', 'data': []}
        self.engine.verify = lambda service, account, secret: probe_and_verify_credential(
            service, account, secret, transport=controlled_http)
        result = self.engine.save_and_verify('deepseek-api', 'main', SECRET)
        self.assertEqual(result['ref'], 'vault://deepseek-api/main')
        self.assertNotIn(SECRET, json.dumps(result))

    def test_transient_failure_and_unsupported_never_claim_valid(self):
        self.create()
        self.engine.verify = lambda s, a, p: probe_and_verify_credential(s, a, p,
            transport=lambda *args: (429, None))
        result = self.engine.save_and_verify('github', 'main', SECRET)
        self.assertEqual(result['status'], 'validation_unavailable')
        self.assertNotIn('ref', result)
        other = self.engine.save_and_verify('custom-service', 'main', 'tiny')
        self.assertEqual(other['status'], 'validation_unsupported')
        self.assertEqual(len(self.rows()), 2)

    def test_github_needs_upstream_auth_not_just_token_prefix(self):
        result = probe_and_verify_credential('github', 'main', 'ghp_SYNTHETIC',
            transport=lambda *args: (401, None))
        self.assertEqual(result['status'], 'rejected')
        denied = probe_and_verify_credential('github', 'main', SECRET,
            transport=lambda *args: (403, None))
        self.assertEqual(denied['status'], 'validation_unavailable')
        result = probe_and_verify_credential('github', 'main', SECRET,
            transport=lambda *args: (200, {'id': 123, 'login': 'synthetic'}))
        self.assertEqual(result['status'], 'valid')

    def test_http_capability_submit_is_idempotent_and_stale_cards_rejected(self):
        self.create()
        self.engine.verify = lambda *a: {'status': 'valid', 'message': 'OK'}
        ctl = LifecycleController(self.engine)
        one = ctl.credential({'service': 'github', 'account': 'main'})
        cap = ctl.frame(one['request_id'], 'http://127.0.0.1:1')['frame_url'].rsplit('/', 1)[1]
        self.assertEqual(ctl.context(cap)['mode'], 'credential')
        body = {'service': 'github', 'account': 'main', 'secret': SECRET}
        result = ctl.submit(cap, body)
        self.assertEqual(ctl.submit(cap, body), result)
        self.assertEqual(len(self.rows()), 1)
        two = ctl.credential({'service': 'github'})
        othercap = ctl.frame(two['request_id'], 'http://127.0.0.1:1')['frame_url'].rsplit('/', 1)[1]
        self.engine.login('owner', PASSWORD)
        with self.assertRaises(LifecycleError): ctl.submit(othercap, body)
        self.assertEqual(len(self.rows()), 1)

    def test_real_http_and_mcp_creation_flow(self):
        ctl = LifecycleController(self.engine)
        token = 'SYNTHETIC-controller-token-' * 2
        server = make_server(ctl, token)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(5)))
        origin = 'http://127.0.0.1:%d' % server.server_port
        discovery = self.root / 'discovery.json'
        SessionFile(discovery).save({'origin': origin, 'token': token})
        env = os.environ.copy(); env['VAULT_LIFECYCLE_DISCOVERY'] = str(discovery)
        proc = subprocess.Popen([sys.executable, str(ROOT / 'lifecycle_mcp.py')], env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf8')
        def cleanup():
            if proc.poll() is None: proc.terminate(); proc.wait(10)
            for stream in (proc.stdin, proc.stdout, proc.stderr): stream.close()
        self.addCleanup(cleanup)
        def rpc(i, method, params):
            proc.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params}) + '\n')
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())
        rpc(1, 'initialize', {'capabilities': {'extensions': {'io.modelcontextprotocol/ui': {'mimeTypes': ['text/html;profile=mcp-app']}}}})
        tools = rpc(2, 'tools/list', {})['result']['tools']
        self.assertFalse(any('passphrase' in t['inputSchema']['properties'] or 'secret' in t['inputSchema']['properties'] for t in tools))
        def tool(i, name, args): return rpc(i, 'tools/call', {'name': name, 'arguments': args})
        first = tool(3, 'vault_guide', {})
        self.assertEqual(first['result']['structuredContent']['status'], 'needs_target')
        created = tool(4, 'vault_guide', {'target': 'local', 'consent': True})
        request_id = created['result']['structuredContent']['request_id']
        self.assertNotIn('frame_url', json.dumps(created))
        self.assertFalse(self.db.exists())
        frame = tool(5, 'vault_lifecycle_frame', {'request_id': request_id})['result']['structuredContent']['frame_url']
        req = urllib.request.Request(frame + '/submit', data=json.dumps({'account': 'owner',
            'passphrase': PASSWORD, 'confirm_passphrase': PASSWORD, 'name': ''}).encode(),
            headers={'Origin': 'null', 'Content-Type': 'text/plain'})
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read())
        self.assertEqual(result['status'], 'ready')
        final = tool(6, 'vault_lifecycle_result', {'request_id': request_id})
        self.assertEqual(final['result']['structuredContent']['status'], 'ready')
        self.assertNotIn(PASSWORD, json.dumps(final))
        self.assertNotIn('token', json.dumps(final))
        bad = tool(7, 'vault_guide', {'passphrase': PASSWORD})
        self.assertIn('error', bad)
        self.assertEqual(self.engine.status()['status'], 'ready')

if __name__ == '__main__': unittest.main(verbosity=2)
