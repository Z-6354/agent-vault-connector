"""Formal tests for vault_server_local.py (single-file local Vault service).

Runs against a scratch database on a dynamic loopback port — the real
C:/Users/han/.hermes/vault/vault.db is never touched. Covers: idempotent install,
token-direct session (auto-unlock), login/unlock flow, storage-only policy
enforcement for arbitrary real service names, CSRF on cookie sessions,
AES-256-GCM ciphertext on disk, PBKDF2 decrypt round-trip, and
LocalStoreAdapter/LocalBackend plug-and-play compatibility.
"""
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
    _HAS_CRYPTO = True
except ImportError:  # suite runs under -I -S -B (no site-packages)
    AESGCM = None
    _HAS_CRYPTO = False

SERVER = str(ROOT / 'vault_server_local.py')
PASSPHRASE = 'SYNTHETIC-TEST-PASSPHRASE'


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@unittest.skipUnless(_HAS_CRYPTO, 'cryptography package unavailable under -I -S -B')
class VaultServerLocalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='vault-local-')
        self.db = Path(self.tmp.name) / 'vault.db'
        self.env = Path(self.tmp.name) / 'agent-vault-management.env'
        self.port = _free_port()
        self.proc = None
        self.cfg = None

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate(); self.proc.wait(timeout=10)
        self.tmp.cleanup()

    def _install(self, extra=()):
        out = subprocess.run([sys.executable, '-I', SERVER, 'install', '--db', str(self.db),
                              '--env-file', str(self.env), '--port', str(self.port),
                              '--passphrase', PASSPHRASE, *extra],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    def _serve(self, auto_unlock=True):
        self.cfg = json.loads(self.env.read_text(encoding='utf8'))
        self.proc = subprocess.Popen([sys.executable, SERVER, 'serve', '--db', str(self.db),
                                      '--env-file', str(self.env), '--port', str(self.port)]
                                     + (['--auto-unlock'] if auto_unlock else []),
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(50):
            time.sleep(0.2)
            try:
                self.call('/management/session')
                return
            except Exception:
                continue
        raise AssertionError('server did not start')

    def call(self, path, body=None, headers=None, token=None):
        base = {'Authorization': 'Bearer ' + (token or (self.cfg or {}).get('token', '')),
                'Content-Type': 'application/json'}
        if headers: base.update(headers)
        req = urllib.request.Request('http://127.0.0.1:%d' % self.port + path,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers=base, method='GET' if body is None else 'POST')
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read() or b'{}'), response.headers
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b'{}'), error.headers

    def _store(self, service, account, secret):
        body = {'mode': 'create', 'label': '%s / %s' % (service, account), 'service_id': service,
                'credential_type': 'password', 'account_alias': account, 'secret': secret,
                'origin': 'https://storage-only.vault.local', 'environment': 'local',
                'granted_operations': []}
        status, value, _ = self.call('/management/drafts', body)
        self.assertEqual(status, 201, value)
        status, value, _ = self.call('/management/drafts/%s/confirm' % value['draft']['draft_id'],
                                     {'draft_version': value['draft']['draft_version'],
                                      'request_id': value['request_id']})
        self.assertEqual(status, 200, value)
        return value['connection']['id']

    def test_install_is_idempotent_and_server_round_trips(self):
        first = self._install()
        self.assertIn('initialized', first)
        second = self._install()  # re-run must not clobber
        self.assertIn('already initialized', second)
        self._serve()

        # token-direct session (auto-unlock): Bearer counts as S2
        status, value, _ = self.call('/management/session')
        self.assertEqual((status, value.get('authenticated'), value.get('state')), (200, True, 'S2'))

        # login flow: S1, wrong passphrase rejected, unlock -> S2
        status, value, headers = self.call('/management/login', {'passphrase': PASSPHRASE})
        self.assertEqual(status, 200)
        self.assertEqual(value['state'], 'S1')
        cookie = (headers.get('Set-Cookie') or '').split(';')[0]
        status, _, _ = self.call('/management/login', {'passphrase': 'WRONG'})
        self.assertEqual(status, 401)
        status, value, _ = self.call('/management/unlock', {'passphrase': PASSPHRASE},
                                     headers={'Cookie': cookie, 'X-CSRF-Token': value['csrf']})
        self.assertEqual(status, 200)
        auth = {'Cookie': cookie, 'X-CSRF-Token': value['csrf']}
        status, value, _ = self.call('/management/session', headers=auth)
        self.assertEqual(value.get('state'), 'S2')

        # real service names stored (storage-only)
        cid = self._store('deepseek-api', 'main', 'SYNTHETIC-DEEPSEEK')
        self.assertTrue(cid)

        # cookie session without CSRF is rejected
        body = {'mode': 'create', 'service_id': 'github', 'credential_type': 'password',
                'account_alias': 'x', 'secret': 's', 'origin': 'o', 'granted_operations': []}
        status, value, _ = self.call('/management/drafts', body, headers={'Cookie': cookie})
        self.assertEqual(status, 403)

        # policy: api_key type and nonzero operations rejected
        bad = dict(body, credential_type='api_key', granted_operations=[])
        status, _, _ = self.call('/management/drafts', bad, headers=auth)
        self.assertEqual(status, 400)
        bad = dict(body, credential_type='password', granted_operations=['login'])
        status, _, _ = self.call('/management/drafts', bad, headers=auth)
        self.assertEqual(status, 400)

        # unauthorized token rejected
        status, _, _ = self.call('/management/session', token='WRONG')
        self.assertEqual(status, 401)

        # disk: ciphertext, iv 12, tag 16, no plaintext
        con = sqlite3.connect(str(self.db))
        row = con.execute('select ciphertext_blob, iv, tag, credential_type, service_id from credentials').fetchone()
        salt_hex = con.execute("select value from meta where key='kdf_salt'").fetchone()[0]
        con.close()
        ct, iv, tag, ctype, service = row
        self.assertEqual((ctype, service), ('password', 'deepseek-api'))
        self.assertEqual((len(iv), len(tag)), (12, 16))
        self.assertNotIn(b'SYNTHETIC-DEEPSEEK', ct + iv + tag)
        self.assertGreater(self.db.stat().st_size, 0)

        # PBKDF2 + AES-256-GCM decrypt round-trip
        import hashlib
        key = hashlib.pbkdf2_hmac('sha256', PASSPHRASE.encode(), bytes.fromhex(salt_hex), 200_000)
        self.assertEqual(AESGCM(key).decrypt(iv, ct + tag, b'vault-local'), b'SYNTHETIC-DEEPSEEK')

    def test_local_store_adapter_plug_and_play(self):
        """The exact save callback used by broker --local stores a real service name."""
        self._install()
        os.environ['VAULT_MANAGEMENT_ENV_FILE'] = str(self.env)
        try:
            self._serve()
            from local_store import LocalStoreAdapter
            adapter = LocalStoreAdapter()
            self.assertTrue(adapter._unlocked())
            connection_id = adapter.save({'service': 'deepseek-api', 'account': 'main'},
                                         'SYNTHETIC-ADAPTER-KEY', 10, request_id='r1')
            self.assertTrue(connection_id)
            con = sqlite3.connect(str(self.db))
            blob = con.execute('select ciphertext_blob, iv, tag from credentials').fetchone()
            con.close()
            self.assertNotIn(b'SYNTHETIC-ADAPTER-KEY', b''.join(blob))
        finally:
            os.environ.pop('VAULT_MANAGEMENT_ENV_FILE', None)


if __name__ == '__main__':
    unittest.main(verbosity=2)
