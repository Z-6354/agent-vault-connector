"""Actual TLS, remote SQLite and native protected client session integration.

A generated local test certificate is trusted explicitly, never with CERT_NONE.
Third-party authentication responses are controlled; TLS/HTTP/database are real.
"""
import contextlib
import datetime
import ipaddress
from pathlib import Path
import sqlite3
import ssl
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from lifecycle_core import LifecycleEngine, LifecycleError, SessionFile, RemoteClient
    from lifecycle_remote import make_remote_server
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

PASSWORD = 'SYNTHETIC-Cloud-Master-Passphrase'
BOOTSTRAP = 'SYNTHETIC-Operator-Provisioning-Token' * 2

@unittest.skipUnless(HAS_CRYPTO, 'Requires cryptography, run without -S')
class RemoteLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Vault integration test')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = self.root / 'cert.pem', self.root / 'private.pem'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        self.remote = LifecycleEngine(self.root / 'remote.db', self.root / 'remote-session.json',
            verifier=lambda *args: {'status': 'valid', 'message': 'controlled-auth-success'})
        self.server = make_remote_server(self.remote, BOOTSTRAP, ctx)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), self.server.server_close(), self.thread.join(5)))
        self.origin = 'https://127.0.0.1:%d' % self.server.server_port
        self.targets_path = self.root / 'targets.json'
        self.client = LifecycleEngine(self.root / 'local.db', self.root / 'vault_client.json',
            remote=RemoteClient(self.targets_path, tls_context=ssl.create_default_context(cafile=str(cert_path))))

    def test_cloud_create_persists_only_remote_ciphertext_and_resumes(self):
        self.assertEqual(self.client.guide(target='cloud', origin=self.origin)['status'], 'needs_create_consent')
        self.assertFalse(self.remote.db.exists())
        with self.assertRaises(LifecycleError):
            self.client.create('owner', PASSWORD, PASSWORD, target='cloud', origin=self.origin, consent=True)
        self.assertFalse(self.remote.db.exists())
        SessionFile(self.targets_path).save({self.origin: BOOTSTRAP})
        created = self.client.create('owner', PASSWORD, PASSWORD, target='cloud', origin=self.origin, consent=True)
        self.assertEqual(created['status'], 'ready')
        self.assertNotIn('token', created)
        secret = 'SYNTHETIC-CLOUD-GITHUB-CREDENTIAL'
        self.assertEqual(self.client.save_and_verify('github', 'main', secret)['ref'], 'vault://github/main')
        self.assertFalse(self.client.db.exists())
        self.assertNotIn(secret.encode(), self.remote.db.read_bytes())
        self.assertNotIn(PASSWORD.encode(), self.client.sessions.path.read_bytes())
        self.assertNotIn(BOOTSTRAP.encode(), self.client.sessions.path.read_bytes())
        with contextlib.closing(sqlite3.connect(self.remote.db)) as con:
            self.assertEqual(con.execute('SELECT count(*) FROM credentials').fetchone()[0], 1)
        # New client instance restores remote token through actual TLS auth.
        restored = LifecycleEngine(self.client.db, self.client.sessions.path, remote=self.client.remote)
        self.assertEqual(restored.status()['status'], 'ready')
        self.remote.verify = lambda *args: {'status': 'rejected', 'message': 'controlled-401'}
        denied = restored.save_and_verify('github', 'main', 'SYNTHETIC-INVALID')
        self.assertEqual(denied['status'], 'rejected')
        with contextlib.closing(sqlite3.connect(self.remote.db)) as con:
            self.assertEqual(con.execute('SELECT count(*) FROM credentials').fetchone()[0], 1)

    def test_switch_local_to_cloud_requires_login_success_before_replacing_session(self):
        self.remote.create('cloud-owner', PASSWORD, PASSWORD, consent=True)
        self.client.create('local-owner', PASSWORD, PASSWORD, consent=True)
        original = self.client.sessions.path.read_bytes()
        guide = self.client.guide(intent='switch_server', target='cloud', origin=self.origin, consent=True)
        self.assertEqual(guide['mode'], 'login')
        with self.assertRaises(LifecycleError):
            self.client.login('cloud-owner', 'SYNTHETIC-wrong-password', target='cloud', origin=self.origin)
        self.assertEqual(original, self.client.sessions.path.read_bytes())
        result = self.client.login('cloud-owner', PASSWORD, target='cloud', origin=self.origin)
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(self.client.sessions.load()['target'], 'cloud')
        self.assertEqual(self.client.status()['status'], 'ready')

if __name__ == '__main__': unittest.main(verbosity=2)
