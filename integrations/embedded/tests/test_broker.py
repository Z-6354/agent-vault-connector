"""Synthetic fixtures only; real loopback HTTP, no production Vault calls.
Run: python -I -S -B tests/test_broker.py
"""
import concurrent.futures
import contextlib
from http.client import HTTPConnection
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit
import uuid
from unittest import mock
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('embedded_broker', ROOT / 'broker.py')
assert spec is not None and spec.loader is not None
broker_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker_module)
SYNTHETIC_SECRET = 'synthetic-only-never-a-real-credential'
SYNTHETIC_REF = str(uuid.uuid4())


def http(origin, method, path, body=None, token=None, origin_header=None, extra=None) -> tuple[int, dict, Any]:
    address = urlsplit(origin)
    conn = HTTPConnection(address.hostname, address.port, timeout=5)
    headers = {'Content-Type': 'text/plain'}
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    if origin_header is not None:
        headers['Origin'] = origin_header
    headers.update(extra or {})
    data = json.dumps(body).encode() if body is not None else None
    try:
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        value = json.loads(raw) if response.getheader('Content-Type') == 'application/json' else raw
        return response.status, dict(response.getheaders()), value
    finally:
        conn.close()


class BrokerHTTPTests(unittest.TestCase):
    def setUp(self):
        self.token = secrets.token_urlsafe(32)
        self.saved = []
        def synthetic_save(metadata, secret, timeout):
            self.saved.append((metadata, secret, timeout))
            return SYNTHETIC_REF
        self.broker = broker_module.Broker(self.token, save_callback=synthetic_save)
        self.thread = threading.Thread(target=self.broker.serve_forever, daemon=True)
        self.thread.start()
        self.origin = self.broker.origin

    def tearDown(self):
        self.broker.server.shutdown()
        self.thread.join(3)
        self.broker.close()

    def call(self, method, path, body=None, *, admin=False, origin=None, **kwargs):
        return http(self.origin, method, path, body, self.token if admin else None, origin, **kwargs)

    def create(self, **overrides):
        data = dict(service='synthetic.example', account='test-user', prompt='Synthetic input', timeout_s=30)
        data.update(overrides)
        status, _, value = self.call('POST', '/requests', data, admin=True)
        self.assertEqual(status, 201, value)
        request_id = value['request_id']
        uuid.UUID(request_id)
        status, _, pending = self.call('GET', '/host/requests', admin=True)
        self.assertEqual(status, 200)
        item = next(item for item in pending['requests'] if item['request_id'] == request_id)
        frame = urlsplit(item['frame_url'])
        return request_id, frame.path + '?' + frame.query

    def result(self, request_id):
        status, _, result = self.call('GET', '/requests/' + request_id, admin=True)
        self.assertEqual(status, 200)
        self.assertNotIn(SYNTHETIC_SECRET, json.dumps(result))
        return result

    def test_admin_and_capability_isolation(self):
        request_id, card = self.create()
        _, second = self.create()
        for method, path, body in [('GET', '/host/requests', None), ('GET', '/requests/' + request_id, None),
                                    ('POST', '/requests', {})]:
            self.assertEqual(self.call(method, path, body)[0], 401)
            self.assertEqual(http(self.origin, method, path, body, 'unknown-token')[0], 401)
        for path in [card.split('?')[0], card + 'wrong', second.split('?')[0] + '?' + card.split('?')[1]]:
            status, headers, _ = self.call('GET', path + '&format=json', origin='null')
            self.assertEqual(status, 404)
            self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.assertEqual(self.call('GET', '/host/requests', admin=True, extra={'Host': 'attacker.example'})[0], 403)
        self.assertEqual(self.saved, [])

    def test_capture_null_origin_and_safe_get(self):
        request_id, card = self.create()
        status, headers, metadata = self.call('GET', card + '&format=json', origin='null')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Access-Control-Allow-Origin'], 'null')
        self.assertEqual(metadata, dict(request_id=request_id, service='synthetic.example', account='test-user',
                                        prompt='Synthetic input', status='pending', timeout_s=30))
        self.assertIn(self.origin, headers['Content-Security-Policy'])
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        status, headers, value = self.call('POST', card, {'secret': SYNTHETIC_SECRET}, origin='null')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Access-Control-Allow-Origin'], 'null')
        self.assertEqual(value, {'request_id': request_id, 'status': 'captured', 'ref': 'vault://synthetic.example/test-user'})
        self.assertEqual(self.result(request_id), value)
        self.assertEqual(self.call('GET', card + '&format=json', origin='null')[2]['ref'], 'vault://synthetic.example/test-user')
        self.assertNotIn(SYNTHETIC_SECRET, json.dumps(value))
        self.assertEqual(len(self.saved), 1)
        self.assertGreater(self.saved[0][2], 0)
        self.assertEqual(self.call('POST', card, {'secret': SYNTHETIC_SECRET}, origin='null')[0], 409)
        self.assertEqual(self.call('POST', card, {'declined': True}, origin='null')[0], 409)
        self.assertEqual(len(self.saved), 1)

    def test_origin_rejection_and_same_origin_allowed(self):
        request_id, card = self.create()
        for origin in [None, 'https://attacker.example', self.origin + '/', 'http://localhost:123']:
            self.assertEqual(self.call('POST', card, {'secret': SYNTHETIC_SECRET}, origin=origin)[0], 403)
        self.assertEqual(self.result(request_id)['status'], 'pending')
        self.assertEqual(self.call('POST', card, {'secret': SYNTHETIC_SECRET}, origin=self.origin)[0], 200)
        self.assertEqual(len(self.saved), 1)

    def test_cancel_and_expiry_irreversible(self):
        request_id, card = self.create()
        self.assertEqual(self.call('POST', card, {'declined': True}, origin='null')[2]['status'], 'declined')
        self.assertEqual(self.call('POST', card, {'secret': SYNTHETIC_SECRET}, origin='null')[0], 409)
        self.assertEqual(self.result(request_id)['status'], 'declined')
        expired_id, expired_card = self.create(timeout_s=0.04)
        time.sleep(0.08)
        self.assertEqual(self.call('POST', expired_card, {'secret': SYNTHETIC_SECRET}, origin='null')[0], 409)
        self.assertEqual(self.result(expired_id)['status'], 'expired')
        self.assertEqual(self.call('GET', '/host/requests', admin=True)[2]['requests'], [])
        self.assertEqual(self.saved, [])

    def test_concurrent_admission_only_one_side_effect(self):
        entered, release = threading.Event(), threading.Event()
        def synthetic_blocking(metadata, secret, timeout):
            self.saved.append(secret)
            entered.set()
            if not release.wait(2):
                raise ValueError('synthetic wait deadline')
            return SYNTHETIC_REF
        self.broker.save = synthetic_blocking
        request_id, card = self.create()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            first = pool.submit(self.call, 'POST', card, {'secret': SYNTHETIC_SECRET}, origin='null')
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.call('POST', card, {'secret': SYNTHETIC_SECRET}, origin='null')[0], 409)
                self.assertEqual(self.call('POST', card, {'declined': True}, origin='null')[0], 409)
                self.assertEqual(self.result(request_id)['status'], 'pending')
            finally:
                release.set()
            self.assertEqual(first.result(timeout=3)[0], 200)
        self.assertEqual(self.saved, [SYNTHETIC_SECRET])

    def test_save_failure_and_invalid_reference_never_leak_or_retry(self):
        for invalid_ref in [False, True]:
            def synthetic_failure(metadata, secret, timeout):
                self.saved.append(secret)
                if invalid_ref:
                    return secret
                raise RuntimeError(secret)
            self.broker.save = synthetic_failure
            request_id, card = self.create()
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                status, _, value = self.call('POST', card, {'secret': SYNTHETIC_SECRET}, origin='null')
            self.assertEqual(status, 502)
            self.assertEqual(value, {'error': 'save_failed'})
            self.assertEqual(stderr.getvalue(), '')
            self.assertEqual(self.result(request_id)['status'], 'declined')
            self.assertEqual(self.call('POST', card, {'secret': SYNTHETIC_SECRET}, origin='null')[0], 409)
        self.assertEqual(len(self.saved), 2)

    def test_invalid_types_and_size_are_json_errors(self):
        for data in [[], 'bad', 17, {'service': []}, {'service': 's', 'account': 'a', 'prompt': 'p', 'secret': SYNTHETIC_SECRET}]:
            status, _, value = self.call('POST', '/requests', data, admin=True)
            self.assertEqual(status, 400)
            self.assertIn('error', value)
        for ttl in [True, '30', [], 0, -1, 3601, float('nan'), float('inf')]:
            status, _, value = self.call('POST', '/requests', dict(service='s', account='a', prompt='p', timeout_s=ttl), admin=True)
            self.assertEqual(status, 400)
        request_id, card = self.create()
        for data in [{'secret': 1}, {'secret': []}, {'secret': ''}, {'declined': 1}, {'declined': True, 'secret': SYNTHETIC_SECRET}]:
            self.assertEqual(self.call('POST', card, data, origin='null')[0], 400)
        self.assertEqual(self.call('POST', card, {'secret': 'x' * 33000}, origin='null')[0], 413)
        self.assertEqual(self.result(request_id)['status'], 'pending')
        self.assertEqual(self.saved, [])

    def test_pending_limit(self):
        for _ in range(16):
            self.create()
        self.assertEqual(self.call('POST', '/requests', dict(service='s', account='a', prompt='p'), admin=True)[0], 429)

    def test_assets_if_parent_has_written_them(self):
        for name, path in [('card.html', None), ('card.js', '/assets/card.js'), ('card.css', '/assets/card.css')]:
            if path is None:
                _, path = self.create()
            status, headers, value = self.call('GET', path)
            source = broker_module.WEB / name
            if source.exists():
                self.assertEqual(status, 200)
                self.assertEqual(value, source.read_bytes())
            else:
                self.assertEqual(status, 404)
            self.assertEqual(headers['Cache-Control'], 'no-store')


class CLIHTTPTests(unittest.TestCase):
    def test_subprocess_startup_discovery_and_admin_auth(self):
        scratch = Path(os.environ.get('TMPDIR') or Path(__file__).resolve().parent)
        with tempfile.TemporaryDirectory(prefix='synthetic-broker-', dir=scratch) as directory:
            discovery = Path(directory) / 'discovery.json'
            proc = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(ROOT / 'broker.py'), '--serve',
                                     '--discovery-file', str(discovery)], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            try:
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(proc.stdout.readline)
                    # The CLI is expected to become ready promptly; no process-wide wait.
                    try:
                        ready = json.loads(future.result(timeout=5))
                    except Exception:
                        proc.kill()
                        raise
                self.assertEqual(set(ready), {'status', 'origin'})
                self.assertEqual(ready['status'], 'ready')
                private = json.loads(discovery.read_text())
                self.assertEqual(private['origin'], ready['origin'])
                self.assertNotIn(private['token'], json.dumps(ready))
                self.assertEqual(http(ready['origin'], 'GET', '/host/requests')[0], 401)
                self.assertEqual(http(ready['origin'], 'GET', '/host/requests', token='unknown')[0], 401)
                status, _, value = http(ready['origin'], 'GET', '/host/requests', token=private['token'])
                self.assertEqual((status, value), (200, {'requests': []}))
                if os.name != 'nt':
                    self.assertEqual(discovery.stat().st_mode & 0o777, 0o600)
            finally:
                proc.terminate()
                _, stderr = proc.communicate(timeout=5)
                self.assertEqual(stderr, '')
                # Forced process termination cannot execute Python cleanup on Windows.


if __name__ == '__main__':
    unittest.main(verbosity=2)
