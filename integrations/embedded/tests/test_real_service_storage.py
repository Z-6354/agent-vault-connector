"""Real-service storage end-to-end: broker --local + mcp_apps + local_backend -> draft/confirm.

Proves a REAL (unregistered) service name flows through the whole chain with the
storage-only policy: origin = STORAGE_ONLY_ORIGIN, granted_operations = [], secret
stored exactly once, and only the redacted vault:// ref is returned to the model.
No /host/storage mock — the real broker route is exercised.
"""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from broker import Broker
from local_backend import LocalBackend, STORAGE_ONLY_ORIGIN
from local_store import LocalStoreAdapter

TOKEN = 'SYNTHETIC-APPS-ADMIN-TOKEN-' * 2
CID = '11111111-2222-4333-8444-555555555555'
SECRET = 'SYNTHETIC-REAL-SERVICE-SECRET'
EXT = 'io.modelcontextprotocol/ui'
MIME = 'text/html;profile=mcp-app'


class RealServiceStorage(unittest.TestCase):
    def test_real_service_flows_draft_confirm_with_storage_only(self):
        state = {'drafts': []}

        class Mgmt(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def send(self, code, value):
                data = json.dumps(value).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers(); self.wfile.write(data)
            def do_GET(self):
                if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
                    return self.send(401, {'error': 'x'})
                if self.path == '/management/session':
                    return self.send(200, {'authenticated': True, 'state': 'S2'})
                if self.path == '/management/connections':
                    return self.send(200, {'services': [{'service_id': 'synthetic-login', 'origin': 'http://127.0.0.1:43122', 'credential_types': ['password'], 'operations': []}]})
                return self.send(404, {'error': 'x'})
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
                if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
                    return self.send(401, {'error': 'x'})
                if self.path == '/management/drafts':
                    if self.headers.get('X-CSRF-Token') != 'csrf-token':
                        return self.send(403, {'error': 'x'})
                    state['drafts'].append(body)
                    return self.send(201, {'draft': {'draft_id': 'draft-1', 'draft_version': 1}, 'request_id': 'req-1'})
                if self.path == '/management/drafts/draft-1/confirm':
                    return self.send(200, {'connection': {'id': CID, 'status': 'active'}})
                return self.send(404, {'error': 'x'})

        mgmt = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Mgmt)
        threading.Thread(target=mgmt.serve_forever, daemon=True).start()
        backend = LocalBackend('http://127.0.0.1:%d' % mgmt.server_port, TOKEN)
        backend.session = 'synthetic-session'; backend.csrf = 'csrf-token'
        adapter = LocalStoreAdapter(backend=backend)
        broker = Broker(TOKEN, save_callback=adapter.save)
        threading.Thread(target=broker.serve_forever, daemon=True).start()
        process = None
        try:
            with tempfile.TemporaryDirectory(prefix='real-svc-') as tmp:
                discovery = Path(tmp) / 'broker.json'
                discovery.write_text(json.dumps({'origin': broker.origin, 'token': TOKEN}))
                env = os.environ.copy(); env['EMBEDDED_VAULT_DISCOVERY'] = str(discovery)
                process = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(ROOT / 'mcp_apps.py')],
                    env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf8')

                def call(i, method, params):
                    process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params}) + '\n')
                    process.stdin.flush()
                    return json.loads(process.stdout.readline())

                call(1, 'initialize', {'protocolVersion': '2025-11-25', 'capabilities': {'extensions': {EXT: {'mimeTypes': [MIME]}}}})
                call(2, 'tools/list', {})
                req = call(3, 'tools/call', {'name': 'request_secure_input', 'arguments': {'service': 'deepseek-api', 'account': 'main'}})
                self.assertNotIn('error', req); self.assertNotIn('isError', req.get('result', {}))
                sc = req['result']['structuredContent']
                self.assertEqual(sc['status'], 'pending')
                request_id = sc['request_id']
                frame = call(4, 'tools/call', {'name': 'secure_input_frame', 'arguments': {'request_id': request_id}})
                frame_url = frame['result']['structuredContent']['frame_url']
                data = json.dumps({'secret': SECRET}).encode()
                submit_req = urllib.request.Request(frame_url, data=data, headers={'Content-Type': 'text/plain', 'Origin': 'null'}, method='POST')
                with urllib.request.urlopen(submit_req, timeout=5) as resp:
                    submitted = json.loads(resp.read())
                self.assertEqual(submitted['status'], 'captured')
                result = call(5, 'tools/call', {'name': 'vault_input_result', 'arguments': {'request_id': request_id}})
                final = result['result']['structuredContent']
                self.assertEqual(final['status'], 'captured')
                self.assertEqual(final['ref'], 'vault://deepseek-api/main')
                # storage-only draft assertions
                self.assertEqual(len(state['drafts']), 1)
                self.assertEqual(state['drafts'][0]['service_id'], 'deepseek-api')
                self.assertEqual(state['drafts'][0]['secret'], SECRET)
                self.assertEqual(state['drafts'][0]['origin'], STORAGE_ONLY_ORIGIN)
                self.assertEqual(state['drafts'][0]['granted_operations'], [])
                self.assertNotIn(SECRET, json.dumps(result))
                process.stdin.close(); process.wait(timeout=10)
                self.assertEqual(process.stderr.read(), '')
        finally:
            if process and process.poll() is None:
                process.terminate(); process.wait(timeout=10)
            broker.close(); mgmt.shutdown(); mgmt.server_close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
