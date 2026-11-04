"""MCP Apps transport exercised against the REAL loopback broker; no simulated endpoints.

The broker is imported and served in-process, so /host/storage, /requests and the card
submit path are the real production routes — a mock cannot mask a missing endpoint here.
"""
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

EXT = 'io.modelcontextprotocol/ui'
MIME = 'text/html;profile=mcp-app'
RESOURCE = 'ui://agent-vault/secure-input'
TOKEN = 'SYNTHETIC-APPS-ADMIN-TOKEN-' * 2  # 54 ASCII chars, >= 32
CID = '11111111-2222-4333-8444-555555555555'
SECRET = 'SYNTHETIC-APPS-SECRET'


def _synthetic_save(metadata, secret, remaining, request_id=None):
    # Valid UUID; the broker derives vault://<service>/<account> from metadata itself.
    return CID


class AppsProtocol(unittest.TestCase):
    def _exercise(self, support=True, local=True):
        save_callback = _synthetic_save if local else None
        broker = Broker(TOKEN, save_callback=save_callback)
        threading.Thread(target=broker.serve_forever, daemon=True).start()
        process = None
        try:
            with tempfile.TemporaryDirectory(prefix='apps-real-broker-') as tmp:
                discovery = Path(tmp) / 'broker.json'
                discovery.write_text(json.dumps({'origin': broker.origin, 'token': TOKEN}))
                env = os.environ.copy()
                env['EMBEDDED_VAULT_DISCOVERY'] = str(discovery)
                process = subprocess.Popen(
                    [sys.executable, '-I', '-S', '-B', str(ROOT / 'mcp_apps.py')],
                    env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding='utf8')

                def call(i, method, params):
                    process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params}) + '\n')
                    process.stdin.flush()
                    row = json.loads(process.stdout.readline())
                    self.assertEqual(row.get('id'), i)
                    self.assertNotIn('error', row)
                    return row['result']

                caps = {'extensions': {EXT: {'mimeTypes': [MIME]}}} if support else {}
                call(1, 'initialize', {'protocolVersion': '2025-11-25', 'capabilities': caps})
                tools = call(2, 'tools/list', {})
                call(3, 'resources/list', {})
                resource = call(4, 'resources/read', {'uri': RESOURCE})
                request = call(5, 'tools/call', {'name': 'request_secure_input', 'arguments': {'service': 'github', 'account': 'main'}})
                out = {'tools': tools, 'resource': resource, 'request': request}

                # Only the success path continues through frame -> submit -> result.
                if not request.get('isError'):
                    sc = request.get('structuredContent', {})
                    request_id = sc.get('request_id')
                    frame = call(6, 'tools/call', {'name': 'secure_input_frame', 'arguments': {'request_id': request_id}})
                    frame_url = frame['structuredContent']['frame_url']
                    data = json.dumps({'secret': SECRET}).encode()
                    submit_req = urllib.request.Request(frame_url, data=data,
                        headers={'Content-Type': 'text/plain', 'Origin': 'null'}, method='POST')
                    with urllib.request.urlopen(submit_req, timeout=5) as resp:
                        submitted = json.loads(resp.read())
                    result = call(7, 'tools/call', {'name': 'vault_input_result', 'arguments': {'request_id': request_id}})
                    out.update(request_id=request_id, frame=frame, frame_url=frame_url,
                               submitted=submitted, result=result)
                process.stdin.close()
                process.wait(timeout=10)
                self.assertEqual(process.stderr.read(), '')
                return out
        finally:
            if process:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                for pipe in (process.stdin, process.stdout, process.stderr):
                    if pipe and not pipe.closed:
                        pipe.close()
            broker.close()

    def test_native_resource_contract_and_request_creation_through_real_broker(self):
        r = self._exercise()
        tools = r['tools']['tools']
        self.assertEqual(tools[0]['_meta']['ui']['resourceUri'], RESOURCE)
        self.assertEqual(tools[0]['_meta']['ui']['visibility'], ['model'])
        self.assertEqual(tools[2]['name'], 'secure_input_frame')
        self.assertEqual(tools[2]['_meta']['ui']['visibility'], ['app'])
        resource = r['resource']['contents'][0]
        self.assertEqual(resource['mimeType'], MIME)
        self.assertIn('ui/initialize', resource['text'])
        self.assertEqual(resource['_meta']['ui']['csp']['connectDomains'], [])
        # Model-visible request result carries only request_id, never frame capability or secret.
        sc = r['request']['structuredContent']
        self.assertEqual(sc['status'], 'pending')
        self.assertNotIn('frame_url', json.dumps(r['request']))
        self.assertNotIn(SECRET, json.dumps(r['request']))
        # The frame capability is available only through the app-only tool.
        self.assertIn('?key=', r['frame_url'])
        self.assertEqual(r['frame']['structuredContent']['request_id'], r['request_id'])
        # Real broker submit -> captured, and the result is a redacted ref.
        self.assertEqual(r['submitted']['status'], 'captured')
        final = r['result']['structuredContent']
        self.assertEqual(final['status'], 'captured')
        self.assertEqual(final['ref'], 'vault://github/main')
        self.assertNotIn(SECRET, json.dumps(r['result']))

    def test_unsupported_host_does_not_create_an_orphan_request(self):
        r = self._exercise(support=False)
        self.assertTrue(r['request']['isError'])
        self.assertIn('native_inline_not_supported', r['request']['content'][0]['text'])

    def test_remote_storage_is_rejected_before_request_creation(self):
        # Real broker without a save_callback reports location=remote; mcp_apps refuses.
        r = self._exercise(local=False)
        self.assertTrue(r['request']['isError'])
        self.assertIn('local_storage_required', r['request']['content'][0]['text'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
