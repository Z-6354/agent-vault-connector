"""MCP boundary tests against a controlled HTTP broker, never production Vault."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT=Path(__file__).resolve().parents[1]
MARKER='SYNTHETIC-BROKER-SECRET-NOT-IN-MCP'
class BoundaryTests(unittest.TestCase):
    def run_case(self,state='captured',bad_ref=False):
        audit=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                audit.append(('POST',self.path,self.headers.get('Authorization')))
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps({'status':'pending','request_id':'fixture-id','secret':MARKER}).encode())
            def do_GET(self):
                audit.append(('GET',self.path,self.headers.get('Authorization')))
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps({'status':state,'request_id':'fixture-id','ref':'vault://wrong' if bad_ref else 'vault://github/main','secret':MARKER,'token':MARKER}).encode())
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            with tempfile.TemporaryDirectory(prefix='embedded-mcp-') as tmp:
                token='synthetic-host-token-'*3
                discovery=Path(tmp)/'broker.json';discovery.write_text(json.dumps({'origin':f'http://127.0.0.1:{server.server_port}','token':token}))
                env=os.environ.copy();env['EMBEDDED_VAULT_DISCOVERY']=str(discovery)
                requests=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
                          {'jsonrpc':'2.0','id':2,'method':'tools/list'},
                          {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'request_secure_input','arguments':{'service':'github','account':'main','mode':'embedded','timeout_s':2}}}]
                process=subprocess.run([sys.executable,'-I','-S','-B',str(ROOT/'mcp_stdio.py')],input='\n'.join(json.dumps(r) for r in requests)+'\n',env=env,capture_output=True,text=True,timeout=10)
                self.assertEqual(process.returncode,0);self.assertEqual(process.stderr,'')
                self.assertNotIn(MARKER,process.stdout+process.stderr);self.assertNotIn(token,process.stdout+process.stderr)
                rows=[json.loads(line) for line in process.stdout.splitlines()]
                self.assertEqual(rows[1]['result']['tools'][0]['name'],'request_secure_input')
                result=json.loads(rows[2]['result']['content'][0]['text'])
                self.assertTrue(all(row[2]=='Bearer '+token for row in audit))
                return result,audit
        finally:server.shutdown();server.server_close()
    def test_captured_reference_only_over_actual_mcp_subprocess(self):
        result,audit=self.run_case()
        self.assertEqual(result['status'],'captured');self.assertEqual(result['ref'],'vault://github/main')
        self.assertEqual({row[0] for row in audit},{'GET','POST'})
        self.assertFalse({'secret','password','token'}&set(result))
    def test_declined_is_terminal(self):
        result,_=self.run_case('declined');self.assertEqual(result['status'],'declined');self.assertNotIn('ref',result)
    def test_expired_is_terminal(self):
        result,_=self.run_case('expired');self.assertEqual(result['status'],'expired')
    def test_unconfirmed_or_wrong_reference_never_reports_capture(self):
        for state,bad_ref in [('captured',True),('error',False)]:
            with self.subTest(state=state,bad_ref=bad_ref):
                result,_=self.run_case(state,bad_ref);self.assertEqual(result['status'],'error')

if __name__=='__main__':unittest.main(verbosity=2)
