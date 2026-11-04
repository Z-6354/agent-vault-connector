"""Actual MCP -> actual broker -> opaque browser iframe -> synthetic Vault save.
Set HERMES_DESKTOP_PACKAGE to the desktop package.json and VAULT_MCP_SOURCE to the shared MCP.
Browser test uses installed Playwright + Edge, does not install or access production credentials.
"""
import functools
import http.server
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('broker_e2e',ROOT/'broker.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class InlineBrowser(unittest.TestCase):
    def test_real_mcp_card_save_reference_only_and_no_popup(self):
        if not os.environ.get('HERMES_DESKTOP_PACKAGE') or not os.environ.get('VAULT_MCP_SOURCE'):
            self.skipTest('Set explicit desktop package and MCP source paths for real browser integration')
        saved=[]
        def save(metadata,secret,timeout):
            saved.append((metadata,secret));return '11111111-2222-4333-8444-555555555555'
        token='SYNTHETIC-INLINE-ADMIN-TOKEN-'*2
        broker=module.Broker(token,save_callback=save)
        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self,format,*args):pass
        host=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=str(ROOT)))
        for server in (broker.server,host):threading.Thread(target=server.serve_forever,daemon=True).start()
        process=None
        try:
            with tempfile.TemporaryDirectory(prefix='inline-e2e-') as tmp:
                discovery=Path(tmp)/'broker.json';discovery.write_text(json.dumps({'origin':broker.origin,'token':token}))
                env=os.environ.copy();env['EMBEDDED_VAULT_DISCOVERY']=str(discovery)
                process=subprocess.Popen([sys.executable,'-I','-S','-B',env['VAULT_MCP_SOURCE']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf8',env=env)
                def call(id,method,params):
                    process.stdin.write(json.dumps({'jsonrpc':'2.0','id':id,'method':method,'params':params})+'\n');process.stdin.flush()
                    row=json.loads(process.stdout.readline());self.assertEqual(row.get('id'),id);self.assertNotIn('error',row)
                    return row['result']
                call(1,'initialize',{'protocolVersion':'2025-11-25'})
                schema=call(100,'tools/list',{})
                tools={tool['name']:tool for tool in schema['tools']}
                modes=tools['request_secure_input']['inputSchema']['properties']['mode']['enum']
                self.assertEqual(set(modes),{'auto','inline','console'})
                self.assertIn('vault_input_result',tools)
                result=call(2,'tools/call',{'name':'request_secure_input','arguments':{'service':'synthetic.example','account':'test-user','mode':'inline','timeout_s':90}})
                pending=json.loads(result['content'][0]['text']);self.assertEqual(pending['status'],'pending')
                self.assertIn('::vault-input{request_id=',pending['next_action']);self.assertNotIn('key=',json.dumps(pending))
                req=urllib.request.Request(broker.origin+'/host/requests',headers={'Authorization':'Bearer '+token})
                with urllib.request.urlopen(req) as response:requests=json.load(response)['requests']
                env.update(HOST_URL=f'http://127.0.0.1:{host.server_port}',CARD_REQUEST=json.dumps(requests[0]))
                browser=subprocess.run([env.get('NODE_BIN','node'),str(ROOT/'tests/inline_browser.mjs')],env=env,capture_output=True,text=True,timeout=60)
                self.assertEqual(browser.returncode,0,browser.stdout+browser.stderr)
                print(browser.stdout.strip())
                result=call(3,'tools/call',{'name':'vault_input_result','arguments':{'request_id':pending['request_id']}})
                final=json.loads(result['content'][0]['text']);self.assertEqual(final['status'],'captured');self.assertEqual(final['ref'],'vault://synthetic.example/test-user')
                self.assertNotIn('SYNTHETIC-INLINE-E2E-ONLY',json.dumps(final));self.assertNotIn(token,json.dumps(final))
                self.assertEqual(len(saved),1);self.assertEqual(saved[0][1],'SYNTHETIC-INLINE-E2E-ONLY')
                process.stdin.close();process.wait(timeout=10);self.assertEqual(process.stderr.read(),'')
        finally:
            if process and process.poll() is None:process.terminate();process.wait(timeout=10)
            if process:
                for stream in (process.stdin,process.stdout,process.stderr):
                    if stream and not stream.closed:stream.close()
            for server in (broker.server,host):server.shutdown();server.server_close()

if __name__=='__main__':unittest.main(verbosity=2)
