"""Public MCP compatibility: removed popup modes reject before any input UI."""
import json
import os
import subprocess
import sys
import unittest

class NoPopup(unittest.TestCase):
    def test_popup_modes_are_not_exposed_or_accepted(self):
        source=os.environ.get('VAULT_MCP_SOURCE')
        if not source:self.skipTest('Set VAULT_MCP_SOURCE for current shared MCP')
        rows=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
              {'jsonrpc':'2.0','id':2,'method':'tools/list'}]
        for i,mode in enumerate(('desktop','web','gui'),3):
            rows.append({'jsonrpc':'2.0','id':i,'method':'tools/call','params':{'name':'request_secure_input','arguments':{'service':'synthetic.example','account':'test','mode':mode}}})
        proc=subprocess.run([sys.executable,'-I','-S','-B',source],input='\n'.join(json.dumps(r) for r in rows)+'\n',text=True,capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,0);self.assertEqual(proc.stderr,'')
        replies=[json.loads(line) for line in proc.stdout.splitlines()]
        tool=next(t for t in replies[1]['result']['tools'] if t['name']=='request_secure_input')
        self.assertEqual(set(tool['inputSchema']['properties']['mode']['enum']),{'auto','inline','console'})
        for reply in replies[2:]:self.assertEqual(reply['error']['code'],-32602)

if __name__=='__main__':unittest.main(verbosity=2)
