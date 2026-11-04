"""End-to-end closure: card JS -> loopback broker (--local) -> local Vault management draft/confirm.

The management server is a faithful HTTP fixture of the local Vault's contract
(session/CSRF, registry, draft->confirm). The real AES-256-GCM SQLite persistence
is exercised by the local Vault's own Node suite on Linux; this test closes the
Python/broker/card side of the chain end-to-end.
"""
import http.server
import json
from pathlib import Path
import sys
import threading
import unittest
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from broker import Broker
from local_backend import LocalBackend
from local_store import LocalStoreAdapter

BROKER_TOKEN='SYNTHETIC-BROKER-ADMIN-TOKEN-'*2
MGMT_TOKEN='SYNTHETIC-MANAGEMENT-TOKEN'
SECRET='SYNTHETIC-E2E-SECRET-NOT-EXPOSED'
PASSWORD_SERVICE={'service_id':'synthetic-login','origin':'http://127.0.0.1:43122','credential_types':['password'],'operations':['browser_fill','login_submit'],'synthetic':True}

class LocalBrokerE2E(unittest.TestCase):
    def setUp(self):
        state={'state':'unlocked','authenticated':True,'csrf':'csrf-token','drafts':[]}
        self.state=state
        def session_state():
            if state['state']=='unlocked':return 'S2'
            if state['state']=='authenticated':return 'S1'
            return state['state']
        class Mgmt(http.server.BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def send(self,code,value):
                data=json.dumps(value).encode();self.send_response(code)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)))
                self.end_headers();self.wfile.write(data)
            def do_GET(self):
                if self.headers.get('Authorization')!='Bearer '+MGMT_TOKEN:return self.send(401,{'error':'x'})
                if self.path=='/management/session':return self.send(200,{'authenticated':True,'state':session_state()})
                if self.path=='/management/connections':return self.send(200,{'services':[PASSWORD_SERVICE]})
                return self.send(404,{'error':'x'})
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
                if self.headers.get('Authorization')!='Bearer '+MGMT_TOKEN:return self.send(401,{'error':'x'})
                if self.path=='/management/drafts':
                    if session_state()!='S2':return self.send(423,{'error':'x'})
                    if self.headers.get('X-CSRF-Token')!='csrf-token':return self.send(403,{'error':'x'})
                    state['drafts'].append(body)
                    return self.send(201,{'draft':{'draft_id':'draft-1','draft_version':1},'request_id':'req-1'})
                if self.path=='/management/drafts/draft-1/confirm':
                    return self.send(200,{'connection':{'id':'11111111-2222-4333-8444-555555555555','status':'active'}})
                return self.send(404,{'error':'x'})
        self.mgmt=http.server.ThreadingHTTPServer(('127.0.0.1',0),Mgmt)
        threading.Thread(target=self.mgmt.serve_forever,daemon=True).start()
        self.mgmt_origin='http://127.0.0.1:%d'%self.mgmt.server_port
        backend=LocalBackend(self.mgmt_origin,MGMT_TOKEN)
        # Simulate an established unlocked management session: the real backend obtains
        # this cookie+CSRF via its own login+unlock with the master passphrase.
        backend.session='synthetic-session-cookie';backend.csrf='csrf-token'
        self.adapter=LocalStoreAdapter(backend=backend)
        self.broker=Broker(BROKER_TOKEN,save_callback=self.adapter.save)
        threading.Thread(target=self.broker.serve_forever,daemon=True).start()
    def tearDown(self):
        self.broker.close();self.mgmt.shutdown();self.mgmt.server_close()
    def call(self,method,path,body=None,token=BROKER_TOKEN,origin=None):
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}
        if origin is not None:headers['Origin']=origin
        req=urllib.request.Request(self.broker.origin+path,data=None if body is None else json.dumps(body).encode(),
            headers=headers,method=method)
        try:
            with urllib.request.urlopen(req,timeout=5) as r:
                return r.status,dict(r.headers),json.loads(r.read() or b'{}')
        except urllib.error.HTTPError as e:
            return e.code,dict(e.headers),json.loads(e.read() or b'{}')
    def test_card_to_local_broker_to_vault_management_full_chain(self):
        status,_,reg=self.call('POST','/requests',{'service':'synthetic-login','account':'main','prompt':'请输入凭据','timeout_s':60})
        self.assertEqual(status,201);self.assertEqual(reg['status'],'pending')
        request_id=reg['request_id']
        status,_,host=self.call('GET','/host/requests')
        frame=next(r['frame_url'] for r in host['requests'] if r['request_id']==request_id)
        path=frame.removeprefix(self.broker.origin)
        status,_,meta=self.call('GET',path+'&format=json',origin='null')
        self.assertEqual(meta['request_id'],request_id);self.assertNotIn('secret',meta)
        status,_,result=self.call('POST',path,{'secret':SECRET},origin='null')
        self.assertEqual(status,200);self.assertEqual(result['status'],'captured')
        self.assertEqual(result['ref'],'vault://synthetic-login/main')
        self.assertEqual(len(self.state['drafts']),1)
        draft=self.state['drafts'][0]
        self.assertEqual(draft['secret'],SECRET)
        self.assertEqual(draft['origin'],'http://127.0.0.1:43122')
        self.assertEqual(draft['granted_operations'],[])
        status,_,final=self.call('GET','/requests/'+request_id)
        self.assertEqual(final,{'request_id':request_id,'status':'captured','ref':'vault://synthetic-login/main'})
        self.assertNotIn(SECRET,json.dumps([reg,host,meta,result,final]))

if __name__=='__main__':unittest.main(verbosity=2)
