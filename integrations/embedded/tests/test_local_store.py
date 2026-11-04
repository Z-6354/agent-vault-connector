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
from local_backend import LocalBackend, LocalBackendError, STORAGE_ONLY_ORIGIN
from local_store import LocalStoreAdapter

TOKEN='SYNTHETIC-MANAGEMENT-TOKEN'
SECRET='SYNTHETIC-LOCAL-SECRET-NOT-EXPOSED'
ID='11111111-2222-4333-8444-555555555555'
PASSWORD_SERVICE={'service_id':'synthetic-login','origin':'http://127.0.0.1:43122','credential_types':['password'],'operations':['browser_fill','login_submit'],'synthetic':True}

class LocalStoreTests(unittest.TestCase):
    def fixture(self, unlocked=True, registry_available=True):
        state={'unlocked':unlocked,'drafts':[]}
        class Mgmt(http.server.BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def send(self,code,value):
                data=json.dumps(value).encode();self.send_response(code)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)))
                self.end_headers();self.wfile.write(data)
            def do_GET(self):
                if self.headers.get('Authorization')!='Bearer '+TOKEN:return self.send(401,{'error':'x'})
                if self.path=='/management/session':
                    return self.send(200,{'authenticated':state['unlocked'],'state':'S2' if state['unlocked'] else 'S0'})
                if self.path=='/management/connections':
                    return self.send(200,{'services':[PASSWORD_SERVICE]}) if registry_available else self.send(503,{'error':'registry_unavailable'})
                return self.send(404,{'error':'x'})
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
                if self.headers.get('Authorization')!='Bearer '+TOKEN:return self.send(401,{'error':'x'})
                if self.path=='/management/drafts':
                    if not state['unlocked']:return self.send(423,{'error':'x'})
                    if self.headers.get('X-CSRF-Token')!='csrf-token':return self.send(403,{'error':'x'})
                    state['drafts'].append(body)
                    return self.send(201,{'draft':{'draft_id':'draft-1','draft_version':1},'request_id':'req-1'})
                if self.path=='/management/drafts/draft-1/confirm':
                    return self.send(200,{'connection':{'id':ID,'status':'active'}})
                return self.send(404,{'error':'x'})
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Mgmt)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        origin='http://127.0.0.1:%d'%server.server_port
        backend=LocalBackend(origin,TOKEN)
        if unlocked:
            backend.session='synthetic-session';backend.csrf='csrf-token'
        return server,state,LocalStoreAdapter(backend=backend)
    def test_save_unlocked_returns_connection_uuid_and_stores_once(self):
        server,state,adapter=self.fixture(True)
        try:
            connection_id=adapter.save({'service':'synthetic-login','account':'main'},SECRET,10,request_id='r1')
            self.assertEqual(connection_id,ID)
            self.assertEqual(len(state['drafts']),1)
            self.assertEqual(state['drafts'][0]['secret'],SECRET)
            self.assertEqual(state['drafts'][0]['origin'],'http://127.0.0.1:43122')
            self.assertEqual(state['drafts'][0]['granted_operations'],[])
        finally:server.shutdown();server.server_close()
    def test_save_locked_raises_without_storing(self):
        server,state,adapter=self.fixture(False)
        try:
            with self.assertRaises(LocalBackendError):adapter.save({'service':'synthetic-login','account':'main'},SECRET,10,request_id='r1')
            self.assertEqual(state['drafts'],[])
        finally:server.shutdown();server.server_close()
    def test_storage_only_unregistered_service_accepted_with_zero_permissions(self):
        server,state,adapter=self.fixture(True)
        try:
            connection_id=adapter.save({'service':'github','account':'main'},SECRET,10,request_id='r1')
            self.assertEqual(connection_id,ID)
            self.assertEqual(len(state['drafts']),1)
            self.assertEqual(state['drafts'][0]['service_id'],'github')
            self.assertEqual(state['drafts'][0]['secret'],SECRET)
            self.assertEqual(state['drafts'][0]['origin'],STORAGE_ONLY_ORIGIN)
            self.assertEqual(state['drafts'][0]['granted_operations'],[])
        finally:server.shutdown();server.server_close()

    def test_storage_only_save_survives_registry_unavailable(self):
        server,state,adapter=self.fixture(True,registry_available=False)
        try:
            self.assertEqual(adapter.save({'service':'deepseek-api','account':'main'},SECRET,10),ID)
            self.assertEqual(state['drafts'][0]['origin'],STORAGE_ONLY_ORIGIN)
            self.assertEqual(state['drafts'][0]['granted_operations'],[])
        finally:server.shutdown();server.server_close()

if __name__=='__main__':unittest.main(verbosity=2)
