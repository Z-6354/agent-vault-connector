import json
import os
from pathlib import Path
import tempfile
import urllib.error
import urllib.request

HOST='127.0.0.1'
STORAGE_ONLY_ORIGIN='https://storage-only.vault.local'

def _discovery_path():
    return Path(os.environ.get('VAULT_MANAGEMENT_ENV_FILE') or str(Path(tempfile.gettempdir()) / 'agent-vault-management.env'))

def _read_config():
    try:
        config=json.loads(_discovery_path().read_text(encoding='utf8'))
    except (OSError, ValueError):
        return None
    origin=config.get('origin');token=config.get('token')
    if not isinstance(origin,str) or not origin.startswith('http://'+HOST+':') or not isinstance(token,str) or not token:
        return None
    port=None
    try:
        host_port=origin[len('http://'):].split('/',1)[0]
        host,port_text=host_port.split(':',1)
        if host!=HOST:return None
        port=int(port_text)
    except (ValueError, IndexError):
        return None
    if not 1024<=port<=65535:return None
    return origin.rstrip('/'),token

class LocalBackendError(Exception):
    pass

class LocalBackend:
    """One authenticated local Vault session. Cookie material stays in memory and is never
    serialized to logs or returned to callers."""
    def __init__(self,origin=None,token=None):
        if origin is None or token is None:
            discovered=_read_config()
            if not discovered:raise LocalBackendError('local_vault_unavailable')
            origin,token=discovered
        self.base=origin;self.token=token
        self.session=None;self.csrf=None
    def request(self,path,body=None):
        headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'}
        if self.session:headers['Cookie']='vault_session='+self.session
        if self.csrf:headers['X-CSRF-Token']=self.csrf
        req=urllib.request.Request(self.base+path,data=None if body is None else json.dumps(body).encode(),
            headers=headers,method='GET' if body is None else 'POST')
        set_cookie=[]
        try:
            with urllib.request.urlopen(req,timeout=5) as response:
                status=response.status;payload=response.read(65536);set_cookie=response.headers.get_all('Set-Cookie') or []
        except urllib.error.HTTPError as error:
            status=error.code;payload=error.read(65536);set_cookie=error.headers.get_all('Set-Cookie') or []
        for value in set_cookie:
            if value.split('=',1)[0]=='vault_session':self.session=value.split(';',1)[0].split('=',1)[1]
        try:return status,json.loads(payload or b'{}')
        except ValueError:return status,{}
    def logged_in(self):
        status,value=self.request('/management/session')
        return status==200 and value.get('authenticated') is True and value.get('state')=='S1'
    def login(self,passphrase):
        status,value=self.request('/management/login',{'passphrase':passphrase})
        if status!=200 or not value.get('authenticated'):return False
        self.csrf=value.get('csrf');return True
    def unlock(self,passphrase):
        status,value=self.request('/management/unlock',{'passphrase':passphrase})
        if status==409:return True
        if status!=200:return False
        self.csrf=value.get('csrf');return True
    def save(self,service,account,secret):
        # Local storage policy is independent of executable service registration.
        # Preserve the explicit synthetic fixture identity; real services all use
        # the registry's fixed storage-only marker with zero granted operations.
        if not isinstance(service,str) or not service.strip() or len(service)>100:
            raise LocalBackendError('save_rejected')
        origin=('http://127.0.0.1:43122' if service=='synthetic-login'
                else STORAGE_ONLY_ORIGIN)
        status,value=self.request('/management/drafts',{
            'mode':'create','label':'%s / %s'%(service,account),'service_id':service,
            'credential_type':'password','account_alias':account,'secret':secret,
            'origin':origin,'environment':'local','granted_operations':[]})
        if status!=201:raise LocalBackendError('save_rejected')
        draft=value.get('draft',{});request_id=value.get('request_id')
        if not draft.get('draft_id') or not request_id:raise LocalBackendError('save_rejected')
        status,result=self.request('/management/drafts/%s/confirm'%draft['draft_id'],
            {'draft_version':draft.get('draft_version'),'request_id':request_id})
        connection=result.get('connection',{}) if status==200 else {}
        if not connection.get('id'):raise LocalBackendError('save_rejected')
        return 'vault://%s/%s'%(service,account),connection['id']
