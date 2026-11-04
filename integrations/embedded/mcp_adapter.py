"""Optional MCP-side embedded broker adapter. Only references/metadata cross this boundary.

A host ships this module beside its existing Vault MCP implementation and calls
request_embedded_input before its desktop/TTY fallbacks. Native host mounting is required.
"""
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_embedded_input(service, account, prompt, timeout_s=120, discovery_file=None, wait=True):
    failure = {'status': 'error', 'next_action': 'Check the native host secure-input integration; do not enter secrets in chat.'}
    if (not isinstance(service,str) or not service.strip() or len(service)>256 or
        not isinstance(account,str) or not account.strip() or len(account)>256 or
        not isinstance(prompt,str) or len(prompt)>2048 or type(timeout_s) is not int or not 1<=timeout_s<=3600):
        return failure
    try:
        discovery_file = discovery_file or os.environ.get('EMBEDDED_VAULT_DISCOVERY')
        if not discovery_file:
            return {'status':'unavailable'}
        config=json.loads(Path(discovery_file).read_text(encoding='utf-8'))
        origin=config['origin']; token=config['token']
        url=urllib.parse.urlsplit(origin)
        if (url.scheme!='http' or url.hostname!='127.0.0.1' or not url.port or
            url.username or url.password or url.path not in ('','/') or url.query or url.fragment or
            not isinstance(token,str) or len(token)<32):return failure
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        deadline=time.monotonic()+timeout_s
        def exchange(path,body=None):
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError()
            req=urllib.request.Request(origin.rstrip('/')+path,
                data=None if body is None else json.dumps(body).encode(),
                headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},
                method='GET' if body is None else 'POST')
            with opener.open(req,timeout=min(5,remaining)) as response:
                data=response.read(32769)
                if response.status not in (200,201) or len(data)>32768:raise ValueError()
                return json.loads(data)
        registered=exchange('/requests',{'service':service,'account':account,'prompt':prompt,'timeout_s':timeout_s})
        request_id=registered.get('request_id')
        if registered.get('status')!='pending' or not isinstance(request_id,str):return failure
        if not wait:
            return {'status':'pending','request_id':request_id,'channel':'inline-card',
                    'next_action':'Render ::vault-input{request_id="%s"} in this chat.' % request_id}
        while time.monotonic()<deadline:
            result=exchange('/requests/'+urllib.parse.quote(request_id,safe=''))
            state=result.get('status')
            if state=='captured':
                expected='vault://'+urllib.parse.quote(service,safe='')+'/'+urllib.parse.quote(account,safe='')
                if result.get('ref')!=expected:return failure
                return {'status':'captured','ref':expected,'request_id':request_id,'service_id':service,'account_alias':account}
            if state in ('declined','expired'):return {'status':state,'request_id':request_id}
            if state!='pending':return failure
            time.sleep(min(.25,max(0,deadline-time.monotonic())))
        return {'status':'expired','request_id':request_id}
    except Exception:
        # Never surface server bodies, discovery data or transport exception strings.
        return failure
