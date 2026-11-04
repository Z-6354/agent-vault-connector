"""MCP Apps transport for the existing per-request isolated credential card.

Run with EMBEDDED_VAULT_DISCOVERY pointing to a trusted *local-storage* broker.
A remote-storage legacy broker is deliberately refused. No secret tool arguments.
"""
import json
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request
import uuid

RESOURCE='ui://agent-vault/secure-input'
MIME='text/html;profile=mcp-app'
EXTENSION='io.modelcontextprotocol/ui'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

class Gateway:
    def __init__(self,filename):
        config=json.loads(Path(filename).read_text(encoding='utf8'))
        origin=urllib.parse.urlsplit(config['origin'])
        if (origin.scheme!='http' or origin.hostname!='127.0.0.1' or not origin.port or
            origin.username or origin.password or origin.path not in ('','/') or origin.query or origin.fragment or
            not isinstance(config['token'],str) or len(config['token'])<32):raise ValueError('invalid_broker')
        self.origin=urllib.parse.urlunsplit(('http',origin.netloc,'','',''))
        self.token=config['token']
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def request(self,path,body=None):
        req=urllib.request.Request(self.origin+path,data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'},method='GET' if body is None else 'POST')
        with self.opener.open(req,timeout=5) as response:
            raw=response.read(65537)
            if response.status not in (200,201) or len(raw)>65536:raise ValueError('invalid_broker')
            result=json.loads(raw)
            if not isinstance(result,dict):raise ValueError('invalid_broker')
            return result

class AppsServer:
    def __init__(self,gateway):
        self.gateway=gateway
        self.initialized=False
        self.ui=False
    def call(self,message):
        identifier=message.get('id') if isinstance(message,dict) else None
        def error(code,text):return {'jsonrpc':'2.0','id':identifier,'error':{'code':code,'message':text}}
        if (not isinstance(message,dict) or message.get('jsonrpc')!='2.0' or
            type(identifier) not in (str,int,type(None))):return error(-32600,'Invalid request')
        if 'id' not in message:return None
        method=message.get('method');params=message.get('params',{})
        if not isinstance(params,dict):return error(-32602,'Invalid params')
        if method=='initialize':
            caps=params.get('capabilities',{})
            ui=caps.get('extensions',{}).get(EXTENSION,{}) if isinstance(caps,dict) and isinstance(caps.get('extensions',{}),dict) else {}
            self.ui=isinstance(ui,dict) and isinstance(ui.get('mimeTypes'),list) and MIME in ui['mimeTypes']
            self.initialized=True
            result={'protocolVersion':'2026-01-26','serverInfo':{'name':'local-vault-inline-app','version':'0.2.0'},
                'capabilities':{'tools':{},'resources':{},'extensions':{EXTENSION:{'mimeTypes':[MIME]}}}}
        elif method=='ping':result={}
        elif not self.initialized:return error(-32002,'Server not initialized')
        elif method=='tools/list':
            request={'name':'request_secure_input','description':'Request native inline credential entry. Requires MCP Apps and a local encrypted Vault. Never pass credentials as arguments.',
                'inputSchema':{'type':'object','properties':{'service':{'type':'string','minLength':1,'maxLength':256},'account':{'type':'string','minLength':1,'maxLength':256},'prompt':{'type':'string','maxLength':512},'timeout_s':{'type':'integer','minimum':5,'maximum':3600}},'required':['service','account'],'additionalProperties':False},
                '_meta':{'ui':{'resourceUri':RESOURCE,'visibility':['model']}}}
            status={'name':'vault_input_result','description':'Read only a redacted input result; never returns a secret.',
                'inputSchema':{'type':'object','properties':{'request_id':{'type':'string','format':'uuid'}},'required':['request_id'],'additionalProperties':False}}
            frame={'name':'secure_input_frame','description':'App-only: fetch the request-scoped card frame URL. Never exposed to the model.',
                'inputSchema':{'type':'object','properties':{'request_id':{'type':'string','format':'uuid'}},'required':['request_id'],'additionalProperties':False},
                '_meta':{'ui':{'visibility':['app']}}}
            result={'tools':[request,status,frame]}
        elif method in ('resources/list','resources/read'):
            resource={'uri':RESOURCE,'name':'Vault inline secure input','mimeType':MIME,
                '_meta':{'ui':{'prefersBorder':False,'csp':{'frameDomains':[self.gateway.origin],'connectDomains':[],'resourceDomains':[]}}}}
            if method=='resources/list':result={'resources':[resource]}
            elif params.get('uri')==RESOURCE:
                resource['text']=Path(__file__).with_name('web').joinpath('mcp-app.html').read_text(encoding='utf8')
                result={'contents':[resource]}
            else:return error(-32602,'Unknown resource')
        elif method=='tools/call':
            args=params.get('arguments',{})
            if not isinstance(args,dict):return error(-32602,'Invalid arguments')
            name=params.get('name')
            try:
                if name=='request_secure_input':
                    if (set(args)-{'service','account','prompt','timeout_s'} or
                        any(not isinstance(args.get(k),str) or not args[k].strip() or len(args[k])>256 for k in ('service','account')) or
                        not isinstance(args.get('prompt',''),str) or len(args.get('prompt',''))>512 or
                        type(args.get('timeout_s',120)) is not int or not 5<=args.get('timeout_s',120)<=3600):return error(-32602,'Invalid arguments')
                    if not self.ui:return self.tool_error(identifier,'native_inline_not_supported','Use a compatible inline host or the no-echo terminal adapter; external windows are disabled.')
                    if self.gateway.request('/host/storage').get('location')!='local':
                        return self.tool_error(identifier,'local_storage_required','Configure the local encrypted Vault; remote storage is disabled for this adapter.')
                    body={**args,'prompt':args.get('prompt') or '请输入凭据','timeout_s':args.get('timeout_s',120)}
                    registered=self.gateway.request('/requests',body)
                    request_id=str(uuid.UUID(registered.get('request_id','')))
                    if registered.get('status')!='pending':raise ValueError('invalid_registration')
                    # Model-visible result stays redacted: request_id only, never the frame capability.
                    safe={'status':'pending','request_id':request_id,'channel':'mcp-apps'}
                    result={'content':[{'type':'text','text':json.dumps(safe)}],'structuredContent':safe}
                elif name=='secure_input_frame':
                    if set(args)!={'request_id'}:return error(-32602,'Invalid arguments')
                    request_id=str(uuid.UUID(args['request_id']))
                    frame_url=self._frame_url(request_id)
                    result={'content':[{'type':'text','text':json.dumps({'request_id':request_id})}],
                            'structuredContent':{'request_id':request_id,'frame_url':frame_url}}
                elif name=='vault_input_result':
                    if set(args)!={'request_id'}:return error(-32602,'Invalid arguments')
                    request_id=str(uuid.UUID(args['request_id']))
                    value=self.gateway.request('/requests/'+request_id)
                    if value.get('request_id')!=request_id or value.get('status') not in ('pending','captured','declined','expired'):raise ValueError('invalid_status')
                    safe={'request_id':request_id,'status':value['status']}
                    if safe['status']=='captured':
                        if not isinstance(value.get('ref'),str) or not value['ref'].startswith('vault://'):raise ValueError('invalid_reference')
                        safe['ref']=value['ref']
                        safe['verification'] = value.get('verification', {'status': 'verified'})
                    result={'content':[{'type':'text','text':json.dumps(safe)}],'structuredContent':safe}
                else:return error(-32602,'Unknown tool')
            except Exception:return self.tool_error(identifier,'local_vault_unavailable','Check the trusted local Vault adapter; never enter credentials in chat.')
        else:return error(-32601,'Method not found')
        return {'jsonrpc':'2.0','id':identifier,'result':result}
    def _frame_url(self,request_id):
        pending=self.gateway.request('/host/requests').get('requests',[])
        row=next((r for r in pending if r.get('request_id')==request_id),None)
        if not row:raise ValueError('invalid_frame')
        frame=urllib.parse.urlsplit(row['frame_url'])
        if (urllib.parse.urlunsplit((frame.scheme,frame.netloc,'','',''))!=self.gateway.origin or
            frame.path!='/card/'+request_id or not urllib.parse.parse_qs(frame.query).get('key')):raise ValueError('invalid_frame')
        return row['frame_url']
    @staticmethod
    def tool_error(identifier,code,next_action):
        return {'jsonrpc':'2.0','id':identifier,'result':{'isError':True,'content':[{'type':'text','text':json.dumps({'status':'error','error':code,'next_action':next_action})}]}}

def main():
    try:server=AppsServer(Gateway(os.environ['EMBEDDED_VAULT_DISCOVERY']))
    except Exception:
        print('Local inline Vault broker configuration is required.',file=sys.stderr);return 1
    sys.stdin.reconfigure(encoding='utf8');sys.stdout.reconfigure(encoding='utf8',line_buffering=True)
    for line in sys.stdin:
        try:message=json.loads(line)
        except ValueError:
            print(json.dumps({'jsonrpc':'2.0','id':None,'error':{'code':-32700,'message':'Parse error'}}));continue
        result=server.call(message)
        if result is not None:print(json.dumps(result,ensure_ascii=False))
    return 0

if __name__=='__main__':raise SystemExit(main())
