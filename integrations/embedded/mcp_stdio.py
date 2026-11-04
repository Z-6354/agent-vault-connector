"""Standard MCP stdio entry for embedded input only; no secret-valued tool arguments."""
import importlib.util
import json
from pathlib import Path
import sys

spec=importlib.util.spec_from_file_location('embedded_adapter',Path(__file__).with_name('mcp_adapter.py'))
adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)


def main():
    sys.stdin.reconfigure(encoding='utf-8');sys.stdout.reconfigure(encoding='utf-8',line_buffering=True)
    initialized=False
    for line in sys.stdin:
        try:
            request=json.loads(line)
        except ValueError:
            print(json.dumps({'jsonrpc':'2.0','id':None,'error':{'code':-32700,'message':'Parse error'}}));continue
        if not isinstance(request,dict) or request.get('jsonrpc')!='2.0' or type(request.get('id')) not in (str,int,type(None)):
            print(json.dumps({'jsonrpc':'2.0','id':None,'error':{'code':-32600,'message':'Invalid request'}}));continue
        if 'id' not in request:continue
        response={'jsonrpc':'2.0','id':request['id']}
        method=request.get('method');params=request.get('params',{})
        if not isinstance(params,dict):response['error']={'code':-32602,'message':'Invalid params'}
        elif method=='initialize':
            initialized=True
            version=params.get('protocolVersion')
            if version not in ('2024-11-05','2025-03-26','2025-06-18','2025-11-25'):version='2025-11-25'
            response['result']={'protocolVersion':version,'capabilities':{'tools':{}},'serverInfo':{'name':'vault-embedded-input','version':'0.1.0'}}
        elif method=='ping':response['result']={}
        elif method=='tools/list':response['result']={'tools':[{'name':'request_secure_input','description':'Request credential entry inside a registered native host. Returns only a safe Vault reference; never send secrets as tool arguments.','inputSchema':{'type':'object','properties':{'service':{'type':'string'},'account':{'type':'string'},'prompt':{'type':'string'},'timeout_s':{'type':'integer','minimum':1,'maximum':3600,'default':120},'mode':{'type':'string','enum':['auto','inline','embedded'],'default':'auto'}},'required':['service','account'],'additionalProperties':False}}]}
        elif method=='tools/call' and not initialized:response['error']={'code':-32002,'message':'Server not initialized'}
        elif method=='tools/call':
            args=params.get('arguments',{})
            if (params.get('name')!='request_secure_input' or not isinstance(args,dict) or
                set(args)-{'service','account','prompt','timeout_s','mode'} or
                args.get('mode','auto') not in ('auto','inline','embedded') or
                not isinstance(args.get('service'),str) or not isinstance(args.get('account'),str)):
                response['error']={'code':-32602,'message':'Invalid tool arguments'}
            else:
                result=adapter.request_embedded_input(args['service'],args['account'],args.get('prompt','请输入凭据'),args.get('timeout_s',120),wait=args.get('mode','auto')=='embedded')
                response['result']={'content':[{'type':'text','text':json.dumps(result,ensure_ascii=False)}],'isError':result.get('status') in ('error','unavailable')}
        else:response['error']={'code':-32601,'message':'Method not found'}
        print(json.dumps(response,ensure_ascii=False))


if __name__=='__main__':main()
