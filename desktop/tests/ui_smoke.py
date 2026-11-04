"""Browser smoke checks with an explicit synthetic Tauri boundary. No production calls.
Requires Python websocket-client; uses installed Microsoft Edge, no browser downloads.
Run: python ui_smoke.py <evidence-directory>
"""
import base64
import functools
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import websocket

UI = Path(__file__).resolve().parents[1] / 'ui'
EVIDENCE = Path(sys.argv[1]); EVIDENCE.mkdir(parents=True, exist_ok=True)
EDGE = Path(os.environ.get('PROGRAMFILES(X86)', 'C:/Program Files (x86)')) / 'Microsoft/Edge/Application/msedge.exe'
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args): pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Handler,directory=str(UI)))
threading.Thread(target=server.serve_forever,daemon=True).start()
sequence=0
ws=None
process=None
profile=tempfile.TemporaryDirectory(prefix='vault-edge-',dir=str(EVIDENCE))

def cdp(method,params=None):
    global sequence
    sequence+=1
    ws.send(json.dumps({'id':sequence,'method':method,'params':params or {}}))
    while True:
        row=json.loads(ws.recv())
        if row.get('id')==sequence:
            if 'error' in row:raise RuntimeError('CDP request failed: '+method)
            return row.get('result',{})

def js(expression):
    result=cdp('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True})
    if 'exceptionDetails' in result:raise RuntimeError('Browser assertion failed')
    return result['result'].get('value')

def check(expression,label):
    assert js(expression) is True,label
    print(label+': PASS')

def screenshot(name):
    result=cdp('Page.captureScreenshot',{'format':'png','captureBeyondViewport':True})
    (EVIDENCE/name).write_bytes(base64.b64decode(result['data']))

mock="""window.__testCalls=[];window.__failSave=false;window.__TAURI__={core:{invoke:async(command,args={})=>{
window.__testCalls.push({command,args:structuredClone(args)});
if(command==='connection_status'||command==='logout')return {state:'disconnected'};
if(command==='login')return {state:'connected',username:'isolated-ui-fixture'};
if(command==='save_credential'){if(window.__expireSave)return {state:'expired'};if(window.__failSave)throw Error('synthetic-server-secret');return {state:'saved'};}
if(command==='resolve')return {state:'resolved',connection_id:'fixture-id',service_id:'<img src=x onerror=alert(1)>',account_alias:'main'};
throw Error('unexpected command');}},event:{listen:async()=>()=>{}}};"""
try:
    process=subprocess.Popen([str(EDGE),'--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--remote-allow-origins=*','--remote-debugging-port=18747','--user-data-dir='+profile.name,'about:blank'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    deadline=time.monotonic()+20
    targets=[]
    while time.monotonic()<deadline:
        try:
            targets=json.load(urllib.request.urlopen('http://127.0.0.1:18747/json/list',timeout=1))
            if targets:break
        except OSError:time.sleep(.1)
    ws=websocket.create_connection(next(t['webSocketDebuggerUrl'] for t in targets if t['type']=='page'),timeout=15)
    cdp('Page.enable');cdp('Runtime.enable')
    cdp('Emulation.setDeviceMetricsOverride',{'width':1120,'height':900,'deviceScaleFactor':1,'mobile':False})
    cdp('Page.addScriptToEvaluateOnNewDocument',{'source':mock})
    cdp('Page.navigate',{'url':'http://127.0.0.1:'+str(server.server_port)})
    js("new Promise(resolve=>{const done=()=>setTimeout(()=>resolve(true),100);document.readyState==='complete'?done():addEventListener('load',done,{once:true})})")
    check("document.querySelector('#secret').type==='password'&&document.querySelector('#save-button').disabled&&!localStorage.length&&!sessionStorage.length",'initial masked input and disconnected save gate')
    check('document.documentElement.scrollWidth<=innerWidth','desktop layout has no horizontal overflow')
    screenshot('desktop-card.png')
    js("document.querySelector('#connect-button').click();document.querySelector('#login-username').value='fixture';document.querySelector('#login-password').value='synthetic-login';document.querySelector('#login-form').requestSubmit();new Promise(r=>setTimeout(r,20))")
    check("!document.querySelector('#login-dialog').open&&document.querySelector('#login-password').value===''&&!document.querySelector('#save-button').disabled",'login clears input and enables authenticated actions')
    js("document.querySelector('#secret').value='synthetic-only-password';document.querySelector('#credential-form').requestSubmit();new Promise(r=>setTimeout(r,20))")
    check("document.querySelector('#secret').value===''&&document.querySelector('#form-notice').textContent.includes('已由中央保险库接收')&&window.__testCalls.find(x=>x.command==='save_credential').args.secret==='synthetic-only-password'",'save passes user secret once to native boundary and clears field')
    js("window.__failSave=true;document.querySelector('#secret').value='synthetic-only-password';document.querySelector('#credential-form').requestSubmit();new Promise(r=>setTimeout(r,20))")
    check("document.querySelector('#secret').value===''&&document.querySelector('#form-notice').textContent.includes('保存未确认')&&!document.body.textContent.includes('synthetic-server-secret')",'failed save uses fixed safe message and clears field')
    js("document.querySelector('#nav-find').click();document.querySelector('#find-form').requestSubmit();new Promise(r=>setTimeout(r,20))")
    check("document.querySelector('#find-result').textContent.includes('fixture-id')&&document.querySelector('#find-result').textContent.includes('<img')&&!document.querySelector('#find-result img')",'metadata renders as text without interpreting HTML')
    js("window.__expireSave=true;window.__failSave=false;document.querySelector('#secret').value='synthetic-only-password';document.querySelector('#credential-form').requestSubmit();new Promise(r=>setTimeout(r,20))")
    check("document.querySelector('#save-button').disabled&&document.querySelector('#find-button').disabled&&document.querySelector('#secret').value===''",'expired session from save disables operations and clears input')
    js("document.querySelector('#connect-button').click();document.querySelector('#login-username').value='fixture';document.querySelector('#login-password').value='synthetic-login';document.querySelector('#login-form').requestSubmit();new Promise(r=>setTimeout(r,20))")
    js("document.querySelector('#connect-button').click();new Promise(r=>setTimeout(r,20))")
    check("document.querySelector('#save-button').disabled&&document.querySelector('#find-button').disabled",'logout disables credential operations')
    cdp('Emulation.setDeviceMetricsOverride',{'width':390,'height':844,'deviceScaleFactor':1,'mobile':False})
    js("document.querySelector('#nav-card').click()")
    check('document.documentElement.scrollWidth<=innerWidth','narrow layout has no horizontal overflow')
    screenshot('narrow-card.png')
    print('RESULT: 9 passed / 0 failed; synthetic native boundary, no production login or writes')
finally:
    if ws:ws.close()
    if process:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill()
    server.shutdown();server.server_close()
    try:profile.cleanup()
    except OSError:pass
