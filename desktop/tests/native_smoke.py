"""Measure release EXE and validate actual WebView IPC without authenticating.
Test-only WebView2 debugging is enabled only in this child environment.
Requires existing psutil and websocket-client; no production URL overrides.
"""
import base64
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import urllib.request
import psutil
import websocket

EXE=Path(__file__).resolve().parents[1]/'src-tauri/target/release/agent-vault-desktop.exe'
OUT=Path(sys.argv[1]);OUT.mkdir(parents=True,exist_ok=True)
u=ctypes.WinDLL('user32',use_last_error=True)
CALLBACK=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
u.EnumWindows.argtypes=[CALLBACK,w.LPARAM]
u.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
u.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int]
u.IsWindowVisible.argtypes=[w.HWND];u.IsWindowVisible.restype=w.BOOL
u.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]

def window(pid):
    found=[]
    @CALLBACK
    def collect(hwnd,_):
        owner=w.DWORD();u.GetWindowThreadProcessId(hwnd,ctypes.byref(owner))
        if owner.value==pid and u.IsWindowVisible(hwnd):
            title=ctypes.create_unicode_buffer(512);u.GetWindowTextW(hwnd,title,len(title))
            if title.value=='Agent Vault':found.append(hwnd)
        return True
    u.EnumWindows(collect,0)
    return found[0] if found else None

def close_process(process):
    if process.poll() is None:
        process.terminate();process.wait(timeout=10)

samples=[]
for run in range(3):
    started=time.perf_counter();p=subprocess.Popen([str(EXE)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+20
        hwnd=None
        while time.monotonic()<deadline and p.poll() is None:
            hwnd=window(p.pid)
            if hwnd:break
            time.sleep(.01)
        assert hwnd,'native window unavailable'
        visible=round((time.perf_counter()-started)*1000,1)
        time.sleep(2)
        parent=psutil.Process(p.pid);members=[parent]+parent.children(recursive=True)
        rss=sum(x.memory_info().rss for x in members if x.is_running())
        private=sum(getattr(x.memory_info(),'private',0) for x in members if x.is_running())
        sample={'run':run+1,'visible_window_ms':visible,'parent_rss_bytes':parent.memory_info().rss,'tree_processes':len(members),'tree_rss_bytes':rss,'tree_private_bytes':private}
        samples.append(sample)
        u.PostMessageW(hwnd,0x0010,0,0)
        deadline=time.monotonic()+3
        while u.IsWindowVisible(hwnd) and time.monotonic()<deadline:time.sleep(.02)
        assert not u.IsWindowVisible(hwnd) and p.poll() is None,'close-to-tray failure'
    finally:close_process(p)
print('native launch/close-to-tray: 3/3 PASS')

env=os.environ.copy();env['WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS']='--remote-debugging-port=18748 --remote-allow-origins=*'
ui_started=time.perf_counter()
p=subprocess.Popen([str(EXE)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
ws=None;sequence=0

def cdp(method,params=None):
    global sequence
    sequence+=1;ws.send(json.dumps({'id':sequence,'method':method,'params':params or {}}))
    while True:
        row=json.loads(ws.recv())
        if row.get('id')==sequence:
            assert 'error' not in row,'CDP failure'
            return row.get('result',{})

def js(expression):
    result=cdp('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True})
    assert 'exceptionDetails' not in result,'native webview assertion failed'
    return result['result'].get('value')

try:
    started=time.perf_counter();deadline=time.monotonic()+20;targets=[];pages=[]
    while time.monotonic()<deadline:
        try:
            targets=json.load(urllib.request.urlopen('http://127.0.0.1:18748/json/list',timeout=1))
            pages=[t for t in targets if t['type']=='page' and 'tauri.localhost' in t.get('url','')]
            if pages:break
        except OSError:pass
        time.sleep(.02)
    assert pages,'native WebView not available'
    ws=websocket.create_connection(pages[0]['webSocketDebuggerUrl'],timeout=10)
    cdp('Runtime.enable');cdp('Page.enable')
    ready_deadline=time.monotonic()+10
    while not js("document.readyState==='complete'&&Boolean(window.__TAURI__?.core)&&Boolean(document.querySelector('#secret'))"):
        assert time.monotonic()<ready_deadline,'native UI not ready'
        time.sleep(.02)
    assert js("(async()=>{const r=await window.__TAURI__.core.invoke('connection_status');return r.state==='disconnected'&&document.querySelector('#secret').type==='password'&&document.querySelector('#save-button').disabled;})()") is True
    ui_ready_ms=round((time.perf_counter()-ui_started)*1000,1)
    print('actual release WebView loads masked UI and real disconnected IPC: PASS')
    assert js("(async()=>{try{await window.__TAURI__.core.invoke('save_credential',{serviceId:'isolated-no-network',accountAlias:'fixture',secret:'synthetic',credentialType:'password'});return false;}catch(e){return e==='not_connected';}})()") is True
    print('actual release IPC refuses unauthenticated save: PASS')
    assert js("(async()=>{try{await window.__TAURI__.core.invoke('login',{username:'',password:''});return false;}catch(e){return e==='invalid_input';}})()") is True
    print('actual release IPC rejects empty login without credential access: PASS')
    shot=cdp('Page.captureScreenshot',{'format':'png','captureBeyondViewport':True})
    (OUT/'native-release.png').write_bytes(base64.b64decode(shot['data']))
    report={'exe':str(EXE),'bytes':EXE.stat().st_size,'sha256':hashlib.sha256(EXE.read_bytes()).hexdigest(),'normal_launch_samples':samples,'median_window_ms':statistics.median(x['visible_window_ms'] for x in samples),'measurement_notes':'All launches use warm OS file cache; window visible is not full UI ready. Memory measured after 2s; tree RSS double-counts shared pages. WebView debugging enabled only for separate IPC test. No auth requests or production writes.','debug_instrumented_ui_ready_ms':ui_ready_ms,'native_ipc_checks_passed':3,'native_close_checks_passed':3}
    (OUT/'native-report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))
finally:
    if ws:ws.close()
    close_process(p)
