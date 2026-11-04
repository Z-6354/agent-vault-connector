// Actual lifecycle controller + SQLite integration; upstream auth is a controlled HTTP server.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
const require=createRequire(process.env.HERMES_DESKTOP_PACKAGE);
const {chromium}=require('playwright-core');
const origin=process.env.LIFECYCLE_TEST_ORIGIN;
const token=process.env.LIFECYCLE_TEST_ADMIN_TOKEN;
const MASTER='SYNTHETIC-browser-master-password';
const GOOD='SYNTHETIC-browser-good-credential';
const BAD='SYNTHETIC-browser-bad-credential';
let currentFrame='',requestId='',useApp=false,completion=[];
const app=await readFile(new URL('../web/lifecycle-app.html',import.meta.url),'utf8');
const host=createServer((req,res)=>{
 res.setHeader('Content-Type','text/html; charset=utf-8');
 res.end(`<!doctype html><title>Lifecycle integration reference host</title><style>body{margin:0;background:#f2f2f7}iframe{border:0;width:460px;height:620px}</style><iframe id="card" sandbox="allow-scripts"></iframe><script>
 const currentFrame=${JSON.stringify(currentFrame)},requestId=${JSON.stringify(requestId)},useApp=${JSON.stringify(useApp)};
 const f=document.querySelector('iframe');
 window.completed=[];
 addEventListener('message',event=>{
  const v=event.data;
  if(event.source!==f.contentWindow)return;
  if(v?.type==='vault-lifecycle-resize'&&Number.isFinite(v.height)&&v.height>=200&&v.height<=900){f.style.height=v.height+'px';return;}
  if(v?.method==='ui/notifications/size-changed'&&Number.isFinite(v.params?.height)&&v.params.height>=60&&v.params.height<=900){f.style.height=v.params.height+'px';return;}
  if(v?.type==='vault-lifecycle-complete'){window.completed.push(v);return;}
  if(v?.method==='ui/initialize')f.contentWindow.postMessage({jsonrpc:'2.0',id:v.id,result:{protocolVersion:'2026-01-26'}},'*');
  if(v?.method==='ui/notifications/initialized')f.contentWindow.postMessage({jsonrpc:'2.0',method:'ui/notifications/tool-result',params:{structuredContent:{status:'pending',request_id:requestId}}},'*');
  if(v?.method==='tools/call'&&v.params?.name==='vault_lifecycle_frame'&&v.params.arguments.request_id===requestId)f.contentWindow.postMessage({jsonrpc:'2.0',id:v.id,result:{structuredContent:{request_id:requestId,frame_url:currentFrame}}},'*');
 });
 if(useApp)f.srcdoc=new TextDecoder().decode(Uint8Array.from(atob(${JSON.stringify(Buffer.from(app).toString('base64'))}),c=>c.charCodeAt(0)));else f.src=currentFrame;
 </script>`);
});
await new Promise(r=>host.listen(0,'127.0.0.1',r));
const hostOrigin=`http://127.0.0.1:${host.address().port}`;
let browser,page,passed=0;
async function api(path,body){
 const response=await fetch(origin+path,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
 assert.equal(response.status,200);return await response.json();
}
async function mount(endpoint,body,viaApp=false){
 const r=await api(endpoint,body);requestId=r.request_id;
 const info=await api('/lifecycle/frame/'+requestId);currentFrame=info.frame_url;useApp=viaApp;
 await page.goto(hostOrigin);
 const outer=page.frameLocator('#card');
 const frame=viaApp?outer.frameLocator('iframe'):outer;
 await frame.locator('#fields').waitFor({state:'visible'});
 return frame;
}
async function settled(frame){await frame.locator('#card').evaluate(async e=>{while(e.getAttribute('aria-busy')==='true')await new Promise(r=>setTimeout(r,20));});}
async function fill(frame,secret,account='owner'){
 await frame.locator('#account').fill(account);await frame.locator('#secret').fill(secret);
}
try{
 browser=await chromium.launch({channel:'msedge',headless:true});page=await browser.newPage({viewport:{width:600,height:800}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 assert.equal((await api('/lifecycle/guide',{})).status,'needs_target');
 assert.equal((await api('/lifecycle/guide',{target:'local'})).status,'needs_create_consent');passed++;
 let frame=await mount('/lifecycle/guide',{target:'local',consent:true});
 assert.equal(await frame.locator('select').count(),0);
 assert.equal(await frame.locator('#account').inputValue(),'');
 if(process.env.LIFECYCLE_SCREENSHOT)await page.screenshot({path:process.env.LIFECYCLE_SCREENSHOT.replace(/\.png$/,'-create.png')});
 await fill(frame,MASTER);await frame.locator('#confirm').fill('different');await frame.locator('#submit').click();
 assert.match(await frame.locator('#notice').innerText(),/不一致/);
 assert.equal((await api('/lifecycle/result/'+requestId)).status,'pending');
 await fill(frame,MASTER);await frame.locator('#confirm').fill(MASTER);await frame.locator('#submit').click();await settled(frame);
 assert.equal((await api('/lifecycle/result/'+requestId)).status,'ready');
 assert.equal(await frame.locator('#secret').inputValue(),'');
 assert.ok((await page.evaluate(()=>window.completed)).every(r=>!JSON.stringify(r).includes(MASTER)));passed++;
 frame=await mount('/lifecycle/guide',{intent:'switch_account',consent:true});
 await fill(frame,'SYNTHETIC-wrong-master');await frame.locator('#submit').click();await settled(frame);
 assert.match(await frame.locator('#notice').innerText(),/不正确/);
 assert.equal(await frame.locator('#secret').inputValue(),'');
 assert.equal((await api('/lifecycle/status')).status,'ready');
 await fill(frame,MASTER);await frame.locator('#secret').press('Enter');await settled(frame);
 assert.equal((await api('/lifecycle/result/'+requestId)).status,'ready');passed++;
 frame=await mount('/lifecycle/credential',{service:'github',account:'main'});
 await fill(frame,BAD,'main');await frame.locator('#submit').click();await settled(frame);
 assert.match(await frame.locator('#notice').innerText(),/验证被拒绝/);
 assert.equal((await api('/lifecycle/result/'+requestId)).status,'rejected');
 await fill(frame,GOOD,'main');await frame.locator('#submit').click();await settled(frame);
 const saved=await api('/lifecycle/result/'+requestId);assert.equal(saved.ref,'vault://github/main');passed++;
 // Full MCP Apps handshake bridge -> app-only frame -> opaque nested input frame -> teardown.
 const r=await api('/lifecycle/credential',{service:'github',account:'main'});requestId=r.request_id;
 currentFrame=(await api('/lifecycle/frame/'+requestId)).frame_url;useApp=true;
 await page.goto(hostOrigin);
 const appFrame=page.frameLocator('#card');const inner=appFrame.frameLocator('iframe');
 await inner.locator('#fields').waitFor({state:'visible'});
 await fill(inner,GOOD,'main');await inner.locator('#submit').click();
 await appFrame.locator('#status').filter({hasText:'验证通过'}).waitFor();
 assert.equal(await appFrame.locator('iframe').count(),0);passed++;
 if(process.env.LIFECYCLE_SCREENSHOT)await page.screenshot({path:process.env.LIFECYCLE_SCREENSHOT});
 assert.equal(page.context().pages().length,1);assert.deepEqual(errors,[]);
 const markup=await page.content();assert.ok(![MASTER,GOOD,BAD].some(s=>markup.includes(s)));
 console.log(`LIFECYCLE_REAL_INTEGRATION_OK ${passed} flows; real HTTP/SQLite/MCP Apps bridge; controlled upstream auth; no popup`);
}finally{if(browser)await browser.close();await new Promise(r=>host.close(r));}
