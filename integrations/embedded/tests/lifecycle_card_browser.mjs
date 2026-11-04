// Run: HERMES_DESKTOP_PACKAGE=/absolute/path/to/package.json node this-file.mjs
// Uses installed playwright-core and Edge; downloads nothing. HTTP responses below
// are an explicit adapter simulation, not production Vault integration evidence.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFile} from 'node:fs/promises';
import {createServer} from 'node:http';
if(!process.env.HERMES_DESKTOP_PACKAGE)throw Error('Set HERMES_DESKTOP_PACKAGE to the installed Hermes desktop package.json');
const require=createRequire(process.env.HERMES_DESKTOP_PACKAGE);
const {chromium}=require('playwright-core');
const html=await readFile(new URL('../web/lifecycle-card.html',import.meta.url),'utf8');
const SAMPLE='SYNTHETIC-BROWSER-ONLY-NOT-A-CREDENTIAL';
let state;
const server=createServer(async(req,res)=>{
 const path=req.url;
 if(path==='/host'){
  res.setHeader('Content-Type','text/html; charset=utf-8');
  res.end('<!doctype html><meta name="viewport" content="width=device-width"><style>body{margin:0}iframe{width:100%;height:850px;border:0}</style><iframe sandbox="allow-scripts" src="/lifecycle/card/synthetic-capability"></iframe>');return;
 }
 if(path==='/lifecycle/card/synthetic-capability'){
  res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);return;
 }
 if(path==='/lifecycle/card/synthetic-capability/context'||path==='/lifecycle/card/synthetic-capability/submit'){
  state.origins.push(req.headers.origin);
  if(req.headers.origin!=='null'){res.writeHead(403).end();return;}
  res.setHeader('Access-Control-Allow-Origin','null');res.setHeader('Content-Type','application/json');
  if(path.endsWith('/context')){res.statusCode=state.contextCode??200;res.end(JSON.stringify(state.context));return;}
  state.contentTypes.push(req.headers['content-type']);
  let body='';for await(const chunk of req)body+=chunk;
  state.submits.push(JSON.parse(body));
  if(state.disconnect){req.socket.destroy();return;}
  if(state.delay)await new Promise(resolve=>setTimeout(resolve,state.delay));
  res.statusCode=state.code??200;
  res.end(state.malformed?'not JSON':JSON.stringify(state.result));return;
 }
 res.writeHead(404).end();
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin=`http://127.0.0.1:${server.address().port}`;
let browser,passed=0;
async function scenario(name,run){await run();passed++;console.log(`PASS ${name}`);}
async function mount(mode='credential',overrides={}){
 state={context:{mode,target:'local',name:'',account:'example-user',service:'example.test'},result:{status:mode==='credential'?'valid':'ready'},submits:[],origins:[],contentTypes:[],...overrides};
 const context=await browser.newContext({viewport:{width:340,height:900},reducedMotion:'reduce'});
 const page=await context.newPage();const errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 context.on('page',p=>{if(p!==page)errors.push('Unexpected popup');});
 page.on('console',msg=>{if(msg.text().includes(SAMPLE))errors.push('Secret in console');});
 await page.goto(origin+'/host');
 const frame=page.frameLocator('iframe');
 await frame.locator('#submit').waitFor({state:'visible'});
 await frame.locator('#card').evaluate(async el=>{while(el.getAttribute('aria-busy')==='true')await new Promise(r=>setTimeout(r,10));});
 assert.equal(await page.evaluate(()=>document.querySelector('iframe').contentDocument===null),true,'Opaque host boundary');
 return {page,frame,async close(){
  assert.deepEqual(errors,[],'Browser errors or leaks');
  assert.ok(state.origins.every(value=>value==='null'));
  assert.ok(state.contentTypes.every(value=>value==='text/plain'));
  assert.ok(!(await page.content()).includes(SAMPLE),'Host DOM secret leak');
  assert.equal(context.pages().length,1);
  await context.close();
 }};
}
async function fill(frame,mode='credential'){
 await frame.locator('#secret').fill(SAMPLE);
 if(mode==='create')await frame.locator('#confirm').fill(SAMPLE);
}
async function finish(frame){await frame.locator('#card').evaluate(async el=>{while(el.getAttribute('aria-busy')==='true')await new Promise(r=>setTimeout(r,10));});}
async function cleared(frame){assert.equal(await frame.locator('#secret').inputValue(),'');assert.equal(await frame.locator('#confirm').inputValue(),'');}
try{
 browser=await chromium.launch({channel:process.env.LIFECYCLE_BROWSER_CHANNEL||'msedge',headless:true});
 for(const mode of ['create','login','credential'])await scenario(`${mode}: isolated light card, prefill, exact payload, success`,async()=>{
  const {frame,page,close}=await mount(mode);
  assert.equal(await frame.locator('form,select').count(),0);
  assert.equal(await frame.locator('#secret').getAttribute('type'),'password');
  assert.equal(await frame.locator('#confirm').getAttribute('type'),'password');
  assert.equal(await frame.locator('#account').inputValue(),'example-user');
  assert.equal(await frame.locator('#name').inputValue(),'');
  assert.equal(await frame.locator('#name-row').isVisible(),mode==='create');
  assert.equal(await frame.locator('#confirm-row').isVisible(),mode==='create');
  assert.equal(await frame.locator('#service-row').isVisible(),mode==='credential');
  const layout=await frame.locator('body').evaluate(el=>({fits:el.scrollWidth<=innerWidth,input:getComputedStyle(document.querySelector('#secret')).backgroundColor,button:getComputedStyle(document.querySelector('#submit')).backgroundColor}));
  assert.deepEqual(layout,{fits:true,input:'rgb(242, 242, 247)',button:'rgb(0, 98, 204)'});
  await fill(frame,mode);
  if(mode==='login')await frame.locator('#secret').press('Enter');else await frame.locator('#submit').click();
  await finish(frame);await cleared(frame);
  assert.equal(state.submits.length,1);
  assert.deepEqual(state.submits[0],mode==='create'?{account:'example-user',passphrase:SAMPLE,confirm_passphrase:SAMPLE,name:''}:mode==='login'?{account:'example-user',passphrase:SAMPLE}:{account:'example-user',secret:SAMPLE,service:'example.test'});
  assert.equal(await frame.locator('#submit').isDisabled(),true);
  assert.equal(await frame.locator('#notice').getAttribute('class'),'notice success');
  await page.keyboard.press('Enter');assert.equal(state.submits.length,1);
  await close();
 });
 await scenario('create: mismatched confirmation clears both secrets and sends nothing',async()=>{
  const {frame,close}=await mount('create');await frame.locator('#secret').fill(SAMPLE);await frame.locator('#confirm').fill('different');await frame.locator('#submit').click();await cleared(frame);
  assert.match(await frame.locator('#notice').innerText(),/不一致/);assert.equal(state.submits.length,0);await close();
 });
 await scenario('unknown metadata stays empty; blank account blocked',async()=>{
  const {frame,close}=await mount('login',{context:{mode:'login',target:'cloud',name:'',account:'',service:''}});
  assert.equal(await frame.locator('#account').inputValue(),'');assert.match(await frame.locator('#target').innerText(),/云端/);
  await fill(frame);await frame.locator('#submit').click();await cleared(frame);assert.equal(state.submits.length,0);assert.match(await frame.locator('#notice').innerText(),/填写账号/);await close();
 });
 await scenario('credential: empty secret and service are blocked',async()=>{
  const {frame,close}=await mount();await frame.locator('#submit').click();assert.match(await frame.locator('#notice').innerText(),/请输入密码或密钥/);
  await fill(frame);await frame.locator('#service').fill('');await frame.locator('#submit').click();await cleared(frame);assert.match(await frame.locator('#notice').innerText(),/填写服务/);assert.equal(state.submits.length,0);await close();
 });
 for(const [status,pattern] of [['rejected',/验证被拒绝/],['validation_unavailable',/验证服务暂时不可用/],['validation_unsupported',/不支持凭据验证/],['error',/结果未能确认/],['ready',/结果未能确认/]])await scenario(`credential: ${status} stays distinct, safe, clears input`,async()=>{
  const {frame,close}=await mount('credential',{result:{status,message:SAMPLE,token:SAMPLE,secret:SAMPLE}});await fill(frame);await frame.locator('#submit').click();await finish(frame);await cleared(frame);
  const text=await frame.locator('body').innerText();assert.match(text,pattern);assert.ok(!text.includes(SAMPLE));assert.equal(await frame.locator('#submit').isEnabled(),true);await close();
 });
 for(const code of [401,403,410,429,500,504])await scenario(`HTTP ${code}: not reported as wrong password`,async()=>{
  const {frame,close}=await mount('login',{code,result:{status:'rejected',message:SAMPLE}});await fill(frame);await frame.locator('#submit').click();await finish(frame);await cleared(frame);
  const text=await frame.locator('#notice').innerText();assert.doesNotMatch(text,/主密码未通过|密码错误/);assert.ok(!text.includes(SAMPLE));assert.equal(await frame.locator('#notice').getAttribute('role'),'alert');await close();
 });
 for(const kind of ['disconnect','malformed'])await scenario(`${kind}: uncertain outcome, clear input, can retry`,async()=>{
  const {frame,close}=await mount('login',{[kind]:true});await fill(frame);await frame.locator('#submit').click();await finish(frame);await cleared(frame);assert.match(await frame.locator('#notice').innerText(),/结果尚未确认/);assert.equal(await frame.locator('#submit').isEnabled(),true);await close();
 });
 await scenario('busy feedback immediately disables duplicate click and Enter',async()=>{
  const {frame,close}=await mount('login',{delay:500});await fill(frame);await frame.locator('#submit').click();
  assert.equal(await frame.locator('#card').getAttribute('aria-busy'),'true');assert.match(await frame.locator('#notice').innerText(),/正在登录/);assert.equal(await frame.locator('#submit').isDisabled(),true);
  await frame.locator('#fields').dispatchEvent('keydown',{key:'Enter'});await cleared(frame);await finish(frame);assert.equal(state.submits.length,1);await close();
 });
 await scenario('context failure hides inputs; explicit retry loads safely',async()=>{
  const {frame,close}=await mount('create',{contextCode:503});assert.equal(await frame.locator('#fields').isVisible(),false);assert.equal(await frame.locator('#submit').innerText(),'重新加载');state.contextCode=200;await frame.locator('#submit').click();await finish(frame);assert.equal(await frame.locator('#fields').isVisible(),true);await close();
 });
 await scenario('invalid context fails closed and metadata cannot execute HTML',async()=>{
  const {frame,close}=await mount('credential',{context:{mode:'unknown',target:'local',account:'',service:'',name:''}});assert.equal(await frame.locator('#fields').isVisible(),false);
  state.context={mode:'credential',target:'cloud',account:'<img src=x onerror=alert(1)>',service:'<script>bad()</script>',name:''};await frame.locator('#submit').click();await finish(frame);assert.equal(await frame.locator('#account').inputValue(),state.context.account);assert.equal(await frame.locator('img,script[src]').count(),0);await close();
 });
 console.log(`LIFECYCLE_CARD_BROWSER_OK ${passed} scenarios; simulated HTTP adapter, actual Edge opaque sandbox; no dependency downloads`);
}finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
