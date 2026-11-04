import {createRequire} from 'node:module';
import {writeFile} from 'node:fs/promises';
const require=createRequire(process.env.HERMES_DESKTOP_PACKAGE);
const {chromium}=require('playwright');
const browser=await chromium.launch({channel:'msedge',headless:true});
try {
 const context=await browser.newContext();const page=await context.newPage();let extraPages=0;
 context.on('page',()=>extraPages++);
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(process.env.HOST_URL+'/reference-host.html');
 await page.waitForFunction(()=>window.__hostReady===true);
 const request=JSON.parse(process.env.CARD_REQUEST);
 await page.evaluate(request=>window.mountVaultRequest(request,'inline'),request);
 const frame=page.frameLocator('iframe');
 await frame.locator('#secret').waitFor({state:'visible'});
 await frame.locator('#secret').fill('SYNTHETIC-INLINE-E2E-ONLY');
 if(await frame.locator('#secret').getAttribute('type')!=='password')throw Error('Input not masked');
 const isolated=await page.evaluate(()=>document.querySelector('iframe').contentDocument===null);
 if(!isolated)throw Error('Host can read credential frame DOM');
 const screenshot=await page.screenshot();
 if(process.env.INLINE_SCREENSHOT)await writeFile(process.env.INLINE_SCREENSHOT,screenshot);
 await frame.locator('#submit').click();
 try {await page.waitForFunction(()=>window.__lastResult?.status==='captured',null,{timeout:10000});}
 catch {const probe=await frame.locator('#form').evaluate(form=>({valid:form.checkValidity(),length:form.querySelector('input').value.length,disabled:form.querySelector('input').disabled,notice:form.querySelector('#notice').textContent}));throw Error('Card did not complete: '+JSON.stringify(probe)+'; script errors: '+errors.join(';'));}
 const state=await page.evaluate(()=>window.__lastResult);
 if(state.ref!=='vault://synthetic.example/test-user'||Object.keys(state).sort().join(',')!=='ref,request_id,status')throw Error('Unsafe result');
 if(await page.locator('iframe').count()!==0)throw Error('Input frame not destroyed');
 if((await page.content()).includes('SYNTHETIC-INLINE-E2E-ONLY'))throw Error('Secret leaked into host document');
 if(extraPages!==0)throw Error('External window opened');
 if(errors.length)throw Error('Browser script failed: '+errors.join(';'));
 console.log('INLINE_UI_OK masked / opaque iframe / captured reference / frame destroyed / host DOM clean / no external window');
 await context.close();
} finally {await browser.close();}
