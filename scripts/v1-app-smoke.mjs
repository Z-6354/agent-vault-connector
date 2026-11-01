// Independent executable smoke of the built CLI app, using only a fresh synthetic vault.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { chromium } from 'playwright-core';
import { initialize } from '../dist/src/vault.js';
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'v1-app-smoke-'));
const directory = path.join(root, 'vault');
const passphrase = 'synthetic isolated app smoke passphrase';
const secret = 'synthetic_isolated_app_smoke_token';
const evidence = path.resolve('docs/evidence');
fs.mkdirSync(evidence,{recursive:true});
let app; let browser; let output=''; const started = new Date().toISOString();
try {
  await initialize(directory,passphrase);
  const socket = net.createServer(); await new Promise(r=>socket.listen(0,'127.0.0.1',r)); const port=socket.address().port; await new Promise(r=>socket.close(r));
  app = spawn(process.execPath,['dist/src/cli.js','serve','--data-dir',directory,'--port',String(port)],{stdio:['ignore','pipe','pipe'],env:{PATH:process.env.PATH,HOME:root,TMPDIR:root,NODE_ENV:'test',HEADLESS:'1'}});
  app.stdout.on('data',b=>{output+=b;});app.stderr.on('data',b=>{output+=b;});
  const origin=`http://127.0.0.1:${port}`;
  await new Promise((resolve,reject)=>{const start=Date.now();const poll=setInterval(async()=>{try{if(app.exitCode!==null)throw new Error('CLI exited');if(Date.now()-start>10000)throw new Error('CLI timeout');const r=await fetch(origin);if(r.ok){clearInterval(poll);resolve();}}catch(error){if(app.exitCode!==null||Date.now()-start>10000){clearInterval(poll);reject(error);}}},50);});
  browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,chromiumSandbox:true,args:['--disable-dev-shm-usage'],env:{...process.env,HEADLESS:'1'}});
  const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(origin);
  await page.getByLabel('Administrator passphrase',{exact:true}).fill(passphrase);await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await page.getByRole('button',{name:'Unlock vault',exact:true}).waitFor();
  await page.getByLabel('Unlock passphrase',{exact:true}).fill(passphrase);await page.getByRole('button',{name:'Unlock vault',exact:true}).click();
  await page.getByRole('button',{name:'Lock vault',exact:true}).waitFor();
  await page.getByLabel('Label',{exact:true}).fill('Isolated CLI app smoke');await page.getByLabel('Account alias',{exact:true}).fill('smoke-account');await page.getByLabel('Secret',{exact:true}).fill(secret);await page.getByLabel('mock.account_summary',{exact:true}).check();
  await page.getByRole('button',{name:'Review connection',exact:true}).click();await page.getByRole('button',{name:'Confirm and save',exact:true}).waitFor();
  await page.getByRole('button',{name:'Confirm and save',exact:true}).click();await page.locator('#credentials').getByText('Isolated CLI app smoke',{exact:true}).waitFor();
  if((await page.locator('body').innerText()).includes(secret))throw new Error('Secret visible');
  await page.getByText('Recent audit events',{exact:true}).click();
  await page.locator('#audit-events').getByText('connection_created',{exact:false}).waitFor();
  await page.getByText('Recover a save result',{exact:true}).click();
  await page.getByRole('button',{name:'Recover save result',exact:true}).click();
  await page.locator('#save-recovery-result').getByText('Isolated CLI app smoke',{exact:false}).waitFor();
  await page.screenshot({path:path.join(evidence,'v1-app-smoke.png'),fullPage:true});
  await page.getByRole('button',{name:'Delete',exact:true}).click();await page.getByText('No connections yet.',{exact:false}).waitFor();
  await page.getByRole('button',{name:'Lock vault',exact:true}).click();await page.getByRole('button',{name:'Unlock vault',exact:true}).waitFor();
  if(errors.length)throw new Error('Browser errors');if(output.includes(secret)||output.includes(passphrase))throw new Error('Secret in process output');
  fs.writeFileSync(path.join(evidence,'v1-app-smoke.json'),JSON.stringify({started,completed:new Date().toISOString(),entrypoint:'node dist/src/cli.js serve',browser:'sandboxed system Chromium via Playwright',synthetic:true,checks:['CLI socket served','S0 to S1 login','S1 to S2 unlock','draft review','confirmed encrypted save','safe audit events visible','signed ticket save-result recovery','secret absent from page and logs','delete','lock to S1'],pageErrors:errors.length,result:'passed'},null,2)+'\n');
  process.stdout.write('Independent built CLI + Chromium smoke passed.\n');
} finally {
  await browser?.close();
  if(app&&app.exitCode===null){app.kill('SIGTERM');await new Promise(resolve=>{app.once('exit',resolve);setTimeout(resolve,3000).unref();});if(app.exitCode===null)app.kill('SIGKILL');}
  fs.rmSync(root,{recursive:true,force:true});
}
