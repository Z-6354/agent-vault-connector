
import fs from 'node:fs'; import path from 'node:path'; import os from 'node:os'; import http from 'node:http';
import {initialize} from './dist/src/vault.js'; import {createServer} from './dist/src/server.js';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'request-debug-'));const dir=path.join(root,'vault');
await initialize(dir,'synthetic debug passphrase');const {app,origin}=await createServer(dir,0);
const key=fs.readFileSync(path.join(dir,'execution.key'),'utf8').trim();
try {
 for(const route of ['/management/session','/management/credentials','/management/unlock','/management/lock','/']) {
  const method=route.endsWith('unlock')||route.endsWith('lock')?'POST':'GET';
  for (const withBody of [true,false]) {
   const result=await new Promise((resolve,reject)=>{
    const request=http.request(`${origin}${route}`,{method,headers:{...(withBody?{'content-type':'application/json'}:{}),authorization:`Bearer ${key}`}},response=>{let text='';response.on('data',chunk=>text+=chunk);response.on('end',()=>resolve({route,method,withBody,status:response.statusCode,text}));});
    request.on('error',reject);request.end(withBody?JSON.stringify({}):undefined);
   }); console.log(JSON.stringify(result));
  }
 }
}finally{await app.close();fs.rmSync(root,{recursive:true,force:true});}
