
import fs from 'node:fs'; import path from 'node:path'; import os from 'node:os';
import {initialize} from './dist/src/vault.js'; import {createServer} from './dist/src/server.js';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'ui-delete-diagnostic-'));
const dir=path.join(root,'vault'); const passphrase='synthetic delete diagnostic passphrase';
await initialize(dir,passphrase); const {app,origin}=await createServer(dir,0);
try {
 let response=await fetch(`${origin}/management/session`); let data=await response.json();
 let cookie=response.headers.get('set-cookie').split(';')[0]; let csrf=data.csrf;
 response=await fetch(`${origin}/management/unlock`,{method:'POST',headers:{cookie,origin,'x-csrf-token':csrf,'content-type':'application/json'},body:JSON.stringify({passphrase})});
 data=await response.json(); cookie=response.headers.get('set-cookie').split(';')[0];csrf=data.csrf;
 const headers={cookie,origin,'x-csrf-token':csrf,'content-type':'application/json'};
 response=await fetch(`${origin}/management/credentials`,{method:'POST',headers,body:JSON.stringify({label:'UI deletion diagnostic',provider:'synthetic-mock',token:'synthetic_delete_diagnostic_123'})});
 data=await response.json(); const id=data.credential.id;
 response=await fetch(`${origin}/management/credentials/${id}`,{method:'DELETE',headers});
 console.log(JSON.stringify({check:'UI-style DELETE with JSON content type and no body',status:response.status,result:await response.json()}));
 response=await fetch(`${origin}/management/credentials`,{headers:{cookie}});data=await response.json();
 console.log(JSON.stringify({check:'credential remains after rejected UI-style DELETE',status:response.status,count:data.credentials.length}));
 response=await fetch(`${origin}/management/credentials/${id}`,{method:'DELETE',headers,body:'{}'});
 console.log(JSON.stringify({check:'DELETE with framed JSON body',status:response.status,result:await response.json()}));
} finally {await app.close();fs.rmSync(root,{recursive:true,force:true});}
