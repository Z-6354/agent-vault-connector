import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { randomBytes } from 'node:crypto';
import { initialize, Vault, canonical } from '../src/vault.js';
import { deriveKey, seal } from '../src/crypto.js';
import type { Authority, SavePayload, OperationInput, OperationDefinition } from '../src/contracts.js';
const pass = 'synthetic contract testing passphrase';
const admin: Authority = {owner_id:'local',principal_id:'admin',client_id:'management',session_id:'session-A'};
const execution: Authority = {owner_id:'local',principal_id:'execution:local',client_id:'execution'};
const payload = (account='fixture'):SavePayload => ({mode:'create',label:'Synthetic contract fixture',service_id:'synthetic-mock',credential_type:'api_key',account_alias:account,secret:'synthetic_contract_secret_1234',origin:'http://127.0.0.1:43121',environment:'local',granted_operations:['mock.account_summary']});
const definition: OperationDefinition = {id:'mock.account_summary',service_id:'synthetic-mock',origin:'http://127.0.0.1:43121',semantics:'non_idempotent',business_target:'synthetic-business-target'};
async function fixture(clock?:()=>number, fault?:(point:any)=>void) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'v1-core-'));
  await initialize(dir,pass); let vault = new Vault(dir,{clock,fault}); await vault.authenticate(pass); await vault.unlock(pass);
  return {dir,get vault(){return vault;}, async restart(){vault.close();vault=new Vault(dir,{clock,fault});await vault.authenticate(pass);await vault.unlock(pass);}, close(){vault.close();fs.rmSync(dir,{recursive:true,force:true});}};
}
function approved(vault:Vault,p=payload()) {
  const draft = vault.createDraft(admin,p), approval=vault.approveDraft(admin,draft.draft_id,draft.draft_version);
  return {request_id:vault.prepareRequest(admin,'save_connection'),draft_id:draft.draft_id,draft_version:draft.draft_version,approval_token:approval.approval_token,payload:p};
}
test('canonical encoding distinguishes missing, undefined, null, empty and exact secret bytes',()=>{
  assert.notEqual(canonical({}),canonical({a:undefined})); assert.notEqual(canonical({a:null}),canonical({a:''}));
  assert.notEqual(canonical({secret:' a '}),canonical({secret:'a'})); assert.equal(canonical({b:2,a:1}),canonical({a:1,b:2}));
});
test('full immutable approval, atomic rollback at every save boundary, single consumption and durable lost-response replay',async()=>{
  let failure: string|undefined;
  const f=await fixture(undefined,p=>{if(p===failure)throw new Error('synthetic transaction failure');});
  try {
    const v=f.vault, request=approved(v);
    const original=v.draftPayload(admin,request.draft_id);original.secret='synthetic_mutation_attempt';
    assert.equal(v.draftPayload(admin,request.draft_id).secret,request.payload.secret);
    for(const point of ['after_write','after_approval_consumed','after_request_result']){
      failure=point;assert.throws(()=>v.saveApproved(admin,request),/synthetic transaction failure/);assert.equal(v.list().length,0);
      const db=new Database(path.join(f.dir,'vault.sqlite'),{readonly:true});try{assert.equal((db.prepare('SELECT COUNT(*) AS n FROM requests').get() as any).n,0);assert.equal((db.prepare('SELECT COUNT(*) AS n FROM consumed_drafts').get() as any).n,0);assert.equal((db.prepare('SELECT COUNT(*) AS n FROM audit_events').get() as any).n,0);}finally{db.close();}
    }
    failure=undefined;
    for(const changed of [{secret:'synthetic_different_secret'},{label:'changed'},{granted_operations:[]},{account_alias:'different-target'}]) assert.throws(()=>v.saveApproved(admin,{...request,payload:{...request.payload,...changed}}),/approval_payload_conflict/);
    assert.throws(()=>v.approveDraft({...admin,session_id:'other'},request.draft_id,1),/authority/);
    const record=v.saveApproved(admin,request);assert.equal(record.record_version,1);assert.equal(v.list().length,1);
    assert.throws(()=>v.saveApproved(admin,{...request,request_id:v.prepareRequest(admin,'save_connection')}),/consumed/);
    await f.restart();const replay=f.vault.saveApproved({...admin,session_id:'new-session'},request);assert.deepEqual(replay,record);assert.equal(f.vault.list().length,1);
    assert.deepEqual(f.vault.getSaveResult({...admin,session_id:'new-session'},request.request_id),record);
    assert.throws(()=>f.vault.getSaveResult(execution,request.request_id),/Admin session/);
    assert.throws(()=>f.vault.getSaveResult({...admin,principal_id:'other'},request.request_id),/Admin session/);
    assert.throws(()=>f.vault.getSaveResult(admin,request.request_id+'x'),/request_invalid/);
    assert.throws(()=>f.vault.getSaveResult(admin,f.vault.prepareRequest(admin,'other')),/request_scope_denied/);
    assert.throws(()=>f.vault.getSaveResult(admin,f.vault.prepareRequest(admin,'save_connection')),/Request not found/);
    assert.throws(()=>f.vault.saveApproved(admin,{...request,payload:{...request.payload,secret:'synthetic_conflict'}}),/idempotency_conflict/);
    assert.throws(()=>f.vault.saveApproved({...admin,principal_id:'other'},request),/request_scope_denied/);
    const bytes=fs.readFileSync(path.join(f.dir,'vault.sqlite'));
    assert(!bytes.includes(Buffer.from(request.payload.secret)));assert(!bytes.includes(Buffer.from(canonical(request.payload))));
    const db=new Database(path.join(f.dir,'vault.sqlite'),{readonly:true});try{const row=db.prepare('SELECT canonical_encrypted FROM requests').get() as any;assert.equal(typeof JSON.parse(row.canonical_encrypted).nonce,'string');const audit=db.prepare('SELECT * FROM audit_events').all();assert(!JSON.stringify(audit).includes(request.payload.secret));}finally{db.close();}
  }finally{f.close();}
});
test('record CAS, independent status/material CAS and unique logical account',async()=>{
  const f=await fixture();try{
    const v=f.vault,r=v.saveApproved(admin,approved(v));
    assert.throws(()=>v.saveApproved(admin,approved(v)),/identity_conflict/);
    const paused=v.setStatus(admin,r.id,'paused',r.status_version);assert.equal(paused.record_version,1);assert.equal(paused.status_version,2);
    assert.throws(()=>v.setStatus(admin,r.id,'active',1),/status_version_conflict/);
    const replacement={...payload(),mode:'replace' as const,target_record_id:r.id,expected_record_version:1,secret:'synthetic_replacement_secret'};
    const a=approved(v,replacement),b=approved(v,replacement);const next=v.saveApproved(admin,a);
    assert.equal(next.record_version,2);assert.equal(next.status_version,3);assert.equal(next.material_version,2);assert.equal(next.status,'paused');
    assert.throws(()=>v.saveApproved(admin,b),/record_version_conflict/);
    assert.throws(()=>v.delete(admin,r.id,1),/record_version_conflict/);v.delete(admin,r.id,2);assert.equal(v.list().length,0);
  }finally{f.close();}
});
test('external references contain no secret envelope or delegated execution authority',async()=>{
  const f=await fixture();try{
    const v=f.vault,p:SavePayload={...payload(),service_id:'external-reference',credential_type:'external_reference',origin:'https://external.example',granted_operations:[],secret:''};
    const request=approved(v,p),record=v.saveApproved(admin,request);
    assert.equal(record.storage_mode,'external_reference');assert.equal(record.can_execute,false);assert.equal(record.status,'unknown');
    const db=new Database(path.join(f.dir,'vault.sqlite'),{readonly:true});try{assert.equal((db.prepare('SELECT encrypted FROM credentials WHERE id=?').get(record.id) as any).encrypted,'');}finally{db.close();}
    await assert.rejects(v.withToken(record.id,async()=>assert.fail('External reference must not yield material')),/external_execution_unsupported/);
    const input:OperationInput={request_id:v.prepareRequest(execution,'external.action'),connection_id:record.id,operation_id:'external.action',expected_record_version:1,args:{}};
    assert.throws(()=>v.beginOperation(execution,input,{id:'external.action',service_id:p.service_id,origin:p.origin,semantics:'read_only',business_target:'fixture'}),/external_execution_unsupported/);
    assert.deepEqual(v.getSaveResult(admin,request.request_id),record);
  }finally{f.close();}
});
test('signed scoped tickets: expired new IDs, seven-day retention and immediate purge never reexecute',async()=>{
  let now=1_800_000_000_000;const f=await fixture(()=>now);try{
    const v=f.vault,expired=v.prepareRequest(admin,'save_connection');now+=86_400_000;
    const request=approved(v);assert.throws(()=>v.saveApproved(admin,{...request,request_id:expired}),/request_expired/);
    assert.throws(()=>v.saveApproved(admin,{...request,request_id:request.request_id+'x'}),/request_invalid/);
    const wrongOp=v.prepareRequest(admin,'other');assert.throws(()=>v.saveApproved(admin,{...request,request_id:wrongOp}),/request_scope_denied/);
    const record=v.saveApproved(admin,request);assert.deepEqual(v.getSaveResult(admin,request.request_id),record);v.purgeComparison(admin,request.request_id,'save_connection');assert.throws(()=>v.saveApproved(admin,request),/result_unavailable/);assert.throws(()=>v.getSaveResult(admin,request.request_id),/result_unavailable/);assert.equal(v.list().length,1);
    const second=approved(v,payload('second'));v.saveApproved(admin,second);now+=7*86_400_000;assert.throws(()=>v.getSaveResult(admin,second.request_id),/result_unavailable/);v.cleanupRetention();assert.throws(()=>v.saveApproved(admin,second),/result_unavailable/);
    assert(v.list().some(item=>item.id===record.id));assert.equal(v.list().length,2);
    v.lock();assert.throws(()=>v.saveApproved(admin,request),/Vault locked/);assert.throws(()=>v.getSaveResult(admin,request.request_id),/Vault locked/);
  }finally{f.close();}
});
test('draft, approval TTLs and epoch invalidation; authentication alone never decrypts',async()=>{
  let now=1_800_000_000_000;const f=await fixture(()=>now);try{
    const v=f.vault,first=approved(v);now+=120_000;assert.throws(()=>v.saveApproved(admin,first),/Approval required/);
    const second=approved(v);now+=600_000;assert.throws(()=>v.saveApproved(admin,second),/Draft expired/);
    const third=approved(v),old=v.epoch,key=v.requireUnlocked();v.lock();assert(v.epoch>old);assert(key.every(x=>x===0));
    await v.authenticate(pass);assert.equal(v.unlocked,false);assert.throws(()=>v.list(),/Vault locked/);await v.unlock(pass);assert.throws(()=>v.saveApproved(admin,third),/Draft expired/);
    const db=new Database(path.join(f.dir,'vault.sqlite'),{readonly:true});try{const meta=db.prepare('SELECT * FROM vault_meta').get() as any;assert.notEqual(meta.salt,meta.auth_salt);assert.notEqual(v.requireUnlocked().toString('base64'),meta.auth_verifier);}finally{db.close();}
  }finally{f.close();}
});
test('external dispatch crash/timeout replay is unknown, durable and blocks new-ID duplicate side effects',async()=>{
  const f=await fixture();try{
    let v=f.vault;const r=v.saveApproved(admin,approved(v));
    const input:OperationInput={request_id:v.prepareRequest(execution,definition.id),connection_id:r.id,operation_id:definition.id,expected_record_version:1,args:{}};
    assert.equal(v.beginOperation(execution,input,definition).operation.state,'accepted');assert.equal(v.markDispatching(execution,input).state,'dispatching');
    await f.restart();v=f.vault;assert.equal(v.getOperationStatus(execution,input.request_id,input.operation_id).state,'outcome_unknown');
    assert.equal(v.beginOperation(execution,input,definition).replayed,true);
    assert.throws(()=>v.beginOperation(execution,{...input,request_id:v.prepareRequest(execution,definition.id)},definition),/reconciliation_required/);
    assert.throws(()=>v.beginOperation(execution,{...input,args:{changed:true}},definition),/idempotency_conflict/);
    assert.throws(()=>v.markDispatching(execution,input),/Dispatch denied/);
    const readDefinition={...definition,semantics:'read_only' as const};const read={...input,request_id:v.prepareRequest(execution,definition.id)};
    assert.equal(v.beginOperation(execution,read,readDefinition).replayed,false);v.markDispatching(execution,read);v.finishOperation(execution,read,'outcome_unknown');
    assert.equal(v.beginOperation(execution,read,readDefinition).operation.state,'outcome_unknown');
    const history=v.listOperationHistory(admin);assert.equal(history.filter(x=>x.state==='outcome_unknown').length,2);
    const unknown=v.getOperationStatus(execution,input.request_id,input.operation_id);
    const reconcile={request_id:input.request_id,operation_name:input.operation_id,principal_id:execution.principal_id,expected_operation_status_version:unknown.operation_status_version,resolution:'authorize_new_attempt' as const,evidence_note:'Synthetic server evidence reviewed'};
    assert.throws(()=>v.reconcileOperation(execution,{...reconcile,accept_duplicate_risk:true}),/Admin session/);
    assert.throws(()=>v.reconcileOperation(admin,reconcile),/acknowledgement/);
    const resolved=v.reconcileOperation(admin,{...reconcile,accept_duplicate_risk:true});assert.equal(resolved.state,'failed_confirmed');
    assert.throws(()=>v.reconcileOperation(admin,{...reconcile,accept_duplicate_risk:true}),/status_version_conflict/);
    const secondUnknown=v.getOperationStatus(execution,read.request_id,read.operation_id);
    v.reconcileOperation(admin,{...reconcile,request_id:read.request_id,expected_operation_status_version:secondUnknown.operation_status_version,resolution:'confirmed_failed'});
    assert.equal(v.beginOperation(execution,{...input,request_id:v.prepareRequest(execution,definition.id)},definition).replayed,false);
  }finally{f.close();}
});
test('accepted but never dispatched recovers as failed_before_dispatch; policy/status/version rechecked before dispatch',async()=>{
  const f=await fixture();try{
    const v=f.vault,r=v.saveApproved(admin,approved(v));
    const input:OperationInput={request_id:v.prepareRequest(execution,definition.id),connection_id:r.id,operation_id:definition.id,expected_record_version:1,args:{}};
    v.beginOperation(execution,input,definition);v.setStatus(admin,r.id,'paused',1);assert.throws(()=>v.markDispatching(execution,input),/Operation denied/);
    await f.restart();assert.equal(f.vault.getOperationStatus(execution,input.request_id,input.operation_id).state,'failed_before_dispatch');
  }finally{f.close();}
});
test('OAuth internal material lease CAS preserves record version; unknown/epoch lease fails closed',async()=>{
  const f=await fixture();try{
    const v=f.vault,p:SavePayload={...payload(),service_id:'github',credential_type:'oauth',origin:'https://api.github.com',granted_operations:['github.current_user'],secret:JSON.stringify({schema:1,provider:'github',approvedScopes:['read:user']})};
    const r=v.saveApproved(admin,approved(v,p)),lease=v.reserveMaterial(admin,r.id,r,'authorize');
    assert.throws(()=>v.reserveMaterial(admin,r.id,r,'refresh'),/unresolved/);
    const replacement=approved(v,{...p,mode:'replace',target_record_id:r.id,expected_record_version:r.record_version});
    assert.throws(()=>v.saveApproved(admin,replacement),/material_change_unresolved/);
    assert.throws(()=>v.completeMaterial({...admin,principal_id:'other'},r.id,lease.lease_id,{status:'active',secret:'synthetic_wrong_principal'}),/lease_conflict/);
    const next=v.completeMaterial(admin,r.id,lease.lease_id,{status:'active',secret:JSON.stringify({schema:1,provider:'github',approvedScopes:['read:user'],material:{accessToken:'synthetic_oauth_access'}}),expected_epoch:v.epoch});
    assert.equal(next.record_version,1);assert.equal(next.status_version,2);assert.equal(next.material_version,2);
    assert.throws(()=>v.reserveMaterial(admin,r.id,r,'refresh'),/version_conflict/);
    const pending=v.reserveMaterial(admin,r.id,next,'refresh');v.lock();await v.unlock(pass);
    assert.throws(()=>v.completeMaterial(admin,r.id,pending.lease_id,{status:'active'}),/lease_conflict/);
    assert.throws(()=>v.reserveMaterial(admin,r.id,next,'refresh'),/unresolved/);
    const reconciliation={expected_record_version:next.record_version,expected_status_version:next.status_version,expected_material_version:next.material_version,evidence_note:'Synthetic upstream token status verified',abandon_old_material:true as const};
    assert.throws(()=>v.reconcileMaterial(execution,r.id,reconciliation),/Admin session/);
    assert.throws(()=>v.reconcileMaterial(admin,r.id,{...reconciliation,expected_material_version:99}),/version_conflict/);
    const reset=v.reconcileMaterial(admin,r.id,reconciliation);assert.equal(reset.status,'needs_user_action');assert.equal(reset.material_change_unresolved,false);assert.equal(reset.record_version,next.record_version);assert.equal(reset.material_version,next.material_version+1);
    const retained=v.readMaterial(admin,r.id).secret;assert(!retained.includes('synthetic_oauth_access'));assert(!retained.includes('material'));
    assert.doesNotThrow(()=>v.reserveMaterial(admin,r.id,reset,'authorize'));
  }finally{f.close();}
});
test('resource authorization rejection only disables the exact current OAuth material and epoch',async()=>{
  const f=await fixture();try{
    const v=f.vault,p:SavePayload={...payload(),service_id:'github',credential_type:'oauth',origin:'https://api.github.com',granted_operations:['github.current_user'],secret:JSON.stringify({schema:1,provider:'github',approvedScopes:['read:user']})};
    const created=v.saveApproved(admin,approved(v,p)),lease=v.reserveMaterial(admin,created.id,created,'authorize');
    const active=v.completeMaterial(admin,created.id,lease.lease_id,{status:'active',secret:JSON.stringify({schema:1,provider:'github',approvedScopes:['read:user'],material:{accessToken:'synthetic_auth_cas'}}),expected_epoch:v.epoch});
    v.requireOAuthReauthorization(execution,active.id,active,v.epoch-1);assert.equal(v.get(active.id).status,'active');
    v.requireOAuthReauthorization(execution,active.id,{...active,material_version:active.material_version-1},v.epoch);assert.equal(v.get(active.id).status,'active');
    const refresh=v.reserveMaterial(admin,active.id,active,'refresh');
    v.requireOAuthReauthorization(execution,active.id,active,v.epoch);assert.equal(v.get(active.id).status,'active');
    const renewed=v.completeMaterial(admin,active.id,refresh.lease_id,{status:'active',expected_epoch:v.epoch});
    v.requireOAuthReauthorization(execution,active.id,active,v.epoch);assert.equal(v.get(active.id).status,'active');
    v.requireOAuthReauthorization(execution,active.id,renewed,v.epoch);assert.equal(v.get(active.id).status,'needs_user_action');
    assert.equal(v.get(active.id).record_version,active.record_version);assert.equal(v.get(active.id).material_version,renewed.material_version);
  }finally{f.close();}
});
test('persisted epoch invalidates another open vault master key and signing-key loss never regenerates tickets',async()=>{
  const f=await fixture();let second:Vault|undefined;
  try {
    const retained=f.vault.requireUnlocked();second=new Vault(f.dir);assert.equal(f.vault.unlocked,false);assert(retained.every(byte=>byte===0));
    const pendingUnlock=f.vault.unlock(pass);second.lock();await assert.rejects(pendingUnlock,/Vault locked/);assert.equal(f.vault.unlocked,false);
    await second.unlock(pass);second.close();second=undefined;
    const signing=path.join(f.dir,'request-signing.key'),bytes=fs.readFileSync(signing);fs.unlinkSync(signing);
    assert.throws(()=>new Vault(f.dir));assert.equal(fs.existsSync(signing),false);
    fs.writeFileSync(signing,bytes,{mode:0o600});
  } finally {second?.close();f.close();}
});
test('legacy encrypted records migrate without changing ciphertext, nonce or AAD; default paused until explicit approval',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'v1-migration-'));let v:Vault|undefined;
  try{
    const salt=randomBytes(32),key=await deriveKey(pass,salt),id='00000000-0000-4000-8000-000000000001';
    const aad=`agent-vault:v1:local:${id}:synthetic-mock:token`,encrypted=JSON.stringify(seal(key,Buffer.from('synthetic_legacy_preserved'),aad));
    const filename=path.join(dir,'vault.sqlite');fs.writeFileSync(filename,'',{mode:0o600});const db=new Database(filename);
    try{db.exec(fs.readFileSync(path.join(process.cwd(),'migrations/001-initial.sql'),'utf8'));db.prepare('INSERT INTO vault_meta(id,version,salt,verifier,execution_hash)VALUES(1,1,?,?,?)').run(salt.toString('base64'),JSON.stringify(seal(key,Buffer.from('agent-vault-key-check-v1'),'agent-vault:v1:local:verifier')),'not-an-execution-key');db.prepare('INSERT INTO credentials VALUES(?,?,?,?,?,?,?)').run(id,'local','Legacy fixture','synthetic-mock',encrypted,'2026-01-01','2026-01-01');}finally{db.close();key.fill(0);}
    v=new Vault(dir);await v.authenticate(pass);assert.equal(v.unlocked,false);await v.unlock(pass);const r=v.get(id);assert.equal(r.status,'paused');assert.equal(r.record_version,1);assert.equal(r.account_alias,`legacy:${id}`);
    const check=new Database(filename,{readonly:true});try{const row=check.prepare('SELECT * FROM credentials').get() as any;assert.equal(row.encrypted,encrypted);assert.equal(row.encryption_context,aad);assert.equal(check.pragma('user_version',{simple:true}),4);}finally{check.close();}
    const backupDb = new Database(path.join(dir,'vault.pre-v1-to-v3.sqlite'),{readonly:true});
    try { assert.equal(backupDb.pragma('user_version',{simple:true}),1); assert.equal((backupDb.prepare('SELECT encrypted FROM credentials').get() as any).encrypted,encrypted); } finally { backupDb.close(); }
    const beforeBackup = fs.readFileSync(path.join(dir,'vault.pre-v1-to-v3.sqlite'));
    v.close();v=new Vault(dir);await v.unlock(pass);assert.equal(v.list().length,1);
    assert.deepEqual(fs.readFileSync(path.join(dir,'vault.pre-v1-to-v3.sqlite')),beforeBackup);
  }finally{v?.close();fs.rmSync(dir,{recursive:true,force:true});}
});
