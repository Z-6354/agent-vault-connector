// Capture actual local validation, including failing output and exact source snapshot hashes.
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
const directory=path.resolve('docs/evidence');fs.mkdirSync(directory,{recursive:true});
function sourceHashes(){
  const hashes={};
  for(const root of ['src','tests','migrations','public','scripts']){
    for(const entry of fs.readdirSync(root,{recursive:true})){const file=path.join(root,String(entry));if(fs.statSync(file).isFile())hashes[file]=createHash('sha256').update(fs.readFileSync(file)).digest('hex');}
  }
  for(const file of ['package.json','package-lock.json','tsconfig.json'])hashes[file]=createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  return hashes;
}
const report={started:new Date().toISOString(),node:process.version,platform:process.platform,synthetic_only:true,commands:[],sources:sourceHashes()};
async function run(command,args,filename){
  const stream=fs.createWriteStream(path.join(directory,filename));
  const start=Date.now();stream.write(`Command: ${[command,...args].join(' ')}\nStarted: ${new Date().toISOString()}\n`);
  const child=spawn(command,args,{env:{...process.env,HEADLESS:'1'},stdio:['ignore','pipe','pipe']});
  child.stdout.on('data',b=>{stream.write(b);process.stdout.write(b);});child.stderr.on('data',b=>{stream.write(b);process.stderr.write(b);});
  const exit=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});
  stream.end(`\nExit code: ${exit}\n`);await new Promise(resolve=>stream.once('finish',resolve));
  report.commands.push({command:[command,...args].join(' '),exit_code:exit,duration_ms:Date.now()-start,log:filename});return exit;
}
try {
  let code=await run('npm',['run','build'],'v1-current-build.log');
  if(!code)code=await run('npm',['test'],'v1-current-tests.log');
  if(!code)code=await run(process.execPath,['scripts/v1-app-smoke.mjs'],'v1-current-app-smoke.log');
  if(!code)code=await run(process.execPath,['dist/src/browser-demo-run.js'],'v1-current-browser-demo.log');
  const testLog=fs.existsSync(path.join(directory,'v1-current-tests.log'))?fs.readFileSync(path.join(directory,'v1-current-tests.log'),'utf8'):'';
  for(const key of ['tests','pass','fail','cancelled','skipped','todo']){const match=testLog.match(new RegExp(`^# ${key} (\\d+)$`,'m'));if(match)report[key]=Number(match[1]);}
  report.result=code===0?'passed':'failed';process.exitCode=code||0;
} catch {report.result='failed';process.exitCode=1;}
finally {
  const finalSources=sourceHashes();
  report.source_snapshot_unchanged=JSON.stringify(report.sources)===JSON.stringify(finalSources);
  if(!report.source_snapshot_unchanged){report.result='failed';report.source_changes=Object.keys({...report.sources,...finalSources}).filter(file=>report.sources[file]!==finalSources[file]);process.exitCode=1;}
  report.completed=new Date().toISOString();fs.writeFileSync(path.join(directory,'v1-current-validation.json'),JSON.stringify(report,null,2)+'\n');
}
