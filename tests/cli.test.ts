import {test} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {Vault} from '../src/vault.js';

test('serve rejects invalid public origin and bind options before vault access', () => {
  for (const args of [
    ['--public-origin', 'https://vault.example/path'],
    ['--allowed-origin', 'https://*.example'],
    ['--public-origin', 'https://vault.example', '--allowed-origin', 'https://vault.example'],
    ['--bind-host', '0.0.0.0'],
    ['--public-origin', 'http://vault.example'],
    ['--trusted-proxy', 'loopback'],
    ['--trusted-proxy', 'loopback', '--public-origin', 'http://127.0.0.1:3210'],
    ['--trusted-proxy', 'true', '--public-origin', 'https://vault.example'],
    ['--trusted-proxy'],
    ['--trusted-proxy', 'loopback', '--trusted-proxy', 'loopback'],
    ['--diagnose-proxy-headers', 'TRUE'],
    ['--diagnose-proxy-headers', '1'],
    ['--diagnose-proxy-headers', ''],
    ['--diagnose-proxy-headers'],
    ['--diagnose-proxy-headers', 'true', '--diagnose-proxy-headers', 'false'],
  ]) {
    const result = (() => { try {
      execFileSync(process.execPath, ['dist/src/cli.js', 'serve', '--data-dir', '/unopened-invalid-config', ...args], { timeout: 5000, stdio: 'pipe' });
    } catch (error) { return error as { status: number; stderr: Buffer }; } })();
    assert(result); assert.equal(result.status, 1);
    assert.match(result.stderr.toString(), /Command failed/);
  }
});

test('built CLI initialization really uses a PTY, hides input, creates usable v3 and refuses overwrite',async()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'v1-cli-'));
  const directory=path.join(root,'vault'),project=process.cwd();let vault:Vault|undefined;
  const env={PATH:process.env.PATH,HOME:root,TMPDIR:root,NODE_ENV:'test'};
  try{
    const output=execFileSync('python3',['tests/pty-init.py',project,directory],{cwd:project,env,timeout:25000,encoding:'utf8'});
    assert.deepEqual(JSON.parse(output),{pty:'passed',echo:false,exitCode:0});
    const before=fs.readFileSync(path.join(directory,'vault.sqlite'));
    assert.throws(()=>execFileSync('python3',['tests/pty-init.py',project,directory],{cwd:project,env,timeout:25000,stdio:'pipe'}));
    assert.deepEqual(fs.readFileSync(path.join(directory,'vault.sqlite')),before);
    assert.throws(()=>execFileSync(process.execPath,['dist/src/cli.js','init','--data-dir',path.join(root,'no-tty')],{cwd:project,env,input:'synthetic passphrase\n',timeout:5000,stdio:'pipe'}));
    vault=new Vault(directory);await vault.authenticate('synthetic acceptance passphrase 2026');assert.equal(vault.unlocked,false);await vault.unlock('synthetic acceptance passphrase 2026');assert.equal(vault.list().length,0);
  }finally{vault?.close();fs.rmSync(root,{recursive:true,force:true});}
});
