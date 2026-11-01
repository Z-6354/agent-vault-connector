import path from 'node:path';
import { initialize } from './vault.js';
import { createServer } from './server.js';
import { startBridge } from './bridge.js';
import { startMock } from './mock.js';
import { markSyntheticProduct, readProductConfig } from './product-config.js';

async function hiddenInput(prompt: string): Promise<string> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Initialization requires an interactive terminal');
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let value = '';
    const restore = () => {
      process.stdin.off('data', onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write('\n');
    };
    const onData = (chunk: Buffer) => {
      for (const character of chunk.toString('utf8')) {
        if (character === '\u0003' || character === '\u0004') { restore(); reject(new Error('Initialization cancelled')); return; }
        if (character === '\r' || character === '\n') { restore(); resolve(value); return; }
        if (character === '\u007f' || character === '\b') value = [...value].slice(0, -1).join('');
        else if (character >= ' ' && value.length < 1024) value += character;
      }
    };
    process.stdin.on('data', onData);
  });
}

async function main() {
  process.umask(0o077);
  const [command, ...args] = process.argv.slice(2);
  const permitted: Record<string, string[]> = {
    init: ['--data-dir', '--synthetic'], serve: ['--data-dir', '--port', '--product-config'], bridge: ['--origin', '--credential-file'], mock: [],
  };
  if (!command || !permitted[command]) throw new Error('Usage: cli.js init|serve|bridge|mock [options]');
  const options = new Map<string, string>();
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i]!;
    const value = args[i + 1];
    if (!permitted[command]!.includes(name) || value === undefined || options.has(name)) throw new Error('Invalid command options');
    options.set(name, value);
  }
  const directory = path.resolve(options.get('--data-dir') ?? './data');
  if (command === 'init') {
    if (options.has('--synthetic') && options.get('--synthetic') !== 'true') throw new Error('Invalid synthetic option');
    let first = await hiddenInput('New passphrase (12+ characters): ');
    let second = await hiddenInput('Confirm passphrase: ');
    if (first !== second) throw new Error('Passphrases do not match');
    await initialize(directory, first);
    if (options.get('--synthetic') === 'true') markSyntheticProduct(directory);
    first = ''; second = '';
    process.stdout.write('Vault initialized. Execution credential stored in execution.key.\n');
  } else if (command === 'serve') {
    const portText = options.get('--port') ?? '43120';
    if (!/^\d+$/.test(portText) || +portText < 1 || +portText > 65535) throw new Error('Invalid port');
    const configFile = options.get('--product-config');
    const productConfig = configFile ? readProductConfig(path.resolve(configFile), directory) : undefined;
    const { app, origin } = await createServer(directory, +portText, { productConfig });
    process.stdout.write(`Vault listening at ${origin} (locked)\n`);
    for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => {
      void app.close().then(() => process.exit(0), () => process.exit(1));
    });
  } else if (command === 'bridge') {
    const credentialFile = options.get('--credential-file');
    if (!credentialFile) throw new Error('Execution credential file is required');
    await startBridge(options.get('--origin') ?? 'http://127.0.0.1:43120', path.resolve(credentialFile));
  } else {
    const server = await startMock();
    process.stdout.write('Synthetic mock listening at http://127.0.0.1:43121\n');
    for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => server.close(() => process.exit(0)));
  }
}

main().catch(() => {
  // Do not serialize errors: dependency and network messages can contain input or credentials.
  process.stderr.write('Command failed. Check command options, terminal, vault state and filesystem permissions.\n');
  process.exitCode = 1;
});
