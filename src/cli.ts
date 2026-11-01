import path from 'node:path';
import { initialize } from './vault.js';
import { createServer } from './server.js';
import { validateNetworkOptions } from './server-config.js';
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
    init: ['--data-dir', '--synthetic'], serve: ['--data-dir', '--port', '--product-config', '--public-origin', '--allowed-origin', '--bind-host', '--diagnose-proxy-headers', '--trusted-proxy'], bridge: ['--origin', '--credential-file'], mock: [],
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
    const diagnostic = options.get('--diagnose-proxy-headers');
    if (diagnostic !== undefined && diagnostic !== 'true' && diagnostic !== 'false') throw new Error('Invalid proxy diagnostic option');
    const trustedProxy = options.get('--trusted-proxy');
    if (trustedProxy !== undefined && trustedProxy !== 'loopback') throw new Error('Invalid trusted proxy option');
    const network = validateNetworkOptions({ trustedProxy, publicOrigin: options.get('--public-origin'), allowedOrigin: options.get('--allowed-origin'), bindHost: options.get('--bind-host'), diagnoseProxyHeaders: diagnostic === 'true' });
    const productConfig = configFile ? readProductConfig(path.resolve(configFile), directory) : undefined;
    const { app, origin, listeningOrigin, executionOrigin } = await createServer(directory, +portText, { productConfig, ...network });
    process.stdout.write(`Vault listening at ${listeningOrigin} (locked)\n`);
    if (origin !== listeningOrigin) process.stdout.write(`Management UI: ${origin}\nLocal execution: ${executionOrigin}\n`);
    if (network.trustedProxy) process.stderr.write('Trusted loopback proxy: a loopback peer does not prove gateway provenance. Restrict the upstream and require the gateway to overwrite/strip forwarded headers; headers are not authentication.\n');
    if (network.bindHost !== '127.0.0.1') process.stderr.write('Nonloopback upstream: firewall to the TLS proxy only; do not expose this HTTP socket publicly.\n');
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
