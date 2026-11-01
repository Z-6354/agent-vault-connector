import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { readPrivateFile, createPrivateFile } from './files.js';
import type { BrowserProductConfig } from './browser-product.js';

const endpoint = z.string().url().max(2048).refine(value => {
  const url = new URL(value);
  return url.protocol === 'http:' && url.hostname === '127.0.0.1' && !!url.port && !url.username && !url.password && !url.search && !url.hash;
});
const provider = z.object({ endpoints: z.object({ authorize: endpoint, token: endpoint, identity: endpoint, revoke: endpoint }).strict() }).strict();
const browser = z.object({ enabled: z.boolean(), executablePath: z.string().min(1).max(1024).optional(), headless: z.boolean().optional() }).strict();
const schema = z.discriminatedUnion('mode', [
  z.object({ mode: z.literal('production'), browser: browser.optional() }).strict(),
  z.object({ mode: z.literal('synthetic'), browser: browser.optional(), providers: z.object({ github: provider, google: provider }).strict() }).strict(),
]);
export type ProductConfig = z.infer<typeof schema>;
export type ProductBrowserConfig = BrowserProductConfig;
const marker = '.synthetic-product';
/** Issued only during a fresh local CLI initialization; cannot switch an existing product vault to fixtures. */
export function markSyntheticProduct(directory: string): void {
  createPrivateFile(path.join(directory, marker), 'agent-vault:isolated-synthetic-product:v1\n');
}
export function assertProductMode(directory: string, config?: ProductConfig): void {
  const markerPath = path.join(directory, marker);
  const marked = fs.existsSync(markerPath);
  if (config?.mode === 'synthetic') {
    const proof = readPrivateFile(markerPath);
    try { if (proof.toString() !== 'agent-vault:isolated-synthetic-product:v1\n') throw new Error('synthetic_vault_required'); }
    finally { proof.fill(0); }
  } else if (marked) throw new Error('synthetic_config_required');
}
export function readProductConfig(filename: string, directory: string): ProductConfig {
  const bytes = readPrivateFile(filename);
  try {
    const parsed = schema.safeParse(JSON.parse(bytes.toString()));
    if (!parsed.success) throw new Error('invalid_product_config');
    assertProductMode(directory, parsed.data);
    return parsed.data;
  } finally { bytes.fill(0); }
}
