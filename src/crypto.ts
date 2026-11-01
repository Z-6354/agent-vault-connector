import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto';

export interface Sealed { nonce: string; ciphertext: string; tag: string }
export const KDF = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const;

export function deriveKey(passphrase: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(passphrase, salt, 32, KDF, (error, key) => error ? reject(error) : resolve(key));
  });
}

export function seal(key: Buffer, plaintext: Buffer, context: string): Sealed {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(context));
  return {
    nonce: nonce.toString('base64'),
    ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]).toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

export function unseal(key: Buffer, encrypted: Sealed, context: string): Buffer {
  const nonce = Buffer.from(encrypted.nonce, 'base64');
  const tag = Buffer.from(encrypted.tag, 'base64');
  if (nonce.length !== 12 || tag.length !== 16) throw new Error('Invalid encrypted data');
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(Buffer.from(encrypted.ciphertext, 'base64')), decipher.final()]);
}
