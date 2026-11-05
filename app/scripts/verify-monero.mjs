import { readFileSync, writeFileSync, mkdirSync, createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import * as openpgp from 'openpgp';

const directory = resolve('.tools/monero');
const fingerprint = '81ac591fe9c4b65c5806afc3f0af4d462a0bdf92';
const filename = 'monero-win-x64-v0.18.5.4.zip';
const key = await openpgp.readKey({ armoredKey: readFileSync(`${directory}/verification/binaryfate.asc`, 'utf8') });
if (key.getFingerprint() !== fingerprint) throw new Error('Monero signing-key fingerprint mismatch.');
const message = await openpgp.readCleartextMessage({ cleartextMessage: readFileSync(`${directory}/verification/hashes.txt`, 'utf8') });
const verified = await openpgp.verify({ message, verificationKeys: key });
if (verified.signatures.length !== 1) throw new Error('Expected one release signature.');
await verified.signatures[0].verified;
const entry = verified.data.split(/\r?\n/).find(line => line.endsWith(`  ${filename}`));
if (!entry || !/^[a-f0-9]{64}  /.test(entry)) throw new Error('Pinned Windows archive absent from signed manifest.');
const hash = createHash('sha256');
for await (const chunk of createReadStream(`${directory}/${filename}`)) hash.update(chunk);
const actual = hash.digest('hex');
if (actual !== entry.slice(0, 64)) throw new Error('Archive hash does not match signed manifest.');
const result = { version: '0.18.5.4', archive: filename, sha256: actual, signingKey: fingerprint, signatureVerified: true,
  manifest: 'https://www.getmonero.org/downloads/hashes.txt', key: 'https://raw.githubusercontent.com/monero-project/monero/v0.18.5.4/utils/gpg_keys/binaryfate.asc', verifiedAt: new Date().toISOString() };
mkdirSync(`${directory}/verification`, { recursive: true });
writeFileSync(`${directory}/verification/verified.json`, JSON.stringify(result, null, 2));
console.log(`Verified release signature and SHA-256: ${filename}`);
