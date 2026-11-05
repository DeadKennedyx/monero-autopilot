import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as openpgp from 'openpgp';

const version = '16.0';
const directory = '.tools/tor';
const archive = `tor-expert-bundle-windows-x86_64-${version}.tar.gz`;
const fingerprint = 'ef6e286dda85ea2a4ba7de684e2c6e8793298290';
const key = await openpgp.readKey({ binaryKey: new Uint8Array(readFileSync(`${directory}/verification/tor.key`)) });
if (key.getFingerprint() !== fingerprint) throw new Error('Tor signing key fingerprint mismatch.');
const bytes = new Uint8Array(readFileSync(`${directory}/${archive}`));
const message = await openpgp.createMessage({ binary: bytes });
const signature = await openpgp.readSignature({ armoredSignature: readFileSync(`${directory}/verification/bundle.asc`, 'utf8') });
const result = await openpgp.verify({ message, signature, verificationKeys: key });
if (result.signatures.length !== 1) throw new Error('Expected exactly one Tor release signature.');
await result.signatures[0].verified;
const record = { version, archive, sha256: createHash('sha256').update(bytes).digest('hex'), signingKey: fingerprint,
  signatureVerified: true, release: `https://dist.torproject.org/torbrowser/${version}/${archive}`,
  key: 'https://openpgpkey.torproject.org/.well-known/openpgpkey/torproject.org/hu/kounek7zrdx745qydx6p59t9mqjpuhdf',
  verificationGuide: 'https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/', verifiedAt: new Date().toISOString() };
mkdirSync(`${directory}/verification`, { recursive: true });
writeFileSync(`${directory}/verification/verified.json`, JSON.stringify(record, null, 2));
console.log(`Verified Tor release signature and SHA-256: ${archive}`);
