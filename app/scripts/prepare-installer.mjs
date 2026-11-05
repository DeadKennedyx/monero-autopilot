import { copyFileSync, createReadStream, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const native = resolve(root, 'src-tauri');
const source = resolve(root, '.tools/monero/release/monero-x86_64-w64-mingw32-v0.18.5.4');
const constants = readFileSync(resolve(root, 'crates/wallet-rpc/src/lib.rs'), 'utf8');
const binaries = [ ['monerod.exe', 'DAEMON_SHA256'], ['monero-wallet-rpc.exe', 'WALLET_SHA256'] ];
const manifest = [];
for (const [file, constant] of binaries) {
  const expected = constants.match(new RegExp(`pub const ${constant}: &str = "([a-f0-9]{64})";`))?.[1];
  if (!expected) throw new Error('Missing pinned hash for ' + file);
  const path = resolve(source, file);
  if (!existsSync(path)) throw new Error('Verified runtime is missing: ' + file);
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  if (hash.digest('hex') !== expected) throw new Error('Runtime verification failed: ' + file);
  manifest.push({ file, sha256: expected });
}
const binaryTarget = resolve(native, 'resources/monero');
const licenseTarget = resolve(native, 'resources/licenses');
mkdirSync(binaryTarget, { recursive: true });
mkdirSync(licenseTarget, { recursive: true });
// Copy only allowlisted executables and licenses. Never package .runtime,
// wallet files, development privacy settings, or the entire source repository.
for (const { file } of manifest) copyFileSync(resolve(source, file), resolve(binaryTarget, file));
copyFileSync(resolve(source, 'LICENSE'), resolve(licenseTarget, 'Monero-LICENSE.txt'));
copyFileSync(resolve(root, '../LICENSE'), resolve(licenseTarget, 'AutoPilot-LICENSE.txt'));
for (const file of ['tor.txt', 'openssl.txt', 'libevent.txt', 'zlib.txt']) {
  copyFileSync(resolve(root, '.tools/tor/release/docs', file), resolve(licenseTarget, file));
}
const allowedBinaries = new Set(manifest.map(entry => entry.file));
if (readdirSync(binaryTarget).some(file => !allowedBinaries.has(file))) throw new Error('Unexpected file in installer runtime staging.');
writeFileSync(resolve(native, 'resources/runtime-manifest.json'), JSON.stringify({ monero: '0.18.5.4', binaries: manifest }, null, 2));
console.log('Installer resources verified: two Monero executables and upstream licenses. Tor remains embedded in the app.');
