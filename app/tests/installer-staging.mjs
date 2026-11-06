// Runs the real staging script against disposable synthetic inputs only.
// No installer, native wallet, production .tools, or existing profile is used.
import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../scripts/prepare-installer.mjs', import.meta.url));
const notices = ['AutoPilot-LICENSE.txt', 'Monero-LICENSE.txt', 'libevent.txt', 'openssl.txt', 'tor.txt', 'zlib.txt'];
function fixture(t) {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'autopilot-installer-staging-'));
  t.after(() => {
    const target = realpathSync(temporaryRoot);
    assert.equal(dirname(target).toLowerCase(), realpathSync(tmpdir()).toLowerCase());
    assert.ok(basename(target).startsWith('autopilot-installer-staging-'));
    rmSync(target, { recursive: true, force: true });
  });
  const root = join(temporaryRoot, 'app');
  const source = join(root, '.tools/monero/release/monero-x86_64-w64-mingw32-v0.18.5.4');
  const tor = join(root, '.tools/tor/release/docs');
  const licenses = join(root, 'src-tauri/resources/licenses');
  const binaries = join(root, 'src-tauri/resources/monero');
  for (const directory of [source, tor, licenses, binaries, join(root, 'scripts'), join(root, 'crates/wallet-rpc/src')]) mkdirSync(directory, { recursive: true });
  copyFileSync(script, join(root, 'scripts/prepare-installer.mjs'));
  const constants = [];
  for (const [file, constant] of [['monerod.exe', 'DAEMON_SHA256'], ['monero-wallet-rpc.exe', 'WALLET_SHA256']]) {
    const bytes = Buffer.from('Synthetic non-executable fixture: ' + file);
    writeFileSync(join(source, file), bytes);
    constants.push(`pub const ${constant}: &str = "${createHash('sha256').update(bytes).digest('hex')}";`);
  }
  writeFileSync(join(root, 'crates/wallet-rpc/src/lib.rs'), constants.join('\n'));
  writeFileSync(join(source, 'LICENSE'), 'Synthetic Monero notice');
  writeFileSync(join(temporaryRoot, 'LICENSE'), 'Synthetic app notice');
  for (const file of ['tor.txt', 'openssl.txt', 'libevent.txt', 'zlib.txt']) writeFileSync(join(tor, file), 'Synthetic notice: ' + file);
  const run = () => spawnSync(process.execPath, [join(root, 'scripts/prepare-installer.mjs')], { cwd: temporaryRoot, encoding: 'utf8', windowsHide: true, timeout: 30000 });
  return { temporaryRoot, root, licenses, binaries, run };
}

test('clean staging contains exactly the approved binaries and six notices', t => {
  const f = fixture(t);
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readdirSync(f.licenses).sort(), notices);
  assert.deepEqual(readdirSync(f.binaries).sort(), ['monero-wallet-rpc.exe', 'monerod.exe']);
  assert.equal(JSON.parse(readFileSync(join(f.root, 'src-tauri/resources/runtime-manifest.json'))).binaries.length, 2);
});

for (const kind of ['license', 'runtime']) test(`unexpected ${kind} file aborts before copying and remains untouched`, t => {
  const f = fixture(t);
  const extra = join(kind === 'license' ? f.licenses : f.binaries, 'unexpected-private-report.txt');
  writeFileSync(extra, 'synthetic marker');
  const result = f.run();
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, new RegExp(`Unexpected file in installer ${kind} staging`));
  assert.equal(readFileSync(extra, 'utf8'), 'synthetic marker');
  assert.ok(!existsSync(join(f.binaries, 'monerod.exe')));
  assert.ok(!existsSync(join(f.root, 'src-tauri/resources/runtime-manifest.json')));
});

test('an allowlisted license name must be a plain file, not a directory', t => {
  const f = fixture(t);
  mkdirSync(join(f.licenses, 'tor.txt'));
  const result = f.run();
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unexpected file in installer license staging/);
  assert.ok(!existsSync(join(f.binaries, 'monerod.exe')));
});

test('a linked license staging directory cannot redirect writes', t => {
  const f = fixture(t);
  const outside = join(f.temporaryRoot, 'outside-staging');
  mkdirSync(outside);
  writeFileSync(join(outside, 'marker.txt'), 'unchanged');
  // The exact directory is a new empty fixture directory; no recursive removal.
  assert.equal(resolve(f.licenses), resolve(f.root, 'src-tauri/resources/licenses'));
  rmdirSync(f.licenses);
  symlinkSync(outside, f.licenses, process.platform === 'win32' ? 'junction' : 'dir');
  const result = f.run();
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Invalid installer license staging directory/);
  assert.deepEqual(readdirSync(outside), ['marker.txt']);
  assert.equal(readFileSync(join(outside, 'marker.txt'), 'utf8'), 'unchanged');
  assert.ok(!existsSync(join(f.binaries, 'monerod.exe')));
});

test('an allowlisted license entry cannot be a link into another directory', t => {
  const f = fixture(t);
  const outside = join(f.temporaryRoot, 'outside-staging');
  mkdirSync(outside);
  symlinkSync(outside, join(f.licenses, 'tor.txt'), process.platform === 'win32' ? 'junction' : 'dir');
  const result = f.run();
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unexpected file in installer license staging/);
  assert.deepEqual(readdirSync(outside), []);
  assert.ok(!existsSync(join(f.binaries, 'monerod.exe')));
});
