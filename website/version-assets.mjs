import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const dist = resolve(import.meta.dirname, 'dist');
const assets = ['styles.css', 'site.js', 'donation-qr.svg'];
const versions = assets.map(file => ({
  file,
  version: createHash('sha256').update(readFileSync(resolve(dist, file))).digest('hex').slice(0, 12),
}));
for (const page of ['index.html', 'downloads.html', 'donate.html']) {
  const path = resolve(dist, page);
  let html = readFileSync(path, 'utf8');
  for (const { file, version } of versions) {
    const pattern = new RegExp(`((?:href|src)=")/${file.replaceAll('.', '\\.')}[^"#]*(")`, 'g');
    html = html.replace(pattern, `$1/${file}?v=${version}$2`);
  }
  writeFileSync(path, html);
}
console.log('Updated stylesheet, script, and donation QR cache versions.');
