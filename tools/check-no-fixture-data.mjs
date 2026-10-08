// Fails when data from the example assessments in fixtures/ shows up in what
// ships: the built UI (app/dist), the check catalog and the collectors. The
// app has no demo mode, so nothing from the examples may reach a user.
//
// Usage: node tools/check-no-fixture-data.mjs

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const examples = join(root, 'fixtures/example-assessments');

// Strings that only the examples contain: their names, and object names that
// are not built-in AD or Entra names (accounts, hosts, mail addresses, SIDs).
const markers = new Set();
for (const dir of readdirSync(examples)) {
  const manifest = JSON.parse(readFileSync(join(examples, dir, 'manifest.json'), 'utf8'));
  if (manifest.name) markers.add(manifest.name);
  const path = join(examples, dir, 'directory.json');
  const directory = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : {};
  for (const o of directory.objects ?? []) {
    if (o.kind === 'domain' || o.kind === 'tenant') continue;
    if (/^Tier \d$/.test(o.name)) continue; // a term the catalog uses, not example data
    if (/@|\d|^[a-z]+\.[a-z]+$|^(svc|adm)-/i.test(o.name) && o.name.length >= 5) markers.add(o.name);
    const sid = o.attributes?.objectSid;
    if (typeof sid === 'string' && sid.startsWith('S-1-5-21-')) markers.add(sid.split('-').slice(0, 7).join('-'));
  }
}

const targets = ['app/dist', 'checks', 'collectors'];
const files = [];
const walk = (p) => {
  if (statSync(p).isDirectory()) for (const n of readdirSync(p)) walk(join(p, n));
  else if (!/\.(woff2?|png|ico|icns)$/.test(p)) files.push(p);
};
for (const t of targets) walk(join(root, t));

let hits = 0;
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  for (const m of markers) {
    if (text.includes(m)) {
      console.error(`${relative(root, f)}: contains example data "${m}"`);
      hits++;
    }
  }
}
console.log(`${markers.size} example markers, ${files.length} files checked, ${hits} found`);
process.exit(hits ? 1 : 0);
