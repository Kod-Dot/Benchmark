// Checks the Microsoft Graph requests of collectors/Invoke-DCAEntra.ps1 and
// the Graph property names the Entra analysis reads against Microsoft's own
// Graph schema (CSDL metadata, v1.0 and beta, from the microsoftgraph/
// msgraph-metadata repository). Without a test tenant, this is how a wrong
// property, navigation or path name is caught before it meets real data.
//
// Usage: node tools/check-graph-schema.mjs [v1.0.xml beta.xml]
// Without files it downloads the current metadata.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const SOURCES = {
  'v1.0': 'https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/master/clean_v10_metadata/cleanMetadataWithDescriptionsv1.0.xml',
  beta: 'https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/master/clean_beta_metadata/cleanMetadataWithDescriptionsbeta.xml',
};

async function load(version, file) {
  if (file) return readFileSync(file, 'utf8');
  const res = await fetch(SOURCES[version]);
  if (!res.ok) throw new Error(`${SOURCES[version]}: ${res.status}`);
  return res.text();
}

/** Types, their properties and navigations, and the container's entry points. */
function parse(full) {
  // The main microsoft.graph schema; other namespaces reuse names like "user".
  const start = full.indexOf('<Schema Namespace="microsoft.graph" ');
  const xml = full.slice(start, full.indexOf('</Schema>', start));
  const types = new Map();
  const derived = new Map();
  const typeRe = /<(EntityType|ComplexType) Name="([^"]+)"([^>]*?)(\/>|>([\s\S]*?)<\/\1>)/g;
  for (const m of xml.matchAll(typeRe)) {
    const base = /BaseType="(?:microsoft\.)?graph\.([^"]+)"/.exec(m[3])?.[1] ?? null;
    const body = m[5] ?? '';
    const props = new Set([...body.matchAll(/<Property Name="([^"]+)"/g)].map((x) => x[1]));
    const navs = new Map(
      [...body.matchAll(/<NavigationProperty Name="([^"]+)" Type="([^"]+)"/g)].map((x) => [x[1], strip(x[2])]),
    );
    types.set(m[2], { base, props, navs });
    if (base) derived.set(base, [...(derived.get(base) ?? []), m[2]]);
  }
  const container = new Map();
  for (const m of xml.matchAll(/<(EntitySet|Singleton) Name="([^"]+)" (?:EntityType|Type)="([^"]+)"/g)) {
    container.set(m[2], { type: strip(m[3]), many: m[1] === 'EntitySet' });
  }
  // Every property name in every namespace, for the names the analysis reads.
  const names = new Set([...full.matchAll(/<(?:Navigation)?Property Name="([^"]+)"/g)].map((x) => x[1]));
  // Names that are only ever navigations: Graph leaves them out unless expanded.
  const structural = new Set([...full.matchAll(/<Property Name="([^"]+)"/g)].map((x) => x[1]));
  const navOnly = new Set([...names].filter((n) => !structural.has(n)));
  return { types, derived, container, names, navOnly };
}

const strip = (t) => {
  const many = t.startsWith('Collection(');
  const name = t.replace(/^Collection\(/, '').replace(/\)$/, '').replace(/^(?:microsoft\.)?graph\./, '');
  return { name, many };
};

/** A type with its base types, and with derived types too for abstract bases like directoryObject. */
function lineage(schema, name, withDerived) {
  const out = [];
  for (let t = name; t; t = schema.types.get(t)?.base) out.push(t);
  if (withDerived) {
    const stack = [name];
    while (stack.length) for (const d of schema.derived.get(stack.pop()) ?? []) out.push(d), stack.push(d);
  }
  return out.map((t) => schema.types.get(t)).filter(Boolean);
}

// Types outside the main namespace are not modelled; nothing is claimed about them.
const has = (schema, type, prop) =>
  !schema.types.has(type) || lineage(schema, type, true).some((t) => t.props.has(prop) || t.navs.has(prop));
const nav = (schema, type, name) => {
  for (const t of lineage(schema, type, true)) if (t.navs.has(name)) return t.navs.get(name);
  // A structural property of a complex or entity type can also be walked.
  return null;
};

/** Splits on commas outside parentheses. */
function topLevel(list) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of list) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) out.push(cur), (cur = '');
    else cur += ch;
  }
  if (cur) out.push(cur);
  return out.map((s) => s.trim()).filter(Boolean);
}

function options(query) {
  const out = {};
  let depth = 0;
  let key = '';
  let cur = '';
  let inKey = true;
  for (const ch of query + '&') {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (depth === 0 && ch === '&') {
      if (key) out[key] = cur;
      key = '';
      cur = '';
      inKey = true;
    } else if (depth === 0 && inKey && ch === '=') inKey = false;
    else if (inKey) key += ch;
    else cur += ch;
  }
  return out;
}

const problems = [];

function checkOptions(schema, type, opts, where) {
  for (const f of topLevel(opts.$select ?? '')) if (!has(schema, type, f)) problems.push(`${where}: $select ${f} is not a property of ${type}`);
  for (const e of topLevel(opts.$expand ?? '')) {
    const name = e.replace(/\(.*$/, '');
    const target = nav(schema, type, name);
    if (!target) {
      problems.push(`${where}: $expand ${name} is not a navigation of ${type}`);
      continue;
    }
    const inner = /\((.*)\)$/.exec(e)?.[1];
    if (inner) checkOptions(schema, target.name, options(inner.replace(/;/g, '&')), `${where} > ${name}`);
  }
  for (const m of (opts.$filter ?? '').matchAll(/([A-Za-z][A-Za-z0-9/]*) (?:eq|ne|ge|le|gt|lt) /g)) {
    const first = m[1].split('/')[0];
    if (!has(schema, type, first)) problems.push(`${where}: $filter ${m[1]} is not a property of ${type}`);
  }
}

const short = (u) => (u.length > 90 ? `${u.slice(0, 87)}...` : u);

function checkPath(schemas, url) {
  const [version, ...rest] = url.split('/');
  const schema = schemas[version];
  if (!schema) return problems.push(`${url}: unknown Graph version`);
  const [path, query = ''] = rest.join('/').split('?');
  const segs = path.split('/');
  let cur = schema.container.get(segs[0]);
  if (!cur) return problems.push(`${url}: ${segs[0]} is not an entity set or singleton`);
  let type = cur.type.name;
  let many = cur.many;
  for (const seg of segs.slice(1)) {
    if (many && seg === '{id}') {
      many = false;
      continue;
    }
    // A type cast (members/microsoft.graph.user) narrows the collection.
    if (seg.startsWith('microsoft.graph.')) {
      if (!schema.types.has(seg.slice('microsoft.graph.'.length))) return problems.push(`${url}: ${seg} is not a Graph type`);
      type = seg.slice('microsoft.graph.'.length);
      continue;
    }
    const n = nav(schema, type, seg);
    if (n) {
      type = n.name;
      many = n.many;
      continue;
    }
    // A complex-typed property (for example policies/crossTenantAccessPolicy/default).
    if (has(schema, type, seg)) {
      type = null;
      break;
    }
    return problems.push(`${url}: ${seg} is not a navigation of ${type}`);
  }
  if (type) checkOptions(schema, type, options(query), short(url));
  return type;
}

// ---------- The collector's requests ----------

const ps = readFileSync(join(root, 'collectors/Invoke-DCAEntra.ps1'), 'utf8');
const vars = {};
for (const m of ps.matchAll(/^\$(\w+) = ((?:'[^']*'(?: \+\s*\r?\n?\s*)?)+)/gm)) {
  vars[m[1]] = [...m[2].matchAll(/'([^']*)'/g)].map((x) => x[1]).join('');
}
const urls = new Set();
for (const m of ps.matchAll(/["']((?:v1\.0|beta)\/[^"']+)["']/g)) {
  let u = m[1]
    .replace(/`\$/g, '$')
    .replace(/\$\(\[Uri\]::EscapeDataString\(\$_\)\)/g, '{id}')
    .replace(/\$_\b/g, '{id}')
    .replace(/\$since/g, '2026-01-01T00:00:00Z');
  for (let i = 0; i < 3; i++) u = u.replace(/\$(userFields|groupFields|appFields|spFields|owners)\b/g, (_, v) => vars[v] ?? `$${v}`);
  u = u.replace(/'\{id\}'/g, "'x'");
  urls.add(u);
}

// ---------- Graph property names the analysis reads ----------

const rustFiles = ['rules.rs', 'rules_ca.rs', 'rules_priv.rs', 'rules_logs.rs', 'rules_more.rs', 'rules_mon.rs', 'rules_intune.rs', 'rules_m365.rs', 'rules_defender.rs', 'rules_rest.rs', 'directory.rs', 'model.rs'].map((f) =>
  join(root, 'crates/dca-core/src/entra', f),
);
// rules_az*.rs read Azure Resource Manager and rules_servers.rs the
// collector's own server reads, not Graph.
for (const f of readdirSync(join(root, 'crates/dca-core/src/hybrid')).filter((f) => !f.startsWith('rules_az') && f !== 'rules_servers.rs'))
  rustFiles.push(join(root, 'crates/dca-core/src/hybrid', f));

// Keys that are not Graph properties: the collector's own markers, and the
// free-form keys of audit log details and modified properties.
const NOT_GRAPH = new Set([
  '@dca.parent', '@dca.truncated', '@odata.type', '@odata.nextLink', 'value', 'key', 'name', 'displayName',
  'oldValue', 'newValue', 'ConsentContext.IsAdminConsent', 'ConsentAction.Permissions', 'Role.DisplayName',
  'Role.TemplateId', 'Role.ObjectID', 'tenant_id', 'tenant', 'account', 'scopes', 'computer', 'started_at', 'sources',
]);

function rustKeys(text) {
  const keys = new Map();
  const add = (k, line) => !keys.has(k) && keys.set(k, line);
  const lineOf = (i) => text.slice(0, i).split('\n').length;
  for (const m of text.matchAll(/\.(?:s|b|a|o|strs|t|n|get)\("([^"]+)"\)/g)) add(m[1], lineOf(m.index));
  for (const m of text.matchAll(/\.at\(&\[([^\]]*)\]\)/g))
    for (const k of m[1].matchAll(/"([^"]+)"/g)) add(k[1], lineOf(m.index));
  return keys;
}

// ---------- Run ----------

const [v1File, betaFile] = process.argv.slice(2);
const schemas = { 'v1.0': parse(await load('v1.0', v1File)), beta: parse(await load('beta', betaFile)) };
for (const s of Object.values(schemas)) if (s.types.size < 500) throw new Error('The Graph metadata did not parse.');

for (const u of urls) checkPath(schemas, u);

const known = new Set();
for (const s of Object.values(schemas)) for (const n of s.names) known.add(n);
const expanded = new Set();
for (const u of urls) {
  for (const m of u.matchAll(/\$expand=([^&]+)/g)) for (const n of m[1].matchAll(/(?:^|[,(=])([A-Za-z]+)/g)) expanded.add(n[1]);
}
const navOnly = new Set([...schemas['v1.0'].navOnly].filter((n) => schemas.beta.navOnly.has(n)));
let keyCount = 0;
for (const f of rustFiles) {
  for (const [k, line] of rustKeys(readFileSync(f, 'utf8'))) {
    keyCount++;
    if (navOnly.has(k) && !expanded.has(k))
      problems.push(`${f.slice(root.length)}:${line}: "${k}" is a navigation property, which Graph returns only with $expand, and no request expands it`);
    if (known.has(k) || NOT_GRAPH.has(k) || !/^[a-z]/.test(k)) continue;
    problems.push(`${f.slice(root.length)}:${line}: "${k}" is not a property anywhere in the Graph schema`);
  }
}

for (const p of problems) console.error(p);
console.log(`${urls.size} Graph requests and ${keyCount} property names checked against the Graph schema, ${problems.length} problems`);
process.exit(problems.length ? 1 : 0);
