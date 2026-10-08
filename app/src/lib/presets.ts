// Attack path presets for the assessment: ready-made questions that find
// where privilege can escalate toward Tier 0, so an administrator knows what
// to remediate. Every preset runs on the collected directory with the graph
// library; nothing is sampled, inferred or executed. The tool is read-only.

import { DirGraph, edgeInfo, isAsRepRoastable, isDc, isKerberoastable, neverExpires } from './graph';
import type { DirObject, Edge, Severity } from './types';
import type { IconName } from './icons';

export interface PresetResult {
  start: DirObject;
  /** The relationship steps toward Tier 0; empty when the finding has no onward path. */
  edges: Edge[];
  title: string;
  severity: Severity;
  note?: string;
}

export interface Preset {
  id: string;
  group: string;
  title: string;
  icon: IconName;
  /** One sentence: what the question looks at and why it matters to fix. */
  about: string;
  run: (g: DirGraph, ctx: PresetContext) => PresetResult[];
}

export interface PresetContext {
  compromised: Set<string>;
  /** Read time of the directory, for "unused" questions. */
  readAt: number;
}

const MAX = 60;
const day = 86_400_000;
const tier0 = (o: DirObject) => o.tier0;

const name = (g: DirGraph, id: string) => g.byId.get(id)?.name ?? id;
const target = (g: DirGraph, edges: Edge[]) => name(g, edges[edges.length - 1].to);
const steps = (n: number) => (n === 1 ? '1 step' : `${n} steps`);

function severityFor(n: number, broad = false): Severity {
  if (broad || n <= 2) return 'critical';
  if (n <= 4) return 'high';
  return 'medium';
}

/** Shortest path to Tier 0 from each start, computed in one reverse pass. */
function fromEach(g: DirGraph, starts: DirObject[], label: (o: DirObject, edges: Edge[]) => string, broad = false): PresetResult[] {
  const next = g.towards(tier0);
  const out: PresetResult[] = [];
  for (const o of starts) {
    if (o.tier0) continue;
    const edges = DirGraph.walk(next, o.id);
    if (!edges.length) continue;
    out.push({ start: o, edges, title: label(o, edges), severity: severityFor(edges.length, broad) });
  }
  out.sort((a, b) => a.edges.length - b.edges.length || a.start.name.localeCompare(b.start.name));
  return out.slice(0, MAX);
}

/** Single relationships of the given kinds landing on a Tier 0 object from outside it. */
function ontoTier0(g: DirGraph, pick: (e: Edge) => boolean, label: (e: Edge) => string, sev: Severity = 'critical'): PresetResult[] {
  const out: PresetResult[] = [];
  for (const e of g.edges) {
    const from = g.byId.get(e.from);
    const to = g.byId.get(e.to);
    if (!from || !to || from.tier0 || !to.tier0 || !pick(e)) continue;
    out.push({ start: from, edges: [e], title: label(e), severity: sev });
  }
  return out.slice(0, MAX * 2);
}

const broadGroup = (o: DirObject) => {
  const sid = String(o.attributes.objectSid ?? '');
  return (
    /^(domain users|domain computers|everyone|authenticated users|all users)$/i.test(o.name) ||
    ['S-1-1-0', 'S-1-5-11'].includes(sid) ||
    /-51[35]$/.test(sid)
  );
};

export const PRESETS: Preset[] = [
  {
    id: 'broad',
    group: 'Where a foothold leads',
    title: 'From any domain user or computer',
    icon: 'people',
    about: 'Everyone, Authenticated Users, Domain Users and Domain Computers are the widest starting points; a path from them means almost any account reaches Tier 0.',
    run: (g) => fromEach(g, g.directory.objects.filter(broadGroup), (o, e) => `Any member of ${o.name} reaches ${target(g, e)} in ${steps(e.length)}`, true),
  },
  {
    id: 'marked',
    group: 'Where a foothold leads',
    title: 'From objects marked as compromised',
    icon: 'flag',
    about: 'Mark accounts or computers in the relationship graph (right-click) to see where control of them would lead.',
    run: (g, c) => fromEach(g, [...c.compromised].map((id) => g.byId.get(id)).filter((o): o is DirObject => !!o), (o, e) => `${o.name} reaches ${target(g, e)} in ${steps(e.length)}`),
  },
  {
    id: 'users',
    group: 'Where a foothold leads',
    title: 'From any user account',
    icon: 'person',
    about: 'Every enabled account outside Tier 0 that has its own path to Tier 0, shortest first.',
    run: (g) => fromEach(g, g.directory.objects.filter((o) => o.kind === 'user' && o.enabled !== false), (o, e) => `${o.name} reaches ${target(g, e)} in ${steps(e.length)}`),
  },
  {
    id: 'computers',
    group: 'Where a foothold leads',
    title: 'From any computer',
    icon: 'desktop',
    about: 'Control of a workstation or server means control of its computer account and the accounts with sessions on it.',
    run: (g) => fromEach(g, g.directory.objects.filter((o) => o.kind === 'computer' && o.enabled !== false), (o, e) => `${o.name} reaches ${target(g, e)} in ${steps(e.length)}`),
  },
  {
    id: 'stale',
    group: 'Where a foothold leads',
    title: 'From accounts unused for 180 days',
    icon: 'clock',
    about: 'Forgotten but enabled accounts are rarely monitored and often keep weak or old passwords; disabling them removes these paths.',
    run: (g, c) => fromEach(g, g.directory.objects.filter((o) => o.kind === 'user' && o.enabled !== false && (!o.last_logon || c.readAt - Date.parse(o.last_logon) > 180 * day)), (o, e) => `Unused account ${o.name} reaches ${target(g, e)} in ${steps(e.length)}`),
  },
  {
    id: 'noexpire',
    group: 'Where a foothold leads',
    title: 'From passwords set never to expire',
    icon: 'key',
    about: 'Accounts whose password never expires keep the same credential indefinitely; these should be few and closely held.',
    run: (g) => fromEach(g, g.directory.objects.filter((o) => o.kind === 'user' && o.enabled !== false && neverExpires(o)), (o, e) => `${o.name} (password never expires) reaches ${target(g, e)} in ${steps(e.length)}`),
  },
  {
    id: 'exposed-creds',
    group: 'Exposed credentials',
    title: 'Accounts whose password can be recovered offline',
    icon: 'personWarning',
    about: 'Accounts with a service name (Kerberoastable) or without pre-authentication (AS-REP) expose material that can be cracked away from the network; strong passwords or gMSA fix this.',
    run: (g) => {
      const next = g.towards(tier0);
      const out: PresetResult[] = [];
      for (const o of g.directory.objects) {
        const how = isKerberoastable(o) ? 'has a service name' : isAsRepRoastable(o) ? 'has no pre-authentication' : null;
        if (!how) continue;
        const edges = o.tier0 ? [] : DirGraph.walk(next, o.id);
        out.push({
          start: o,
          edges,
          title: o.tier0 ? `${o.name} is Tier 0 and ${how}` : edges.length ? `${o.name} (${how}) reaches ${target(g, edges)} in ${steps(edges.length)}` : `${o.name} ${how}`,
          severity: o.tier0 ? 'critical' : edges.length ? severityFor(edges.length + 1) : 'medium',
          note: o.tier0 || edges.length ? undefined : 'No onward path to Tier 0 in the collected relationships.',
        });
      }
      return out.sort((a, b) => Number(!a.start.tier0) - Number(!b.start.tier0) || (a.edges.length || 99) - (b.edges.length || 99)).slice(0, MAX);
    },
  },
  {
    id: 'dir-replication',
    group: 'Exposed credentials',
    title: 'Non-domain-controllers with directory replication rights',
    icon: 'shieldError',
    about: 'Replication rights on the domain expose every account secret; only domain controllers should hold them.',
    run: (g) => ontoTier0(g, (e) => e.kind === 'DCSync', (e) => `${name(g, e.from)} holds directory replication rights on ${name(g, e.to)}`),
  },
  {
    id: 'secret-read',
    group: 'Exposed credentials',
    title: 'Who can read LAPS and gMSA passwords',
    icon: 'lockOpen',
    about: 'Reading a computer’s managed local administrator password, or a group managed service account password, grants control of it.',
    run: (g) => g.edges.filter((e) => e.kind === 'ReadLAPSPassword' || e.kind === 'ReadGMSAPassword').map((e) => ({ start: g.byId.get(e.from)!, edges: [e], title: `${name(g, e.from)} can ${edgeInfo(e.kind).label.toLowerCase()} of ${name(g, e.to)}`, severity: (g.byId.get(e.to)?.tier0 ? 'critical' : 'medium') as Severity })).filter((r) => r.start).slice(0, MAX),
  },
  {
    id: 'onto-tier0-control',
    group: 'Direct control of Tier 0',
    title: 'Permissions held on Tier 0 objects',
    icon: 'shieldError',
    about: 'Full control, write, permission or ownership rights on a Tier 0 object held by anything outside Tier 0. Each should be removed or justified.',
    run: (g) => ontoTier0(g, (e) => edgeInfo(e.kind).category === 'control', (e) => `${name(g, e.from)} holds ${edgeInfo(e.kind).label.toLowerCase()} on ${name(g, e.to)}`),
  },
  {
    id: 'onto-tier0-cred',
    group: 'Direct control of Tier 0',
    title: 'Credential rights on Tier 0 accounts',
    icon: 'personKey',
    about: 'Rights that let a non-Tier-0 principal set a Tier 0 account’s credential (reset, key credential or service name).',
    run: (g) => ontoTier0(g, (e) => edgeInfo(e.kind).category === 'credential' && e.kind !== 'DCSync', (e) => `${name(g, e.from)} can ${edgeInfo(e.kind).label.toLowerCase()} on ${name(g, e.to)}`),
  },
  {
    id: 'onto-tier0-members',
    group: 'Direct control of Tier 0',
    title: 'Who can change Tier 0 group membership',
    icon: 'peopleTeam',
    about: 'Adding a member to a Tier 0 group grants its privileges; this right should be limited to Tier 0 administrators.',
    run: (g) => ontoTier0(g, (e) => ['AddMember', 'AddSelf', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns'].includes(e.kind) && g.byId.get(e.to)?.kind === 'group', (e) => `${name(g, e.from)} can change members of ${name(g, e.to)} (${edgeInfo(e.kind).label.toLowerCase()})`),
  },
  {
    id: 'owners',
    group: 'Direct control of Tier 0',
    title: 'Owners of Tier 0 objects',
    icon: 'personKey',
    about: 'An object’s owner can always rewrite its permissions. Tier 0 objects should be owned by Domain Admins.',
    run: (g) => ontoTier0(g, (e) => e.kind === 'Owns', (e) => `${name(g, e.from)} owns ${name(g, e.to)}`),
  },
  {
    id: 'adminsdholder',
    group: 'Direct control of Tier 0',
    title: 'Control of AdminSDHolder',
    icon: 'shieldCheckmark',
    about: 'Permissions on AdminSDHolder are copied onto every protected account about every hour, so control of it is control of Tier 0.',
    run: (g) => g.edges.filter((e) => /adminsdholder/i.test(name(g, e.to)) && edgeInfo(e.kind).category === 'control' && !g.byId.get(e.from)?.tier0).map((e) => ({ start: g.byId.get(e.from)!, edges: [e], title: `${name(g, e.from)} holds ${edgeInfo(e.kind).label.toLowerCase()} on AdminSDHolder`, severity: 'critical' as Severity })).filter((r) => r.start),
  },
  {
    id: 'gpo-tier0',
    group: 'Group Policy and delegation',
    title: 'Group Policy that applies to Tier 0',
    icon: 'document',
    about: 'A GPO linked over domain controllers or Tier 0 accounts runs on them, so whoever can edit it has Tier 0 reach.',
    run: (g) => {
      const out: PresetResult[] = [];
      for (const link of g.edges.filter((e) => e.kind === 'GPLink')) {
        const gpo = g.byId.get(link.from);
        const ou = g.byId.get(link.to);
        if (!gpo || !ou) continue;
        const reach = g.reach(ou.id, 'out', { kinds: new Set(['Contains']), maxDepth: 12 });
        const t0 = [...reach.keys()].map((id) => g.byId.get(id)).find((o) => o?.tier0 && o.id !== ou.id) ?? (ou.tier0 ? ou : undefined);
        if (!t0) continue;
        const editors = g.into(gpo.id).filter((e) => edgeInfo(e.kind).category === 'control' && !g.byId.get(e.from)?.tier0);
        if (!editors.length) out.push({ start: gpo, edges: [link], title: `${gpo.name} applies to ${t0.name}`, severity: 'medium', note: 'No principal outside Tier 0 can edit it in the collected permissions.' });
        for (const ed of editors) out.push({ start: g.byId.get(ed.from)!, edges: [ed, link], title: `${name(g, ed.from)} can edit ${gpo.name}, which applies to ${t0.name}`, severity: 'critical' });
      }
      return out.sort((a, b) => b.edges.length - a.edges.length).slice(0, MAX);
    },
  },
  {
    id: 'constrained',
    group: 'Group Policy and delegation',
    title: 'Delegation that targets a Tier 0 computer',
    icon: 'server',
    about: 'An account configured to delegate to a domain controller or other Tier 0 host can obtain access to it as any user; constrained delegation to Tier 0 should not exist.',
    run: (g) => g.edges.filter((e) => (e.kind === 'AllowedToDelegate' || e.kind === 'AllowedToAct') && g.byId.get(e.to)?.tier0 && !g.byId.get(e.from)?.tier0).map((e) => ({ start: g.byId.get(e.from)!, edges: [e], title: `${name(g, e.from)} is configured to delegate to ${name(g, e.to)}`, severity: 'high' as Severity })).filter((r) => r.start).slice(0, MAX),
  },
  {
    id: 'certificates',
    group: 'Certificates',
    title: 'Certificate templates that allow impersonation',
    icon: 'certificate',
    about: 'A template whose enrollee supplies the subject and issues authentication certificates lets a requester obtain one as any user; restrict the subject or the enroll right.',
    run: (g) => {
      const out: PresetResult[] = [];
      const next = g.towards(tier0);
      for (const e of g.edges) {
        if (!edgeInfo(e.kind).category || edgeInfo(e.kind).category !== 'certificate') continue;
        if (!/^ESC/.test(e.kind)) continue;
        const from = g.byId.get(e.from);
        if (!from) continue;
        const onward = from.tier0 ? [] : DirGraph.walk(next, from.id);
        out.push({ start: from, edges: [e, ...onward], title: `${from.name} can enroll in ${name(g, e.to)} (${edgeInfo(e.kind).label})`, severity: 'critical' });
      }
      return out.slice(0, MAX);
    },
  },
];

export const PRESET_GROUPS = [...new Set(PRESETS.map((p) => p.group))];
