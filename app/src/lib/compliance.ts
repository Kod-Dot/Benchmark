// Findings rolled up by the frameworks the catalog maps each check to
// (detail.frameworks) and by MITRE ATT&CK technique. A roll-up only covers
// the checks that map to a framework; it is not an audit of the framework.

import type { Finding } from './types';

export interface Control {
  /** "AC-2", "5.4", "vuln1_permissions_domain", or "" when the mapping names no control. */
  id: string;
  /** For MITRE: the technique name. */
  name: string;
  /** NIST family, MITRE tactic, or "" when the framework has no grouping. */
  group: string;
  findings: Finding[];
}

export interface Framework {
  id: string;
  title: string;
  controls: Control[];
  findings: Finding[];
}

interface Known {
  id: string;
  title: string;
  prefix: string;
  /** How to group controls, from the control id. */
  group?: (control: string) => string;
}

const NIST_FAMILIES: Record<string, string> = {
  AC: 'Access control',
  AT: 'Awareness and training',
  AU: 'Audit and accountability',
  CA: 'Assessment, authorization and monitoring',
  CM: 'Configuration management',
  CP: 'Contingency planning',
  IA: 'Identification and authentication',
  IR: 'Incident response',
  MA: 'Maintenance',
  MP: 'Media protection',
  PE: 'Physical and environmental protection',
  PL: 'Planning',
  PM: 'Program management',
  PS: 'Personnel security',
  PT: 'PII processing and transparency',
  RA: 'Risk assessment',
  SA: 'System and services acquisition',
  SC: 'System and communications protection',
  SI: 'System and information integrity',
  SR: 'Supply chain risk management',
};

const KNOWN: Known[] = [
  {
    id: 'nist',
    title: 'NIST SP 800-53',
    prefix: 'NIST 800-53',
    group: (c) => {
      const fam = c.split('-')[0];
      return NIST_FAMILIES[fam] ? `${fam} · ${NIST_FAMILIES[fam]}` : fam;
    },
  },
  { id: 'cis-controls', title: 'CIS Controls', prefix: 'CIS Controls', group: (c) => `Control ${c.split('.')[0]}` },
  { id: 'cis-m365', title: 'CIS Microsoft 365 Foundations Benchmark', prefix: 'CIS Microsoft 365 Foundations Benchmark' },
  { id: 'cis-windows', title: 'CIS Windows Server Benchmark', prefix: 'CIS Windows Server' },
  { id: 'anssi', title: 'ANSSI Active Directory security points', prefix: 'ANSSI', group: (c) => c.split('_')[0].replace('vuln', 'Level ') },
  { id: 'ms-baseline', title: 'Microsoft security baseline', prefix: 'Microsoft security baseline' },
  { id: 'mcsb', title: 'Microsoft cloud security benchmark', prefix: 'Microsoft cloud security benchmark' },
  { id: 'secure-score', title: 'Microsoft Secure Score', prefix: 'Microsoft Secure Score' },
  { id: 'eam', title: 'Microsoft enterprise access model', prefix: 'Microsoft enterprise access model' },
];

function add(map: Map<string, Control>, key: string, make: () => Control, f: Finding) {
  let c = map.get(key);
  if (!c) map.set(key, (c = make()));
  if (!c.findings.includes(f)) c.findings.push(f);
}

const naturally = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });

export function frameworks(findings: Finding[]): Framework[] {
  const byFw = new Map<string, Map<string, Control>>();
  const mitre = new Map<string, Control>();
  for (const f of findings) {
    for (const ref of f.detail?.frameworks ?? []) {
      const k = KNOWN.find((x) => ref === x.prefix || ref.startsWith(`${x.prefix} `));
      if (!k) continue;
      const id = ref.slice(k.prefix.length).trim();
      const map = byFw.get(k.id) ?? new Map<string, Control>();
      byFw.set(k.id, map);
      add(map, id, () => ({ id, name: '', group: id && k.group ? k.group(id) : '', findings: [] }), f);
    }
    for (const m of f.mitre) {
      add(mitre, m.id, () => ({ id: m.id, name: m.name, group: m.tactic, findings: [] }), f);
    }
  }
  const out: Framework[] = [];
  const finish = (id: string, title: string, map: Map<string, Control>) => {
    const controls = [...map.values()].sort((a, b) => naturally(a.group, b.group) || naturally(a.id, b.id));
    const all = new Set(controls.flatMap((c) => c.findings));
    out.push({ id, title, controls, findings: [...all] });
  };
  if (mitre.size) finish('mitre', 'MITRE ATT&CK', mitre);
  for (const k of KNOWN) {
    const map = byFw.get(k.id);
    if (map?.size) finish(k.id, k.title, map);
  }
  return out;
}

export interface Tally {
  failed: number;
  passed: number;
  accepted: number;
  notAssessed: number;
}

export function tally(findings: Finding[]): Tally {
  const t = { failed: 0, passed: 0, accepted: 0, notAssessed: 0 };
  for (const f of findings) {
    if (f.status === 'failed') t.failed++;
    else if (f.status === 'passed') t.passed++;
    else if (f.status === 'accepted') t.accepted++;
    else t.notAssessed++;
  }
  return t;
}

/** Share of assessed checks that passed, or null when none was assessed. */
export function passRate(t: Tally): number | null {
  const assessed = t.failed + t.passed + t.accepted;
  return assessed ? Math.round((t.passed / assessed) * 100) : null;
}
