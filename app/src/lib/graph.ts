// The directory as a graph: adjacency, path search and what each kind of
// relationship means. Shared by the relationship graph and attack paths.
//
// Everything here works on the collected directory only; nothing is guessed.
// Two relationships are derived from collected attributes rather than read
// as edges: containment (an object's parent OU or domain, so control of an
// OU or a linked GPO reaches what is inside it) and constrained delegation
// (msDS-AllowedToDelegateTo naming a service on a computer we have).

import type { DirObject, Directory, Edge } from './types';

export type EdgeCategory = 'membership' | 'control' | 'credential' | 'session' | 'delegation' | 'certificate' | 'policy' | 'cloud' | 'structure';

export interface EdgeInfo {
  label: string;
  category: EdgeCategory;
  /** What holding this relationship lets the source do to the target. */
  allows: string;
  /** Whether an attacker who controls the source gains the target. */
  traversable: boolean;
  /** The check whose fix removes it, when there is one. */
  check?: string;
}

const ACE = 'An access control entry on the target grants this right.';

export const EDGE_INFO: Record<string, EdgeInfo> = {
  MemberOf: { label: 'Member of', category: 'membership', traversable: true, allows: 'Has every right the group has, including rights the group holds through nesting.' },
  Contains: { label: 'Contains', category: 'structure', traversable: true, allows: 'Inheritable permissions and policies on the container reach the objects in it.' },
  GenericAll: { label: 'Full control', category: 'control', traversable: true, check: 'AD-ACL-005', allows: `Can change anything on the target: reset its password, add members, write SPNs or key credentials, or change its permissions. ${ACE}` },
  GenericWrite: { label: 'Write all properties', category: 'control', traversable: true, check: 'AD-ACL-005', allows: `Can write any attribute, for example servicePrincipalName (targeted Kerberoasting), msDS-KeyCredentialLink (shadow credentials) or scriptPath. ${ACE}` },
  WriteDacl: { label: 'Modify permissions', category: 'control', traversable: true, check: 'AD-ACL-005', allows: `Can grant itself any right on the target, then use it. ${ACE}` },
  WriteOwner: { label: 'Take ownership', category: 'control', traversable: true, check: 'AD-ACL-005', allows: `Can make itself the owner, and an owner can always change the permissions. ${ACE}` },
  Owns: { label: 'Owner', category: 'control', traversable: true, check: 'AD-ACL-016', allows: 'The owner can always change the permissions on the object, so it can grant itself full control.' },
  AllExtendedRights: { label: 'All extended rights', category: 'control', traversable: true, allows: `Includes resetting passwords and, on the domain, replicating secrets. ${ACE}` },
  AddMember: { label: 'Add members', category: 'control', traversable: true, check: 'AD-ACL-005', allows: `Can add any account, including itself, to the group. ${ACE}` },
  AddSelf: { label: 'Add self', category: 'control', traversable: true, check: 'AD-ACL-005', allows: `Can add itself to the group. ${ACE}` },
  ForceChangePassword: { label: 'Reset password', category: 'credential', traversable: true, check: 'AD-ACL-008', allows: `Can set a new password without knowing the old one, then sign in as the account. ${ACE}` },
  ResetPassword: { label: 'Reset password', category: 'credential', traversable: true, check: 'AD-ACL-008', allows: 'Can set a new password without knowing the old one, then sign in as the account.' },
  AddKeyCredentialLink: { label: 'Shadow credentials', category: 'credential', traversable: true, check: 'AD-ACL-010', allows: `Can add a key to msDS-KeyCredentialLink and then request a Kerberos ticket as the target with PKINIT. ${ACE}` },
  WriteSPN: { label: 'Write SPN', category: 'credential', traversable: true, check: 'AD-ACL-009', allows: `Can add a service principal name, request a service ticket and crack the password offline (targeted Kerberoasting). ${ACE}` },
  WriteAccountRestrictions: { label: 'Configure RBCD', category: 'delegation', traversable: true, check: 'AD-ACL-011', allows: `Can set resource-based constrained delegation on the computer, then impersonate any user to it. ${ACE}` },
  AllowedToAct: { label: 'RBCD allowed', category: 'delegation', traversable: true, allows: 'Is allowed to impersonate any user to the target (resource-based constrained delegation).' },
  AllowedToDelegate: { label: 'Constrained delegation', category: 'delegation', traversable: true, allows: 'Can obtain service tickets to the target as any user (msDS-AllowedToDelegateTo), which often means administrator access to it.' },
  WriteGPLink: { label: 'Link a GPO', category: 'policy', traversable: true, check: 'AD-ACL-025', allows: 'Can link a Group Policy it controls to the container, running its settings on every computer or user inside.' },
  GPLink: { label: 'GPO applies to', category: 'policy', traversable: true, allows: 'The policy applies to the objects in the container, so whoever can edit the GPO runs code there.' },
  DCSync: { label: 'DCSync', category: 'credential', traversable: true, check: 'AD-ACL-002', allows: 'Can replicate password hashes from a domain controller, including krbtgt and every administrator.' },
  AdminTo: { label: 'Local admin', category: 'session', traversable: true, allows: 'Is a local administrator on the computer, so it can run code there and read credentials of anyone signed in.' },
  CanRDP: { label: 'Remote Desktop', category: 'session', traversable: false, allows: 'Can sign in with Remote Desktop.' },
  CanPSRemote: { label: 'PowerShell remoting', category: 'session', traversable: false, allows: 'Can connect with PowerShell remoting.' },
  HasSession: { label: 'Session', category: 'session', traversable: true, allows: 'The account was signed in on the computer, so its credentials can be taken by an administrator of that computer.' },
  ReadLAPSPassword: { label: 'Read LAPS password', category: 'credential', traversable: true, allows: 'Can read the local administrator password of the computer.' },
  ReadGMSAPassword: { label: 'Read gMSA password', category: 'credential', traversable: true, allows: 'Can retrieve the managed service account password and sign in as it.' },
  Enroll: { label: 'Can enroll', category: 'certificate', traversable: true, allows: 'Can request certificates from the template.' },
  Publishes: { label: 'Publishes', category: 'certificate', traversable: false, allows: 'The certification authority issues certificates from this template.' },
  ESC1: { label: 'ESC1', category: 'certificate', traversable: true, check: 'AD-PKI-002', allows: 'The requester supplies the subject of an authentication certificate, so it can request one as any user, including a domain admin.' },
  ESC2: { label: 'ESC2', category: 'certificate', traversable: true, allows: 'The template issues any-purpose certificates usable to authenticate as the enrollee or to request others.' },
  ESC3: { label: 'ESC3', category: 'certificate', traversable: true, allows: 'Enrollment agent certificates let the holder request certificates on behalf of other users.' },
  ESC4: { label: 'ESC4', category: 'certificate', traversable: true, allows: 'Write access to the template lets the holder make it vulnerable, then enroll.' },
  HasRole: { label: 'Has role', category: 'cloud', traversable: true, allows: 'Holds the Entra ID directory role and every permission it grants.' },
  SyncedTo: { label: 'Synced to', category: 'cloud', traversable: true, allows: 'The on-premises account is synchronized to the cloud account, so whoever controls one usually controls the other.' },
  PasswordWriteback: { label: 'Password writeback', category: 'cloud', traversable: true, allows: 'Password changes made in the cloud are written back to the on-premises account.' },
  OwnsApp: { label: 'Owns app', category: 'cloud', traversable: true, allows: 'Can add credentials to the application and act as it.' },
};

export const CATEGORY_LABEL: Record<EdgeCategory, string> = {
  membership: 'Membership',
  control: 'Permissions',
  credential: 'Credential access',
  session: 'Sessions and admin rights',
  delegation: 'Delegation',
  certificate: 'Certificates',
  policy: 'Group Policy',
  cloud: 'Cloud and hybrid',
  structure: 'Containment',
};

export function edgeInfo(kind: string): EdgeInfo {
  return EDGE_INFO[kind] ?? { label: kind, category: 'control', traversable: true, allows: 'Gives the source control over the target.' };
}

export function attr(o: DirObject | undefined, name: string): string | undefined {
  if (!o) return undefined;
  const v = o.attributes[name];
  if (v === undefined || v === null) return undefined;
  return Array.isArray(v) ? v.map(String).join(', ') : String(v);
}

function attrList(o: DirObject, name: string): string[] {
  const v = o.attributes[name];
  if (v === undefined || v === null || v === '') return [];
  return Array.isArray(v) ? v.map(String) : [String(v)];
}

const UAC = { DISABLED: 0x2, DONT_EXPIRE: 0x10000, TRUSTED_FOR_DELEGATION: 0x80000, NOT_DELEGATED: 0x100000, DONT_REQ_PREAUTH: 0x400000, TRUSTED_TO_AUTH: 0x1000000 };
export function uac(o: DirObject): number {
  return Number(o.attributes.userAccountControl ?? 0) || 0;
}
export const isKerberoastable = (o: DirObject) => o.kind === 'user' && o.enabled !== false && attrList(o, 'servicePrincipalName').length > 0 && o.name.toLowerCase() !== 'krbtgt';
export const isAsRepRoastable = (o: DirObject) => o.kind === 'user' && o.enabled !== false && (uac(o) & UAC.DONT_REQ_PREAUTH) !== 0;
export const hasUnconstrained = (o: DirObject) => (uac(o) & UAC.TRUSTED_FOR_DELEGATION) !== 0;
export const neverExpires = (o: DirObject) => (uac(o) & UAC.DONT_EXPIRE) !== 0;
export const isDc = (o: DirObject) => o.kind === 'computer' && ((uac(o) & 0x2000) !== 0 || o.flags.some((f) => /domain controller/i.test(f.text)));

/** One step on a path: the edge, and whether the graph derived it. */
export interface Hop {
  edge: Edge;
  derived?: boolean;
}

export interface SearchOptions {
  /** Relationship kinds to follow; all traversable kinds when absent. */
  kinds?: Set<string>;
  /** Objects the path may not pass through. */
  avoid?: Set<string>;
  maxDepth?: number;
}

export class DirGraph {
  readonly byId: Map<string, DirObject>;
  /** Collected edges plus derived ones, by source and by target. */
  readonly out = new Map<string, Edge[]>();
  readonly inc = new Map<string, Edge[]>();
  readonly derived = new Set<Edge>();
  readonly edges: Edge[] = [];
  readonly tier0: DirObject[];

  constructor(readonly directory: Directory) {
    this.byId = new Map(directory.objects.map((o) => [o.id, o]));
    for (const e of directory.edges) this.add(e);
    // Containment: OUs and domains reach what is directly inside them.
    for (const o of directory.objects) {
      const p = o.parent ? this.byId.get(o.parent) : undefined;
      if (p && (p.kind === 'ou' || p.kind === 'domain')) this.add({ from: p.id, to: o.id, kind: 'Contains', note: null }, true);
    }
    // Constrained delegation, from the SPNs a principal may delegate to.
    const byHost = new Map<string, DirObject>();
    for (const o of directory.objects) {
      if (o.kind !== 'computer') continue;
      const dns = attr(o, 'dNSHostName')?.toLowerCase();
      if (dns) {
        byHost.set(dns, o);
        byHost.set(dns.split('.')[0], o);
      }
      byHost.set(o.name.toLowerCase().replace(/\$$/, ''), o);
    }
    for (const o of directory.objects) {
      for (const spn of attrList(o, 'msDS-AllowedToDelegateTo')) {
        const host = spn.split('/')[1]?.split(':')[0]?.toLowerCase();
        const target = host ? byHost.get(host) : undefined;
        if (target && target.id !== o.id && !this.has(o.id, target.id, 'AllowedToDelegate'))
          this.add({ from: o.id, to: target.id, kind: 'AllowedToDelegate', note: spn }, true);
      }
    }
    this.tier0 = directory.objects.filter((o) => o.tier0);
  }

  private add(e: Edge, derived = false) {
    (this.out.get(e.from) ?? this.out.set(e.from, []).get(e.from)!).push(e);
    (this.inc.get(e.to) ?? this.inc.set(e.to, []).get(e.to)!).push(e);
    this.edges.push(e);
    if (derived) this.derived.add(e);
  }

  has(from: string, to: string, kind: string): boolean {
    return (this.out.get(from) ?? []).some((e) => e.to === to && e.kind === kind);
  }

  outOf(id: string, kinds?: Set<string>): Edge[] {
    const list = this.out.get(id) ?? [];
    return kinds ? list.filter((e) => kinds.has(e.kind)) : list;
  }

  into(id: string, kinds?: Set<string>): Edge[] {
    const list = this.inc.get(id) ?? [];
    return kinds ? list.filter((e) => kinds.has(e.kind)) : list;
  }

  private follows(e: Edge, opts: SearchOptions, dir: 'out' | 'in' = 'out'): boolean {
    // Containment only matters forwards, from a container someone controls;
    // walking it backwards would make every object "reachable" from its OU.
    if (e.kind === 'Contains' && (dir === 'in' || this.byId.get(e.from)?.kind === 'domain')) return false;
    if (opts.kinds) return opts.kinds.has(e.kind);
    return edgeInfo(e.kind).traversable;
  }

  /**
   * Shortest path (fewest steps) from any of `starts` to an object for which
   * `goal` is true. Breadth-first, so it is the shortest in steps.
   */
  shortest(starts: string[], goal: (o: DirObject) => boolean, opts: SearchOptions = {}): Edge[] | null {
    const prev = new Map<string, Edge>();
    const seen = new Set(starts);
    let frontier = [...starts];
    const max = opts.maxDepth ?? 24;
    for (let depth = 0; depth <= max && frontier.length; depth++) {
      const next: string[] = [];
      for (const id of frontier) {
        const o = this.byId.get(id);
        if (o && depth > 0 && goal(o)) {
          const path: Edge[] = [];
          let cur = id;
          while (prev.has(cur)) {
            const e = prev.get(cur)!;
            path.unshift(e);
            cur = e.from;
          }
          return path;
        }
        for (const e of this.out.get(id) ?? []) {
          if (seen.has(e.to) || opts.avoid?.has(e.to) || !this.follows(e, opts)) continue;
          seen.add(e.to);
          prev.set(e.to, e);
          next.push(e.to);
        }
      }
      frontier = next;
    }
    return null;
  }

  /** Up to `k` different short paths from `from` to `to`, shortest first (Yen's method). */
  kShortest(from: string, to: string, k: number, opts: SearchOptions = {}): Edge[][] {
    const first = this.shortest([from], (o) => o.id === to, opts);
    if (!first) return [];
    const found: Edge[][] = [first];
    const candidates: Edge[][] = [];
    const sig = (p: Edge[]) => p.map((e) => `${e.from}>${e.kind}>${e.to}`).join('|');
    const known = new Set([sig(first)]);
    for (let n = 1; n < k; n++) {
      const last = found[n - 1];
      for (let i = 0; i < last.length; i++) {
        const root = last.slice(0, i);
        const spur = i === 0 ? from : last[i - 1].to;
        const blocked = new Set<string>();
        for (const p of found) if (sig(p.slice(0, i)) === sig(root) && p[i]) blocked.add(`${p[i].from}>${p[i].kind}>${p[i].to}`);
        const avoid = new Set(opts.avoid ?? []);
        for (const e of root) avoid.add(e.from);
        const spurPath = this.shortestAvoidingEdges(spur, to, blocked, avoid, opts);
        if (!spurPath) continue;
        const total = [...root, ...spurPath];
        const s = sig(total);
        if (!known.has(s)) {
          known.add(s);
          candidates.push(total);
        }
      }
      if (!candidates.length) break;
      candidates.sort((a, b) => a.length - b.length);
      found.push(candidates.shift()!);
    }
    return found;
  }

  private shortestAvoidingEdges(from: string, to: string, blocked: Set<string>, avoid: Set<string>, opts: SearchOptions): Edge[] | null {
    const prev = new Map<string, Edge>();
    const seen = new Set([from]);
    const queue = [from];
    while (queue.length) {
      const id = queue.shift()!;
      if (id === to) {
        const path: Edge[] = [];
        let cur = id;
        while (prev.has(cur)) {
          const e = prev.get(cur)!;
          path.unshift(e);
          cur = e.from;
        }
        return path;
      }
      for (const e of this.out.get(id) ?? []) {
        if (seen.has(e.to) || avoid.has(e.to) || blocked.has(`${e.from}>${e.kind}>${e.to}`) || !this.follows(e, opts)) continue;
        seen.add(e.to);
        prev.set(e.to, e);
        queue.push(e.to);
      }
    }
    return null;
  }

  /** Everything reachable from (dir 'out') or reaching (dir 'in') an object, by distance. */
  reach(id: string, dir: 'out' | 'in', opts: SearchOptions = {}): Map<string, { depth: number; via: Edge | null }> {
    const out = new Map<string, { depth: number; via: Edge | null }>([[id, { depth: 0, via: null }]]);
    let frontier = [id];
    const max = opts.maxDepth ?? 24;
    for (let depth = 1; depth <= max && frontier.length; depth++) {
      const next: string[] = [];
      for (const cur of frontier) {
        const list = dir === 'out' ? this.out.get(cur) : this.inc.get(cur);
        for (const e of list ?? []) {
          const other = dir === 'out' ? e.to : e.from;
          if (out.has(other) || opts.avoid?.has(other) || !this.follows(e, opts, dir)) continue;
          out.set(other, { depth, via: e });
          next.push(other);
        }
      }
      frontier = next;
    }
    return out;
  }

  /**
   * For every object that can reach a goal, the first step of its shortest
   * way there: one backwards breadth-first walk from all goals at once, so
   * "the path from every user" costs one pass instead of one per user.
   */
  towards(goal: (o: DirObject) => boolean, opts: SearchOptions = {}): Map<string, Edge | null> {
    const next = new Map<string, Edge | null>();
    let frontier: string[] = [];
    for (const o of this.directory.objects)
      if (goal(o)) {
        next.set(o.id, null);
        frontier.push(o.id);
      }
    const max = opts.maxDepth ?? 24;
    for (let depth = 0; depth < max && frontier.length; depth++) {
      const nf: string[] = [];
      for (const id of frontier)
        for (const e of this.inc.get(id) ?? []) {
          if (next.has(e.from) || opts.avoid?.has(e.from) || !this.follows(e, opts)) continue;
          next.set(e.from, e);
          nf.push(e.from);
        }
      frontier = nf;
    }
    return next;
  }

  /** The path from `start` along a `towards` map; empty when it cannot reach. */
  static walk(next: Map<string, Edge | null>, start: string): Edge[] {
    const path: Edge[] = [];
    let e = next.get(start);
    while (e && path.length < 64) {
      path.push(e);
      e = next.get(e.to);
    }
    return path;
  }

  /** Groups an object belongs to, directly and through nesting. */
  memberOf(id: string): { group: DirObject; via: DirObject | null }[] {
    const out: { group: DirObject; via: DirObject | null }[] = [];
    const seen = new Set([id]);
    const queue: { id: string; via: DirObject | null }[] = [{ id, via: null }];
    while (queue.length) {
      const cur = queue.shift()!;
      for (const e of this.out.get(cur.id) ?? []) {
        if (e.kind !== 'MemberOf' || seen.has(e.to)) continue;
        const g = this.byId.get(e.to);
        if (!g) continue;
        seen.add(e.to);
        out.push({ group: g, via: cur.via });
        queue.push({ id: e.to, via: cur.via ?? g });
      }
    }
    return out;
  }

  /** Members of a group, directly and through nested groups. */
  members(id: string): { member: DirObject; via: DirObject | null }[] {
    const out: { member: DirObject; via: DirObject | null }[] = [];
    const seen = new Set([id]);
    const queue: { id: string; via: DirObject | null }[] = [{ id, via: null }];
    while (queue.length) {
      const cur = queue.shift()!;
      for (const e of this.inc.get(cur.id) ?? []) {
        if (e.kind !== 'MemberOf' || seen.has(e.from)) continue;
        const m = this.byId.get(e.from);
        if (!m) continue;
        seen.add(e.from);
        out.push({ member: m, via: cur.via });
        if (m.kind === 'group') queue.push({ id: e.from, via: cur.via ?? m });
      }
    }
    return out;
  }
}

/** An object's distinguished name, or the name to use in a command. */
export function dn(o: DirObject): string {
  return attr(o, 'distinguishedName') ?? o.name;
}

const q = (s: string) => `'${s.replace(/'/g, "''")}'`;

/**
 * A PowerShell command that removes the relationship, for an administrator
 * to review and run. Benchmark never runs it: the assessment is read-only.
 */
export function fixCommand(e: Edge, from: DirObject | undefined, to: DirObject | undefined): string | null {
  if (!from || !to) return null;
  const who = attr(from, 'sAMAccountName') ?? from.name;
  const cloud = from.source !== to.source || !attr(to, 'distinguishedName');
  switch (e.kind) {
    case 'MemberOf':
      if (to.kind === 'role') return `# Entra ID: remove the role assignment\nGet-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '${from.id}'" |\n  Where-Object RoleDefinitionId -eq ${q(String(to.attributes.roleTemplateId ?? to.id))} |\n  Remove-MgRoleManagementDirectoryRoleAssignment`;
      if (cloud) return `# Entra ID: remove the group membership\nRemove-MgGroupMemberByRef -GroupId ${q(to.id)} -DirectoryObjectId ${q(from.id)}`;
      return `Remove-ADGroupMember -Identity ${q(dn(to))} -Members ${q(dn(from))} -Confirm`;
    case 'HasRole':
      return `# Entra ID: remove the role assignment\nGet-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '${from.id}'" |\n  Where-Object RoleDefinitionId -eq ${q(String(to.attributes.roleTemplateId ?? to.id))} |\n  Remove-MgRoleManagementDirectoryRoleAssignment`;
    case 'Owns':
      return `# Make Domain Admins the owner again\n$path = 'AD:' + ${q(dn(to))}\n$acl = Get-Acl $path\n$acl.SetOwner([Security.Principal.NTAccount]'Domain Admins')\nSet-Acl -Path $path -AclObject $acl`;
    case 'DCSync':
      return `# Remove the replication rights from the domain root\n$path = 'AD:' + ${q(dn(to))}\n$acl = Get-Acl $path\n$acl.Access | Where-Object { $_.IdentityReference -like ${q(`*\\${who}`)} -and $_.ObjectType -in @(\n  [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', [guid]'89e95b76-444d-4c62-991a-0facbeda640c') } |\n  ForEach-Object { [void]$acl.RemoveAccessRule($_) }\nSet-Acl -Path $path -AclObject $acl`;
    case 'GenericAll':
    case 'GenericWrite':
    case 'WriteDacl':
    case 'WriteOwner':
    case 'AllExtendedRights':
    case 'AddMember':
    case 'AddSelf':
    case 'ForceChangePassword':
    case 'ResetPassword':
    case 'AddKeyCredentialLink':
    case 'WriteSPN':
    case 'WriteAccountRestrictions':
    case 'WriteGPLink':
    case 'ReadLAPSPassword':
    case 'ReadGMSAPassword':
      return `# Remove the access entries ${who} holds on ${to.name}\n# (inherited entries must be removed where they are set)\n$path = 'AD:' + ${q(dn(to))}\n$acl = Get-Acl $path\n$acl.Access | Where-Object { $_.IdentityReference -like ${q(`*\\${who}`)} -and -not $_.IsInherited } |\n  ForEach-Object { [void]$acl.RemoveAccessRule($_) }\nSet-Acl -Path $path -AclObject $acl`;
    case 'AllowedToDelegate':
      return `Set-ADObject -Identity ${q(dn(from))} -Remove @{ 'msDS-AllowedToDelegateTo' = ${q(e.note ?? '')} }`;
    case 'AllowedToAct':
      return `Set-ADComputer -Identity ${q(dn(to))} -PrincipalsAllowedToDelegateToAccount $null`;
    case 'AdminTo':
      return `# On ${to.name}; prefer managing local Administrators with Group Policy or LAPS\nInvoke-Command -ComputerName ${q(attr(to, 'dNSHostName') ?? to.name)} -ScriptBlock {\n  Remove-LocalGroupMember -Group 'Administrators' -Member ${q(who)}\n}`;
    case 'HasSession':
      return `# Sign the account out of ${from.name}, and keep Tier 0 accounts off lower-tier computers\n# (Deny log on locally / through Remote Desktop for Tier 0 groups in the computer's GPO)\nquser /server:${attr(from, 'dNSHostName') ?? from.name}`;
    case 'Enroll':
      return `# Remove the enroll right on the template\n$path = 'AD:' + ${q(dn(to))}\n$acl = Get-Acl $path\n$acl.Access | Where-Object { $_.IdentityReference -like ${q(`*\\${who}`)} -and $_.ObjectType -eq [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55' } |\n  ForEach-Object { [void]$acl.RemoveAccessRule($_) }\nSet-Acl -Path $path -AclObject $acl`;
    case 'ESC1':
      return `# Stop the requester from supplying the subject (clears CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)\n$t = Get-ADObject ${q(dn(from))} -Properties 'msPKI-Certificate-Name-Flag'\nSet-ADObject $t -Replace @{ 'msPKI-Certificate-Name-Flag' = ($t.'msPKI-Certificate-Name-Flag' -band -bnot 1) }`;
    case 'GPLink':
      return `# Unlink the GPO, or limit who can edit it\nRemove-GPLink -Name ${q(from.name)} -Target ${q(dn(to))}`;
    default:
      return null;
  }
}
