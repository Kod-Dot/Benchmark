import type { IconName } from './icons';
import type { Finding, Manifest, Severity } from './types';

export const severityMeta: Record<Severity, { label: string; icon: IconName }> = {
  critical: { label: 'Critical', icon: 'errorCircle' },
  high: { label: 'High', icon: 'warning' },
  medium: { label: 'Medium', icon: 'diamond' },
  low: { label: 'Low', icon: 'subtractCircleFilled' },
  info: { label: 'Info', icon: 'info' },
};

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const satisfies readonly Severity[];

const nf = new Intl.NumberFormat();
export const num = (n: number) => nf.format(n);

export function date(iso: string | null | undefined, withTime = false): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    ...(withTime ? { hour: '2-digit', minute: '2-digit' } : {}),
  });
}

/** Whole days between an ISO date and a reference date (default: now). */
export function daysSince(iso: string | null | undefined, ref?: string | null): number | null {
  if (!iso) return null;
  const a = new Date(iso).getTime();
  const b = ref ? new Date(ref).getTime() : Date.now();
  if (Number.isNaN(a) || Number.isNaN(b)) return null;
  return Math.floor((b - a) / 86_400_000);
}

export function scopeText(m: Manifest): string {
  return [...m.scope.domains, m.scope.tenant].filter(Boolean).join(', ');
}

export function runName(m: Manifest, fallback: string): string {
  return m.name ?? fallback;
}

/** "3 computers", "Tenant", or the number of listed objects. */
export function affectedText(f: Finding): string {
  if (f.affected_count != null) {
    return f.affected_unit ? `${num(f.affected_count)} ${f.affected_unit}` : num(f.affected_count);
  }
  if (f.affected.length === 1) return f.affected[0].kind === 'tenant' ? 'Tenant' : f.affected[0].name;
  return f.affected.length ? num(f.affected.length) : '';
}

/** Heat class for an area score, matching the dashboard legend. */
export function heat(score: number | null): string {
  if (score == null) return 'h-na';
  if (score < 40) return 'h-crit';
  if (score < 60) return 'h-high';
  if (score < 80) return 'h-med';
  return 'h-ok';
}

export function scoreColour(score: number | null): string {
  if (score == null) return 'var(--border-strong)';
  if (score < 40) return 'var(--sev-critical)';
  if (score < 60) return 'var(--sev-high)';
  if (score < 80) return 'var(--sev-medium)';
  return 'var(--ok)';
}

export function cvssColour(score: number): string {
  if (score >= 9) return 'var(--sev-critical)';
  if (score >= 7) return 'var(--sev-high)';
  if (score >= 4) return 'var(--sev-medium)';
  return 'var(--sev-low)';
}

export const kindIcon = (kind: string): IconName =>
  (
    ({
      user: 'person',
      computer: 'desktop',
      group: 'people',
      ou: 'folder',
      gpo: 'document',
      template: 'certificate',
      ca: 'server',
      domain: 'building',
      trust: 'link',
      tenant: 'cloud',
      role: 'personKey',
      app: 'apps',
      client: 'desktop',
      device: 'desktop',
      ip: 'globe',
      protocol: 'link',
      policy: 'shieldCheckmark',
      account: 'person',
      mailbox: 'mail',
      connector: 'plugConnected',
      subscription: 'cloud',
      resource: 'cube',
      azrole: 'personKey',
    }) as Record<string, IconName>
  )[kind] ?? 'circle';

export const kindLabel = (kind: string): string =>
  ({
    user: 'User',
    computer: 'Computer',
    group: 'Group',
    ou: 'OU',
    gpo: 'GPO',
    template: 'Certificate template',
    ca: 'Certificate authority',
    domain: 'Domain',
    trust: 'Trust',
    tenant: 'Tenant',
    role: 'Entra role',
    app: 'Application',
    client: 'Client',
    device: 'Device',
    ip: 'IP address',
    protocol: 'Protocol',
    policy: 'Policy',
    account: 'Account',
    mailbox: 'Mailbox',
    connector: 'Connector',
    subscription: 'Subscription',
    resource: 'Azure resource',
    azrole: 'Azure role',
  })[kind] ?? kind;

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${num(n)} ${n === 1 ? one : many}`;
}
