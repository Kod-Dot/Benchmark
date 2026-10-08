// Password and sign-in age buckets, shared by the Account ages page and the
// technical report. Ages are measured from when the directory was read.

import { daysSince } from './format';
import type { DirObject, Directory } from './types';

export type AgeMeasure = 'password' | 'logon';

export const AGE_BUCKETS = [
  { label: 'Under 30 days', max: 30 },
  { label: '30 to 89 days', max: 90 },
  { label: '90 to 179 days', max: 180 },
  { label: '180 to 364 days', max: 365 },
  { label: '1 to 2 years', max: 730 },
  { label: 'Over 2 years', max: Infinity },
];

export const AGE_NONE: Record<AgeMeasure, string> = { password: 'Never set', logon: 'No sign-in recorded' };

export const ageOf = (o: DirObject, m: AgeMeasure) => (m === 'password' ? o.password_last_set : o.last_logon);

/** One bin per bucket, then one for objects without a value. */
export function ageHistogram(objects: DirObject[], m: AgeMeasure, readAt: string | undefined) {
  const bins = [
    ...AGE_BUCKETS.map((b) => ({ label: b.label, objs: [] as DirObject[] })),
    { label: AGE_NONE[m], objs: [] as DirObject[] },
  ];
  for (const o of objects) {
    const d = daysSince(ageOf(o, m), readAt);
    const i = d === null ? AGE_BUCKETS.length : AGE_BUCKETS.findIndex((b) => d < b.max);
    bins[i < 0 ? AGE_BUCKETS.length - 1 : i].objs.push(o);
  }
  return bins;
}

/** Directory sources that hold users or computers. */
export const accountSources = (d: Directory) =>
  d.sources.filter((s) => d.objects.some((o) => o.source === s.name && (o.kind === 'user' || o.kind === 'computer')));
