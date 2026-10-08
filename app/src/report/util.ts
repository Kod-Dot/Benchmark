import type { Finding, Severity } from '../lib/types';

/** Maturity level read from the score. The report says it is derived. */
export const MATURITY = [
  { min: 0, label: 'Initial', text: 'Basic controls are missing; well-known attacks succeed.' },
  { min: 40, label: 'Developing', text: 'Some controls exist, with serious gaps an attacker can use.' },
  { min: 60, label: 'Defined', text: 'Most controls exist; a few high-impact gaps remain.' },
  { min: 75, label: 'Managed', text: 'Controls are in place and gaps are limited.' },
  { min: 90, label: 'Optimized', text: 'Hardened beyond common baselines.' },
] as const;

export function maturity(score: number | null) {
  if (score == null) return null;
  let level: (typeof MATURITY)[number] = MATURITY[0];
  for (const m of MATURITY) if (score >= m.min) level = m;
  return level;
}

/** The first sentence of a catalog text, for summaries. */
export function firstSentence(text: string | null | undefined): string {
  if (!text) return '';
  const m = text.match(/^(.+?[.!?])(\s|$)/s);
  return (m ? m[1] : text).trim();
}

export const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const statusText = {
  failed: 'Failed',
  passed: 'Passed',
  not_assessed: 'Not assessed',
  accepted: 'Accepted risk',
} as const;

/** Data sources named by the findings, in first-seen order. */
export function sourcesOf(findings: Finding[]): string[] {
  const seen = new Set<string>();
  for (const f of findings) for (const s of f.data_sources) seen.add(s);
  return [...seen];
}

/** CSS string literal, for @page margin boxes. */
export const cssString = (s: string) => `"${s.replace(/[\\"]/g, '\\$&').replace(/[\n\r]/g, ' ')}"`;
