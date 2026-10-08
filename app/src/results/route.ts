import type { Finding, Severity } from '../lib/types';

export type Route =
  | { page: 'dashboard' }
  | { page: 'findings'; group?: string; area?: string; severity?: Severity; query?: string }
  | { page: 'finding'; key: string }
  | { page: 'paths' }
  | { page: 'hunting' }
  | { page: 'compliance' }
  | { page: 'compare' }
  | { page: 'directory'; source?: string; container?: string }
  | { page: 'ages' }
  | { page: 'object'; id: string }
  | { page: 'graph'; id?: string };

/** A finding's key. Combined runs can hold the same check more than once. */
export const findingKey = (f: Finding) => `${f.run}::${f.id}`;

export type Go = (route: Route) => void;
