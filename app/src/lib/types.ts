// Mirrors the serialized types in crates/dca-core.

export interface Environment {
  computer: string | null;
  user: string | null;
  domain: string | null;
  os: string;
}

export interface Source {
  id: string;
  title: string;
  needs: string;
  kind: 'onprem' | 'cloud';
}

export interface AreaSummary {
  code: string;
  title: string;
  sources: string[];
  generated: boolean;
  checks: number;
  implemented: number;
}

export interface GroupSummary {
  id: string;
  title: string;
  areas: AreaSummary[];
  checks: number;
  implemented: number;
}

export interface CatalogSummary {
  groups: GroupSummary[];
  sources: Source[];
  checks: number;
  implemented: number;
}

export interface Manifest {
  name: string | null;
  tool_version: string;
  catalog_version: string;
  scope: { domains: string[]; tenant: string | null };
  started_at: string;
  finished_at: string | null;
  score: number | null;
  areas?: string[];
}

export interface AssessmentEntry {
  path: string;
  name: string;
  manifest: Manifest;
}

export interface Listing {
  dir: string;
  exists: boolean;
  assessments: AssessmentEntry[];
  unreadable: { path: string; reason: string }[];
}

export type ProbeState = 'ok' | 'partial' | 'failed' | 'untested';

export interface ProbeResult {
  source: string;
  state: ProbeState;
  detail: string;
}

// ---------- Collection (crates/dca-core/src/ad/raw.rs, app commands) ----------

export type CollectEvent =
  | { type: 'start'; area: string }
  | { type: 'progress'; area: string; read: number }
  | { type: 'done'; area: string; count: number }
  | { type: 'error'; area: string; message: string }
  | { type: 'finished'; finished_at: string }
  | { type: 'signin'; url: string; code: string | null }
  | { type: 'signedin'; account: string };

/** Which collector an event came from: both have a `users` area. */
export type CollectScope = 'entra' | 'ad';

export type CollectProgress = { type: 'event'; scope: CollectScope; event: CollectEvent } | { type: 'analyzing' };

export interface CollectOutcome {
  path: string;
  manifest: Manifest;
}

// ---------- Results (crates/dca-core/src/results.rs) ----------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ResultStatus = 'failed' | 'passed' | 'not_assessed' | 'accepted';

export interface Reference {
  title: string;
  url: string;
}

export interface CheckDetail {
  description: string;
  impact: string | null;
  attack: string[];
  remediation: string[];
  verify: string | null;
  cvss: string | null;
  mitre: string[];
  frameworks: string[];
  references: Reference[];
}

export interface Cvss {
  vector: string;
  score: number;
  metrics: [string, string][];
}

export interface Mitre {
  id: string;
  name: string;
  tactic: string;
  url: string;
}

export interface Affected {
  name: string;
  kind: string;
  location: string | null;
  reason: string | null;
  object: string | null;
  /** Threat-hunting observations: when it was seen (ISO 8601). */
  last_seen?: string | null;
}

export interface Finding {
  id: string;
  title: string;
  area: string;
  area_title: string;
  group: string;
  run: string;
  status: ResultStatus;
  severity: Severity;
  cvss: Cvss | null;
  mitre: Mitre[];
  detail: CheckDetail | null;
  data_sources: string[];
  affected_count: number | null;
  affected_unit: string | null;
  affected: Affected[];
  expected: string | null;
  found: string | null;
  evidence: { label: string; value: string }[];
  raw: string | null;
  note: string | null;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface AreaScore {
  code: string;
  title: string;
  group: string;
  score: number | null;
  failed: number;
  assessed: number;
}

export interface Summary {
  score: number | null;
  status: { failed: number; passed: number; not_assessed: number; accepted: number };
  severity: SeverityCounts;
  groups: { id: string; title: string; score: number | null; failed: number }[];
  areas: AreaScore[];
  tactics: { tactic: string; findings: number }[];
}

export interface PathStep {
  name: string;
  kind: string;
  object: string | null;
  via: string | null;
}

export interface AttackPath {
  title: string;
  severity: Severity;
  steps: PathStep[];
  checks: string[];
}

export interface DirObject {
  id: string;
  kind: string;
  name: string;
  display_name: string | null;
  source: string;
  parent: string | null;
  enabled: boolean | null;
  tier0: boolean;
  last_logon: string | null;
  password_last_set: string | null;
  flags: { text: string; level: string }[];
  attributes: Record<string, unknown>;
}

export interface Edge {
  from: string;
  to: string;
  kind: string;
  note: string | null;
}

export interface Directory {
  sources: { name: string; kind: 'onprem' | 'cloud'; read_at: string }[];
  objects: DirObject[];
  edges: Edge[];
}

export interface RunInfo {
  path: string;
  name: string;
  manifest: Manifest;
}

export interface AssessmentView {
  runs: RunInfo[];
  catalog_version: string;
  summary: Summary;
  findings: Finding[];
  paths: AttackPath[];
  choke_points: { check: string; title: string; paths: number }[];
  directory: Directory | null;
}

export type ChangeKind = 'new' | 'fixed' | 'worse' | 'better' | 'still_open';

export interface Comparison {
  earlier: RunInfo;
  later: RunInfo;
  same_scope: boolean;
  same_catalog: boolean;
  score_before: number | null;
  score_after: number | null;
  severity_before: SeverityCounts;
  severity_after: SeverityCounts;
  changes: {
    kind: ChangeKind;
    finding: Finding;
    before: { status: ResultStatus; severity: Severity; affected_count: number | null } | null;
  }[];
  areas: { code: string; title: string; before: number | null; after: number | null }[];
  directory: { label: string; before: number | null; after: number | null }[];
}

// ---------- Exports (crates/dca-core/src/report) ----------

export type ReportKind = 'executive' | 'technical' | 'remediation' | 'dashboard' | 'changes' | 'raw';
export type ReportFormat = 'pdf' | 'html' | 'xlsx' | 'csv' | 'json' | 'sarif';

export interface Branding {
  organization: string;
  prepared_by: string;
  classification: string;
  logo: string | null;
}

export interface PlanRow {
  order: number;
  id: string;
  title: string;
  area: string;
  severity: Severity;
  cvss: string;
  affected: string;
  effort: 'S' | 'M' | 'L';
  phase: 30 | 90 | 180;
  quick_win: boolean;
  owner: string;
  status: string;
  first_step: string;
  verify: string;
}

/** What an exported page embeds as window.__DCA__. */
export interface ExportedPage {
  mode: 'report' | 'offline';
  kind: ReportKind;
  title: string;
  view: AssessmentView;
  comparison: Comparison | null;
  plan: PlanRow[] | null;
  branding: Branding;
  omit_accepted: boolean;
  accepted: number;
  pseudonymized: boolean;
  generated_at: string;
  tool_version: string;
}

export interface ExportRequest {
  paths: string[];
  baseline: string | null;
  out_dir: string;
  reports: { kind: ReportKind; formats: ReportFormat[] }[];
  branding: { organization: string; prepared_by: string; classification: string; logo: string | null };
  pseudonymize: boolean;
  omit_accepted: boolean;
}

export interface ExportOutcome {
  folder: string;
  files: string[];
  warnings: string[];
}

declare global {
  interface Window {
    __DCA__?: ExportedPage;
  }
}

/** An accepted risk, as the Settings screen lists it. */
export interface ExceptionRow {
  check: string;
  title: string;
  scope: string[];
  reason: string;
  accepted_by: string;
  accepted_on: string;
  expires_on: string | null;
  active: boolean;
}
