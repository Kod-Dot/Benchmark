// Calls into the Rust core. Outside the desktop app (a browser preview of
// the UI) there is no backend: calls reject with BackendUnavailable and the
// UI says so, rather than showing invented values. The one exception is the
// dev server, which serves the real catalog and the EXAMPLE assessments from
// fixtures/ (written by `cargo run -p dca-core --bin preview-data`); the UI
// labels them as examples.

import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type {
  AssessmentView,
  CatalogSummary,
  CollectOutcome,
  CollectProgress,
  Comparison,
  Environment,
  ExceptionRow,
  ExportOutcome,
  ExportRequest,
  Listing,
  ProbeResult,
} from './types';

export class BackendUnavailable extends Error {
  constructor() {
    super('Only available in the Benchmark desktop app.');
  }
}

export const inDesktopApp = isTauri();

function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!inDesktopApp) return Promise.reject(new BackendUnavailable());
  return invoke<T>(command, args);
}

export const getEnvironment = () => call<Environment>('get_environment');

async function preview<T>(file: string): Promise<T> {
  const res = await fetch(`/__preview/${file}`);
  if (!res.ok) throw new BackendUnavailable();
  return res.json();
}

/** True when the listing comes from the example assessments of the browser preview. */
export const showingExamples = !inDesktopApp;

export const listAssessments = () =>
  inDesktopApp ? call<Listing>('list_assessments') : preview<Listing>('listing.json');

export const getCatalogSummary = () =>
  inDesktopApp
    ? call<CatalogSummary>('get_catalog_summary')
    : preview<CatalogSummary>('catalog-summary.json');

const folderName = (path: string) => path.split(/[\\/]/).filter(Boolean).pop() ?? path;

/** One assessment, or several combined into one dashboard. */
export function openAssessments(paths: string[]): Promise<AssessmentView> {
  if (inDesktopApp) return call<AssessmentView>('open_assessments', { paths });
  const names = paths.map(folderName);
  if (names.length === 1) return preview<AssessmentView>(`view-${names[0]}.json`);
  return preview<AssessmentView>(`combine-${names.join('-')}.json`).catch(() => {
    throw new Error('The browser preview has only one example combination of assessments.');
  });
}

export function compareAssessments(earlier: string, later: string): Promise<Comparison> {
  if (inDesktopApp) return call<Comparison>('compare_assessments', { earlier, later });
  return preview<Comparison>(`compare-${folderName(earlier)}-${folderName(later)}.json`).catch(() => {
    throw new Error('The browser preview has only one example comparison of assessments.');
  });
}

export const runAccessCheck = (domain: string, sources: string[]) =>
  call<ProbeResult[]>('run_access_check', { domain, sources });

export function onAccessProbe(handler: (r: ProbeResult) => void): Promise<UnlistenFn> {
  if (!inDesktopApp) return Promise.resolve(() => {});
  return listen<ProbeResult>('access-probe', (e) => handler(e.payload));
}

export interface CollectRequest {
  name: string | null;
  domain: string;
  tenant: string | null;
  areas: string[];
  sources: string[];
}

/** Creates an assessment, collects it and analyzes it. */
export const runCollection = (req: CollectRequest) => call<CollectOutcome>('run_collection', { ...req });

export const cancelCollection = () => call<void>('cancel_collection');

export function onCollectProgress(handler: (p: CollectProgress) => void): Promise<UnlistenFn> {
  if (!inDesktopApp) return Promise.resolve(() => {});
  return listen<CollectProgress>('collect-progress', (e) => handler(e.payload));
}

export async function pickBundle(): Promise<string | null> {
  if (!inDesktopApp) throw new BackendUnavailable();
  const { open } = await import('@tauri-apps/plugin-dialog');
  const picked = await open({
    title: 'Open assessment bundle',
    multiple: false,
    filters: [{ name: 'Benchmark bundle', extensions: ['zip'] }],
  });
  return typeof picked === 'string' ? picked : null;
}

/** Imports a bundle into the assessments folder; returns the new assessment's folder. */
export const openBundle = (path: string) => call<string>('open_bundle', { path });

// ---------- Export ----------

/** Writes the chosen reports into a new folder; PDFs need Edge or Chrome. */
export const exportReport = (request: ExportRequest) => call<ExportOutcome>('export_report', { request });

export const defaultExportDir = () => call<string>('default_export_dir');

export const openFolder = (path: string) => call<void>('open_folder', { path });

export const openSignIn = (url: string) => call<void>('open_sign_in', { url });

/** Opens a web link in the system browser (desktop app only). */
export const openUrl = (url: string) => call<void>('open_url', { url });

export async function pickLogo(): Promise<string | null> {
  if (!inDesktopApp) throw new BackendUnavailable();
  const { open } = await import('@tauri-apps/plugin-dialog');
  const picked = await open({
    title: 'Choose a logo for the reports',
    multiple: false,
    filters: [{ name: 'Image', extensions: ['png', 'svg'] }],
  });
  return typeof picked === 'string' ? picked : null;
}

export async function pickFolder(current: string): Promise<string | null> {
  if (!inDesktopApp) throw new BackendUnavailable();
  const { open } = await import('@tauri-apps/plugin-dialog');
  const picked = await open({ title: 'Save reports to', directory: true, multiple: false, defaultPath: current || undefined });
  return typeof picked === 'string' ? picked : null;
}

// ---------- Accepted risks ----------

export const listExceptions = () => call<ExceptionRow[]>('list_exceptions');

/** Accepts the risk of a failed check for the domains and tenant of `run`. */
export const acceptRisk = (check: string, group: string, run: string, reason: string, expiresOn: string | null) =>
  call<void>('accept_risk', { check, group, run, reason, expiresOn });

export const withdrawRisk = (check: string, group: string, run: string) =>
  call<void>('withdraw_risk', { check, group, run, scope: null });

export const removeException = (check: string, scope: string[]) =>
  call<void>('withdraw_risk', { check, group: '', run: null, scope });

export const assessmentsFolder = () => call<string>('assessments_folder');

// ---------- Sign-in account ----------
export const accountExists = () => call<boolean>('account_exists');
export const accountName = () => call<string | null>('account_name');
export const createAccount = (username: string, password: string) =>
  call<void>('create_account', { username, password });
export const signIn = (username: string, password: string) =>
  call<void>('sign_in', { username, password });
export const changePassword = (username: string, current: string, newPassword: string) =>
  call<void>('change_password', { username, current, newPassword });
