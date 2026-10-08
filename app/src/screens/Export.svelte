<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import Select from '../components/Select.svelte';
  import { date, num, plural } from '../lib/format';
  import {
    defaultExportDir,
    exportReport,
    inDesktopApp,
    openFolder,
    pickFolder,
    pickLogo,
  } from '../lib/backend';
  import type { AssessmentView, ExportOutcome, Listing, Manifest, ReportFormat, ReportKind } from '../lib/types';

  let {
    view,
    listing,
    example,
    onBack,
  }: { view: AssessmentView; listing: Listing | null; example: boolean; onBack: () => void } = $props();

  const title = $derived(view.runs.map((r) => r.name).join(' + '));

  // The changes report compares a single run with an earlier run of the same scope.
  const sameScope = (a: Manifest, b: Manifest) =>
    [...a.scope.domains].sort().join() === [...b.scope.domains].sort().join() &&
    (a.scope.tenant ?? '') === (b.scope.tenant ?? '');
  const earlier = $derived.by(() => {
    if (view.runs.length !== 1) return [];
    const run = view.runs[0];
    return (listing?.assessments ?? [])
      .filter((e) => e.path !== run.path && sameScope(e.manifest, run.manifest) && e.manifest.started_at < run.manifest.started_at)
      .sort((a, b) => b.manifest.started_at.localeCompare(a.manifest.started_at));
  });
  // svelte-ignore state_referenced_locally
  let baseline = $state<string | null>(earlier[0]?.path ?? null);
  const baselineName = $derived.by(() => {
    const e = earlier.find((x) => x.path === baseline);
    return e ? (e.manifest.name ?? e.name) : null;
  });

  type Row = { kind: ReportKind; title: string; text: string; audience: string; formats: ReportFormat[] };
  const rows = $derived<Row[]>([
    { kind: 'executive', title: 'Executive summary', text: 'Score, maturity, top risks in business terms and the recommended next steps. 3 to 5 pages.', audience: 'Leadership', formats: ['pdf', 'html'] },
    { kind: 'technical', title: 'Technical report', text: 'Every finding with evidence, affected objects, remediation and references. Methodology and coverage appendix.', audience: 'Administrators', formats: ['pdf', 'html'] },
    { kind: 'remediation', title: 'Remediation plan', text: 'One row per finding with effort, suggested owner and order, grouped into 30, 90 and 180 days.', audience: 'Project managers', formats: ['xlsx', 'csv'] },
    { kind: 'dashboard', title: 'Offline dashboard', text: 'This results view as one HTML file that opens in any browser without Benchmark.', audience: 'Anyone', formats: ['html'] },
    {
      kind: 'changes',
      title: baselineName ? `Changes since ${baselineName}` : 'Changes since an earlier assessment',
      text: baselineName
        ? 'New and fixed findings and score change per area.'
        : view.runs.length > 1
          ? 'Not available for combined assessments.'
          : 'Needs an earlier assessment of the same scope.',
      audience: 'Ongoing programs',
      formats: ['pdf', 'html'],
    },
    { kind: 'raw', title: 'Raw results', text: 'Machine-readable results for ticketing systems and SIEM.', audience: 'Automation', formats: ['json', 'csv', 'sarif'] },
  ]);

  // Chosen formats per report; an empty list means the report is off.
  let chosen = $state<Record<ReportKind, ReportFormat[]>>({
    executive: ['pdf'],
    technical: ['pdf'],
    remediation: ['xlsx'],
    dashboard: [],
    changes: [],
    raw: [],
  });
  const available = (r: Row) => r.kind !== 'changes' || baseline != null;

  function toggleRow(r: Row) {
    chosen[r.kind] = chosen[r.kind].length ? [] : [r.formats[0]];
  }

  function toggleFormat(r: Row, f: ReportFormat) {
    const now = chosen[r.kind];
    chosen[r.kind] = now.includes(f) ? now.filter((x) => x !== f) : r.formats.filter((x) => x === f || now.includes(x));
  }

  // Branding and the save folder are remembered between exports on this computer.
  const SAVED = 'dca-export-settings';
  let saved: { organization?: string; prepared_by?: string; classification?: string; logo?: string | null; out_dir?: string } = {};
  try {
    saved = JSON.parse(localStorage.getItem(SAVED) ?? '{}');
  } catch {
    saved = {};
  }
  let organization = $state(saved.organization ?? '');
  let preparedBy = $state(saved.prepared_by ?? '');
  let classification = $state(saved.classification ?? 'Confidential');
  let logo = $state<string | null>(saved.logo ?? null);
  let outDir = $state(saved.out_dir ?? '');
  let pseudonymize = $state(false);
  let omitAccepted = $state(true);

  if (!saved.out_dir && inDesktopApp) defaultExportDir().then((d) => (outDir ||= d)).catch(() => {});

  const accepted = $derived(view.findings.filter((f) => f.status === 'accepted').length);
  const picked = $derived(rows.filter((r) => available(r) && chosen[r.kind].length));
  const fileCount = $derived(picked.reduce((n, r) => n + chosen[r.kind].length, 0));

  let busy = $state(false);
  let error = $state<string | null>(null);
  let outcome = $state<ExportOutcome | null>(null);

  async function chooseLogo() {
    try {
      logo = (await pickLogo()) ?? logo;
    } catch (e) {
      error = String((e as Error)?.message ?? e);
    }
  }

  async function chooseFolder() {
    try {
      outDir = (await pickFolder(outDir)) ?? outDir;
    } catch (e) {
      error = String((e as Error)?.message ?? e);
    }
  }

  async function run() {
    busy = true;
    error = null;
    outcome = null;
    try {
      localStorage.setItem(
        SAVED,
        JSON.stringify({ organization, prepared_by: preparedBy, classification, logo, out_dir: outDir }),
      );
    } catch {
      // Remembering settings is a convenience; export anyway.
    }
    try {
      outcome = await exportReport({
        paths: view.runs.map((r) => r.path),
        baseline: chosen.changes.length ? baseline : null,
        out_dir: outDir.trim(),
        reports: picked.map((r) => ({ kind: r.kind, formats: chosen[r.kind] })),
        branding: { organization: organization.trim(), prepared_by: preparedBy.trim(), classification: classification.trim(), logo },
        pseudonymize,
        omit_accepted: omitAccepted,
      });
    } catch (e) {
      error = String((e as Error)?.message ?? e);
    } finally {
      busy = false;
    }
  }

  const fileName = (p: string) => p.split(/[\\/]/).pop() ?? p;
  const blocker = $derived(
    !inDesktopApp
      ? example
        ? 'Export runs in the desktop app. This browser preview shows example data.'
        : 'Export runs in the desktop app.'
      : !picked.length
        ? 'Choose at least one report.'
        : !outDir.trim()
          ? 'Choose where to save the reports.'
          : null,
  );
</script>

<div class="screen">
  <header class="header">
    <button class="btn ghost" onclick={onBack}><Icon name="arrowLeft" size={18} />Results</button>
    <h2>Export · {title}</h2>
  </header>

  <main class="body">
    {#if outcome}
      <section class="done" aria-live="polite">
        <div class="done-h">
          <Icon name="checkmarkCircle" />
          <div class="grow">
            <strong>Saved {plural(outcome.files.length, 'file')}</strong>
            <div class="mono small muted">{outcome.folder}</div>
          </div>
          <button class="btn sm" onclick={() => outcome && openFolder(outcome.folder).catch((e) => (error = String(e?.message ?? e)))}><Icon name="folderOpen" size={16} />Open folder</button>
        </div>
        <ul class="files">
          {#each outcome.files as f (f)}<li><Icon name="document" size={16} />{fileName(f)}</li>{/each}
        </ul>
        {#each outcome.warnings as w, i (i)}
          <p class="warn"><Icon name="warning" size={16} />{w}</p>
        {/each}
      </section>
    {/if}
    {#if error}
      <p class="notice-line err" role="alert"><Icon name="errorCircle" size={18} />{error}</p>
    {/if}

    <section class="reports">
      <h3>Reports</h3>
      <div class="scroll-x">
        <table class="t">
          <thead>
            <tr><th style="width: 48px"></th><th>Report</th><th style="width: 170px">For</th><th style="width: 220px">Formats</th></tr>
          </thead>
          <tbody>
            {#each rows as r (r.kind)}
              {@const on = available(r) && chosen[r.kind].length > 0}
              <tr class:off={!available(r)}>
                <td><input type="checkbox" checked={on} disabled={!available(r)} onchange={() => toggleRow(r)} aria-label={r.title} /></td>
                <td>
                  <strong>{r.title}</strong>
                  <div class="muted small">{r.text}</div>
                  {#if r.kind === 'changes' && earlier.length > 1}
                    <div class="baseline small">
                      Compare with
                      <Select label="Compare with" bind:value={baseline} options={earlier.map((e) => ({ value: e.path, label: `${e.manifest.name ?? e.name} · ${date(e.manifest.started_at)}` }))} />
                    </div>
                  {/if}
                </td>
                <td class="muted">{r.audience}</td>
                <td>
                  <div class="formats" role="group" aria-label="{r.title} formats">
                    {#each r.formats as f (f)}
                      <button
                        class="fmt"
                        class:on={on && chosen[r.kind].includes(f)}
                        aria-pressed={on && chosen[r.kind].includes(f)}
                        disabled={!available(r)}
                        onclick={() => toggleFormat(r, f)}>{f.toUpperCase()}</button
                      >
                    {/each}
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="muted small">PDFs are printed by Microsoft Edge. Without Edge or Chrome the HTML version is saved instead, ready to print from any browser.</p>
    </section>

    <section class="cols">
      <div class="col">
        <h3>Branding</h3>
        <label class="field">Organization name<input type="text" bind:value={organization} placeholder="Shown on the cover" /></label>
        <label class="field">Prepared by<input type="text" bind:value={preparedBy} placeholder="Your name or team" /></label>
        <label class="field">Classification label<input type="text" bind:value={classification} placeholder="For example Confidential" /></label>
        <div class="logo">
          <button class="btn sm" onclick={chooseLogo}><Icon name="folderOpen" size={16} />{logo ? 'Change logo…' : 'Choose logo…'}</button>
          {#if logo}
            <span class="small clip" title={logo}>{fileName(logo)}</span>
            <button class="linkbtn small" onclick={() => (logo = null)}>Remove</button>
          {:else}
            <span class="muted small">PNG or SVG</span>
          {/if}
        </div>
      </div>
      <div class="col">
        <h3>Privacy</h3>
        <label class="check">
          <input type="checkbox" bind:checked={pseudonymize} />
          <span><strong>Replace names with pseudonyms</strong><span class="muted small block">For sharing with third parties. The same object always gets the same pseudonym.</span></span>
        </label>
        <label class="check">
          <input type="checkbox" bind:checked={omitAccepted} disabled={!accepted} />
          <span>
            <strong>Leave out accepted risks</strong>
            <span class="muted small block">
              {#if !accepted}This assessment has no accepted risks.
              {:else if omitAccepted}{plural(accepted, 'exception')} {accepted === 1 ? 'is' : 'are'} listed in an appendix only.
              {:else}{plural(accepted, 'exception')} {accepted === 1 ? 'is' : 'are'} reported with the findings.{/if}
            </span>
          </span>
        </label>
        <div class="field">
          <label for="out-dir">Save to</label>
          <div class="pathrow">
            <input id="out-dir" class="mono" type="text" bind:value={outDir} spellcheck="false" />
            <button class="btn sm" onclick={chooseFolder} disabled={!inDesktopApp}>Browse…</button>
          </div>
          <span class="muted small">Each export goes into a new folder named after the assessment and time.</span>
        </div>
      </div>
    </section>
  </main>

  <footer class="actionbar">
    <span class="muted">{blocker ?? `${plural(picked.length, 'report')}, ${plural(fileCount, 'file')}`}</span>
    <button class="btn primary" disabled={busy || blocker != null} onclick={run}>
      <Icon name="arrowDownload" size={18} />{busy ? 'Exporting…' : 'Export'}
    </button>
  </footer>
</div>

<style>
  .screen {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .header {
    display: flex;
    align-items: center;
    gap: 20px;
    min-height: 56px;
    padding: 10px 20px;
  }

  .header h2 {
    flex: 1 1 auto;
  }

  .body {
    flex: 1 1 0;
    min-height: 0;
    overflow: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .reports,
  .col {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .cols {
    display: flex;
    flex-wrap: wrap;
    gap: 32px;
  }

  .col {
    flex: 1 1 320px;
    gap: 16px;
  }

  .t {
    min-width: 720px;
  }

  tr.off td {
    color: var(--text-muted);
  }

  .formats {
    display: flex;
    gap: 6px;
  }

  .fmt {
    height: 26px;
    padding: 0 9px;
    border: 1px solid var(--border-strong);
    border-radius: 4px;
    background: var(--surface);
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }

  .fmt:hover:not(:disabled) {
    border-color: var(--accent);
  }

  .fmt.on {
    background: var(--accent-soft);
    border-color: var(--accent);
    color: var(--text);
  }

  .fmt:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }

  .baseline {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 6px;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-weight: 500;
  }

  .field .muted {
    font-weight: 400;
  }

  .check {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    cursor: pointer;
  }

  .check input {
    margin-top: 3px;
  }

  .muted.block,
  .small.block {
    display: block;
  }

  .logo,
  .pathrow {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .pathrow input {
    flex: 1 1 auto;
  }

  .clip {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .done {
    border: 1px solid var(--border);
    border-left: 3px solid var(--ok);
    border-radius: var(--radius);
    background: var(--surface);
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .done-h {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .done-h > :global(.icon) {
    color: var(--ok);
  }

  .grow {
    flex: 1 1 auto;
    min-width: 0;
  }

  .files {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 6px 20px;
    font-size: 13px;
  }

  .files li,
  .warn {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .warn {
    align-items: flex-start;
    font-size: 13px;
  }

  .warn :global(.icon) {
    color: var(--sev-high);
    margin-top: 1px;
  }

  .err :global(.icon) {
    color: var(--sev-critical);
  }

  .actionbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 12px 24px;
  }
</style>
