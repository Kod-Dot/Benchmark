<script lang="ts">
  import { freeze } from '../lib/freeze';
  import { VirtualRows } from '../lib/virtual.svelte';
  import Icon from '../components/Icon.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import { cvssColour, kindIcon, kindLabel, num, plural, severityMeta } from '../lib/format';
  import type { AssessmentView, Finding } from '../lib/types';
  import { findingKey, type Go } from './route';
  import { acceptRisk, withdrawRisk } from '../lib/backend';

  let {
    finding: f,
    view,
    go,
    onReload,
  }: {
    finding: Finding;
    view: AssessmentView;
    go: Go;
    /** Set when risks can be accepted here (the desktop app, real assessments). */
    onReload?: () => Promise<void>;
  } = $props();

  const d = $derived(f.detail);
  const failed = $derived(view.findings.filter((x) => x.status === 'failed'));
  const rank = $derived(failed.findIndex((x) => findingKey(x) === findingKey(f)) + 1);
  const paths = $derived(view.paths.filter((p) => p.checks.includes(f.id)));
  const objectIds = $derived(new Set(view.directory?.objects.map((o) => o.id) ?? []));
  const graphTarget = $derived(f.affected.find((a) => a.object && objectIds.has(a.object))?.object);
  const statusText = $derived(
    { failed: 'Failed', passed: 'Passed', not_assessed: 'Not assessed', accepted: 'Accepted risk' }[f.status],
  );

  let copied = $state(false);
  async function copy() {
    const lines = [
      `${f.id} ${f.title}`,
      `Severity: ${severityMeta[f.severity].label}${f.cvss ? `, CVSS ${f.cvss.score.toFixed(1)} (${f.cvss.vector}, estimated)` : ''}`,
      d?.description ?? '',
      f.found ? `Found: ${f.found}` : '',
      f.affected.length ? `Affected: ${f.affected.map((a) => a.name).join(', ')}` : '',
      d?.remediation.length ? `Fix:\n${d.remediation.map((r, i) => `${i + 1}. ${r}`).join('\n')}` : '',
    ].filter(Boolean);
    await navigator.clipboard.writeText(lines.join('\n\n'));
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }

  // ---------- Risk acceptance ----------
  const run = $derived(view.runs.find((r) => r.name === f.run) ?? (view.runs.length === 1 ? view.runs[0] : undefined));
  // Mirrors exceptions::scope_for in the engine.
  const appliesTo = $derived.by(() => {
    if (!run) return '';
    const { domains, tenant } = run.manifest.scope;
    const keys = ['onprem', 'endpoints', 'baselines'].includes(f.group)
      ? domains
      : ['entra', 'm365', 'azure'].includes(f.group)
        ? [tenant]
        : [...domains, tenant];
    const list = keys.filter(Boolean) as string[];
    return list.length > 1 ? `${list.slice(0, -1).join(', ')} and ${list[list.length - 1]}` : (list[0] ?? '');
  });

  function inDays(days: number) {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d.toISOString().slice(0, 10);
  }

  let accepting = $state(false);
  let reason = $state('');
  let expires = $state(inDays(90));
  let busy = $state(false);
  let riskError = $state<string | null>(null);

  async function act(work: () => Promise<void>) {
    busy = true;
    riskError = null;
    try {
      await work();
      accepting = false;
      reason = '';
      await onReload?.();
    } catch (e) {
      riskError = String((e as Error)?.message ?? e);
    } finally {
      busy = false;
    }
  }

  const accept = () => act(() => acceptRisk(f.id, f.group, run!.path, reason, expires || null));
  const withdraw = () => act(() => withdrawRisk(f.id, f.group, run!.path));

  function jump(id: string) {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  const win = new VirtualRows();
</script>

<div class="vhead">
  <div class="vmeta">
    {#if f.status === 'failed'}<SevBadge severity={f.severity} large />{/if}
    <span class="tag mono">{f.id}</span>
    {#if f.status === 'failed'}
      <span class="state failed"><Icon name="dismissCircle" size={16} />{statusText}</span>
    {:else}
      <StatusPill status={f.status} large />
    {/if}
    <span class="muted small">{f.area_title}{view.runs.length > 1 ? ` · ${f.run}` : ''}</span>
  </div>
  <h1>{f.title}</h1>
  <div class="vmeta">
    {#if graphTarget}
      <button class="btn sm" onclick={() => go({ page: 'graph', id: graphTarget })}><Icon name="peopleTeam" size={16} />Show in graph</button>
    {/if}
    <button class="btn sm" onclick={copy}><Icon name="copy" size={16} />{copied ? 'Copied' : 'Copy finding'}</button>
    {#if f.note && f.status !== 'accepted'}<span class="muted small">{f.note}</span>{/if}
  </div>
</div>

<div class="tabs" use:freeze>
  <button class="on" onclick={() => jump('f-desc')}>Overview</button>
  <button onclick={() => jump('f-affected')}>Affected components <span class="count">{f.affected_count ?? f.affected.length}</span></button>
  <button onclick={() => jump('f-evidence')}>Results and evidence</button>
  {#if d?.remediation.length}<button onclick={() => jump('f-fix')}>Remediation</button>{/if}
  {#if d?.references.length}<button onclick={() => jump('f-refs')}>References <span class="count">{d.references.length}</span></button>{/if}
</div>

<div class="vbody">
  <div class="vmain">
    {#if d}
      <section class="vsec" id="f-desc">
        <h3>Description</h3>
        <p class="prose">{d.description}</p>
      </section>
      {#if d.impact || paths.length}
        <section class="vsec">
          <h3>Impact</h3>
          {#if d.impact}<p class="prose">{d.impact}</p>{/if}
          {#if paths.length}
            <dl class="kv tight">
              <dt>Attack paths that use it</dt>
              <dd><button class="linkbtn" onclick={() => go({ page: 'paths' })}>{paths.length} of {plural(view.paths.length, 'path')} to Tier 0</button></dd>
            </dl>
          {/if}
        </section>
      {/if}
      {#if d.attack.length}
        <section class="vsec">
          <h3>How an attacker uses it</h3>
          <ol class="steps-list">{#each d.attack as step, i (i)}<li>{step}</li>{/each}</ol>
        </section>
      {/if}
    {:else}
      <section class="vsec" id="f-desc">
        <h3>Description</h3>
        <p class="muted">The catalog has no written explanation for this check yet. The result and evidence below are what the assessment found.</p>
      </section>
    {/if}

    <section class="vsec" id="f-affected">
      <h3>Affected components · {num(f.affected_count ?? f.affected.length)}</h3>
      {#if f.affected.length}
        <div class="scroll-x">
          <table class="t" aria-rowcount={f.affected.length + 1}>
            <thead><tr aria-rowindex="1"><th style="width: 240px">Object</th><th>Location</th><th style="width: 300px">Why it is affected</th></tr></thead>
            <tbody use:win.rows={f.affected.length}>
              {#if win.start > 0}<tr class="gap" aria-hidden="true"><td colspan="3" style:height="{win.before}px"></td></tr>{/if}
              {#each f.affected.slice(win.start, win.end) as a, j (win.start + j)}
                <tr data-index={win.start + j} aria-rowindex={win.start + j + 2}>
                  <td>
                    <span class="obj">
                      <span class="otype"><Icon name={kindIcon(a.kind)} size={16} /></span>
                      <span>
                        {#if a.object && objectIds.has(a.object)}
                          <button class="linkbtn plain strong" onclick={() => go({ page: 'object', id: a.object! })}>{a.name}</button>
                        {:else}
                          <strong>{a.name}</strong>
                        {/if}
                        <span class="muted small block">{kindLabel(a.kind)}</span>
                      </span>
                    </span>
                  </td>
                  <td><span class="mono small muted wrap">{a.location ?? ''}</span></td>
                  <td class="small">{a.reason ?? ''}</td>
                </tr>
              {/each}
              {#if win.end < f.affected.length}<tr class="gap" aria-hidden="true"><td colspan="3" style:height="{win.after(f.affected.length)}px"></td></tr>{/if}
            </tbody>
          </table>
        </div>
        {#if f.affected_count != null && f.affected_count > f.affected.length}
          <p class="muted small">Showing {f.affected.length} of {num(f.affected_count)}.</p>
        {/if}
      {:else}
        <p class="muted">No objects are listed for this result.</p>
      {/if}
    </section>

    <section class="vsec" id="f-evidence">
      <h3>Results and evidence</h3>
      <dl class="kv tight wrap">
        {#if f.expected}<dt>Expected</dt><dd>{f.expected}</dd>{/if}
        {#if f.found}<dt>Found</dt><dd>{f.found}</dd>{/if}
        {#each f.evidence as e, i (i)}<dt>{e.label}</dt><dd>{e.value}</dd>{/each}
        <dt>Result</dt><dd>{statusText}</dd>
      </dl>
      {#if f.raw}<pre class="codeblock">{f.raw}</pre>{/if}
    </section>

    {#if d?.remediation.length}
      <section class="vsec" id="f-fix">
        <h3>Remediation</h3>
        <ol class="steps-list">{#each d.remediation as step, i (i)}<li>{step}</li>{/each}</ol>
        {#if d.verify}
          <h4>Verify the fix</h4>
          <pre class="codeblock">{d.verify}</pre>
          <p class="muted small">Or run the assessment again: {f.id} passes once the fix is in place.</p>
        {/if}
      </section>
    {/if}

    {#if d?.references.length}
      <section class="vsec" id="f-refs">
        <h3>References</h3>
        <ul class="reflist">
          {#each d.references as r (r.url)}
            <li>
              <Icon name="open" size={16} />
              <span><a href={r.url} target="_blank" rel="noreferrer">{r.title}</a><span class="muted small block">{new URL(r.url).hostname}</span></span>
            </li>
          {/each}
        </ul>
      </section>
    {/if}
  </div>

  <aside class="vside">
    <section class="panel">
      <div class="panel-h"><h4>Severity</h4></div>
      <div class="panel-b">
        <div class="line"><SevBadge severity={f.severity} large />{#if rank > 0}<span class="muted small">Rank {rank} of {failed.length}</span>{/if}</div>
      </div>
    </section>

    {#if f.status === 'accepted' || (f.status === 'failed' && onReload && run)}
      <section class="panel">
        <div class="panel-h"><h4>Risk acceptance</h4></div>
        <div class="panel-b risk">
          {#if f.status === 'accepted'}
            <p class="small">{f.note ?? 'The risk of this finding was accepted.'}</p>
            <p class="muted small">It is not counted in the score while the acceptance applies, and shows as failed again once it expires.</p>
            {#if onReload && run}
              <div class="line"><button class="btn sm" disabled={busy} onclick={withdraw}>Withdraw acceptance</button></div>
            {/if}
          {:else if !accepting}
            <p class="muted small">Record a decision to live with this finding. It stays listed, is left out of the score, and comes back when the acceptance expires.</p>
            <div class="line"><button class="btn sm" onclick={() => (accepting = true)}><Icon name="checkmarkCircle" size={16} />Accept risk…</button></div>
          {:else}
            <form
              class="risk-form"
              onsubmit={(e) => {
                e.preventDefault();
                accept();
              }}
            >
              <label class="field small">Reason
                <textarea rows="3" bind:value={reason} required placeholder="For example: needed by the payroll app until it is replaced in Q2"></textarea>
              </label>
              <label class="field small">Expires on
                <input type="date" bind:value={expires} min={inDays(0)} />
                <span class="muted">Leave empty to keep it until withdrawn.</span>
              </label>
              <p class="muted small">Applies to {appliesTo}, in this and later assessments. Recorded under your Windows account.</p>
              <div class="line">
                <button class="btn sm primary" type="submit" disabled={busy || !reason.trim()}>Accept risk</button>
                <button class="btn sm ghost" type="button" disabled={busy} onclick={() => (accepting = false)}>Cancel</button>
              </div>
            </form>
          {/if}
          {#if riskError}<p class="error small">{riskError}</p>{/if}
        </div>
      </section>
    {/if}

    {#if f.cvss}
      <section class="panel">
        <div class="panel-h"><h4>CVSS 3.1</h4><span class="muted small">estimated</span></div>
        <div class="panel-b">
          <div class="line"><span class="score-big" style:color={cvssColour(f.cvss.score)}>{f.cvss.score.toFixed(1)}</span><span class="muted">of 10</span></div>
          <div class="meter"><span style:width="{f.cvss.score * 10}%" style:background={cvssColour(f.cvss.score)}></span></div>
          <code class="codeblock vector">{f.cvss.vector}</code>
          <dl class="metrics">
            {#each f.cvss.metrics as [name, value] (name)}<dt>{name}</dt><dd>{value}</dd>{/each}
          </dl>
        </div>
      </section>
    {/if}

    {#if f.mitre.length}
      <section class="panel">
        <div class="panel-h"><h4>MITRE ATT&amp;CK</h4></div>
        <div class="panel-b mitres">
          {#each f.mitre as m (m.id)}
            <a class="mitre" href={m.url} target="_blank" rel="noreferrer">
              <span class="id">{m.id}</span><span class="small">{m.name}<span class="muted block">{m.tactic}</span></span>
            </a>
          {/each}
        </div>
      </section>
    {/if}

    <section class="panel">
      <div class="panel-h"><h4>Check</h4></div>
      <div class="panel-b">
        <dl class="kv tight wrap side">
          <dt>Check ID</dt><dd class="mono">{f.id}</dd>
          <dt>Area</dt><dd>{f.area} · {f.area_title}</dd>
          {#if f.data_sources.length}<dt>Data source</dt><dd>{f.data_sources.join(', ')}</dd>{/if}
          {#if d?.frameworks.length}<dt>Frameworks</dt><dd class="tags">{#each d.frameworks as fw (fw)}<span class="tag">{fw}</span>{/each}</dd>{/if}
          <dt>Catalog</dt><dd>{view.catalog_version}</dd>
        </dl>
      </div>
    </section>
  </aside>
</div>

<style>
  .risk p {
    margin: 0;
  }

  .risk,
  .risk-form {
    display: flex;
    flex-direction: column;
    gap: 10px;
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

  .field textarea,
  .field input[type='date'] {
    padding: 6px var(--space-3);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    background: var(--surface);
    color: var(--text);
    font: inherit;
    font-weight: 400;
    width: 100%;
  }

  .field textarea {
    resize: vertical;
  }

  .field textarea:focus-visible,
  .field input[type='date']:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
    border-color: var(--accent);
  }

  .error {
    color: var(--sev-critical);
    margin: 0;
  }

  .vhead {
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 4px 28px 14px 8px;
  }

  .vhead h1 {
    font-size: 36px;
    max-width: 980px;
  }

  .vmeta,
  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px 14px;
  }

  .line {
    align-items: baseline;
  }

  .tabs {
    padding: 8px 28px 10px 8px;
  }

  .vbody {
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    padding: 6px 28px 28px 8px;
    align-items: flex-start;
  }

  .vmain {
    flex: 999 1 560px;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 30px;
    padding: 26px 28px;
    border-radius: var(--radius-lg);
    background: var(--surface);
  }

  .vside {
    flex: 1 1 300px;
    max-width: 380px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .vsec {
    display: flex;
    flex-direction: column;
    gap: 10px;
    scroll-margin-top: 56px;
  }

  .vsec > h3 {
    font-size: 19px;
    font-weight: 500;
    color: var(--text);
  }

  .vsec h4 {
    margin: 6px 0 0;
  }

  .prose {
    max-width: 760px;
  }

  .steps-list {
    margin: 0;
    padding-left: 22px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-width: 760px;
  }

  .obj {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .block {
    display: block;
  }

  .strong {
    font-weight: 600;
  }

  .wrap {
    word-break: break-all;
  }

  .reflist {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .reflist li {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 9px 0;
    border-bottom: 1px solid var(--border);
    color: var(--text-muted);
  }

  .reflist li:last-child {
    border-bottom: none;
  }

  .vector {
    font-size: 11.5px;
  }

  .metrics {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 4px 12px;
    margin: 0;
    font-size: 13px;
  }

  .metrics dt {
    color: var(--text-muted);
  }

  .metrics dd {
    margin: 0;
    font-weight: 600;
    text-align: right;
  }

  .mitres {
    gap: 8px;
  }

  .mitre {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
  }

  .mitre:hover {
    border-color: var(--accent);
    color: var(--text);
  }

  .mitre .id {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 600;
    color: var(--accent-ink);
    min-width: 78px;
  }

  .side {
    grid-template-columns: 100px 1fr;
    border-top: none;
  }

  .tags {
    flex-wrap: wrap;
    gap: 6px;
  }
</style>
