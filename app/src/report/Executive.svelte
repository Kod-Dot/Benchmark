<script lang="ts">
  import SevBadge from '../components/SevBadge.svelte';
  import { affectedText, num, plural, scopeText, scoreColour, SEVERITIES, severityMeta } from '../lib/format';
  import type { ExportedPage } from '../lib/types';
  import { firstSentence, maturity, MATURITY } from './util';

  let { page }: { page: ExportedPage } = $props();

  const view = $derived(page.view);
  const s = $derived(view.summary);
  const failed = $derived(view.findings.filter((f) => f.status === 'failed'));
  const assessed = $derived(s.status.failed + s.status.passed);
  const level = $derived(maturity(s.score));
  const top = $derived(failed.slice(0, 5));
  // Areas with a failure, weakest first; the rest are counted in one line.
  const areas = $derived(
    s.areas.filter((a) => a.score != null && a.failed > 0).sort((a, b) => (a.score ?? 0) - (b.score ?? 0) || a.code.localeCompare(b.code)),
  );
  const clean = $derived(s.areas.filter((a) => a.score != null && a.failed === 0).length);
  const plan = $derived(page.plan ?? []);
  const phases = $derived(
    ([30, 90, 180] as const).map((days) => {
      const rows = plan.filter((r) => r.phase === days);
      return { days, rows, quick: rows.filter((r) => r.quick_win).length };
    }),
  );
  const scope = $derived(view.runs.map((r) => scopeText(r.manifest)).filter(Boolean).join(', '));

  // Why checks could not be assessed, most common reason first.
  const gaps = $derived.by(() => {
    const by = new Map<string, number>();
    for (const f of view.findings.filter((x) => x.status === 'not_assessed')) {
      const why = f.note ?? 'No data was collected for it';
      by.set(why, (by.get(why) ?? 0) + 1);
    }
    return [...by.entries()].sort((a, b) => b[1] - a[1]);
  });
</script>

<section class="sec">
  <h2>At a glance</h2>
  <div class="glance">
    {#if s.score != null}
      <div class="ring" style:background="conic-gradient({scoreColour(s.score)} 0 {s.score}%, var(--surface-alt) {s.score}% 100%)" role="img" aria-label="Score {s.score} of 100">
        <div><span class="ring-value">{s.score}</span><span class="muted small">of 100</span></div>
      </div>
    {/if}
    <div class="glance-text">
      <p class="lead">
        Benchmark ran {plural(assessed, 'check')} against {scope || 'the directory'}.
        {#if failed.length}
          {plural(failed.length, 'check')} failed, {num(s.severity.critical)} of them critical and {num(s.severity.high)} high.
        {:else}
          None of them failed.
        {/if}
        {#if s.score != null}The security score is {s.score} of 100.{/if}
      </p>
      {#if top[0]}
        <p>The most urgent issue is <strong>{top[0].title.replace(/\.$/, '')}</strong>{top[0].detail?.impact ? `: ${firstSentence(top[0].detail.impact).replace(/^./, (c) => c.toLowerCase())}` : '.'}</p>
      {/if}
      {#if view.paths.length}
        <p>The assessment found {plural(view.paths.length, 'path')} that let a less privileged account take control of the domain (Tier 0).</p>
      {/if}
    </div>
  </div>

  <div class="sevrow">
    {#each SEVERITIES as sev (sev)}
      <div class="sevcell">
        <SevBadge severity={sev} />
        <span class="big num">{num(s.severity[sev])}</span>
      </div>
    {/each}
    <div class="sevcell">
      <span class="muted small cell-label">Passed checks</span>
      <span class="big num">{num(s.status.passed)}</span>
    </div>
  </div>

  {#if level}
    <h3 class="sub">Maturity</h3>
    <ol class="maturity">
      {#each MATURITY as m (m.label)}
        <li class:on={m.label === level.label}>
          <strong>{m.label}</strong>
          <span class="small muted">{m.min}{m.min === 90 ? '+' : `–${MATURITY[MATURITY.indexOf(m) + 1].min - 1}`}</span>
        </li>
      {/each}
    </ol>
    <p class="small muted">{level.label}: {level.text} The level is read from the security score.</p>
  {/if}
</section>

<section class="sec">
  <h2>Top risks</h2>
  {#if top.length}
    <table class="t rt">
      <thead><tr><th style="width: 28px">#</th><th style="width: 110px">Severity</th><th>Risk</th><th class="right" style="width: 120px">Affected</th></tr></thead>
      <tbody>
        {#each top as f, i (f.id + f.run)}
          <tr>
            <td class="num muted">{i + 1}</td>
            <td><SevBadge severity={f.severity} /></td>
            <td>
              <strong>{f.title}</strong>
              {#if f.detail?.impact || f.detail?.description}
                <div class="small">{firstSentence(f.detail.impact ?? f.detail.description)}</div>
              {/if}
              <div class="mono small muted">{f.id} · {f.area_title}</div>
            </td>
            <td class="right num">{affectedText(f)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <p class="muted">No check failed.</p>
  {/if}
</section>

{#if view.paths.length}
  <section class="sec avoid">
    <h2>Attack paths to Tier 0</h2>
    <p>
      {plural(view.paths.length, 'path')} lead from ordinary accounts to control of the domain:
      {SEVERITIES.map((sev) => [sev, view.paths.filter((p) => p.severity === sev).length] as const)
        .filter(([, n]) => n)
        .map(([sev, n]) => `${n} ${severityMeta[sev].label.toLowerCase()}`)
        .join(', ')}.
    </p>
    {#if view.choke_points.length}
      <h3 class="sub">Fix these first</h3>
      <ol class="plain-list">
        {#each view.choke_points.slice(0, 5) as c (c.check)}
          <li><strong>{c.title}</strong> <span class="muted">breaks {plural(c.paths, 'path')}</span></li>
        {/each}
      </ol>
    {/if}
  </section>
{/if}

<section class="sec">
  <h2>Score by area</h2>
  {#if areas.length}
  <table class="t">
    <thead><tr><th>Area</th><th style="width: 46%">Score</th><th class="right" style="width: 90px">Failed</th></tr></thead>
    <tbody>
      {#each areas as a (a.code)}
        <tr>
          <td>{a.title} <span class="mono small muted">{a.code}</span></td>
          <td>
            <span class="scorebar"><span class="meter"><span style:width="{a.score}%" style:background={scoreColour(a.score)}></span></span><span class="num">{a.score}</span></span>
          </td>
          <td class="right num">{num(a.failed)} of {num(a.assessed)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  {/if}
  {#if clean}<p class="small muted">{plural(clean, 'other area')} passed every check that was assessed.</p>{/if}
</section>

{#if plan.length}
  <section class="sec">
    <h2>Recommended next steps</h2>
    <p class="small muted">From the remediation plan: findings grouped by how soon to fix them, ordered by severity, with quick wins first. Effort is estimated from how many objects need changing.</p>
    <div class="phases">
      {#each phases as p (p.days)}
        <div class="phase">
          <h3>Within {p.days} days</h3>
          <p class="num"><strong>{plural(p.rows.length, 'finding')}</strong>{#if p.quick}<span class="muted">&nbsp;· {num(p.quick)} quick {p.quick === 1 ? 'win' : 'wins'}</span>{/if}</p>
          <ol class="plain-list small">
            {#each p.rows.slice(0, 5) as r (r.id + r.title)}
              <li>{r.title}</li>
            {/each}
          </ol>
          {#if p.rows.length > 5}<p class="small muted">and {num(p.rows.length - 5)} more</p>{/if}
        </div>
      {/each}
    </div>
  </section>
{/if}

<section class="sec avoid">
  <h2>Coverage and limits</h2>
  <ul class="plain-list">
    <li>{plural(assessed, 'check')} were assessed: {num(s.status.passed)} passed and {num(s.status.failed)} failed.</li>
    {#if s.status.not_assessed}
      <li>{plural(s.status.not_assessed, 'check')} could not be assessed and are not part of the score.</li>
    {/if}
    {#if page.accepted}
      <li>{plural(page.accepted, 'finding')} {page.accepted === 1 ? 'is an accepted risk' : 'are accepted risks'}, left out of the score{page.omit_accepted ? ' and listed only in the technical report appendix' : ''}.</li>
    {/if}
    <li>The assessment only read configuration; it changed nothing. Results describe the environment when the data was collected.</li>
  </ul>
  {#if gaps.length}
    <table class="t">
      <thead><tr><th>Why checks were not assessed</th><th class="right" style="width: 90px">Checks</th></tr></thead>
      <tbody>
        {#each gaps.slice(0, 6) as [why, n] (why)}
          <tr><td class="small">{why}</td><td class="right num">{num(n)}</td></tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>
