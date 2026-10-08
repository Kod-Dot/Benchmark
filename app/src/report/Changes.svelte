<script lang="ts">
  import SevBadge from '../components/SevBadge.svelte';
  import { affectedText, num, plural, SEVERITIES } from '../lib/format';
  import type { ChangeKind, Comparison, ExportedPage } from '../lib/types';
  import { statusText } from './util';

  let { page, comparison: c }: { page: ExportedPage; comparison: Comparison } = $props();

  const of = (k: ChangeKind) => c.changes.filter((x) => x.kind === k);
  const delta = (before: number | null, after: number | null) =>
    before == null || after == null ? null : after - before;
  const signed = (n: number | null) => (n == null ? '–' : n > 0 ? `+${n}` : `${n}`);
  const scoreDelta = $derived(delta(c.score_before, c.score_after));
  const groups: { kind: ChangeKind; title: string; text: string }[] = [
    { kind: 'new', title: 'New findings', text: 'Checks that fail now and passed or were not assessed before.' },
    { kind: 'worse', title: 'Got worse', text: 'Still failing, with more affected objects or a higher severity.' },
    { kind: 'fixed', title: 'Fixed', text: 'Checks that failed before and pass now.' },
    { kind: 'better', title: 'Improved', text: 'Still failing, with fewer affected objects.' },
    { kind: 'still_open', title: 'Still open', text: 'Failing in both assessments without change.' },
  ];
  const areas = $derived(c.areas.filter((a) => a.before !== a.after));
  const directory = $derived(c.directory.filter((d) => d.before !== d.after));
</script>

<section class="sec">
  <h2>Summary</h2>
  {#if !c.same_scope}
    <p class="notice-line">The assessments cover different scopes, so findings outside the shared scope show as new or fixed.</p>
  {:else if !c.same_catalog}
    <p class="notice-line">The assessments used different check catalogs; checks added in between show as new.</p>
  {/if}
  <div class="sevrow">
    <div class="sevcell">
      <span class="muted small cell-label">Score</span>
      <span class="big num">{c.score_before ?? '–'} <span class="muted">to</span> {c.score_after ?? '–'}</span>
      {#if scoreDelta != null}<span class="num" class:delta-up={scoreDelta > 0} class:delta-down={scoreDelta < 0}>{signed(scoreDelta)} points</span>{/if}
    </div>
    {#each groups.slice(0, 4) as g (g.kind)}
      <div class="sevcell"><span class="muted small cell-label">{g.title}</span><span class="big num">{num(of(g.kind).length)}</span></div>
    {/each}
  </div>

  <table class="t">
    <thead><tr><th>Severity</th><th class="right">{c.earlier.name}</th><th class="right">{c.later.name}</th><th class="right">Change</th></tr></thead>
    <tbody>
      {#each SEVERITIES as sev (sev)}
        {@const d = c.severity_after[sev] - c.severity_before[sev]}
        <tr>
          <td><SevBadge severity={sev} /></td>
          <td class="right num">{num(c.severity_before[sev])}</td>
          <td class="right num">{num(c.severity_after[sev])}</td>
          <td class="right num" class:delta-up={d < 0} class:delta-down={d > 0}>{signed(d)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

{#each groups as g (g.kind)}
  {@const rows = of(g.kind)}
  {#if rows.length}
    <section class="sec">
      <h2>{g.title} · {num(rows.length)}</h2>
      <p class="small muted">{g.text}</p>
      <table class="t">
        <thead><tr><th style="width: 100px">Severity</th><th>Finding</th><th class="right" style="width: 150px">Before</th><th class="right" style="width: 150px">Now</th></tr></thead>
        <tbody>
          {#each rows as x (x.finding.run + x.finding.id)}
            <tr>
              <td><SevBadge severity={x.kind === 'fixed' && x.before ? x.before.severity : x.finding.severity} /></td>
              <td>{x.finding.title}<div class="mono small muted">{x.finding.id} · {x.finding.area_title}</div></td>
              <td class="right num small">
                {#if !x.before}Not in the earlier run{:else if x.before.status !== 'failed'}{statusText[x.before.status]}{:else if x.before.affected_count != null}{num(x.before.affected_count)}{x.finding.affected_unit ? ` ${x.finding.affected_unit}` : ''}{:else}Failed{/if}
              </td>
              <td class="right num small">{x.kind === 'fixed' ? 'Passed' : affectedText(x.finding) || 'Failed'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}
{/each}

<section class="sec">
  <h2>Score by area</h2>
  {#if areas.length}
    <table class="t">
      <thead><tr><th>Area</th><th class="right" style="width: 110px">Before</th><th class="right" style="width: 110px">Now</th><th class="right" style="width: 110px">Change</th></tr></thead>
      <tbody>
        {#each areas as a (a.code)}
          {@const d = delta(a.before, a.after)}
          <tr>
            <td>{a.title} <span class="mono small muted">{a.code}</span></td>
            <td class="right num">{a.before ?? '–'}</td>
            <td class="right num">{a.after ?? '–'}</td>
            <td class="right num" class:delta-up={(d ?? 0) > 0} class:delta-down={(d ?? 0) < 0}>{signed(d)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <p class="muted">No area score changed.</p>
  {/if}
</section>

{#if directory.length}
  <section class="sec avoid">
    <h2>Directory changes</h2>
    <table class="t">
      <thead><tr><th>Measure</th><th class="right" style="width: 110px">Before</th><th class="right" style="width: 110px">Now</th><th class="right" style="width: 110px">Change</th></tr></thead>
      <tbody>
        {#each directory as d (d.label)}
          <tr>
            <td>{d.label}</td>
            <td class="right num">{d.before == null ? '–' : num(d.before)}</td>
            <td class="right num">{d.after == null ? '–' : num(d.after)}</td>
            <td class="right num">{signed(delta(d.before, d.after))}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
{/if}

<p class="small muted endnote">{plural(c.changes.length, 'finding')} compared. {page.pseudonymized ? 'Names are pseudonyms.' : ''}</p>
