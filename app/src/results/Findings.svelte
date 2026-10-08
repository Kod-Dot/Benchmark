<script lang="ts">
  import { freeze } from '../lib/freeze';
  import { rowNav } from '../lib/rownav';
  import { untrack } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Select from '../components/Select.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import { affectedText, num, plural, SEVERITIES, severityMeta } from '../lib/format';
  import type { AssessmentView, ResultStatus, Severity } from '../lib/types';
  import { findingKey, type Go, type Route } from './route';

  let { view, go, initial }: { view: AssessmentView; go: Go; initial: Extract<Route, { page: 'findings' }> } =
    $props();

  // Initial filters come from where the user clicked; they edit them from here.
  let severity = $state<Severity | 'all'>(untrack(() => initial.severity ?? 'all'));
  let group = $state(untrack(() => initial.group ?? 'all'));
  let area = $state(untrack(() => initial.area ?? 'all'));
  let status = $state<ResultStatus | 'all'>('failed');
  let query = $state(untrack(() => initial.query ?? ''));
  let limit = $state(100);

  const groups = $derived(view.summary.groups);
  const areas = $derived(view.summary.areas.filter((a) => group === 'all' || a.group === group));
  const base = $derived(
    view.findings.filter(
      (f) =>
        (group === 'all' || f.group === group) &&
        (area === 'all' || f.area === area) &&
        (status === 'all' || f.status === status) &&
        (!query ||
          [f.id, f.title, ...f.affected.map((a) => a.name)].some((t) => t.toLowerCase().includes(query.toLowerCase()))),
    ),
  );
  const rows = $derived(base.filter((f) => severity === 'all' || f.severity === severity));
  const sevCount = (s: Severity) => base.filter((f) => f.severity === s).length;
  const multiRun = $derived(view.runs.length > 1);

  const heading = $derived(
    area !== 'all'
      ? (view.summary.areas.find((a) => a.code === area)?.title ?? area)
      : group !== 'all'
        ? (groups.find((g) => g.id === group)?.title ?? 'Findings')
        : 'Findings',
  );
  const s = $derived(view.summary.status);
</script>

<div use:freeze>
<div class="toolbar">
  <div class="titles">
    <h2>{heading}</h2>
    <span class="muted small">{plural(s.failed, 'failed check')} · {num(s.passed)} passed · {num(s.not_assessed)} not assessed · {plural(s.accepted, 'accepted risk')}</span>
  </div>
  <label class="search" style="width: 300px">
    <Icon name="filter" size={16} />
    <input type="text" data-find placeholder="Filter by title, ID or object" aria-label="Filter findings" aria-keyshortcuts="Control+F" bind:value={query} />
    <span class="kbd" aria-hidden="true">Ctrl F</span>
  </label>
</div>

<div class="toolbar filters">
  <div class="seg" role="group" aria-label="Severity">
    <button class:on={severity === 'all'} onclick={() => (severity = 'all')}>All<span class="count">{num(base.length)}</span></button>
    {#each SEVERITIES as sv (sv)}
      <button class:on={severity === sv} onclick={() => (severity = sv)}>
        <span class="dot" style:color="var(--sev-{sv})"><Icon name={severityMeta[sv].icon} size={16} /></span>{severityMeta[sv].label}<span class="count">{sevCount(sv)}</span>
      </button>
    {/each}
  </div>
  <Select
    label="Group"
    icon="layer"
    bind:value={group}
    onchange={() => (area = 'all')}
    options={[{ value: 'all', label: 'All groups' }, ...groups.map((g) => ({ value: g.id, label: g.title }))]}
  />
  <Select
    label="Area"
    bind:value={area}
    options={[{ value: 'all', label: 'All areas' }, ...areas.map((a) => ({ value: a.code, label: a.title, sub: a.code }))]}
  />
  <Select
    label="Result"
    icon="filter"
    bind:value={status}
    options={[
      { value: 'failed', label: 'Failed' },
      { value: 'accepted', label: 'Accepted risks' },
      { value: 'not_assessed', label: 'Not assessed' },
      { value: 'passed', label: 'Passed' },
      { value: 'all', label: 'Every result' },
    ]}
  />
</div>
</div>

<div class="scroll-x">
  <table use:rowNav class="t flat stick">
    <thead>
      <tr>
        <th class="pl" style="width: 132px">Severity</th>
        <th>Finding</th>
        <th style="width: 190px">Area</th>
        <th style="width: 110px">MITRE</th>
        <th class="right" style="width: 70px">CVSS</th>
        <th class="right" style="width: 140px">Affected</th>
        {#if multiRun}<th style="width: 150px">Run</th>{/if}
        <th style="width: 56px"></th>
      </tr>
    </thead>
    <tbody>
      {#each rows.slice(0, limit) as f (findingKey(f))}
        <tr class="row" onclick={() => go({ page: 'finding', key: findingKey(f) })}>
          <td class="pl">
            {#if f.status === 'failed'}
              <SevBadge severity={f.severity} />
            {:else}
              <StatusPill status={f.status} />
            {/if}
          </td>
          <td>
            <button class="linkbtn plain" onclick={(e) => { e.stopPropagation(); go({ page: 'finding', key: findingKey(f) }); }}>{f.title}</button>
            <div class="mono muted">{f.id}{#if f.note} · <span class="small">{f.note}</span>{/if}</div>
          </td>
          <td class="muted small">{f.area_title}</td>
          <td class="mono small">{f.mitre[0]?.id ?? ''}</td>
          <td class="right num strong">{f.cvss ? f.cvss.score.toFixed(1) : ''}</td>
          <td class="right num">{affectedText(f)}</td>
          {#if multiRun}<td class="small">{f.run}</td>{/if}
          <td class="right pr"><Icon name="chevronRight" size={16} /></td>
        </tr>
      {:else}
        <tr><td colspan="8" class="pl muted">Nothing matches these filters.</td></tr>
      {/each}
    </tbody>
  </table>
</div>
<p class="muted small foot">
  Showing {num(Math.min(limit, rows.length))} of {num(rows.length)}. CVSS scores are Benchmark's estimates for each check, not vendor scores.
  {#if rows.length > limit}<button class="linkbtn" onclick={() => (limit += 100)}>Show more</button>{/if}
</p>

<style>
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    padding: 12px 28px 14px 8px;
  }

  .filters {
    padding-top: 12px;
    padding-bottom: 12px;
    gap: 10px;
  }

  .titles {
    display: flex;
    flex-direction: column;
    gap: 2px;
    flex: 1 1 auto;
  }

  .dot {
    display: inline-flex;
  }

  .t .pl {
    padding-left: 24px;
  }

  .t .pr {
    padding-right: 24px;
  }

  .row {
    cursor: pointer;
  }

  .strong {
    font-weight: 600;
  }

  .foot {
    padding: 14px 24px;
  }
</style>
