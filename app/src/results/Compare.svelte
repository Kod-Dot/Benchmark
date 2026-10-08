<script lang="ts">
  import { freeze } from '../lib/freeze';
  import { untrack } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Select from '../components/Select.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import { compareAssessments } from '../lib/backend';
  import { affectedText, date, num, scopeText, scoreColour, SEVERITIES } from '../lib/format';
  import type { AssessmentView, ChangeKind, Comparison, Listing } from '../lib/types';
  import { findingKey, type Go } from './route';

  let {
    view,
    listing,
    go,
    onOpen,
  }: { view: AssessmentView; listing: Listing | null; go: Go; onOpen: (paths: string[]) => Promise<string | null> } = $props();

  let mode = $state<'compare' | 'combine'>('compare');
  const runs = $derived(listing?.assessments ?? []);
  const runOptions = $derived(runs.map((r) => ({ value: r.path, label: `${r.manifest.name ?? r.name} · ${date(r.manifest.started_at)}` })));
  const scopeKey = (path: string) => {
    const r = runs.find((a) => a.path === path);
    return r ? scopeText(r.manifest) : '';
  };

  // Defaults: the open run against the newest older run with the same scope.
  const current = untrack(() => view.runs[0]?.path ?? '');
  let later = $state(current);
  let earlier = $state(
    untrack(
      () =>
        runs.find((a) => a.path !== current && scopeKey(a.path) === scopeKey(current) && a.manifest.started_at < (view.runs[0]?.manifest.started_at ?? ''))?.path ??
        runs.find((a) => a.path !== current)?.path ??
        '',
    ),
  );

  let result = $state<Comparison | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(false);

  $effect(() => {
    const [a, b] = [earlier, later];
    if (!a || !b || a === b) {
      result = null;
      return;
    }
    loading = true;
    error = null;
    compareAssessments(a, b)
      .then((c) => (result = c))
      .catch((e) => {
        result = null;
        error = String(e?.message ?? e);
      })
      .finally(() => (loading = false));
  });

  const openKeys = $derived(new Set(view.findings.map(findingKey)));
  let filter = $state<ChangeKind | 'all'>('all');
  const changes = $derived((result?.changes ?? []).filter((c) => filter === 'all' || c.kind === filter));
  const countOf = (k: ChangeKind) => result?.changes.filter((c) => c.kind === k).length ?? 0;
  const kindText: Record<ChangeKind, string> = { new: 'New', fixed: 'Fixed', worse: 'Worse', better: 'Better', still_open: 'Still open' };
  const kindIcon = { new: 'add', fixed: 'checkmarkCircle', worse: 'warning', better: 'checkmarkCircle', still_open: 'history' } as const;

  function delta(a: number | null, b: number | null) {
    if (a == null || b == null) return { text: '', cls: 'muted' };
    const d = b - a;
    return { text: d > 0 ? `+${d}` : `${d}`, cls: d > 0 ? 'delta-up' : d < 0 ? 'delta-down' : 'muted' };
  }

  function beforeText(c: Comparison['changes'][number]) {
    if (!c.before) return 'not run before';
    if (c.kind === 'fixed') return c.before.affected_count != null ? `was ${num(c.before.affected_count)}` : 'was failing';
    if (c.before.affected_count != null && c.before.affected_count !== c.finding.affected_count)
      return `was ${num(c.before.affected_count)}`;
    if (c.before.severity !== c.finding.severity) return `was ${c.before.severity}`;
    if (c.before.status !== 'failed') return c.before.status === 'passed' ? 'passed before' : 'not assessed before';
    return 'unchanged';
  }

  // Combine
  let picked = $state<Set<string>>(new Set(untrack(() => view.runs.map((r) => r.path))));
  const toggle = (p: string) => {
    const next = new Set(picked);
    if (next.has(p)) next.delete(p);
    else next.add(p);
    picked = next;
  };
  let combineError = $state<string | null>(null);
  const sameScopePicked = $derived.by(() => {
    const scopes = [...picked].map(scopeKey);
    return new Set(scopes).size < scopes.length;
  });
</script>

<div class="toolbar" use:freeze>
  <h2 class="grow">Compare and combine</h2>
  <div class="seg" role="group" aria-label="Mode">
    <button class:on={mode === 'compare'} onclick={() => (mode = 'compare')}><Icon name="arrowSwap" size={16} />Compare two runs</button>
    <button class:on={mode === 'combine'} onclick={() => (mode = 'combine')}><Icon name="layer" size={16} />Combine into one dashboard</button>
  </div>
</div>

{#if runs.length < 2}
  <div class="empty-state">
    <Icon name="history" size={28} />
    <p>Comparing and combining need at least two assessments.</p>
    <p class="small">Run another assessment, or open a bundle, and it appears here.</p>
  </div>
{:else if mode === 'compare'}
  <div class="content">
    <div class="pickers">
      <div class="picker">
        <Icon name="history" />
        <span class="pk"><span class="lbl">Earlier run</span>
          <Select bare label="Earlier run" bind:value={earlier} options={runOptions} />
          <span class="muted small">{scopeKey(earlier)}</span>
        </span>
      </div>
      <Icon name="arrowRight" />
      <div class="picker accent">
        <Icon name="calendar" />
        <span class="pk"><span class="lbl">Later run</span>
          <Select bare label="Later run" bind:value={later} options={runOptions} />
          <span class="muted small">{scopeKey(later)}</span>
        </span>
      </div>
      <button class="btn" onclick={() => ([earlier, later] = [later, earlier])}><Icon name="arrowSwap" />Swap</button>
    </div>

    {#if earlier === later}
      <p class="muted">Choose two different runs.</p>
    {:else if error}
      <div class="notice-line"><Icon name="warning" /><span>{error}</span></div>
    {:else if result}
      <p class="muted small">
        {#if result.same_scope && result.same_catalog}Both runs used catalog {result.later.manifest.catalog_version} and the same scope, so every check is compared like for like.
        {:else if !result.same_scope}The runs cover different scopes, so findings outside the shared scope show as new or missing. To see them side by side, combine them instead.
        {:else}The runs used different catalog versions; checks added in between show as new.{/if}
      </p>

      <div class="grid">
        <section class="panel s3">
          <div class="panel-h"><h4>Security score</h4></div>
          <div class="panel-b">
            <div class="line"><span class="score-big muted">{result.score_before ?? '–'}</span><Icon name="arrowRight" /><span class="score-big">{result.score_after ?? '–'}</span></div>
            {#if delta(result.score_before, result.score_after).text}
              {@const d = delta(result.score_before, result.score_after)}
              <span class={d.cls}>{d.text} points</span>
            {/if}
          </div>
        </section>
        <section class="panel s3">
          <div class="panel-h"><h4>Fixed</h4></div>
          <div class="panel-b"><span class="score-big delta-up">{countOf('fixed')}</span><span class="muted small">findings failed before and pass now</span></div>
        </section>
        <section class="panel s3">
          <div class="panel-h"><h4>New</h4></div>
          <div class="panel-b">
            <span class="score-big delta-down">{countOf('new')}</span>
            <span class="muted small">findings that fail now and did not before{#if countOf('worse')}, and {countOf('worse')} got worse{/if}</span>
          </div>
        </section>
        <section class="panel s3">
          <div class="panel-h"><h4>By severity</h4></div>
          <div class="panel-b sevs">
            {#each SEVERITIES as s (s)}
              <div class="line sev-line"><SevBadge severity={s} /><span class="grow"></span><span class="num muted">{result.severity_before[s]}</span><Icon name="arrowRight" size={16} /><strong class="num">{result.severity_after[s]}</strong></div>
            {/each}
          </div>
        </section>

        <section class="panel s12">
          <div class="panel-h">
            <Icon name="history" /><h4>What changed</h4>
            <div class="seg sm" role="group" aria-label="Filter changes">
              <button class:on={filter === 'all'} onclick={() => (filter = 'all')}>All {result.changes.length}</button>
              {#each ['new', 'fixed', 'worse', 'better'] as const as k (k)}
                <button class:on={filter === k} onclick={() => (filter = k)}>{kindText[k]} {countOf(k)}</button>
              {/each}
            </div>
          </div>
          <div class="panel-b flush scroll-x">
            <table class="t flat">
              <thead><tr><th class="pl" style="width: 130px">Change</th><th style="width: 130px">Severity</th><th>Finding</th><th class="right" style="width: 150px">Now</th><th class="pr" style="width: 200px">Before</th></tr></thead>
              <tbody>
                {#each changes as c (c.kind + c.finding.id)}
                  <tr>
                    <td class="pl"><span class="chg {c.kind}"><Icon name={kindIcon[c.kind]} size={14} />{kindText[c.kind]}</span></td>
                    <td><SevBadge severity={c.kind === 'fixed' && c.before ? c.before.severity : c.finding.severity} /></td>
                    <td>
                      {#if openKeys.has(findingKey(c.finding))}
                        <button class="linkbtn plain" onclick={() => go({ page: 'finding', key: findingKey(c.finding) })}>{c.finding.title}</button>
                      {:else}{c.finding.title}{/if}
                      <div class="mono muted">{c.finding.id}</div>
                    </td>
                    <td class="right num">{c.kind === 'fixed' ? 'Passed' : affectedText(c.finding)}</td>
                    <td class="muted small pr">{beforeText(c)}</td>
                  </tr>
                {:else}
                  <tr><td colspan="5" class="pl muted">No changes of this kind.</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel s7">
          <div class="panel-h">
            <Icon name="apps" /><h4>Score by area</h4>
            <span class="legend small muted"><span><i class="before"></i>Earlier</span><span><i class="after"></i>Later</span></span>
          </div>
          <div class="panel-b flush">
            <table class="t flat">
              <thead><tr><th class="pl">Area</th><th></th><th class="right" style="width: 56px">Earlier</th><th class="right" style="width: 56px">Later</th><th class="right pr" style="width: 70px">Change</th></tr></thead>
              <tbody>
                {#each result.areas as a (a.code)}
                  {@const d = delta(a.before, a.after)}
                  <tr>
                    <td class="pl"><span class="mono muted small">{a.code}</span><div>{a.title}</div></td>
                    <td style="width: 40%">
                      <div class="pair">
                        <div class="meter"><span style:width="{a.before ?? 0}%" style:background="var(--border-strong)"></span></div>
                        <div class="meter"><span style:width="{a.after ?? 0}%" style:background={scoreColour(a.after)}></span></div>
                      </div>
                    </td>
                    <td class="right num muted">{a.before ?? '–'}</td>
                    <td class="right num strong">{a.after ?? '–'}</td>
                    <td class="right num pr {d.cls}">{d.text}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel s5">
          <div class="panel-h"><Icon name="organization" /><h4>Directory changes</h4></div>
          <div class="panel-b kpis">
            {#each result.directory as d (d.label)}
              <div class="kpi">
                <span class="label">{d.label}</span>
                <span class="value mid">{d.after == null ? '–' : num(d.after)}</span>
                <span class="small muted">{d.before == null ? 'not collected before' : d.after == null ? `was ${num(d.before)}` : d.after === d.before ? 'no change' : `${d.after > d.before ? '+' : ''}${num(d.after - d.before)}`}</span>
              </div>
            {/each}
          </div>
        </section>
      </div>
    {:else if loading}
      <p class="muted">Comparing…</p>
    {/if}
  </div>
{:else}
  <div class="content">
    <p class="prose">Combine runs that cover different domains, forests or tenants into one dashboard. Each finding keeps the run it came from, and the score is computed over all of them together.</p>
    <div class="scroll-x">
      <table class="t">
        <thead><tr><th style="width: 48px"></th><th>Assessment</th><th>Scope</th><th>Collected</th><th class="right">Score</th></tr></thead>
        <tbody>
          {#each runs as r (r.path)}
            <tr class:selected={picked.has(r.path)}>
              <td><input type="checkbox" checked={picked.has(r.path)} onchange={() => toggle(r.path)} aria-label={r.manifest.name ?? r.name} /></td>
              <td><strong>{r.manifest.name ?? r.name}</strong></td>
              <td class="tags">
                {#each r.manifest.scope.domains as d (d)}<span class="tag"><Icon name="building" size={14} />{d}</span>{/each}
                {#if r.manifest.scope.tenant}<span class="tag"><Icon name="cloud" size={14} />{r.manifest.scope.tenant}</span>{/if}
              </td>
              <td class="num">{date(r.manifest.started_at)}</td>
              <td class="right num">{r.manifest.score ?? ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if sameScopePicked}
      <div class="notice-line"><Icon name="info" /><span>Two of the chosen runs cover the same scope, so the same findings would be counted twice. Use Compare for runs of the same scope.</span></div>
    {/if}
    <div class="line">
      <button class="btn primary" disabled={picked.size < 2} onclick={async () => (combineError = await onOpen([...picked]))}><Icon name="layer" />Open combined dashboard</button>
      <span class="muted small">{picked.size} runs chosen</span>
    </div>
    {#if combineError}<div class="notice-line"><Icon name="warning" /><span>{combineError}</span></div>{/if}
  </div>
{/if}

<style>
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    padding: 12px 28px 14px 8px;
  }

  .grow {
    flex: 1 1 auto;
  }

  .content {
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .pickers {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
  }

  .picker {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 18px;
    border: 2px solid transparent;
    border-radius: var(--radius-item);
    background: var(--surface);
    min-width: 0;
    flex: 1 1 280px;
    color: var(--text-muted);
  }

  .picker.accent {
    border-color: var(--pill);
  }

  .picker.accent > :global(.icon) {
    color: var(--accent-ink);
  }

  .pk {
    display: flex;
    flex-direction: column;
    flex: 1 1 auto;
    min-width: 0;
  }

  .lbl {
    font-size: 12px;
  }

  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
  }

  .sevs {
    gap: 6px;
  }

  .sev-line {
    gap: 8px;
  }

  .legend {
    display: inline-flex;
    gap: 10px;
  }

  .legend span {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .legend i {
    width: 12px;
    height: 7px;
    border-radius: 2px;
  }

  .legend .before {
    background: var(--border-strong);
  }

  .legend .after {
    background: var(--accent);
  }

  .pair {
    display: grid;
    gap: 3px;
    min-width: 140px;
  }

  .pair .meter {
    height: 7px;
  }

  .strong {
    font-weight: 600;
  }

  .kpis {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 20px 16px;
    align-content: start;
  }

  .mid {
    font-size: 24px !important;
  }

  .tags {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .prose {
    max-width: 760px;
  }
</style>
