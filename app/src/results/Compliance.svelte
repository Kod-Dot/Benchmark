<script lang="ts">
  import { freeze } from '../lib/freeze';
  import Icon from '../components/Icon.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import { frameworks, passRate, tally, type Control, type Tally } from '../lib/compliance';
  import { num, plural } from '../lib/format';
  import type { AssessmentView, Finding } from '../lib/types';
  import { findingKey, type Go } from './route';

  let { view, go }: { view: AssessmentView; go: Go } = $props();

  const all = $derived(frameworks(view.findings));
  let picked = $state<string | null>(null);
  const fw = $derived(all.find((f) => f.id === picked) ?? all[0]);
  const total = $derived(fw ? tally(fw.findings) : null);
  const rate = $derived(total ? passRate(total) : null);

  let open = $state<Set<string>>(new Set());
  function toggle(key: string) {
    const next = new Set(open);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    open = next;
  }

  /** Controls with a group header row before the first of each group. */
  const rows = $derived.by(() => {
    const out: { header: string | null; c: Control; key: string }[] = [];
    let last: string | null = null;
    for (const c of fw?.controls ?? []) {
      out.push({ header: c.group && c.group !== last ? c.group : null, c, key: `${c.group}|${c.id}` });
      last = c.group;
    }
    return out;
  });

  const statusOrder = { failed: 0, accepted: 1, not_assessed: 2, passed: 3 };
  const sorted = (fs: Finding[]) => [...fs].sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);
  const statusText = { failed: 'Failed', passed: 'Passed', not_assessed: 'Not assessed', accepted: 'Accepted risk' };

  function pick(id: string) {
    picked = id;
    open = new Set();
  }
</script>

{#snippet bar(t: Tally)}
  {@const n = t.failed + t.passed + t.accepted + t.notAssessed}
  <span class="bar" role="img" aria-label="{t.failed} failed, {t.passed} passed, {t.accepted} accepted, {t.notAssessed} not assessed">
    {#if t.failed}<span class="seg-f" style:flex-grow={t.failed / n}></span>{/if}
    {#if t.accepted}<span class="seg-a" style:flex-grow={t.accepted / n}></span>{/if}
    {#if t.passed}<span class="seg-p" style:flex-grow={t.passed / n}></span>{/if}
    {#if t.notAssessed}<span class="seg-n" style:flex-grow={t.notAssessed / n}></span>{/if}
  </span>
{/snippet}

{#snippet counts(t: Tally)}
  <span class="counts small">
    {#if t.failed}<span class="state failed"><Icon name="dismissCircle" size={16} />{t.failed} failed</span>{/if}
    {#if t.passed}<span class="state ok"><Icon name="checkmarkCircle" size={16} />{t.passed} passed</span>{/if}
    {#if t.accepted}<span class="state neutral">{t.accepted} accepted</span>{/if}
    {#if t.notAssessed}<span class="state neutral">{t.notAssessed} not assessed</span>{/if}
  </span>
{/snippet}

<div class="toolbar" use:freeze>
  <div class="titles">
    <h2>Compliance</h2>
    <span class="muted small">
      Results grouped by the framework controls the catalog maps each check to. This covers only the mapped checks: it
      shows where the assessment touches a framework, not whether you meet it.
    </span>
  </div>
</div>

{#if !fw}
  <p class="empty">No check in this assessment maps to a framework.</p>
{:else}
  <div class="split">
    <nav class="fws" aria-label="Frameworks">
      {#each all as f (f.id)}
        {@const t = tally(f.findings)}
        {@const r = passRate(t)}
        <button class:on={f.id === fw.id} onclick={() => pick(f.id)}>
          <span class="fw-title">{f.title}</span>
          <span class="muted small">{plural(f.findings.length, 'check')}{r !== null ? ` · ${r}% passed` : ''}</span>
          {@render bar(t)}
        </button>
      {/each}
    </nav>

    <div class="main">
      <div class="head">
        <h3>{fw.title}</h3>
        {#if total}
          <div class="summary">
            {#if rate !== null}<span class="rate">{rate}%</span><span class="muted small">of assessed checks passed</span>{/if}
            {@render counts(total)}
          </div>
        {/if}
      </div>

      <div class="scroll-x">
        <table class="t">
          <thead>
            <tr>
              <th style="width: 36px"></th>
              <th style="width: 320px">{fw.id === 'mitre' ? 'Technique' : 'Control'}</th>
              <th style="width: 90px" class="r">Checks</th>
              <th style="width: 200px">Result</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each rows as row (row.key)}
              {@const t = tally(row.c.findings)}
              {#if row.header}
                <tr class="group"><td colspan="5">{row.header}</td></tr>
              {/if}
              <tr class="ctl" onclick={() => toggle(row.key)}>
                <td>
                  <button class="chev" aria-expanded={open.has(row.key)} aria-label="Show checks"><Icon name={open.has(row.key) ? 'chevronDown' : 'chevronRight'} size={16} /></button>
                </td>
                <td>
                  {#if row.c.id}<span class="mono">{row.c.id}</span>{:else}<span class="muted">Whole framework</span>{/if}
                  {#if row.c.name}<span class="block small">{row.c.name}</span>{/if}
                </td>
                <td class="r num">{num(row.c.findings.length)}</td>
                <td>{@render bar(t)}</td>
                <td>{@render counts(t)}</td>
              </tr>
              {#if open.has(row.key)}
                {#each sorted(row.c.findings) as f (findingKey(f))}
                  <tr class="sub">
                    <td></td>
                    <td colspan="2">
                      <button class="linkbtn plain" onclick={() => go({ page: 'finding', key: findingKey(f) })}>{f.title}</button>
                      <span class="mono small muted block">{f.id}{view.runs.length > 1 ? ` · ${f.run}` : ''}</span>
                    </td>
                    <td>
                      <span class="state" class:failed={f.status === 'failed'} class:ok={f.status === 'passed'} class:neutral={f.status === 'accepted' || f.status === 'not_assessed'}>
                        {statusText[f.status]}
                      </span>
                    </td>
                    <td>{#if f.status === 'failed'}<SevBadge severity={f.severity} />{/if}</td>
                  </tr>
                {/each}
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
      <p class="muted small legend">
        <span class="key seg-f"></span>Failed <span class="key seg-a"></span>Accepted risk <span class="key seg-p"></span>Passed
        <span class="key seg-n"></span>Not assessed
      </p>
    </div>
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

  .titles {
    display: flex;
    flex-direction: column;
    gap: 4px;
    flex: 1 1 auto;
    max-width: 900px;
  }

  .split {
    display: flex;
    align-items: flex-start;
    min-height: 0;
    gap: 18px;
    padding: 0 28px 28px 8px;
  }

  .fws {
    flex: 0 0 290px;
    display: flex;
    flex-direction: column;
    padding: 12px;
    gap: 4px;
    border-radius: var(--radius-lg);
    background: var(--surface);
  }

  .fws button {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 4px;
    padding: 10px 12px;
    border: none;
    border-radius: 16px;
    background: none;
    color: var(--text);
    font: inherit;
    text-align: left;
    cursor: pointer;
  }

  .fws button:hover {
    background: var(--surface-raised);
  }

  .fws button.on {
    background: var(--surface-raised);
    box-shadow: inset 0 0 0 2px var(--pill);
  }

  .fw-title {
    font-weight: 600;
  }

  .main {
    flex: 1 1 auto;
    min-width: 0;
    padding: 20px 24px 24px;
    border-radius: var(--radius-lg);
    background: var(--surface);
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .head {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .summary {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 6px 16px;
  }

  .rate {
    font-family: var(--font-display);
    font-size: 40px;
    font-weight: 300;
    line-height: 1;
  }

  .counts {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px 14px;
  }

  .bar {
    display: flex;
    gap: 2px;
    height: 10px;
    min-width: 120px;
    border-radius: 999px;
    overflow: hidden;
  }

  .bar span {
    flex-basis: 0;
    min-width: 3px;
  }

  .seg-f {
    background: var(--sev-critical-bg);
  }

  .seg-a {
    background: var(--lilac);
  }

  .seg-p {
    background: var(--ok-bg);
  }

  .seg-n {
    background: var(--border-strong);
  }

  .t {
    min-width: 860px;
  }

  tr.group td {
    background: var(--surface-alt);
    font-weight: 600;
    font-size: 13px;
  }

  tr.ctl {
    cursor: pointer;
  }

  tr.ctl:hover td {
    background: var(--surface-alt);
  }

  tr.sub td {
    background: var(--bg);
  }

  .chev {
    display: inline-flex;
    padding: 2px;
    border: none;
    background: none;
    color: var(--text-muted);
    cursor: pointer;
  }

  .r {
    text-align: right;
  }

  .block {
    display: block;
  }

  .legend {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin: 0;
  }

  .key {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 2px;
    margin-left: 8px;
  }

  .key:first-child {
    margin-left: 0;
  }

  .empty {
    margin: 24px;
    padding: 14px 16px;
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius);
  }
</style>
