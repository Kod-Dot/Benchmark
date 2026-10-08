<script lang="ts">
  import { freeze } from '../lib/freeze';
  import { untrack } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Select from '../components/Select.svelte';
  import { VirtualRows } from '../lib/virtual.svelte';
  import { AGE_BUCKETS, accountSources, ageHistogram, type AgeMeasure } from '../lib/ages';
  import { date, kindIcon, num, plural } from '../lib/format';
  import type { Directory } from '../lib/types';
  import type { Go } from './route';

  let { directory, go }: { directory: Directory; go: Go } = $props();

  const withAges = $derived(accountSources(directory));
  let source = $state(untrack(() => withAges[0]?.name ?? ''));
  let kind = $state<'user' | 'computer'>('user');
  let enabledOnly = $state(true);
  let picked = $state<{ m: AgeMeasure; i: number } | null>(null);

  const src = $derived(withAges.find((s) => s.name === source));
  const kinds = $derived(
    (['user', 'computer'] as const).filter((k) => directory.objects.some((o) => o.source === source && o.kind === k)),
  );
  $effect(() => {
    if (!kinds.includes(kind) && kinds[0]) kind = kinds[0];
  });

  const objects = $derived(
    directory.objects.filter(
      (o) => o.source === source && o.kind === kind && (!enabledOnly || o.enabled !== false),
    ),
  );

  const histogram = (m: AgeMeasure) => ageHistogram(objects, m, src?.read_at);

  const charts = $derived([
    { m: 'password' as AgeMeasure, title: 'Password age', bins: histogram('password') },
    { m: 'logon' as AgeMeasure, title: 'Time since last sign-in', bins: histogram('logon') },
  ]);

  const selected = $derived.by(() => {
    if (!picked) return null;
    const c = charts.find((x) => x.m === picked!.m);
    const bin = c?.bins[picked.i];
    return c && bin ? { title: c.title, label: bin.label, objs: bin.objs } : null;
  });

  function pick(m: AgeMeasure, i: number) {
    picked = picked?.m === m && picked.i === i ? null : { m, i };
  }

  const kindWord = $derived(kind === 'user' ? 'user' : 'computer');
  const win = new VirtualRows();
  const listed = $derived(
    selected ? [...selected.objs].sort((a, b) => Number(b.tier0) - Number(a.tier0) || a.name.localeCompare(b.name)) : [],
  );
</script>

<div class="toolbar" use:freeze>
  <div class="titles">
    <h2>Account ages</h2>
    <span class="muted small">
      How long since passwords were set and since accounts last signed in, measured from when the directory was read.
      Stale accounts and old passwords are where unused access piles up. Select a bar to list its accounts.
    </span>
  </div>
</div>

{#if !src}
  <p class="empty">This assessment has no users or computers to measure.</p>
{:else}
  <div class="body">
    <div class="filters">
      {#if withAges.length > 1}
        <div class="field">
          <span class="muted small">Source</span>
          <Select label="Source" bind:value={source} onchange={() => (picked = null)} options={withAges.map((s) => ({ value: s.name, label: s.name }))} />
        </div>
      {/if}
      <div class="seg" role="radiogroup" aria-label="Object kind">
        {#each kinds as k (k)}
          <button role="radio" aria-checked={kind === k} class:on={kind === k} onclick={() => (kind = k)}>
            <Icon name={kindIcon(k)} size={16} />{k === 'user' ? 'Users' : 'Computers'}
          </button>
        {/each}
      </div>
      <label class="check"><input type="checkbox" bind:checked={enabledOnly} />Enabled accounts only</label>
      <span class="spacer"></span>
      <span class="muted small">{plural(objects.length, kindWord)} · read {date(src.read_at, true)}</span>
    </div>

    <div class="charts">
      {#each charts as c (c.m)}
        {@const peak = Math.max(1, ...c.bins.map((b) => b.objs.length))}
        <section class="chart">
          <h3>{c.title}</h3>
          <div class="bars" role="group" aria-label="{c.title} of {plural(objects.length, kindWord)}">
            {#each c.bins as b, i (b.label)}
              {@const on = picked?.m === c.m && picked.i === i}
              <button
                class="col"
                class:on
                class:none={i === AGE_BUCKETS.length}
                aria-pressed={on}
                disabled={!b.objs.length}
                onclick={() => pick(c.m, i)}
              >
                <span class="val num">{num(b.objs.length)}</span>
                <span class="track"><span class="bar" style:height="{(b.objs.length / peak) * 100}%"></span></span>
                <span class="lbl small">{b.label}</span>
              </button>
            {/each}
          </div>
        </section>
      {/each}
    </div>

    {#if selected}
      <section class="list">
        <div class="list-h">
          <h3>{selected.title}: {selected.label}</h3>
          <span class="muted small">{plural(selected.objs.length, kindWord)}</span>
          <span class="spacer"></span>
          <button class="btn sm ghost" onclick={() => (picked = null)}>Clear selection</button>
        </div>
        <div class="scroll-x">
          <table class="t stick" aria-rowcount={listed.length + 1}>
            <thead>
              <tr aria-rowindex="1">
                <th>Name</th>
                <th style="width: 110px">State</th>
                <th style="width: 140px">Last sign-in</th>
                <th style="width: 140px">Password set</th>
                <th style="width: 260px">Flags</th>
              </tr>
            </thead>
            <tbody use:win.rows={listed.length}>
              {#if win.start > 0}<tr class="gap" aria-hidden="true"><td colspan="5" style:height="{win.before}px"></td></tr>{/if}
              {#each listed.slice(win.start, win.end) as o, j (o.id)}
                <tr data-index={win.start + j} aria-rowindex={win.start + j + 2}>
                  <td>
                    <span class="obj">
                      <span class="otype" class:t0={o.tier0}><Icon name={kindIcon(o.kind)} size={16} /></span>
                      <span>
                        <button class="linkbtn plain strong" onclick={() => go({ page: 'object', id: o.id })}>{o.name}</button>
                        {#if o.display_name}<span class="muted small block">{o.display_name}</span>{/if}
                      </span>
                    </span>
                  </td>
                  <td>
                    {#if o.enabled === false}<span class="state neutral"><Icon name="subtractCircle" size={16} />Disabled</span>
                    {:else if o.enabled}<span class="state ok"><Icon name="checkmarkCircle" size={16} />Enabled</span>{/if}
                  </td>
                  <td class="num small">{date(o.last_logon)}</td>
                  <td class="num small">{date(o.password_last_set)}</td>
                  <td><span class="flags">{#each o.flags as fl, i (i)}<span class="flag {fl.level}">{fl.text}</span>{/each}</span></td>
                </tr>
              {/each}
              {#if win.end < listed.length}<tr class="gap" aria-hidden="true"><td colspan="5" style:height="{win.after(listed.length)}px"></td></tr>{/if}
            </tbody>
          </table>
        </div>
      </section>
    {/if}
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

  .body {
    padding: 16px 24px 32px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px 20px;
  }

  .field {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .check {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .spacer {
    flex: 1 1 auto;
  }

  .charts {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
    gap: 24px 40px;
  }

  .chart {
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 20px 22px 18px;
    border-radius: var(--radius-lg);
    background: var(--surface);
  }

  .chart h3 {
    font-size: 17px;
    font-weight: 500;
    color: var(--text);
  }

  .bars {
    display: grid;
    grid-template-columns: repeat(7, 1fr);
    gap: 2px;
  }

  .col {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 4px;
    padding: 4px 2px;
    border: none;
    border-radius: 14px;
    background: none;
    color: var(--text);
    font: inherit;
    cursor: pointer;
  }

  .col:hover:not(:disabled),
  .col.on {
    background: var(--surface-raised);
  }

  .col:disabled {
    cursor: default;
  }

  .val {
    text-align: center;
    font-weight: 600;
    font-size: 13px;
  }

  .col:disabled .val {
    color: var(--text-muted);
    font-weight: 400;
  }

  .track {
    display: flex;
    align-items: flex-end;
    height: 120px;
    border-bottom: 1px solid var(--border-strong);
  }

  .bar {
    display: block;
    width: 100%;
    min-height: 0;
    background: var(--peri);
    border-radius: 10px 10px 4px 4px;
  }

  .col.none .bar {
    background: var(--border-strong);
  }

  .lbl {
    text-align: center;
    color: var(--text-muted);
    line-height: 1.25;
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .list-h {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 4px 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }

  .t {
    min-width: 820px;
  }

  .obj {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .otype {
    display: inline-flex;
    color: var(--text-muted);
  }

  .otype.t0 {
    color: var(--accent-ink);
  }

  .block {
    display: block;
  }

  .strong {
    font-weight: 600;
  }

  .flags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .empty {
    margin: 24px;
    padding: 14px 16px;
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius);
  }
</style>
