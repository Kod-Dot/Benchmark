<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import Select from '../components/Select.svelte';
  import { kindIcon, plural } from '../lib/format';
  import { DirGraph, edgeInfo, fixCommand } from '../lib/graph';
  import { compromised } from '../lib/marks.svelte';
  import { copyText } from '../lib/toast.svelte';
  import { PRESETS, PRESET_GROUPS, type Preset, type PresetResult } from '../lib/presets';
  import type { AssessmentView } from '../lib/types';
  import { findingKey, type Go } from './route';

  let { view, go }: { view: AssessmentView; go: Go } = $props();

  type Mode = 'presets' | 'analyzed';
  let mode = $state<Mode>('presets');

  const objectIds = $derived(new Set(view.directory?.objects.map((o) => o.id) ?? []));
  const tier0 = $derived(new Set(view.directory?.objects.filter((o) => o.tier0).map((o) => o.id) ?? []));
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const paths = $derived([...view.paths].sort((a, b) => order[a.severity] - order[b.severity] || a.steps.length - b.steps.length));

  function openCheck(id: string) {
    const f = view.findings.find((x) => x.id === id);
    if (f) go({ page: 'finding', key: findingKey(f) });
  }

  // ---------- Presets ----------
  const graph = $derived(view.directory ? new DirGraph(view.directory) : null);
  const readAt = $derived(
    Math.max(0, ...(view.directory?.sources.map((s) => Date.parse(s.read_at)).filter((n) => !Number.isNaN(n)) ?? [])) || Date.now(),
  );

  let presetId = $state(PRESETS[0].id);
  const preset = $derived<Preset>(PRESETS.find((p) => p.id === presetId) ?? PRESETS[0]);

  // Count results per preset so the picker shows how many each finds, and empty
  // ones read as a clean result rather than a dead link.
  const counts = $derived.by(() => {
    const g = graph;
    const map = new Map<string, number>();
    if (!g) return map;
    const ctx = { compromised, readAt };
    for (const p of PRESETS) {
      try {
        map.set(p.id, p.run(g, ctx).length);
      } catch {
        map.set(p.id, 0);
      }
    }
    return map;
  });

  const results = $derived.by<PresetResult[]>(() => {
    const g = graph;
    if (!g) return [];
    try {
      return preset.run(g, { compromised, readAt });
    } catch {
      return [];
    }
  });

  function name(id: string) {
    return graph?.byId.get(id)?.name ?? id;
  }
  function kindOf(id: string) {
    return graph?.byId.get(id)?.kind ?? 'unknown';
  }

  function copyRemediation(r: PresetResult) {
    const g = graph;
    if (!g) return;
    const lines = r.edges
      .map((e) => fixCommand(e, g.byId.get(e.from), g.byId.get(e.to)))
      .filter((c): c is string => !!c);
    if (!lines.length) return;
    copyText(lines.join('\n\n'), 'Commands copied: review them before running');
  }
</script>

<div class="toolbar">
  <div class="titles">
    <h2>Attack paths to Tier 0</h2>
    <span class="muted small">
      {#if mode === 'presets'}
        Ready-made questions that find where privilege can escalate toward the objects that control the directory
      {:else}
        {plural(view.paths.length, 'path')} the engine traced from less privileged principals to Tier 0
      {/if}
    </span>
  </div>
  <div class="seg" role="group" aria-label="View">
    <button class:on={mode === 'presets'} onclick={() => (mode = 'presets')}>Presets</button>
    <button class:on={mode === 'analyzed'} onclick={() => (mode = 'analyzed')}>Traced paths</button>
    {#if view.directory}
      <button onclick={() => go({ page: 'graph' })}>Graph</button>
    {/if}
  </div>
</div>

{#if mode === 'presets'}
  {#if !graph}
    <p class="muted pad">This assessment did not collect directory relationships, so attack-path presets are unavailable.</p>
  {:else}
    <div class="split">
      <nav class="picker" aria-label="Attack-path presets">
        {#each PRESET_GROUPS as group (group)}
          <div class="pgroup">{group}</div>
          {#each PRESETS.filter((p) => p.group === group) as p (p.id)}
            {@const n = counts.get(p.id) ?? 0}
            <button class="pitem enter" class:on={p.id === presetId} onclick={() => (presetId = p.id)}>
              <Icon name={p.icon} size={18} />
              <span class="plabel">{p.title}</span>
              <span class="pcount" class:zero={n === 0}>{n}</span>
            </button>
          {/each}
        {/each}
      </nav>

      <div class="list" data-scroller>
        <div class="about">
          <h3>{preset.title}</h3>
          <p class="muted">{preset.about}</p>
        </div>

        {#if presetId === 'marked' && compromised.size === 0}
          <p class="muted pad">Right-click an object in the relationship graph and choose "Mark as compromised" to see where control of it would lead.</p>
        {:else}
          {#each results as r, i (i)}
            <section class="path enter">
              <div class="head">
                <SevBadge severity={r.severity} />
                <strong>{r.title}</strong>
                {#if r.edges.some((e) => fixCommand(e, graph.byId.get(e.from), graph.byId.get(e.to)))}
                  <button class="linkbtn small fixbtn" onclick={() => copyRemediation(r)}>
                    <Icon name="copy" size={14} /> How to remove it
                  </button>
                {/if}
              </div>
              {#if r.edges.length}
                <div class="chain">
                  <button class="obj" class:t0={tier0.has(r.start.id)} onclick={() => go({ page: 'object', id: r.start.id })}>
                    <Icon name={kindIcon(r.start.kind)} />{r.start.name}
                  </button>
                  {#each r.edges as e, j (j)}
                    {@const last = j === r.edges.length - 1}
                    <span class="edge"><span class="mono">{edgeInfo(e.kind).label}</span><Icon name="arrowRight" size={16} /></span>
                    {#if objectIds.has(e.to)}
                      <button class="obj" class:target={last} class:t0={tier0.has(e.to)} onclick={() => go({ page: 'object', id: e.to })}>
                        <Icon name={kindIcon(kindOf(e.to))} />{name(e.to)}
                      </button>
                    {:else}
                      <span class="obj" class:target={last}><Icon name={kindIcon(kindOf(e.to))} />{name(e.to)}</span>
                    {/if}
                  {/each}
                </div>
              {:else}
                <div class="chain">
                  <button class="obj" class:t0={tier0.has(r.start.id)} class:target={r.start.tier0} onclick={() => go({ page: 'object', id: r.start.id })}>
                    <Icon name={kindIcon(r.start.kind)} />{r.start.name}
                  </button>
                </div>
              {/if}
              {#if r.note}<p class="muted small note">{r.note}</p>{/if}
            </section>
          {:else}
            <p class="muted pad">Nothing matched this question in the collected relationships.</p>
          {/each}
        {/if}
      </div>
    </div>
  {/if}
{:else}
  <div class="split">
    <div class="list" data-scroller>
      {#each paths as p, i (i)}
        <section class="path">
          <div class="head">
            <SevBadge severity={p.severity} />
            <strong>{p.title}</strong>
            {#each p.checks as c (c)}<button class="linkbtn small mono" onclick={() => openCheck(c)}>{c}</button>{/each}
          </div>
          <div class="chain">
            {#each p.steps as s, j (j)}
              {@const last = j === p.steps.length - 1}
              {#if s.object && objectIds.has(s.object)}
                <button class="obj" class:target={last} class:t0={s.object && tier0.has(s.object)} onclick={() => go({ page: 'object', id: s.object! })}>
                  <Icon name={kindIcon(s.kind)} />{s.name}
                </button>
              {:else}
                <span class="obj" class:target={last}><Icon name={kindIcon(s.kind)} />{s.name}</span>
              {/if}
              {#if s.via && !last}
                <span class="edge"><span class="mono">{s.via}</span><Icon name="arrowRight" size={16} /></span>
              {/if}
            {/each}
          </div>
        </section>
      {:else}
        <p class="muted pad">No attack paths to Tier 0 were traced in this assessment.</p>
      {/each}
    </div>

    {#if view.choke_points.length}
      <aside class="side">
        <div class="sidehead">
          <h3>Choke points</h3>
          <p class="muted small">Fixing one of these breaks the most paths.</p>
        </div>
        <table class="t flat">
          <thead><tr><th class="pl">Fix</th><th class="right pr">Paths broken</th></tr></thead>
          <tbody>
            {#each view.choke_points as c (c.check)}
              <tr>
                <td class="pl"><button class="linkbtn plain" onclick={() => openCheck(c.check)}>{c.title}</button><div class="mono muted">{c.check}</div></td>
                <td class="right num pr">{c.paths} of {view.paths.length}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </aside>
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
    gap: 2px;
    flex: 1 1 auto;
    min-width: 0;
  }

  .split {
    display: flex;
    flex: 1 1 auto;
    min-height: 0;
    gap: 18px;
    padding: 0 28px 28px 8px;
    align-items: flex-start;
  }

  .picker {
    flex: 0 0 300px;
    border-radius: var(--radius-lg);
    background: var(--surface);
    padding: 14px 12px 18px;
  }

  .pgroup {
    font-size: 11.5px;
    font-weight: 600;
    letter-spacing: 0.02em;
    color: var(--text-muted);
    padding: 14px 10px 6px;
  }

  .pgroup:first-child {
    padding-top: 4px;
  }

  .pitem {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 9px 12px;
    border: 0;
    border-radius: 14px;
    background: transparent;
    color: var(--text);
    font: inherit;
    text-align: left;
    cursor: pointer;
    transition: background var(--transition);
  }

  .pitem:hover {
    background: var(--surface-raised);
  }

  .pitem.on {
    background: var(--mint);
    color: var(--ink);
    font-weight: 600;
  }

  .plabel {
    flex: 1 1 auto;
    min-width: 0;
  }

  .pcount {
    flex: 0 0 auto;
    min-width: 22px;
    height: 20px;
    padding: 0 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 10px;
    background: var(--surface-alt);
    color: var(--text-muted);
    font-size: 12px;
    font-variant-numeric: tabular-nums;
  }

  .pcount.zero {
    opacity: 0.45;
  }

  .pitem.on .pcount {
    background: rgb(255 255 255 / 0.55);
    color: var(--ink);
  }

  .list {
    flex: 1 1 auto;
    min-width: 0;
    padding: 24px 26px;
    border-radius: var(--radius-lg);
    background: var(--surface);
    display: flex;
    flex-direction: column;
    gap: 20px;
    overflow-y: auto;
  }

  .about {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding-bottom: 4px;
  }

  .about p {
    max-width: 68ch;
  }

  .path {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }

  .head,
  .chain {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 12px;
  }

  .chain {
    gap: 8px;
  }

  .fixbtn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }

  .note {
    margin: -4px 0 0;
  }

  .obj {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 42px;
    padding: 0 18px 0 14px;
    border: 1px solid transparent;
    border-radius: 999px;
    background: var(--surface-raised);
    color: var(--text);
    font: inherit;
    white-space: nowrap;
  }

  button.obj {
    cursor: pointer;
  }

  button.obj:hover {
    border-color: var(--accent);
  }

  .obj.target {
    box-shadow: inset 0 0 0 2px var(--salmon);
    font-weight: 600;
  }

  .obj.t0 :global(.icon) {
    color: var(--sev-critical);
  }

  .edge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--text-muted);
    font-size: 12.5px;
  }

  .side {
    flex: 0 0 400px;
    background: var(--surface);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }

  .sidehead {
    padding: 20px 24px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .t .pl {
    padding-left: 24px;
  }

  .t .pr {
    padding-right: 24px;
  }

  .pad {
    padding: 24px;
  }
</style>
