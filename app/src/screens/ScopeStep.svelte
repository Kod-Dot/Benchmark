<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import type { CatalogSummary, GroupSummary } from '../lib/types';

  let {
    catalog,
    domain = $bindable(),
    tenant = $bindable(),
    selected = $bindable(),
    onNext,
    onBack,
  }: {
    catalog: CatalogSummary;
    domain: string;
    tenant: string;
    selected: Set<string>;
    onNext: () => void;
    onBack: () => void;
  } = $props();

  let expanded = $state<Set<string>>(new Set(['onprem']));

  const sourceTitle = (id: string) => catalog.sources.find((s) => s.id === id)?.title ?? id;

  function groupState(g: GroupSummary) {
    const n = g.areas.filter((a) => selected.has(a.code)).length;
    return { all: n === g.areas.length, some: n > 0 && n < g.areas.length };
  }

  function groupSources(g: GroupSummary) {
    return catalog.sources.filter((s) => g.areas.some((a) => a.sources.includes(s.id)));
  }

  function toggleGroup(g: GroupSummary) {
    const next = new Set(selected);
    const on = !groupState(g).all;
    for (const a of g.areas) on ? next.add(a.code) : next.delete(a.code);
    selected = next;
  }

  function toggleArea(code: string) {
    const next = new Set(selected);
    next.has(code) ? next.delete(code) : next.add(code);
    selected = next;
  }

  function toggleExpanded(id: string) {
    const next = new Set(expanded);
    next.has(id) ? next.delete(id) : next.add(id);
    expanded = next;
  }

  const allAreas = $derived(catalog.groups.flatMap((g) => g.areas));
  const chosen = $derived(allAreas.filter((a) => selected.has(a.code)));
  const chosenChecks = $derived(chosen.reduce((n, a) => n + a.checks, 0));
  const needsCloud = $derived(
    chosen.some((a) =>
      a.sources.some((s) => catalog.sources.find((x) => x.id === s)?.kind === 'cloud'),
    ),
  );
  const needsDomain = $derived(
    chosen.some((a) =>
      a.sources.some((s) => catalog.sources.find((x) => x.id === s)?.kind === 'onprem'),
    ),
  );
  const missing = $derived(
    chosen.length === 0
      ? 'Select at least one area.'
      : needsDomain && !domain.trim()
        ? 'Enter the domain to assess.'
        : needsCloud && !tenant.trim()
          ? 'Enter the Microsoft 365 tenant for the cloud areas you selected.'
          : null,
  );
</script>

<div class="layout">
  <aside class="target">
    <h3>Target</h3>
    <label>
      <span>Active Directory domain {#if !needsDomain}<span class="muted">(optional)</span>{/if}</span>
      <input type="text" bind:value={domain} placeholder="corp.example.com" spellcheck="false" />
      <small class="muted">Detected from this computer when it is domain-joined.</small>
    </label>
    <label>
      <span>Microsoft 365 tenant {#if !needsCloud}<span class="muted">(optional)</span>{/if}</span>
      <input type="text" bind:value={tenant} placeholder="contoso.onmicrosoft.com" spellcheck="false" />
      <small class="muted">You sign in to Microsoft when collection starts, with a work or school account in this tenant. Personal Microsoft accounts (outlook.com, hotmail.com) have no tenant to assess.</small>
    </label>
  </aside>

  <section class="areas" aria-label="Areas to assess">
    <table>
      <thead>
        <tr>
          <th class="col-check"></th>
          <th>Area</th>
          <th class="right col-checks">Checks</th>
          <th class="col-sources">Reads from</th>
        </tr>
      </thead>
      <tbody>
        {#each catalog.groups as g (g.id)}
          {@const st = groupState(g)}
          {@const open = expanded.has(g.id)}
          <tr class="group">
            <td class="col-check">
              <input
                type="checkbox"
                checked={st.all}
                indeterminate={st.some}
                onchange={() => toggleGroup(g)}
                aria-label="Select all of {g.title}"
              />
            </td>
            <td>
              <button class="expander" onclick={() => toggleExpanded(g.id)} aria-expanded={open}>
                <Icon name={open ? 'chevronDown' : 'chevronRight'} size={16} />
                <span class="group-title">{g.title}</span>
                <span class="muted count">{g.areas.length} area{g.areas.length === 1 ? '' : 's'}</span>
              </button>
            </td>
            <td class="right num">
              {#if g.areas.every((a) => a.generated)}<span class="muted">Generated</span>{:else}{g.checks}{/if}
            </td>
            <td class="muted sources">{groupSources(g).map((s) => s.title).join(', ')}</td>
          </tr>
          {#if open}
            {#each g.areas as a (a.code)}
              <tr class="area">
                <td class="col-check">
                  <input
                    type="checkbox"
                    checked={selected.has(a.code)}
                    onchange={() => toggleArea(a.code)}
                    aria-label="Select {a.title}"
                  />
                </td>
                <td>
                  <div class="area-name">
                    <code>{a.code}</code>
                    <span>{a.title}</span>
                  </div>
                </td>
                <td class="right num">
                  {#if a.generated}<span class="muted">Generated</span>{:else}{a.checks}{/if}
                </td>
                <td class="muted sources">{a.sources.map(sourceTitle).join(', ')}</td>
              </tr>
            {/each}
          {/if}
        {/each}
      </tbody>
    </table>
  </section>
</div>

<footer class="bar">
  <p>
    <strong class="num">{chosen.length}</strong> of {allAreas.length} areas selected,
    <strong class="num">{chosenChecks}</strong> checks{#if missing}<span class="muted">{" · "}{missing}</span>{/if}
  </p>
  <div class="buttons">
    <button class="btn" onclick={onBack}><Icon name="arrowLeft" size={18} />Back</button>
    <button class="btn primary" disabled={!!missing} onclick={onNext}>
      Next: Check access <Icon name="arrowRight" size={18} />
    </button>
  </div>
</footer>

<style>
  .buttons {
    display: flex;
    gap: var(--space-3);
  }

  .layout {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: 300px 1fr;
    gap: 18px;
    padding: 4px 24px 0;
  }

  .target {
    display: flex;
    flex-direction: column;
    align-self: start;
    gap: var(--space-4);
    padding: 22px;
    border-radius: var(--radius-lg);
    background: var(--surface);
  }

  label {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    font-weight: 500;
  }

  small {
    font-weight: 400;
    font-size: 12.5px;
  }

  .areas {
    overflow: auto;
    border-radius: var(--radius-lg);
    background: var(--surface);
  }

  thead th {
    position: sticky;
    top: 0;
    z-index: 1;
  }

  .col-check {
    width: 44px;
    padding-left: var(--space-4);
  }

  .group td {
    background: var(--surface);
    height: 44px;
  }

  .expander {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    border: none;
    background: none;
    color: var(--text);
    padding: 0;
    cursor: pointer;
  }

  .group-title {
    font-weight: 600;
  }

  .count {
    font-size: 13px;
  }

  .area td {
    height: var(--row-height);
  }

  .area:hover td {
    background: var(--surface-alt);
  }

  table {
    table-layout: fixed;
  }

  .col-checks {
    width: 96px;
  }

  .col-sources {
    width: 38%;
  }

  .area-name {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding-left: 24px;
  }

  .area-name code {
    min-width: 76px;
    color: var(--text-muted);
  }

  .sources {
    font-size: 13px;
  }

  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-5);
  }
</style>
