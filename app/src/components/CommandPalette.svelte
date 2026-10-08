<script lang="ts" module>
  import type { IconName } from '../lib/icons';
  import type { Route } from '../results/route';

  /** A page or command the palette can jump to. */
  export interface PaletteCommand {
    label: string;
    icon: IconName;
    hint?: string;
    keywords?: string;
    run: Route | (() => void);
  }
</script>

<script lang="ts">
  import { tick } from 'svelte';
  import Icon from './Icon.svelte';
  import SevBadge from './SevBadge.svelte';
  import { kindIcon } from '../lib/format';
  import type { AssessmentView, Severity } from '../lib/types';
  import { findingKey, type Go } from '../results/route';

  let {
    open = $bindable(false),
    view,
    commands,
    go,
  }: { open?: boolean; view: AssessmentView; commands: PaletteCommand[]; go: Go } = $props();

  interface Item {
    id: string;
    label: string;
    sub?: string;
    icon: IconName;
    severity?: Severity;
    passed?: boolean;
    run: Route | (() => void);
  }

  const PER_GROUP = 8;
  let dialog: HTMLDialogElement | undefined = $state();
  let input: HTMLInputElement | undefined = $state();
  let query = $state('');
  let active = $state(0);
  let returnFocus: HTMLElement | null = null;

  $effect(() => {
    if (!dialog) return;
    if (open && !dialog.open) {
      returnFocus = document.activeElement as HTMLElement | null;
      query = '';
      active = 0;
      dialog.showModal();
      tick().then(() => input?.focus());
    } else if (!open && dialog.open) {
      dialog.close();
    }
  });

  function onClose() {
    open = false;
    returnFocus?.focus?.();
  }

  /** 0 when the (lower-case) text starts with the query, 1 when a word does, 2 when it only contains it. */
  function rank(t: string, q: string): number {
    const i = t.indexOf(q);
    if (i < 0) return -1;
    if (i === 0) return 0;
    return /[\s\-_.\\/:·(]/.test(t[i - 1]) ? 1 : 2;
  }

  function best<T>(all: Iterable<T>, texts: (x: T) => string[], q: string, max: number): T[] {
    const buckets: T[][] = [[], [], []];
    for (const x of all) {
      let r = -1;
      for (const s of texts(x)) {
        const k = rank(s, q);
        if (k >= 0 && (r < 0 || k < r)) r = k;
      }
      if (r < 0) continue;
      if (buckets[r].length < max) buckets[r].push(x);
      // Enough exact starts: nothing later can rank higher.
      if (buckets[0].length >= max) break;
    }
    return buckets.flat().slice(0, max);
  }

  const areas = $derived(view.summary.areas.filter((a) => a.assessed > 0 || a.failed > 0));
  const findings = $derived(
    [...view.findings].sort(
      (a, b) => Number(b.status === 'failed') - Number(a.status === 'failed') || a.id.localeCompare(b.id),
    ),
  );

  // Lower-cased once, not on every key press: a directory can hold 500,000 objects.
  const objectKeys = $derived(
    (view.directory?.objects ?? []).map((o) => ({ o, text: [o.name.toLowerCase(), (o.display_name ?? '').toLowerCase()] })),
  );

  const groups = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const pages: Item[] = (q ? best(commands, (c) => [c.label.toLowerCase(), (c.keywords ?? '').toLowerCase()], q, PER_GROUP) : commands).map((c, i) => ({
      id: `cmd-${i}-${c.label}`,
      label: c.label,
      sub: c.hint,
      icon: c.icon,
      run: c.run,
    }));
    if (!q) return [{ title: 'Go to', items: pages }];
    const areaItems: Item[] = best(areas, (a) => [a.code.toLowerCase(), a.title.toLowerCase()], q, PER_GROUP).map((a) => ({
      id: `area-${a.code}`,
      label: a.title,
      sub: `${a.code} · ${a.failed} failed of ${a.assessed}`,
      icon: 'layer',
      run: { page: 'findings', area: a.code },
    }));
    const checkItems: Item[] = best(findings, (f) => [f.id.toLowerCase(), f.title.toLowerCase()], q, PER_GROUP).map((f) => ({
      id: `check-${findingKey(f)}`,
      label: f.title,
      sub: f.id,
      icon: 'shieldCheckmark',
      severity: f.status === 'failed' ? f.severity : undefined,
      passed: f.status === 'passed',
      run: { page: 'finding', key: findingKey(f) },
    }));
    const objectItems: Item[] = best(objectKeys, (k) => k.text, q, PER_GROUP).map(
      ({ o }) => ({
        id: `obj-${o.id}`,
        label: o.name,
        sub: o.display_name && o.display_name !== o.name ? `${o.display_name} · ${o.source}` : o.source,
        icon: kindIcon(o.kind),
        run: { page: 'object', id: o.id },
      }),
    );
    return [
      { title: 'Go to', items: pages },
      { title: 'Areas', items: areaItems },
      { title: 'Checks', items: checkItems },
      { title: 'Objects', items: objectItems },
    ].filter((g) => g.items.length);
  });

  const flat = $derived(groups.flatMap((g) => g.items));
  const activeItem = $derived(flat[Math.min(active, flat.length - 1)]);

  $effect(() => {
    // A new query starts again at the top.
    void query;
    active = 0;
  });

  function choose(item: Item | undefined) {
    if (!item) return;
    open = false;
    returnFocus = null;
    if (typeof item.run === 'function') item.run();
    else go(item.run);
  }

  async function move(to: number) {
    if (!flat.length) return;
    active = (to + flat.length) % flat.length;
    await tick();
    dialog?.querySelector(`[data-active="true"]`)?.scrollIntoView({ block: 'nearest' });
  }

  function onKey(e: KeyboardEvent) {
    const moves: Record<string, number> = {
      ArrowDown: active + 1,
      ArrowUp: active - 1,
      PageDown: Math.min(active + PER_GROUP, flat.length - 1),
      PageUp: Math.max(active - PER_GROUP, 0),
    };
    if (e.key in moves) {
      e.preventDefault();
      move(moves[e.key]);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      choose(activeItem);
    }
  }
</script>

<dialog
  bind:this={dialog}
  class="palette"
  aria-label="Go to a page, area, check or object"
  onclose={onClose}
  onclick={(e) => {
    // A click on the backdrop closes the palette.
    if (e.target === dialog) open = false;
  }}
>
  <div class="box">
    <label class="field">
      <Icon name="search" size={20} />
      <input
        bind:this={input}
        bind:value={query}
        type="text"
        role="combobox"
        aria-expanded="true"
        aria-controls="palette-list"
        aria-activedescendant={activeItem?.id}
        aria-autocomplete="list"
        placeholder="Go to a page, area, check or object"
        autocomplete="off"
        spellcheck="false"
        onkeydown={onKey}
      />
      <span class="kbd">Esc</span>
    </label>
    <div class="list" id="palette-list" role="listbox" aria-label="Results">
      {#each groups as g (g.title)}
        <div role="group" aria-labelledby="palette-{g.title}">
          <div class="gh" id="palette-{g.title}">{g.title}</div>
          {#each g.items as it (it.id)}
            {@const on = activeItem?.id === it.id}
            <div
              id={it.id}
              class="opt"
              class:on
              role="option"
              tabindex="-1"
              aria-selected={on}
              data-active={on}
              onmousemove={() => (active = flat.indexOf(it))}
              onclick={() => choose(it)}
              onkeydown={() => {}}
            >
              <Icon name={it.icon} size={16} />
              <span class="label">{it.label}</span>
              {#if it.sub}<span class="sub mono">{it.sub}</span>{/if}
              {#if it.severity}<SevBadge severity={it.severity} />{:else if it.passed}<span class="passed small">Passed</span>{/if}
            </div>
          {/each}
        </div>
      {:else}
        <p class="none muted">Nothing matches “{query}”.</p>
      {/each}
    </div>
    <div class="foot muted small">
      <span><span class="kbd">↑</span><span class="kbd">↓</span> to move</span>
      <span><span class="kbd">Enter</span> to open</span>
      <span class="spacer"></span>
      <span>Ctrl F searches the page you are on</span>
    </div>
  </div>
</dialog>

<style>
  .palette {
    width: min(680px, calc(100vw - 32px));
    max-height: min(560px, calc(100vh - 96px));
    margin: 12vh auto auto;
    padding: 0;
    border: 1px solid var(--border-strong);
    border-radius: 22px;
    background: var(--surface);
    color: var(--text);
    box-shadow: 0 16px 48px rgb(0 0 0 / 0.22);
    overflow: hidden;
  }

  .palette::backdrop {
    background: rgb(0 0 0 / 0.28);
  }

  .box {
    display: flex;
    flex-direction: column;
    max-height: inherit;
  }

  .field {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 14px;
    height: 52px;
    flex: none;
    border-bottom: 1px solid var(--border);
    color: var(--text-muted);
  }

  .field input {
    flex: 1 1 auto;
    min-width: 0;
    height: 100%;
    border: none;
    outline: none;
    background: transparent;
    color: var(--text);
    font: inherit;
    font-size: 16px;
  }

  .list {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    padding: 6px;
  }

  .gh {
    padding: 10px 10px 4px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
  }

  .opt {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 36px;
    padding: 0 10px;
    border-radius: 12px;
    cursor: pointer;
  }

  .opt :global(.icon) {
    flex: none;
    color: var(--text-muted);
  }

  .opt.on {
    background: var(--accent-soft);
    box-shadow: inset 3px 0 0 var(--accent);
  }

  .label {
    flex: 0 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sub {
    flex: 1 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 12px;
    color: var(--text-muted);
  }

  .passed {
    flex: none;
    color: var(--text-muted);
  }

  .none {
    padding: 16px 10px;
    margin: 0;
  }

  .foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 16px;
    flex: none;
    padding: 8px 14px;
    border-top: 1px solid var(--border);
    background: var(--surface-alt);
  }

  .foot .kbd {
    margin-right: 2px;
  }

  .spacer {
    flex: 1 1 auto;
  }

  @media (forced-colors: active) {
    .opt.on {
      outline: 2px solid Highlight;
      outline-offset: -2px;
    }
  }
</style>
