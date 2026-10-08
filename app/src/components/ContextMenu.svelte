<script lang="ts" module>
  import type { IconName } from '../lib/icons';

  export interface MenuItem {
    label: string;
    icon?: IconName;
    hint?: string;
    disabled?: boolean;
    run: () => void;
  }

  /** A menu is groups of items, drawn with separators between them. */
  export type MenuGroups = (MenuItem[] | { title: string; items: MenuItem[] })[];
</script>

<script lang="ts">
  import { tick } from 'svelte';
  import Icon from './Icon.svelte';

  let { menu = $bindable(null) }: { menu: { x: number; y: number; title?: string; groups: MenuGroups } | null } = $props();

  let pop: HTMLDivElement | undefined = $state();
  let place = $state({ left: 0, top: 0 });
  let returnFocus: HTMLElement | null = null;

  const groups = $derived(
    (menu?.groups ?? []).map((g) => (Array.isArray(g) ? { title: '', items: g } : g)).filter((g) => g.items.length),
  );

  $effect(() => {
    if (!pop) return;
    if (menu) {
      returnFocus = document.activeElement as HTMLElement | null;
      place = { left: menu.x, top: menu.y };
      if (!pop.matches(':popover-open')) pop.showPopover();
      tick().then(() => {
        if (!pop) return;
        // Keep the whole menu on screen.
        // offsetWidth/Height ignore the opening scale, so the size is the final one.
        const w = pop.offsetWidth;
        const h = pop.offsetHeight;
        place = {
          left: Math.max(8, Math.min(menu!.x, window.innerWidth - w - 8)),
          top: Math.max(8, Math.min(menu!.y, window.innerHeight - h - 8)),
        };
        items()[0]?.focus();
      });
    } else if (pop.matches(':popover-open')) pop.hidePopover();
  });

  const items = () => [...(pop?.querySelectorAll<HTMLButtonElement>('button[role="menuitem"]:not(:disabled)') ?? [])];

  function onKey(e: KeyboardEvent) {
    const list = items();
    const i = list.indexOf(document.activeElement as HTMLButtonElement);
    const to: Record<string, number> = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: list.length - 1 };
    if (e.key in to) {
      e.preventDefault();
      list[(to[e.key] + list.length) % list.length]?.focus();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      close(true);
    }
  }

  function close(refocus: boolean) {
    menu = null;
    if (refocus) returnFocus?.focus?.();
  }

  function run(item: MenuItem) {
    close(true);
    item.run();
  }
</script>

<div
  bind:this={pop}
  popover="auto"
  class="menu"
  role="menu"
  tabindex="-1"
  aria-label={menu?.title ?? 'Actions'}
  style:left="{place.left}px"
  style:top="{place.top}px"
  onkeydown={onKey}
  ontoggle={(e) => {
    if ((e as ToggleEvent).newState === 'closed' && menu) menu = null;
  }}
>
  {#if menu?.title}<div class="mt">{menu.title}</div>{/if}
  {#each groups as g, gi (gi)}
    {#if gi > 0}<div class="sep" role="separator"></div>{/if}
    {#if g.title}<div class="gt">{g.title}</div>{/if}
    {#each g.items as it (it.label)}
      <button role="menuitem" disabled={it.disabled} onclick={() => run(it)}>
        <span class="ic">{#if it.icon}<Icon name={it.icon} size={16} />{/if}</span>
        <span class="lb">{it.label}</span>
        {#if it.hint}<span class="hint">{it.hint}</span>{/if}
      </button>
    {/each}
  {/each}
</div>

<style>
  .menu {
    position: fixed;
    inset: auto;
    margin: 0;
    min-width: 240px;
    max-width: 360px;
    max-height: calc(100vh - 16px);
    overflow-y: auto;
    padding: 4px;
    border: 1px solid var(--border-strong);
    border-radius: 18px;
    background: var(--surface);
    color: var(--text);
    box-shadow: 0 14px 36px rgb(0 0 0 / 0.18);
    opacity: 0;
    transform: scale(0.97);
    transform-origin: top left;
    transition:
      opacity 120ms ease-out,
      transform 120ms ease-out,
      display 120ms allow-discrete,
      overlay 120ms allow-discrete;
  }

  .menu:popover-open {
    opacity: 1;
    transform: none;
  }

  @starting-style {
    .menu:popover-open {
      opacity: 0;
      transform: scale(0.97);
    }
  }

  .mt {
    padding: 8px 10px 6px;
    font-weight: 600;
    font-size: 13px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .gt {
    padding: 6px 10px 2px;
    font-size: 12px;
    color: var(--text-muted);
  }

  .sep {
    height: 1px;
    margin: 4px 6px;
    background: var(--border);
  }

  button {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    min-height: 32px;
    padding: 0 10px 0 6px;
    border: none;
    border-radius: 10px;
    background: none;
    color: var(--text);
    font: inherit;
    font-size: 13.5px;
    text-align: left;
    cursor: pointer;
  }

  button:hover:not(:disabled),
  button:focus-visible {
    background: var(--accent-soft);
    outline: none;
  }

  button:disabled {
    color: var(--text-muted);
    cursor: default;
  }

  .ic {
    display: inline-flex;
    width: 18px;
    color: var(--text-muted);
  }

  .lb {
    flex: 1 1 auto;
  }

  .hint {
    font-size: 12px;
    color: var(--text-muted);
  }

  @media (forced-colors: active) {
    button:focus-visible {
      outline: 2px solid Highlight;
    }
  }
</style>
