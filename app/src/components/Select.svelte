<script lang="ts" module>
  import type { IconName } from '../lib/icons';

  export interface SelectOption<T extends string = string> {
    value: T;
    label: string;
    /** A second, muted line or trailing text. */
    sub?: string;
    icon?: IconName;
  }
</script>

<script lang="ts" generics="T extends string">
  import { tick } from 'svelte';
  import Icon from './Icon.svelte';

  let {
    value = $bindable(),
    options,
    label,
    icon,
    bare = false,
    onchange,
  }: {
    value: T | null;
    options: SelectOption<T>[];
    /** Accessible name; also shown above the value when `bare`. */
    label: string;
    icon?: IconName;
    /** Borderless, for use inside a larger picker. */
    bare?: boolean;
    onchange?: (value: T) => void;
  } = $props();

  const uid = `sel-${Math.random().toString(36).slice(2, 9)}`;
  let button: HTMLButtonElement | undefined = $state();
  let pop: HTMLDivElement | undefined = $state();
  let open = $state(false);
  let active = $state(0);
  let place = $state({ left: 0, top: 0, width: 0, up: false, max: 320 });
  let typed = '';
  let typedAt = 0;

  const current = $derived(options.find((o) => o.value === value));

  function measure() {
    if (!button) return;
    const r = button.getBoundingClientRect();
    const below = window.innerHeight - r.bottom - 12;
    const above = r.top - 12;
    const up = below < 220 && above > below;
    place = { left: r.left, top: up ? r.top - 4 : r.bottom + 4, width: Math.max(r.width, 200), up, max: Math.min(360, up ? above : below) };
  }

  async function show() {
    if (open || !pop) return;
    measure();
    active = Math.max(0, options.findIndex((o) => o.value === value));
    pop.showPopover();
    open = true;
    await tick();
    pop.querySelector<HTMLElement>(`[data-i="${active}"]`)?.scrollIntoView({ block: 'nearest' });
  }

  function hide(refocus = true) {
    if (pop?.matches(':popover-open')) pop.hidePopover();
    open = false;
    if (refocus) button?.focus();
  }

  function pick(i: number) {
    const o = options[i];
    if (!o) return;
    hide();
    if (o.value !== value) {
      value = o.value;
      onchange?.(o.value);
    }
  }

  async function moveTo(i: number) {
    active = Math.min(Math.max(i, 0), options.length - 1);
    await tick();
    pop?.querySelector<HTMLElement>(`[data-i="${active}"]`)?.scrollIntoView({ block: 'nearest' });
  }

  function onKey(e: KeyboardEvent) {
    const k = e.key;
    if (!open) {
      if (k === 'ArrowDown' || k === 'ArrowUp' || k === 'Enter' || k === ' ') {
        e.preventDefault();
        show();
      }
      return;
    }
    const moves: Record<string, number> = {
      ArrowDown: active + 1,
      ArrowUp: active - 1,
      Home: 0,
      End: options.length - 1,
      PageDown: active + 8,
      PageUp: active - 8,
    };
    if (k in moves) {
      e.preventDefault();
      moveTo(moves[k]);
    } else if (k === 'Enter' || k === ' ') {
      e.preventDefault();
      pick(active);
    } else if (k === 'Escape' || k === 'Tab') {
      if (k === 'Escape') e.preventDefault();
      hide(k === 'Escape');
    } else if (k.length === 1) {
      // Type to jump, as a native list does.
      const now = Date.now();
      typed = now - typedAt < 700 ? typed + k.toLowerCase() : k.toLowerCase();
      typedAt = now;
      const i = options.findIndex((o) => o.label.toLowerCase().startsWith(typed));
      if (i >= 0) moveTo(i);
    }
  }

  $effect(() => {
    if (!open) return;
    // The list is fixed to the screen: move it with the page, close it if the button scrolls away.
    const follow = () => {
      if (!button) return;
      const r = button.getBoundingClientRect();
      if (r.bottom < 0 || r.top > window.innerHeight) hide(false);
      else measure();
    };
    window.addEventListener('scroll', follow, true);
    window.addEventListener('resize', follow);
    return () => {
      window.removeEventListener('scroll', follow, true);
      window.removeEventListener('resize', follow);
    };
  });
</script>

<button
  bind:this={button}
  type="button"
  class="dd"
  class:bare
  class:open
  role="combobox"
  aria-label={label}
  aria-haspopup="listbox"
  aria-expanded={open}
  aria-controls={uid}
  aria-activedescendant={open ? `${uid}-${active}` : undefined}
  onclick={() => (open ? hide() : show())}
  onkeydown={onKey}
>
  {#if icon}<Icon name={icon} size={16} />{:else if current?.icon}<Icon name={current.icon} size={16} />{/if}
  <span class="val">{current?.label ?? ''}</span>
  <span class="chev"><Icon name="chevronDown" size={16} /></span>
</button>

<div
  bind:this={pop}
  popover="auto"
  class="pop"
  class:up={place.up}
  style:left="{place.left}px"
  style:top="{place.top}px"
  style:min-width="{place.width}px"
  style:max-height="{place.max}px"
  ontoggle={(e) => {
    if ((e as ToggleEvent).newState === 'closed') open = false;
  }}
>
  <div id={uid} role="listbox" aria-label={label}>
    {#each options as o, i (o.value)}
      <div
        id="{uid}-{i}"
        data-i={i}
        class="opt"
        class:on={i === active}
        role="option"
        tabindex="-1"
        aria-selected={o.value === value}
        onmousemove={() => (active = i)}
        onclick={() => pick(i)}
        onkeydown={() => {}}
      >
        <span class="tick">{#if o.value === value}<Icon name="checkmark" size={16} />{/if}</span>
        {#if o.icon}<Icon name={o.icon} size={16} />{/if}
        <span class="ol">{o.label}</span>
        {#if o.sub}<span class="os muted">{o.sub}</span>{/if}
      </div>
    {/each}
  </div>
</div>

<style>
  .dd {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 38px;
    min-width: 0;
    max-width: 100%;
    padding: 0 12px 0 14px;
    border: 1px solid var(--border-strong);
    border-radius: 999px;
    background: transparent;
    color: var(--text);
    text-align: left;
    cursor: pointer;
    transition:
      border-color var(--transition),
      background var(--transition),
      box-shadow var(--transition);
  }

  .dd:hover {
    border-color: var(--text-muted);
  }

  .dd.open,
  .dd:focus-visible {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
    outline: none;
  }

  .dd :global(.icon) {
    color: var(--text-muted);
  }

  .dd.bare {
    height: auto;
    padding: 0;
    border: none;
    background: transparent;
    font-weight: 600;
  }

  .dd.bare.open,
  .dd.bare:focus-visible {
    box-shadow: none;
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .val {
    flex: 1 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .chev {
    display: inline-flex;
    transition: transform var(--transition);
  }

  .open .chev {
    transform: rotate(180deg);
  }

  .pop {
    position: fixed;
    inset: auto;
    margin: 0;
    padding: 4px;
    overflow-y: auto;
    border: 1px solid var(--border-strong);
    border-radius: 18px;
    background: var(--surface);
    color: var(--text);
    box-shadow: 0 12px 32px rgb(0 0 0 / 0.16);
    opacity: 0;
    transform: translateY(-4px) scale(0.98);
    transform-origin: top left;
    transition:
      opacity 140ms ease-out,
      transform 140ms ease-out,
      display 140ms allow-discrete,
      overlay 140ms allow-discrete;
  }

  .pop.up {
    translate: 0 -100%;
    transform-origin: bottom left;
  }

  .pop:popover-open {
    opacity: 1;
    transform: none;
  }

  @starting-style {
    .pop:popover-open {
      opacity: 0;
      transform: translateY(-4px) scale(0.98);
    }
  }

  .opt {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 34px;
    padding: 0 10px 0 6px;
    border-radius: 10px;
    cursor: pointer;
    white-space: nowrap;
  }

  .opt.on {
    background: var(--accent-soft);
  }

  .opt :global(.icon) {
    color: var(--text-muted);
  }

  .tick {
    display: inline-flex;
    width: 16px;
    color: var(--accent-ink);
  }

  .tick :global(.icon) {
    color: var(--accent-ink);
  }

  .ol {
    flex: 1 1 auto;
  }

  .os {
    font-size: 12px;
    margin-left: 12px;
  }

  @media (forced-colors: active) {
    .opt.on {
      outline: 2px solid Highlight;
      outline-offset: -2px;
    }
  }
</style>
