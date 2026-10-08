<script lang="ts">
  import Icon from './Icon.svelte';
  import { kindIcon, kindLabel } from '../lib/format';
  import type { DirObject } from '../lib/types';

  let {
    objects,
    value = null,
    placeholder = 'Find an object',
    label,
    onpick,
    find = false,
    width = '260px',
  }: {
    objects: DirObject[];
    value?: DirObject | null;
    placeholder?: string;
    label: string;
    onpick: (o: DirObject) => void;
    /** Marks this box as the page's Ctrl+F search. */
    find?: boolean;
    width?: string;
  } = $props();

  const uid = `op-${Math.random().toString(36).slice(2, 9)}`;
  let query = $state('');
  let open = $state(false);
  let active = $state(0);
  let input: HTMLInputElement | undefined = $state();

  // Lower-cased once; a directory can be large.
  const keys = $derived(objects.map((o) => `${o.name} ${o.display_name ?? ''}`.toLowerCase()));
  const matches = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (q.length < 1) return [];
    const starts: DirObject[] = [];
    const contains: DirObject[] = [];
    for (let i = 0; i < objects.length && starts.length < 10; i++) {
      const k = keys[i];
      if (k.startsWith(q)) starts.push(objects[i]);
      else if (contains.length < 10 && k.includes(q)) contains.push(objects[i]);
    }
    return [...starts, ...contains].slice(0, 10);
  });

  function pick(o: DirObject | undefined) {
    if (!o) return;
    onpick(o);
    query = '';
    open = false;
    input?.blur();
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      open = true;
      const n = matches.length || 1;
      active = (active + (e.key === 'ArrowDown' ? 1 : -1) + n) % n;
    } else if (e.key === 'Enter') {
      e.preventDefault();
      pick(matches[active]);
    } else if (e.key === 'Escape' && query) {
      e.preventDefault();
      e.stopPropagation();
      query = '';
    }
  }
</script>

<div class="picker" style:width>
  <label class="search">
    {#if value && !query}<Icon name={kindIcon(value.kind)} size={16} />{:else}<Icon name="search" size={16} />{/if}
    <input
      bind:this={input}
      type="text"
      data-find={find ? '' : undefined}
      role="combobox"
      aria-label={label}
      aria-expanded={open && matches.length > 0}
      aria-controls={uid}
      aria-autocomplete="list"
      aria-activedescendant={open && matches[active] ? `${uid}-${active}` : undefined}
      placeholder={value?.name ?? placeholder}
      class:has={!!value}
      bind:value={query}
      oninput={() => {
        open = true;
        active = 0;
      }}
      onfocus={() => (open = true)}
      onblur={() => setTimeout(() => (open = false), 120)}
      onkeydown={onKey}
      autocomplete="off"
      spellcheck="false"
    />
  </label>
  {#if open && matches.length}
    <ul class="results" id={uid} role="listbox" aria-label="{label} results">
      {#each matches as m, i (m.id)}
        <li id="{uid}-{i}" role="option" aria-selected={i === active} class:on={i === active}>
          <button tabindex="-1" onmousedown={(e) => e.preventDefault()} onclick={() => pick(m)} onmousemove={() => (active = i)}>
            <span class="ic" class:t0={m.tier0}><Icon name={kindIcon(m.kind)} size={16} /></span>
            <span class="nm">{m.name}{#if m.display_name && m.display_name !== m.name}<span class="muted"> · {m.display_name}</span>{/if}</span>
            <span class="muted small">{kindLabel(m.kind)}</span>
          </button>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .picker {
    position: relative;
    max-width: 100%;
  }

  input.has::placeholder {
    color: var(--text);
    font-weight: 500;
  }

  .results {
    position: absolute;
    z-index: 30;
    top: calc(100% + 4px);
    left: 0;
    min-width: 100%;
    width: max-content;
    max-width: 440px;
    margin: 0;
    padding: 4px;
    list-style: none;
    border: 1px solid var(--border-strong);
    border-radius: 18px;
    background: var(--surface);
    box-shadow: 0 12px 32px rgb(0 0 0 / 0.16);
    animation: dca-rise 140ms ease-out both;
  }

  .results button {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    min-height: 34px;
    padding: 0 8px;
    border: none;
    border-radius: 10px;
    background: none;
    color: var(--text);
    font: inherit;
    text-align: left;
    cursor: pointer;
  }

  .on button {
    background: var(--accent-soft);
  }

  .ic {
    display: inline-flex;
    color: var(--text-muted);
  }

  .ic.t0 {
    color: var(--sev-critical);
  }

  .nm {
    flex: 1 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
