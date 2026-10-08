<script lang="ts">
  import { rowNav } from '../lib/rownav';
  import { VirtualRows } from '../lib/virtual.svelte';
  import { freeze } from '../lib/freeze';
  import { untrack } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Select from '../components/Select.svelte';
  import ContextMenu, { type MenuGroups } from '../components/ContextMenu.svelte';
  import { attr, dn } from '../lib/graph';
  import { compromised } from '../lib/marks.svelte';
  import { copyText, toast } from '../lib/toast.svelte';
  import { date, daysSince, kindIcon, num } from '../lib/format';
  import type { DirObject, Directory } from '../lib/types';
  import type { Go, Route } from './route';

  let {
    directory,
    go,
    initial,
  }: { directory: Directory; go: Go; initial: Extract<Route, { page: 'directory' }> } = $props();

  const KINDS = [
    { kind: 'user', label: 'Users', icon: 'person' },
    { kind: 'computer', label: 'Computers', icon: 'desktop' },
    { kind: 'group', label: 'Groups', icon: 'people' },
    { kind: 'ou', label: 'OUs', icon: 'folder' },
    { kind: 'gpo', label: 'GPOs', icon: 'document' },
    { kind: 'trust', label: 'Trusts', icon: 'link' },
    { kind: 'template', label: 'Templates', icon: 'certificate' },
    { kind: 'role', label: 'Roles', icon: 'personKey' },
    { kind: 'app', label: 'Apps', icon: 'apps' },
  ] as const;

  let source = $state(untrack(() => initial.source ?? directory.sources[0]?.name ?? ''));
  let container = $state<string | null>(untrack(() => initial.container ?? null));
  let kind = $state<string>('user');
  let includeSub = $state(true);
  let query = $state('');
  let ouQuery = $state('');
  const win = new VirtualRows();
  let stateFilter = $state<'all' | 'enabled' | 'disabled'>('all');
  let tier0Only = $state(false);
  let flaggedOnly = $state(false);
  type SortKey = 'name' | 'ou' | 'state' | 'logon' | 'pwd' | 'os' | 'members';
  let sortKey = $state<SortKey>('name');
  let sortDir = $state<1 | -1>(1);
  let menu = $state<{ x: number; y: number; title?: string; groups: MenuGroups } | null>(null);
  let expanded = $state<Set<string>>(new Set());

  const src = $derived(directory.sources.find((s) => s.name === source));
  const inSource = $derived(directory.objects.filter((o) => o.source === source));
  const byId = $derived(new Map(directory.objects.map((o) => [o.id, o])));
  const children = $derived.by(() => {
    const m = new Map<string, DirObject[]>();
    for (const o of inSource) {
      if (!o.parent) continue;
      if (!m.has(o.parent)) m.set(o.parent, []);
      m.get(o.parent)!.push(o);
    }
    return m;
  });
  const isContainer = (o: DirObject) => o.kind === 'ou' || o.kind === 'domain';
  const roots = $derived(inSource.filter((o) => isContainer(o) && (!o.parent || !byId.has(o.parent))));
  const subContainers = (id: string) =>
    (children.get(id) ?? []).filter(isContainer).sort((a, b) => a.name.localeCompare(b.name));

  function descendants(id: string): DirObject[] {
    const out: DirObject[] = [];
    // A loop, not push(...list): an OU can hold more objects than a call takes arguments.
    const stack: DirObject[] = [];
    for (const c of children.get(id) ?? []) stack.push(c);
    while (stack.length) {
      const o = stack.pop()!;
      out.push(o);
      for (const c of children.get(o.id) ?? []) stack.push(c);
    }
    return out;
  }
  /** Objects under each container, counted bottom-up in one pass. */
  const countUnder = $derived.by(() => {
    const m = new Map<string, number>();
    for (const o of inSource) {
      for (let p = o.parent ? byId.get(o.parent) : undefined, guard = 0; p && guard < 64; p = p.parent ? byId.get(p.parent) : undefined, guard++) {
        if (isContainer(p)) m.set(p.id, (m.get(p.id) ?? 0) + 1);
      }
    }
    return m;
  });

  const scope = $derived(
    container ? (includeSub ? descendants(container) : (children.get(container) ?? [])) : inSource,
  );
  const kinds = $derived(KINDS.filter((k) => inSource.some((o) => o.kind === k.kind)));
  $effect(() => {
    if (!kinds.some((k) => k.kind === kind) && kinds[0]) kind = kinds[0].kind;
  });
  // Sorted once per kind and place; the filter then keeps that order.
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
  const ofKind = $derived.by(() => {
    const list = scope.filter(
      (o) =>
        o.kind === kind &&
        (stateFilter === 'all' || (stateFilter === 'enabled' ? o.enabled !== false : o.enabled === false)) &&
        (!tier0Only || o.tier0) &&
        (!flaggedOnly || o.flags.length > 0),
    );
    const t = (s: string | null) => (s ? Date.parse(s) || 0 : 0);
    const key: Record<SortKey, (o: DirObject) => string | number> = {
      name: (o) => o.name,
      ou: (o) => path(o),
      state: (o) => (o.enabled === false ? 1 : 0),
      logon: (o) => t(o.last_logon),
      pwd: (o) => t(o.password_last_set),
      os: (o) => String(o.attributes.operatingSystem ?? ''),
      members: (o) => members.get(o.id) ?? 0,
    };
    const k = key[sortKey];
    return list.sort((a, b) => {
      if (sortKey === 'name' && a.tier0 !== b.tier0) return Number(b.tier0) - Number(a.tier0);
      const x = k(a);
      const y = k(b);
      const c = typeof x === 'number' && typeof y === 'number' ? x - y : collator.compare(String(x), String(y));
      return (c || collator.compare(a.name, b.name)) * sortDir;
    });
  });

  function sortBy(k: SortKey) {
    if (sortKey === k) sortDir = sortDir === 1 ? -1 : 1;
    else {
      sortKey = k;
      sortDir = k === 'logon' || k === 'pwd' || k === 'members' ? -1 : 1;
    }
  }
  const aria = (k: SortKey) => (sortKey === k ? (sortDir === 1 ? 'ascending' : 'descending') : 'none');

  function rowMenu(e: MouseEvent, o: DirObject) {
    e.preventDefault();
    const sid = attr(o, 'objectSid');
    menu = {
      x: e.clientX,
      y: e.clientY,
      title: o.name,
      groups: [
        [
          { label: 'Open details', icon: 'open', run: () => go({ page: 'object', id: o.id }) },
          { label: 'Show in the relationship graph', icon: 'peopleTeam', run: () => go({ page: 'graph', id: o.id }) },
        ],
        [
          compromised.has(o.id)
            ? { label: 'Clear compromised mark', icon: 'flag', run: () => compromised.delete(o.id) }
            : { label: 'Mark as compromised', icon: 'flag', run: () => { compromised.add(o.id); toast(`${o.name} is marked as compromised`); } },
        ],
        {
          title: 'Copy',
          items: [
            { label: 'Name', icon: 'copy', run: () => copyText(o.name, 'Name copied') },
            ...(attr(o, 'distinguishedName') ? [{ label: 'Distinguished name', icon: 'copy' as const, run: () => copyText(dn(o), 'Distinguished name copied') }] : []),
            ...(sid ? [{ label: 'SID', icon: 'copy' as const, run: () => copyText(sid, 'SID copied') }] : []),
          ],
        },
      ],
    };
  }
  // Lower-cased once per list, by position, so a key press is one pass of includes().
  const searchText = $derived(ofKind.map((o) => `${o.name} ${o.display_name ?? ''}`.toLowerCase()));
  /** Positions in ofKind of the last match, so typing on narrows that instead of starting over. */
  let last: { list: DirObject[]; q: string; hits: number[] } | null = null;
  const rows = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return ofKind;
    const from = last && last.list === ofKind && q.startsWith(last.q) ? last.hits : null;
    const hits: number[] = [];
    if (from) {
      for (const i of from) if (searchText[i].includes(q)) hits.push(i);
    } else {
      for (let i = 0; i < searchText.length; i++) if (searchText[i].includes(q)) hits.push(i);
    }
    last = { list: ofKind, q, hits };
    return hits.map((i) => ofKind[i]);
  });
  const members = $derived.by(() => {
    const m = new Map<string, number>();
    for (const e of directory.edges) if (e.kind === 'MemberOf') m.set(e.to, (m.get(e.to) ?? 0) + 1);
    return m;
  });

  function path(o: DirObject): string {
    const parts: string[] = [];
    let p = o.parent ? byId.get(o.parent) : undefined;
    while (p && p.kind === 'ou') {
      parts.unshift(p.name);
      p = p.parent ? byId.get(p.parent) : undefined;
    }
    return parts.join(' · ');
  }

  function dnOf(id: string | null): string {
    if (!id) return src?.name ?? '';
    const parts: string[] = [];
    let p = byId.get(id);
    while (p) {
      parts.push(p.kind === 'ou' ? `OU=${p.name}` : p.kind === 'domain' ? p.name.split('.').map((x) => `DC=${x}`).join(',') : p.name);
      p = p.parent ? byId.get(p.parent) : undefined;
    }
    return parts.join(',');
  }

  function toggle(id: string) {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    expanded = next;
  }

  function choose(id: string | null) {
    container = id;
  }

  const ouMatches = $derived(
    ouQuery.trim()
      ? inSource.filter((o) => o.kind === 'ou' && o.name.toLowerCase().includes(ouQuery.trim().toLowerCase()))
      : [],
  );
  const kindCounts = $derived.by(() => {
    const m = new Map<string, number>();
    for (const o of scope) m.set(o.kind, (m.get(o.kind) ?? 0) + 1);
    return m;
  });
  const kindCount = (k: string) => kindCounts.get(k) ?? 0;

  // Folder cards: the three main kinds of this directory, in lemon, sky and lilac.
  const FOLDER_TONES = ['', 'sky', 'lilac'];
  const folders = $derived.by(() => {
    const order = src?.kind === 'cloud' ? ['user', 'group', 'app', 'role'] : ['user', 'computer', 'group'];
    return order
      .map((k) => KINDS.find((x) => x.kind === k)!)
      .filter((k) => k && kindCount(k.kind) > 0)
      .slice(0, 3)
      .map((k, i) => {
        const list = scope.filter((o) => o.kind === k.kind);
        const enabled = list.filter((o) => o.enabled === true).length;
        const disabled = list.filter((o) => o.enabled === false).length;
        return {
          ...k,
          tone: FOLDER_TONES[i],
          total: list.length,
          enabled,
          disabled,
          tier0: list.filter((o) => o.tier0).length,
          flagged: list.filter((o) => o.flags.length > 0).length,
        };
      });
  });
</script>

{#snippet branch(o: DirObject)}
  {@const subs = subContainers(o.id)}
  {@const open = expanded.has(o.id) || o.kind === 'domain'}
  <li>
    <div class="node" class:active={container === o.id || (o.kind === 'domain' && container === null)}>
      {#if subs.length && o.kind !== 'domain'}
        <button class="twisty" onclick={() => toggle(o.id)} aria-label={open ? 'Collapse' : 'Expand'}><Icon name={open ? 'chevronDown' : 'chevronRight'} size={16} /></button>
      {:else}
        <span class="twisty"></span>
      {/if}
      <button class="pick" onclick={() => choose(o.kind === 'domain' ? null : o.id)}>
        <Icon name={o.kind === 'domain' ? 'building' : open && subs.length ? 'folderOpen' : 'folder'} size={16} />
        <span class="name">{o.name}</span>
        <span class="count">{num(countUnder.get(o.id) ?? 0)}</span>
      </button>
    </div>
    {#if open && subs.length}
      <ul>{#each subs as s (s.id)}{@render branch(s)}{/each}</ul>
    {/if}
  </li>
{/snippet}

{#snippet sorter(k: SortKey, label: string, right = false)}
  <button class="sortbtn" class:right class:on={sortKey === k} onclick={() => sortBy(k)}>
    {label}<span class="arrow" class:down={sortKey === k && sortDir === -1}><Icon name="chevronDown" size={14} /></span>
  </button>
{/snippet}

<div class="layout">
  <aside class="treepane">
    {#if directory.sources.length > 1}
      <div class="seg full" role="group" aria-label="Directory">
        {#each directory.sources as s (s.name)}
          <button class:on={source === s.name} onclick={() => { source = s.name; choose(null); }}>
            <Icon name={s.kind === 'cloud' ? 'cloud' : 'building'} size={16} />{s.kind === 'cloud' ? 'Entra ID' : s.name.split('.')[0]}
          </button>
        {/each}
      </div>
    {/if}
    {#if src?.kind === 'onprem'}
      <label class="search full"><Icon name="search" size={16} /><input type="text" placeholder="Find an OU" aria-label="Find an OU" bind:value={ouQuery} /></label>
    {/if}
    {#if ouMatches.length}
      <ul class="tree">
        {#each ouMatches as o (o.id)}
          <li><div class="node" class:active={container === o.id}><span class="twisty"></span><button class="pick" onclick={() => choose(o.id)}><Icon name="folder" size={16} /><span class="name">{o.name}</span><span class="count muted small">{path(o)}</span></button></div></li>
        {/each}
      </ul>
    {:else if roots.length}
      <ul class="tree">{#each roots as r (r.id)}{@render branch(r)}{/each}</ul>
    {:else}
      <ul class="tree">
        <li><div class="node active"><span class="twisty"></span><button class="pick"><Icon name="cloud" size={16} /><span class="name strong">{source}</span><span class="count">{num(inSource.length)}</span></button></div></li>
      </ul>
    {/if}
  </aside>

  <section class="pane">
    <div class="toolbar" use:freeze>
      <div class="titles">
        <h2>Directory</h2>
        <span class="muted small mono">{dnOf(container)}</span>
      </div>
      <button class="btn" onclick={() => go({ page: 'graph', id: rows[0]?.id })} disabled={!rows.length}><Icon name="peopleTeam" />Open in graph</button>
    </div>

    <div class="content">
      {#if folders.length}
        <div class="folders">
          {#each folders as f (f.kind)}
            <button class="folder {f.tone}" class:on={kind === f.kind} aria-pressed={kind === f.kind} onclick={() => (kind = f.kind)}>
              <span class="tabrow">
                <span class="ftab"><Icon name={f.icon} size={18} />{f.label}</span>
                {#if kind === f.kind}<span class="showing">Showing</span>{/if}
              </span>
              <span class="fbody">
                <span class="fnum num">{num(f.total)}</span>
                <span class="frows">
                  {#if f.enabled || f.disabled}<span><Icon name="checkmarkCircle" size={16} />{num(f.enabled)} enabled, {num(f.disabled)} disabled</span>{/if}
                  <span><Icon name="shieldError" size={16} />{num(f.tier0)} Tier 0</span>
                  <span><Icon name="flag" size={16} />{num(f.flagged)} with flags</span>
                </span>
              </span>
            </button>
          {/each}
        </div>
      {/if}

      <div class="seg kinds" role="group" aria-label="Object kind">
        {#each kinds as k (k.kind)}
          <button class:on={kind === k.kind} aria-pressed={kind === k.kind} onclick={() => (kind = k.kind)}>
            <Icon name={k.icon} size={16} />{k.label}<span class="count">{num(kindCount(k.kind))}</span>
          </button>
        {/each}
      </div>

      <div class="filters">
        <label class="search"><Icon name="search" size={16} /><input type="text" data-find placeholder="Filter by name" aria-label="Filter objects" aria-keyshortcuts="Control+F" bind:value={query} /><span class="kbd" aria-hidden="true">Ctrl F</span></label>
        {#if kind === 'user' || kind === 'computer'}
          <Select
            label="State"
            bind:value={stateFilter}
            options={[
              { value: 'all', label: 'Enabled and disabled' },
              { value: 'enabled', label: 'Enabled only' },
              { value: 'disabled', label: 'Disabled only' },
            ]}
          />
        {/if}
        <label class="check"><input type="checkbox" bind:checked={tier0Only} />Tier 0 only</label>
        <label class="check"><input type="checkbox" bind:checked={flaggedOnly} />With flags</label>
        {#if container}
          <label class="check"><input type="checkbox" bind:checked={includeSub} />Include sub-OUs</label>
        {/if}
        <span class="spacer"></span>
        <span class="muted small" aria-live="polite">Read {date(src?.read_at, true)} · {num(rows.length)} {rows.length === 1 ? 'object' : 'objects'}</span>
      </div>

      <div class="scroll-x">
        <table use:rowNav class="t stick" aria-rowcount={rows.length + 1}>
          <thead>
            <tr aria-rowindex="1">
              <th class="pl" aria-sort={aria('name')}>{@render sorter('name', 'Name')}</th>
              {#if kind === 'user' || kind === 'computer'}
                <th style="width: 170px" aria-sort={aria('ou')}>{@render sorter('ou', 'OU')}</th><th style="width: 110px" aria-sort={aria('state')}>{@render sorter('state', 'State')}</th><th style="width: 120px" aria-sort={aria('logon')}>{@render sorter('logon', 'Last logon')}</th>
                {#if kind === 'user'}<th class="right" style="width: 120px" aria-sort={aria('pwd')}>{@render sorter('pwd', 'Password age', true)}</th>{:else}<th style="width: 200px" aria-sort={aria('os')}>{@render sorter('os', 'Operating system')}</th>{/if}
              {:else if kind === 'group'}
                <th style="width: 170px" aria-sort={aria('ou')}>{@render sorter('ou', 'OU')}</th><th class="right" style="width: 130px" aria-sort={aria('members')}>{@render sorter('members', 'Direct members', true)}</th>
              {:else}
                <th style="width: 220px">Location</th>
              {/if}
              <th class="pr" style="width: 260px">Flags</th>
            </tr>
          </thead>
          <tbody use:win.rows={rows.length}>
            {#if win.start > 0}<tr class="gap" aria-hidden="true"><td colspan="7" style:height="{win.before}px"></td></tr>{/if}
            {#each rows.slice(win.start, win.end) as o, j (o.id)}
              <tr class="row" class:marked={compromised.has(o.id)} data-index={win.start + j} aria-rowindex={win.start + j + 2} onclick={() => go({ page: 'object', id: o.id })} oncontextmenu={(e) => rowMenu(e, o)}>
                <td class="pl">
                  <span class="obj">
                    <span class="otype" class:t0={o.tier0}><Icon name={kindIcon(o.kind)} size={16} /></span>
                    <span><button class="linkbtn plain strong" onclick={(e) => { e.stopPropagation(); go({ page: 'object', id: o.id }); }}>{o.name}</button>
                      {#if o.display_name}<span class="muted small block">{o.display_name}</span>{/if}</span>
                  </span>
                </td>
                {#if kind === 'user' || kind === 'computer'}
                  <td class="small">{path(o)}</td>
                  <td>
                    {#if o.enabled === false}<span class="state neutral"><Icon name="subtractCircle" size={16} />Disabled</span>
                    {:else if o.enabled}<span class="state ok"><Icon name="checkmarkCircle" size={16} />Enabled</span>{/if}
                  </td>
                  <td class="num small">{date(o.last_logon)}</td>
                  {#if kind === 'user'}
                    <td class="right num small">{o.password_last_set ? `${num(daysSince(o.password_last_set, src?.read_at) ?? 0)} days` : ''}</td>
                  {:else}
                    <td class="small">{String(o.attributes.operatingSystem ?? '')}</td>
                  {/if}
                {:else if kind === 'group'}
                  <td class="small">{path(o)}</td>
                  <td class="right num">{num(members.get(o.id) ?? 0)}</td>
                {:else}
                  <td class="small">{path(o) || (o.parent ? byId.get(o.parent)?.name : source)}</td>
                {/if}
                <td class="pr"><span class="flags">{#each o.flags as fl, i (i)}<span class="flag {fl.level}">{fl.text}</span>{/each}</span></td>
              </tr>
            {:else}
              <tr><td colspan="7" class="pl muted">No objects of this kind here.</td></tr>
            {/each}
            {#if win.end < rows.length}<tr class="gap" aria-hidden="true"><td colspan="7" style:height="{win.after(rows.length)}px"></td></tr>{/if}
          </tbody>
        </table>
      </div>
    </div>
  </section>
</div>

<ContextMenu bind:menu />

<style>
  .sortbtn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0;
    border: none;
    background: none;
    color: inherit;
    font: inherit;
    cursor: pointer;
  }

  .sortbtn.right {
    flex-direction: row;
    margin-left: auto;
  }

  .sortbtn .arrow {
    display: inline-flex;
    opacity: 0;
    transform: rotate(180deg);
    transition:
      opacity var(--transition),
      transform var(--transition);
  }

  .sortbtn:hover .arrow {
    opacity: 0.5;
  }

  .sortbtn.on {
    color: var(--text);
  }

  .sortbtn.on .arrow {
    opacity: 1;
  }

  .sortbtn .arrow.down {
    transform: none;
  }

  tr.marked td:first-child {
    box-shadow: inset 3px 0 0 var(--sev-critical);
  }

  .layout {
    display: flex;
    flex: 1 1 auto;
    gap: 18px;
    padding: 8px 28px 28px 8px;
    align-items: flex-start;
  }

  .treepane {
    flex: 0 0 280px;
    position: sticky;
    top: 8px;
    max-height: calc(100vh - 150px);
    border-radius: var(--radius-lg);
    background: var(--surface);
    padding: 16px 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    overflow-y: auto;
  }

  .full {
    width: 100%;
  }

  .seg.full button {
    flex: 1 1 0;
    justify-content: center;
  }

  .tree,
  .tree ul {
    list-style: none;
    margin: 0;
    padding: 0;
    font-size: 13.5px;
  }

  .tree ul {
    padding-left: 16px;
  }

  .node {
    display: flex;
    align-items: center;
    border-radius: 10px;
  }

  .node:hover {
    background: var(--surface-raised);
  }

  .node.active {
    background: var(--accent-soft);
  }

  .node.active .name {
    font-weight: 600;
  }

  .twisty {
    flex: none;
    width: 22px;
    height: 30px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: none;
    background: none;
    padding: 0;
    color: var(--text-muted);
    cursor: pointer;
  }

  .pick {
    flex: 1 1 auto;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 30px;
    padding: 0 8px 0 0;
    border: none;
    background: none;
    color: var(--text);
    font: inherit;
    text-align: left;
    cursor: pointer;
  }

  .pick :global(.icon) {
    color: var(--text-muted);
  }

  .pick .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .pick .count {
    margin-left: auto;
  }

  .pane {
    flex: 1 1 auto;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    padding: 0 0 14px;
  }

  .titles {
    display: flex;
    flex-direction: column;
    gap: 2px;
    flex: 1 1 auto;
    min-width: 0;
  }

  .content {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .folders {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 18px;
  }

  button.folder {
    padding: 0;
    border: none;
    background: none;
    font: inherit;
    text-align: left;
    cursor: pointer;
  }

  button.folder:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 3px;
    border-radius: 26px;
  }

  button.folder .fbody {
    transition: transform var(--transition);
  }

  button.folder:hover .fbody {
    transform: translateY(-1px);
  }

  .showing {
    margin-bottom: 8px;
    padding: 3px 10px;
    border-radius: 999px;
    background: var(--pill);
    color: var(--pill-fg);
    font-size: 12px;
    font-weight: 500;
  }

  .fnum {
    font-size: 44px;
    font-weight: 300;
    line-height: 1;
    letter-spacing: -0.02em;
  }

  .frows {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 13.5px;
  }

  .frows span {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .seg.kinds {
    align-self: flex-start;
    flex-wrap: wrap;
  }

  @media (max-width: 1100px) {
    .folders {
      grid-template-columns: minmax(0, 1fr);
    }
  }

  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
  }

  .check {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }

  .obj {
    display: flex;
    align-items: center;
    gap: 10px;
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

  .row {
    cursor: pointer;
  }

  .t .pl {
    padding-left: 20px;
  }

  .t .pr {
    padding-right: 20px;
  }
</style>
