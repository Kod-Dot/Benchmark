<script lang="ts">
  import { untrack } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Select from '../components/Select.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import GraphCanvas from '../components/GraphCanvas.svelte';
  import ObjectPicker from '../components/ObjectPicker.svelte';
  import ContextMenu, { type MenuGroups } from '../components/ContextMenu.svelte';
  import { date, kindIcon, kindLabel, num } from '../lib/format';
  import {
    attr,
    CATEGORY_LABEL,
    DirGraph,
    dn,
    edgeInfo,
    fixCommand,
    hasUnconstrained,
    isAsRepRoastable,
    isKerberoastable,
    type EdgeCategory,
  } from '../lib/graph';
  import { compromised } from '../lib/marks.svelte';
  import { copyText, toast } from '../lib/toast.svelte';
  import type { DirObject, Directory, Edge, Finding } from '../lib/types';
  import { findingKey, type Go } from './route';

  let {
    directory,
    go,
    focus,
    findings = [],
  }: { directory: Directory; go: Go; focus?: string; findings?: Finding[] } = $props();

  const graph = $derived(new DirGraph(directory));
  const MAX_NODES = 180;
  const MEMBERSHIP = new Set(['MemberOf']);

  // Start from the requested object, else something with a way to Tier 0.
  const defaultFocus = untrack(() => {
    if (focus) return focus;
    const g = new DirGraph(directory);
    const candidates = directory.objects.filter((o) => !o.tier0 && (o.kind === 'group' || o.kind === 'user'));
    return (
      candidates.find((o) => g.outOf(o.id).some((e) => e.kind !== 'MemberOf' && edgeInfo(e.kind).traversable) && g.shortest([o.id], (t) => t.tier0)) ??
      candidates.find((o) => g.shortest([o.id], (t) => t.tier0)) ??
      directory.objects.find((o) => o.tier0 && o.kind === 'group') ??
      directory.objects[0]
    )?.id;
  });

  type Mode = 'overview' | 'paths' | 'neighbours' | 'reaches' | 'reachedBy' | 'between';
  // Opened from an object: paths through it. Opened on its own: the whole
  // picture of what can reach Tier 0.
  const startFocused = untrack(() => !!focus);
  let center = $state<string>(defaultFocus ?? '');
  let selected = $state<string | null>(startFocused ? (defaultFocus ?? null) : null);
  let selectedEdge = $state.raw<Edge | null>(null);
  let mode = $state<Mode>(startFocused ? 'paths' : 'overview');
  let depth = $state<'1' | '2' | '3' | '6'>('2');
  let from = $state<string | null>(null);
  let to = $state<string | null>(null);
  let added = $state.raw<Edge[]>([]);
  let hidden = $state.raw(new Set<string>());
  let pinned = $state.raw(new Set<string>());
  let off = $state.raw(new Set<EdgeCategory>(['structure']));
  let canvas: GraphCanvas | undefined = $state();
  let menu = $state<{ x: number; y: number; title?: string; groups: MenuGroups } | null>(null);
  let showFilter = $state(false);

  const allowed = (e: Edge) => !off.has(edgeInfo(e.kind).category);
  const kinds = $derived(new Set(graph.edges.map((e) => e.kind).filter((k) => !off.has(edgeInfo(k).category))));
  const searchOpts = $derived({ kinds: new Set([...kinds, 'Contains'].filter((k) => edgeInfo(k).traversable)), avoid: hidden });

  // What the chosen view shows, before expansions and hidden objects.
  const base = $derived.by(() => {
    const chosen = new Set<Edge>();
    const add = (list: Edge[] | null | undefined) => list?.forEach((e) => chosen.add(e));
    if (mode === 'between') {
      if (from && to) for (const p of graph.kShortest(from, to, 4, searchOpts)) add(p);
      else if (from) {
        // Until a target is chosen, show what the start reaches to pick from.
        const r = graph.reach(from, 'out', { ...searchOpts, maxDepth: 2 });
        add([...r.values()].filter((v) => v.via).sort((a, b) => a.depth - b.depth).slice(0, MAX_NODES - 1).map((v) => v.via!));
      }
    } else if (mode === 'overview') {
      for (const e of overview.edges) chosen.add(e);
    } else if (mode === 'neighbours') {
      const list = [...graph.outOf(center), ...graph.into(center)].filter(allowed);
      // Rights first, then membership, so a large group does not crowd them out.
      list.sort((a, b) => Number(a.kind === 'MemberOf') - Number(b.kind === 'MemberOf'));
      add(list.slice(0, MAX_NODES - 1));
    } else if (mode === 'reaches' || mode === 'reachedBy') {
      const r = graph.reach(center, mode === 'reaches' ? 'out' : 'in', { ...searchOpts, maxDepth: Number(depth) });
      const byDepth = [...r.values()].filter((v) => v.via).sort((a, b) => a.depth - b.depth);
      add(byDepth.slice(0, MAX_NODES - 1).map((v) => v.via!));
    } else {
      // Paths through the object: who can take it over, and its way to Tier 0.
      add(graph.shortest([center], (o) => o.tier0, searchOpts));
      const r = graph.reach(center, 'in', { ...searchOpts, maxDepth: Number(depth) });
      for (const [id, v] of r) {
        if (!v.via) continue;
        const o = graph.byId.get(id);
        // Every user of a large group adds nothing to the picture.
        if (v.via.kind === 'MemberOf' && o?.kind === 'user' && graph.into(v.via.to, new Set(['MemberOf'])).length > 6) continue;
        chosen.add(v.via);
        if (chosen.size > MAX_NODES) break;
      }
    }
    return [...chosen];
  });

  // Every object with a way to Tier 0, and the shortest way from each.
  const overview = $derived.by(() => {
    const next = graph.towards((o) => o.tier0, searchOpts);
    const starts = directory.objects
      .filter((o) => !o.tier0 && next.get(o.id) && o.kind !== 'ou' && o.kind !== 'domain' && o.kind !== 'gpo')
      .map((o) => ({ o, path: DirGraph.walk(next, o.id) }))
      .sort((a, b) => a.path.length - b.path.length || a.o.name.localeCompare(b.o.name));
    const edges = new Set<Edge>();
    const ids = new Set<string>();
    const entries: { o: DirObject; path: Edge[] }[] = [];
    for (const s of starts) {
      const first = s.path[0];
      // Each user of a large group adds nothing: the group stands for them.
      const crowd = first.kind === 'MemberOf' && s.o.kind === 'user' && graph.into(first.to, MEMBERSHIP).length > 6;
      entries.push(s);
      if (crowd) continue;
      const extra = [s.o.id, ...s.path.map((e) => e.to)].filter((id) => !ids.has(id)).length;
      if (ids.size + extra > MAX_NODES) continue;
      for (const e of s.path) {
        edges.add(e);
        ids.add(e.from);
        ids.add(e.to);
      }
    }
    return { edges, entries };
  });

  const shownEdges = $derived.by(() => {
    const seen = new Set<Edge>();
    const out: Edge[] = [];
    for (const e of [...base, ...added]) {
      if (seen.has(e) || hidden.has(e.from) || hidden.has(e.to)) continue;
      if (!allowed(e) && !added.includes(e) && mode !== 'between' && mode !== 'paths' && mode !== 'overview') continue;
      seen.add(e);
      out.push(e);
    }
    return out;
  });
  const nodeIds = $derived.by(() => {
    const ids = new Set<string>();
    if (mode !== 'between' && mode !== 'overview' && !hidden.has(center)) ids.add(center);
    if (mode === 'between') {
      if (from) ids.add(from);
      if (to) ids.add(to);
    }
    for (const id of pinned) if (!hidden.has(id)) ids.add(id);
    for (const e of shownEdges) {
      ids.add(e.from);
      ids.add(e.to);
    }
    return [...ids].filter((id) => graph.byId.has(id));
  });
  const anchor = $derived(mode === 'between' ? from : mode === 'overview' ? null : center);

  // Emphasise every relationship that leads on to Tier 0, or the found paths.
  const hot = $derived.by(() => {
    if (mode === 'between') {
      const first = from && to ? graph.kShortest(from, to, 1, searchOpts)[0] : null;
      return new Set(first ?? []);
    }
    const ok = new Set(nodeIds.filter((id) => graph.byId.get(id)?.tier0));
    for (let i = 0; i < nodeIds.length; i++) for (const e of shownEdges) if (ok.has(e.to) && edgeInfo(e.kind).traversable) ok.add(e.from);
    return new Set(shownEdges.filter((e) => ok.has(e.to) && !graph.byId.get(e.from)?.tier0 && edgeInfo(e.kind).traversable));
  });

  // A selected relationship that is no longer drawn is no longer selected.
  $effect(() => {
    if (selectedEdge && !shownEdges.includes(selectedEdge)) selectedEdge = null;
  });

  function startAt(id: string, m: Mode = mode === 'between' || mode === 'overview' ? 'paths' : mode) {
    center = id;
    selected = id;
    selectedEdge = null;
    mode = m;
    added = [];
    if (hidden.has(id)) hidden = new Set([...hidden].filter((h) => h !== id));
    canvas?.fit();
  }

  function expand(list: Edge[], what: string) {
    const fresh = list.filter((e) => !shownEdges.includes(e) && !hidden.has(e.from) && !hidden.has(e.to));
    if (!fresh.length) {
      toast(`Nothing more to show for ${what}`);
      return;
    }
    const room = Math.max(0, MAX_NODES - nodeIds.length);
    added = [...added, ...fresh.slice(0, room)];
    if (fresh.length > room) toast(`Showing ${num(room)} of ${num(fresh.length)}: the graph is full`);
  }

  function hide(id: string) {
    hidden = new Set([...hidden, id]);
    if (selected === id) selected = null;
  }

  function toggleSet(set: Set<string>, id: string) {
    const next = new Set(set);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
  }

  function reset() {
    added = [];
    hidden = new Set();
    pinned = new Set();
    canvas?.fit();
  }

  // ---------- Selected object ----------
  const sel = $derived(selected ? graph.byId.get(selected) : undefined);
  const rel = $derived.by(() => {
    if (!sel) return null;
    const id = sel.id;
    const outE = graph.outOf(id);
    const inE = graph.into(id);
    return {
      memberOf: outE.filter((e) => e.kind === 'MemberOf'),
      nestedOf: graph.memberOf(id).filter((m) => m.via),
      members: inE.filter((e) => e.kind === 'MemberOf'),
      allMembers: sel.kind === 'group' ? graph.members(id) : [],
      controls: outE.filter((e) => !MEMBERSHIP.has(e.kind) && e.kind !== 'HasSession' && e.kind !== 'Contains' && edgeInfo(e.kind).category !== 'cloud'),
      inherited: graph
        .memberOf(id)
        .flatMap((m) => graph.outOf(m.group.id).filter((e) => !MEMBERSHIP.has(e.kind) && e.kind !== 'Contains' && e.kind !== 'HasSession').map((e) => ({ e, via: m.group }))),
      controlledBy: inE.filter((e) => !MEMBERSHIP.has(e.kind) && e.kind !== 'HasSession' && e.kind !== 'Contains' && edgeInfo(e.kind).category !== 'cloud'),
      sessions: [...outE, ...inE].filter((e) => e.kind === 'HasSession'),
      cloud: [...outE, ...inE].filter((e) => edgeInfo(e.kind).category === 'cloud' && e.kind !== 'MemberOf'),
      contains: outE.filter((e) => e.kind === 'Contains'),
    };
  });
  const selPath = $derived(sel && !sel.tier0 ? (graph.shortest([sel.id], (o) => o.tier0, searchOpts) ?? []) : []);
  const selFindings = $derived(sel ? findings.filter((f) => f.status === 'failed' && f.affected.some((a) => a.object === sel.id)) : []);
  const traits = $derived.by(() => {
    if (!sel) return [];
    const t: { text: string; level: string }[] = [];
    if (sel.tier0) t.push({ text: 'Tier 0', level: 'crit' });
    if (compromised.has(sel.id)) t.push({ text: 'Marked compromised', level: 'crit' });
    if (sel.enabled === false) t.push({ text: 'Disabled', level: 'info' });
    if (isKerberoastable(sel)) t.push({ text: 'Kerberoastable', level: 'warn' });
    if (isAsRepRoastable(sel)) t.push({ text: 'AS-REP roastable', level: 'warn' });
    if (hasUnconstrained(sel) && !sel.tier0) t.push({ text: 'Unconstrained delegation', level: 'warn' });
    for (const f of sel.flags) if (!t.some((x) => x.text === f.text)) t.push(f);
    return t;
  });
  const facts = $derived.by(() => {
    if (!sel) return [];
    const rows: [string, string][] = [];
    const push = (k: string, v: string | undefined | null) => v && rows.push([k, v]);
    push('Distinguished name', attr(sel, 'distinguishedName'));
    push('Sign-in name', attr(sel, 'userPrincipalName') ?? attr(sel, 'sAMAccountName'));
    push('SID', attr(sel, 'objectSid'));
    push('Operating system', attr(sel, 'operatingSystem'));
    push('Last sign-in', sel.last_logon ? date(sel.last_logon) : null);
    push('Password set', sel.password_last_set ? date(sel.password_last_set) : null);
    push('Service names', attr(sel, 'servicePrincipalName'));
    push('Delegates to', attr(sel, 'msDS-AllowedToDelegateTo'));
    push('Description', attr(sel, 'description'));
    return rows;
  });

  // Collapsible relationship lists
  let openLists = $state<Record<string, boolean>>({ controls: true, controlledBy: true, memberOf: true, members: false });

  // ---------- Selected relationship ----------
  const edgeFrom = $derived(selectedEdge ? graph.byId.get(selectedEdge.from) : undefined);
  const edgeTo = $derived(selectedEdge ? graph.byId.get(selectedEdge.to) : undefined);
  const edgeFix = $derived(selectedEdge ? fixCommand(selectedEdge, edgeFrom, edgeTo) : null);
  const edgeCheck = $derived(selectedEdge ? edgeInfo(selectedEdge.kind).check : undefined);
  const edgeFinding = $derived(edgeCheck ? findings.find((f) => f.id === edgeCheck && f.status === 'failed') : undefined);

  // ---------- Context menu ----------
  function nodeMenu(id: string, x: number, y: number) {
    const o = graph.byId.get(id);
    if (!o) return;
    const outE = graph.outOf(id);
    const inE = graph.into(id);
    const cnt = (n: number) => (n ? num(n) : '');
    const memberOf = outE.filter((e) => e.kind === 'MemberOf');
    const members = inE.filter((e) => e.kind === 'MemberOf');
    const controls = outE.filter((e) => e.kind !== 'MemberOf' && e.kind !== 'Contains');
    const controlledBy = inE.filter((e) => e.kind !== 'MemberOf' && e.kind !== 'Contains');
    const contains = outE.filter((e) => e.kind === 'Contains');
    const rights = outE.filter((e) => fixCommand(e, o, graph.byId.get(e.to)));
    menu = {
      x,
      y,
      title: o.name,
      groups: [
        {
          title: 'Show',
          items: [
            { label: 'Start the graph here', icon: 'target', run: () => startAt(id, 'paths') },
            { label: 'What it can reach', icon: 'arrowRight', run: () => startAt(id, 'reaches') },
            { label: 'What can reach it', icon: 'arrowLeft', run: () => startAt(id, 'reachedBy') },
            { label: 'Paths from here to…', icon: 'arrowRouting', hint: 'then pick a target', run: () => { mode = 'between'; from = id; if (to === id) to = null; } },
            ...(from && from !== id ? [{ label: `Paths from ${graph.byId.get(from)?.name} to here`, icon: 'arrowRouting' as const, run: () => { mode = 'between'; to = id; } }] : []),
          ],
        },
        {
          title: 'Expand',
          items: [
            { label: 'Members', icon: 'people', hint: cnt(members.length), disabled: !members.length, run: () => expand(members, 'members') },
            { label: 'Member of', icon: 'peopleTeam', hint: cnt(memberOf.length), disabled: !memberOf.length, run: () => expand(memberOf, 'member of') },
            { label: 'Controls', icon: 'key', hint: cnt(controls.length), disabled: !controls.length, run: () => expand(controls, 'controls') },
            { label: 'Controlled by', icon: 'shieldError', hint: cnt(controlledBy.length), disabled: !controlledBy.length, run: () => expand(controlledBy, 'controlled by') },
            ...(contains.length ? [{ label: 'Contents', icon: 'folderOpen' as const, hint: cnt(contains.length), run: () => expand(contains, 'contents') }] : []),
          ],
        },
        {
          title: 'Mark',
          items: [
            compromised.has(id)
              ? { label: 'Clear compromised mark', icon: 'flag', run: () => compromised.delete(id) }
              : { label: 'Mark as compromised', icon: 'flag', run: () => { compromised.add(id); toast(`${o.name} is marked; Attack paths can start from it`); } },
            { label: pinned.has(id) ? 'Unpin' : 'Pin to the graph', icon: 'pin', run: () => (pinned = toggleSet(pinned, id)) },
            { label: 'Hide from the graph', icon: 'eyeOff', disabled: id === anchor, run: () => hide(id) },
          ],
        },
        {
          title: 'Copy',
          items: [
            { label: 'Name', icon: 'copy', run: () => copyText(o.name, 'Name copied') },
            ...(attr(o, 'distinguishedName') ? [{ label: 'Distinguished name', icon: 'copy' as const, run: () => copyText(dn(o), 'Distinguished name copied') }] : []),
            ...(attr(o, 'objectSid') ? [{ label: 'SID', icon: 'copy' as const, run: () => copyText(attr(o, 'objectSid')!, 'SID copied') }] : []),
            ...(rights.length
              ? [{ label: 'Commands to remove its rights', icon: 'copy' as const, hint: cnt(rights.length), run: () => copyText(fixScript(rights), 'Commands copied: review them before running') }]
              : []),
          ],
        },
        [{ label: 'Open details', icon: 'open', hint: 'Ctrl Enter', run: () => go({ page: 'object', id }) }],
      ],
    };
  }

  function edgeMenu(e: Edge, x: number, y: number) {
    const a = graph.byId.get(e.from);
    const b = graph.byId.get(e.to);
    const info = edgeInfo(e.kind);
    const fix = fixCommand(e, a, b);
    menu = {
      x,
      y,
      title: `${a?.name} · ${info.label} · ${b?.name}`,
      groups: [
        [
          { label: 'What this allows', icon: 'info', run: () => (selectedEdge = e) },
          { label: 'Copy the command to remove it', icon: 'copy', disabled: !fix, run: () => fix && copyText(fix, 'Command copied: review it before running') },
        ],
        [
          { label: `Hide ${CATEGORY_LABEL[info.category].toLowerCase()}`, icon: 'eyeOff', run: () => (off = new Set([...off, info.category])) },
          { label: `Open ${a?.name}`, icon: 'open', run: () => go({ page: 'object', id: e.from }) },
          { label: `Open ${b?.name}`, icon: 'open', run: () => go({ page: 'object', id: e.to }) },
        ],
      ],
    };
  }

  function fixScript(list: Edge[]) {
    const head = '# Generated by Benchmark from a read-only assessment. Review every command before running it.\n';
    return head + list.map((e) => `\n# ${graph.byId.get(e.from)?.name} · ${edgeInfo(e.kind).label} · ${graph.byId.get(e.to)?.name}\n${fixCommand(e, graph.byId.get(e.from), graph.byId.get(e.to))}`).join('\n');
  }

  function onContext(at: { x: number; y: number; id?: string; edge?: Edge }) {
    if (at.id) nodeMenu(at.id, at.x, at.y);
    else if (at.edge) edgeMenu(at.edge, at.x, at.y);
  }

  function focusOn(id: string, via?: Edge) {
    if (via && !shownEdges.includes(via)) expand([via], 'this relationship');
    else if (!nodeIds.includes(id)) pinned = new Set([...pinned, id]);
    selected = id;
    selectedEdge = null;
    requestAnimationFrame(() => canvas?.reveal(id));
  }

  const categories = $derived(
    (Object.keys(CATEGORY_LABEL) as EdgeCategory[]).filter((c) => graph.edges.some((e) => edgeInfo(e.kind).category === c)),
  );
  const objects = $derived(directory.objects);
  const plural = (n: number, one: string, many: string) => `${num(n)} ${n === 1 ? one : many}`;

  // Why the view is empty, so an empty canvas never looks broken.
  const emptyNote = $derived.by(() => {
    if (shownEdges.length || mode === 'between') return null;
    const name = graph.byId.get(center)?.name ?? 'This object';
    const steps = plural(Number(depth), 'step', 'steps');
    if (mode === 'overview') return 'Nothing in this assessment can reach Tier 0 through the relationships shown.';
    if (mode === 'neighbours') return `${name} has no relationships of the kinds shown.`;
    if (mode === 'reaches') return `${name} reaches nothing within ${steps} through the relationships shown.`;
    if (mode === 'reachedBy') return `Nothing reaches ${name} within ${steps} through the relationships shown.`;
    return `${name} has no way to Tier 0, and nothing reaches it within ${steps}.`;
  });
  const modeOptions: { value: Mode; label: string }[] = [
    { value: 'overview', label: 'Everything that reaches Tier 0' },
    { value: 'paths', label: 'Paths to Tier 0' },
    { value: 'neighbours', label: 'Neighbours' },
    { value: 'reaches', label: 'What it reaches' },
    { value: 'reachedBy', label: 'What reaches it' },
    { value: 'between', label: 'Path between two' },
  ];
</script>

{#snippet item(e: Edge, other: string, note?: string)}
  {@const o = graph.byId.get(other)}
  {#if o}
    <li>
      <button class="ri" onclick={() => focusOn(other, e)} oncontextmenu={(ev) => { ev.preventDefault(); nodeMenu(other, ev.clientX, ev.clientY); }}>
        <span class="otype sm" class:t0={o.tier0}><Icon name={kindIcon(o.kind)} size={14} /></span>
        <span class="rn">{o.name}</span>
        <span class="rk">{note ?? edgeInfo(e.kind).label}</span>
      </button>
    </li>
  {/if}
{/snippet}

{#snippet list(key: string, title: string, edges: Edge[], side: 'to' | 'from', icon: import('../lib/icons').IconName, empty: string)}
  <section class="rl">
    <button class="rh" aria-expanded={!!openLists[key]} onclick={() => (openLists = { ...openLists, [key]: !openLists[key] })}>
      <Icon name={openLists[key] ? 'chevronDown' : 'chevronRight'} size={16} />
      <Icon name={icon} size={16} />
      <span>{title}</span>
      <span class="count">{num(edges.length)}</span>
    </button>
    {#if openLists[key]}
      {#if edges.length}
        <ul class="ritems">
          {#each edges.slice(0, 50) as e, i (i)}{@render item(e, side === 'to' ? e.to : e.from)}{/each}
        </ul>
        <div class="rfoot">
          {#if edges.length > 50}<span class="muted small">First 50 of {num(edges.length)}</span>{/if}
          <button class="linkbtn small" onclick={() => expand(edges, title.toLowerCase())}>Show all in the graph</button>
        </div>
      {:else}
        <p class="muted small rempty">{empty}</p>
      {/if}
    {/if}
  </section>
{/snippet}

<div class="toolbar">
  <h2>Relationship graph</h2>
  {#if mode === 'between'}
    <ObjectPicker {objects} label="From" placeholder="From…" value={from ? graph.byId.get(from) : null} onpick={(o) => (from = o.id)} find width="220px" />
    <button class="btn sm ghost" aria-label="Swap" onclick={() => ([from, to] = [to, from])}><Icon name="arrowSwap" size={16} /></button>
    <ObjectPicker {objects} label="To" placeholder="To… (for example Domain Admins)" value={to ? graph.byId.get(to) : null} onpick={(o) => (to = o.id)} width="220px" />
  {:else}
    <ObjectPicker {objects} label="Start from" placeholder="Start from an object…" value={mode === 'overview' ? null : graph.byId.get(center)} onpick={(o) => startAt(o.id)} find />
  {/if}
  <Select label="Show" icon="branch" bind:value={mode} options={modeOptions} onchange={() => { added = []; canvas?.fit(); }} />
  {#if mode !== 'between' && mode !== 'neighbours' && mode !== 'overview'}
    <Select
      label="Depth"
      bind:value={depth}
      options={[
        { value: '1', label: '1 step' },
        { value: '2', label: '2 steps' },
        { value: '3', label: '3 steps' },
        { value: '6', label: '6 steps' },
      ]}
    />
  {/if}
  <span class="spacer"></span>
  <div class="filter">
    <button class="btn" aria-expanded={showFilter} onclick={() => (showFilter = !showFilter)}>
      <Icon name="filter" size={16} />Relationships{#if off.size > 1 || !off.has('structure')}<span class="count">{num(categories.filter((c) => !off.has(c)).length)} of {num(categories.length)}</span>{/if}
    </button>
    {#if showFilter}
      <div class="fpop" role="group" aria-label="Relationships to show">
        {#each categories as c (c)}
          <label class="fchk"><input type="checkbox" checked={!off.has(c)} onchange={() => { const n = new Set(off); if (n.has(c)) n.delete(c); else n.add(c); off = n; }} />{CATEGORY_LABEL[c]}</label>
        {/each}
        <div class="ffoot">
          <button class="linkbtn small" onclick={() => (off = new Set())}>Show all</button>
          <button class="linkbtn small" onclick={() => (showFilter = false)}>Done</button>
        </div>
      </div>
    {/if}
  </div>
  {#if added.length || hidden.size || pinned.size}
    <button class="btn" onclick={reset}><Icon name="arrowSync" size={16} />Reset</button>
  {/if}
</div>

<div class="split">
  <div class="graphwrap">
    {#if mode === 'between' && !from}
      <div class="hint enter">
        <Icon name="arrowRouting" size={28} />
        <p><strong>Find the shortest ways from one object to another.</strong></p>
        <p class="muted small">Pick a starting object and a target above, or right-click any object in the graph and choose “Paths from here to…”.</p>
      </div>
    {:else if mode === 'between' && to && !shownEdges.length}
      <div class="hint enter">
        <Icon name="shieldCheckmark" size={28} />
        <p><strong>No path from {graph.byId.get(from ?? '')?.name} to {graph.byId.get(to ?? '')?.name}.</strong></p>
        <p class="muted small">None of the collected relationships of the kinds shown connect them.</p>
      </div>
    {:else}
      <GraphCanvas
        bind:this={canvas}
        {graph}
        {nodeIds}
        edges={shownEdges}
        {anchor}
        bind:selected
        bind:selectedEdge
        {hot}
        marked={compromised}
        {pinned}
        onopen={(id) => startAt(id)}
        oncontext={onContext}
      />
      {#if mode === 'between' && !to}
        <p class="banner enter" role="status"><Icon name="arrowRouting" size={16} />Now pick a target above, or right-click an object here and choose “Paths from {graph.byId.get(from ?? '')?.name} to here”.</p>
      {:else if emptyNote}
        <p class="banner enter" role="status">
          <Icon name="info" size={16} />{emptyNote}
          {#if mode !== 'overview'}<button class="linkbtn small" onclick={() => { mode = 'overview'; selected = null; added = []; canvas?.fit(); }}>Show everything that reaches Tier 0</button>{/if}
        </p>
      {/if}
    {/if}
    <div class="tools" role="group" aria-label="View">
      <button onclick={() => canvas?.zoom(1.25)} aria-label="Zoom in" title="Zoom in"><Icon name="zoomIn" size={16} /></button>
      <button onclick={() => canvas?.zoom(0.8)} aria-label="Zoom out" title="Zoom out"><Icon name="zoomOut" size={16} /></button>
      <button onclick={() => canvas?.fit()} aria-label="Fit to view" title="Fit to view"><Icon name="zoomFit" size={16} /></button>
    </div>
    <div class="legend small">
      <span><i class="hotline"></i>Leads to Tier 0</span>
      <span><i class="line"></i>Relationship</span>
      <span><i class="dash"></i>Derived from attributes</span>
      <span class="muted">{plural(nodeIds.length, 'object', 'objects')} · {plural(shownEdges.length, 'relationship', 'relationships')} · right-click for actions</span>
    </div>
  </div>

  <aside class="side">
    {#if selectedEdge && edgeFrom && edgeTo}
      {@const info = edgeInfo(selectedEdge.kind)}
      <section class="enter">
        <span class="muted small">{CATEGORY_LABEL[info.category]}</span>
        <h4 class="et">{info.label}</h4>
        <div class="ends">
          <button class="end" onclick={() => focusOn(edgeFrom.id)}><span class="otype" class:t0={edgeFrom.tier0}><Icon name={kindIcon(edgeFrom.kind)} size={16} /></span>{edgeFrom.name}</button>
          <Icon name="arrowRight" size={16} />
          <button class="end" onclick={() => focusOn(edgeTo.id)}><span class="otype" class:t0={edgeTo.tier0}><Icon name={kindIcon(edgeTo.kind)} size={16} /></span>{edgeTo.name}</button>
        </div>
      </section>
      <section>
        <h3>What this allows</h3>
        <p class="small">{info.allows}</p>
        {#if graph.derived.has(selectedEdge)}<p class="muted small">Derived from {selectedEdge.kind === 'Contains' ? 'where the object sits in the directory' : `the object's attributes${selectedEdge.note ? ` (${selectedEdge.note})` : ''}`}.</p>
        {:else if selectedEdge.note}<p class="muted small">{selectedEdge.note}</p>{/if}
        {#if !info.traversable}<p class="muted small">On its own this does not give control, so attack paths do not follow it.</p>{/if}
      </section>
      {#if edgeFinding}
        <section>
          <h3>Finding</h3>
          <button class="frow" onclick={() => go({ page: 'finding', key: findingKey(edgeFinding) })}><SevBadge severity={edgeFinding.severity} /><span>{edgeFinding.title}</span></button>
        </section>
      {/if}
      <section>
        <h3>How to remove it</h3>
        {#if edgeFix}
          <pre class="codeblock">{edgeFix}</pre>
          <div class="row">
            <button class="btn sm" onclick={() => copyText(edgeFix, 'Command copied: review it before running')}><Icon name="copy" size={16} />Copy command</button>
          </div>
          <p class="muted small">Benchmark never changes the directory. Review the command, confirm the right is not needed, and run it yourself.</p>
        {:else}
          <p class="small muted">Remove the {info.label.toLowerCase()} relationship where it is managed{selectedEdge.kind === 'Contains' ? ': move the object, or remove the inheritable permission on the container' : ''}.</p>
        {/if}
      </section>
    {:else if sel && rel}
      {#key sel.id}
        <section class="enter">
          <div class="head">
            <span class="otype lg" class:t0={sel.tier0}><Icon name={kindIcon(sel.kind)} size={20} /></span>
            <div class="hn">
              <h4>{sel.name}</h4>
              <span class="muted small">{kindLabel(sel.kind)} · {sel.source}</span>
            </div>
            <button class="btn sm ghost" aria-label="More actions" onclick={(e) => { const r = (e.currentTarget as HTMLElement).getBoundingClientRect(); nodeMenu(sel.id, r.left - 180, r.bottom + 4); }}><Icon name="moreHorizontal" size={16} /></button>
          </div>
          {#if sel.display_name && sel.display_name !== sel.name}<p class="small">{sel.display_name}</p>{/if}
          {#if traits.length}<div class="flags">{#each traits as t, i (i)}<span class="flag {t.level}">{t.text}</span>{/each}</div>{/if}
          <div class="row">
            <button class="btn sm" onclick={() => go({ page: 'object', id: sel.id })}><Icon name="open" size={16} />Details</button>
            {#if sel.id !== center || mode === 'between' || mode === 'overview'}<button class="btn sm" onclick={() => startAt(sel.id, 'paths')}><Icon name="target" size={16} />Start here</button>{/if}
            {#if mode === 'between' && from && sel.id !== from && sel.id !== to}<button class="btn sm" onclick={() => (to = sel.id)}><Icon name="arrowRouting" size={16} />Paths to here</button>{/if}
          </div>
        </section>

        <section>
          <h3>Path to Tier 0</h3>
          {#if sel.tier0}
            <p class="small">This object is Tier 0: whoever controls it controls the domain or tenant.</p>
          {:else if selPath.length}
            <ol class="chain">
              <li><button class="step" onclick={() => focusOn(sel.id)}><Icon name={kindIcon(sel.kind)} size={14} />{sel.name}</button></li>
              {#each selPath as e, i (i)}
                {@const t = graph.byId.get(e.to)}
                <li class="via">{edgeInfo(e.kind).label}</li>
                <li><button class="step" class:t0={t?.tier0} onclick={() => focusOn(e.to, e)}><Icon name={kindIcon(t?.kind ?? '')} size={14} />{t?.name}</button></li>
              {/each}
            </ol>
            <div class="row">
              <span class="muted small">{selPath.length} {selPath.length === 1 ? 'step' : 'steps'}</span>
              <button class="linkbtn small" onclick={() => expand(selPath, 'this path')}>Show in the graph</button>
              <button class="linkbtn small" onclick={() => copyText(fixScript(selPath.filter((e) => fixCommand(e, graph.byId.get(e.from), graph.byId.get(e.to)))), 'Commands copied: review them before running')}>Copy fix commands</button>
            </div>
          {:else}
            <p class="small muted">No path to Tier 0 through the relationships shown.</p>
          {/if}
        </section>

        <section class="lists">
          {@render list('controls', 'Controls', rel.controls, 'to', 'key', 'Holds no rights over other objects directly.')}
          {#if rel.inherited.length}
            <section class="rl">
              <button class="rh" aria-expanded={!!openLists.inherited} onclick={() => (openLists = { ...openLists, inherited: !openLists.inherited })}>
                <Icon name={openLists.inherited ? 'chevronDown' : 'chevronRight'} size={16} /><Icon name="peopleTeam" size={16} /><span>Rights through its groups</span><span class="count">{num(rel.inherited.length)}</span>
              </button>
              {#if openLists.inherited}
                <ul class="ritems">{#each rel.inherited.slice(0, 50) as r, i (i)}{@render item(r.e, r.e.to, `${edgeInfo(r.e.kind).label} via ${r.via.name}`)}{/each}</ul>
              {/if}
            </section>
          {/if}
          {@render list('controlledBy', 'Controlled by', rel.controlledBy, 'from', 'shieldError', 'No one holds rights over it beyond the defaults read.')}
          {@render list('memberOf', 'Member of', rel.memberOf, 'to', 'peopleTeam', 'Not a member of any group read.')}
          {#if rel.nestedOf.length}<p class="muted small nest">Also a member of {num(rel.nestedOf.length)} {rel.nestedOf.length === 1 ? 'group' : 'groups'} through nesting.</p>{/if}
          {#if sel.kind === 'group' || rel.members.length}
            {@render list('members', 'Members', rel.members, 'from', 'people', 'The group has no members.')}
            {#if rel.allMembers.length > rel.members.length}<p class="muted small nest">{num(rel.allMembers.length)} members in total, counting nested groups.</p>{/if}
          {/if}
          {#if rel.sessions.length}{@render list('sessions', 'Sessions', rel.sessions, sel.kind === 'computer' ? 'to' : 'from', 'desktop', '')}{/if}
          {#if rel.cloud.length}{@render list('cloud', 'Cloud and hybrid', rel.cloud, 'to', 'cloud', '')}{/if}
          {#if rel.contains.length}{@render list('contains', 'Contains', rel.contains, 'to', 'folderOpen', '')}{/if}
        </section>

        {#if selFindings.length}
          <section>
            <h3>Findings <span class="count">{num(selFindings.length)}</span></h3>
            {#each selFindings.slice(0, 6) as f (findingKey(f))}
              <button class="frow" onclick={() => go({ page: 'finding', key: findingKey(f) })}><SevBadge severity={f.severity} /><span>{f.title}</span></button>
            {/each}
          </section>
        {/if}

        {#if facts.length}
          <section>
            <h3>Attributes</h3>
            <dl class="kv tight wrap">
              {#each facts as [k, v] (k)}<dt>{k}</dt><dd class:mono={k !== 'Description' && k !== 'Operating system'} class="small">{v}</dd>{/each}
            </dl>
          </section>
        {/if}
      {/key}
    {:else if mode === 'overview' && overview.entries.length}
      <section class="enter">
        <h3>What can reach Tier 0 <span class="count">{num(overview.entries.length)}</span></h3>
        <p class="small muted">Objects outside Tier 0 with a way to take it over, shortest first. Select one to see its path; double-click an object in the graph to start from it.</p>
      </section>
      <section class="lists">
        <ul class="ritems flat">
          {#each overview.entries.slice(0, 80) as en (en.o.id)}
            <li>
              <button class="ri" onclick={() => focusOn(en.o.id)} oncontextmenu={(ev) => { ev.preventDefault(); nodeMenu(en.o.id, ev.clientX, ev.clientY); }}>
                <span class="otype sm"><Icon name={kindIcon(en.o.kind)} size={14} /></span>
                <span class="rn">{en.o.name}</span>
                <span class="rk">{plural(en.path.length, 'step', 'steps')}</span>
              </button>
            </li>
          {/each}
        </ul>
        {#if overview.entries.length > 80}<p class="muted small nest">First 80 of {num(overview.entries.length)}</p>{/if}
      </section>
    {:else}
      <section class="enter">
        <h3>Nothing selected</h3>
        <p class="small muted">Select an object or a relationship to see what it means. Double-click an object to start the graph from it; right-click for every action.</p>
      </section>
    {/if}
  </aside>
</div>

<ContextMenu bind:menu />

<style>
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    padding: 12px 28px 14px 8px;
  }

  .toolbar h2 {
    margin-right: 8px;
  }

  .filter {
    position: relative;
  }

  .fpop {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 30;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 260px;
    padding: 8px;
    border: none;
    border-radius: var(--radius-md);
    background: var(--surface-raised);
    box-shadow: var(--shadow-pop);
    animation: dca-rise 140ms ease-out both;
  }

  .fchk {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 34px;
    padding: 0 10px;
    border-radius: var(--radius);
    cursor: pointer;
  }

  .fchk:hover {
    background: var(--surface-alt);
  }

  .ffoot {
    display: flex;
    justify-content: space-between;
    padding: 6px 8px 2px;
    border-top: 1px solid var(--border);
    margin-top: 4px;
  }

  .split {
    flex: 1 1 auto;
    min-height: 520px;
    display: flex;
    gap: 18px;
    padding: 0 28px 20px 8px;
  }

  .graphwrap {
    position: relative;
    flex: 1 1 auto;
    min-width: 0;
    display: flex;
    flex-direction: column;
    border-radius: var(--radius-lg);
    background: var(--surface);
    overflow: hidden;
  }

  .hint {
    margin: auto;
    max-width: 380px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    text-align: center;
    color: var(--text-muted);
  }

  .hint p {
    color: var(--text);
  }

  .banner {
    position: absolute;
    top: 14px;
    left: 50%;
    transform: translateX(-50%);
    z-index: 2;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: center;
    gap: 6px 10px;
    width: max-content;
    max-width: calc(100% - 140px);
    margin: 0;
    padding: 8px 18px;
    border-radius: var(--radius-item);
    background: var(--surface-raised);
    box-shadow: 0 6px 18px -10px rgb(0 0 0 / 0.35);
    font-size: 13px;
    text-align: center;
  }

  .banner :global(.icon) {
    color: var(--accent-ink);
  }

  .ritems.flat {
    padding-left: 0;
  }

  .tools {
    position: absolute;
    top: 14px;
    right: 14px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .tools button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border: none;
    border-radius: 50%;
    background: var(--surface-raised);
    color: var(--text);
    cursor: pointer;
    box-shadow: 0 4px 14px -8px rgb(0 0 0 / 0.3);
  }

  .tools button:hover {
    background: var(--rail-hover);
  }

  .legend {
    position: absolute;
    left: 14px;
    bottom: 14px;
    display: flex;
    flex-wrap: wrap;
    gap: 6px 16px;
    align-items: center;
    max-width: calc(100% - 220px);
    padding: 6px 14px;
    border: none;
    border-radius: 999px;
    background: color-mix(in srgb, var(--surface-raised) 92%, transparent);
    pointer-events: none;
  }

  .legend span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .legend i {
    display: inline-block;
    width: 18px;
    height: 0;
    border-top: 2px solid var(--border-strong);
  }

  .legend .hotline {
    border-top-color: var(--sev-critical);
    border-top-width: 2.5px;
  }

  .legend .dash {
    border-top-style: dashed;
  }

  .side {
    flex: 0 0 360px;
    border-radius: var(--radius-lg);
    background: var(--surface);
    overflow-y: auto;
  }

  .side section {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .side h3 {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .head {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .hn {
    flex: 1 1 auto;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .hn h4 {
    margin: 0;
    font-size: 16px;
    overflow-wrap: anywhere;
  }

  .otype.lg {
    width: 40px;
    height: 40px;
    border-radius: 10px;
  }

  .otype.sm {
    width: 24px;
    height: 24px;
  }

  .flags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 12px;
  }

  .chain {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .chain .via {
    margin-left: 13px;
    padding: 2px 0 2px 16px;
    border-left: 2px solid var(--sev-critical-soft);
    font-size: 12px;
    color: var(--sev-critical);
  }

  .step {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    max-width: 100%;
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface);
    color: var(--text);
    font: inherit;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: border-color var(--transition), background var(--transition);
  }

  .step:hover {
    border-color: var(--text-muted);
    background: var(--surface-alt);
  }

  .step.t0 {
    border-color: var(--sev-critical);
    color: var(--sev-critical);
  }

  .lists {
    padding: 8px 12px !important;
    gap: 0 !important;
  }

  .rl {
    padding: 0 !important;
    border: none !important;
    gap: 0 !important;
  }

  .rh {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    min-height: 36px;
    padding: 0 8px;
    border: none;
    border-radius: 6px;
    background: none;
    color: var(--text);
    font: inherit;
    font-weight: 600;
    font-size: 13.5px;
    text-align: left;
    cursor: pointer;
  }

  .rh:hover {
    background: var(--surface-alt);
  }

  .rh :global(.icon) {
    color: var(--text-muted);
  }

  .rh .count {
    margin-left: auto;
  }

  .ritems {
    list-style: none;
    margin: 0 0 4px;
    padding: 0 0 0 22px;
    animation: dca-fade 160ms ease-out both;
  }

  .ri {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    min-height: 32px;
    padding: 0 8px 0 4px;
    border: none;
    border-radius: 6px;
    background: none;
    color: var(--text);
    font: inherit;
    font-size: 13px;
    text-align: left;
    cursor: pointer;
  }

  .ri:hover {
    background: var(--surface-alt);
  }

  .rn {
    flex: 1 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .rk {
    flex: none;
    font-size: 12px;
    color: var(--text-muted);
  }

  .rfoot {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    padding: 0 8px 8px 26px;
  }

  .rempty {
    padding: 0 8px 8px 30px;
  }

  .nest {
    padding: 0 8px 6px 30px;
  }

  .frow {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 0;
    border: none;
    background: none;
    color: var(--text);
    font: inherit;
    font-size: 13px;
    text-align: left;
    cursor: pointer;
  }

  .frow:hover span:last-child {
    text-decoration: underline;
  }

  .et {
    margin: 0;
    font-size: 16px;
  }

  .ends {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
  }

  .ends > :global(.icon) {
    margin-left: 14px;
    transform: rotate(90deg);
    color: var(--text-muted);
  }

  .end {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 4px 10px 4px 4px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    color: var(--text);
    font: inherit;
    font-weight: 500;
    cursor: pointer;
  }

  .end:hover {
    border-color: var(--text-muted);
  }

  pre.codeblock {
    margin: 0;
    max-height: 260px;
    overflow: auto;
    white-space: pre;
    font-size: 12px;
  }
</style>
