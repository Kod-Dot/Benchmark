<script lang="ts">
  import { untrack } from 'svelte';
  import Icon from './Icon.svelte';
  import { kindIcon, kindLabel } from '../lib/format';
  import { DirGraph, edgeInfo } from '../lib/graph';
  import { layered, nodeWidth, NODE_H, type Layout } from '../lib/graphLayout';
  import type { DirObject, Edge } from '../lib/types';

  let {
    graph,
    nodeIds,
    edges,
    anchor = null,
    selected = $bindable(null),
    selectedEdge = $bindable(null),
    hot = new Set<Edge>(),
    marked = new Set<string>(),
    pinned = new Set<string>(),
    label = 'Relationship graph',
    onopen,
    oncontext,
  }: {
    graph: DirGraph;
    nodeIds: string[];
    edges: Edge[];
    anchor?: string | null;
    selected?: string | null;
    selectedEdge?: Edge | null;
    /** Relationships to draw emphasised, such as the steps of an attack path. */
    hot?: Set<Edge>;
    /** Objects marked as compromised. */
    marked?: Set<string>;
    pinned?: Set<string>;
    label?: string;
    onopen?: (id: string) => void;
    oncontext?: (at: { x: number; y: number; id?: string; edge?: Edge }) => void;
  } = $props();

  const nodes = $derived(nodeIds.map((id) => graph.byId.get(id)).filter(Boolean) as DirObject[]);
  const sub = (o: DirObject) => (o.tier0 ? `${kindLabel(o.kind)} · Tier 0` : o.enabled === false ? `${kindLabel(o.kind)} · disabled` : kindLabel(o.kind));
  const layout: Layout = $derived(
    layered(
      nodes.map((n) => ({ id: n.id, width: nodeWidth(n.name, sub(n)) })),
      edges.map((e) => ({ from: e.from, to: e.to })),
      anchor ?? undefined,
    ),
  );

  // Positions on screen move smoothly from the old layout to the new one.
  type Pt = { x: number; y: number; width: number };
  let shown = $state.raw(new Map<string, Pt>());
  let born = $state.raw(new Set<string>());
  let frame = 0;
  const reduce = () =>
    document.documentElement.getAttribute('data-motion') === 'off' || matchMedia('(prefers-reduced-motion: reduce)').matches;

  $effect(() => {
    const target = layout.pos;
    untrack(() => {
      cancelAnimationFrame(frame);
      const from = new Map(shown);
      const fresh = new Set<string>();
      // A new object grows out of the object it is connected to.
      for (const [id, p] of target) {
        if (from.has(id)) continue;
        fresh.add(id);
        const link = edges.find((e) => (e.to === id && from.has(e.from)) || (e.from === id && from.has(e.to)));
        const origin = link ? from.get(link.to === id ? link.from : link.to) : undefined;
        from.set(id, origin ? { ...origin, width: p.width } : { ...p });
      }
      born = fresh;
      if (reduce() || from.size === fresh.size) {
        shown = new Map([...target].map(([id, p]) => [id, { x: p.x, y: p.y, width: p.width }]));
        if (!userMoved) requestAnimationFrame(fit);
        return;
      }
      const t0 = performance.now();
      const step = (now: number) => {
        const t = Math.min(1, (now - t0) / 420);
        const k = 1 - Math.pow(1 - t, 3);
        const next = new Map<string, Pt>();
        for (const [id, p] of target) {
          const a = from.get(id) ?? p;
          next.set(id, { x: a.x + (p.x - a.x) * k, y: a.y + (p.y - a.y) * k, width: a.width + (p.width - a.width) * k });
        }
        shown = next;
        if (t < 1) frame = requestAnimationFrame(step);
      };
      frame = requestAnimationFrame(step);
      if (!userMoved) fitTo(layout);
    });
  });

  // Pan and zoom
  let box: HTMLDivElement | undefined = $state();
  let scale = $state(1);
  let tx = $state(0);
  let ty = $state(0);
  let userMoved = false;
  let drag: { x: number; y: number; tx: number; ty: number; moved: boolean } | null = null;
  let smooth = $state(false);

  function fitTo(l: Layout, animate = true) {
    if (!box) return;
    const w = box.clientWidth;
    const h = box.clientHeight;
    // Never shrink names past reading size: a long chain starts at its left
    // end instead, and the overview map shows the rest.
    const s = Math.min(1.15, Math.max(0.8, Math.min((w - 40) / l.width, (h - 40) / l.height)));
    smooth = animate && !reduce();
    scale = s;
    tx = l.width * s > w ? 0 : (w - l.width * s) / 2;
    ty = l.height * s > h ? 0 : Math.max(10, (h - l.height * s) / 2);
    setTimeout(() => (smooth = false), 320);
  }
  export function fit() {
    userMoved = false;
    fitTo(layout);
  }

  function zoomAt(f: number, cx?: number, cy?: number) {
    if (!box) return;
    const r = box.getBoundingClientRect();
    const px = cx ?? r.width / 2;
    const py = cy ?? r.height / 2;
    const next = Math.min(2.5, Math.max(0.2, scale * f));
    tx = px - ((px - tx) * next) / scale;
    ty = py - ((py - ty) * next) / scale;
    scale = next;
    userMoved = true;
  }
  export function zoom(f: number) {
    smooth = !reduce();
    zoomAt(f);
    setTimeout(() => (smooth = false), 220);
  }

  function onWheel(e: WheelEvent) {
    e.preventDefault();
    const r = box!.getBoundingClientRect();
    if (e.ctrlKey || Math.abs(e.deltaY) >= Math.abs(e.deltaX)) zoomAt(Math.exp(-e.deltaY * 0.0015), e.clientX - r.left, e.clientY - r.top);
    else {
      tx -= e.deltaX;
      userMoved = true;
    }
  }
  function onDown(e: PointerEvent) {
    if (e.button !== 0 || (e.target as HTMLElement).closest('button, [data-edge]')) return;
    drag = { x: e.clientX, y: e.clientY, tx, ty, moved: false };
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  }
  function onMove(e: PointerEvent) {
    if (!drag) return;
    const dx = e.clientX - drag.x;
    const dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    tx = drag.tx + dx;
    ty = drag.ty + dy;
    userMoved = true;
  }
  function onUp() {
    if (drag && !drag.moved) {
      selected = null;
      selectedEdge = null;
    }
    drag = null;
  }

  /** Brings an object into view, for keyboard moves and pane links. */
  export function reveal(id: string) {
    const p = layout.pos.get(id);
    if (!p || !box) return;
    const x = tx + (p.x + p.width / 2) * scale;
    const y = ty + (p.y + NODE_H / 2) * scale;
    if (x < 40 || x > box.clientWidth - 40 || y < 40 || y > box.clientHeight - 40) {
      smooth = !reduce();
      tx += box.clientWidth / 2 - x;
      ty += box.clientHeight / 2 - y;
      setTimeout(() => (smooth = false), 320);
    }
  }

  // Lines: a curve from the right of one object to the left of the next.
  let hover = $state<string | null>(null);
  let hoverEdge = $state.raw<Edge | null>(null);
  // Hovering an object fades what is not connected to it.
  const near = $derived.by(() => {
    const focus = hover;
    if (!focus) return null;
    const s = new Set<string>([focus]);
    for (const e of edges) {
      if (e.from === focus) s.add(e.to);
      if (e.to === focus) s.add(e.from);
    }
    return s;
  });
  const pathOn = $derived(new Set([...hot].flatMap((e) => [e.from, e.to])));

  // Where each line meets an object: lines into (or out of) one object are
  // spread down its side in the order of the objects at their other end, so
  // they arrive apart instead of piling onto one point.
  const ports = $derived.by(() => {
    const ins = new Map<string, Edge[]>();
    const outs = new Map<string, Edge[]>();
    for (const e of edges) {
      const a = shown.get(e.from);
      const b = shown.get(e.to);
      if (!a || !b || !(b.x > a.x + a.width - 4)) continue;
      (ins.get(e.to) ?? ins.set(e.to, []).get(e.to)!).push(e);
      (outs.get(e.from) ?? outs.set(e.from, []).get(e.from)!).push(e);
    }
    const off = new Map<string, number>();
    const spread = (list: Edge[], side: 'in' | 'out') => {
      const other = (e: Edge) => shown.get(side === 'in' ? e.from : e.to)!.y;
      list.sort((x, y) => other(x) - other(y));
      const gap = list.length > 1 ? Math.min(9, (NODE_H - 20) / (list.length - 1)) : 0;
      list.forEach((e, i) => off.set(`${side}|${edges.indexOf(e)}`, (i - (list.length - 1) / 2) * gap));
    };
    for (const l of ins.values()) spread(l, 'in');
    for (const l of outs.values()) spread(l, 'out');
    return off;
  });

  function curve(e: Edge, i: number) {
    const a = shown.get(e.from);
    const b = shown.get(e.to);
    if (!a || !b) return null;
    const ay = a.y + NODE_H / 2 + (ports.get(`out|${i}`) ?? 0);
    const by = b.y + NODE_H / 2 + (ports.get(`in|${i}`) ?? 0);
    if (b.x > a.x + a.width - 4) {
      const x1 = a.x + a.width;
      const x2 = b.x - 6;
      const dx = Math.max(40, (x2 - x1) / 2);
      // The label sits nearer the source, where lines into one object are still apart.
      const t = 0.4;
      const u = 1 - t;
      const mx = u * u * u * x1 + 3 * u * u * t * (x1 + dx) + 3 * u * t * t * (x2 - dx) + t * t * t * x2;
      const my = u * u * u * ay + 3 * u * u * t * ay + 3 * u * t * t * by + t * t * t * by;
      return { d: `M${x1},${ay} C${x1 + dx},${ay} ${x2 - dx},${by} ${x2},${by}`, mx, my };
    }
    // Against the flow, or in the same column: loop above both objects.
    const top = Math.min(a.y, b.y) - 34;
    const x1 = a.x + a.width / 2;
    const x2 = b.x + b.width / 2;
    return { d: `M${x1},${a.y} C${x1},${top} ${x2},${top} ${x2},${b.y - 6}`, mx: (x1 + x2) / 2, my: top + 6 };
  }

  const lines = $derived(
    edges
      .map((e, i) => {
        const c = curve(e, i);
        return c && { e, i, ...c, hot: hot.has(e), derived: graph.derived.has(e) };
      })
      .filter((l) => l !== null),
  );
  // Labels only where they help: few lines, or the lines near the focus.
  const showAllLabels = $derived(edges.length <= 40);

  // Arrow keys walk the graph: right and left follow the lines out of and
  // into the object, up and down move within its column.
  function step(id: string, key: string): string | undefined {
    const p = layout.pos.get(id);
    if (!p) return;
    const y = (n: string) => layout.pos.get(n)?.y ?? 0;
    const nearest = (list: string[]) => list.filter((n) => layout.pos.has(n)).sort((a, b) => Math.abs(y(a) - p.y) - Math.abs(y(b) - p.y))[0];
    if (key === 'ArrowRight') return nearest(edges.filter((e) => e.from === id).map((e) => e.to)) ?? nearest([...layout.pos].filter(([, q]) => q.layer === p.layer + 1).map(([n]) => n));
    if (key === 'ArrowLeft') return nearest(edges.filter((e) => e.to === id).map((e) => e.from)) ?? nearest([...layout.pos].filter(([, q]) => q.layer === p.layer - 1).map(([n]) => n));
    const col = [...layout.pos].filter(([, q]) => q.layer === p.layer).sort((a, b) => a[1].y - b[1].y).map(([n]) => n);
    const i = col.indexOf(id);
    return col[key === 'ArrowUp' ? i - 1 : i + 1];
  }

  function nodeKey(e: KeyboardEvent, id: string) {
    if (e.key.startsWith('Arrow') && !e.altKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      const to = step(id, e.key);
      if (!to) return;
      reveal(to);
      box?.querySelector<HTMLElement>(`.node[data-id="${CSS.escape(to)}"]`)?.focus({ preventScroll: true });
    } else if (e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10')) {
      e.preventDefault();
      const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
      oncontext?.({ x: r.left + 12, y: r.bottom - 6, id });
    } else if (e.key === 'Enter' && e.ctrlKey) {
      onopen?.(id);
    }
  }

  // Overview map
  const MINI_W = 168;
  const miniScale = $derived(Math.min(MINI_W / layout.width, 110 / layout.height));
  let boxW = $state(800);
  let boxH = $state(600);
  function miniJump(e: MouseEvent) {
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const gx = (e.clientX - r.left) / miniScale;
    const gy = (e.clientY - r.top) / miniScale;
    smooth = !reduce();
    tx = boxW / 2 - gx * scale;
    ty = boxH / 2 - gy * scale;
    userMoved = true;
    setTimeout(() => (smooth = false), 320);
  }
</script>

<div
  class="canvas"
  bind:this={box}
  bind:clientWidth={boxW}
  bind:clientHeight={boxH}
  role="application"
  aria-label={label}
  aria-roledescription="graph"
  onwheel={onWheel}
  onpointerdown={onDown}
  onpointermove={onMove}
  onpointerup={onUp}
  oncontextmenu={(e) => {
    if (!(e.target as HTMLElement).closest('button, [data-edge]')) e.preventDefault();
  }}
>
  <div class="stage" class:smooth style:transform="translate({tx}px, {ty}px) scale({scale})" style:width="{layout.width}px" style:height="{layout.height}px">
    <svg width={layout.width} height={layout.height} class="lines">
      <defs>
        <marker id="gc-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="ah" /></marker>
        <marker id="gc-arrow-hot" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="ah hot" /></marker>
        <marker id="gc-arrow-on" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="ah on" /></marker>
      </defs>
      {#each lines as l (`${l.e.from}|${l.e.kind}|${l.e.to}|${l.i}`)}
        {@const on = selectedEdge === l.e || hoverEdge === l.e || (l.e.from === (hover ?? selected) || l.e.to === (hover ?? selected))}
        {@const dim = near !== null && !on && !l.hot}
        <path d={l.d} class="ln" class:hot={l.hot} class:on class:dim class:derived={l.derived} pathLength="1" marker-end={on ? 'url(#gc-arrow-on)' : l.hot ? 'url(#gc-arrow-hot)' : 'url(#gc-arrow)'} />
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <path
          d={l.d}
          class="hit"
          data-edge
          role="button"
          tabindex="-1"
          aria-label="{graph.byId.get(l.e.from)?.name} {edgeInfo(l.e.kind).label} {graph.byId.get(l.e.to)?.name}"
          onpointerenter={() => (hoverEdge = l.e)}
          onpointerleave={() => (hoverEdge = null)}
          onclick={() => {
            selectedEdge = l.e;
            selected = null;
          }}
          oncontextmenu={(ev) => {
            ev.preventDefault();
            selectedEdge = l.e;
            oncontext?.({ x: ev.clientX, y: ev.clientY, edge: l.e });
          }}
        />
      {/each}
    </svg>
    {#each lines as l (`lbl|${l.e.from}|${l.e.kind}|${l.e.to}|${l.i}`)}
      {@const on = selectedEdge === l.e || hoverEdge === l.e || (l.e.from === (hover ?? selected) || l.e.to === (hover ?? selected))}
      {#if showAllLabels || on || l.hot}
        <span class="lbl" class:hot={l.hot} class:on class:dim={near !== null && !on && !l.hot} style:left="{l.mx}px" style:top="{l.my}px">{edgeInfo(l.e.kind).label}</span>
      {/if}
    {/each}
    {#each nodes as n (n.id)}
      {@const p = shown.get(n.id)}
      {#if p}
        <button
          class="node"
          class:t0={n.tier0}
          class:anchor={n.id === anchor}
          class:sel={n.id === selected}
          class:dim={near !== null && !near.has(n.id) && !pathOn.has(n.id)}
          class:path={pathOn.has(n.id)}
          class:off={n.enabled === false}
          class:born={born.has(n.id)}
          data-id={n.id}
          style:left="{p.x}px"
          style:top="{p.y}px"
          style:width="{p.width}px"
          aria-pressed={n.id === selected}
          aria-label="{n.name} {sub(n)}{marked.has(n.id) ? ', marked as compromised' : ''}"
          onclick={() => {
            selected = n.id;
            selectedEdge = null;
          }}
          ondblclick={() => onopen?.(n.id)}
          onpointerenter={() => (hover = n.id)}
          onpointerleave={() => (hover = null)}
          onfocus={() => (hover = n.id)}
          onblur={() => (hover = null)}
          onkeydown={(e) => nodeKey(e, n.id)}
          oncontextmenu={(e) => {
            e.preventDefault();
            selected = n.id;
            selectedEdge = null;
            oncontext?.({ x: e.clientX, y: e.clientY, id: n.id });
          }}
        >
          <span class="ico"><Icon name={kindIcon(n.kind)} size={18} /></span>
          <span class="txt"><span class="nm">{n.name}</span>{' '}<span class="sb">{sub(n)}</span></span>
          {#if marked.has(n.id)}<span class="badge mk" title="Marked as compromised"><Icon name="flag" size={12} /></span>
          {:else if pinned.has(n.id)}<span class="badge pn" title="Pinned"><Icon name="pin" size={12} /></span>{/if}
        </button>
      {/if}
    {/each}
  </div>

  {#if layout.width * scale > boxW || layout.height * scale > boxH}
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="mini" style:width="{layout.width * miniScale}px" style:height="{layout.height * miniScale}px" onclick={miniJump} title="Overview: select to move there">
      {#each nodes as n (n.id)}
        {@const p = layout.pos.get(n.id)}
        {#if p}<i class:t0={n.tier0} class:sel={n.id === selected} style:left="{p.x * miniScale}px" style:top="{p.y * miniScale}px" style:width="{Math.max(3, p.width * miniScale)}px" style:height="{Math.max(2, NODE_H * miniScale)}px"></i>{/if}
      {/each}
      <b
        style:left="{(-tx / scale) * miniScale}px"
        style:top="{(-ty / scale) * miniScale}px"
        style:width="{(boxW / scale) * miniScale}px"
        style:height="{(boxH / scale) * miniScale}px"
      ></b>
    </div>
  {/if}
</div>

<style>
  .canvas {
    position: relative;
    overflow: hidden;
    flex: 1 1 auto;
    min-height: 0;
    background: var(--bg);
    cursor: grab;
    touch-action: none;
    user-select: none;
  }

  .canvas:active {
    cursor: grabbing;
  }

  .stage {
    position: absolute;
    left: 0;
    top: 0;
    transform-origin: 0 0;
  }

  .stage.smooth {
    transition: transform 300ms cubic-bezier(0.2, 0.7, 0.2, 1);
  }

  .lines {
    position: absolute;
    inset: 0;
    overflow: visible;
  }

  .ln {
    fill: none;
    stroke: var(--border-strong);
    stroke-width: 1.6;
    transition:
      stroke 160ms ease-out,
      opacity 160ms ease-out,
      stroke-width 160ms ease-out;
    stroke-dasharray: 1;
    stroke-dashoffset: 0;
    animation: draw 520ms cubic-bezier(0.3, 0.6, 0.2, 1) both;
  }

  @keyframes draw {
    from {
      stroke-dashoffset: 1;
    }
  }

  .ln.derived {
    stroke-dasharray: 0.012 0.008;
    animation: none;
  }

  .ln.hot {
    stroke: var(--sev-critical);
    stroke-width: 2.4;
  }

  .ln.on {
    stroke: var(--accent);
    stroke-width: 2.4;
  }

  .ln.dim {
    opacity: 0.22;
  }

  .ah {
    fill: var(--border-strong);
  }

  .ah.hot {
    fill: var(--sev-critical);
  }

  .ah.on {
    fill: var(--accent);
  }

  .hit:focus {
    outline: none;
  }

  .hit {
    fill: none;
    stroke: transparent;
    stroke-width: 14;
    pointer-events: stroke;
    cursor: pointer;
  }

  .lbl {
    position: absolute;
    transform: translate(-50%, -50%);
    padding: 1px 6px;
    border-radius: 9px;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    white-space: nowrap;
    pointer-events: none;
    transition:
      opacity 160ms ease-out,
      color 160ms ease-out,
      border-color 160ms ease-out;
    animation: dca-fade 300ms 200ms ease-out both;
  }

  .lbl.hot {
    color: var(--sev-critical);
    border-color: var(--sev-critical-soft);
  }

  .lbl.on {
    color: var(--accent-ink);
    border-color: var(--accent);
  }

  .lbl.dim {
    opacity: 0.25;
  }

  .node {
    position: absolute;
    display: flex;
    align-items: center;
    gap: 10px;
    height: 52px;
    padding: 0 18px 0 8px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--surface-raised);
    color: var(--text);
    font: inherit;
    text-align: left;
    cursor: pointer;
    box-shadow: 0 1px 2px rgb(0 0 0 / 0.06);
    transition:
      box-shadow 160ms ease-out,
      border-color 160ms ease-out,
      opacity 160ms ease-out,
      transform 160ms ease-out;
  }

  .node.born {
    animation: dca-pop 380ms cubic-bezier(0.2, 0.7, 0.2, 1) both;
  }

  .node:hover {
    border-color: var(--text-muted);
    box-shadow: 0 6px 18px -6px rgb(0 0 0 / 0.25);
    transform: translateY(-1px);
  }

  .node:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .node.sel {
    border-color: var(--accent);
    box-shadow:
      0 0 0 3px var(--accent-soft),
      0 6px 18px -6px rgb(0 0 0 / 0.25);
  }

  .node.anchor {
    border-width: 2px;
    border-color: var(--accent);
  }

  .node.path,
  .node.t0 {
    border-color: transparent;
    box-shadow: inset 0 0 0 2px var(--salmon);
  }

  .node.path.sel,
  .node.t0.sel {
    box-shadow:
      inset 0 0 0 2px var(--salmon),
      0 0 0 3px var(--accent-soft);
  }

  .node.dim {
    opacity: 0.35;
  }

  .node.off .nm {
    color: var(--text-muted);
  }

  .ico {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: var(--surface-alt);
    color: var(--text);
  }

  .t0 .ico {
    background: var(--salmon);
    color: var(--ink);
  }

  .anchor .ico {
    background: var(--accent-soft);
    color: var(--accent-ink);
  }

  .txt {
    display: flex;
    flex-direction: column;
    min-width: 0;
    line-height: 1.25;
  }

  .nm {
    font-size: 13px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sb {
    font-size: 12px;
    color: var(--text-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .t0 .sb {
    color: var(--sev-critical);
  }

  .badge {
    position: absolute;
    top: -7px;
    right: -7px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    border: 2px solid var(--bg);
  }

  .badge.mk {
    background: var(--sev-critical);
    color: var(--sev-critical-fg);
  }

  .badge.pn {
    background: var(--accent-ink);
    color: var(--accent-text);
  }

  .mini {
    position: absolute;
    right: 14px;
    bottom: 14px;
    border: 1px solid var(--border);
    border-radius: 14px;
    background: color-mix(in srgb, var(--surface-raised) 92%, transparent);
    box-shadow: 0 4px 14px -6px rgb(0 0 0 / 0.25);
    overflow: hidden;
    cursor: pointer;
    animation: dca-fade 200ms ease-out both;
  }

  .mini i {
    position: absolute;
    border-radius: 1px;
    background: var(--border-strong);
  }

  .mini i.t0 {
    background: var(--sev-critical);
  }

  .mini i.sel {
    background: var(--accent);
  }

  .mini b {
    position: absolute;
    border: 1.5px solid var(--accent);
    border-radius: 2px;
    background: color-mix(in srgb, var(--accent) 8%, transparent);
    pointer-events: none;
  }

  @media (forced-colors: active) {
    .node.sel {
      outline: 3px solid Highlight;
    }
    .ln {
      stroke: CanvasText;
    }
    .ln.hot,
    .ln.on {
      stroke: Highlight;
    }
  }
</style>
