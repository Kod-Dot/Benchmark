// Layered ("left to right") layout for the relationship graph: each
// relationship points right where it can, objects in a column are ordered
// to cross as few lines as possible, and each object sits level with the
// objects it connects to. A small Sugiyama-style layout, enough for the few
// hundred objects the graph shows at once.

export interface LayoutNode {
  id: string;
  width: number;
}

export interface LayoutEdge {
  from: string;
  to: string;
}

export interface Placed {
  x: number;
  y: number;
  width: number;
  layer: number;
}

export interface Layout {
  pos: Map<string, Placed>;
  width: number;
  height: number;
  /** Edges drawn against the flow (cycles), routed around the columns. */
  back: Set<string>;
}

export const NODE_H = 52;
const GAP_X = 96;
const GAP_Y = 22;
const PAD = 60;

export const edgeKey = (e: LayoutEdge) => `${e.from}->${e.to}`;

export function layered(nodes: LayoutNode[], edges: LayoutEdge[], anchor?: string): Layout {
  const ids = nodes.map((n) => n.id);
  const has = new Set(ids);
  const list = edges.filter((e) => has.has(e.from) && has.has(e.to) && e.from !== e.to);
  const out = new Map<string, string[]>(ids.map((i) => [i, []]));
  const inc = new Map<string, string[]>(ids.map((i) => [i, []]));
  for (const e of list) {
    out.get(e.from)!.push(e.to);
    inc.get(e.to)!.push(e.from);
  }

  // 1. Break cycles: edges that close a loop in a depth-first walk point back.
  const back = new Set<string>();
  const state = new Map<string, 1 | 2>();
  const order = anchor && has.has(anchor) ? [anchor, ...ids.filter((i) => i !== anchor)] : ids;
  for (const root of order) {
    if (state.has(root)) continue;
    const stack: [string, number][] = [[root, 0]];
    state.set(root, 1);
    while (stack.length) {
      const top = stack[stack.length - 1];
      const nexts = out.get(top[0])!;
      if (top[1] < nexts.length) {
        const n = nexts[top[1]++];
        const s = state.get(n);
        if (s === 1) back.add(`${top[0]}->${n}`);
        else if (!s) {
          state.set(n, 1);
          stack.push([n, 0]);
        }
      } else {
        state.set(top[0], 2);
        stack.pop();
      }
    }
  }
  const fwd = list.filter((e) => !back.has(edgeKey(e)));

  // 2. Layers: longest path from the sources, then pull each object right
  // up against its nearest target so chains stay short.
  const layer = new Map<string, number>(ids.map((i) => [i, 0]));
  const indeg = new Map<string, number>(ids.map((i) => [i, 0]));
  for (const e of fwd) indeg.set(e.to, indeg.get(e.to)! + 1);
  const queue = ids.filter((i) => indeg.get(i) === 0);
  const topo: string[] = [];
  while (queue.length) {
    const n = queue.shift()!;
    topo.push(n);
    for (const e of fwd)
      if (e.from === n) {
        layer.set(e.to, Math.max(layer.get(e.to)!, layer.get(n)! + 1));
        indeg.set(e.to, indeg.get(e.to)! - 1);
        if (indeg.get(e.to) === 0) queue.push(e.to);
      }
  }
  for (let i = topo.length - 1; i >= 0; i--) {
    const n = topo[i];
    const targets = fwd.filter((e) => e.from === n).map((e) => layer.get(e.to)!);
    if (targets.length && (inc.get(n)!.length === 0 || n !== anchor)) {
      const want = Math.min(...targets) - 1;
      if (want > layer.get(n)!) layer.set(n, want);
    }
  }

  // 3. Order within each layer by the average position of neighbours,
  // sweeping right then left a few times.
  const maxLayer = Math.max(0, ...layer.values());
  const cols: string[][] = Array.from({ length: maxLayer + 1 }, () => []);
  for (const n of order) cols[layer.get(n)!].push(n);
  const index = new Map<string, number>();
  const reindex = () => cols.forEach((c) => c.forEach((n, i) => index.set(n, i)));
  reindex();
  const bary = (n: string, side: 'in' | 'out') => {
    const ns = (side === 'in' ? inc : out).get(n)!.filter((m) => Math.abs(layer.get(m)! - layer.get(n)!) === 1);
    if (!ns.length) return index.get(n)!;
    return ns.reduce((s, m) => s + index.get(m)!, 0) / ns.length;
  };
  for (let sweep = 0; sweep < 6; sweep++) {
    const down = sweep % 2 === 0;
    const range = down ? cols.map((_, i) => i).slice(1) : cols.map((_, i) => i).slice(0, -1).reverse();
    for (const l of range) {
      const b = new Map(cols[l].map((n) => [n, bary(n, down ? 'in' : 'out')]));
      cols[l].sort((a, c) => b.get(a)! - b.get(c)!);
      reindex();
    }
  }

  // 4. Coordinates: stack each column, then nudge objects towards their
  // neighbours' heights while keeping the order and spacing.
  const widthOf = new Map(nodes.map((n) => [n.id, n.width]));
  const colWidth = cols.map((c) => Math.max(120, ...c.map((n) => widthOf.get(n)!)));
  const colX: number[] = [];
  let x = PAD;
  for (const w of colWidth) {
    colX.push(x);
    x += w + GAP_X;
  }
  const y = new Map<string, number>();
  const tallest = Math.max(1, ...cols.map((c) => c.length));
  const full = tallest * (NODE_H + GAP_Y);
  cols.forEach((c) => {
    const start = (full - c.length * (NODE_H + GAP_Y)) / 2;
    c.forEach((n, i) => y.set(n, PAD + start + i * (NODE_H + GAP_Y)));
  });
  for (let pass = 0; pass < 8; pass++) {
    for (const c of pass % 2 ? [...cols].reverse() : cols) {
      const want = c.map((n) => {
        const ns = [...out.get(n)!, ...inc.get(n)!];
        return ns.length ? ns.reduce((s, m) => s + y.get(m)!, 0) / ns.length : y.get(n)!;
      });
      // Keep order with minimum spacing: forward then backward pass.
      const placed = want.slice();
      for (let i = 1; i < placed.length; i++) placed[i] = Math.max(placed[i], placed[i - 1] + NODE_H + GAP_Y);
      for (let i = placed.length - 2; i >= 0; i--) placed[i] = Math.min(placed[i], placed[i + 1] - NODE_H - GAP_Y);
      c.forEach((n, i) => y.set(n, placed[i]));
    }
  }
  const minY = Math.min(...y.values());
  const pos = new Map<string, Placed>();
  for (const n of ids) {
    const l = layer.get(n)!;
    const w = widthOf.get(n)!;
    pos.set(n, { x: colX[l] + (colWidth[l] - w) / 2, y: y.get(n)! - minY + PAD, width: w, layer: l });
  }
  const height = Math.max(...[...pos.values()].map((p) => p.y + NODE_H)) + PAD;
  return { pos, width: x - GAP_X + PAD, height, back };
}

let ctx: CanvasRenderingContext2D | null = null;
/** Width of a node for its label, measured with the UI font. */
export function nodeWidth(name: string, sub: string): number {
  ctx ??= document.createElement('canvas').getContext('2d');
  if (!ctx) return Math.min(260, name.length * 7.4 + 64);
  ctx.font = '600 13px "Urbanist Variable", "Segoe UI", sans-serif';
  const a = ctx.measureText(name).width;
  ctx.font = '12px "Urbanist Variable", "Segoe UI", sans-serif';
  const b = ctx.measureText(sub).width;
  return Math.min(300, Math.ceil(Math.max(a, b)) + 76);
}
