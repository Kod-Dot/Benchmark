<script lang="ts">
  import type { AssessmentEntry } from '../lib/types';

  let { assessments, onOpen }: { assessments: AssessmentEntry[]; onOpen: (path: string) => void } = $props();

  interface Point {
    entry: AssessmentEntry;
    at: number;
    score: number;
  }

  const scopeLabel = (e: AssessmentEntry) =>
    [...e.manifest.scope.domains].sort().concat(e.manifest.scope.tenant ?? []).join(', ');

  /** One series per scope that has at least two scored assessments, oldest first. */
  const series = $derived.by(() => {
    const by = new Map<string, Point[]>();
    for (const entry of assessments) {
      const at = Date.parse(entry.manifest.finished_at ?? entry.manifest.started_at);
      const score = entry.manifest.score;
      if (score === null || score === undefined || Number.isNaN(at)) continue;
      const key = scopeLabel(entry);
      if (!key) continue;
      by.set(key, [...(by.get(key) ?? []), { entry, at, score: Math.round(score) }]);
    }
    return [...by.entries()]
      .filter(([, pts]) => pts.length >= 2)
      .map(([scope, pts]) => ({ scope, points: pts.sort((a, b) => a.at - b.at) }))
      .sort((a, b) => b.points[b.points.length - 1].at - a.points[a.points.length - 1].at);
  });

  const H = 150;
  const PAD = { top: 22, right: 24, bottom: 26, left: 36 };
  /** Keeps the first and last points clear of the axis labels. */
  const INSET = 24;
  let width = $state(860);
  let hover = $state<{ s: number; i: number } | null>(null);

  function geometry(points: Point[]) {
    const t0 = points[0].at;
    const t1 = points[points.length - 1].at;
    const span = Math.max(t1 - t0, 1);
    const w = Math.max(width - PAD.left - PAD.right - 2 * INSET, 100);
    const h = H - PAD.top - PAD.bottom;
    return points.map((p) => ({
      ...p,
      x: PAD.left + INSET + (t1 === t0 ? w / 2 : ((p.at - t0) / span) * w),
      y: PAD.top + (1 - p.score / 100) * h,
    }));
  }

  /** Label every point when there are few; otherwise the first, last, lowest and highest. */
  function labelled(points: Point[], i: number) {
    if (points.length <= 8) return true;
    const scores = points.map((p) => p.score);
    const s = points[i].score;
    return i === 0 || i === points.length - 1 || s === Math.min(...scores) || s === Math.max(...scores);
  }

  const day = (t: number) => new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
  const yFor = (v: number) => PAD.top + (1 - v / 100) * (H - PAD.top - PAD.bottom);
</script>

{#if series.length}
  <section class="trend" bind:clientWidth={width}>
    <h3>Score over time</h3>
    <p class="muted small">
      The score each assessment had when it was analyzed, for scopes assessed more than once. Risks accepted later are
      not reflected here. Select a point to open that assessment.
    </p>
    {#each series as s, si (s.scope)}
      {@const pts = geometry(s.points)}
      {@const first = s.points[0].score}
      {@const last = s.points[s.points.length - 1].score}
      <figure>
        <figcaption>
          <span class="scope">{s.scope}</span>
          <span class="muted small">
            {s.points.length} assessments, {first} to {last}
            {#if last !== first}({last > first ? '+' : ''}{last - first}){/if}
          </span>
        </figcaption>
        <div class="plot">
          <svg width={width} height={H} role="group" aria-label="Score for {s.scope}: {s.points.map((p) => `${p.score} on ${day(p.at)}`).join(', ')}">
            {#each [0, 50, 100] as g (g)}
              <line class="grid" x1={PAD.left} x2={width - PAD.right} y1={yFor(g)} y2={yFor(g)} />
              <text class="tick" x={PAD.left - 8} y={yFor(g) + 4} text-anchor="end">{g}</text>
            {/each}
            <polyline class="line" points={pts.map((p) => `${p.x},${p.y}`).join(' ')} />
            {#each pts as p, i (p.entry.path)}
              {#if labelled(s.points, i)}
                <text class="val" x={p.x} y={p.y - 10} text-anchor="middle">{p.score}</text>
              {/if}
              <g
                class="pt"
                class:on={hover?.s === si && hover.i === i}
                role="button"
                tabindex="0"
                aria-label="{p.entry.manifest.name ?? p.entry.name}, {day(p.at)}, score {p.score}. Open"
                onmouseenter={() => (hover = { s: si, i })}
                onmouseleave={() => (hover = null)}
                onfocus={() => (hover = { s: si, i })}
                onblur={() => (hover = null)}
                onclick={() => onOpen(p.entry.path)}
                onkeydown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onOpen(p.entry.path);
                  }
                }}
              >
                <circle class="hit" cx={p.x} cy={p.y} r="14" />
                <circle class="dot" cx={p.x} cy={p.y} r="5" />
              </g>
            {/each}
            <text class="tick" x={pts[0].x} y={H - 6} text-anchor="middle">{day(s.points[0].at)}</text>
            {#if pts.length > 1}
              <text class="tick" x={pts[pts.length - 1].x} y={H - 6} text-anchor="middle">{day(s.points[s.points.length - 1].at)}</text>
            {/if}
          </svg>
          {#if hover?.s === si}
            {@const p = pts[hover.i]}
            {@const right = p.x > width / 2}
            <div class="tip" class:right style:left="{p.x + (right ? -14 : 14)}px" style:top="{Math.max(p.y - 20, 0)}px">
              <strong>{p.entry.manifest.name ?? p.entry.name}</strong>
              <span>{day(p.at)}</span>
              <span>Score {p.score}</span>
            </div>
          {/if}
        </div>
      </figure>
    {/each}
  </section>
{/if}

<style>
  .trend {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .trend > p {
    margin: 0;
    margin-top: calc(var(--space-2) * -1);
  }

  figure {
    margin: 0;
    padding: var(--space-3) 0 0;
    border-top: 1px solid var(--border);
  }

  figcaption {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: var(--space-1) var(--space-3);
  }

  .scope {
    font-weight: 600;
  }

  .plot {
    position: relative;
  }

  svg {
    display: block;
    overflow: visible;
  }

  .grid {
    stroke: var(--border);
    stroke-width: 1;
  }

  .tick,
  .val {
    font-size: 12px;
    fill: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }

  .val {
    fill: var(--text);
    font-weight: 600;
    stroke: var(--bg);
    stroke-width: 4px;
    stroke-linejoin: round;
    paint-order: stroke;
  }

  .line {
    fill: none;
    stroke: var(--accent);
    stroke-width: 2;
    stroke-linejoin: round;
    stroke-linecap: round;
  }

  .pt {
    cursor: pointer;
    outline: none;
  }

  .hit {
    fill: transparent;
  }

  .dot {
    fill: var(--accent);
    stroke: var(--bg);
    stroke-width: 2;
  }

  .pt.on .dot,
  .pt:focus-visible .dot {
    r: 7;
  }

  .pt:focus-visible .hit {
    stroke: var(--accent);
    stroke-width: 2;
  }

  .tip {
    position: absolute;
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 10px;
    min-width: 150px;
    background: var(--surface);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    box-shadow: 0 4px 14px rgb(0 0 0 / 0.12);
    font-size: 12px;
    pointer-events: none;
    z-index: 2;
  }

  .tip.right {
    transform: translateX(-100%);
  }
</style>
