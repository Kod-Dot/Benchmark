<script lang="ts">
  import { freeze } from '../lib/freeze';
  import Icon from '../components/Icon.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import { date, kindIcon, kindLabel, num, plural } from '../lib/format';
  import type { Affected, AssessmentView, Finding } from '../lib/types';
  import { findingKey, type Go } from './route';

  let { view, go }: { view: AssessmentView; go: Go } = $props();

  const DAYS = 30;
  const DAY_MS = 86_400_000;

  const hunts = $derived(view.findings.filter((f) => f.group === 'hunting'));
  const withObs = $derived(hunts.filter((f) => f.status === 'failed' || f.status === 'accepted'));
  const notAssessed = $derived(hunts.filter((f) => f.status === 'not_assessed'));

  interface Obs {
    hunt: Finding;
    a: Affected;
    at: number | null;
  }

  const observations = $derived.by(() => {
    const list: Obs[] = withObs.flatMap((hunt) =>
      hunt.affected.map((a) => {
        const t = a.last_seen ? Date.parse(a.last_seen) : NaN;
        return { hunt, a, at: Number.isNaN(t) ? null : t };
      }),
    );
    return list.sort((x, y) => (y.at ?? -Infinity) - (x.at ?? -Infinity));
  });

  // The 30 days up to the collection (or the newest observation, if later).
  const end = $derived.by(() => {
    const collected = view.runs
      .map((r) => Date.parse(r.manifest.finished_at ?? r.manifest.started_at))
      .filter((t) => !Number.isNaN(t));
    const latest = Math.max(...collected, ...observations.map((o) => o.at ?? -Infinity));
    return Number.isFinite(latest) ? startOfDay(latest) : startOfDay(Date.now());
  });

  function startOfDay(t: number) {
    const d = new Date(t);
    d.setHours(0, 0, 0, 0);
    return d.getTime();
  }

  const days = $derived.by(() => {
    const out = Array.from({ length: DAYS }, (_, i) => ({ day: end - (DAYS - 1 - i) * DAY_MS, obs: [] as Obs[] }));
    for (const o of observations) {
      if (o.at === null) continue;
      const i = Math.round((startOfDay(o.at) - out[0].day) / DAY_MS);
      if (i >= 0 && i < DAYS) out[i].obs.push(o);
    }
    return out;
  });
  const timed = $derived(days.reduce((n, d) => n + d.obs.length, 0));
  const untimed = $derived(observations.filter((o) => o.at === null).length);
  const peak = $derived(Math.max(1, ...days.map((d) => d.obs.length)));

  let hover = $state<number | null>(null);
  const dayLabel = (t: number) => new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });

  function openHunt(f: Finding) {
    go({ page: 'finding', key: findingKey(f) });
  }
</script>

<div class="toolbar" use:freeze>
  <div class="titles">
    <h2>Threat hunting</h2>
    <span class="muted small">
      Signs of attack activity in domain controller event logs and Entra sign-in and audit logs. These are leads to
      investigate, kept apart from configuration findings. A hunt with nothing to show only means nothing matching was
      logged.
    </span>
  </div>
</div>

<div class="body">
  <dl class="counts">
    <div><dt>Hunts run</dt><dd>{num(hunts.length - notAssessed.length)}</dd></div>
    <div><dt>With observations</dt><dd>{num(withObs.length)}</dd></div>
    <div><dt>Observations</dt><dd>{num(observations.length)}</dd></div>
    <div><dt>Not assessed</dt><dd>{num(notAssessed.length)}</dd></div>
  </dl>

  <section class="sec">
    <div class="sec-h">
      <h3>Observations by day</h3>
      <span class="muted small">
        Last {DAYS} days to {dayLabel(end)}{untimed ? `; ${plural(untimed, 'observation')} without a time ${untimed === 1 ? 'is' : 'are'} in the table only` : ''}
      </span>
    </div>
    {#if timed}
      <div class="chart" role="img" aria-label="{plural(timed, 'observation')} over the last {DAYS} days; the table below lists them">
        <span class="ymax muted small">{peak} a day</span>
        <div class="bars" onmouseleave={() => (hover = null)} role="presentation">
          {#each days as d, i (d.day)}
            <div class="col" class:on={hover === i} onmouseenter={() => (hover = i)} role="presentation">
              {#if d.obs.length}
                <span class="bar" style:height="{(d.obs.length / peak) * 100}%"></span>
              {/if}
            </div>
          {/each}
          {#if hover !== null}
            {@const d = days[hover]}
            {@const right = hover >= DAYS / 2}
            <div
              class="tip"
              class:right
              style:left="calc(28px + (100% - 28px) * {(right ? hover : hover + 1) / DAYS} {right ? '-' : '+'} 8px)"
            >
              <strong>{dayLabel(d.day)}</strong>
              <span>{plural(d.obs.length, 'observation')}</span>
              {#each [...new Set(d.obs.map((o) => o.hunt.title))].slice(0, 3) as t (t)}<span class="muted">{t}</span>{/each}
            </div>
          {/if}
        </div>
        <div class="axis muted small">
          <span>{dayLabel(days[0].day)}</span>
          <span>{dayLabel(days[Math.floor(DAYS / 2)].day)}</span>
          <span>{dayLabel(end)}</span>
        </div>
      </div>
    {:else}
      <p class="empty">
        {observations.length
          ? 'None of the observations carries a time; they are listed below.'
          : 'No observations in the collected logs.'}
      </p>
    {/if}
  </section>

  <section class="sec">
    <div class="sec-h"><h3>Observations</h3><span class="muted small">newest first</span></div>
    {#if observations.length}
      <div class="scroll-x">
        <table class="t">
          <thead>
            <tr>
              <th style="width: 150px">When</th>
              <th style="width: 110px">Severity</th>
              <th style="width: 300px">Hunt</th>
              <th style="width: 220px">Subject</th>
              <th>What was seen</th>
            </tr>
          </thead>
          <tbody>
            {#each observations as o, i (i)}
              <tr>
                <td class="small num">{o.at === null ? '' : date(o.a.last_seen, true)}</td>
                <td><SevBadge severity={o.hunt.severity} /></td>
                <td>
                  <button class="linkbtn plain" onclick={() => openHunt(o.hunt)}>{o.hunt.title}</button>
                  <span class="mono small muted block">{o.hunt.id}{o.hunt.status === 'accepted' ? ' · accepted' : ''}</span>
                </td>
                <td>
                  <span class="obj">
                    <Icon name={kindIcon(o.a.kind)} size={16} />
                    <span>
                      {#if o.a.object && view.directory?.objects.some((x) => x.id === o.a.object)}
                        <button class="linkbtn plain strong" onclick={() => go({ page: 'object', id: o.a.object! })}>{o.a.name}</button>
                      {:else}
                        <strong>{o.a.name}</strong>
                      {/if}
                      <span class="muted small block">{kindLabel(o.a.kind)}{o.a.location ? ` · ${o.a.location}` : ''}</span>
                    </span>
                  </span>
                </td>
                <td class="small">{o.a.reason ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <p class="empty">No hunt found anything to investigate.</p>
    {/if}
  </section>

  <section class="sec">
    <div class="sec-h"><h3>Hunts</h3><span class="muted small">what each one looked for and what it found</span></div>
    <div class="scroll-x">
      <table class="t">
        <thead>
          <tr><th style="width: 120px">Hunt</th><th>Looks for</th><th style="width: 200px">Result</th></tr>
        </thead>
        <tbody>
          {#each hunts as h (findingKey(h))}
            <tr>
              <td class="mono small">{h.id}</td>
              <td><button class="linkbtn plain" onclick={() => openHunt(h)}>{h.title}</button></td>
              <td class="small">
                {#if h.status === 'failed'}
                  <span class="state failed"><Icon name="warning" size={16} />{plural(h.affected_count ?? h.affected.length, 'observation')}</span>
                {:else if h.status === 'accepted'}
                  <span class="state neutral"><Icon name="checkmarkCircle" size={16} />Accepted</span>
                {:else if h.status === 'passed'}
                  <span class="state ok"><Icon name="checkmarkCircle" size={16} />Nothing found</span>
                {:else}
                  <span class="state neutral" title={h.note ?? ''}><Icon name="subtractCircle" size={16} />Not assessed</span>
                {/if}
              </td>
            </tr>
          {:else}
            <tr><td colspan="3" class="muted">No threat-hunting checks were part of this assessment.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
</div>

<style>
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    padding: 12px 28px 14px 8px;
  }

  .titles {
    display: flex;
    flex-direction: column;
    gap: 4px;
    flex: 1 1 auto;
    max-width: 900px;
  }

  .body {
    padding: 20px 24px 32px;
    display: flex;
    flex-direction: column;
    gap: 28px;
  }

  .counts {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 40px;
    margin: 0;
  }

  .counts div {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .counts dt {
    color: var(--text-muted);
    font-size: 12px;
  }

  .counts dd {
    margin: 0;
    font-family: var(--font-display);
    font-size: 26px;
    line-height: 1.1;
  }

  .sec {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .sec-h {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 4px 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }

  .chart {
    position: relative;
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-width: 1100px;
  }

  .ymax {
    position: absolute;
    top: -2px;
    left: 0;
  }

  .bars {
    position: relative;
    display: grid;
    grid-template-columns: repeat(30, 1fr);
    gap: 2px;
    height: 140px;
    padding-left: 28px;
    margin-top: 22px;
    border-bottom: 1px solid var(--border-strong);
  }

  .col {
    position: relative;
    display: flex;
    align-items: flex-end;
    height: 100%;
    border-radius: 4px 4px 0 0;
  }

  .col.on {
    background: var(--accent-soft);
  }

  .bar {
    display: block;
    width: 100%;
    min-height: 3px;
    background: var(--accent);
    border-radius: 4px 4px 0 0;
  }

  .tip {
    position: absolute;
    top: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 10px;
    min-width: 160px;
    max-width: 280px;
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

  .axis {
    display: flex;
    justify-content: space-between;
    padding-left: 28px;
  }

  .empty {
    margin: 0;
    padding: 14px 16px;
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius);
  }

  .t {
    min-width: 900px;
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
</style>
