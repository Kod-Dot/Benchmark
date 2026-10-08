<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import { affectedText, daysSince, heat, num, plural, scopeText, SEVERITIES, severityMeta } from '../lib/format';
  import type { AssessmentView } from '../lib/types';
  import { findingKey, type Go } from './route';

  let { view, go, onExport }: { view: AssessmentView; go: Go; onExport?: () => void } = $props();

  type Tab = 'risks' | 'paths' | 'areas' | 'mitre' | 'coverage';
  let tab = $state<Tab>('risks');
  const tabs: { id: Tab; label: string }[] = [
    { id: 'risks', label: 'Top risks' },
    { id: 'paths', label: 'Attack paths' },
    { id: 'areas', label: 'Areas' },
    { id: 'mitre', label: 'MITRE ATT&CK' },
    { id: 'coverage', label: 'Coverage' },
  ];
  // Gauge colours in a fixed order, so a group keeps its colour.
  const gaugeColours = ['var(--peri)', 'var(--violet)', 'var(--ok-bg)', 'var(--sky)', 'var(--lilac)', 'var(--orange)'];
  const ARC = Math.PI * 34;


  // Filter the dashboard to one group of checks (On-premises, Entra...).
  let group = $state<string>('all');
  const groupTabs = $derived([
    { id: 'all', title: 'All' },
    ...view.summary.groups
      .filter((g) => ['onprem', 'entra', 'hybrid'].includes(g.id))
      .map((g) => ({ id: g.id, title: g.id === 'onprem' ? 'On-premises' : g.title.replace('Microsoft ', '') })),
  ]);
  const inGroup = $derived(view.findings.filter((f) => group === 'all' || f.group === group));
  const failed = $derived(inGroup.filter((f) => f.status === 'failed'));
  const counts = $derived(
    Object.fromEntries(SEVERITIES.map((s) => [s, failed.filter((f) => f.severity === s).length])) as Record<string, number>,
  );
  const status = $derived({
    passed: inGroup.filter((f) => f.status === 'passed').length,
    notAssessed: inGroup.filter((f) => f.status === 'not_assessed').length,
    accepted: inGroup.filter((f) => f.status === 'accepted').length,
  });
  const score = $derived(
    group === 'all' ? view.summary.score : (view.summary.groups.find((g) => g.id === group)?.score ?? null),
  );
  const areas = $derived(view.summary.areas.filter((a) => group === 'all' || a.group === group));
  const top = $derived(failed.slice(0, 8));
  const total = $derived(failed.length + status.passed + status.accepted + status.notAssessed);
  const sevTotal = $derived(Math.max(1, failed.length));
  const tactics = $derived(view.summary.tactics.slice(0, 7));
  const maxTactic = $derived(Math.max(1, ...tactics.map((t) => t.findings)));
  const notAssessed = $derived(inGroup.filter((f) => f.status === 'not_assessed'));


  // Directory figures, read from telemetry when it was collected.
  const dir = $derived(view.directory);
  const ofKind = (kind: string, source?: 'onprem' | 'cloud') =>
    (dir?.objects ?? []).filter(
      (o) => o.kind === kind && (!source || dir!.sources.find((s) => s.name === o.source)?.kind === source),
    );
  const onpremSource = $derived(dir?.sources.find((s) => s.kind === 'onprem')?.name);
  const cloudSource = $derived(dir?.sources.find((s) => s.kind === 'cloud')?.name);

  const glance = $derived.by(() => {
    type Tile = { icon: import('../lib/icons').IconName; label: string; n: number; go: import('./route').Route };
    const all: Tile[] = [
      { icon: 'person', label: 'AD users', n: ofKind('user', 'onprem').length, go: { page: 'directory', source: onpremSource } },
      { icon: 'desktop', label: 'Computers', n: ofKind('computer', 'onprem').length, go: { page: 'directory', source: onpremSource } },
      { icon: 'people', label: 'Groups', n: ofKind('group', 'onprem').length, go: { page: 'directory', source: onpremSource } },
      { icon: 'folder', label: 'OUs', n: ofKind('ou').length, go: { page: 'directory', source: onpremSource } },
      { icon: 'document', label: 'GPOs', n: ofKind('gpo').length, go: { page: 'directory', source: onpremSource } },
      { icon: 'cloud', label: 'Entra users', n: ofKind('user', 'cloud').length, go: { page: 'directory', source: cloudSource } },
      { icon: 'personKey', label: 'Entra roles', n: ofKind('role').length, go: { page: 'directory', source: cloudSource } },
      { icon: 'apps', label: 'Applications', n: ofKind('app').length, go: { page: 'directory', source: cloudSource } },
    ];
    return all.filter((t) => t.n > 0).slice(0, 6);
  });
  const collectedAt = $derived(view.runs[0]?.manifest.finished_at ?? view.runs[0]?.manifest.started_at);
  const hygiene = $derived.by(() => {
    if (!dir) return [];
    const users = ofKind('user', 'onprem');
    const enabled = users.filter((u) => u.enabled !== false);
    const stale = enabled.filter((u) => (daysSince(u.last_logon, collectedAt) ?? 0) > 90 || !u.last_logon);
    const oldPwd = enabled.filter((u) => (daysSince(u.password_last_set, collectedAt) ?? 0) > 365);
    const disabled = users.filter((u) => u.enabled === false);
    const t0 = dir.objects.filter((o) => o.tier0);
    const pct = (n: number, of: number) => (of ? Math.round((n / of) * 100) : 0);
    return [
      { label: 'Stale enabled users', n: stale.length, of: enabled.length, note: `${pct(stale.length, enabled.length)}% of enabled AD users, no logon in 90 days`, colour: 'var(--sev-high)' },
      { label: 'Passwords older than a year', n: oldPwd.length, of: enabled.length, note: `${pct(oldPwd.length, enabled.length)}% of enabled AD users`, colour: 'var(--sev-medium)' },
      { label: 'Disabled users', n: disabled.length, of: users.length, note: `${pct(disabled.length, users.length)}% of AD users`, colour: 'var(--border-strong)' },
      { label: 'Tier 0 objects', n: t0.length, of: dir.objects.length, note: 'Objects that control the directory', colour: 'var(--sev-critical)' },
    ];
  });
</script>

<div class="dash">
  <div class="hero">
    <div class="score">
      <span class="lbl">Security score{group === 'all' ? '' : `, ${groupTabs.find((t) => t.id === group)?.title}`}</span>
      {#if score != null}
        <span class="big num">{score}<small>/100</small></span>
      {:else}
        <span class="big none">Not scored</span>
      {/if}
    </div>
    <span class="spacer"></span>
    {#if groupTabs.length > 2}
      <div class="seg" role="group" aria-label="Show">
        {#each groupTabs as t (t.id)}
          <button class:on={group === t.id} aria-pressed={group === t.id} onclick={() => (group = t.id)}>{t.title}</button>
        {/each}
      </div>
    {/if}
  </div>

  <section class="coverage" aria-label="Checks in this run">
    <div class="covtop"><span>Checks in this run</span><span class="num">{plural(total, 'check')}</span></div>
    {#if total}
      <div class="covbar">
        {#if status.passed}
          <div class="pass" style:flex-grow={status.passed}><span>{num(status.passed)} passed</span><span class="tick"><Icon name="checkmark" size={18} /></span></div>
        {/if}
        {#if failed.length}
          <button class="fail" style:flex-grow={failed.length} onclick={() => go({ page: 'findings', group: group === 'all' ? undefined : group })}>
            <span>{num(failed.length)} failed</span><span class="tick"><Icon name="warning" size={18} /></span>
          </button>
        {/if}
        {#if status.accepted}
          <div class="acc" style:flex-grow={status.accepted}><span>{num(status.accepted)} accepted</span></div>
        {/if}
        {#if status.notAssessed}
          <div class="na striped" style:flex-grow={status.notAssessed}><span>{num(status.notAssessed)} not assessed</span></div>
        {/if}
      </div>
    {/if}
  </section>

  <div class="cols">
    <div class="stack">
      <section class="panel">
        <div class="panel-h"><h4>Areas</h4><span class="muted small">score out of 100</span></div>
        <div class="panel-b">
          <div class="gauges">
            {#each view.summary.groups as g, i (g.id)}
              <button class="gauge" onclick={() => go({ page: 'findings', group: g.id })} title="{g.title} findings">
                <svg viewBox="0 0 84 48" aria-hidden="true">
                  <path d="M8 44 A34 34 0 0 1 76 44" class="track" />
                  {#if g.score != null}
                    <path d="M8 44 A34 34 0 0 1 76 44" class="arc" stroke={gaugeColours[i % gaugeColours.length]} stroke-dasharray="{(g.score / 100) * ARC} {ARC}" />
                  {/if}
                </svg>
                <strong class="num">{g.score ?? '–'}</strong>
                <span>{g.id === 'onprem' ? 'On-premises' : g.title.replace('Microsoft ', '')}</span>
              </button>
            {/each}
          </div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-h">
          <h4>Findings by severity</h4>
          <button class="linkbtn small" onclick={() => go({ page: 'findings', group: group === 'all' ? undefined : group })}>View all</button>
        </div>
        <div class="panel-b">
          <div class="sevbar" aria-hidden="true">
            {#each SEVERITIES as s (s)}
              {#if counts[s]}<span style:flex-grow={counts[s] / sevTotal} style:background="var(--sev-{s}-bg)"></span>{/if}
            {/each}
          </div>
          <div class="legend">
            {#each SEVERITIES as s (s)}
              <button class="plainbtn" onclick={() => go({ page: 'findings', severity: s, group: group === 'all' ? undefined : group })}>
                <i style:background="var(--sev-{s}-bg)"></i>{severityMeta[s].label}<b class="num">{counts[s]}</b>
              </button>
            {/each}
          </div>
        </div>
      </section>

      {#if hygiene.length}
        <section class="panel">
          <div class="panel-h"><h4>Identity hygiene</h4></div>
          <div class="panel-b hyg">
            {#each hygiene as h (h.label)}
              <div>
                <div class="line"><span class="grow">{h.label}</span><strong class="num">{num(h.n)}</strong></div>
                <div class="meter"><span style:width="{h.of ? (h.n / h.of) * 100 : 0}%" style:background={h.colour}></span></div>
                <span class="muted small">{h.note}</span>
              </div>
            {/each}
          </div>
        </section>
      {/if}
    </div>

    <section class="tabbed">
      <div class="ptabs" role="tablist" aria-label="Dashboard">
        {#each tabs as t (t.id)}
          <button role="tab" id="dt-{t.id}" class:on={tab === t.id} aria-selected={tab === t.id} aria-controls="dp" onclick={() => (tab = t.id)}>{t.label}</button>
        {/each}
      </div>
      <div class="pbody" role="tabpanel" id="dp" aria-labelledby="dt-{tab}">
        {#if tab === 'risks'}
          <div class="ph"><h3 class="grp">Open</h3><button class="linkbtn small" onclick={() => go({ page: 'findings' })}>All findings</button></div>
          <ul class="tl">
            {#each top as f (findingKey(f))}
              <li>
                <span class="node"><span class="dot" style:background="var(--sev-{f.severity}-bg)"><Icon name={severityMeta[f.severity].icon} size={18} /></span><span class="vline"></span></span>
                <button class="item" onclick={() => go({ page: 'finding', key: findingKey(f) })}>
                  <span class="row"><span class="ttl">{f.title}</span><SevBadge severity={f.severity} /></span>
                  <span class="meta"><span class="mono">{f.id}</span><i></i><span>{f.area_title}</span>{#if affectedText(f)}<i></i><span>{affectedText(f)} affected</span>{/if}</span>
                </button>
              </li>
            {:else}
              <li class="muted">No failed checks.</li>
            {/each}
          </ul>
        {:else if tab === 'paths'}
          <div class="kpi"><span class="value">{view.paths.length}</span><span class="label">paths from less privileged principals to Tier 0</span></div>
          <div class="badges">
            {#each SEVERITIES as s (s)}
              {@const n = view.paths.filter((p) => p.severity === s).length}
              {#if n}<SevBadge severity={s} label="{n} {severityMeta[s].label}" />{/if}
            {/each}
          </div>
          {#if view.choke_points.length}
            <h3 class="grp">Fix first</h3>
            <ol class="fixes">
              {#each view.choke_points.slice(0, 5) as c (c.check)}
                <li class="item">{c.title}<span class="muted small">breaks {plural(c.paths, 'path')}</span></li>
              {/each}
            </ol>
          {/if}
          <div><button class="btn" onclick={() => go({ page: 'paths' })}>Open attack paths<Icon name="arrowRight" size={16} /></button></div>
        {:else if tab === 'areas'}
          <div class="ph">
            <span class="legend-inline small muted">
              <span><i class="h-crit"></i>below 40</span><span><i class="h-high"></i>40–59</span><span><i class="h-med"></i>60–79</span><span><i class="h-ok"></i>80+</span>
            </span>
          </div>
          <div class="heat">
            {#each areas as a (a.code)}
              <button class={heat(a.score)} onclick={() => go({ page: 'findings', area: a.code })} title={a.title}>
                <span class="code">{a.code}</span>
                <span class="small clip">{a.title}</span>
                <span class="score">{a.score ?? '–'}</span>
              </button>
            {/each}
          </div>
        {:else if tab === 'mitre'}
          <div class="bars">
            {#each tactics as t (t.tactic)}
              <div class="hbar tactic"><span class="small">{t.tactic}</span><span class="track"><span style:width="{(t.findings / maxTactic) * 100}%" style:background="var(--violet)"></span></span><span class="num r">{t.findings}</span></div>
            {:else}
              <p class="muted">No failed check is mapped to MITRE ATT&amp;CK yet.</p>
            {/each}
          </div>
        {:else}
          <p class="muted small">{scopeText(view.runs[0].manifest)}</p>
          <div class="kpis four">
            <div class="kpi"><span class="label">Failed</span><span class="value small-value">{num(failed.length)}</span></div>
            <div class="kpi"><span class="label">Passed</span><span class="value small-value">{num(status.passed)}</span></div>
            <div class="kpi"><span class="label">Not assessed</span><span class="value small-value">{num(status.notAssessed)}</span></div>
            <div class="kpi"><span class="label">Accepted</span><span class="value small-value">{num(status.accepted)}</span></div>
          </div>
          {#if notAssessed.length}
            <ul class="notes">
              {#each notAssessed.slice(0, 8) as f (findingKey(f))}
                <li class="item"><span class="mono muted">{f.id}</span>{f.note ?? 'Not assessed'}</li>
              {/each}
            </ul>
          {/if}
        {/if}
      </div>
    </section>

    <div class="stack side">
      <section class="panel">
        <div class="panel-h"><h4>Directory</h4>{#if dir}<button class="linkbtn small" onclick={() => go({ page: 'directory' })}>Explore</button>{/if}</div>
        <div class="panel-b">
          {#if dir}
            <div class="glance">
              {#each glance as t (t.label)}
                <button class="tile plainbtn" onclick={() => go(t.go)}>
                  <span class="ti"><Icon name={t.icon} size={18} /></span>
                  <span class="tlab">{t.label}</span>
                  <span class="tv num">{num(t.n)}</span>
                </button>
              {/each}
            </div>
          {:else}
            <p class="muted">Directory telemetry was not collected in this run.</p>
          {/if}
        </div>
      </section>

      {#if onExport}
        <h3 class="side-h">Reports</h3>
        {#each [{ t: 'Executive summary', f: 'PDF or HTML', icon: 'document' }, { t: 'Technical report', f: 'PDF or HTML', icon: 'textTree' }, { t: 'Remediation plan', f: 'XLSX or CSV', icon: 'checkmarkCircle' }] as r (r.t)}
          <button class="file" onclick={onExport}>
            <span class="fi"><Icon name={r.icon as import('../lib/icons').IconName} size={18} /></span>
            <span class="ft"><small>{r.t}</small>{r.f}</span>
            <span class="fr"><Icon name="arrowDownload" size={16} /></span>
          </button>
        {/each}
      {/if}
    </div>
  </div>
</div>

<style>
  .dash {
    display: flex;
    flex-direction: column;
    gap: 20px;
    padding: 8px 28px 28px 8px;
  }

  .hero {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: 16px 24px;
  }

  .score {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .lbl {
    color: var(--text-muted);
  }

  .big {
    font-family: var(--font-display);
    font-weight: 300;
    font-size: 78px;
    line-height: 0.95;
    letter-spacing: -0.03em;
  }

  .big small {
    font-size: 30px;
    color: var(--text-muted);
    letter-spacing: 0;
  }

  .big.none {
    font-size: 40px;
    color: var(--text-muted);
  }

  .coverage {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .covtop {
    display: flex;
    justify-content: space-between;
    color: var(--text-muted);
  }

  .covbar {
    display: flex;
    gap: 6px;
    height: 50px;
  }

  .covbar > * {
    flex: 1 1 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 0 6px 0 16px;
    border: none;
    border-radius: 16px;
    color: var(--ink);
    font: inherit;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    min-width: 150px;
  }

  .covbar .pass {
    background: var(--ok-bg);
  }

  .covbar .fail {
    background: var(--salmon);
    cursor: pointer;
    transition: filter var(--transition);
  }

  .covbar .fail:hover {
    filter: brightness(1.04) saturate(1.1);
  }

  .covbar .fail:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .covbar .acc {
    background: var(--lilac);
    min-width: 130px;
  }

  .covbar .na {
    color: var(--text);
    justify-content: flex-end;
    padding-right: 16px;
    min-width: 170px;
  }

  .covbar .na span {
    padding: 4px 10px;
    border-radius: 999px;
    background: var(--bg);
  }

  .tick {
    width: 38px;
    height: 38px;
    border-radius: 12px;
    background: rgb(255 255 255 / 0.5);
    display: grid;
    place-items: center;
    flex: none;
  }

  .cols {
    display: grid;
    grid-template-columns: 300px minmax(0, 1fr) 260px;
    gap: 18px;
    align-items: start;
  }

  .stack {
    display: flex;
    flex-direction: column;
    gap: 18px;
    min-width: 0;
  }

  .gauges {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px 6px;
  }

  .gauge {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    padding: 4px 0;
    border: none;
    border-radius: 14px;
    background: none;
    color: var(--text-muted);
    font: inherit;
    font-size: 12.5px;
    text-align: center;
    cursor: pointer;
  }

  .gauge:hover {
    background: var(--surface-raised);
  }

  .gauge svg {
    width: 80px;
    height: 46px;
    fill: none;
    stroke-width: 7;
    stroke-linecap: round;
  }

  .gauge .track {
    stroke: var(--border);
  }

  .gauge .arc {
    animation: dash-arc 800ms cubic-bezier(0.3, 0.6, 0.2, 1) both;
  }

  @keyframes dash-arc {
    from {
      stroke-dasharray: 0 999;
    }
  }

  .gauge strong {
    font-size: 22px;
    font-weight: 400;
    color: var(--text);
    margin-top: -28px;
    margin-bottom: 6px;
  }

  .sevbar {
    display: flex;
    gap: 4px;
    height: 14px;
  }

  .sevbar span {
    border-radius: 7px;
    min-width: 8px;
  }

  .legend {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 4px 14px;
  }

  .legend button {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 6px;
    margin: 0 -6px;
    border-radius: 8px;
  }

  .legend button:hover {
    background: var(--surface-raised);
  }

  .legend i {
    width: 10px;
    height: 10px;
    border-radius: 4px;
    flex: none;
  }

  .legend b {
    margin-left: auto;
    font-weight: 500;
  }

  .plainbtn {
    border: none;
    background: none;
    padding: 0;
    font: inherit;
    color: var(--text);
    text-align: left;
    cursor: pointer;
  }

  .hyg {
    gap: 14px;
  }

  .hyg > div {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .line {
    display: flex;
  }

  .grow {
    flex: 1 1 auto;
  }

  /* Main panel: the chosen tab is joined to the panel, the others are pills */
  .tabbed {
    min-width: 0;
  }

  .ptabs {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: 6px;
  }

  .ptabs button {
    position: relative;
    height: 40px;
    padding: 0 16px;
    border: none;
    border-radius: 18px 18px 0 0;
    background: color-mix(in srgb, var(--surface) 55%, transparent);
    color: var(--text-muted);
    font: inherit;
    font-size: 14px;
    cursor: pointer;
    transition: background var(--transition), color var(--transition);
  }

  .ptabs button:hover:not(.on) {
    color: var(--text);
    background: color-mix(in srgb, var(--surface) 80%, transparent);
  }

  .ptabs button.on {
    height: 50px;
    padding: 0 24px;
    border-radius: 22px 22px 0 0;
    background: var(--surface);
    color: var(--text);
    font-size: 16px;
  }

  .ptabs button.on:not(:first-child)::before,
  .ptabs button.on::after {
    content: '';
    position: absolute;
    bottom: 0;
    width: 22px;
    height: 22px;
  }

  .ptabs button.on::after {
    right: -22px;
    background: radial-gradient(circle at 100% 0, transparent 21px, var(--surface) 22px);
  }

  .ptabs button.on:not(:first-child)::before {
    left: -22px;
    background: radial-gradient(circle at 0 0, transparent 21px, var(--surface) 22px);
  }

  .ptabs button:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }

  .pbody {
    background: var(--surface);
    border-radius: 0 26px 26px 26px;
    padding: 22px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    min-height: 420px;
  }

  .ph {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .grp {
    font-size: 22px;
    font-weight: 400;
    color: var(--text);
  }

  .tl {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
  }

  .tl li {
    display: grid;
    grid-template-columns: 48px minmax(0, 1fr);
    gap: 12px;
  }

  .node {
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  .dot {
    width: 44px;
    height: 44px;
    border-radius: 15px;
    display: grid;
    place-items: center;
    color: var(--ink);
    flex: none;
  }

  .vline {
    width: 1px;
    flex: 1 1 auto;
    min-height: 12px;
    background: var(--border);
  }

  .tl li:last-child .vline {
    visibility: hidden;
  }

  button.item {
    margin-bottom: 10px;
    border: none;
    font: inherit;
    color: var(--text);
    text-align: left;
    cursor: pointer;
    transition: background var(--transition), transform var(--transition);
  }

  button.item:hover {
    transform: translateX(2px);
  }

  button.item:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .item .row {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .item .ttl {
    flex: 1 1 auto;
    font-size: 15.5px;
  }

  .meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 10px;
    color: var(--text-muted);
    font-size: 13px;
  }

  .meta i {
    width: 3px;
    height: 3px;
    border-radius: 50%;
    background: var(--text-muted);
  }

  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .fixes,
  .notes {
    margin: 0;
    padding: 0;
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .fixes .item,
  .notes .item {
    flex-direction: row;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 6px 12px;
  }

  .notes .item {
    justify-content: flex-start;
    font-size: 13.5px;
  }

  .legend-inline {
    display: inline-flex;
    gap: 12px;
  }

  .legend-inline span {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }

  .legend-inline i {
    width: 12px;
    height: 12px;
    border-radius: 4px;
  }

  .clip {
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .bars {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .hbar.tactic {
    grid-template-columns: 190px 1fr 36px;
  }

  .r {
    text-align: right;
  }

  .kpis {
    display: grid;
    gap: 18px 12px;
  }

  .kpis.four {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }

  .small-value {
    font-size: 30px !important;
  }

  .glance {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .tile {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 10px 8px 8px;
    border-radius: 14px;
    transition: background var(--transition);
  }

  .tile:hover {
    background: var(--surface-raised);
  }

  .ti {
    display: grid;
    place-items: center;
    width: 34px;
    height: 34px;
    border-radius: 11px;
    background: var(--surface-raised);
    color: var(--text);
    flex: none;
  }

  .tlab {
    flex: 1 1 auto;
  }

  .tv {
    font-size: 18px;
  }

  .side-h {
    font-size: 22px;
    font-weight: 400;
    color: var(--text);
    padding: 6px 4px 0;
  }

  .file {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 12px 12px 14px;
    border: none;
    border-radius: 22px;
    background: var(--surface);
    color: var(--text);
    font: inherit;
    text-align: left;
    cursor: pointer;
    transition: background var(--transition);
  }

  .file:hover {
    background: var(--surface-raised);
  }

  .fi {
    display: grid;
    place-items: center;
    width: 38px;
    height: 38px;
    border-radius: 12px;
    background: var(--lilac);
    color: var(--ink);
    flex: none;
  }

  .ft {
    flex: 1 1 auto;
    display: flex;
    flex-direction: column;
  }

  .ft small {
    color: var(--text-muted);
    font-size: 12.5px;
  }

  .fr {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    border: 1px solid var(--border-strong);
    flex: none;
  }

  .plainbtn:focus-visible,
  .file:focus-visible,
  .gauge:focus-visible,
  .tile:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  @media (max-width: 1320px) {
    .cols {
      grid-template-columns: 290px minmax(0, 1fr);
    }

    .side {
      grid-column: 1 / -1;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    }

    .side-h {
      grid-column: 1 / -1;
    }
  }

  @media (max-width: 980px) {
    .cols {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
