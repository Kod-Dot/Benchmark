<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import type { IconName } from '../lib/icons';
  import { date, num } from '../lib/format';
  import type { AssessmentView, ExportedPage, Listing } from '../lib/types';
  import { findingKey, type Route } from './route';
  import Dashboard from './Dashboard.svelte';
  import Findings from './Findings.svelte';
  import FindingDetail from './FindingDetail.svelte';
  import AttackPaths from './AttackPaths.svelte';
  import Hunting from './Hunting.svelte';
  import Compliance from './Compliance.svelte';
  import Ages from './Ages.svelte';
  import Compare from './Compare.svelte';
  import Directory from './Directory.svelte';
  import ObjectDetail from './ObjectDetail.svelte';
  import Graph from './Graph.svelte';
  import CommandPalette, { type PaletteCommand } from '../components/CommandPalette.svelte';
  import Toast from '../components/Toast.svelte';
  import { compromised } from '../lib/marks.svelte';
  import { externalLinks } from '../lib/external';
  import { applyTheme, savedTheme, type Theme } from '../lib/theme';

  let {
    view,
    listing,
    example,
    onHome,
    onOpen,
    onExport,
    onReload,
    onSettings,
    offline = null,
  }: {
    view: AssessmentView;
    listing: Listing | null;
    example: boolean;
    onHome: () => void;
    onOpen: (paths: string[]) => Promise<string | null>;
    onExport?: () => void;
    /** Reloads the open assessments, after a risk is accepted or withdrawn. */
    onReload?: () => Promise<void>;
    onSettings?: () => void;
    /** Set when this is an exported offline dashboard. */
    offline?: ExportedPage | null;
  } = $props();

  let route = $state<Route>({ page: 'dashboard' });
  // Marks belong to the assessment being explored.
  compromised.clear();
  let history: Route[] = [];
  let canBack = $state(false);
  let main: HTMLElement | undefined = $state();

  function go(next: Route) {
    history.push(route);
    canBack = true;
    route = next;
    main?.scrollTo(0, 0);
  }

  function back() {
    route = history.pop() ?? { page: 'dashboard' };
    canBack = history.length > 0;
  }

  let theme = $state<Theme>(savedTheme());
  const themes: { id: Theme; label: string; icon: IconName }[] = [
    { id: 'light', label: 'Light theme', icon: 'weatherSunny' },
    { id: 'dark', label: 'Dark theme', icon: 'weatherMoon' },
    { id: 'system', label: 'Same as Windows', icon: 'desktop' },
  ];

  function setTheme(t: Theme) {
    theme = t;
    applyTheme(t, true);
  }

  const failed = $derived(view.findings.filter((f) => f.status === 'failed'));
  const countIn = (group: string) => failed.filter((f) => f.group === group).length;
  const groups = $derived(
    view.summary.groups.filter((g) => g.id !== 'hunting').map((g) => ({ ...g, count: countIn(g.id) })),
  );
  const hasHunts = $derived(view.findings.some((f) => f.group === 'hunting'));
  const objectCount = $derived(view.directory?.objects.length ?? 0);
  const groupIcon: Record<string, IconName> = {
    onprem: 'building',
    entra: 'cloud',
    hybrid: 'branchFork',
    m365: 'apps',
    azure: 'globe',
    endpoints: 'desktop',
    baselines: 'document',
  };

  const navTitle: Record<string, string> = { onprem: 'On-premises AD', entra: 'Entra ID', m365: 'Microsoft 365', endpoints: 'Endpoints' };

  const title = $derived(view.runs.map((r) => r.name).join(' + '));
  // Scope chips: domains in sky, the tenant in lilac, as in the plan.
  const scopeChips = $derived.by(() => {
    const out: { label: string; tone: string; icon: IconName }[] = [];
    const seen = new Set<string>();
    for (const r of view.runs) {
      for (const d of r.manifest.scope.domains)
        if (!seen.has(d)) {
          seen.add(d);
          out.push({ label: d, tone: 'sky', icon: 'building' });
        }
      const t = r.manifest.scope.tenant;
      if (t && !seen.has(t)) {
        seen.add(t);
        out.push({ label: t, tone: 'lilac', icon: 'cloud' });
      }
    }
    return out;
  });
  const collected = $derived(view.runs.length === 1 ? view.runs[0].manifest.finished_at ?? view.runs[0].manifest.started_at : null);

  // Ctrl+K: jump anywhere. Ctrl+F: the search box of the page on screen.
  let paletteOpen = $state(false);

  function onKey(e: KeyboardEvent) {
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      paletteOpen = true;
    } else if (mod && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      const find = main?.querySelector<HTMLInputElement>('input[data-find]');
      if (find) {
        find.focus();
        find.select();
      } else paletteOpen = true;
    } else if (e.key === 'Escape' && (route.page === 'finding' || route.page === 'object') && !e.defaultPrevented) {
      // Esc leaves a detail page, unless focus is in a field or dialog.
      const t = e.target as HTMLElement;
      if (t.closest('input, textarea, select, dialog, [role="dialog"]')) return;
      back();
    }
  }

  const hasAccounts = $derived(view.directory?.objects.some((o) => o.kind === 'user' || o.kind === 'computer') ?? false);
  const navActive = (page: Route['page'], group?: string) =>
    route.page === page && (group === undefined || (route.page === 'findings' && route.group === group));

  const commands = $derived.by(() => {
    const out: PaletteCommand[] = [{ label: 'Dashboard', icon: 'board', run: { page: 'dashboard' } }];
    out.push({ label: 'All findings', icon: 'filter', hint: `${num(failed.length)} failed`, run: { page: 'findings' } });
    for (const g of groups)
      out.push({ label: `${navTitle[g.id] ?? g.title} findings`, icon: groupIcon[g.id] ?? 'document', hint: `${num(g.count)} failed`, run: { page: 'findings', group: g.id } });
    if (view.directory) {
      out.push({ label: 'Directory', icon: 'organization', hint: `${num(objectCount)} objects`, keywords: 'users computers groups ou telemetry', run: { page: 'directory' } });
      out.push({ label: 'Relationship graph', icon: 'peopleTeam', keywords: 'members edges', run: { page: 'graph' } });
      if (hasAccounts) out.push({ label: 'Account ages', icon: 'clock', keywords: 'stale password last logon', run: { page: 'ages' } });
    }
    out.push({ label: 'Attack paths', icon: 'shieldError', hint: `${num(view.paths.length)} paths`, keywords: 'tier 0', run: { page: 'paths' } });
    if (hasHunts) out.push({ label: 'Threat hunting', icon: 'search', keywords: 'events hunt', run: { page: 'hunting' } });
    out.push({ label: 'Compliance', icon: 'shieldCheckmark', keywords: 'cis nist iso mitre framework', run: { page: 'compliance' } });
    if (!offline) {
      out.push({ label: 'Compare and combine', icon: 'arrowSwap', keywords: 'diff changes runs', run: { page: 'compare' } });
      if (onExport) out.push({ label: 'Export reports', icon: 'arrowDownload', keywords: 'pdf html csv xlsx sarif report', run: onExport });
      if (onSettings) out.push({ label: 'Settings', icon: 'settings', keywords: 'preferences theme', run: onSettings });
      out.push({ label: 'Start screen', icon: 'arrowLeft', keywords: 'home assessments', run: onHome });
    }
    return out;
  });
</script>

<svelte:window onkeydown={onKey} />

{#snippet railBtn(label: string, icon: IconName, active: boolean, onclick: () => void, badge?: number)}
  {@const count = badge ? (badge > 999 ? '999+' : num(badge)) : ''}
  <button class="rbtn" class:on={active} aria-label={count ? `${label} ${count}` : label} aria-current={active ? 'page' : undefined} {onclick}>
    <Icon name={icon} />
    <span class="tip" aria-hidden="true">{label}</span>
    {#if count}{' '}<span class="badge">{count}</span>{/if}
  </button>
{/snippet}

<div class="ws">
  <nav class="rail" aria-label="Assessment">
    {#if offline}
      <span class="mark"><Logo kind="mark" height={30} /></span>
    {:else}
      <button class="mark" onclick={onHome} aria-label="Home, all assessments"><Logo kind="mark" height={30} /></button>
    {/if}
    <div class="rail-items">
      {@render railBtn('Dashboard', 'board', navActive('dashboard'), () => go({ page: 'dashboard' }))}
      {@render railBtn('Findings', 'filter', route.page === 'findings' || route.page === 'finding', () => go({ page: 'findings' }), failed.length)}
      {#if view.directory}
        {@render railBtn('Directory', 'organization', navActive('directory') || navActive('object'), () => go({ page: 'directory' }))}
        {@render railBtn('Relationship graph', 'peopleTeam', navActive('graph'), () => go({ page: 'graph' }))}
        {#if hasAccounts}
          {@render railBtn('Account ages', 'clock', navActive('ages'), () => go({ page: 'ages' }))}
        {/if}
      {/if}
      {@render railBtn('Attack paths', 'shieldError', navActive('paths'), () => go({ page: 'paths' }))}
      {#if hasHunts}
        {@render railBtn('Threat hunting', 'search', navActive('hunting'), () => go({ page: 'hunting' }))}
      {/if}
      {@render railBtn('Compliance', 'shieldCheckmark', navActive('compliance'), () => go({ page: 'compliance' }))}
      {#if !offline}
        {@render railBtn('Compare and combine', 'arrowSwap', navActive('compare'), () => go({ page: 'compare' }))}
      {/if}
    </div>
    <span class="rail-spacer"></span>
    <div class="themepill" role="group" aria-label="Theme">
      {#each themes as t (t.id)}
        <button class:on={theme === t.id} aria-pressed={theme === t.id} aria-label={t.label} title={t.label} onclick={() => setTheme(t.id)}>
          <Icon name={t.icon} size={18} />
        </button>
      {/each}
    </div>
    {#if !offline}
      {#if onSettings}{@render railBtn('Settings', 'settings', false, onSettings)}{/if}
      {@render railBtn('Home', 'home', false, onHome)}
    {/if}
  </nav>

  <header class="bar">
    {#if canBack}
      <button class="back" onclick={back} aria-label="Back"><Icon name="arrowLeft" /></button>
    {/if}
    <h1 class="title">{title}</h1>
    <div class="chips">
      {#each scopeChips as c (c.label)}<span class="chip {c.tone}"><Icon name={c.icon} size={14} />{c.label}</span>{/each}
      {#if example}<span class="chip plain">Example data</span>{/if}
      {#if offline?.branding.classification}<span class="chip classification">{offline.branding.classification}</span>{/if}
    </div>
    <span class="spacer"></span>
    <button class="search opener" onclick={() => (paletteOpen = true)} aria-keyshortcuts="Control+K">
      <Icon name="search" size={16} />
      <span class="ph">Search checks, objects and pages</span>
      <span class="kbd">Ctrl K</span>
    </button>
    {#if !offline}
      <button class="btn round" onclick={() => go({ page: 'compare' })} aria-label="Compare" title="Compare"><Icon name="arrowSwap" /></button>
      <button class="btn primary" onclick={onExport} disabled={!onExport}><Icon name="arrowDownload" />Export report</button>
    {/if}
  </header>

  <main class="main" data-scroller bind:this={main} use:externalLinks>
    {#key route}
    <div class="page enter-page">
    {#if route.page === 'dashboard'}
      <Dashboard {view} {go} {onExport} />
    {:else if route.page === 'findings'}
      {#key route}
        <Findings {view} {go} initial={route} />
      {/key}
    {:else if route.page === 'finding'}
      {@const key = route.key}
      {@const f = view.findings.find((x) => findingKey(x) === key)}
      {#if f}
        <FindingDetail finding={f} {view} {go} {onReload} />
      {/if}
    {:else if route.page === 'paths'}
      <AttackPaths {view} {go} />
    {:else if route.page === 'hunting'}
      <Hunting {view} {go} />
    {:else if route.page === 'compliance'}
      <Compliance {view} {go} />
    {:else if route.page === 'compare' && !offline}
      <Compare {view} {listing} {go} {onOpen} />
    {:else if route.page === 'directory' && view.directory}
      <Directory directory={view.directory} {go} initial={route} />
    {:else if route.page === 'ages' && view.directory}
      <Ages directory={view.directory} {go} />
    {:else if route.page === 'object' && view.directory}
      {#key route.id}
        <ObjectDetail id={route.id} {view} {go} />
      {/key}
    {:else if route.page === 'graph' && view.directory}
      {#key route.id}
        <Graph directory={view.directory} {go} focus={route.id} findings={view.findings} />
      {/key}
    {/if}
    </div>
    {/key}
  </main>

  <footer class="statusbar">
    {#if collected}<span>Collected {date(collected, true)}</span>{/if}
    <span>Catalog {view.catalog_version}</span>
    {#if offline}
      <span>Offline copy exported {date(offline.generated_at, true)}{offline.branding.organization ? ` for ${offline.branding.organization}` : ''}</span>
      {#if offline.pseudonymized}<span>Names are pseudonyms</span>{/if}
    {:else}
      {#each view.runs as r (r.path)}<span class="mono">{r.path}</span>{/each}
    {/if}
    <span class="spacer"></span>
    <span>Read-only assessment</span>
  </footer>
</div>

<CommandPalette bind:open={paletteOpen} {view} {commands} {go} />
<Toast />

<style>
  /* Shell: icon rail on the left, top bar, the page, a quiet status line. */
  .ws {
    height: 100%;
    display: grid;
    grid-template-columns: 84px minmax(0, 1fr);
    grid-template-rows: auto minmax(0, 1fr) auto;
  }

  .rail {
    grid-row: 1 / 4;
    position: relative;
    z-index: 20;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
    padding: 18px 0 14px;
    overflow: visible;
  }

  .mark {
    display: grid;
    place-items: center;
    width: 50px;
    height: 50px;
    margin-bottom: 18px;
    border: none;
    border-radius: 15px;
    background: none;
    color: var(--text);
    cursor: pointer;
  }

  span.mark {
    cursor: default;
  }

  .rail-items {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .rail-spacer {
    flex: 1 1 auto;
    min-height: 24px;
  }

  .rbtn {
    position: relative;
    width: 48px;
    height: 48px;
    display: grid;
    place-items: center;
    border: none;
    border-radius: 15px;
    background: var(--rail);
    color: var(--text);
    cursor: pointer;
    transition:
      background var(--transition),
      color var(--transition),
      transform var(--transition);
  }

  .rbtn:not(.on):hover {
    background: var(--rail-hover);
    transform: translateY(-1px);
  }

  .rbtn.on {
    background: var(--pill);
    color: var(--pill-fg);
  }

  .rbtn:focus-visible,
  .mark:focus-visible,
  .themepill button:focus-visible,
  .back:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }

  .badge {
    position: absolute;
    top: -5px;
    right: -7px;
    min-width: 22px;
    height: 19px;
    padding: 0 6px;
    border-radius: 10px;
    background: var(--salmon);
    color: var(--ink);
    font-size: 11px;
    font-weight: 600;
    line-height: 19px;
    text-align: center;
    font-variant-numeric: tabular-nums;
  }

  /* The name of a rail button slides out in a pill on hover or keyboard focus */
  .tip {
    position: absolute;
    left: calc(100% + 12px);
    top: 50%;
    height: 34px;
    padding: 0 16px 0 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    border-radius: 999px;
    background: var(--pill);
    color: var(--pill-fg);
    font-size: 13.5px;
    font-weight: 500;
    white-space: nowrap;
    pointer-events: none;
    opacity: 0;
    transform: translate(-10px, -50%) scale(0.9);
    transform-origin: left center;
    box-shadow: var(--shadow-pop);
    transition:
      opacity 160ms ease,
      transform 260ms var(--spring);
  }

  .tip::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--mint);
  }

  .rbtn:hover .tip,
  .rbtn:focus-visible .tip {
    opacity: 1;
    transform: translate(0, -50%) scale(1);
  }

  .themepill {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 4px;
    margin-bottom: 4px;
    border-radius: 999px;
    background: var(--rail);
  }

  .themepill button {
    width: 40px;
    height: 40px;
    display: grid;
    place-items: center;
    border: none;
    border-radius: 50%;
    background: none;
    color: var(--text-muted);
    cursor: pointer;
    transition: background var(--transition), color var(--transition);
  }

  .themepill button:hover:not(.on) {
    color: var(--text);
  }

  .themepill button.on {
    background: var(--pill);
    color: var(--pill-fg);
  }

  .bar {
    grid-column: 2;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px 14px;
    min-height: 82px;
    padding: 16px 28px 8px 8px;
  }

  .back {
    width: 38px;
    height: 38px;
    display: grid;
    place-items: center;
    border: none;
    border-radius: 50%;
    background: none;
    color: var(--text-muted);
    cursor: pointer;
  }

  .back:hover {
    color: var(--text);
    background: var(--surface);
  }

  .title {
    font-size: 26px;
    font-weight: 400;
    letter-spacing: -0.01em;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 46ch;
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 12px;
    border-radius: 999px;
    color: var(--ink);
    font-size: 13px;
    font-weight: 500;
    white-space: nowrap;
  }

  .chip.sky {
    background: var(--sky);
  }

  .chip.lilac {
    background: var(--lilac);
  }

  .chip.plain {
    color: var(--text);
    background: var(--surface);
  }

  .chip.classification {
    background: var(--salmon);
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  .opener {
    font: inherit;
    cursor: pointer;
    text-align: left;
    width: 340px;
  }

  .opener .ph {
    flex: 1 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .opener:hover {
    background: var(--surface-raised);
  }

  .bar .btn {
    height: 44px;
  }

  .bar .btn.round {
    width: 44px;
    background: var(--surface);
    border-color: transparent;
  }

  .bar .btn.round:hover {
    background: var(--surface-raised);
  }

  .main {
    grid-column: 2;
    min-width: 0;
    min-height: 0;
    overflow: auto;
    /* A block scroller, not flex: a flex scroll container mis-roots the
       sticky page toolbar (it pins above the scrollport), which left the
       table header floating in the middle of the list while scrolling. */
    display: block;
  }

  .page {
    /* Fills the scroller so full-height pages (graph, directory) still get
       their height now that .main is a block, not a flex column. */
    min-height: 100%;
    display: flex;
    flex-direction: column;
  }

  .statusbar {
    grid-column: 2;
    display: flex;
    flex-wrap: wrap;
    gap: 6px 20px;
    align-items: center;
    min-height: 34px;
    padding: 0 28px 0 8px;
    font-size: 12.5px;
    color: var(--text-muted);
  }

  @media (max-width: 900px) {
    .opener {
      width: 220px;
    }
  }
</style>
