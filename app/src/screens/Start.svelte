<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import type { IconName } from '../lib/icons';
  import Notice from '../components/Notice.svelte';
  import ScoreTrend from '../components/ScoreTrend.svelte';
  import ScoreRing from '../components/ScoreRing.svelte';
  import { inDesktopApp } from '../lib/backend';
  import { num, scopeText, scoreColour } from '../lib/format';
  import type { AssessmentEntry, CatalogSummary, Environment, Listing } from '../lib/types';

  let {
    environment,
    catalog,
    catalogError,
    listing,
    listingError,
    openError,
    onNew,
    onOpen,
    onBundle,
    importing,
    onSettings,
  }: {
    environment: Environment | null;
    catalog: CatalogSummary | null;
    catalogError: string | null;
    listing: Listing | null;
    listingError: string | null;
    openError: string | null;
    onNew: () => void;
    onOpen: (path: string) => void;
    onBundle: () => void;
    importing: boolean;
    onSettings: () => void;
  } = $props();

  const unavailable = inDesktopApp ? 'Not detected' : 'Desktop app only';

  function formatDate(iso: string | null) {
    if (!iso) return '';
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }
  const relative = (iso: string | null) => {
    if (!iso) return '';
    const d = Date.parse(iso);
    if (Number.isNaN(d)) return '';
    const days = Math.round((Date.now() - d) / 86_400_000);
    if (days <= 0) return 'today';
    if (days === 1) return 'yesterday';
    if (days < 30) return `${days} days ago`;
    if (days < 365) return `${Math.round(days / 30)} months ago`;
    return `${Math.round(days / 365)} years ago`;
  };

  const scopeOf = (a: AssessmentEntry) => scopeText(a.manifest) || (a.manifest.name ?? a.name);
  const recent = $derived(listing?.assessments ?? []);
  const groupIcon: Record<string, IconName> = { onprem: 'building', entra: 'cloud', hybrid: 'branchFork', m365: 'apps', azure: 'globe', endpoints: 'desktop', baselines: 'document', hunting: 'search' };
  const coverage = $derived(
    catalog
      ? (() => {
          const impl = catalog.implemented;
          const total = catalog.checks;
          return { impl, total, pct: total ? Math.round((impl / total) * 100) : 0 };
        })()
      : null,
  );
</script>

<main class="start" class:preview={!inDesktopApp}>
  <header class="hero">
    <div class="brand">
      <div>
        <h1><Logo height={46} /></h1>
        <p class="lede">Security posture, measured. Read-only assessment for Active Directory, Microsoft Entra ID, Microsoft 365, Azure and endpoints.</p>
      </div>
    </div>
    <div class="actions">
      <button class="btn primary lg" onclick={onNew}><Icon name="add" size={18} /> New assessment</button>
      <button class="btn lg" disabled={!inDesktopApp || importing} title={inDesktopApp ? 'A .zip of an assessment, or of collector output from a run with -Bundle' : 'Desktop app only'} onclick={onBundle}>
        <Icon name="folderOpen" size={18} /> {importing ? 'Opening bundle…' : 'Open bundle…'}
      </button>
      <button class="btn lg ghost" onclick={onSettings}><Icon name="settings" size={18} /> Settings</button>
    </div>
  </header>

  {#if !inDesktopApp}
    <Notice>
      This is a browser preview of the interface. Computer details and access checks are only available in the Benchmark desktop app on Windows. The assessments below are examples against reserved example domains, so the result screens can be reviewed.
    </Notice>
  {/if}

  <div class="top">
    <section class="panel span2">
      <div class="phead"><h3><Icon name="history" size={16} /> Recent assessments</h3>{#if recent.length}<span class="muted small">{num(recent.length)} in {inDesktopApp && listing ? 'this folder' : 'the examples'}</span>{/if}</div>
      {#if recent.length}
        <ul class="runs stagger">
          {#each recent.slice(0, 6) as a, i (a.path)}
            <li style="--i: {i}">
              <button class="run" onclick={() => onOpen(a.path)}>
                <ScoreRing score={a.manifest.score} size={48} stroke={5} />
                <span class="rmain">
                  <span class="rname">{a.manifest.name ?? a.name}</span>
                  <span class="rscope muted">{scopeOf(a)}</span>
                </span>
                <span class="rwhen muted small">{relative(a.manifest.finished_at ?? a.manifest.started_at)}<span class="block">{formatDate(a.manifest.finished_at ?? a.manifest.started_at)}</span></span>
                <Icon name="chevronRight" size={18} />
              </button>
            </li>
          {/each}
        </ul>
        {#if openError}<p class="error small">{openError}</p>{/if}
        {#if listing && listing.unreadable.length > 0}<p class="muted small pad">{num(listing.unreadable.length)} folder{listing.unreadable.length === 1 ? '' : 's'} could not be read.</p>{/if}
      {:else if listing}
        <div class="empty-state">
          <Icon name="board" size={28} />
          <p>No assessments yet.</p>
          <p class="muted small">Run one and it appears here. Start with <strong>New assessment</strong>.</p>
        </div>
      {:else}
        <p class="empty muted">{listingError ?? 'Loading…'}</p>
      {/if}
    </section>

    <section class="panel">
      <div class="phead"><h3><Icon name="desktop" size={16} /> This computer</h3></div>
      <dl class="facts">
        <dt>Computer</dt><dd>{environment?.computer ?? unavailable}</dd>
        <dt>Signed in</dt><dd>{environment?.user ?? unavailable}</dd>
        <dt>Domain</dt>
        <dd>{#if environment?.domain}{environment.domain}{:else if environment}<span class="muted">Not a domain account</span>{:else}{unavailable}{/if}</dd>
        <dt>Folder</dt><dd class="path">{#if listing}<code>{listing.dir}</code>{:else}{unavailable}{/if}</dd>
      </dl>
      {#if coverage}
        <div class="cov">
          <div class="covtop"><span>Check coverage</span><span class="num"><strong>{num(coverage.impl)}</strong> of {num(coverage.total)}</span></div>
          <div class="meter" style="--v: {coverage.pct}%"><span></span></div>
          <span class="muted small">{coverage.pct}% of the catalog runs in this version</span>
        </div>
      {/if}
    </section>
  </div>

  {#if listing && recent.length}
    <ScoreTrend assessments={recent} {onOpen} />
  {/if}

  <section class="panel">
    <div class="phead"><h3><Icon name="layer" size={16} /> Check catalog</h3>{#if catalog}<span class="muted small">{num(catalog.groups.reduce((n, g) => n + g.areas.length, 0))} areas · {num(catalog.checks)} checks</span>{/if}</div>
    {#if catalog}
      <ul class="cat">
        {#each catalog.groups as g (g.id)}
          {@const generated = g.areas.every((a) => a.generated)}
          {@const pct = generated || !g.checks ? 0 : Math.round((g.implemented / g.checks) * 100)}
          <li>
            <span class="cg"><span class="ci"><Icon name={groupIcon[g.id] ?? 'document'} size={16} /></span>{g.title}</span>
            <span class="muted small areas">{num(g.areas.length)} {g.areas.length === 1 ? 'area' : 'areas'}</span>
            {#if generated}
              <span class="muted small gen">Generated from baselines</span>
            {:else}
              <span class="cbar"><span class="cbfill" style="--v: {pct}%"></span></span>
              <span class="num cn"><strong>{num(g.implemented)}</strong> / {num(g.checks)}</span>
            {/if}
          </li>
        {/each}
      </ul>
    {:else}
      <p class="empty muted">{catalogError ?? 'Loading…'}</p>
    {/if}
  </section>
</main>

<style>
  .start {
    max-width: 1180px;
    margin: 0 auto;
    padding: var(--space-7) var(--space-6) var(--space-6);
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .hero {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .brand {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }

  h1 {
    display: flex;
    margin: 0;
  }

  .lede {
    margin-top: 4px;
    font-size: 15px;
    color: var(--text-muted);
    max-width: 560px;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
  }

  .btn.lg {
    height: 46px;
    padding: 0 22px;
  }

  .top {
    display: grid;
    grid-template-columns: 1.6fr 1fr;
    gap: var(--space-4);
    align-items: start;
  }

  .panel {
    background: var(--surface);
    border-radius: var(--radius-lg);
    padding: 20px 22px 22px;
  }

  .span2 {
    grid-column: auto;
  }

  .phead {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: var(--space-3);
  }

  .phead h3 {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 21px;
    font-weight: 400;
    color: var(--text);
  }

  .phead h3 :global(.icon) {
    color: var(--text-muted);
  }

  .runs {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .run {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    width: 100%;
    padding: 10px 16px 10px 10px;
    border: 1px solid transparent;
    border-radius: var(--radius-item);
    background: var(--surface-raised);
    color: var(--text);
    font: inherit;
    text-align: left;
    cursor: pointer;
    transition:
      background var(--transition),
      border-color var(--transition),
      transform var(--transition);
  }

  .run:hover {
    border-color: var(--border);
    transform: translateX(2px);
  }

  .run:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }

  .rmain {
    flex: 1 1 auto;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .rname {
    font-size: 15.5px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .rscope {
    font-size: 13px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .rwhen {
    flex: none;
    text-align: right;
  }

  .run > :global(.icon) {
    color: var(--text-muted);
    flex: none;
  }

  .block {
    display: block;
    font-size: 11.5px;
  }

  .facts {
    display: grid;
    grid-template-columns: 92px 1fr;
    gap: 0;
    margin: 0;
  }

  .facts dt,
  .facts dd {
    margin: 0;
    padding: 7px 0;
    border-bottom: 1px solid var(--border);
    min-height: 34px;
    display: flex;
    align-items: center;
  }

  .facts dt {
    color: var(--text-muted);
    font-size: 13px;
  }

  .facts dd {
    overflow-wrap: anywhere;
  }

  .facts .path {
    font-size: 12px;
  }

  .cov {
    margin-top: var(--space-4);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .covtop {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    font-size: 13px;
    color: var(--text-muted);
  }

  .meter {
    height: 8px;
    border-radius: 999px;
    background: var(--surface-alt);
    overflow: hidden;
  }

  .meter span {
    display: block;
    height: 100%;
    width: var(--v);
    border-radius: 999px;
    background: var(--violet);
    animation: dca-grow-x 600ms cubic-bezier(0.2, 0.7, 0.2, 1) both;
    transform-origin: left;
  }

  .cat {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
  }

  .cat li {
    display: grid;
    grid-template-columns: minmax(180px, 1.4fr) 76px 1fr 90px;
    align-items: center;
    gap: var(--space-3);
    padding: 10px 2px;
    border-bottom: 1px solid var(--border);
  }

  .cat li:last-child {
    border-bottom: none;
  }

  .cg {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 500;
  }

  .ci {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 34px;
    height: 34px;
    flex: none;
    border-radius: 11px;
    background: var(--surface-raised);
    color: var(--text);
  }

  .cbar {
    height: 6px;
    border-radius: 999px;
    background: var(--surface-alt);
    overflow: hidden;
  }

  .cbfill {
    display: block;
    height: 100%;
    width: var(--v);
    border-radius: 999px;
    background: var(--peri);
    animation: dca-grow-x 600ms cubic-bezier(0.2, 0.7, 0.2, 1) both;
    transform-origin: left;
  }

  .cn {
    text-align: right;
    font-size: 13px;
    color: var(--text-muted);
  }

  .gen {
    grid-column: 3 / span 2;
  }

  .areas {
    text-align: right;
  }

  .pad {
    padding: 8px 12px 0;
  }

  .empty {
    padding: var(--space-4) 0;
  }

  .error {
    color: var(--sev-critical);
    padding: 4px 12px;
  }

  @media (max-width: 860px) {
    .top {
      grid-template-columns: 1fr;
    }

    .cat li {
      grid-template-columns: 1fr auto;
      row-gap: 6px;
    }

    .cat .cbar,
    .areas {
      display: none;
    }

    .cn {
      grid-column: 2;
    }
  }
</style>
