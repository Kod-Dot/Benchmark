<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import { date, scopeText } from '../lib/format';
  import type { ExportedPage } from '../lib/types';

  let { page }: { page: ExportedPage } = $props();

  const heading = $derived(
    page.kind === 'executive'
      ? 'Executive summary'
      : page.kind === 'technical'
        ? 'Technical report'
        : `Changes since ${page.comparison?.earlier.name ?? 'the baseline'}`,
  );
  const runs = $derived(page.kind === 'changes' && page.comparison ? [page.comparison.later] : page.view.runs);
  const scopes = $derived([...new Set(runs.map((r) => scopeText(r.manifest)).filter(Boolean))]);
  const collected = $derived(runs.map((r) => r.manifest.finished_at ?? r.manifest.started_at));
  const b = $derived(page.branding);
</script>

<header class="cover">
  <div class="cover-top">
    {#if b.logo}
      <img class="logo" src={b.logo} alt={b.organization || 'Logo'} />
    {:else}
      <span class="brand"><Logo height={28} /></span>
    {/if}
    {#if b.classification}<span class="classification">{b.classification}</span>{/if}
  </div>

  <div class="cover-title">
    <p class="overline">Active Directory and Entra ID security assessment</p>
    <h1>{heading}</h1>
    <p class="scope">{runs.map((r) => r.name).join(' + ')}</p>
    {#if scopes.length}<p class="muted">{scopes.join(' · ')}</p>{/if}
  </div>

  <dl class="kv tight cover-facts">
    {#if b.organization}<dt>Organization</dt><dd>{b.organization}</dd>{/if}
    {#if b.prepared_by}<dt>Prepared by</dt><dd>{b.prepared_by}</dd>{/if}
    <dt>Data collected</dt>
    <dd>{collected.map((c) => date(c, true)).join(', ')}</dd>
    {#if page.kind === 'changes' && page.comparison}
      <dt>Compared with</dt>
      <dd>{page.comparison.earlier.name}, collected {date(page.comparison.earlier.manifest.finished_at ?? page.comparison.earlier.manifest.started_at, true)}</dd>
    {/if}
    <dt>Report produced</dt>
    <dd>{date(page.generated_at, true)}</dd>
    <dt>Tool and catalog</dt>
    <dd>Benchmark {page.tool_version}, check catalog {page.view.catalog_version}</dd>
  </dl>

  {#if page.pseudonymized}
    <p class="cover-note"><Icon name="info" size={16} />Object, user and domain names in this report are replaced with pseudonyms. The same object always has the same pseudonym.</p>
  {/if}
</header>
