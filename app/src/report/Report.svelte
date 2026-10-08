<script lang="ts">
  import Cover from './Cover.svelte';
  import Executive from './Executive.svelte';
  import Technical from './Technical.svelte';
  import Changes from './Changes.svelte';
  import { cssString } from './util';

  const page = window.__DCA__;

  // Page numbers, the classification label and the report name sit in the
  // printed page margins. They need the text inside CSS, so the rule is
  // written here rather than in report.css.
  if (page) {
    const label = page.branding.classification.trim();
    const style = document.createElement('style');
    style.textContent = `@page {
      ${label ? `@top-right { content: ${cssString(label.toUpperCase())}; }` : ''}
      @bottom-left { content: ${cssString(page.title)}; }
    }
    @page :first { @top-left { content: none; } @top-right { content: none; } @bottom-left { content: none; } @bottom-right { content: none; } }`;
    document.head.appendChild(style);
  }
</script>

{#if !page}
  <main class="nodata">
    <h2>No report data</h2>
    <p class="muted">This page shows a report exported from Benchmark. Export one from the Results screen.</p>
  </main>
{:else}
  <article class="doc">
    <Cover {page} />
    {#if page.kind === 'executive'}
      <Executive {page} />
    {:else if page.kind === 'technical'}
      <Technical {page} />
    {:else if page.kind === 'changes' && page.comparison}
      <Changes {page} comparison={page.comparison} />
    {/if}
  </article>
{/if}

<style>
  .nodata {
    max-width: 560px;
    margin: 80px auto;
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 0 24px;
  }
</style>
