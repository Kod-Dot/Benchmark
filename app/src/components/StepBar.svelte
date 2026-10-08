<script lang="ts">
  let { steps, current }: { steps: string[]; current: number } = $props();
</script>

<ol class="steps" aria-label="Assessment steps">
  {#each steps as step, i (step)}
    <li class:done={i < current} class:current={i === current} aria-current={i === current ? 'step' : undefined}>
      <span class="index num">{i + 1}</span>
      <span class="label">{step}</span>
    </li>
  {/each}
</ol>

<style>
  /* Segmented steps: done in mint, the current one solid, the rest striped */
  .steps {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    list-style: none;
    margin: 0;
    padding: 0;
  }

  li {
    display: flex;
    align-items: center;
    gap: 8px;
    height: 36px;
    padding: 0 14px 0 6px;
    border-radius: 999px;
    color: var(--text);
    font-weight: 500;
    font-size: 13.5px;
    background: repeating-linear-gradient(90deg, var(--stripe) 0 2px, transparent 2px 6px);
  }

  .index {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--bg);
    font-size: 12px;
  }

  li:not(.done, .current) .label {
    padding: 2px 8px;
    margin-left: -4px;
    border-radius: 999px;
    background: var(--bg);
  }

  .done {
    background: var(--mint);
    color: var(--ink);
  }

  .done .index {
    background: rgb(255 255 255 / 0.55);
  }

  .current {
    background: var(--pill);
    color: var(--pill-fg);
  }

  .current .index {
    background: color-mix(in srgb, var(--pill-fg) 22%, transparent);
  }
</style>
