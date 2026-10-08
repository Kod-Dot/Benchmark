<script lang="ts">
  import { scoreColour } from '../lib/format';

  let {
    score,
    size = 48,
    stroke = 5,
    label = true,
  }: { score: number | null; size?: number; stroke?: number; label?: boolean } = $props();

  const r = $derived((size - stroke) / 2);
  const c = $derived(2 * Math.PI * r);
  const value = $derived(score == null ? 0 : Math.max(0, Math.min(100, score)));
  const colour = $derived(scoreColour(score));
</script>

<span class="ring" style:width="{size}px" style:height="{size}px" role="img" aria-label={score == null ? 'Not scored' : `Score ${Math.round(value)} of 100`}>
  <svg width={size} height={size} viewBox="0 0 {size} {size}">
    <circle cx={size / 2} cy={size / 2} {r} fill="none" stroke="var(--surface-alt)" stroke-width={stroke} />
    {#if score != null}
      <circle
        cx={size / 2}
        cy={size / 2}
        {r}
        fill="none"
        stroke={colour}
        stroke-width={stroke}
        stroke-linecap="round"
        stroke-dasharray="{(value / 100) * c} {c}"
        transform="rotate(-90 {size / 2} {size / 2})"
        class="arc"
      />
    {/if}
  </svg>
  {#if label}
    <span class="n" style:font-size="{Math.round(size * 0.32)}px">{score == null ? '–' : Math.round(value)}</span>
  {/if}
</span>

<style>
  .ring {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
  }

  .arc {
    animation: ring-draw 700ms cubic-bezier(0.3, 0.6, 0.2, 1) both;
  }

  @keyframes ring-draw {
    from {
      stroke-dasharray: 0 999;
    }
  }

  :global(:root[data-motion='off']) .arc {
    animation: none;
  }

  .n {
    position: absolute;
    font-weight: 650;
    font-variant-numeric: tabular-nums;
  }
</style>
