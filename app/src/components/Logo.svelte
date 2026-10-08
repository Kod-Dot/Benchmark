<script lang="ts">
  // The Benchmark logo, traced from the brand guidelines. The wordmark is for
  // Home, reports and other formal placements; the mark (B and red bar) is the
  // compact form. Black artwork follows the text colour, so it reverses to
  // white on dark backgrounds; the red bar never changes.
  import wordmark from '../assets/brand/benchmark-wordmark.svg?raw';
  import mark from '../assets/brand/benchmark-mark.svg?raw';

  let { kind = 'wordmark', height = 24 }: { kind?: 'wordmark' | 'mark'; height?: number } = $props();
</script>

<span class="bm-logo" role="img" aria-label="Benchmark" style:height="{height}px">
  {@html kind === 'mark' ? mark : wordmark}
</span>

<style>
  .bm-logo {
    display: inline-flex;
    flex: none;
    color: var(--logo-ink, var(--text));
  }

  .bm-logo :global(svg) {
    height: 100%;
    width: auto;
    display: block;
  }
</style>
