<script lang="ts">
  import { icons, type IconName } from '../lib/icons';

  let { name, size = 20, label }: { name: IconName; size?: number; label?: string } = $props();
</script>

<span
  class="icon"
  style:width="{size}px"
  style:height="{size}px"
  role={label ? 'img' : undefined}
  aria-label={label}
  aria-hidden={label ? undefined : 'true'}
>
  {@html icons[name]}
</span>

<style>
  .icon {
    display: inline-flex;
    flex: none;
  }

  .icon :global(svg) {
    width: 100%;
    height: 100%;
    fill: currentColor;
  }
</style>
