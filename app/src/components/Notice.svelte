<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';

  let { children }: { children: Snippet } = $props();
</script>

<div class="notice" role="note">
  <Icon name="info" size={18} />
  <p>{@render children()}</p>
</div>

<style>
  .notice {
    display: flex;
    gap: 12px;
    align-items: flex-start;
    padding: 14px 18px;
    border-radius: var(--radius-md);
    background: var(--surface);
    color: var(--text);
  }

  .notice :global(.icon) {
    flex: none;
    width: 30px !important;
    height: 30px !important;
    padding: 6px;
    border-radius: 10px;
    background: var(--lilac);
    color: var(--ink);
    margin-top: -3px;
  }
</style>
