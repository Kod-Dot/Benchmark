<script lang="ts">
  import Icon from './Icon.svelte';
  import { toastState } from '../lib/toast.svelte';
</script>

<div class="toasts" role="status" aria-live="polite">
  {#if toastState.text}
    {#key toastState.id}
      <div class="toast"><Icon name="checkmarkCircle" size={16} />{toastState.text}</div>
    {/key}
  {/if}
</div>

<style>
  .toasts {
    position: fixed;
    left: 50%;
    bottom: 48px;
    transform: translateX(-50%);
    z-index: 100;
    pointer-events: none;
  }

  .toast {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 14px;
    border-radius: 999px;
    background: var(--text);
    color: var(--bg);
    font-size: 13px;
    font-weight: 500;
    box-shadow: 0 10px 28px rgb(0 0 0 / 0.25);
    animation: dca-rise 200ms cubic-bezier(0.2, 0.7, 0.2, 1) both;
  }
</style>
