<script lang="ts">
  import Icon from './Icon.svelte';
  import { severityMeta } from '../lib/format';
  import type { Severity } from '../lib/types';

  let { severity, large = false, label }: { severity: Severity; large?: boolean; label?: string } =
    $props();
  const meta = $derived(severityMeta[severity]);
</script>

<span class="sev {severity}" class:lg={large}>
  <Icon name={meta.icon} size={large ? 16 : 14} />{label ?? meta.label}
</span>
