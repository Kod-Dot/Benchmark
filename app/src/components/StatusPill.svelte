<script lang="ts">
  import Icon from './Icon.svelte';
  import type { IconName } from '../lib/icons';
  import type { ResultStatus } from '../lib/types';

  let { status, large = false }: { status: ResultStatus; large?: boolean } = $props();

  const meta: Record<ResultStatus, { label: string; icon: IconName }> = {
    failed: { label: 'Failed', icon: 'errorCircle' },
    passed: { label: 'Passed', icon: 'checkmarkCircle' },
    accepted: { label: 'Accepted', icon: 'shieldCheckmark' },
    not_assessed: { label: 'Not assessed', icon: 'subtractCircle' },
  };
  const m = $derived(meta[status]);
</script>

<span class="pill {status}" class:lg={large}>
  <Icon name={m.icon} size={large ? 16 : 14} />{m.label}
</span>
