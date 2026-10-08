<script lang="ts">
  import { untrack } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import StepBar from '../components/StepBar.svelte';
  import WhatToAssess from './WhatToAssess.svelte';
  import ScopeStep from './ScopeStep.svelte';
  import AccessStep from './AccessStep.svelte';
  import CollectStep, { type AreaRow } from './CollectStep.svelte';
  import ReviewStep from './ReviewStep.svelte';
  import type { CatalogSummary, CollectOutcome, Environment } from '../lib/types';

  let {
    environment,
    catalog,
    onExit,
    onOpen,
    onCollected,
  }: {
    environment: Environment | null;
    catalog: CatalogSummary | null;
    onExit: () => void;
    onOpen: (paths: string[]) => Promise<string | null>;
    /** A new assessment was written; the start screen's list is stale. */
    onCollected: () => void;
  } = $props();

  const steps = ['What to assess', 'Scope', 'Check access', 'Collect', 'Review'];
  let step = $state(0);

  // Initial values only: the user edits these from here on. Both directories
  // are offered; on-premises is preselected only when this computer is in a domain.
  let onprem = $state(untrack(() => !!environment?.domain || !environment));
  let entra = $state(true);
  let domain = $state(untrack(() => environment?.domain ?? ''));
  let tenant = $state('');
  let selected = $state<Set<string>>(new Set());
  let name = $state('');
  let outcome = $state<CollectOutcome | null>(null);
  let rows = $state<AreaRow[]>([]);

  /** The areas that follow from the first step's choice; the Scope step refines them. */
  function chooseAreas() {
    const groups = [...(onprem ? ['onprem'] : []), ...(entra ? ['entra'] : []), ...(onprem && entra ? ['hybrid'] : [])];
    selected = new Set(catalog?.groups.filter((g) => groups.includes(g.id)).flatMap((g) => g.areas.map((a) => a.code)) ?? []);
    step = 1;
  }
</script>

<div class="screen">
  <header class="top">
    <button class="btn back" onclick={onExit}>
      <Icon name="arrowLeft" size={18} /> Start
    </button>
    <h2>New assessment</h2>
    <StepBar {steps} current={step} />
  </header>

  {#if !catalog}
    <p class="body muted">The check catalog could not be loaded.</p>
  {:else if step === 0}
    <WhatToAssess {catalog} {environment} bind:onprem bind:entra onNext={chooseAreas} onCancel={onExit} />
  {:else if step === 1}
    <ScopeStep {catalog} bind:domain bind:tenant bind:selected onNext={() => (step = 2)} onBack={() => (step = 0)} />
  {:else if step === 2}
    <AccessStep {catalog} {domain} {tenant} {selected} onBack={() => (step = 1)} onNext={() => (step = 3)} />
  {:else if step === 3}
    <CollectStep
      {catalog}
      {domain}
      {tenant}
      {selected}
      bind:name
      onBack={() => (step = 2)}
      onDone={(o, r) => {
        outcome = o;
        rows = r;
        step = 4;
        onCollected();
      }}
    />
  {:else if step === 4 && outcome}
    <ReviewStep {outcome} {rows} {onOpen} {onExit} />
  {/if}
</div>

<style>
  .screen {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .top {
    display: flex;
    align-items: center;
    gap: var(--space-5);
    padding: var(--space-3) var(--space-5);
  }

  .top h2 {
    margin-right: auto;
  }

  .back {
    border-color: transparent;
    background: transparent;
    padding: 0 var(--space-2);
  }

  .body {
    padding: var(--space-5);
  }
</style>
