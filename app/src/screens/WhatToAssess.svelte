<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import type { CatalogSummary, Environment } from '../lib/types';

  let {
    catalog,
    environment,
    onprem = $bindable(),
    entra = $bindable(),
    onNext,
    onCancel,
  }: {
    catalog: CatalogSummary;
    environment: Environment | null;
    onprem: boolean;
    entra: boolean;
    onNext: () => void;
    onCancel: () => void;
  } = $props();

  const group = (id: string) => catalog.groups.find((g) => g.id === id);
  const op = $derived(group('onprem'));
  const en = $derived(group('entra'));
  const hy = $derived(group('hybrid'));
  const areaNames = (id: string, n: number) =>
    group(id)?.areas.slice(0, n).map((a) => a.title.toLowerCase()).join(', ') ?? '';

  const summary = $derived(
    onprem && entra
      ? `Hybrid assessment: ${(op?.checks ?? 0) + (en?.checks ?? 0) + (hy?.checks ?? 0)} checks, including ${hy?.checks ?? 0} hybrid checks, in one dashboard.`
      : onprem
        ? `On-premises assessment: ${op?.checks ?? 0} checks.`
        : entra
          ? `Entra ID assessment: ${en?.checks ?? 0} checks.`
          : 'Choose at least one.',
  );
</script>

<div class="body">
  <div class="inner">
    <div class="intro">
      <h1>What do you want to assess?</h1>
      <p class="muted">
        Choose one or both. Choosing both adds the hybrid checks that connect the two, such as Entra
        Connect, federation and attack paths that cross from on-premises to the cloud.
      </p>
    </div>

    <div class="choices">
      <label class="choice" class:on={onprem}>
        <span class="top">
          <span class="mark"><Icon name="building" size={40} /></span>
          <span class="names">
            <strong>On-premises Active Directory</strong>
            <span class="muted small">Forests, domains and domain controllers</span>
          </span>
          <input type="checkbox" bind:checked={onprem} aria-label="On-premises Active Directory" />
        </span>
        <ul>
          <li>{op?.checks ?? 0} checks in {op?.areas.length ?? 0} areas: {areaNames('onprem', 6)} and more</li>
          <li>Directory telemetry: users, computers, groups, OUs and GPOs, with the relationships between them</li>
          <li>Runs as any domain user; more areas with domain controller read access</li>
        </ul>
        <span class="muted small">
          {#if environment?.domain}Detected: <strong class="text">{environment.domain}</strong>{:else}No domain detected on this computer; enter it on the next step{/if}
        </span>
      </label>

      <label class="choice" class:on={entra}>
        <span class="top">
          <span class="mark"><Icon name="cloud" size={40} /></span>
          <span class="names">
            <strong>Microsoft Entra ID</strong>
            <span class="muted small">Cloud tenant, applications and Conditional Access</span>
          </span>
          <input type="checkbox" bind:checked={entra} aria-label="Microsoft Entra ID" />
        </span>
        <ul>
          <li>{en?.checks ?? 0} checks in {en?.areas.length ?? 0} areas: {areaNames('entra', 6)} and more</li>
          <li>Directory telemetry: users, groups, roles, applications and service principals</li>
          <li>Sign in with an account that has the Global Reader role</li>
        </ul>
        <span class="muted small">Microsoft 365, Azure and endpoint areas can be added on the next step</span>
      </label>
    </div>

    <div class="notice-line">
      <Icon name="branchFork" />
      <span>{summary}</span>
    </div>
  </div>
</div>

<footer class="actionbar">
  <button class="btn" onclick={onCancel}>Cancel</button>
  <button class="btn primary" disabled={!onprem && !entra} onclick={onNext}>Next: Scope<Icon name="arrowRight" size={18} /></button>
</footer>

<style>
  .body {
    flex: 1 1 0;
    min-height: 0;
    overflow: auto;
    padding: 48px 32px;
  }

  .inner {
    max-width: 1040px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    gap: 28px;
  }

  .intro {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .intro h1 {
    font-size: 30px;
  }

  .intro p {
    font-size: 15px;
    max-width: 760px;
  }

  .choices {
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
  }

  .choice {
    display: flex;
    flex-direction: column;
    gap: 14px;
    padding: 26px;
    border: 2px solid transparent;
    border-radius: var(--radius-lg);
    background: var(--surface);
    flex: 1 1 360px;
    cursor: pointer;
  }

  .choice {
    transition: border-color var(--transition), transform var(--transition);
  }

  .choice:hover {
    transform: translateY(-1px);
  }

  .choice.on {
    border-color: var(--pill);
  }

  .choice.on .mark {
    background: var(--mint);
    color: var(--ink);
  }

  .top {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .top input {
    margin-left: auto;
    width: 20px;
    height: 20px;
  }

  .mark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 52px;
    height: 52px;
    border-radius: 17px;
    background: var(--surface-raised);
    color: var(--text);
    flex: none;
  }

  .names {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .names strong {
    font-size: 20px;
    font-weight: 500;
  }

  .choice ul {
    margin: 0;
    padding-left: 18px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    color: var(--text-muted);
    font-size: 13.5px;
  }

  .text {
    color: var(--text);
  }

  .notice-line {
    align-items: center;
  }

  .notice-line :global(.icon) {
    color: var(--accent-ink);
  }

  .actionbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 12px 24px;
  }
</style>
