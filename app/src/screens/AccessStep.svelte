<script lang="ts">
  import { onDestroy } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Notice from '../components/Notice.svelte';
  import { inDesktopApp, onAccessProbe, runAccessCheck } from '../lib/backend';
  import type { IconName } from '../lib/icons';
  import type { CatalogSummary, ProbeResult, Source } from '../lib/types';

  let {
    catalog,
    domain,
    tenant,
    selected,
    onBack,
    onNext,
  }: {
    catalog: CatalogSummary;
    domain: string;
    tenant: string;
    selected: Set<string>;
    onBack: () => void;
    onNext: () => void;
  } = $props();

  const required: Source[] = $derived.by(() => {
    const areas = catalog.groups.flatMap((g) => g.areas).filter((a) => selected.has(a.code));
    return catalog.sources.filter((s) => areas.some((a) => a.sources.includes(s.id)));
  });
  const onprem = $derived(required.filter((s) => s.kind === 'onprem'));
  const cloud = $derived(required.filter((s) => s.kind === 'cloud'));
  const collectable = $derived(onprem.length > 0 || cloud.some((s) => s.id === 'graph'));

  let results = $state<Record<string, ProbeResult>>({});
  let running = $state(false);
  let error = $state<string | null>(null);

  const unlisten = onAccessProbe((r) => (results = { ...results, [r.source]: r }));
  onDestroy(() => unlisten.then((f) => f()));

  // The probe script tests sources in the order given, so the first source
  // without a result is the one being tested right now.
  const testing = $derived(running ? onprem.find((s) => !results[s.id])?.id : undefined);

  async function run() {
    running = true;
    error = null;
    results = {};
    try {
      const all = await runAccessCheck(domain.trim(), onprem.map((s) => s.id));
      results = Object.fromEntries(all.map((r) => [r.source, r]));
    } catch (e) {
      error = String((e as Error)?.message ?? e);
    } finally {
      running = false;
    }
  }

  const stateView: Record<string, { icon: IconName; label: string; tone: string }> = {
    ok: { icon: 'checkmarkCircle', label: 'Can read', tone: 'ok' },
    partial: { icon: 'warning', label: 'Partly', tone: 'partial' },
    failed: { icon: 'dismissCircle', label: 'Cannot read', tone: 'failed' },
    untested: { icon: 'subtractCircle', label: 'Tested later', tone: 'neutral' },
  };
</script>

<div class="body">
  <div class="intro">
    <p>
      Before collecting anything, Benchmark tests what this account can actually read. Areas
      whose sources cannot be read are reported as <em>not assessed</em>, with the reason.
    </p>
    <button class="btn primary" onclick={run} disabled={running || !inDesktopApp || onprem.length === 0}>
      <Icon name={running ? 'arrowSync' : 'play'} size={18} />
      {running ? 'Testing…' : Object.keys(results).length ? 'Test again' : 'Run access check'}
    </button>
  </div>

  {#if !inDesktopApp}
    <Notice>Access checks run against your domain, so they only work in the desktop app on Windows.</Notice>
  {/if}
  {#if error}
    <Notice>{error}</Notice>
  {/if}

  {#if onprem.length}
    <h3>On-premises · <span class="target">{domain}</span></h3>
    <table>
      <thead>
        <tr><th class="c-source">Source</th><th class="c-needs">Needs</th><th class="c-result">Result</th><th>Detail</th></tr>
      </thead>
      <tbody>
        {#each onprem as s (s.id)}
          {@const r = results[s.id]}
          <tr>
            <td class="source">{s.title}</td>
            <td class="muted">{s.needs}</td>
            <td class="result">
              {#if r}
                {@const v = stateView[r.state]}
                <span class="state {v.tone}"><Icon name={v.icon} size={16} /> {v.label}</span>
              {:else if testing === s.id}
                <span class="state neutral"><Icon name="arrowSync" size={16} /> Testing</span>
              {:else}
                <span class="state neutral"><Icon name="circle" size={16} /> Not tested</span>
              {/if}
            </td>
            <td class="detail">{r?.detail ?? ''}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  {#if cloud.length}
    <h3>Microsoft cloud · <span class="target">{tenant}</span></h3>
    <table>
      <thead>
        <tr><th class="c-source">Source</th><th class="c-needs">Needs</th><th class="c-result">Result</th><th>Detail</th></tr>
      </thead>
      <tbody>
        {#each cloud as s (s.id)}
          <tr>
            <td class="source">{s.title}</td>
            <td class="muted">{s.needs}</td>
            {#if s.id === 'exo'}
              <td class="result"><span class="state neutral"><Icon name="personKey" size={16} /> At sign-in</span></td>
              <td class="detail muted">Read through Microsoft's ExchangeOnlineManagement module (version 3 or later) on this computer, with Get- cmdlets only. Without the module, Exchange Online checks show as not assessed.</td>
            {:else if s.id === 'spo' || s.id === 'teams' || s.id === 'purview'}
              <td class="result"><span class="state neutral"><Icon name="personKey" size={16} /> At sign-in</span></td>
              <td class="detail muted">Read through Microsoft's {s.id === 'spo' ? 'Microsoft.Online.SharePoint.PowerShell' : s.id === 'teams' ? 'MicrosoftTeams' : 'ExchangeOnlineManagement (Security & Compliance)'} module on this computer, with Get- cmdlets only. Without the module, these checks show as not assessed.</td>
            {:else if s.id === 'defender'}
              <td class="result"><span class="state neutral"><Icon name="personKey" size={16} /> At sign-in</span></td>
              <td class="detail muted">Read from Microsoft Graph and the Defender for Endpoint API with GET requests only. Areas the account cannot read are reported as not assessed.</td>
            {:else if s.id === 'arm'}
              <td class="result"><span class="state neutral"><Icon name="personKey" size={16} /> At sign-in</span></td>
              <td class="detail muted">Read from Azure Resource Manager with GET requests only. Subscriptions the account cannot read are left out, and their checks show what was read.</td>
            {:else if s.id === 'graph' || s.id === 'graph-logs'}
              <td class="result"><span class="state neutral"><Icon name="personKey" size={16} /> At sign-in</span></td>
              <td class="detail muted">You sign in to Microsoft when collection starts. Areas the account cannot read are reported as not assessed.</td>
            {:else}
              <td class="result"><span class="state neutral"><Icon name="subtractCircle" size={16} /> Not collected</span></td>
              <td class="detail muted">Its collector is not built yet; checks that need it show as not assessed.</td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<footer class="bar">
  <button class="btn" onclick={onBack}><Icon name="arrowLeft" size={18} /> Back to scope</button>
  <div class="next">
    {#if !collectable}
      <span class="muted">The chosen areas need sources this version cannot collect yet.</span>
    {:else if onprem.length && !Object.keys(results).length}
      <span class="muted">You can collect without testing; unreadable parts are reported.</span>
    {/if}
    <button class="btn primary" onclick={onNext} disabled={running || !collectable}>Next: Collect <Icon name="arrowRight" size={18} /></button>
  </div>
</footer>

<style>
  .body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: var(--space-5);
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .intro {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-5);
  }

  .intro p {
    max-width: 680px;
  }

  h3 {
    margin-top: var(--space-2);
  }

  table {
    background: var(--surface);
    border-radius: var(--radius-lg);
    border-collapse: separate;
    border-spacing: 0;
    overflow: hidden;
  }

  table {
    table-layout: fixed;
  }

  .c-source {
    width: 26%;
  }

  .c-needs {
    width: 30%;
  }

  .c-result {
    width: 150px;
  }

  .target {
    text-transform: none;
    letter-spacing: 0;
    font-weight: 500;
  }

  tbody tr:last-child td {
    border-bottom: none;
  }

  .source {
    font-weight: 500;
    white-space: nowrap;
  }

  .result {
    white-space: nowrap;
  }

  .state {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
  }

  .state.ok {
    color: var(--sev-low);
  }

  .state.partial {
    color: var(--sev-medium);
  }

  .state.failed {
    color: var(--sev-critical);
  }

  .state.neutral {
    color: var(--text-muted);
  }

  .detail {
    font-size: 13px;
  }

  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-3) var(--space-5);
  }

  .next {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }
</style>
