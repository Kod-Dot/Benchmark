<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import Notice from '../components/Notice.svelte';
  import { date, num, scopeText, scoreColour } from '../lib/format';
  import type { CollectOutcome } from '../lib/types';
  import type { AreaRow } from './CollectStep.svelte';

  let {
    outcome,
    rows,
    onOpen,
    onExit,
  }: {
    outcome: CollectOutcome;
    rows: AreaRow[];
    onOpen: (paths: string[]) => Promise<string | null>;
    onExit: () => void;
  } = $props();

  const m = $derived(outcome.manifest);
  const failed = $derived(rows.filter((r) => r.state === 'failed'));
  const read = $derived(rows.filter((r) => r.state === 'read'));
  const groups = $derived(
    [
      { scope: 'entra', title: 'Microsoft Entra ID', target: m.scope.tenant ?? '' },
      { scope: 'ad', title: 'On-premises', target: m.scope.domains.join(', ') },
    ]
      .map((g) => ({ ...g, rows: rows.filter((r) => r.scope === g.scope) }))
      .filter((g) => g.rows.length),
  );
  let opening = $state(false);
  let error = $state<string | null>(null);

  async function open() {
    opening = true;
    error = await onOpen([outcome.path]);
    opening = false;
  }
</script>

<div class="body">
  <div class="head">
    <div class="score" style="--c: {scoreColour(m.score)}">
      <span class="value">{m.score ?? '–'}</span>
      <span class="muted small">Score</span>
    </div>
    <div>
      <h1>{m.name ?? scopeText(m)}</h1>
      <p class="muted">
        {scopeText(m)} · collected {date(m.started_at, true)} · finished {date(m.finished_at, true)}
      </p>
      <p class="muted small path">{outcome.path}</p>
    </div>
  </div>

  {#if error}
    <Notice>{error}</Notice>
  {/if}
  {#if failed.length}
    <Notice>
      {failed.length === 1 ? 'One part' : `${failed.length} parts`} of the data could not be read. Checks that need
      {failed.length === 1 ? 'it' : 'them'} are reported as not assessed, with the reason.
    </Notice>
  {/if}

  {#each groups as g (g.scope)}
    {#if groups.length > 1}<h3>{g.title} · <span class="target">{g.target}</span></h3>{/if}
    <table>
      <thead>
        <tr><th class="c-area">Data</th><th class="c-state">Status</th><th class="c-count right">Objects</th><th>Detail</th></tr>
      </thead>
      <tbody>
        {#each g.rows as r (r.key)}
          <tr>
            <td class="area">{r.label}</td>
            <td>
              {#if r.state === 'read'}
                <span class="state ok"><Icon name="checkmarkCircle" size={16} /> Read</span>
              {:else if r.state === 'failed'}
                <span class="state failed"><Icon name="dismissCircle" size={16} /> Could not read</span>
              {:else if r.state === 'unlicensed'}
                <span class="state neutral"><Icon name="subtractCircle" size={16} /> Not licensed</span>
              {:else}
                <span class="state neutral"><Icon name="subtractCircle" size={16} /> Not read</span>
              {/if}
            </td>
            <td class="right num">{r.state === 'read' && r.area !== 'signin' ? num(r.count) : ''}</td>
            <td class="detail">{r.message}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/each}
  <p class="muted small">{read.length} of {rows.length} parts read.</p>
</div>

<footer class="bar">
  <button class="btn" onclick={onExit}><Icon name="arrowLeft" size={18} /> Start</button>
  <button class="btn primary" onclick={open} disabled={opening}>
    <Icon name="board" size={18} /> Open results
  </button>
</footer>

<style>
  .target {
    text-transform: none;
    letter-spacing: 0;
    font-weight: 500;
  }

  .body {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: var(--space-5);
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .head {
    display: flex;
    align-items: center;
    gap: var(--space-5);
  }

  .score {
    width: 88px;
    height: 88px;
    border-radius: 50%;
    border: 6px solid var(--c);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    flex: none;
  }

  .score .value {
    font-size: 26px;
    font-weight: 600;
    line-height: 1;
  }

  .path {
    font-family: var(--font-mono);
    margin-top: var(--space-1);
  }

  table {
    background: var(--surface);
    border-radius: var(--radius-lg);
    border-collapse: separate;
    border-spacing: 0;
    overflow: hidden;
    table-layout: fixed;
  }

  .c-area {
    width: 32%;
  }

  .c-state {
    width: 170px;
  }

  .c-count {
    width: 120px;
  }

  tbody tr:last-child td {
    border-bottom: none;
  }

  .area {
    font-weight: 500;
  }

  .right {
    text-align: right;
  }

  .num {
    font-variant-numeric: tabular-nums;
  }

  .state {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
  }

  .state.ok {
    color: var(--sev-low);
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
</style>
