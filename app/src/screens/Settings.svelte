<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import { accountName, assessmentsFolder, changePassword, inDesktopApp, listExceptions, openFolder, removeException } from '../lib/backend';
  import { num } from '../lib/format';
  import { applyTheme, savedTheme, type Theme } from '../lib/theme';
  import { display, setMotion, setZoom, stepZoom, ZOOM_STEPS } from '../lib/prefs.svelte';
  import type { CatalogSummary, ExceptionRow } from '../lib/types';

  let {
    catalog,
    onBack,
    backLabel,
    onChanged,
  }: {
    catalog: CatalogSummary | null;
    onBack: () => void;
    backLabel: string;
    /** Called after an accepted risk is removed, so open results reload. */
    onChanged?: () => Promise<void>;
  } = $props();

  let rows = $state<ExceptionRow[] | null>(null);
  let folder = $state<string | null>(null);
  let error = $state<string | null>(null);
  let busy = $state<string | null>(null);
  let theme = $state<Theme>(savedTheme());

  const message = (e: unknown) => String((e as Error)?.message ?? e);

  function refresh() {
    listExceptions()
      .then((r) => (rows = r))
      .catch((e) => (error = message(e)));
  }

  if (inDesktopApp) {
    refresh();
    assessmentsFolder()
      .then((f) => (folder = f))
      .catch((e) => (error = message(e)));
  }

  const key = (r: ExceptionRow) => `${r.check}|${r.scope.join(',')}`;
  const active = $derived(rows?.filter((r) => r.active).length ?? 0);

  async function remove(r: ExceptionRow) {
    busy = key(r);
    error = null;
    try {
      await removeException(r.check, r.scope);
      refresh();
      await onChanged?.();
    } catch (e) {
      error = message(e);
    } finally {
      busy = null;
    }
  }

  function setTheme(t: Theme) {
    theme = t;
    applyTheme(t, true);
  }

  // ---------- Account ----------
  let who = $state<string | null>(null);
  let changingPw = $state(false);
  let curPw = $state('');
  let newPw = $state('');
  let confirmPw = $state('');
  let pwError = $state<string | null>(null);
  let pwDone = $state(false);
  if (inDesktopApp) accountName().then((n) => (who = n)).catch(() => {});

  async function savePassword() {
    pwError = null;
    pwDone = false;
    if (!who) return;
    if (newPw !== confirmPw) {
      pwError = 'The two new passwords do not match.';
      return;
    }
    busy = 'password';
    try {
      await changePassword(who, curPw, newPw);
      curPw = newPw = confirmPw = '';
      changingPw = false;
      pwDone = true;
    } catch (e) {
      pwError = message(e);
    } finally {
      busy = null;
    }
  }

  const themes: { id: Theme; label: string }[] = [
    { id: 'light', label: 'Light' },
    { id: 'dark', label: 'Dark' },
    { id: 'system', label: 'Same as Windows' },
  ];
</script>

<div class="screen">
  <header class="header">
    <button class="btn ghost" onclick={onBack}><Icon name="arrowLeft" size={18} />{backLabel}</button>
    <h2>Settings</h2>
  </header>

  <main class="body">
    {#if error}
      <p class="notice-line err" role="alert"><Icon name="errorCircle" size={18} />{error}</p>
    {/if}

    {#if inDesktopApp && who}
      <section class="part">
        <div class="part-h">
          <h3>Account</h3>
          <span class="muted small">Signed in as {who}</span>
        </div>
        <p class="muted small">Your password gates this app on this computer. Only its Argon2 hash is stored, never the password. You can also change it from the separate BenchmarkPassword tool.</p>
        {#if pwDone}
          <p class="notice-line ok" role="status"><Icon name="checkmarkCircle" size={18} />Password changed.</p>
        {/if}
        <div class="line">
          <button class="btn sm primary" aria-expanded={changingPw} onclick={() => { changingPw = !changingPw; pwDone = false; pwError = null; }}><Icon name="key" size={16} />Change password</button>
        </div>
        {#if changingPw}
          <div class="pwform">
            <label class="field"><span class="small muted">Current password</span><input type="password" autocomplete="current-password" bind:value={curPw} /></label>
            <label class="field"><span class="small muted">New password</span><input type="password" autocomplete="new-password" bind:value={newPw} /></label>
            <label class="field"><span class="small muted">Confirm new password</span><input type="password" autocomplete="new-password" bind:value={confirmPw} /></label>
            <div class="line"><button class="btn sm primary" disabled={!curPw || !newPw || busy !== null} onclick={savePassword}>{busy === 'password' ? 'Saving…' : 'Save password'}</button></div>
          </div>
        {/if}
        {#if pwError}<p class="notice-line err" role="alert"><Icon name="errorCircle" size={18} />{pwError}</p>{/if}
      </section>
    {/if}

    <section class="part">
      <div class="part-h">
        <h3>Accepted risks</h3>
        {#if rows?.length}<span class="muted small">{num(active)} active, {num(rows.length - active)} expired</span>{/if}
      </div>
      <p class="muted small lead">
        Accepted from a finding's detail pane. Each one applies to every assessment of the same domains or tenant, including
        later runs, until it expires or is removed. A check with an active acceptance is shown as an accepted risk and left
        out of the score.
      </p>
      {#if !inDesktopApp}
        <p class="empty">Accepted risks are kept by the desktop app.</p>
      {:else if rows === null}
        <p class="empty muted">{error ? 'Could not be read.' : 'Loading…'}</p>
      {:else if rows.length === 0}
        <p class="empty">No risks have been accepted. Open a failed finding and choose Accept risk to record one.</p>
      {:else}
        <div class="scroll-x">
          <table class="t">
            <thead>
              <tr>
                <th style="width: 280px">Check</th>
                <th style="width: 180px">Applies to</th>
                <th>Reason</th>
                <th style="width: 190px">Accepted</th>
                <th style="width: 120px">Expires</th>
                <th style="width: 110px"></th>
              </tr>
            </thead>
            <tbody>
              {#each rows as r (key(r))}
                <tr class:off={!r.active}>
                  <td>
                    <span class="mono small block">{r.check}</span>
                    {r.title || 'No longer in the catalog'}
                  </td>
                  <td class="small">{r.scope.join(', ')}</td>
                  <td class="small">{r.reason}</td>
                  <td class="small">{r.accepted_by}<span class="muted block">{r.accepted_on}</span></td>
                  <td class="small">
                    {#if r.active}
                      {r.expires_on ?? 'Until removed'}
                    {:else}
                      <span class="state failed"><Icon name="dismissCircle" size={16} />Expired {r.expires_on}</span>
                    {/if}
                  </td>
                  <td class="right">
                    <button class="btn sm ghost" disabled={busy !== null} onclick={() => remove(r)}>{busy === key(r) ? 'Removing…' : 'Remove'}</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <section class="part">
      <h3>Assessments folder</h3>
      <p class="muted small lead">Each assessment is a sub-folder with its collected data and results. The accepted risks are kept here too, in exceptions.json.</p>
      {#if folder}
        <div class="line">
          <code class="path">{folder}</code>
          <button class="btn sm" onclick={() => folder && openFolder(folder).catch((e) => (error = message(e)))}><Icon name="folderOpen" size={16} />Open folder</button>
        </div>
      {:else}
        <p class="empty muted">{inDesktopApp ? 'Loading…' : 'Desktop app only'}</p>
      {/if}
    </section>

    <section class="part">
      <h3>Appearance</h3>
      <div class="choices" role="radiogroup" aria-label="Theme">
        {#each themes as t (t.id)}
          <label class="choice" class:on={theme === t.id}>
            <input type="radio" name="theme" checked={theme === t.id} onchange={() => setTheme(t.id)} />
            {t.label}
          </label>
        {/each}
      </div>
    </section>

    <section class="part">
      <h3>Zoom</h3>
      <p class="muted small lead">Makes everything in the window larger or smaller. <span class="kbd">Ctrl +</span> and <span class="kbd">Ctrl −</span> change it anywhere, <span class="kbd">Ctrl 0</span> resets it.</p>
      <div class="zoomrow">
        <button class="btn sm" onclick={() => setZoom(stepZoom(display.zoom, -1))} disabled={display.zoom <= ZOOM_STEPS[0]} aria-label="Zoom out"><Icon name="zoomOut" size={16} /></button>
        <div class="seg" role="radiogroup" aria-label="Zoom">
          {#each ZOOM_STEPS as z (z)}
            <button role="radio" aria-checked={display.zoom === z} class:on={display.zoom === z} onclick={() => setZoom(z)}>{Math.round(z * 100)}%</button>
          {/each}
        </div>
        <button class="btn sm" onclick={() => setZoom(stepZoom(display.zoom, 1))} disabled={display.zoom >= ZOOM_STEPS[ZOOM_STEPS.length - 1]} aria-label="Zoom in"><Icon name="zoomIn" size={16} /></button>
        {#if display.zoom !== 1}<button class="linkbtn small" onclick={() => setZoom(1)}>Reset to 100%</button>{/if}
      </div>
    </section>

    <section class="part">
      <h3>Animations</h3>
      <p class="muted small lead">Page transitions, charts that draw in and hover effects. Windows' "Animation effects" setting turns them off too.</p>
      <div class="choices" role="radiogroup" aria-label="Animations">
        <label class="choice" class:on={display.motion === 'on'}><input type="radio" name="motion" checked={display.motion === 'on'} onchange={() => setMotion('on')} />On</label>
        <label class="choice" class:on={display.motion === 'off'}><input type="radio" name="motion" checked={display.motion === 'off'} onchange={() => setMotion('off')} />Off</label>
      </div>
    </section>

    <section class="part">
      <h3>Check catalog</h3>
      {#if catalog}
        <dl class="kv tight">
          <dt>Checks</dt><dd>{num(catalog.implemented)} run in this version, {num(catalog.checks - catalog.implemented)} more are planned</dd>
          <dt>Data sources</dt><dd>{num(catalog.sources.length)}</dd>
        </dl>
      {:else}
        <p class="empty muted">The catalog could not be read.</p>
      {/if}
    </section>
  </main>
</div>

<style>
  .screen {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .header {
    display: flex;
    align-items: center;
    gap: 20px;
    min-height: 72px;
    padding: 14px 28px;
  }

  .header h2 {
    flex: 1 1 auto;
  }

  .body {
    flex: 1 1 0;
    min-height: 0;
    overflow: auto;
    padding: 8px 28px 32px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 18px;
  }

  .part {
    display: flex;
    flex-direction: column;
    gap: 10px;
    width: 100%;
    max-width: 1100px;
    padding: 20px 24px 24px;
    border-radius: var(--radius-lg);
    background: var(--surface);
  }

  .part-h h3,
  .part > h3 {
    font-size: 19px;
    font-weight: 500;
    color: var(--text);
  }

  .part-h {
    display: flex;
    align-items: baseline;
    gap: 12px;
  }

  .lead {
    margin: 0;
    max-width: 760px;
  }

  .t {
    min-width: 900px;
  }

  tr.off td {
    color: var(--text-muted);
  }

  .block {
    display: block;
  }

  .right {
    text-align: right;
  }

  .empty {
    margin: 0;
    padding: 14px 18px;
    border-radius: var(--radius-md);
    background: var(--surface-raised);
  }

  .pwform {
    display: flex;
    flex-direction: column;
    gap: 10px;
    max-width: 320px;
    margin-top: 4px;
  }

  .pwform .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .pwform .field input {
    padding: 9px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface-raised);
    color: var(--text);
    font-size: 14px;
  }

  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px 14px;
  }

  .path {
    font-family: var(--font-mono);
    font-size: 13px;
    word-break: break-all;
  }

  .zoomrow {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }

  .choices {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .choice {
    display: flex;
    align-items: center;
    gap: 8px;
    height: 38px;
    padding: 0 16px;
    border: 1px solid var(--border-strong);
    border-radius: 999px;
    background: transparent;
    cursor: pointer;
    transition: background var(--transition), color var(--transition);
  }

  .choice.on {
    border-color: transparent;
    background: var(--pill);
    color: var(--pill-fg);
  }

  .choice input {
    accent-color: var(--accent);
    margin: 0;
  }
</style>
