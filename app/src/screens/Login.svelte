<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import { createAccount, signIn } from '../lib/backend';

  const { create, onAuthed }: { create: boolean; onAuthed: (username: string) => void } = $props();

  let username = $state('');
  let password = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);

  const ready = $derived(
    username.trim().length > 0 && password.length > 0 && (!create || password === confirm),
  );

  async function submit(e: Event) {
    e.preventDefault();
    if (!ready || busy) return;
    busy = true;
    error = null;
    try {
      if (create) {
        if (password !== confirm) throw new Error('The two passwords do not match.');
        await createAccount(username.trim(), password);
      }
      await signIn(username.trim(), password);
      onAuthed(username.trim());
    } catch (err) {
      error = String((err as Error)?.message ?? err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="gate">
  <form class="card" onsubmit={submit}>
    <div class="head">
      <h1><Logo height={40} /></h1>
      <p class="sub">{create ? 'Create your account to set up Benchmark on this computer.' : 'Sign in to continue.'}</p>
    </div>

    <label class="field">
      <span>Username</span>
      <input autocomplete="username" spellcheck="false" bind:value={username} />
    </label>

    <label class="field">
      <span>Password</span>
      <input type="password" autocomplete={create ? 'new-password' : 'current-password'} bind:value={password} />
    </label>

    {#if create}
      <label class="field">
        <span>Confirm password</span>
        <input type="password" autocomplete="new-password" bind:value={confirm} />
      </label>
      <p class="hint">Use at least 10 characters. Only its Argon2 hash is kept on this computer, never the password itself.</p>
    {/if}

    {#if error}
      <p class="err" role="alert"><Icon name="errorCircle" size={18} />{error}</p>
    {/if}

    <button class="btn primary" type="submit" disabled={!ready || busy}>
      {busy ? (create ? 'Creating…' : 'Signing in…') : create ? 'Create account' : 'Sign in'}
    </button>

    {#if !create}
      <p class="aside">Forgot it? Use the BenchmarkPassword tool to set a new one.</p>
    {/if}
  </form>
</div>

<style>
  .gate {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 24px;
    background: var(--surface, #f6f7f9);
  }

  .card {
    width: 100%;
    max-width: 360px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 32px 28px;
    border: 1px solid var(--border);
    border-radius: calc(var(--radius) * 1.5);
    background: var(--surface-raised, #fff);
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.08);
  }

  .head {
    text-align: center;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .head h1 {
    margin: 0;
    display: flex;
    justify-content: center;
  }

  .sub {
    margin: 0;
    color: var(--text-muted, #667);
    font-size: 14px;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .field span {
    font-size: 13px;
    color: var(--text-muted, #667);
  }

  .field input {
    padding: 11px 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface-raised, #fff);
    color: var(--text);
    font-size: 15px;
  }

  .field input:focus-visible {
    outline: 2px solid var(--accent, #c4302b);
    outline-offset: 1px;
  }

  .hint {
    margin: -4px 0 0;
    font-size: 12px;
    color: var(--text-muted, #889);
  }

  .err {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    color: var(--danger, #c4302b);
    font-size: 13px;
  }

  .aside {
    margin: 0;
    text-align: center;
    font-size: 12px;
    color: var(--text-muted, #889);
  }
</style>
